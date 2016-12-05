/*-
 * Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2016 Broadcom, All Rights Reserved.
 * The term Broadcom refers to Broadcom Limited and/or its subsidiaries
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS'
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#ifndef _BNXT_H
#define _BNXT_H

#include <sys/types.h>
#include <sys/bus.h>
#include <sys/bus_dma.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/iflib.h>

#include "hsi_struct_def.h"

/* PCI IDs */
#define BROADCOM_VENDOR_ID	0x14E4

#define BCM57301	0x16c8
#define BCM57302	0x16c9
#define BCM57304	0x16ca
#define BCM57311	0x16ce
#define BCM57312	0x16cf
#define BCM57314	0x16df
#define BCM57402	0x16d0
#define BCM57402_NPAR	0x16d4
#define BCM57404	0x16d1
#define BCM57404_NPAR	0x16e7
#define BCM57406	0x16d2
#define BCM57406_NPAR	0x16e8
#define BCM57407	0x16d5
#define BCM57407_NPAR	0x16ea
#define BCM57407_SFP	0x16e9
#define BCM57412	0x16d6
#define BCM57412_NPAR1	0x16de
#define BCM57412_NPAR2	0x16eb
#define BCM57414	0x16d7
#define BCM57414_NPAR1	0x16ec
#define BCM57414_NPAR2	0x16ed
#define BCM57416	0x16d8
#define BCM57416_NPAR1	0x16ee
#define BCM57416_NPAR2	0x16ef
#define BCM57416_SFP	0x16e3
#define BCM57417	0x16d9
#define BCM57417_NPAR1	0x16c0
#define BCM57417_NPAR2	0x16cc
#define BCM57417_SFP	0x16e2
#define BCM58700	0x16cd
#define NETXTREME_C_VF1	0x16cb
#define NETXTREME_C_VF2	0x16e1
#define NETXTREME_C_VF3	0x16e5
#define NETXTREME_E_VF1	0x16c1
#define NETXTREME_E_VF2	0x16d3
#define NETXTREME_E_VF3	0x16dc

#define CSUM_OFFLOAD		(CSUM_IP_TSO|CSUM_IP6_TSO|CSUM_IP| \
				 CSUM_IP_UDP|CSUM_IP_TCP|CSUM_IP_SCTP| \
				 CSUM_IP6_UDP|CSUM_IP6_TCP|CSUM_IP6_SCTP)

#define BNXT_MAX_MTU	9000

/* Completion related defines */
#define CMP_VALID(cmp, v_bit) \
	((!!(((struct cmpl_base *)(cmp))->info3_v & htole32(CMPL_BASE_V))) == !!(v_bit) )

#define NEXT_CP_CONS_V(ring, cons, v_bit) do {				    \
	if (__predict_false(++(cons) == (ring)->ring_size))		    \
		((cons) = 0, (v_bit) = !v_bit);				    \
} while (0)

#define RING_NEXT(ring, idx) (__predict_false(idx + 1 == (ring)->ring_size) ? \
								0 : idx + 1)

#define CMPL_PREFETCH_NEXT(cpr, idx)					    \
	__builtin_prefetch(&((struct cmpl_base *)(cpr)->ring.vaddr)[((idx) +\
	    (CACHE_LINE_SIZE / sizeof(struct cmpl_base))) &		    \
	    ((cpr)->ring.ring_size - 1)])

/*
 * If we update the index, a write barrier is needed after the write to ensure
 * the completion ring has space before the RX/TX ring does.  Since we can't
 * make the RX and AG doorbells covered by the same barrier without remapping
 * MSI-X vectors, we create the barrier over the enture doorbell bar.
 * TODO: Remap the MSI-X vectors to allow a barrier to only cover the doorbells
 *       for a single ring group.
 *
 * A barrier of just the size of the write is used to ensure the ordering
 * remains correct and no writes are lost.
 */
#define BNXT_CP_DISABLE_DB(ring) do {					    \
	bus_space_barrier((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, (ring)->doorbell, 4,	    \
	    BUS_SPACE_BARRIER_WRITE);					    \
	bus_space_barrier((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, 0,			    \
	    (ring)->softc->doorbell_bar.size, BUS_SPACE_BARRIER_WRITE);	    \
	bus_space_write_4((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, (ring)->doorbell,	    \
	    htole32(CMPL_DOORBELL_KEY_CMPL | CMPL_DOORBELL_MASK));	    \
} while (0)

#define BNXT_CP_ENABLE_DB(ring) do {					    \
	bus_space_barrier((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, (ring)->doorbell, 4,	    \
	    BUS_SPACE_BARRIER_WRITE);					    \
	bus_space_barrier((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, 0,			    \
	    (ring)->softc->doorbell_bar.size, BUS_SPACE_BARRIER_WRITE);	    \
	bus_space_write_4((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, (ring)->doorbell,	    \
	    htole32(CMPL_DOORBELL_KEY_CMPL));				    \
} while (0)

#define BNXT_CP_IDX_ENABLE_DB(ring, cons) do {				    \
	bus_space_barrier((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, (ring)->doorbell, 4,	    \
	    BUS_SPACE_BARRIER_WRITE);					    \
	bus_space_write_4((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, (ring)->doorbell,	    \
	    htole32(CMPL_DOORBELL_KEY_CMPL | CMPL_DOORBELL_IDX_VALID |	    \
	    (cons)));							    \
	bus_space_barrier((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, 0,			    \
	    (ring)->softc->doorbell_bar.size, BUS_SPACE_BARRIER_WRITE);	    \
} while (0)

#define BNXT_CP_IDX_DISABLE_DB(ring, cons) do {				    \
	bus_space_barrier((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, (ring)->doorbell, 4,	    \
	    BUS_SPACE_BARRIER_WRITE);					    \
	bus_space_write_4((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, (ring)->doorbell,	    \
	    htole32(CMPL_DOORBELL_KEY_CMPL | CMPL_DOORBELL_IDX_VALID |	    \
	    CMPL_DOORBELL_MASK | (cons)));				    \
	bus_space_barrier((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, 0,			    \
	    (ring)->softc->doorbell_bar.size, BUS_SPACE_BARRIER_WRITE);	    \
} while (0)

#define BNXT_TX_DB(ring, idx) do {					    \
	bus_space_barrier((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, (ring)->doorbell, 4,	    \
	    BUS_SPACE_BARRIER_WRITE);					    \
	bus_space_write_4(						    \
	    (ring)->softc->doorbell_bar.tag,				    \
	    (ring)->softc->doorbell_bar.handle,				    \
	    (ring)->doorbell, htole32(TX_DOORBELL_KEY_TX | (idx)));	    \
} while (0)

#define BNXT_RX_DB(ring, idx) do {					    \
	bus_space_barrier((ring)->softc->doorbell_bar.tag,		    \
	    (ring)->softc->doorbell_bar.handle, (ring)->doorbell, 4,	    \
	    BUS_SPACE_BARRIER_WRITE);					    \
	bus_space_write_4(						    \
	    (ring)->softc->doorbell_bar.tag,				    \
	    (ring)->softc->doorbell_bar.handle,				    \
	    (ring)->doorbell, htole32(RX_DOORBELL_KEY_RX | (idx)));	    \
} while (0)

/* Lock macros */
#define BNXT_HWRM_LOCK_INIT(_softc, _name) \
    mtx_init(&(_softc)->hwrm_lock, _name, "BNXT HWRM Lock", MTX_DEF)
#define BNXT_HWRM_LOCK(_softc)		mtx_lock(&(_softc)->hwrm_lock)
#define BNXT_HWRM_UNLOCK(_softc)	mtx_unlock(&(_softc)->hwrm_lock)
#define BNXT_HWRM_LOCK_DESTROY(_softc)	mtx_destroy(&(_softc)->hwrm_lock)
#define BNXT_HWRM_LOCK_ASSERT(_softc)	mtx_assert(&(_softc)->hwrm_lock,    \
    MA_OWNED)

/* Chip info */
#define BNXT_TSO_SIZE	UINT16_MAX

/* NVRAM access */
enum bnxt_nvm_directory_type {
	BNX_DIR_TYPE_UNUSED = 0,
	BNX_DIR_TYPE_PKG_LOG = 1,
	BNX_DIR_TYPE_UPDATE = 2,
	BNX_DIR_TYPE_CHIMP_PATCH = 3,
	BNX_DIR_TYPE_BOOTCODE = 4,
	BNX_DIR_TYPE_VPD = 5,
	BNX_DIR_TYPE_EXP_ROM_MBA = 6,
	BNX_DIR_TYPE_AVS = 7,
	BNX_DIR_TYPE_PCIE = 8,
	BNX_DIR_TYPE_PORT_MACRO = 9,
	BNX_DIR_TYPE_APE_FW = 10,
	BNX_DIR_TYPE_APE_PATCH = 11,
	BNX_DIR_TYPE_KONG_FW = 12,
	BNX_DIR_TYPE_KONG_PATCH = 13,
	BNX_DIR_TYPE_BONO_FW = 14,
	BNX_DIR_TYPE_BONO_PATCH = 15,
	BNX_DIR_TYPE_TANG_FW = 16,
	BNX_DIR_TYPE_TANG_PATCH = 17,
	BNX_DIR_TYPE_BOOTCODE_2 = 18,
	BNX_DIR_TYPE_CCM = 19,
	BNX_DIR_TYPE_PCI_CFG = 20,
	BNX_DIR_TYPE_TSCF_UCODE = 21,
	BNX_DIR_TYPE_ISCSI_BOOT = 22,
	BNX_DIR_TYPE_ISCSI_BOOT_IPV6 = 24,
	BNX_DIR_TYPE_ISCSI_BOOT_IPV4N6 = 25,
	BNX_DIR_TYPE_ISCSI_BOOT_CFG6 = 26,
	BNX_DIR_TYPE_EXT_PHY = 27,
	BNX_DIR_TYPE_SHARED_CFG = 40,
	BNX_DIR_TYPE_PORT_CFG = 41,
	BNX_DIR_TYPE_FUNC_CFG = 42,
	BNX_DIR_TYPE_MGMT_CFG = 48,
	BNX_DIR_TYPE_MGMT_DATA = 49,
	BNX_DIR_TYPE_MGMT_WEB_DATA = 50,
	BNX_DIR_TYPE_MGMT_WEB_META = 51,
	BNX_DIR_TYPE_MGMT_EVENT_LOG = 52,
	BNX_DIR_TYPE_MGMT_AUDIT_LOG = 53
};

enum bnxnvm_pkglog_field_index {
	BNX_PKG_LOG_FIELD_IDX_INSTALLED_TIMESTAMP	= 0,
	BNX_PKG_LOG_FIELD_IDX_PKG_DESCRIPTION		= 1,
	BNX_PKG_LOG_FIELD_IDX_PKG_VERSION		= 2,
	BNX_PKG_LOG_FIELD_IDX_PKG_TIMESTAMP		= 3,
	BNX_PKG_LOG_FIELD_IDX_PKG_CHECKSUM		= 4,
	BNX_PKG_LOG_FIELD_IDX_INSTALLED_ITEMS		= 5,
	BNX_PKG_LOG_FIELD_IDX_INSTALLED_MASK		= 6
};

#define BNX_DIR_ORDINAL_FIRST		0
#define BNX_DIR_EXT_NONE		0

struct bnxt_bar_info {
	struct resource		*res;
	bus_space_tag_t		tag;
	bus_space_handle_t	handle;
	bus_size_t		size;
	int			rid;
};

struct bnxt_link_info {
	uint8_t		media_type;
	uint8_t		transceiver;
	uint8_t		phy_addr;
	uint8_t		phy_link_status;
	uint8_t		wire_speed;
	uint8_t		loop_back;
	uint8_t		link_up;
	uint8_t		last_link_up;
	uint8_t		duplex;
	uint8_t		last_duplex;
	uint8_t		pause;
	uint8_t		last_pause;
	uint8_t		auto_pause;
	uint8_t		force_pause;
	uint8_t		duplex_setting;
	uint8_t		auto_mode;
#define PHY_VER_LEN		3
	uint8_t		phy_ver[PHY_VER_LEN];
	uint8_t		phy_type;
	uint16_t	link_speed;
	uint16_t	support_speeds;
	uint16_t	auto_link_speeds;
	uint16_t	auto_link_speed;
	uint16_t	force_link_speed;
	uint32_t	preemphasis;

	/* copy of requested setting */
	uint8_t		autoneg;
#define BNXT_AUTONEG_SPEED	1
#define BNXT_AUTONEG_FLOW_CTRL	2
	uint8_t		req_duplex;
	uint8_t		req_flow_ctrl;
	uint16_t	req_link_speed;
};

enum bnxt_cp_type {
	BNXT_DEFAULT,
	BNXT_TX,
	BNXT_RX,
	BNXT_SHARED
};

struct bnxt_cos_queue {
	uint8_t	id;
	uint8_t	profile;
};

struct bnxt_func_info {
	uint32_t	fw_fid;
	uint8_t		mac_addr[ETHER_ADDR_LEN];
	uint16_t	max_rsscos_ctxs;
	uint16_t	max_cp_rings;
	uint16_t	max_tx_rings;
	uint16_t	max_rx_rings;
	uint16_t	max_hw_ring_grps;
	uint16_t	max_irqs;
	uint16_t	max_l2_ctxs;
	uint16_t	max_vnics;
	uint16_t	max_stat_ctxs;
};

struct bnxt_pf_info {
#define BNXT_FIRST_PF_FID	1
#define BNXT_FIRST_VF_FID	128
	uint8_t		port_id;
	uint32_t	first_vf_id;
	uint16_t	active_vfs;
	uint16_t	max_vfs;
	uint32_t	max_encap_records;
	uint32_t	max_decap_records;
	uint32_t	max_tx_em_flows;
	uint32_t	max_tx_wm_flows;
	uint32_t	max_rx_em_flows;
	uint32_t	max_rx_wm_flows;
	unsigned long	*vf_event_bmap;
	uint16_t	hwrm_cmd_req_pages;
	void		*hwrm_cmd_req_addr[4];
	bus_addr_t	hwrm_cmd_req_dma_addr[4];
};

struct bnxt_vf_info {
	uint16_t	fw_fid;
	uint8_t		mac_addr[ETHER_ADDR_LEN];
	uint16_t	max_rsscos_ctxs;
	uint16_t	max_cp_rings;
	uint16_t	max_tx_rings;
	uint16_t	max_rx_rings;
	uint16_t	max_hw_ring_grps;
	uint16_t	max_l2_ctxs;
	uint16_t	max_irqs;
	uint16_t	max_vnics;
	uint16_t	max_stat_ctxs;
	uint32_t	vlan;
#define BNXT_VF_QOS		0x1
#define BNXT_VF_SPOOFCHK	0x2
#define BNXT_VF_LINK_FORCED	0x4
#define BNXT_VF_LINK_UP		0x8
	uint32_t	flags;
	uint32_t	func_flags; /* func cfg flags */
	uint32_t	min_tx_rate;
	uint32_t	max_tx_rate;
	void		*hwrm_cmd_req_addr;
	bus_addr_t	hwrm_cmd_req_dma_addr;
};

#define BNXT_FLAG_VF		(1<<1)

#define BNXT_PF(softc)		(!((softc)->flags & BNXT_FLAG_VF))
#define BNXT_VF(softc)		((softc)->flags & BNXT_FLAG_VF)

struct bnxt_vlan_tag {
	SLIST_ENTRY(bnxt_vlan_tag) next;
	uint16_t	tpid;
	uint16_t	tag;
};

struct bnxt_vnic_info {
	uint16_t	id;
	uint16_t	def_ring_grp;
	uint16_t	cos_rule;
	uint16_t	lb_rule;
	uint16_t	mru;

	uint32_t	rx_mask;
	bool		vlan_only;
	struct iflib_dma_info mc_list;
	int		mc_list_count;
#define BNXT_MAX_MC_ADDRS		16

	uint32_t	flags;
#define BNXT_VNIC_FLAG_DEFAULT		0x01
#define BNXT_VNIC_FLAG_BD_STALL		0x02
#define BNXT_VNIC_FLAG_VLAN_STRIP	0x04

	uint64_t	filter_id;
	uint32_t	flow_id;

	uint16_t	rss_id;
	uint32_t	rss_hash_type;
	uint8_t		rss_hash_key[HW_HASH_KEY_SIZE];
	struct iflib_dma_info rss_hash_key_tbl;
	struct iflib_dma_info	rss_grp_tbl;
	SLIST_HEAD(vlan_head, bnxt_vlan_tag) vlan_tags;
	struct iflib_dma_info vlan_tag_list;
};

struct bnxt_grp_info {
	uint16_t	stats_ctx;
	uint16_t	grp_id;
	uint16_t	rx_ring_id;
	uint16_t	cp_ring_id;
	uint16_t	ag_ring_id;
};

struct bnxt_ring {
	uint64_t		paddr;
	vm_offset_t		doorbell;
	caddr_t			vaddr;
	struct bnxt_softc	*softc;
	uint32_t		ring_size;	/* Must be a power of two */
	uint16_t		id;		/* Logical ID */
	uint16_t		phys_id;
};

struct bnxt_cp_ring {
	struct bnxt_ring	ring;
	struct if_irq		irq;
	uint32_t		cons;
	bool			v_bit;		/* Value of valid bit */
	struct ctx_hw_stats	*stats;
	uint32_t		stats_ctx_id;
	uint32_t		last_idx;	/* Used by RX rings only
						 * set to the last read pidx
						 */
};

struct bnxt_full_tpa_start {
	struct rx_tpa_start_cmpl low;
	struct rx_tpa_start_cmpl_hi high;
};

/* All the version information for the part */
#define BNXT_VERSTR_SIZE	(3*3+2+1)	/* ie: "255.255.255\0" */
#define BNXT_NAME_SIZE		17
struct bnxt_ver_info {
	uint8_t		hwrm_if_major;
	uint8_t		hwrm_if_minor;
	uint8_t		hwrm_if_update;
	char		hwrm_if_ver[BNXT_VERSTR_SIZE];
	char		driver_hwrm_if_ver[BNXT_VERSTR_SIZE];
	char		hwrm_fw_ver[BNXT_VERSTR_SIZE];
	char		mgmt_fw_ver[BNXT_VERSTR_SIZE];
	char		netctrl_fw_ver[BNXT_VERSTR_SIZE];
	char		roce_fw_ver[BNXT_VERSTR_SIZE];
	char		phy_ver[BNXT_VERSTR_SIZE];
	char		pkg_ver[64];

	char		hwrm_fw_name[BNXT_NAME_SIZE];
	char		mgmt_fw_name[BNXT_NAME_SIZE];
	char		netctrl_fw_name[BNXT_NAME_SIZE];
	char		roce_fw_name[BNXT_NAME_SIZE];
	char		phy_vendor[BNXT_NAME_SIZE];
	char		phy_partnumber[BNXT_NAME_SIZE];

	uint16_t	chip_num;
	uint8_t		chip_rev;
	uint8_t		chip_metal;
	uint8_t		chip_bond_id;
	uint8_t		chip_type;

	uint8_t		hwrm_min_major;
	uint8_t		hwrm_min_minor;
	uint8_t		hwrm_min_update;

	struct sysctl_ctx_list	ver_ctx;
	struct sysctl_oid	*ver_oid;
};

struct bnxt_nvram_info {
	uint16_t	mfg_id;
	uint16_t	device_id;
	uint32_t	sector_size;
	uint32_t	size;
	uint32_t	reserved_size;
	uint32_t	available_size;

	struct sysctl_ctx_list	nvm_ctx;
	struct sysctl_oid	*nvm_oid;
};

struct bnxt_softc {
	device_t	dev;
	if_ctx_t	ctx;
	if_softc_ctx_t	scctx;
	if_shared_ctx_t	sctx;
	struct ifmedia	*media;

	struct bnxt_bar_info	hwrm_bar;
	struct bnxt_bar_info	doorbell_bar;
	struct bnxt_link_info	link_info;
#define BNXT_FLAG_NPAR		1
	uint32_t		flags;
	uint32_t		total_msix;

	struct bnxt_func_info	func;
	struct bnxt_pf_info	pf;
	struct bnxt_vf_info	vf;

	uint16_t		hwrm_cmd_seq;
	uint32_t		hwrm_cmd_timeo;	/* milliseconds */
	struct iflib_dma_info	hwrm_cmd_resp;
	/* Interrupt info for HWRM */
	struct if_irq		irq;
	struct mtx		hwrm_lock;
	uint16_t		hwrm_max_req_len;

#define BNXT_MAX_QUEUE		8
	uint8_t			max_tc;
	struct bnxt_cos_queue	q_info[BNXT_MAX_QUEUE];

	struct iflib_dma_info	hw_rx_port_stats;
	struct iflib_dma_info	hw_tx_port_stats;
	struct rx_port_stats	*rx_port_stats;
	struct tx_port_stats	*tx_port_stats;

	int			num_cp_rings;

	struct bnxt_ring	*tx_rings;
	struct bnxt_cp_ring	*tx_cp_rings;
	struct iflib_dma_info	tx_stats;
	int			ntxqsets;

	struct bnxt_vnic_info	vnic_info;
	struct bnxt_ring	*ag_rings;
	struct bnxt_ring	*rx_rings;
	struct bnxt_cp_ring	*rx_cp_rings;
	struct bnxt_grp_info	*grp_info;
	struct iflib_dma_info	rx_stats;
	int			nrxqsets;

	struct bnxt_cp_ring	def_cp_ring;
	struct iflib_dma_info	def_cp_ring_mem;
	struct grouptask	def_cp_task;

	struct sysctl_ctx_list	hw_stats;
	struct sysctl_oid	*hw_stats_oid;

	struct bnxt_full_tpa_start *tpa_start;
	struct bnxt_ver_info	*ver_info;
	struct bnxt_nvram_info	*nvm_info;
};

struct bnxt_filter_info {
	STAILQ_ENTRY(bnxt_filter_info) next;
	uint64_t	fw_l2_filter_id;
#define INVALID_MAC_INDEX ((uint16_t)-1)
	uint16_t	mac_index;

	/* Filter Characteristics */
	uint32_t	flags;
	uint32_t	enables;
	uint8_t		l2_addr[ETHER_ADDR_LEN];
	uint8_t		l2_addr_mask[ETHER_ADDR_LEN];
	uint16_t	l2_ovlan;
	uint16_t	l2_ovlan_mask;
	uint16_t	l2_ivlan;
	uint16_t	l2_ivlan_mask;
	uint8_t		t_l2_addr[ETHER_ADDR_LEN];
	uint8_t		t_l2_addr_mask[ETHER_ADDR_LEN];
	uint16_t	t_l2_ovlan;
	uint16_t	t_l2_ovlan_mask;
	uint16_t	t_l2_ivlan;
	uint16_t	t_l2_ivlan_mask;
	uint8_t		tunnel_type;
	uint16_t	mirror_vnic_id;
	uint32_t	vni;
	uint8_t		pri_hint;
	uint64_t	l2_filter_id_hint;
};

/* Function declarations */
void bnxt_report_link(struct bnxt_softc *softc);
bool bnxt_check_hwrm_version(struct bnxt_softc *softc);

#endif /* _BNXT_H */
