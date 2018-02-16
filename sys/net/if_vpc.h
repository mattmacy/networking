/*
 * Copyright (C) 2017 Matthew Macy <matt.macy@joyent.com>
 * Copyright (C) 2017 Joyent Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef __IF_VPC_H_
#define __IF_VPC_H_

#include <netinet/in.h>
#include <sys/uuid.h>
#include <sys/ioccom.h>

#define VPC_VERS 0x20171228
struct vpc_ioctl_header {
	uint64_t vih_magic;
	uint64_t vih_type;
};
struct vpclink_listen {
	struct vpc_ioctl_header vl_vih;
	struct sockaddr vl_addr;
};

struct vpclink_fte {
	uint32_t vf_vni;
	uint8_t vf_hwaddr[ETHER_ADDR_LEN];
	struct sockaddr vf_protoaddr;
};

struct vpc_fte_list {
	struct vpc_ioctl_header vfl_vih;
	uint32_t vfl_count;
	struct vpclink_fte vfl_vftes[0];
};

#define VPC_LISTEN								\
	_IOW('k', 1, struct vpc_listen)
#define VPC_FTE_ALL								\
	_IOWR('k', 4, struct vpc_fte_list)


struct vpci_attach {
	struct vpc_ioctl_header va_vih;
	char va_ifname[IFNAMSIZ];

};
struct vpci_vni {
	struct vpc_ioctl_header vv_vih;
	uint32_t vv_vni;
};

#define VPCI_ATTACH								\
	_IOW('k', 1, struct vpci_attach)
#define VPCI_ATTACHED_GET			   			\
	_IOWR('k', 2, struct vpci_attach)
#define VPCI_DETACH								\
	_IOW('k', 3, struct vpc_ioctl_header)
#define VPCI_VNI_SET							\
	_IOW('k', 4, struct vpci_vni)
#define VPCI_VNI_GET							\
	_IOWR('k', 5, struct vpci_vni)


struct vpcsw_port {
	struct vpc_ioctl_header vp_ioh;
	vpc_id_t vp_id;
};

#define VPCSW_REQ_NDv4 0x1
#define VPCSW_REQ_NDv6 0x2
#define VPCSW_REQ_DHCPv4 0x3
#define VPCSW_REQ_DHCPv6 0x4
#define VPCSW_REQ_MAX VPCSW_REQ_DHCPv6 

#define VPCSW_VERSION 0x42


struct vpcsw_op_header {
	uint32_t voh_version;
	uint32_t voh_op;
};

struct vpcsw_op_context {
	uint32_t voc_vni;
	uint16_t voc_vlanid;
	uint8_t voc_smac[ETHER_ADDR_LEN];
};

union vpcsw_request_data {
	struct {
		struct in_addr target;
	} vrqd_ndv4;
	struct {
		struct in6_addr target;
	} vrqd_ndv6;
};

struct vpcsw_request {
	struct vpcsw_op_header vrq_header;
	struct vpcsw_op_context vrq_context;
	union vpcsw_request_data vrq_data;
};

union vpcsw_response_data {
	struct {
		uint8_t ether_addr[ETHER_ADDR_LEN];
	} vrsd_ndv4;
	struct {
		uint8_t ether_addr[ETHER_ADDR_LEN];
	} vrsd_ndv6;
	struct {
		struct in_addr client_addr;
		struct in_addr gw_addr;
		struct in_addr dns_addr;
		uint8_t prefixlen;
	} vrsd_dhcpv4;
	struct {
		struct in6_addr client_addr;
		struct in6_addr gw_addr;
		struct in6_addr dns_addr;
		uint8_t prefixlen;
	} vrsd_dhcpv6;
};

struct vpcsw_response {
	struct vpcsw_op_header vrs_header;
	struct vpcsw_op_context vrs_context;
	union vpcsw_response_data vrs_data;
};

#define VPCSW_POLL									\
	_IOWR('k', 1, struct vpcsw_request)
#define VPCSW_RESPONSE_NDv4		   					\
	_IOW('k', 2, struct vpcsw_response)
#define VPCSW_RESPONSE_NDv6		   					\
	_IOW('k', 3, struct vpcsw_response)
#define VPCSW_RESPONSE_DHCPv4		  				\
	_IOW('k', 4, struct vpcsw_response)
#define VPCSW_RESPONSE_DHCPv6		   	  			\
	_IOW('k', 5, struct vpcsw_response)


#ifdef _KERNEL
#include <sys/proc.h>
#include <sys/sched.h>
#include <net/art.h>
#include <ck_epoch.h>

#define M_TRUNK M_PROTO1

struct ifp_cache {
	uint16_t ic_ifindex_max;
	uint16_t ic_size;
	uint32_t ic_pad;
	struct ifnet *ic_ifps[0];
};

struct vpc_pkt_info {
	uint16_t vpi_etype;
	uint8_t vpi_l2_len;
	uint8_t vpi_l3_len;
	uint8_t vpi_l4_len;
	uint8_t vpi_v6:1;
	uint8_t vpi_proto:7;
};

struct ck_epoch_record;
extern ck_epoch_t vpc_epoch;
extern struct ck_epoch_record vpc_global_record;
DPCPU_DECLARE(struct ck_epoch_record *, vpc_epoch_record);


int vpc_parse_pkt(struct mbuf *m0, struct vpc_pkt_info *tpi);
int vpc_art_tree_clone(art_tree *src, art_tree **dst, struct malloc_type *type);
void vpc_art_free(art_tree *tree, struct malloc_type *type);

static inline void
vpc_epoch_begin(void)
{
	_critical_enter();
	sched_pin();
	ck_epoch_begin(DPCPU_GET(vpc_epoch_record), NULL);
	_critical_exit();
}

static inline void
vpc_epoch_end(void)
{
	_critical_enter();
	sched_unpin();
	ck_epoch_end(DPCPU_GET(vpc_epoch_record), NULL);
	_critical_exit();
}

int vpc_ifp_cache(struct ifnet *ifp);


enum vpcp_port_type {
	VPCP_TYPE_NONE,
	VPCP_TYPE_VMI,
	VPCP_TYPE_PHYS
};

int vpcp_set_ifswitch(if_ctx_t ctx, if_t ifp);
if_t vpcp_get_ifswitch(if_ctx_t ctx);
void vpcp_clear_ifswitch(if_ctx_t ctx);

typedef struct vpcctx_public {
	struct ifnet *v_ifp;
	vpc_type_t v_obj_type;
	vpc_id_t v_id;
} *vpc_ctx_t;

typedef int (*vpc_ctl_fn) (vpc_ctx_t ctx, vpc_op_t op, size_t keylen,
				   const void *key, size_t *vallen, void **buf);

int vmmnet_insert(const vpc_id_t *id, if_t ifp, vpc_type_t type);
vpc_ctx_t vmmnet_lookup(const vpc_id_t *id);
struct ifnet *vpc_if_lookup(uint32_t ifindex);


int vmnic_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
			  size_t *outlen, void **outdata);

int vpcsw_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
			  size_t *outlen, void **outdata);

int vpcp_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
			 size_t *outlen, void **outdata);


#endif
enum vpc_obj_type {
	VPC_OBJ_INVALID = 0,
	VPC_OBJ_SWITCH = 1,
	VPC_OBJ_PORT = 2,
	VPC_OBJ_ROUTER = 3,
	VPC_OBJ_NAT = 4,
	VPC_OBJ_LINK = 5,
	VPC_OBJ_VMNIC = 6,
	VPC_OBJ_MGMT = 7,
	VPC_OBJ_PHYS = 8,
	VPC_OBJ_TYPE_MAX = 8,
};


enum vpc_meta_op_type {
	VPC_OBJ_DESTROY = 1,
	VPC_OBJ_TYPE_GET = 2,
	VPC_META_OP_TYPE_MAX = 2
};

enum vpc_vmnic_op_type {
	VPC_VMNIC_INVALID = 0,
	VPC_VMNIC_NQUEUES_GET =		1,
	VPC_VMNIC_NQUEUES_SET =		2,
	VPC_VMNIC_MAC_GET =		3,
	VPC_VMNIC_MAC_SET =		4,
	VPC_VMNIC_ATTACH =		5,
	VPC_VMNIC_MSIX =		6,
	VPC_VMNIC_FREEZE =		7,
	VPC_VMNIC_UNFREEZE =		8,
	VPC_VMNIC_OP_TYPE_MAX =			8,
};

enum vpc_vpcsw_op_type {
	VPC_VPCSW_INVALID = 0,
	VPC_VPCSW_PORT_ADD =		1,
	VPC_VPCSW_PORT_DEL =		2,
	VPC_VPCSW_PORT_UPLINK_SET =		3,
	VPC_VPCSW_PORT_UPLINK_GET =		4,
	VPC_VPCSW_OP_TYPE_MAX =			4,
};

enum vpc_vpcp_op_type {
	VPC_VPCP_INVALID = 0,
	VPC_VPCP_CONNECT = 1,
	VPC_VPCP_DISCONNECT = 2,
	VPC_VPCP_VNI_GET = 3,
	VPC_VPCP_VNI_SET = 4,
	VPC_VPCP_VTAG_GET = 5,
	VPC_VPCP_VTAG_SET = 6,
	VPC_VPCP_MAC_GET = 7,
	VPC_VPCP_MAC_SET = 8,
	VPC_VPCP_PEER_ID_GET = 9,
	VPC_VPCP_MAX = 9,
};

enum vpc_phys_op_type {
	VPC_PHYS_INVALID = 0,
	VPC_PHYS_ATTACH = 1,
	VPC_PHYS_MAX = 1,
};

#define IOC_MUT IOC_VOID
#define VPC_OP(objtype, op) (((objtype) << 16)| (op))
/* Modify state based on operation only -- userspace: VPC_OP_WR */
#define VPC_OP_M(objtype, op) (IOC_MUT | ((objtype) << 16)| (op))
/* Read state based on operation only -- userspace: VPC_OP_RD */
#define VPC_OP_O(objtype, op) (IOC_OUT | ((objtype) << 16)| (op))
#define VPC_OP_OM(objtype, op) (IOC_OUT | IOC_MUT | ((objtype) << 16)| (op))
#define VPC_OP_I(objtype, op) (IOC_IN | ((objtype) << 16)| (op))
/* Modify state based on operation and passed data -- userspace: VPC_OP_WR_KEY */
#define VPC_OP_IM(objtype, op) (IOC_IN|IOC_MUT | ((objtype) << 16)| (op))
#define VPC_OP_IO(objtype, op) ((IOC_IN|IOC_OUT) | ((objtype) << 16)| (op))
/* Modify state based on operation and passed data and read back results -- userspace: VPC_OP_RDWR_KEY_VAL */
#define VPC_OP_IOM(objtype, op) ((IOC_IN|IOC_OUT|IOC_MUT) | ((objtype) << 16)| (op))

#define VPC_OBJ_TYPE(op) ((op & ~(IOC_OUT|IOC_IN|IOC_MUT)) >> 16)
#define VPC_OBJ_OP(op) ((op) & ((1<<16)-1))

#define VPC_OBJ_OP_DESTROY VPC_OP_M(VPC_OBJ_MGMT, VPC_OBJ_DESTROY)
#define VPC_OBJ_OP_TYPE_GET VPC_OP_O(VPC_OBJ_MGMT, VPC_OBJ_TYPE_GET)

#define VPC_VPCSW_OP_PORT_ADD VPC_OP_IM(VPC_OBJ_SWITCH, VPC_VPCSW_PORT_ADD)
#define VPC_VPCSW_OP_PORT_DEL VPC_OP_M(VPC_OBJ_SWITCH, VPC_VPCSW_PORT_DEL)
#define VPC_VPCSW_OP_PORT_UPLINK_GET VPC_OP_O(VPC_OBJ_SWITCH, VPC_VPCSW_PORT_UPLINK_GET)
#define VPC_VPCSW_OP_PORT_UPLINK_SET VPC_OP_IM(VPC_OBJ_SWITCH, VPC_VPCSW_PORT_UPLINK_SET)

#define VPC_VMNIC_OP_NQUEUES_GET VPC_OP_O(VPC_OBJ_VMNIC, VPC_VMNIC_NQUEUES_GET)
#define VPC_VMNIC_OP_NQUEUES_SET VPC_OP_IM(VPC_OBJ_VMNIC, VPC_VMNIC_NQUEUES_SET)
#define VPC_VMNIC_OP_MAC_GET VPC_OP_O(VPC_OBJ_VMNIC, VPC_VMNIC_MAC_GET)
#define VPC_VMNIC_OP_MAC_SET VPC_OP_IM(VPC_OBJ_VMNIC, VPC_VMNIC_MAC_SET)
#define VPC_VMNIC_OP_ATTACH VPC_OP_IM(VPC_OBJ_VMNIC, VPC_VMNIC_ATTACH)
#define VPC_VMNIC_OP_MSIX VPC_OP_IM(VPC_OBJ_VMNIC, VPC_VMNIC_MSIX)
#define VPC_VMNIC_OP_FREEZE VPC_OP_M(VPC_OBJ_VMNIC, VPC_VMNIC_FREEZE)
#define VPC_VMNIC_OP_UNFREEZE VPC_OP_M(VPC_OBJ_VMNIC, VPC_VMNIC_UNFREEZE)

#define VPC_VPCP_OP_CONNECT VPC_OP_IM(VPC_OBJ_PORT, VPC_VPCP_CONNECT)
#define VPC_VPCP_OP_DISCONNECT VPC_OP_M(VPC_OBJ_PORT, VPC_VPCP_DISCONNECT)
#define VPC_VPCP_OP_VNI_GET VPC_OP_O(VPC_OBJ_PORT, VPC_VPCP_VNI_GET)
#define VPC_VPCP_OP_VNI_SET VPC_OP_IM(VPC_OBJ_PORT, VPC_VPCP_VNI_SET)
#define VPC_VPCP_OP_VTAG_GET VPC_OP_O(VPC_OBJ_PORT, VPC_VPCP_VTAG_GET)
#define VPC_VPCP_OP_VTAG_SET VPC_OP_IM(VPC_OBJ_PORT, VPC_VPCP_VTAG_SET)
#define VPC_VPCP_OP_MAC_GET VPC_OP_O(VPC_OBJ_PORT, VPC_VPCP_MAC_GET)
#define VPC_VPCP_OP_MAC_SET VPC_OP_IM(VPC_OBJ_PORT, VPC_VPCP_MAC_SET)
#define VPC_VPCP_OP_PEER_ID_GET VPC_OP_O(VPC_OBJ_PORT, VPC_VPCP_PEER_ID_GET)

#define VPC_PHYS_OP_ATTACH VPC_OP_IM(VPC_OBJ_PHYS, VPC_PHYS_ATTACH)

#define VPC_F_CREATE (1ULL << 0)
#define VPC_F_OPEN (1ULL << 1)
#define VPC_F_READ (1ULL << 2)
#define VPC_F_WRITE (1ULL << 3)
#endif
