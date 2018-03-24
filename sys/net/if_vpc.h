/*
 * Copyright (C) 2017-2018 Matthew Macy <mmacy@mattmacy.io>
 * Copyright (C) 2017-2018 Joyent Inc.
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

struct vpcmux_fte {
	uint32_t vf_vni;
	uint16_t vf_vlanid;
	uint8_t vf_hwaddr[ETHER_ADDR_LEN];
	struct sockaddr vf_protoaddr;
};

struct vpcmux_fte_list {
	uint32_t vfl_count;
	struct vpcmux_fte vfl_vftes[0];
};

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


#define VPCSW_REQ_NDv4 0x1
#define VPCSW_REQ_NDv6 0x2
#define VPCSW_REQ_DHCPv4 0x4
#define VPCSW_REQ_DHCPv6 0x8
#define VPCSW_REQ_MAX VPCSW_REQ_DHCPv6 

#define VPCSW_VERSION 0x42


struct vpcsw_op_header {
	uint32_t voh_version;
	uint32_t voh_op;
};

struct vpcsw_op_context {
	uint32_t voc_vni;
	uint16_t voc_vtag;
	uint16_t voc_len;
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
	vpc_id_t vrq_id;
	uint8_t vrq_data[0];
};

struct vpcsw_response {
	struct vpcsw_op_context vrs_context;
	uint8_t vrs_data[0];
};

struct vpcrtr_request_v4 {
	uint8_t vr_vpcsw_mac[ETHER_ADDR_LEN];
	uint16_t vr_svtag;
	uint32_t vr_svni;
	struct in_addr vr_saddr;
	struct in_addr vr_daddr;
	uint8_t vr_smac[ETHER_ADDR_LEN];
};

struct vpcrtr_request_v6 {
	uint8_t vr_vpcsw_smac[ETHER_ADDR_LEN];
	uint16_t vr_svtag;
	uint32_t vr_svni;
	struct in6_addr vr_saddr;
	struct in6_addr vr_daddr;
	uint8_t vr_smac[ETHER_ADDR_LEN];
};

struct vpcrtr_response_v4 {
	struct vpcrtr_request_v4 vr_context;
	uint16_t vr_dvtag;
	uint32_t vr_dvni;
	struct in_addr vr_daddr;
	uint8_t vr_dmac[ETHER_ADDR_LEN];
	uint8_t vr_vpcsw_dmac[ETHER_ADDR_LEN];
};

typedef struct {
	uint32_t voh_type;
	uint32_t voh_unit;
	vpc_id_t voh_id;
} vpc_obj_header_t;

typedef struct {
	vpc_obj_header_t voi_hdr;
    union {
		struct {
			uint32_t vni;
		} vswitch;
		struct {
			uint8_t type;
		} port;
		struct {
		} vmnic;
		struct {
		} ethlink;
		struct {
		} vpcmux;
	};
} vpc_obj_info_t;


typedef struct {
	uint64_t vht_version:4;
	uint64_t vht_pad1:4;
	uint64_t vht_obj_type:8;
	uint64_t vht_pad2:48;
} vpc_handle_type_t;

#ifdef _KERNEL
#include <sys/proc.h>
#include <sys/sched.h>
#include <net/art.h>
#include <ck_epoch.h>

#define M_TRUNK			M_PROTO1
#define M_HOLBLOCKING	M_PROTO2

#define M_VPCMASK		(M_PROTO1|M_PROTO2)

struct ifp_cache {
	uint16_t ic_ifindex_max;
	uint16_t ic_size;
	uint32_t ic_pad;
	struct ifnet *ic_ifps[0];
};

struct vpc_pkt_info {
	uint16_t vpi_etype;
	uint16_t vpi_hash;
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

int vpcp_set_ifswitch(if_ctx_t ctx, if_t ifp);
if_t vpcp_get_ifswitch(if_ctx_t ctx);
void vpcp_clear_ifswitch(if_ctx_t ctx);

struct rtr_ctx;
typedef struct rtr_ctx *rtr_ctx_t;

typedef struct vpcctx_public {
	struct ifnet *v_ifp;
	vpc_type_t v_obj_type;
	vpc_id_t v_id;
} *vpc_ctx_t;

struct vpc_copy_info {
	struct proc *vci_proc;
	vm_page_t *vci_pages;
	int vci_max_count;
};

typedef int (*vpc_ctl_fn) (vpc_ctx_t ctx, vpc_op_t op, size_t keylen,
				   const void *key, size_t *vallen, void **buf);

int vmmnet_insert(const vpc_id_t *id, if_t ifp, vpc_type_t type);
vpc_ctx_t vmmnet_lookup(const vpc_id_t *id);
void vmmnet_delete(const vpc_id_t *id);
void vmmnet_ref(vpc_ctx_t vctx);
void vmmnet_rele(vpc_ctx_t vctx);

struct ifnet *vpc_if_lookup(uint32_t ifindex);
int vpc_async_copyout(struct vpc_copy_info *vci, const void *kaddr, void *uaddr, size_t len);
int vpcp_port_disconnect_ifp(struct ifnet *ifp);
void vpcp_set_pcpu_cache(if_ctx_t ctx, void *cache);
void *vpcp_get_pcpu_cache(if_ctx_t ctx);
void vpcp_get_id(struct ifnet *portifp, vpc_id_t *id);

int vpcsw_transmit_ext(struct ifnet *ifp, struct mbuf *m, void *cache);
int vpcsw_port_connect(if_ctx_t switchctx, struct ifnet *portifp, struct ifnet *devifp);
int vpcsw_port_disconnect(if_ctx_t switchctx, struct ifnet *portifp);


int vmnic_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
			  size_t *outlen, void **outdata);

int vpcsw_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
			  size_t *outlen, void **outdata);

int vpcp_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
			 size_t *outlen, void **outdata);

int vpcrtr_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
			   size_t *outlen, void **outdata);

int vpcmux_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
				size_t *outlen, void **outdata);

int ethlink_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
			   size_t *outlen, void **outdata);

int hostlink_ctl(vpc_ctx_t vctx, vpc_op_t op, size_t inlen, const void *in,
				 size_t *outlen, void **outdata);

struct ifnet *ethlink_ifp_get(if_ctx_t ctx);

rtr_ctx_t vpc_rtr_ctx_alloc(void);
void vpc_rtr_ctx_free(rtr_ctx_t rc);

int vpc_rtr_add(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen, int family);
int vpc_rtr_addv4(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen);
int vpc_rtr_addv6(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen);

int vpc_rtr_del(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen, int family);
int vpc_rtr_delv4(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen);
int vpc_rtr_delv6(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen);

int vpc_rtr_lookup(rtr_ctx_t rc, void *key, uint32_t *val, int family);
int vpc_rtr_lookupv4(rtr_ctx_t rc, void *key, uint32_t *val);
int vpc_rtr_lookupv6(rtr_ctx_t rc, void *key, uint32_t *val);

#endif

enum vpc_obj_type {
	VPC_OBJ_INVALID = 0,
	VPC_OBJ_SWITCH = 1,
	VPC_OBJ_PORT = 2,
	VPC_OBJ_ROUTER = 3,
	VPC_OBJ_NAT = 4,
	VPC_OBJ_VPCMUX = 5,
	VPC_OBJ_VMNIC = 6,
	VPC_OBJ_MGMT = 7,
	VPC_OBJ_ETHLINK = 8,
	VPC_OBJ_META = 9,
	VPC_OBJ_TYPE_ANY = 10,
	VPC_OBJ_HOSTLINK = 11,
	VPC_OBJ_TYPE_MAX = 11,
};

enum vpc_vpcsw_op_type {
	VPC_VPCSW_INVALID = 0,
	VPC_VPCSW_PORT_ADD =		1,
	VPC_VPCSW_PORT_DEL =		2,
	VPC_VPCSW_PORT_UPLINK_SET =		3,
	VPC_VPCSW_PORT_UPLINK_GET =		4,
	VPC_VPCSW_STATE_GET =		5,
	VPC_VPCSW_STATE_SET =		6,
	VPC_VPCSW_RESET =		7,
	VPC_VPCSW_RESPONSE =		8,
	VPC_VPCSW_OP_TYPE_MAX =		8,
};

enum vpc_vpcp_op_type {
	VPC_VPCP_INVALID = 0,
	VPC_VPCP_CONNECT = 1,
	VPC_VPCP_DISCONNECT = 2,
	VPC_VPCP_VNI_GET = 3,
	VPC_VPCP_VNI_SET = 4,
	VPC_VPCP_VTAG_GET = 5,
	VPC_VPCP_VTAG_SET = 6,
	VPC_VPCP_UNUSED7 = 7,
	VPC_VPCP_UNUSED8 = 8,
	VPC_VPCP_PEER_ID_GET = 9,
	VPC_VPCP_MAX = 9,
};

enum vpc_vpcrtr_op_type {
	VPC_VPCRTR_INVALID = 0,
	// add/update
	VPC_VPCRTR_ROUTE_SET = 1,
	// delete
	VPC_VPCRTR_ROUTE_DEL = 2,
	// dump route table
	VPC_VPCRTR_ROUTE_LIST = 3,
	VPC_VPCRTR_MAX_OPS = 3
};

enum vpc_vpcnat_op_type {
	VPC_VPCNAT_INVALID = 0,
	VPC_VPCNAT_MAX = 0,
};

enum vpc_vpcmux_op_type {
	VPC_VPCMUX_INVALID = 0,
	VPC_VPCMUX_LISTEN = 1,
	VPC_VPCMUX_FTE_SET = 2,
	VPC_VPCMUX_FTE_DEL = 3,
	VPC_VPCMUX_FTE_LIST = 4,
	VPC_VPCMUX_UNDERLAY_ATTACH = 5,
	VPC_VPCMUX_MAX = 5,
};

enum vpc_vmnic_op_type {
	VPC_VMNIC_INVALID = 0,
	VPC_VMNIC_NQUEUES_GET =		1,
	VPC_VMNIC_NQUEUES_SET =		2,
	VPC_VMNIC_UNUSED3 =		3,
	VPC_VMNIC_UNUSED4 =		4,
	VPC_VMNIC_UNUSED5 =		5,
	VPC_VMNIC_UNUSED6 =		6,
	VPC_VMNIC_ATTACH =		7,
	VPC_VMNIC_MSIX =		8,
	VPC_VMNIC_FREEZE =		9,
	VPC_VMNIC_UNFREEZE =		10,
	VPC_VMNIC_OP_TYPE_MAX =			10,
};

enum vpc_meta_op_type {
	VPC_META_INVALID = 0,
	VPC_OBJ_DESTROY = 1,
	VPC_OBJ_TYPE_GET = 2,
	VPC_OBJ_COMMIT = 3,
	VPC_OBJ_MAC_SET = 4,
	VPC_OBJ_MAC_GET = 5,
	VPC_OBJ_MTU_SET = 6,
	VPC_OBJ_MTU_GET = 7,
	VPC_OBJ_ID_GET = 8,
	VPC_META_OP_TYPE_MAX = 8
};

enum vpc_mgmt_op_type {
	VPC_MGMT_INVALID = 0,
	VPC_OBJ_TYPE_COUNT_GET = 1,
	VPC_OBJ_HDR_GET_ALL = 2,
	VPC_MGMT_OP_TYPE_MAX = 2
};

enum vpc_ethlink_op_type {
	VPC_ETHLINK_INVALID = 0,
	VPC_ETHLINK_ATTACH = 1,
	VPC_ETHLINK_CLONEATTACH = 2,
	VPC_ETHLINK_DEVCTL = 3,
	VPC_ETHLINK_MAX = 3,
};


enum vpc_hostlink_op_type {
	VPC_HOSTLINK_INVALID = 0,
	VPC_HOSTLINK_MAX = 0,
};


#define IOC_MUT IOC_VOID
#define IOC_PRIV 0x10000000
#define IOC_PRIVMUT (IOC_MUT|IOC_PRIV)

#define VPC_OP(objtype, op) (((objtype) << 16)| (op))
/* Modify state based on operation only -- userspace: VPC_OP_WR */
#define VPC_OP_M(objtype, op) (IOC_MUT | ((objtype) << 16)| (op))
#define VPC_OP_MP(objtype, op) (IOC_PRIVMUT | ((objtype) << 16)| (op))
/* Read state based on operation only -- userspace: VPC_OP_RD */
#define VPC_OP_O(objtype, op) (IOC_OUT | ((objtype) << 16)| (op))
#define VPC_OP_OP(objtype, op) (IOC_OUT | IOC_PRIV | ((objtype) << 16)| (op))
#define VPC_OP_OM(objtype, op) (IOC_OUT | IOC_MUT | ((objtype) << 16)| (op))
#define VPC_OP_OMP(objtype, op) (IOC_OUT | IOC_PRIVMUT | ((objtype) << 16)| (op))
#define VPC_OP_I(objtype, op) (IOC_IN | ((objtype) << 16)| (op))
#define VPC_OP_IP(objtype, op) (IOC_IN | IOC_PRIV | ((objtype) << 16)| (op))
/* Modify state based on operation and passed data -- userspace: VPC_OP_WR_KEY */
#define VPC_OP_IM(objtype, op) (IOC_IN|IOC_MUT | ((objtype) << 16)| (op))
#define VPC_OP_IMP(objtype, op) (IOC_IN|IOC_PRIVMUT | ((objtype) << 16)| (op))
#define VPC_OP_IO(objtype, op) ((IOC_IN|IOC_OUT) | ((objtype) << 16)| (op))
#define VPC_OP_IOP(objtype, op) ((IOC_IN|IOC_OUT|IOC_PRIV) | ((objtype) << 16)| (op))
/* Modify state based on operation and passed data and read back results -- userspace: VPC_OP_RDWR_KEY_VAL */
#define VPC_OP_IOM(objtype, op) ((IOC_IN|IOC_OUT|IOC_MUT) | ((objtype) << 16)| (op))
#define VPC_OP_IOMP(objtype, op) ((IOC_IN|IOC_OUT|IOC_PRIVMUT) | ((objtype) << 16)| (op))

#define VPC_OBJ_TYPE(op) ((op & ~(IOC_OUT|IOC_IN|IOC_PRIVMUT)) >> 16)
#define VPC_OBJ_OP(op) ((op) & ((1<<16)-1))

#define VPC_OBJ_OP_TYPE_COUNT_GET VPC_OP_IO(VPC_OBJ_MGMT, VPC_OBJ_TYPE_COUNT_GET)
#define VPC_OBJ_OP_HDR_GET_ALL VPC_OP_IO(VPC_OBJ_MGMT, VPC_OBJ_HDR_GET_ALL)

#define VPC_OBJ_OP_DESTROY VPC_OP_MP(VPC_OBJ_META, VPC_OBJ_DESTROY)
#define VPC_OBJ_OP_TYPE_GET VPC_OP_O(VPC_OBJ_META, VPC_OBJ_TYPE_GET)
#define VPC_OBJ_OP_COMMIT VPC_OP_MP(VPC_OBJ_META, VPC_OBJ_COMMIT)
#define VPC_OBJ_OP_MAC_SET VPC_OP_IMP(VPC_OBJ_META, VPC_OBJ_MAC_SET)
#define VPC_OBJ_OP_MAC_GET VPC_OP_O(VPC_OBJ_META, VPC_OBJ_MAC_GET)
#define VPC_OBJ_OP_MTU_SET VPC_OP_IMP(VPC_OBJ_META, VPC_OBJ_MTU_SET)
#define VPC_OBJ_OP_MTU_GET VPC_OP_O(VPC_OBJ_META, VPC_OBJ_MTU_GET)
#define VPC_OBJ_OP_ID_GET VPC_OP_O(VPC_OBJ_META, VPC_OBJ_ID_GET)

#define VPC_VPCSW_OP_PORT_ADD VPC_OP_IMP(VPC_OBJ_SWITCH, VPC_VPCSW_PORT_ADD)
#define VPC_VPCSW_OP_PORT_DEL VPC_OP_IMP(VPC_OBJ_SWITCH, VPC_VPCSW_PORT_DEL)
#define VPC_VPCSW_OP_PORT_UPLINK_GET VPC_OP_O(VPC_OBJ_SWITCH, VPC_VPCSW_PORT_UPLINK_GET)
#define VPC_VPCSW_OP_PORT_UPLINK_SET VPC_OP_IMP(VPC_OBJ_SWITCH, VPC_VPCSW_PORT_UPLINK_SET)
#define VPC_VPCSW_OP_STATE_GET VPC_OP_O(VPC_OBJ_SWITCH, VPC_VPCSW_STATE_GET)
#define VPC_VPCSW_OP_STATE_SET VPC_OP_IMP(VPC_OBJ_SWITCH, VPC_VPCSW_STATE_SET)
#define VPC_VPCSW_OP_RESET VPC_OP_MP(VPC_OBJ_SWITCH, VPC_VPCSW_RESET)
#define VPC_VPCSW_OP_RESPONSE VPC_OP_IMP(VPC_OBJ_SWITCH, VPC_VPCSW_RESPONSE)

#define VPC_VMNIC_OP_NQUEUES_GET VPC_OP_O(VPC_OBJ_VMNIC, VPC_VMNIC_NQUEUES_GET)
#define VPC_VMNIC_OP_NQUEUES_SET VPC_OP_IMP(VPC_OBJ_VMNIC, VPC_VMNIC_NQUEUES_SET)


#define VPC_VMNIC_OP_ATTACH VPC_OP_IMP(VPC_OBJ_VMNIC, VPC_VMNIC_ATTACH)
#define VPC_VMNIC_OP_MSIX VPC_OP_IMP(VPC_OBJ_VMNIC, VPC_VMNIC_MSIX)
#define VPC_VMNIC_OP_FREEZE VPC_OP_MP(VPC_OBJ_VMNIC, VPC_VMNIC_FREEZE)
#define VPC_VMNIC_OP_UNFREEZE VPC_OP_MP(VPC_OBJ_VMNIC, VPC_VMNIC_UNFREEZE)

#define VPC_VPCP_OP_CONNECT VPC_OP_IMP(VPC_OBJ_PORT, VPC_VPCP_CONNECT)
#define VPC_VPCP_OP_DISCONNECT VPC_OP_MP(VPC_OBJ_PORT, VPC_VPCP_DISCONNECT)
#define VPC_VPCP_OP_VNI_GET VPC_OP_O(VPC_OBJ_PORT, VPC_VPCP_VNI_GET)
#define VPC_VPCP_OP_VNI_SET VPC_OP_IMP(VPC_OBJ_PORT, VPC_VPCP_VNI_SET)
#define VPC_VPCP_OP_VTAG_GET VPC_OP_O(VPC_OBJ_PORT, VPC_VPCP_VTAG_GET)
#define VPC_VPCP_OP_VTAG_SET VPC_OP_IMP(VPC_OBJ_PORT, VPC_VPCP_VTAG_SET)
#define VPC_VPCP_OP_PEER_ID_GET VPC_OP_O(VPC_OBJ_PORT, VPC_VPCP_PEER_ID_GET)

#define VPC_ETHLINK_OP_ATTACH VPC_OP_IMP(VPC_OBJ_ETHLINK, VPC_ETHLINK_ATTACH)


#define VPC_VPCMUX_OP_LISTEN VPC_OP_IMP(VPC_OBJ_VPCMUX, VPC_VPCMUX_LISTEN)
#define VPC_VPCMUX_OP_FTE_SET VPC_OP_IMP(VPC_OBJ_VPCMUX, VPC_VPCMUX_FTE_SET)
#define VPC_VPCMUX_OP_FTE_DEL VPC_OP_IMP(VPC_OBJ_VPCMUX, VPC_VPCMUX_FTE_DEL)
#define VPC_VPCMUX_OP_UNDERLAY_ATTACH VPC_OP_IMP(VPC_OBJ_VPCMUX, VPC_VPCMUX_UNDERLAY_ATTACH)
#define VPC_VPCMUX_OP_FTE_LIST VPC_OP_O(VPC_OBJ_VPCMUX, VPC_VPCMUX_FTE_LIST)


#define VPC_F_CREATE (1ULL << 0)
#define VPC_F_OPEN (1ULL << 1)
#define VPC_F_READ (1ULL << 2)
#define VPC_F_WRITE (1ULL << 3)

#define VPCSW_SIZE_IDX 0
#define VPCSW_ADDR_IDX 1

#endif
