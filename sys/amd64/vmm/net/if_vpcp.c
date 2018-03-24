/*
 * Copyright (C) 2018 Matthew Macy <matt.macy@joyent.com>
 * Copyright (C) 2018 Joyent Inc.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/bus.h>
#include <sys/eventhandler.h>
#include <sys/sockio.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/priv.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/rmlock.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/taskqueue.h>
#include <sys/limits.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if_vlan_var.h>
#include <net/iflib.h>
#include <net/if.h>
#include <net/if_clone.h>
#include <net/if_bridgevar.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_fw.h>

#include <netinet/ip6.h>
#include <netpfil/ipfw/ip_fw_private.h>

#include <net/if_vpc.h>
#include "ifdi_if.h"


static MALLOC_DEFINE(M_VPCP, "vpcp", "virtual machine interface port");

#define VPCI_DEBUG
#ifdef VPCI_DEBUG
#define  DPRINTF printf
#else
#define DPRINTF(...)
#endif

static struct vpcp_softc *
ctx_to_vs(if_ctx_t ctx)
{
	return (iflib_get_softc(ctx));
}
/*
 *
 */
#define VS_IPFW_EGRESS	0x1
#define VS_IPFW_INGRESS	0x2

struct vpcp_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
	struct ifnet *vs_ifswitch;
	struct ifnet *vs_ifdev;
	struct ifnet *vs_ifport;
	uint32_t vs_mflags;
	uint32_t vs_vxlanid;
	uint32_t vs_flags;
	uint16_t vs_vlanid;
	vpc_id_t vs_devid;
	enum vpc_obj_type vs_type;
	struct ip_fw_chain *vs_chain;
	void *vs_pcpu_cache;
};

static void vpcp_vxlanid_set(if_ctx_t ctx, uint32_t vxlanid);
static uint32_t vpcp_vxlanid_get(if_ctx_t ctx);
static void vpcp_vlanid_set(if_ctx_t ctx, uint16_t vlanid);
static uint16_t vpcp_vlanid_get(if_ctx_t ctx);
static int vpcp_port_type_set(if_ctx_t ctx, vpc_ctx_t vctx, enum vpc_obj_type type);
static int clone_count;

static void
vpcp_stub_linkstate(if_t ifp __unused)
{
}

static int
vpcp_stub_transmit(if_t ifp __unused, struct mbuf *m)
{
	panic("switch port transmit should never be called");
	m_freechain(m);
	return (0);
}

static void
vpcp_stub_input(if_t ifp __unused, struct mbuf *m)
{
	m_freechain(m);
}

static int
vpcp_stub_mbuf_to_qid(if_t ifp __unused, struct mbuf *m __unused)
{
	return (0);
}

static void
vmi_txflags(struct mbuf *m, struct vpc_pkt_info *vpi, bool egress)
{
	if (egress) {
		m->m_pkthdr.tso_segsz = m->m_pkthdr.flowid;
		m->m_pkthdr.fibnum = 0;
	}
	m->m_pkthdr.flowid = vpi->vpi_hash;
	m->m_pkthdr.l2hlen = vpi->vpi_l2_len;
	m->m_pkthdr.l3hlen = vpi->vpi_l3_len;
	m->m_pkthdr.l4hlen = vpi->vpi_l4_len;

	MPASS((m->m_pkthdr.csum_flags & CSUM_TSO) == 0 || 
		  m->m_pkthdr.flowid);
}

#ifdef INVARIANTS
static inline void
safe_mvec_sanity(const struct mbuf *m)
{
	if (m_ismvec(m))
		mvec_sanity(m);
}
#else
static inline void
safe_mvec_sanity(const struct mbuf *m __unused) {}
#endif

static void
vmi_input_process(struct ifnet *ifp, struct mbuf **m0, bool egress)
{
	struct vpcp_softc *vs;
	struct vpc_pkt_info vpi;
	struct mbuf *mnext, *mh, *mt, *m;
	caddr_t hdr;
	bool filter;
	int dir = egress ? PFIL_OUT : PFIL_IN;
	int action;
	//vni = (vs->vs_flags & VS_VXLANTAG) ? vs->vs_vni : 0;

	m = *m0;
	mh = mt = NULL;
	vs = iflib_get_softc(ifp->if_softc);
	filter = (egress && (vs->vs_flags & VS_IPFW_EGRESS)) ||
		(!egress && (vs->vs_flags & VS_IPFW_INGRESS));
	do {
		mnext = m->m_nextpkt;
		/* set mbuf flags for transmit */
		ETHER_BPF_MTAP(ifp, m);
		m->m_pkthdr.rcvif = ifp;
		hdr = mtod(m, caddr_t);
		vpc_parse_pkt(m, &vpi);
		vmi_txflags(m, &vpi, egress);
		if (filter) {
			action = ipfw_check_frame(&m, m->m_pkthdr.rcvif, dir, vs->vs_chain);
			if (__predict_false(action != IP_FW_PASS)) {
				m_freem(m);
				goto next;
			}
		}
		if (mh == NULL) {
			mh = mt = m;
		} else {
			mt->m_nextpkt = m;
			mt = m;
		}
		if (egress) {
			m->m_flags |= vs->vs_mflags;
			m->m_flags |= M_HOLBLOCKING;
			m->m_pkthdr.vxlanid = vs->vs_vxlanid;
			m->m_pkthdr.ether_vtag = vs->vs_vlanid;
		} else if ((m->m_flags & M_TRUNK) == 0)
			m->m_pkthdr.csum_flags |= CSUM_DATA_VALID;
		next:
		safe_mvec_sanity(m);
		m = mnext;
	} while (m != NULL);
	*m0 = mh;
}

static void
vmi_input(if_t ifp, struct mbuf *m)
{
	struct vpcp_softc *vs = iflib_get_softc(ifp->if_softc);
	struct ifnet *devifp = vs->vs_ifdev;

	vmi_input_process(vs->vs_ifport, &m, false);
	if (__predict_true(m != NULL))
		devifp->if_transmit_txq(devifp, m);
}

static int
vmi_bridge_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *s __unused, struct rtentry *r __unused)
{
	struct vpcp_softc *vs;
	struct ifnet *ifswitch;

	vs = ifp->if_bridge;
	ifswitch = vs->vs_ifswitch;
	vmi_input_process(vs->vs_ifport, &m, true);
	if (__predict_false(m == NULL))
		return (0);
	return (vpcsw_transmit_ext(ifswitch, m, vs->vs_pcpu_cache));
}

/*
 * Ingress -- from NIC
 */
static struct mbuf *
vmi_bridge_input(if_t ifp, struct mbuf *m)
{
	panic("%s should not be called\n", __func__);
}

/*
 * Egress -- from switch (i.e. switch output -> NIC input)
 */
static void
phys_input(struct ifnet *ifport, struct mbuf *m)
{
	if_ctx_t ctx = ifport->if_softc;
	struct vpcp_softc *vs = iflib_get_softc(ctx);
	struct ifnet *ifdev = vs->vs_ifdev;
	struct mbuf *mp, *mnext;
	int qid;
	bool batch;

	mp = m->m_nextpkt;
	qid = ifdev->if_mbuf_to_qid(ifdev, m);
	batch = true;
	m->m_flags &= ~M_VPCMASK;
	while (mp) {
		mp->m_flags &= ~M_VPCMASK;
		mp->m_pkthdr.rcvif = NULL;
		if (batch && ifdev->if_mbuf_to_qid(ifdev, m) != qid)
			batch = false;
		mp = mp->m_nextpkt;
	}
	if (__predict_true(batch)) {
		ifdev->if_transmit_txq(ifdev, m);
	} else {
		mp = m;
		do {
			mnext = mp->m_nextpkt;
			mp->m_nextpkt = NULL;
			ifdev->if_transmit_txq(ifdev, mp);
			mp = mnext;
		} while (mp);
	}
}

static int
phys_mbuf_to_qid(if_t ifp __unused, struct mbuf *m __unused)
{
	panic("%s should not be called\n", __func__);
	return (0);
}

static int
phys_bridge_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *s __unused, struct rtentry *r __unused)
{
	panic("%s should not be called\n", __func__);
	return (0);
}

/*
 * Ingress -- from NIC
 */
static struct mbuf *
phys_bridge_input(if_t ifp, struct mbuf *m)
{
	struct ether_header *eh;
	struct mbuf *mret, *mh, *mt, *mnext, *mp;
	struct vpcp_softc *vs;
	struct ifnet *ifswitch;

	MPASS(ifp->if_bridge != NULL);
	vs = ifp->if_bridge;

	eh = (void*)m->m_data;
	mh = mt = mret = NULL;
	mp = m;
	do {
		mnext = mp->m_nextpkt;
		mp->m_nextpkt = NULL;
		if (__predict_false(mp->m_flags & M_TRUNK)) {
			mp->m_flags &= ~M_TRUNK;
			goto next;
		}
		mp->m_flags |= M_TRUNK;
		if (__predict_false(ETHER_IS_MULTICAST(eh->ether_dhost) &&
							!(m->m_flags & (M_VXLANTAG|M_VLANTAG)))) {
			/* Order doesn't matter for broadcast packets */
			mp->m_nextpkt = mret;
			mret = mp;
		} else if (mh == NULL) {
			mh = mt = mp;
		} else {
			mt->m_nextpkt = mp;
			mt = mp;
		}
	next:
		mp = mnext;
	} while (mp);

	ifswitch = vs->vs_ifswitch;
	if (__predict_true(mh != NULL))
		vpcsw_transmit_ext(ifswitch, mh, vs->vs_pcpu_cache);
	if (__predict_false(mret != NULL))
		vpcsw_transmit_ext(ifswitch, mret, vs->vs_pcpu_cache);
	return (NULL);
}

static void
hostlink_input(if_t ifp, struct mbuf *m)
{
	struct vpcp_softc *vs = iflib_get_softc(ifp->if_softc);
	struct ifnet *devifp = vs->vs_ifdev;
	struct mbuf *mp = m;

	do {
		mp->m_pkthdr.rcvif = devifp;
		mp = mp->m_nextpkt;
	} while (mp);

	devifp->if_input(devifp, m);
}

static int
hostlink_bridge_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *s __unused, struct rtentry *r __unused)
{
	struct mbuf *mp;
	struct vpcp_softc *vs;
	struct ifnet *ifswitch;

	vs = ifp->if_bridge;
	ifswitch = vs->vs_ifswitch;
	mp = m;

	do {
		mp->m_pkthdr.rcvif = vs->vs_ifport;
		mp = m->m_nextpkt;
	} while (mp);
	mp = (void*)pktchain_to_mvec(m, ifp->if_mtu, M_NOWAIT);
	if (__predict_false(mp == NULL))
		return (0);
	return (vpcsw_transmit_ext(ifswitch, mp, vs->vs_pcpu_cache));
}

static struct mbuf *
hostlink_bridge_input(if_t ifp, struct mbuf *m)
{
	return (m);
}

static int
vpcp_port_type_set(if_ctx_t portctx, vpc_ctx_t vctx, enum vpc_obj_type type)
{
	struct ifnet *ifp, *ifdev;
	struct vpcp_softc *vs;
	enum vpc_obj_type prevtype;
	uint64_t baudrate;
	if_ctx_t switchctx;
	int rc;

	ifp = iflib_get_ifp(portctx);
	vs = iflib_get_softc(portctx);
	switchctx = vs->vs_ifswitch->if_softc;
	ifdev = NULL;
	baudrate = 0;

	if (vs->vs_type != VPC_OBJ_INVALID &&
		type != VPC_OBJ_INVALID) {
		if (bootverbose)
			printf("%s can't transition directly between port types, vs_type=%x type=%x\n",
				   __func__, vs->vs_type, type);
		return (EEXIST);
	}
	if (type != VPC_OBJ_INVALID) {
		MPASS(vctx != NULL);

		if (bootverbose)
			printf("%s transitioning to type=%x\n",
				   __func__, type);

		ifdev = vctx->v_ifp;
		vs->vs_ifdev = ifdev;
		if (type == VPC_OBJ_ETHLINK) {
			if_ctx_t ifctx = ifdev->if_softc;

			ifdev = ethlink_ifp_get(ifctx);
		}
		if (ifdev->if_bridge != NULL) {
			printf("%s in use\n", ifdev->if_xname);
			return (EINVAL);
		}
		baudrate = ifdev->if_baudrate;
	} else
		MPASS(vctx == NULL);

	prevtype = vs->vs_type;
	vs->vs_type = type;
	rc = 0;

	switch (type) {
		case VPC_OBJ_INVALID:
			ifp->if_input = vpcp_stub_input;
			ifp->if_bridge_linkstate = vpcp_stub_linkstate;
			if (vs->vs_ifdev) {
				ifdev = vs->vs_ifdev;
				if (vs->vs_type == VPC_OBJ_ETHLINK) {
					if_ctx_t ifctx = ifdev->if_softc;

					ifdev = ethlink_ifp_get(ifctx);
				}
				ifdev->if_bridge = NULL;
				wmb();
				vpcsw_port_disconnect(switchctx, ifp);
				ifdev->if_bridge_input = NULL;
				ifdev->if_bridge_output = NULL;
				ifdev->if_bridge_linkstate = NULL;
				if_rele(vs->vs_ifdev);
				vs->vs_ifdev = NULL;
			}
			break;
		case VPC_OBJ_VPCLINK:
		case VPC_OBJ_ETHLINK:
			if_setmbuftoqidfn(ifp, phys_mbuf_to_qid);
			ifp->if_input = phys_input;
			ifdev->if_bridge_input = phys_bridge_input;
			ifdev->if_bridge_output = phys_bridge_output;
			break;
		case VPC_OBJ_HOSTLINK:
			ifp->if_input = hostlink_input;
			ifdev->if_bridge_input = hostlink_bridge_input;
			ifdev->if_bridge_output = hostlink_bridge_output;
			break;
		case VPC_OBJ_VMNIC:
			ifp->if_input = vmi_input;
			ifdev->if_bridge_input = vmi_bridge_input;
			ifdev->if_bridge_output = vmi_bridge_output;
			break;
		default:
			vs->vs_type = prevtype;
			device_printf(iflib_get_dev(portctx), "unknown port type %d\n", type);
			rc = EINVAL;
	}
	if (rc == 0) {
		if (type == VPC_OBJ_INVALID) {
			MPASS(vs->vs_ifdev == NULL);
			iflib_link_state_change(vs->vs_ctx, LINK_STATE_DOWN, IF_Gbps(100));
		} else {
			ifdev->if_bridge_linkstate = vpcp_stub_linkstate;
			wmb();
			ifdev->if_bridge = vs;
			vpcsw_port_connect(switchctx, ifp, ifdev);
			iflib_link_state_change(vs->vs_ctx, LINK_STATE_UP, baudrate);
			if_ref(ifdev);
			vs->vs_ifdev = ifdev;
			memcpy(&vs->vs_devid, &vctx->v_id, sizeof(vpc_id_t));
		}
	}
	return (rc);
}

static int
vpcp_port_connect(if_ctx_t ctx, const vpc_id_t *id)
{
	vpc_ctx_t vctx;

	vctx = vmmnet_lookup(id);
	if (vctx == NULL) {
		if (bootverbose)
			printf("%s no context for %16D found\n",
				   __func__, id, ":");
		return (ENOENT);
	}
	if (vctx->v_ifp == NULL) {
		if (bootverbose)
			printf("%s %16D not attached\n",
				   __func__, id, ":");

		return (ENXIO);
	}
	return (vpcp_port_type_set(ctx, vctx, vctx->v_obj_type));
}

static int
vpcp_port_disconnect(if_ctx_t ctx)
{
	return (vpcp_port_type_set(ctx, NULL, VPC_OBJ_INVALID));
}

int
vpcp_port_disconnect_ifp(struct ifnet *ifp)
{
	struct vpcp_softc *vs = ifp->if_bridge;
	if_ctx_t ctx = vs->vs_ctx;

	MPASS(vs->vs_ifdev == ifp);
	return (vpcp_port_type_set(ctx, NULL, VPC_OBJ_INVALID));
}

void
vpcp_get_id(struct ifnet *portifp, vpc_id_t *id)
{
	if_ctx_t ctx = portifp->if_softc;
	struct vpcp_softc *vs;

	vs = iflib_get_softc(ctx);
	memcpy(id, &vs->vs_devid, sizeof(*id));
}

int
vpcp_ctl(vpc_ctx_t vctx, vpc_op_t op, size_t inlen, const void *in,
				 size_t *outlen, void **outdata)
{
	if_ctx_t ctx = vctx->v_ifp->if_softc;
	struct vpcp_softc *vs;
	int rc;

	rc = 0;
	vs = iflib_get_softc(ctx);
	switch (op) {
		case VPC_VPCP_OP_CONNECT:
			if (inlen != sizeof(vpc_id_t))
				goto fail;
			rc = vpcp_port_connect(ctx, in);
			break;
		case VPC_VPCP_OP_DISCONNECT:
			rc = vpcp_port_disconnect(ctx);
			break;
		case VPC_VPCP_OP_VNI_GET: {
			uint32_t *out;

			out = malloc(sizeof(uint32_t), M_TEMP, M_WAITOK);
			*outlen = sizeof(uint32_t);
			*out = vpcp_vxlanid_get(ctx);
			*outdata = out;
			break;
		}
		case VPC_VPCP_OP_VNI_SET: {
			uint32_t vni;

			if (inlen != sizeof(uint32_t))
				goto fail;
			vni = *(const uint32_t *)in;
			if (vni > ((1<<24)-1))
				goto fail;
			vpcp_vxlanid_set(ctx, vni);
			break;
		}
		case VPC_VPCP_OP_VTAG_GET: {
			uint16_t *out;

			out = malloc(sizeof(uint16_t), M_TEMP, M_WAITOK);
			*outlen = sizeof(uint16_t);
			*out = vpcp_vlanid_get(ctx);
			*outdata = out;
			break;
		}
		case VPC_VPCP_OP_VTAG_SET: {
			uint16_t vtag;

			if (inlen != sizeof(uint16_t))
				goto fail;
			vtag = *(const uint16_t *)in;
			if (vtag > ((1<<12)-1))
				goto fail;
			vpcp_vlanid_set(ctx, vtag);
			break;
		}
		case VPC_VPCP_OP_PEER_ID_GET: {
			vpc_id_t *id;

			if (vs->vs_type == VPC_OBJ_INVALID)
				return (ENXIO);
			*outlen = sizeof(vpc_id_t);
			id = malloc(*outlen, M_TEMP, M_WAITOK);
			memcpy(id, &vs->vs_devid, *outlen);
			break;
		}
	}
	return (rc);
 fail:
	return (EINVAL);
}

static int
vpcp_object_info_get(if_ctx_t ctx, void *arg, int size)
{
	struct vpcp_softc *vs = iflib_get_softc(ctx);
	vpc_obj_info_t *voi = arg;

	if (size != sizeof(*voi))
		return (EBADRPC);
	voi->port.type = vs->vs_type;
	return (0);
}

#define VPCP_CAPS														\
	IFCAP_TSO | IFCAP_HWCSUM | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM |	\
	IFCAP_VLAN_HWTSO | IFCAP_VLAN_MTU | IFCAP_TXCSUM_IPV6 | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU | \
	IFCAP_LINKSTATE

static int
vpcp_ipfw_init(struct ip_fw_chain *chain)
{
	int error;
	struct ip_fw *rule = NULL;

	ipfw_init_srv(chain);
	error = ipfw_init_tables(chain, 0);

	if (error) {
		printf("ipfw2: setting up tables failed\n");
		free(chain->map, M_IPFW);
		return (ENOSPC);
	}

	IPFW_LOCK_INIT(chain);
	/* fill and insert the default rule */
	rule = ipfw_alloc_rule(chain, sizeof(struct ip_fw));
	rule->cmd_len = 1;
	rule->cmd[0].len = 1;
	rule->cmd[0].opcode = O_ACCEPT;
	chain->default_rule = rule;
	ipfw_add_protected_rule(chain, rule, 0);
	ipfw_eaction_init(chain, 0);

	return (0);
}

static void
vpcp_ipfw_deinit(struct ip_fw_chain *chain)
{
	struct ip_fw *reap;
	int i;

	reap = NULL;
	IPFW_UH_WLOCK(chain);
	IPFW_WLOCK(chain);
	for (i = 0; i < chain->n_rules; i++)
		ipfw_reap_add(chain, &reap, chain->map[i]);

	IPFW_WUNLOCK(chain);
	IPFW_UH_WUNLOCK(chain);

	ipfw_destroy_tables(chain, 0);
	ipfw_eaction_uninit(chain, 0);
	if (reap != NULL)
		ipfw_reap_rules(reap);
	vnet_ipfw_iface_destroy(chain);
	ipfw_destroy_srv(chain);
	IPFW_LOCK_DESTROY(chain);
}

static int
vpcp_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct vpcp_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;
	int rc;

	atomic_add_int(&clone_count, 1);
	vs->vs_ctx = ctx;
	vs->vs_ifport = iflib_get_ifp(ctx);
	vs->vs_chain = malloc(sizeof(struct ip_fw_chain), M_VPCP, M_WAITOK|M_ZERO);
	if ((rc = vpcp_ipfw_init(vs->vs_chain))) {
		free(vs->vs_chain, M_VPCP);
		return (rc);
	}
	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	scctx->isc_capenable = VPCP_CAPS;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
		| CSUM_IP6_UDP | CSUM_IP6_TCP;
	return (0);
}

static int
vpcp_attach_post(if_ctx_t ctx)
{
	struct ifnet *ifp;

	ifp = iflib_get_ifp(ctx);
	if_settransmitfn(ifp, vpcp_stub_transmit);
	if_settransmittxqfn(ifp, vpcp_stub_transmit);
	if_setmbuftoqidfn(ifp, vpcp_stub_mbuf_to_qid);
	ifp->if_input = vpcp_stub_input;
	ifp->if_bridge_linkstate = vpcp_stub_linkstate;
	return (0);
}

static int
vpcp_detach(if_ctx_t ctx)
{
	struct vpcp_softc *vs = iflib_get_softc(ctx);

	if (vs->vs_ifdev != NULL) {
		if (bootverbose)
			printf("disconnecting port for %s\n", iflib_get_ifp(ctx)->if_xname);
		vpcp_port_disconnect(ctx);
	}
	if (vs->vs_ifswitch != NULL)
		if_rele(vs->vs_ifswitch);
	vpcp_ipfw_deinit(vs->vs_chain);
	free(vs->vs_chain, M_VPCP);
	atomic_add_int(&clone_count, -1);

	return (0);
}

static void
vpcp_init(if_ctx_t ctx)
{
}

static void
vpcp_stop(if_ctx_t ctx)
{
}

int
vpcp_set_ifswitch(if_ctx_t ctx, if_t ifswitch)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	if (vs->vs_ifswitch != NULL)
		return (EEXIST);
	if_ref(ifswitch);

	vs->vs_ifswitch = ifswitch;
	return (0);
}

if_t
vpcp_get_ifswitch(if_ctx_t ctx)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	return (vs->vs_ifswitch);
}

void
vpcp_clear_ifswitch(if_ctx_t ctx)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	if (vs->vs_ifswitch == NULL)
		return;
	if_rele(vs->vs_ifswitch);
	vs->vs_ifswitch = NULL;
}

static void
vpcp_vxlanid_set(if_ctx_t ctx, uint32_t vxlanid)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	if (vxlanid)
		vs->vs_mflags |= M_VXLANTAG;
	vs->vs_vxlanid = vxlanid;
}

static uint32_t
vpcp_vxlanid_get(if_ctx_t ctx)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	return (vs->vs_vxlanid);
}

static void
vpcp_vlanid_set(if_ctx_t ctx, uint16_t vlanid)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	if (vlanid)
		vs->vs_mflags |= M_VLANTAG;
	vs->vs_vlanid = vlanid;
}

static uint16_t
vpcp_vlanid_get(if_ctx_t ctx)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	return (vs->vs_vlanid);
}

void
vpcp_set_pcpu_cache(if_ctx_t ctx, void *cache)
{
	struct vpcp_softc *vs = iflib_get_softc(ctx);

	vs->vs_pcpu_cache = cache;
}

void *
vpcp_get_pcpu_cache(if_ctx_t ctx)
{
	struct vpcp_softc *vs = iflib_get_softc(ctx);

	return (vs->vs_pcpu_cache);
}

static device_method_t vpcp_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, vpcp_cloneattach),
	DEVMETHOD(ifdi_attach_post, vpcp_attach_post),
	DEVMETHOD(ifdi_detach, vpcp_detach),
	DEVMETHOD(ifdi_init, vpcp_init),
	DEVMETHOD(ifdi_stop, vpcp_stop),
	DEVMETHOD(ifdi_object_info_get, vpcp_object_info_get),
	DEVMETHOD_END
};

static driver_t vpcp_iflib_driver = {
	"vpcp", vpcp_if_methods, sizeof(struct vpcp_softc)
};

char vpcp_driver_version[] = "0.0.1";

static struct if_shared_ctx vpcp_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_driver_version = vpcp_driver_version,
	.isc_driver = &vpcp_iflib_driver,
	.isc_flags = IFLIB_PSEUDO,
	.isc_name = "vpcp",
};

if_shared_ctx_t vpcp_sctx = &vpcp_sctx_init;


static if_pseudo_t vpcp_pseudo;	

static int
vpcp_module_init(void)
{
	vpcp_pseudo = iflib_clone_register(vpcp_sctx);

	return vpcp_pseudo != NULL ? 0 : ENXIO;
}

static void
vpcp_module_deinit(void)
{
	iflib_clone_deregister(vpcp_pseudo);
}

static int
vpcp_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
	case MOD_LOAD:
		if ((err = vpcp_module_init()) != 0)
			return (err);
		break;
	case MOD_UNLOAD:
		if (clone_count == 0)
			vpcp_module_deinit();
		else
			return (EBUSY);
		break;
	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t vpcp_moduledata = {
	"vpcp",
	vpcp_module_event_handler,
	NULL
};

DECLARE_MODULE(vpcp, vpcp_moduledata, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(vpcp, 1);
MODULE_DEPEND(vpcp, iflib, 1, 1, 1);
MODULE_DEPEND(vpcp, ipfw, 3, 3, 3);
