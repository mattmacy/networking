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
struct vpcp_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
	struct ifnet *vs_ifparent;
	struct ifnet *vs_ifswitch;
	uint32_t vs_mflags;
	uint32_t vs_vxlanid;
	uint16_t vs_vlanid;
	enum vpcp_port_type vs_type;
};

static int clone_count;

static int
vpcp_stub_transmit(if_t ifp __unused, struct mbuf *m)
{
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
vmi_txflags(struct mbuf *m, struct vpc_pkt_info *vpi)
{
	m->m_pkthdr.tso_segsz = m->m_pkthdr.fibnum;
	m->m_pkthdr.l2hlen = vpi->vpi_l2_len;
	m->m_pkthdr.l3hlen = vpi->vpi_l3_len;
	m->m_pkthdr.l4hlen = vpi->vpi_l4_len;
	m->m_pkthdr.fibnum = 0;
}

static void
vmi_input_process(struct ifnet *ifp, struct mbuf *m, bool setid)
{
	struct vpcp_softc *vs;
	struct vpc_pkt_info vpi;
	caddr_t hdr;
	//vni = (vs->vs_flags & VS_VXLANTAG) ? vs->vs_vni : 0;

	vs = iflib_get_softc(ifp->if_softc);
	do {
		/* set mbuf flags for transmit */
		ETHER_BPF_MTAP(ifp, m);
		hdr = mtod(m, caddr_t);
		vpc_parse_pkt(m, &vpi);
		vmi_txflags(m, &vpi);
		if (setid) {
			m->m_flags |= vs->vs_mflags;
			m->m_pkthdr.vxlanid = vs->vs_vxlanid;
			m->m_pkthdr.ether_vtag = vs->vs_vlanid;
		}
		m = m->m_nextpkt;
	} while (m != NULL);
}

static int
vmi_transmit(if_t ifp, struct mbuf *m)
{
	int rc;

	MPASS(ifp->if_bridge);
	/*
	 * Preprocess
	 */
	vmi_input_process(ifp, m, true);
	
	BRIDGE_OUTPUT(ifp, m, rc);
	return (rc);
}

static void
vmi_input(if_t ifp, struct mbuf *m)
{
	struct vpcp_softc *vs;

	vmi_input_process(ifp, m, false);
	vs = iflib_get_softc((if_ctx_t)ifp->if_softc);
	(void)vs->vs_ifparent->if_transmit_txq(vs->vs_ifparent, m);
}

static int
phys_transmit(if_t ifp __unused, struct mbuf *m)
{
	panic("%s should not be called\n", __func__);
	m_freechain(m);
	return (0);
}

/*
 * Egress -- from switch (i.e. switch output -> NIC input)
 */
static void
phys_input(struct ifnet *ifport, struct mbuf *m)
{
	if_ctx_t ctx = ifport->if_softc;
	struct vpcp_softc *vs = iflib_get_softc(ctx);
	struct ifnet *ifparent = vs->vs_ifparent;
	struct mbuf *mp, *mnext;
	int qid;
	bool batch;

	mp = m->m_nextpkt;
	qid = ifparent->if_mbuf_to_qid(ifparent, m);
	batch = true;
	while (mp) {
		mp->m_pkthdr.rcvif = NULL;
		if (ifparent->if_mbuf_to_qid(ifparent, m) != qid)
			batch = false;
	}
	if (__predict_true(batch)) {
		vs->vs_ifparent->if_transmit_txq(vs->vs_ifparent, m);
	} else {
		mp = m;
		do {
			mnext = mp->m_nextpkt;
			mp->m_nextpkt = NULL;
			vs->vs_ifparent->if_transmit_txq(vs->vs_ifparent, mp);
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
		mp->m_flags |= M_TRUNK;
		if (__predict_false(ETHER_IS_MULTICAST(eh->ether_dhost) &&
							!(m->m_flags & M_VXLANTAG|M_VLANTAG))) {
			/* Order doesn't matter for broadcast packets */
			mp->m_nextpkt = mret;
			mret = mp;
		} else if (mh == NULL) {
			mh = mt = mp;
		} else {
			mt->m_nextpkt = mp;
			mt = mp;
		}
		mp = mnext;
	} while (mp);

	ifswitch = vs->vs_ifswitch;
	if (__predict_true(mh != NULL))
		ifswitch->if_transmit_txq(ifswitch, mh);
	if (__predict_false((mret != NULL) && ifswitch->if_transmit_txq(ifswitch, mret)))
		return (NULL);
	return (mret);
}

int
vpcp_port_type_set(if_ctx_t portctx, struct ifnet *devifp, enum vpcp_port_type type)
{
	struct ifnet *ifp;
	struct vpcp_softc *vs;
	enum vpcp_port_type prevtype;
	int rc;

#ifdef INVARIANTS
	if (type == VPCP_TYPE_NONE)
		MPASS(devifp == NULL);
	else
		MPASS(devifp != NULL);
#endif

	ifp = iflib_get_ifp(portctx);
	vs = iflib_get_softc(portctx);
	vs->vs_ifparent = devifp;
	prevtype = vs->vs_type;
	vs->vs_type = type;
	rc = 0;

	if (devifp->if_bridge != NULL) {
		printf("%s in use\n", devifp->if_xname);
		return (EINVAL);
	}
	devifp->if_bridge = NULL;
	devifp->if_bridge_input = NULL;
	devifp->if_bridge_output = NULL;

	switch (type) {
		case VPCP_TYPE_NONE:
			if_settransmitfn(ifp, vpcp_stub_transmit);
			if_settransmittxqfn(ifp, vpcp_stub_transmit);
			ifp->if_input = vpcp_stub_input;
			break;
		case VPCP_TYPE_VMI:
			if_settransmitfn(ifp, vmi_transmit);
			if_settransmittxqfn(ifp, vmi_transmit);
			ifp->if_input = vmi_input;
			break;
		case VPCP_TYPE_PHYS:
			if_settransmitfn(ifp, phys_transmit);
			if_settransmittxqfn(ifp, phys_transmit);
			if_setmbuftoqidfn(ifp, phys_mbuf_to_qid);
			ifp->if_input = phys_input;
			devifp->if_bridge = vs;
			devifp->if_bridge_input = phys_bridge_input;
			devifp->if_bridge_output = phys_bridge_output;
			break;
		default:
			vs->vs_type = prevtype;
			device_printf(iflib_get_dev(portctx), "unknown port type %d\n", type);
			rc = EINVAL;
	}
	return (rc);
}

enum vpcp_port_type
vpcp_port_type_get(if_ctx_t ctx)
{
	struct vpcp_softc *vs;

	vs = iflib_get_softc(ctx);
	return (vs->vs_type);
}

#define VPCP_CAPS														\
	IFCAP_TSO | IFCAP_HWCSUM | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM |	\
	IFCAP_VLAN_HWTSO | IFCAP_VLAN_MTU | IFCAP_TXCSUM_IPV6 | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU | \
	IFCAP_LINKSTATE

static int
vpcp_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct vpcp_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;

	atomic_add_int(&clone_count, 1);
	vs->vs_ctx = ctx;

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
	return (0);
}

static int
vpcp_detach(if_ctx_t ctx)
{
	struct vpcp_softc *vs = iflib_get_softc(ctx);

	if (vs->vs_ifparent != NULL)
		if_rele(vs->vs_ifparent);
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

void
vpcp_set_ifparent(if_ctx_t ctx, if_t ifp)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	if (ifp != vs->vs_ifparent) {
		if_rele(vs->vs_ifparent);
		if_ref(ifp);
	}
	vs->vs_ifparent = ifp;
	iflib_get_ifp(vs->vs_ctx)->if_mtu = ifp->if_mtu;
	iflib_link_state_change(vs->vs_ctx, LINK_STATE_UP, IF_Gbps(50));
}

if_t
vpcp_get_ifparent(if_ctx_t ctx)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	return (vs->vs_ifparent);
}

void
vpcp_clear_ifparent(if_ctx_t ctx)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	if (vs->vs_ifparent == NULL)
		return;
	if_rele(vs->vs_ifparent);
	vs->vs_ifparent = NULL;
	iflib_link_state_change(vs->vs_ctx, LINK_STATE_DOWN, 0);
}

void
vpcp_set_vxlanid(if_ctx_t ctx, uint32_t vxlanid)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	if (vxlanid)
		vs->vs_mflags |= M_VXLANTAG;
	vs->vs_vxlanid = vxlanid;
}

uint32_t
vpcp_get_vxlanid(if_ctx_t ctx)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	return (vs->vs_vxlanid);
}

void
vpcp_set_vlanid(if_ctx_t ctx, uint16_t vlanid)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	if (vlanid)
		vs->vs_mflags |= M_VLANTAG;
	vs->vs_vlanid = vlanid;
}

uint16_t
vpcp_get_vlanid(if_ctx_t ctx)
{
	struct vpcp_softc *vs = ctx_to_vs(ctx);

	return (vs->vs_vlanid);
}

static device_method_t vpcp_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, vpcp_cloneattach),
	DEVMETHOD(ifdi_attach_post, vpcp_attach_post),
	DEVMETHOD(ifdi_detach, vpcp_detach),
	DEVMETHOD(ifdi_init, vpcp_init),
	DEVMETHOD(ifdi_stop, vpcp_stop),
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

DECLARE_MODULE(vpcp, vpcp_moduledata, SI_SUB_INIT_IF, SI_ORDER_ANY);
MODULE_VERSION(vpcp, 1);
MODULE_DEPEND(vpcp, iflib, 1, 1, 1);
