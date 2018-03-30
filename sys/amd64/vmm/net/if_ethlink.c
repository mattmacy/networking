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
#include <net/if_media.h>

#include <net/if_vpc.h>

#include "ifdi_if.h"

static MALLOC_DEFINE(M_ETHLINK, "ethlink", "virtual private cloud interface");


#define ETHLINK_DEBUG

#ifdef ETHLINK_DEBUG
#define  DPRINTF printf
#else
#define DPRINTF(...)
#endif

static int ethlink_transmit(if_t ifp, struct mbuf *m);

struct ethlink_softc {
	if_softc_ctx_t shared;
	if_ctx_t es_ctx;
	struct ifnet *es_ifp;
	struct ifnet *es_underlay_ifp;
	uint32_t es_mflags;
	uint16_t es_vtag;
};

static int clone_count;

static int
ethlink_mbuf_to_qid(if_t ifp __unused, struct mbuf *m __unused)
{
	return (0);
}

static void
ethlink_disconnect(struct ethlink_softc *es)
{
	struct ifnet *oifp = es->es_underlay_ifp;

	if (oifp) {
		oifp->if_bridge = NULL;
		oifp->if_bridge_input = NULL;
		oifp->if_bridge_output = NULL;
		oifp->if_bridge_linkstate = NULL;
		oifp->if_capabilities &= ~IFCAP_BRIDGE_BATCH;
		if_rele(oifp);
		es->es_underlay_ifp = NULL;
	}
}

#define ETHLINK_CAPS														\
	IFCAP_TSO | IFCAP_HWCSUM | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM |	\
	IFCAP_VLAN_HWTSO | IFCAP_VLAN_MTU | IFCAP_TXCSUM_IPV6 | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU | \
	IFCAP_LINKSTATE

static int
ethlink_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct ethlink_softc *es = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;

	atomic_add_int(&clone_count, 1);
	es->es_ctx = ctx;
	es->es_ifp = iflib_get_ifp(ctx);
	scctx = es->shared = iflib_get_softc_ctx(ctx);
	scctx->isc_capenable = ETHLINK_CAPS;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
		| CSUM_IP6_UDP | CSUM_IP6_TCP;
	return (0);
}

static int
ethlink_attach_post(if_ctx_t ctx)
{
	struct ifnet *ifp;

	ifp = iflib_get_ifp(ctx);
	if_settransmitfn(ifp, ethlink_transmit);
	if_settransmittxqfn(ifp, ethlink_transmit);
	if_setmbuftoqidfn(ifp, ethlink_mbuf_to_qid);
	return (0);
}

static int
ethlink_detach(if_ctx_t ctx)
{
	struct ethlink_softc *es = iflib_get_softc(ctx);

	if (es->es_ifp->if_bridge)
		vpcp_port_disconnect_ifp(es->es_ifp);
	ethlink_disconnect(es);
	atomic_add_int(&clone_count, -1);

	return (0);
}

static void
ethlink_init(if_ctx_t ctx)
{
}

static void
ethlink_stop(if_ctx_t ctx)
{
}

struct ifnet *
ethlink_ifp_get(if_ctx_t ctx)
{
	struct ethlink_softc *es = iflib_get_softc(ctx);

	return (es->es_underlay_ifp);
}

static int
ethlink_transmit(if_t ifp, struct mbuf *m)
{
	struct ifnet *oifp;
	if_ctx_t ctx;
	struct ethlink_softc *es;
	struct mbuf *mp, *mnext;
	bool can_batch;
	int lasterr, rc, qid;

	ctx = ifp->if_softc;
	es = iflib_get_softc(ctx);
	oifp = es->es_underlay_ifp;
	can_batch = true;
	if (bpf_peers_present(ifp->if_bpf)) {
		mp = m;
		do {
			ETHER_BPF_MTAP(ifp, mp);
			mp = mp->m_nextpkt;
		} while (mp);
	}
	if (__predict_false(oifp == NULL)) {
		m_freechain(m);
		return (ENOBUFS);
	}
	MPASS(ifp == es->es_ifp);
	if (es->es_vtag) {
		m->m_flags |= M_VLANTAG;
		m->m_pkthdr.ether_vtag = es->es_vtag;
	}
	m->m_pkthdr.rcvif = NULL;
	qid = oifp->if_mbuf_to_qid(oifp, m);
	mp = m->m_nextpkt;
	while (mp) {
		if (es->es_vtag) {
			mp->m_flags |= M_VLANTAG;
			mp->m_pkthdr.ether_vtag = es->es_vtag;
		}
		if (can_batch && (qid != oifp->if_mbuf_to_qid(oifp, m)))
			can_batch = false;
		mp->m_pkthdr.rcvif = NULL;
		mp = mp->m_nextpkt;
	}
	if (can_batch)
		return (oifp->if_transmit_txq(oifp, m));

	do {
		mnext = mp->m_nextpkt;
		mp->m_nextpkt = NULL;
		rc = oifp->if_transmit_txq(oifp, mp);
		if (rc)
			lasterr = rc;
		mp = mnext;
	} while (mp != NULL);
	return (lasterr);
}

static struct mbuf *
ethlink_bridge_input(if_t ifp, struct mbuf *m)
{
	struct ethlink_softc *es;
	struct mbuf *mp, *mh, *mt, *mnext;

	es = ifp->if_bridge;
	if (es->es_ifp->if_bridge == NULL)
		return (m);
	mh = mt = NULL;
	mp = m;
	do {
		mnext = mp->m_nextpkt;
		mp->m_nextpkt = NULL;
		if (mp->m_flags & M_VLANTAG) {
			if (__predict_false(mp->m_pkthdr.ether_vtag != es->es_vtag)) {
				m_freem(mp);
				goto next;
			}
			mp->m_flags &= ~M_VLANTAG;
			mp->m_pkthdr.ether_vtag = 0;
		}
		mp->m_flags |= M_TRUNK;
		if (mh != NULL) {
			mt->m_nextpkt = mp;
			mt = mp;
		} else
			mh = mt = mp;
	next:
		mp = mnext;
	} while (mp != NULL);
	if (__predict_false(mh == NULL))
		return (NULL);

	return (*(es->es_ifp)->if_bridge_input)(es->es_ifp, mh);
}

static int
ethlink_bridge_output(struct ifnet *ifp, struct mbuf *m,
					  struct sockaddr *s __unused, struct rtentry *r__unused)
{
	struct ethlink_softc *es;

	es = ifp->if_bridge;
	return (ethlink_transmit(es->es_ifp, m));
}

static void
ethlink_bridge_linkstate(struct ifnet *ifp __unused)
{
}

int
ethlink_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
				 size_t *outlen, void **outdata)
{
	if_ctx_t ifctx = ctx->v_ifp->if_softc;
	struct ethlink_softc *es;
	struct sockaddr_dl *sdl;
	char buf[IFNAMSIZ];
	int rc;

	rc = 0;
	es = iflib_get_softc(ifctx);
	switch (op) {
		case VPC_ETHLINK_OP_CONNECT: {
			struct ifnet *ifp;

			ethlink_disconnect(es);
			bzero(buf, IFNAMSIZ);
			strncpy(buf, in, min(inlen, IFNAMSIZ-1));
			if ((ifp = ifunit_ref(buf)) == NULL)
				return (ENOENT);
			if (ifp->if_addr == NULL) {
				if_rele(ifp);
				return (ENXIO);
			}
			sdl = (struct sockaddr_dl *)ifp->if_addr->ifa_addr;
			if (sdl->sdl_type == IFT_ETHER)
				iflib_set_mac(ifctx, LLADDR(sdl));
			es->es_ifp->if_capabilities = ifp->if_capabilities;
			es->es_underlay_ifp = ifp;
			ifp->if_capabilities |= IFCAP_BRIDGE_BATCH;
			ifp->if_bridge_input = ethlink_bridge_input;
			ifp->if_bridge_output = ethlink_bridge_output;
			ifp->if_bridge_linkstate = ethlink_bridge_linkstate;
			wmb();
			ifp->if_bridge = es;
			break;
		}
		case VPC_ETHLINK_OP_DISCONNECT:
			ethlink_disconnect(es);
			break;
		case VPC_ETHLINK_OP_CONNECTED_NAME_GET: {
			char *ifname;

			if (*outlen < IFNAMSIZ)
				return (EOVERFLOW);
			if (es->es_underlay_ifp == NULL)
				return (EAGAIN);
			ifname = malloc(IFNAMSIZ, M_TEMP, M_WAITOK|M_ZERO);
			strncpy(ifname, es->es_underlay_ifp->if_xname, IFNAMSIZ);
			*outdata = ifname;
			*outlen = IFNAMSIZ;
			break;
		}
		case VPC_ETHLINK_OP_VTAG_GET: {
			uint16_t *out;

			out = malloc(sizeof(uint16_t), M_TEMP, M_WAITOK);
			*outlen = sizeof(uint16_t);
			*out = es->es_vtag;
			*outdata = out;
			break;
		}
		case VPC_ETHLINK_OP_VTAG_SET: {
			uint16_t vtag;

			if (inlen != sizeof(uint16_t))
				return (EBADRPC);
			vtag = *(const uint16_t *)in;
			es->es_vtag = vtag;
			break;
		}
		default:
			rc = EOPNOTSUPP;
			break;
	}
	return (rc);
}

static device_method_t ethlink_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, ethlink_cloneattach),
	DEVMETHOD(ifdi_attach_post, ethlink_attach_post),
	DEVMETHOD(ifdi_detach, ethlink_detach),
	DEVMETHOD(ifdi_init, ethlink_init),
	DEVMETHOD(ifdi_stop, ethlink_stop),
	DEVMETHOD_END
};

static driver_t ethlink_iflib_driver = {
	"ethlink", ethlink_if_methods, sizeof(struct ethlink_softc)
};

char ethlink_driver_version[] = "0.0.1";

static struct if_shared_ctx ethlink_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_driver_version = ethlink_driver_version,
	.isc_driver = &ethlink_iflib_driver,
	.isc_flags = IFLIB_PSEUDO,
	.isc_name = "ethlink",
};

if_shared_ctx_t ethlink_sctx = &ethlink_sctx_init;


static if_pseudo_t ethlink_pseudo;

static int
ethlink_module_init(void)
{
	ethlink_pseudo = iflib_clone_register(ethlink_sctx);

	return ethlink_pseudo != NULL ? 0 : ENXIO;
}

static void
ethlink_module_deinit(void)
{
	iflib_clone_deregister(ethlink_pseudo);
}

static int
ethlink_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
	case MOD_LOAD:
		if ((err = ethlink_module_init()) != 0)
			return (err);
		break;
	case MOD_UNLOAD:
		if (clone_count == 0)
			ethlink_module_deinit();
		else
			return (EBUSY);
		break;
	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t ethlink_moduledata = {
	"ethlink",
	ethlink_module_event_handler,
	NULL
};

DECLARE_MODULE(ethlink, ethlink_moduledata, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(ethlink, 1);
MODULE_DEPEND(ethlink, iflib, 1, 1, 1);
