/*
 * Copyright (C) 2017-2018 Matthew Macy <mmacy@mattmacy.io>
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
#include <net/if_media.h>

#include <net/if_vpc.h>

#include "ifdi_if.h"

static MALLOC_DEFINE(M_HOSTIF, "hostif", "virtual private cloud interface");


#define HOSTIF_DEBUG

#ifdef HOSTIF_DEBUG
#define  DPRINTF printf
#else
#define DPRINTF(...)
#endif


static int soft_tso;
static SYSCTL_NODE(_net, OID_AUTO, hostif, CTLFLAG_RD, 0,
                   "hostif parameters");

SYSCTL_INT(_net_hostif, OID_AUTO, soft_tso, CTLFLAG_RW,
		   &soft_tso, 0, "enable soft tso");


struct hostif_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
};

static int clone_count;

static int
hostif_mbuf_to_qid(if_t ifp __unused, struct mbuf *m __unused)
{
	return (0);
}

static int
hostif_transmit(if_t ifp, struct mbuf *m)
{
	struct mbuf *mp = m;
	struct mbuf_ext *mext;

	do {
		ETHER_BPF_MTAP(ifp, mp);
		mp = mp->m_nextpkt;
	} while (mp);

	if (ifp->if_bridge == NULL) {
		m_freechain(m);
		return (ENOBUFS);
	}
	if (soft_tso) {
		mext = pktchain_to_mvec(m, ifp->if_mtu, M_NOWAIT);
		if (__predict_false(mext == NULL))
			return (ENOMEM);
		if (m->m_pkthdr.csum_flags & CSUM_TSO) {
			m = (void*)mvec_tso(mext, 0, true);
			if (__predict_false(m == NULL))
				return (ENOMEM);
		} else
			m = (void *)mext;
	}
	return ((*(ifp)->if_bridge_output)(ifp, m, NULL, NULL));
}

#define HOSTIF_CAPS														\
	IFCAP_TSO | IFCAP_HWCSUM | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM |	\
	IFCAP_VLAN_HWTSO | IFCAP_VLAN_MTU | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU | \
	IFCAP_LINKSTATE

static int
hostif_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct hostif_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;

	atomic_add_int(&clone_count, 1);
	vs->vs_ctx = ctx;

	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	scctx->isc_capenable = HOSTIF_CAPS;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
		| CSUM_IP6_UDP | CSUM_IP6_TCP;
	return (0);
}

static int
hostif_attach_post(if_ctx_t ctx)
{
	struct ifnet *ifp;

	ifp = iflib_get_ifp(ctx);
	if_settransmitfn(ifp, hostif_transmit);
	if_settransmittxqfn(ifp, hostif_transmit);
	if_setmbuftoqidfn(ifp, hostif_mbuf_to_qid);
	iflib_link_state_change(ctx, LINK_STATE_UP, IF_Gbps(50));
	return (0);
}

static int
hostif_detach(if_ctx_t ctx)
{
	iflib_link_state_change(ctx, LINK_STATE_DOWN, IF_Gbps(50));
	atomic_add_int(&clone_count, -1);
	return (0);
}

static void
hostif_init(if_ctx_t ctx)
{
}

static void
hostif_stop(if_ctx_t ctx)
{
}

int
hostif_ctl(vpc_ctx_t vctx, vpc_op_t op, size_t inlen, const void *in,
				 size_t *outlen, void **outdata)
{
	return (0);
}

static device_method_t hostif_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, hostif_cloneattach),
	DEVMETHOD(ifdi_attach_post, hostif_attach_post),
	DEVMETHOD(ifdi_detach, hostif_detach),
	DEVMETHOD(ifdi_init, hostif_init),
	DEVMETHOD(ifdi_stop, hostif_stop),
	DEVMETHOD_END
};

static driver_t hostif_iflib_driver = {
	"hostif", hostif_if_methods, sizeof(struct hostif_softc)
};

char hostif_driver_version[] = "0.0.1";

static struct if_shared_ctx hostif_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_driver_version = hostif_driver_version,
	.isc_driver = &hostif_iflib_driver,
	.isc_flags = IFLIB_PSEUDO,
	.isc_name = "hostif",
};

if_shared_ctx_t hostif_sctx = &hostif_sctx_init;


static if_pseudo_t hostif_pseudo;

static int
hostif_module_init(void)
{
	hostif_pseudo = iflib_clone_register(hostif_sctx);

	return hostif_pseudo != NULL ? 0 : ENXIO;
}

static void
hostif_module_deinit(void)
{
	iflib_clone_deregister(hostif_pseudo);
}

static int
hostif_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
	case MOD_LOAD:
		if ((err = hostif_module_init()) != 0)
			return (err);
		break;
	case MOD_UNLOAD:
		if (clone_count == 0)
			hostif_module_deinit();
		else
			return (EBUSY);
		break;
	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t hostif_moduledata = {
	"hostif",
	hostif_module_event_handler,
	NULL
};

DECLARE_MODULE(hostif, hostif_moduledata, SI_SUB_INIT_IF, SI_ORDER_ANY);
MODULE_VERSION(hostif, 1);
MODULE_DEPEND(hostif, iflib, 1, 1, 1);
