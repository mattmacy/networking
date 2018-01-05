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
#include <net/if_media.h>

#include <net/if_vpc.h>

#include "ifdi_if.h"

static MALLOC_DEFINE(M_VPCI, "vpci", "virtual private cloud interface");


#define VPCI_DEBUG

#ifdef VPCI_DEBUG
#define  DPRINTF printf
#else
#define DPRINTF(...)
#endif

/*
 * ifconfig vpci0 create
 * ifconfig vpci0 192.168.0.100
 * ifconfig vpci0 attach vpc0
 */

struct vpci_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
	struct ifnet *vs_ifparent;
	uint32_t vs_vni;
};

static int clone_count;

static int
vpci_mbuf_to_qid(if_t ifp __unused, struct mbuf *m __unused)
{
	return (0);
}

static int
vpci_transmit(if_t ifp, struct mbuf *m)
{
	struct mbuf *mp, *mnext, *mh, *mt, *mtmp;
	if_ctx_t ctx = ifp->if_softc;
	struct vpci_softc *vs = iflib_get_softc(ctx);
	struct ifnet *parent = vs->vs_ifparent;

	if (__predict_false(vs->vs_ifparent == NULL)) {
		m_freechain(m);
		DPRINTF("freeing without parent\n");
		return (ENOBUFS);
	}
	mp = m;
	mh = mt = NULL;
	while (mp) {
		mnext = mp->m_nextpkt;
		mp->m_flags |= M_VXLANTAG;
		mp->m_pkthdr.vxlanid = vs->vs_vni;
		if ((mp->m_pkthdr.csum_flags & CSUM_TSO) &&
			!((mp->m_flags & M_EXT) && (mp->m_ext.ext_type == EXT_MVEC))) {
			mp->m_nextpkt = NULL;
			mtmp = mchain_to_mvec(mp, M_NOWAIT);
			if (__predict_false(mtmp == NULL)) {
				m_freem(mp);
				mp = mnext;
				continue;
			}
			mp = mtmp;
		}
		if (mt == NULL) {
			mh = mt = mp;
		} else {
			mt->m_nextpkt = mp;
			mt = mp;
		}
		mp = mnext;
	}

	return (parent->if_transmit_txq(parent, mh));
}

#define VPCI_CAPS														\
	IFCAP_TSO | IFCAP_HWCSUM | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM |	\
	IFCAP_VLAN_HWTSO | IFCAP_VLAN_MTU | IFCAP_TXCSUM_IPV6 | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU | \
	IFCAP_LINKSTATE

static int
vpci_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct vpci_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;

	atomic_add_int(&clone_count, 1);
	vs->vs_ctx = ctx;

	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	scctx->isc_capenable = VPCI_CAPS;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
		| CSUM_IP6_UDP | CSUM_IP6_TCP;
	return (0);
}

static int
vpci_attach_post(if_ctx_t ctx)
{
	struct ifnet *ifp;

	ifp = iflib_get_ifp(ctx);
	if_settransmitfn(ifp, vpci_transmit);
	if_settransmittxqfn(ifp, vpci_transmit);
	if_setmbuftoqidfn(ifp, vpci_mbuf_to_qid);
	return (0);
}

static int
vpci_detach(if_ctx_t ctx)
{
	struct vpci_softc *vs = iflib_get_softc(ctx);

	if (vs->vs_ifparent != NULL)
		if_rele(vs->vs_ifparent);
	atomic_add_int(&clone_count, -1);

	return (0);
}

static void
vpci_init(if_ctx_t ctx)
{
}

static void
vpci_stop(if_ctx_t ctx)
{
}

static int
vpci_set_ifparent(struct vpci_softc *vs, struct vpci_attach *va)
{
	struct ifnet *ifp;

	if ((ifp = ifunit_ref(va->va_ifname)) == NULL)
		return (ENXIO);
	if (ifp == vs->vs_ifparent)
		if_rele(ifp);
	else if (vs->vs_ifparent)
		if_rele(vs->vs_ifparent);
	vs->vs_ifparent = ifp;

	iflib_get_ifp(vs->vs_ctx)->if_mtu = ifp->if_mtu;
	iflib_link_state_change(vs->vs_ctx, LINK_STATE_UP, IF_Gbps(50));
	return (0);
}

static int
vpci_get_ifparent(struct vpci_softc *vs, struct vpci_attach *va)
{
	if (vs->vs_ifparent == NULL)
		return (ENOENT);
	bcopy(vs->vs_ifparent->if_xname, va->va_ifname, IFNAMSIZ);
	return (0);
}

static void
vpci_clear_ifparent(struct vpci_softc *vs)
{
	if (vs->vs_ifparent == NULL)
		return;
	if_rele(vs->vs_ifparent);
	vs->vs_ifparent = NULL;
	iflib_link_state_change(vs->vs_ctx, LINK_STATE_DOWN, 0);
}


static void
vpci_vni(struct vpci_softc *vs, struct vpci_vni *vv, int set)
{
	if (set)
		vs->vs_vni = vv->vv_vni;
	else
		vv->vv_vni = vs->vs_vni;
}

static int
vpci_priv_ioctl(if_ctx_t ctx, u_long command, caddr_t data)
{
	struct vpci_softc *vs = iflib_get_softc(ctx);
	struct ifreq *ifr = (struct ifreq *)data;
	struct ifreq_buffer *ifbuf = &ifr->ifr_ifru.ifru_buffer;
	struct vpc_ioctl_header *ioh =
	    (struct vpc_ioctl_header *)(ifbuf->buffer);
	int rc = 0;
	struct vpci_ioctl_data *iod = NULL;

	if (command != SIOCGPRIVATE_0)
		return (EINVAL);

	if ((rc = priv_check(curthread, PRIV_DRIVER)) != 0)
		return (rc);
	/*
	 * XXX --- need to make sure that nothing is in transmit
	 * while we're fiddling with state
	 *
	 */

#ifdef notyet
	/* need sx lock for iflib context */
	iod = malloc(ifbuf->length, M_VPCI, M_WAITOK | M_ZERO);
#endif
	if (IOCPARM_LEN(ioh->vih_type) != ifbuf->length) {
		DPRINTF("IOCPARM_LEN: %d ifbuf->length: %d\n",
			   (int)IOCPARM_LEN(ioh->vih_type), (int)ifbuf->length);
		return (EINVAL);
	}
	iod = malloc(ifbuf->length, M_VPCI, M_NOWAIT | M_ZERO);
	if (iod == NULL)
		return (ENOMEM);
	rc = copyin(ioh, iod, ifbuf->length);
	if (rc) {
		free(iod, M_VPCI);
		return (rc);
	}
	switch (ioh->vih_type) {
		case VPCI_ATTACH:
			rc = vpci_set_ifparent(vs, (struct vpci_attach *)iod);
			break;
		case VPCI_ATTACHED_GET:
			rc = vpci_get_ifparent(vs, (struct vpci_attach *)iod);
			if (!rc)
				rc = copyout(iod, ioh, sizeof(struct vpci_attach));
			break;
		case VPCI_DETACH:
			vpci_clear_ifparent(vs);
			break;
		case VPCI_VNI_SET:
			vpci_vni(vs, (struct vpci_vni *)iod, 1);
			break;
		case VPCI_VNI_GET:
			vpci_vni(vs, (struct vpci_vni *)iod, 0);
			rc = copyout(iod, ioh, sizeof(struct vpci_vni));
			break;
		default:
			rc = ENOIOCTL;
			break;
	}
	free(iod, M_VPCI);
	return (rc);
}

static device_method_t vpci_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, vpci_cloneattach),
	DEVMETHOD(ifdi_attach_post, vpci_attach_post),
	DEVMETHOD(ifdi_detach, vpci_detach),
	DEVMETHOD(ifdi_init, vpci_init),
	DEVMETHOD(ifdi_stop, vpci_stop),
	DEVMETHOD(ifdi_priv_ioctl, vpci_priv_ioctl),
	DEVMETHOD_END
};

static driver_t vpci_iflib_driver = {
	"vpci", vpci_if_methods, sizeof(struct vpci_softc)
};

char vpci_driver_version[] = "0.0.1";

static struct if_shared_ctx vpci_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_driver_version = vpci_driver_version,
	.isc_driver = &vpci_iflib_driver,
	.isc_flags = IFLIB_PSEUDO,
	.isc_name = "vpci",
};

if_shared_ctx_t vpci_sctx = &vpci_sctx_init;


static if_pseudo_t vpci_pseudo;	

static int
vpci_module_init(void)
{
	vpci_pseudo = iflib_clone_register(vpci_sctx);

	return vpci_pseudo != NULL ? 0 : ENXIO;
}

static void
vpci_module_deinit(void)
{
	iflib_clone_deregister(vpci_pseudo);
}

static int
vpci_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
	case MOD_LOAD:
		if ((err = vpci_module_init()) != 0)
			return (err);
		break;
	case MOD_UNLOAD:
		if (clone_count == 0)
			vpci_module_deinit();
		else
			return (EBUSY);
		break;
	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t vpci_moduledata = {
	"vpci",
	vpci_module_event_handler,
	NULL
};

DECLARE_MODULE(vpci, vpci_moduledata, SI_SUB_INIT_IF, SI_ORDER_ANY);
MODULE_VERSION(vpci, 1);
MODULE_DEPEND(vpci, iflib, 1, 1, 1);
