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

#include <net/if_vpc.h>

#include "ifdi_if.h"

static MALLOC_DEFINE(M_VPCB, "vpcb", "virtual private cloud bridge");

/*
 * ifconfig vpcb0 create
 * ifconfig vpcb0 addm vpc0
 * ifconfig vpcb0 priority vpc0 200
 * ifconfig vpcb0 vpc-resolver 127.0.0.1:5000
 * ifconfig vpcb0 addm vmi7
 * ifconfig vpcb0 pathcost vmi7 2000000
 */

struct vpcb_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
};

#ifdef notyet
static void
m_freechain(struct mbuf *m)
{
	struct mbuf *mp, *mnext;

	mp = m;
	do {
		mnext = mp->m_nextpkt;
		m_freem(mp);
		mp = mnext;
	} while (mp != NULL);
}
#endif

static int
vpcb_transmit(if_t ifp, struct mbuf *m)
{
	/*
	 * - If ARP + VXLANTAG put in ck_ring and kick grouptask
	 * - If MAC address resolves to internal interface call interface transmit
	 * - If unknown pass packet out lowest cost interface
	 */

	return (ENXIO);
}

static int
vpcb_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct vpcb_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;


	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	vs->vs_ctx = ctx;
	return (0);
}

static int
vpcb_attach_post(if_ctx_t ctx)
{
	struct ifnet *ifp;

	ifp = iflib_get_ifp(ctx);

	ifp->if_transmit = vpcb_transmit;
	return (0);
}

static int
vpcb_detach(if_ctx_t ctx)
{
	return (0);
}

static void
vpcb_init(if_ctx_t ctx)
{
}

static void
vpcb_stop(if_ctx_t ctx)
{
}

static int
vpcb_set_resolver(struct vpcb_softc *vs, struct vpcb_resolver *vr)
{
	/*
	 * Resolve IP -> interface
	 * allocate ck_ring and grouptask
	 */

	return (ENOTSUP);
}

static int
vpcb_priv_ioctl(if_ctx_t ctx, u_long command, caddr_t data)
{
	struct vpcb_softc *vs = iflib_get_softc(ctx);
	struct ifreq *ifr = (struct ifreq *)data;
	struct ifreq_buffer *ifbuf = &ifr->ifr_ifru.ifru_buffer;
	struct vpc_ioctl_header *ioh =
	    (struct vpc_ioctl_header *)(ifbuf->buffer);
	int rc = ENOTSUP;
	struct vpcb_ioctl_data *iod = NULL;

	if (command != SIOCGPRIVATE_0)
		return (EINVAL);

	if ((rc = priv_check(curthread, PRIV_DRIVER)) != 0)
		return (rc);
#ifdef notyet
	/* need sx lock for iflib context */
	iod = malloc(ifbuf->length, M_VPCB, M_WAITOK | M_ZERO);
#endif
	iod = malloc(ifbuf->length, M_VPCB, M_NOWAIT | M_ZERO);
	if (iod == NULL)
		return (ENOMEM);
	rc = copyin(ioh, iod, ifbuf->length);
	if (rc) {
		free(iod, M_VPC);
		return (rc);
	}
	switch (ioh->vih_type) {
		case VPCB_RESOLVER:
			rc = vpcb_set_resolver(vs, (struct vpcb_resolver *)iod);
			break;
		default:
			rc = ENOIOCTL;
			break;
	}
	free(iod, M_VPCB);
	return (rc);
}

static device_method_t vpcb_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, vpcb_cloneattach),
	DEVMETHOD(ifdi_attach_post, vpcb_attach_post),
	DEVMETHOD(ifdi_detach, vpcb_detach),
	DEVMETHOD(ifdi_init, vpcb_init),
	DEVMETHOD(ifdi_stop, vpcb_stop),
	DEVMETHOD(ifdi_priv_ioctl, vpcb_priv_ioctl),
	DEVMETHOD_END
};

static driver_t vpcb_iflib_driver = {
	"vpcb", vpcb_if_methods, sizeof(struct vpcb_softc)
};

char vpcb_driver_version[] = "0.0.1";

static struct if_shared_ctx vpcb_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_driver_version = vpcb_driver_version,
	.isc_driver = &vpcb_iflib_driver,
	.isc_flags = 0,
	.isc_name = "vpcb",
};

if_shared_ctx_t vpcb_sctx = &vpcb_sctx_init;


static if_pseudo_t vpcb_pseudo;	

static int
vpcb_module_init(void)
{
	vpcb_pseudo = iflib_clone_register(vpcb_sctx);

	return (vpcb_pseudo != NULL);
}

static int
vpcb_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
	case MOD_LOAD:
		if ((err = vpcb_module_init()) != 0)
			return (err);
		break;
	case MOD_UNLOAD:
		return (EBUSY);
	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t vpcb_moduledata = {
	"vpcb",
	vpcb_module_event_handler,
	NULL
};

DECLARE_MODULE(vpcb, vpcb_moduledata, SI_SUB_INIT_IF, SI_ORDER_ANY);
MODULE_VERSION(vpcb, 1);
MODULE_DEPEND(vpcb, iflib, 1, 1, 1);
