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

/*
 * ifconfig ixl0 alias 10.1.3.4
 *
 * # Virtual Private Cloud
 * ifconfig vpc0 create
 * ifconfig vpc0 az az0
 * ifconfig vpc0 listen 10.1.3.4:3947
 *
 * ifconfig vmb0 addm vpc0
 *
 */

static MALLOC_DEFINE(M_VPC, "vpc", "virtual private cloud");

struct vpc_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
	struct ifnet *vs_ifparent;
	if_transmit_fn_t vs_parent_transmit;   /* initiate output routine */
};

static int clone_count;

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

static int
vpc_transmit(if_t ifp, struct mbuf *m)
{
	if_ctx_t ctx = ifp->if_softc;
	struct vpc_softc *vs = iflib_get_softc(ctx);
	struct ifnet *parent = vs->vs_ifparent;
	struct mbuf *mp, *mnext;
	int lasterr, rc;

	if (__predict_false(parent == NULL)) {
		m_freechain(m);
		return (ENXIO);
	}
	/* check for M_VLANTAG do encap */

	if (__predict_true(parent->if_capabilities & IFCAP_TXBATCH))
		return (vs->vs_parent_transmit(vs->vs_ifparent, m));

	mp = m;
	lasterr = 0;
	do {
		mnext = mp->m_nextpkt;
		mp->m_nextpkt = NULL;
		rc = vs->vs_parent_transmit(vs->vs_ifparent, m);
		if (rc)
			lasterr = rc;
		mp = mnext;
	} while (mp != NULL);

	return (lasterr);
}

static int
vpc_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct vpc_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;

	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	vs->vs_ctx = ctx;
	atomic_add_int(&clone_count, 1);
	return (0);
}

static int
vpc_attach_post(if_ctx_t ctx)
{
	struct ifnet *ifp;

	ifp = iflib_get_ifp(ctx);

	ifp->if_transmit = vpc_transmit;
	return (0);
}

static int
vpc_detach(if_ctx_t ctx)
{
	atomic_add_int(&clone_count, -1);
	return (0);
}

static void
vpc_init(if_ctx_t ctx)
{
}

static void
vpc_stop(if_ctx_t ctx)
{
}

static int
vpc_set_listen(struct vpc_softc *vs, struct vpc_listen *vl)
{
	/*
	 * Resolve IP -> interface
	 * - check for IFCAP_VXLANDECAP on interface
	 * - check that interface doesn't already have DECAP enabled
	 * - set port & ip on interface
	 * - set interface as parent
	 */

	return (ENOTSUP);
}

static int
vpc_priv_ioctl(if_ctx_t ctx, u_long command, caddr_t data)
{
	struct vpc_softc *vs = iflib_get_softc(ctx);
	struct ifreq *ifr = (struct ifreq *)data;
	struct ifreq_buffer *ifbuf = &ifr->ifr_ifru.ifru_buffer;
	struct vpc_ioctl_header *ioh =
	    (struct vpc_ioctl_header *)(ifbuf->buffer);
	int rc = ENOTSUP;
	struct vpc_ioctl_data *iod = NULL;

	if (command != SIOCGPRIVATE_0)
		return (EINVAL);

	if ((rc = priv_check(curthread, PRIV_DRIVER)) != 0)
		return (rc);
#ifdef notyet
	/* need sx lock for iflib context */
	iod = malloc(ifbuf->length, M_VPC, M_WAITOK | M_ZERO);
#endif
	iod = malloc(ifbuf->length, M_VPC, M_NOWAIT | M_ZERO);
	copyin(ioh, iod, ifbuf->length);

	switch (ioh->vih_type) {
		case VPC_LISTEN:
			rc = vpc_set_listen(vs, (struct vpc_listen *)iod);
			break;
		default:
			rc = ENOIOCTL;
			break;
	}
	free(iod, M_VPC);
	return (rc);
}

static device_method_t vpc_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, vpc_cloneattach),
	DEVMETHOD(ifdi_attach_post, vpc_attach_post),
	DEVMETHOD(ifdi_detach, vpc_detach),
	DEVMETHOD(ifdi_init, vpc_init),
	DEVMETHOD(ifdi_stop, vpc_stop),
	DEVMETHOD(ifdi_priv_ioctl, vpc_priv_ioctl),
	DEVMETHOD_END
};

static driver_t vpc_iflib_driver = {
	"vpc", vpc_if_methods, sizeof(struct vpc_softc)
};

char vpc_driver_version[] = "0.0.1";

static struct if_shared_ctx vpc_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_driver_version = vpc_driver_version,
	.isc_driver = &vpc_iflib_driver,
	.isc_flags = 0,
	.isc_name = "vpc",
};

if_shared_ctx_t vpc_sctx = &vpc_sctx_init;


static if_pseudo_t vpc_pseudo;	

static int
vpc_module_init(void)
{
	vpc_pseudo = iflib_clone_register(vpc_sctx);

	return (vpc_pseudo != NULL);
}

static int
vpc_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
		case MOD_LOAD:
			if ((err = vpc_module_init()) != 0)
				return (err);
			break;
		case MOD_UNLOAD:
			if (clone_count == 0)
				iflib_clone_deregister(vpc_pseudo);
			else
				return (EBUSY);
			break;
		default:
			return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t vpc_moduledata = {
	"vpc",
	vpc_module_event_handler,
	NULL
};

DECLARE_MODULE(vpc, vpc_moduledata, SI_SUB_INIT_IF, SI_ORDER_ANY);
MODULE_VERSION(vpc, 1);
MODULE_DEPEND(vpc, iflib, 1, 1, 1);
