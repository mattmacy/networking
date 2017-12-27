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
#include <sys/jail.h>
#include <sys/md5.h>
#include <sys/proc.h>
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

static MALLOC_DEFINE(M_VPCI, "vpci", "virtual private cloud bridge");

/*
 * ifconfig vpci0 create
 * ifconfig vpci0 addm vpc0
 * ifconfig vpci0 priority vpc0 200
 * ifconfig vpci0 vpc-resolver 127.0.0.1:5000
 * ifconfig vpci0 addm vmi7
 * ifconfig vpci0 pathcost vmi7 2000000
 */

struct vpci_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
	struct ifnet *vs_ifparent;
	uint32_t vs_vni;
	uint8_t vs_mac[ETHER_ADDR_LEN];
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
vpci_transmit(if_t ifp, struct mbuf *m)
{
	if_ctx_t ctx = ifp->if_softc;
	struct vpci_softc *vs = iflib_get_softc(ctx);
	struct ifnet *parent = vs->vs_ifparent;
	
	m->m_flags |= M_VXLANTAG;
	m->m_pkthdr.vxlanid = vs->vs_vni;
	return (parent->if_transmit(parent, m));
}

static int
vpci_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct vpci_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;


	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	vs->vs_ctx = ctx;
	return (0);
}

static void
vpci_gen_mac(struct vpci_softc *vs)
{
	struct thread *td;
	struct ifnet *ifp;
	MD5_CTX mdctx;
	char uuid[HOSTUUIDLEN+1];
	char buf[HOSTUUIDLEN+16];
	unsigned char digest[16];

	td = curthread;
	ifp = iflib_get_ifp(vs->vs_ctx);
	uuid[HOSTUUIDLEN] = 0;
	bcopy(td->td_ucred->cr_prison->pr_hostuuid, uuid, HOSTUUIDLEN);
	snprintf(buf, HOSTUUIDLEN+16, "%s-%d", uuid, ifp->if_index);
		
	/*
	 * Generate a pseudo-random, deterministic MAC
	 * address based on the UUID and unit number.
	 * The FreeBSD Foundation OUI of 58-9C-FC is used.
	 */
	MD5Init(&mdctx);
	MD5Update(&mdctx, buf, strlen(buf));
	MD5Final(digest, &mdctx);

	vs->vs_mac[0] = 0x58;
	vs->vs_mac[1] = 0x9C;
	vs->vs_mac[2] = 0xFC;
	vs->vs_mac[3] = digest[0];
	vs->vs_mac[4] = digest[1];
	vs->vs_mac[5] = digest[2];
}

static int
vpci_attach_post(if_ctx_t ctx)
{
	struct ifnet *ifp;
	struct vpci_softc *vs;

	ifp = iflib_get_ifp(ctx);
	vs = iflib_get_softc(ctx);
	
	ifp->if_transmit = vpci_transmit;
	vpci_gen_mac(vs);
	iflib_set_mac(ctx, vs->vs_mac);
	return (0);
}

static int
vpci_detach(if_ctx_t ctx)
{
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
	return (EOPNOTSUPP);
}

static int
vpci_priv_ioctl(if_ctx_t ctx, u_long command, caddr_t data)
{
	struct vpci_softc *vs = iflib_get_softc(ctx);
	struct ifreq *ifr = (struct ifreq *)data;
	struct ifreq_buffer *ifbuf = &ifr->ifr_ifru.ifru_buffer;
	struct vpc_ioctl_header *ioh =
	    (struct vpc_ioctl_header *)(ifbuf->buffer);
	int rc = ENOTSUP;
	struct vpci_ioctl_data *iod = NULL;

	if (command != SIOCGPRIVATE_0)
		return (EINVAL);

	if ((rc = priv_check(curthread, PRIV_DRIVER)) != 0)
		return (rc);
#ifdef notyet
	/* need sx lock for iflib context */
	iod = malloc(ifbuf->length, M_VPCI, M_WAITOK | M_ZERO);
#endif
	iod = malloc(ifbuf->length, M_VPCI, M_NOWAIT | M_ZERO);
	copyin(ioh, iod, ifbuf->length);

	switch (ioh->vih_type) {
		case VPCI_ATTACH:
			rc = vpci_set_ifparent(vs, (struct vpci_attach *)iod);
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
	.isc_flags = 0,
	.isc_name = "vpci",
};

if_shared_ctx_t vpci_sctx = &vpci_sctx_init;


static if_pseudo_t vpci_pseudo;	

static int
vpci_module_init(void)
{
	vpci_pseudo = iflib_clone_register(vpci_sctx);

	return (vpci_pseudo != NULL);
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
		return (EBUSY);
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
