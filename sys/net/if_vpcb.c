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
#include <sys/conf.h>
#include <sys/eventhandler.h>
#include <sys/sockio.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/priv.h>
#include <sys/mutex.h>
#include <sys/module.h>
#include <sys/refcount.h>
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
#include <net/if_arp.h>
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

struct pinfo {
	uint16_t etype;
};

static volatile int32_t modrefcnt;

struct vpcb_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
	struct mbuf *vs_mh;
	struct cdev *vs_vpcbctldev;
	struct mtx vs_lock;
	volatile int32_t vs_refcnt;
};


static d_ioctl_t vpcbctl_ioctl;
static d_open_t vpcbctl_open;
static d_close_t vpcbctl_close;

static struct cdevsw vpcbctl_cdevsw = {
       .d_version =    D_VERSION,
       .d_flags =      0,
       .d_open =       vpcbctl_open,
       .d_close =      vpcbctl_close,
       .d_ioctl =      vpcbctl_ioctl,
       .d_name =       "vpcbctl",
};

static int
vpcbctl_open(struct cdev *dev, int flags, int fmp, struct thread *td)
{
	struct vpcb_softc *vs;

	vs = dev->si_drv1;
	refcount_acquire(&vs->vs_refcnt);
	refcount_acquire(&modrefcnt);
	return (0);
}

static int
vpcbctl_close(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	struct vpcb_softc *vs;

	vs = dev->si_drv1;
	refcount_release(&vs->vs_refcnt);
	refcount_release(&modrefcnt);
	return (0);
}

static const char *opcode_map[] = {
	"",
	"VPCB_REQ_NDv4",
	"VPCB_REQ_NDv6",
	"VPCB_REQ_DHCPv4",
	"VPCB_REQ_DHCPv6",
};

static int
parse_pkt(struct mbuf *m, struct pinfo *pinfo)
{
	return (0);
}

static int
vpcb_poll_dispatch(struct vpcb_softc *vs, struct vpcb_request *vr)
{
	struct mbuf *m;
	struct ether_header *eh;
	struct pinfo pinfo;
	int rc;

	if (vr->vrq_header.voh_version == VPCB_VERSION) {
		printf("version %d doesn't match compiled version: %d\n",
			   vr->vrq_header.voh_version, VPCB_VERSION);
		return (ENXIO);
	}

	bzero(vr, sizeof(*vr));
	vr->vrq_header.voh_version = VPCB_VERSION;
	mtx_lock(&vs->vs_lock);
	while (vs->vs_mh == NULL) {
		rc = msleep(vs, &vs->vs_lock, PCATCH, "vpcbpoll", 0);
		if (rc == ERESTART) {
			mtx_unlock(&vs->vs_lock);
			return (rc);
		}
	}
	/* dequeue mbuf */
	m  = vs->vs_mh;
	vs->vs_mh = m->m_nextpkt;
	mtx_unlock(&vs->vs_lock);

	if (m->m_flags & M_VXLANTAG)
		vr->vrq_context.voc_vni = m->m_pkthdr.vxlanid;
	if (m->m_flags & M_VLANTAG)
		vr->vrq_context.voc_vlanid = m->m_pkthdr.ether_vtag;
	parse_pkt(m, &pinfo);
	eh = (void*)m->m_data;
	memcpy(vr->vrq_context.voc_smac, eh->ether_shost, ETHER_ADDR_LEN);
	switch (pinfo.etype) {
		case ETHERTYPE_ARP: {
			struct arphdr *ah = (struct arphdr *)(m->m_data + m->m_pkthdr.l2hlen);
			vr->vrq_header.voh_op = VPCB_REQ_NDv4;
			memcpy(&vr->vrq_data.vrqd_ndv4.target, ar_tpa(ah), sizeof(struct in_addr));
			break;
		}
		case ETHERTYPE_IP:
			/* validate DHCP or move on to next packet*/
			printf("parse DHCP!\n");
			break;
		case ETHERTYPE_IPV6:
			/* validate DHCP/ND or move on to next packet*/
			printf("parse v6!\n");
			break;
	}
	return (0);
}

static int 
vpcb_response_dispatch(struct vpcb_softc *vs, unsigned long cmd, struct vpcb_response *vrs)
{
	if (vrs->vrs_header.voh_version != VPCB_VERSION) {
		printf("invalid version %d\n",
			   vrs->vrs_header.voh_version);
		return (EINVAL);
	}
	if (vrs->vrs_header.voh_op < 1 ||
		vrs->vrs_header.voh_op > VPCB_REQ_MAX) {
		printf("invalid opcode %d\n",
			   vrs->vrs_header.voh_op);
		return (EINVAL);
	}
	printf("version: %x opcode: %s vni: %d vlanid: %d\n",
		   vrs->vrs_header.voh_version,
		   opcode_map[vrs->vrs_header.voh_op],
		   vrs->vrs_context.voc_vni,
		   vrs->vrs_context.voc_vlanid);
	switch (cmd) {
		case VPCB_RESPONSE_NDv6:
		case VPCB_RESPONSE_NDv4:
			printf("data: %6D", vrs->vrs_data.vrsd_ndv4.ether_addr, ":");
			break;
		case VPCB_RESPONSE_DHCPv4:
		case VPCB_RESPONSE_DHCPv6:
			break;
	}
	return (0);
}

static int
vpcbctl_ioctl(struct cdev *dev, unsigned long cmd, caddr_t data,
    int fflag, struct thread *td)
{
	struct vpcb_softc *vs;

	vs = dev->si_drv1;
	switch (cmd) {
		case VPCB_POLL:
			return (vpcb_poll_dispatch(vs, (struct vpcb_request *)data));
			break;
		case VPCB_RESPONSE_NDv4:
		case VPCB_RESPONSE_NDv6:
		case VPCB_RESPONSE_DHCPv4:
		case VPCB_RESPONSE_DHCPv6:
			return (vpcb_response_dispatch(vs, cmd, (struct vpcb_response *)data));
			break;
		default:
			return (ENOIOCTL);
	}
	return (0);
}

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
	device_t dev;
	uint32_t unitno;

	dev = iflib_get_dev(ctx);
	unitno = device_get_unit(dev);
	vs->vs_vpcbctldev = make_dev(&vpcbctl_cdevsw, unitno,
								 UID_ROOT, GID_VPC, 0660, "vpcbctl");
	if (vs->vs_vpcbctldev == NULL)
		return (ENOMEM);
	vs->vs_vpcbctldev->si_drv1 = vs;
	refcount_init(&vs->vs_refcnt, 0);
	refcount_acquire(&modrefcnt);
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
	struct vpcb_softc *vs = iflib_get_softc(ctx);

	if (vs->vs_refcnt != 0)
		return (EBUSY);

	destroy_dev(vs->vs_vpcbctldev);
	refcount_release(&modrefcnt);
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

static device_method_t vpcb_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, vpcb_cloneattach),
	DEVMETHOD(ifdi_attach_post, vpcb_attach_post),
	DEVMETHOD(ifdi_detach, vpcb_detach),
	DEVMETHOD(ifdi_init, vpcb_init),
	DEVMETHOD(ifdi_stop, vpcb_stop),
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
	.isc_flags = IFLIB_PSEUDO,
	.isc_name = "vpcb",
};

if_shared_ctx_t vpcb_sctx = &vpcb_sctx_init;


static if_pseudo_t vpcb_pseudo;	

static int
vpcb_module_init(void)
{
	vpcb_pseudo = iflib_clone_register(vpcb_sctx);

	return (vpcb_pseudo == NULL) ? ENXIO : 0;
}

static void
vpcb_module_deinit(void)
{
	iflib_clone_deregister(vpcb_pseudo);
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
			if (modrefcnt == 0)
				vpcb_module_deinit();
			else
				return (EBUSY);
			break;
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
