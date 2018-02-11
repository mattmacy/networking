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
#include <sys/proc.h>
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
#include <net/route.h>
#include <net/art.h>

#include <ck_epoch.h>
#include <net/if_vpc.h>

#include <netinet/udp.h>

#include "ifdi_if.h"

static MALLOC_DEFINE(M_VPCSW, "vpcsw", "virtual private cloud bridge");

#define VCE_TRUSTED 0x0
#define VCE_IPSEC 0x1
#define DHCP_SPORT	68
#define DHCP_DPORT	67

/*
 * ifconfig vpcsw0 create
 * ifconfig vpcsw0 addm vpc0
 * ifconfig vpcsw0 priority vpc0 200
 * ifconfig vpcsw0 vpc-resolver 127.0.0.1:5000
 * ifconfig vpcsw0 addm vmi7
 * ifconfig vpcsw0 pathcost vmi7 2000000
 */

struct vpcsw_source {
	uint16_t vs_dmac[3]; /* destination mac address */
	uint16_t vs_vlanid; /* source vlanid */
	uint32_t vs_vni;	/* source vni */
};

struct vpcsw_cache_ent {
	struct vpcsw_source vce_src;
	uint16_t vce_ifindex;	/* interface index */
	int vce_ticks;		/* time when entry was created */
};

static DPCPU_DEFINE(struct vpcsw_cache_ent *, hdr_cache);

struct pinfo {
	uint16_t etype;
};

static volatile int32_t modrefcnt;

struct vpcsw_mcast_queue {
	int vmq_mcount;
	struct mbuf *vmq_mh;
	struct mbuf *vmq_mt;
};

struct vpcsw_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
	if_t vs_ifp;
	struct cdev *vs_vpcswctldev;
	volatile int32_t vs_refcnt;
	struct mtx vs_lock;

	struct vpcsw_mcast_queue vs_vmq;
	art_tree *vs_ftable_ro;
	art_tree *vs_ftable_rw;
	void (*vs_oinput)(struct ifnet *, struct mbuf *);
	struct ifnet *vs_ifdefault;
};

static d_ioctl_t vpcswctl_ioctl;
static d_open_t vpcswctl_open;
static d_close_t vpcswctl_close;

static struct cdevsw vpcswctl_cdevsw = {
       .d_version =    D_VERSION,
       .d_flags =      0,
       .d_open =       vpcswctl_open,
       .d_close =      vpcswctl_close,
       .d_ioctl =      vpcswctl_ioctl,
       .d_name =       "vpcswctl",
};

static int
vpcswctl_open(struct cdev *dev, int flags, int fmp, struct thread *td)
{
	struct vpcsw_softc *vs;

	vs = dev->si_drv1;
	refcount_acquire(&vs->vs_refcnt);
	refcount_acquire(&modrefcnt);
	return (0);
}

static int
vpcswctl_close(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	struct vpcsw_softc *vs;

	vs = dev->si_drv1;
	refcount_release(&vs->vs_refcnt);
	refcount_release(&modrefcnt);
	return (0);
}

static const char *opcode_map[] = {
	"",
	"VPCSW_REQ_NDv4",
	"VPCSW_REQ_NDv6",
	"VPCSW_REQ_DHCPv4",
	"VPCSW_REQ_DHCPv6",
};

static int
vpcsw_poll_dispatch(struct vpcsw_softc *vs, struct vpcsw_request *vr)
{
	struct vpcsw_mcast_queue *vmq;
	struct ether_header *eh;
	struct mbuf *m;
	struct vpc_pkt_info pinfo;
	int rc;
	bool valid;

	if (vr->vrq_header.voh_version == VPCSW_VERSION) {
		printf("version %d doesn't match compiled version: %d\n",
			   vr->vrq_header.voh_version, VPCSW_VERSION);
		return (ENXIO);
	}
 restart:
	bzero(vr, sizeof(*vr));
	vr->vrq_header.voh_version = VPCSW_VERSION;
	vmq = &vs->vs_vmq;
	mtx_lock(&vs->vs_lock);
	while (vmq->vmq_mh == NULL) {
		rc = msleep(vs, &vs->vs_lock, PCATCH, "vpcswpoll", 0);
		if (rc == ERESTART) {
			mtx_unlock(&vs->vs_lock);
			return (rc);
		}
	}
	/* dequeue mbuf */
	m  = vmq->vmq_mh;
	vmq->vmq_mh = m->m_nextpkt;
	if (vmq->vmq_mh == NULL)
		vmq->vmq_mt = NULL;
	mtx_unlock(&vs->vs_lock);

	if (m->m_flags & M_VXLANTAG)
		vr->vrq_context.voc_vni = m->m_pkthdr.vxlanid;
	if (m->m_flags & M_VLANTAG)
		vr->vrq_context.voc_vlanid = m->m_pkthdr.ether_vtag;
	vpc_parse_pkt(m, &pinfo);
	eh = (void*)m->m_data;
	memcpy(vr->vrq_context.voc_smac, eh->ether_shost, ETHER_ADDR_LEN);
	switch (pinfo.vpi_etype) {
		case ETHERTYPE_ARP: {
			struct arphdr *ah = (struct arphdr *)(m->m_data + m->m_pkthdr.l2hlen);
			vr->vrq_header.voh_op = VPCSW_REQ_NDv4;
			memcpy(&vr->vrq_data.vrqd_ndv4.target, ar_tpa(ah), sizeof(struct in_addr));
			valid = true;
			break;
		}
		case ETHERTYPE_IP: {
			struct udphdr *uh = (struct udphdr *)(m->m_data + m->m_pkthdr.l2hlen + m->m_pkthdr.l3hlen);

			/* validate DHCP or move on to next packet*/
			if (pinfo.vpi_proto != IPPROTO_UDP)
				break;
			if (uh->uh_sport != DHCP_SPORT || uh->uh_dport != DHCP_DPORT)
				break;
			vr->vrq_header.voh_op = VPCSW_REQ_DHCPv4;
			valid = true;
			break;
		}
		case ETHERTYPE_IPV6:
			/* validate DHCP/ND or move on to next packet*/
			printf("parse v6!\n");
			break;
	}
	m_freem(m);
	if (!valid)
		goto restart;
	return (0);
}

static int 
vpcsw_response_dispatch(struct vpcsw_softc *vs, unsigned long cmd, struct vpcsw_response *vrs)
{
	if (vrs->vrs_header.voh_version != VPCSW_VERSION) {
		printf("invalid version %d\n",
			   vrs->vrs_header.voh_version);
		return (EINVAL);
	}
	if (vrs->vrs_header.voh_op < 1 ||
		vrs->vrs_header.voh_op > VPCSW_REQ_MAX) {
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
		case VPCSW_RESPONSE_NDv4:
			break;
		case VPCSW_RESPONSE_NDv6:
		case VPCSW_RESPONSE_DHCPv4:
		case VPCSW_RESPONSE_DHCPv6:
			printf("not yet supported %lx\n", cmd);
			break;
	}
	return (0);
}

static int
vpcswctl_ioctl(struct cdev *dev, unsigned long cmd, caddr_t data,
    int fflag, struct thread *td)
{
	struct vpcsw_softc *vs;

	vs = dev->si_drv1;
	switch (cmd) {
		case VPCSW_POLL:
			return (vpcsw_poll_dispatch(vs, (struct vpcsw_request *)data));
			break;
		case VPCSW_RESPONSE_NDv4:
		case VPCSW_RESPONSE_NDv6:
		case VPCSW_RESPONSE_DHCPv4:
		case VPCSW_RESPONSE_DHCPv6:
			return (vpcsw_response_dispatch(vs, cmd, (struct vpcsw_response *)data));
			break;
		default:
			return (ENOIOCTL);
	}
	return (0);
}

static __inline int
hdrcmp(struct vpcsw_source *vlhs, struct vpcsw_source *vrhs)
{
	uint16_t *lhs, *rhs;

	lhs = (uint16_t *)vlhs;
	rhs = (uint16_t *)vrhs;
	return ((lhs[0] ^ rhs[0]) |
			(lhs[1] ^ rhs[1]) |
			(lhs[2] ^ rhs[2]) |
			(lhs[3] ^ rhs[3]) |
			(lhs[4] ^ rhs[4]) |
			(lhs[5] ^ rhs[5]));
}

static int
vpcsw_cache_lookup(struct mbuf *m)
{
	struct vpcsw_cache_ent *vcep;
	struct vpcsw_source vsrc;
	struct ether_header *eh;
	struct ifnet *ifp;
	uint16_t *mac;

	eh = (void*)m->m_data;
	mac = (uint16_t *)eh->ether_dhost;
	vsrc.vs_vlanid = m->m_pkthdr.ether_vtag;
	vsrc.vs_vni = m->m_pkthdr.vxlanid;
	vsrc.vs_dmac[0] = mac[0];
	vsrc.vs_dmac[1] = mac[1];
	vsrc.vs_dmac[2] = mac[2];
	_critical_enter();
	vcep = DPCPU_GET(hdr_cache);
	if (__predict_false(vcep->vce_ticks == 0))
		goto skip;
	ifp = vpc_ic->ic_ifps[vcep->vce_ifindex];
	if (ifp == NULL)
		goto skip;
	/*
	 * Is still in caching window
	 */
	if (__predict_false(ticks - vcep->vce_ticks < hz/4))
		goto skip;
	if (ifp->if_flags & IFF_DYING) {
		GROUPTASK_ENQUEUE(&vpc_ifp_task);
		goto skip;
	}
	/*
	 * dmac & vxlanid match
	 */
	if (hdrcmp(&vcep->vce_src, &vsrc) == 0) {
		/* cache hit */
		_critical_exit();
		m->m_pkthdr.rcvif = ifp;
		return (1);
	}
	skip:
	vcep->vce_ticks = 0;
	_critical_exit();
	return (0);
}

static void
vpcsw_cache_update(struct mbuf *m)
{
	struct vpcsw_cache_ent *vcep;
	struct vpcsw_source *vsrc;
	struct ether_header *eh;
	uint16_t *mac;

	eh = (void*)m->m_data;
	mac = (uint16_t *)eh->ether_dhost;
	_critical_enter();
	vcep = DPCPU_GET(hdr_cache);
	vsrc = &vcep->vce_src;
	vsrc->vs_vlanid = m->m_pkthdr.ether_vtag;
	vsrc->vs_vni = m->m_pkthdr.vxlanid;
	vsrc->vs_dmac[0] = mac[0];
	vsrc->vs_dmac[1] = mac[1];
	vsrc->vs_dmac[2] = mac[2];
	vcep->vce_ifindex = m->m_pkthdr.rcvif->if_index;
	vcep->vce_ticks = ticks;
	_critical_exit();
}

static int
vpc_broadcast_one(void *data, const unsigned char *key __unused, uint32_t key_len __unused, void *value)
{
	struct ifnet *ifp;
	uint16_t *ifindexp = value;
	struct mbuf *m;

	m = m_dup((struct mbuf *)data, M_NOWAIT);
	if (__predict_false(m == NULL))
		return (ENOMEM);
	ifp = vpc_ic->ic_ifps[*ifindexp];
	if (ifp == NULL)
		return (0);
	if (ifp->if_flags & IFF_DYING) {
		GROUPTASK_ENQUEUE(&vpc_ifp_task);
		return (0);
	}
	m->m_pkthdr.rcvif = ifp;
	ifp->if_input(ifp, m);
	return (0);
}

static int
vpcsw_process_mcast(struct vpcsw_softc *vs, struct mbuf **msrc)
{
	struct vpcsw_mcast_queue *vmq;
	struct mbuf *m, *mp;
	int rc;

	vmq = &vs->vs_vmq;
	m = *msrc;
	*msrc = NULL;
	if ((m->m_flags & (M_VXLANTAG|M_TRUNK)) == M_VXLANTAG) {
		if (m->m_flags & M_EXT) {
			if (__predict_false(m->m_next != NULL || m->m_pkthdr.len > MCLBYTES)) {
				m_freem(m);
				return (0);
			}
			if (__predict_false(m->m_pkthdr.len > MHLEN)) {
				mp = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
			} else {
				mp = m_gethdr(M_NOWAIT, MT_DATA);
			}
			if (mp != NULL) {
				memcpy(&mp->m_pkthdr, &m->m_pkthdr, sizeof(struct pkthdr));
				memcpy(mp->m_data, m->m_data, m->m_pkthdr.len);
			}
			m_freem(m);
			m = mp;
			if (__predict_false(m == NULL))
				return (ENOBUFS);
		}
		mtx_lock(&vs->vs_lock);
		if (vmq->vmq_mt)
			vmq->vmq_mt->m_nextpkt = m;
		else
			vmq->vmq_mh = vmq->vmq_mt = m;
		vmq->vmq_mcount++;
		if (vmq->vmq_mcount > 128) {
			m = vmq->vmq_mh;
			vmq->vmq_mh = m->m_nextpkt;
			m->m_nextpkt = NULL;
			m_freem(m);
			vmq->vmq_mcount--;
		}
		wakeup(vs);
		mtx_unlock(&vs->vs_lock);
		*msrc = NULL;
		rc = 0;
	} else if (!(m->m_flags & M_VXLANTAG)) {
		art_iter(vs->vs_ftable_ro, vpc_broadcast_one, m);
		rc = 0;
	} else {
		m_freem(m);
		rc = EINVAL;
	}
	return (rc);
}

static int
vpcsw_process_one(struct vpcsw_softc *vs, struct mbuf **mp)
{
	struct ether_header *eh;
	uint16_t *vif;
	struct ifnet *ifp;

	m = *mp;
	eh = (void*)m->m_data;
	if (__predict_false(ETHER_IS_MULTICAST(eh->ether_dhost)))
		return (vpcsw_process_mcast(vs, mp));
	if (vpcsw_cache_lookup(m))
		return (0);
	vif = art_search(vs->vs_ftable_ro, (const unsigned char *)eh->ether_dhost);
	ifp = (vif != NULL) ? vpc_ic->ic_ifps[*vif] : vs->vs_ifdefault;
	if (__predict_false(ifp == NULL)) {
		m_freem(m);
		*mp = NULL;
		return (ENOBUFS);
	}
	if (ifp->if_flags & IFF_DYING) {
		GROUPTASK_ENQUEUE(&vpc_ifp_task);
		return (ENOBUFS);
	}
	m->m_pkthdr.rcvif = ifp;
	vpcsw_cache_update(m);

	return (0);
}

static int
vpcsw_transit(struct vpcsw_softc *vs, struct mbuf *m)
{
	struct ifnet *ifnext;
	struct mbuf *mh, *mt, *mnext;
	bool can_batch = true;
	int rc, lasterr;

	vpc_epoch_begin();
	mh = mt = NULL;
	do {
		mnext = m->m_nextpkt;
		m->m_nextpkt = NULL;
		rc = vpcsw_process_one(vs, &m);
		if (m == NULL) {
			m = mnext;
			continue;
		}
		if (__predict_false(rc))
			break;
		if (mh == NULL) {
			mh = mt = m;
			ifnext = m->m_pkthdr.rcvif;
		} else {
			mt->m_nextpkt = m;
			mt = m;
			if (__predict_false(ifnext != m->m_pkthdr.rcvif))
				can_batch = false;
		}
		MPASS(m != mnext);
		m = mnext;
	} while (m != NULL);
	if (__predict_false(mnext != NULL))
		m_freechain(mnext);

	if (mh == NULL) {
		lasterr = rc;
		goto done;
	}
	lasterr = 0;
	if (can_batch) {
		ifnext = mh->m_pkthdr.rcvif;
		ifnext->if_input(ifnext, mh);
		goto done;
	}
	m = mh;
	do {
		mnext = m->m_nextpkt;
		m->m_nextpkt = NULL;
		ifnext = m->m_pkthdr.rcvif;
		ifnext->if_input(ifnext, m);
		m = mnext;
	} while (m != NULL);
 done:
	vpc_epoch_end();
	return (lasterr);
}

static int
vpcsw_transmit(if_t ifp, struct mbuf *m)
{
	struct vpcsw_softc *vs;

	vs = ifp->if_softc;
	return vpcsw_transit(vs, m);
}

static int
vpcsw_bridge_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *s __unused, struct rtentry *r __unused)
{
	struct vpcsw_softc *vs;

	MPASS(ifp->if_bridge != NULL);
	vs = ifp->if_bridge;
	return (vpcsw_transit(vs, m));
}

static struct mbuf *
vpcsw_bridge_input(if_t ifp, struct mbuf *m)
{
	struct vpcsw_softc *vs;

	MPASS(ifp->if_bridge != NULL);
	vs = ifp->if_bridge;
	vpcsw_transit(vs, m);

	return (NULL);
}

static int
vpcsw_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct vpcsw_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;
	device_t dev;
	uint32_t unitno;

	dev = iflib_get_dev(ctx);
	unitno = device_get_unit(dev);
	vs->vs_vpcswctldev = make_dev(&vpcswctl_cdevsw, unitno,
								 UID_ROOT, GID_VPC, 0660, "vpcswctl");
	if (vs->vs_vpcswctldev == NULL)
		return (ENOMEM);
	refcount_acquire(&modrefcnt);

	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	vs->vs_ctx = ctx;
	vs->vs_ifp = iflib_get_ifp(ctx);
	refcount_init(&vs->vs_refcnt, 0);
	vs->vs_vpcswctldev->si_drv1 = vs;
	mtx_init(&vs->vs_lock, "vpcsw softc", NULL, MTX_DEF);
	vs->vs_ftable_ro = malloc(sizeof(art_tree), M_VPCSW, M_WAITOK|M_ZERO);
	vs->vs_ftable_rw = malloc(sizeof(art_tree), M_VPCSW, M_WAITOK|M_ZERO);
	art_tree_init(vs->vs_ftable_ro, ETHER_ADDR_LEN);
	art_tree_init(vs->vs_ftable_rw, ETHER_ADDR_LEN);
	return (0);
}

static int
vpcsw_port_add(struct vpcsw_softc *vs, struct vpcsw_port *port)
{
	struct ifnet *ifp;
	struct ifreq ifr;
	struct sockaddr_dl *sdl;
	art_tree *newftable, *oldftable;
	uint16_t *ifindexp;
	int rc;

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "vpcp%d", port->vp_portno);
	if ((rc = if_clone_create(ifr.ifr_name, sizeof(ifr.ifr_name), NULL)))
		return (rc);
	if ((ifp = ifunit_ref(ifr.ifr_name)) == NULL) {
		if (bootverbose)
			printf("couldn't reference %s\n", ifr.ifr_name);
		return (ENXIO);
	}
	sdl = (struct sockaddr_dl *)ifp->if_addr->ifa_addr;
	if (sdl->sdl_type != IFT_ETHER) {
		if_rele(ifp);
		return (EINVAL);
	}
	ifindexp = malloc(sizeof(uint16_t), M_VPCSW, M_WAITOK);
	*ifindexp = ifp->if_index;
	vpc_ifp_cache(ifp);
	ifp->if_bridge = vs;
	ifp->if_bridge_input = vpcsw_bridge_input;
	ifp->if_bridge_output = vpcsw_bridge_output;
	art_insert(vs->vs_ftable_rw, LLADDR(sdl), ifindexp);
	rc = vpc_art_tree_clone(vs->vs_ftable_rw, &newftable, M_VPCSW);
	if (rc)
		goto fail;
	oldftable = vs->vs_ftable_ro;
	vs->vs_ftable_ro = newftable;
	ck_epoch_synchronize(&vpc_global_record);
	vpc_art_free(oldftable, M_VPCSW);
	if_rele(ifp);
	return (0);
 fail:
	free(ifindexp, M_VPCSW);
	if_rele(ifp);
	return (rc);
}

static int
vpcsw_port_delete(struct vpcsw_softc *vs, struct vpcsw_port *port)
{
	struct ifnet *ifp;
	struct sockaddr_dl *sdl;
	art_tree *newftable, *oldftable;
	uint16_t *ifindexp;
	struct ifreq ifr;
	int rc;

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "vpcp%d", port->vp_portno);
	if ((ifp = ifunit_ref(ifr.ifr_name)) == NULL) {
		if (bootverbose)
			printf("couldn't reference %s\n", ifr.ifr_name);
		return (ENXIO);
	}
	sdl = (struct sockaddr_dl *)ifp->if_addr->ifa_addr;
	if (sdl->sdl_type != IFT_ETHER) {
		if_rele(ifp);
		return (EINVAL);
	}
	/* Verify ifnet in table */
	if (art_search(vs->vs_ftable_rw, LLADDR(sdl)) == NULL) {
		if (bootverbose)
			printf("%s not found\n", ifr.ifr_name);
		if_rele(ifp);
		return (ENOENT);
	}

	ifindexp = art_delete(vs->vs_ftable_rw, LLADDR(sdl));
	free(ifindexp, M_VPCSW);
	rc = vpc_art_tree_clone(vs->vs_ftable_rw, &newftable, M_VPCSW);
	if (rc)
		goto fail;
	oldftable = vs->vs_ftable_ro;
	vs->vs_ftable_ro = newftable;
	ck_epoch_synchronize(&vpc_global_record);
	vpc_art_free(oldftable, M_VPCSW);
	ifp->if_bridge = NULL;
	ifp->if_bridge_input = NULL;
	ifp->if_bridge_output = NULL;
	if_rele(ifp);
	if_clone_destroy(ifr.ifr_name);
	return (0);
 fail:
	free(ifindexp, M_VPCSW);
	if_rele(ifp);
	return (rc);
}

static int
vpcsw_port_uplink(struct vpcsw_softc *vs, struct vpcsw_port *port)
{
	struct ifnet *ifp;
	struct ifreq ifr;
	int rc;

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "vpcp%d", port->vp_portno);
	if ((rc = if_clone_create(ifr.ifr_name, sizeof(ifr.ifr_name), NULL)))
		return (rc);
	if ((ifp = ifunit_ref(ifr.ifr_name)) == NULL) {
		if (bootverbose)
			printf("couldn't reference %s\n", ifr.ifr_name);
		return (ENXIO);
	}
	if (vs->vs_ifdefault != NULL) {
		if_rele(vs->vs_ifdefault);
		if_clone_destroy(ifr.ifr_name);
	}
	vs->vs_ifdefault = ifp;
	return (0);
}

static int
vpcsw_priv_ioctl(if_ctx_t ctx, u_long command, caddr_t data)
{
	struct vpcsw_softc *vs = iflib_get_softc(ctx);
	struct ifreq *ifr = (struct ifreq *)data;
	struct ifreq_buffer *ifbuf = &ifr->ifr_ifru.ifru_buffer;
	struct vpc_ioctl_header *ioh =
	    (struct vpc_ioctl_header *)(ifbuf->buffer);
	int rc = ENOTSUP;
	struct vpc_ioctl_data *iod = NULL;

	if (command != SIOCGPRIVATE_0)
		return (EINVAL);
#ifdef notyet
	/* need sx lock for iflib context */
	iod = malloc(ifbuf->length, M_VPCSW, M_WAITOK | M_ZERO);
#endif
	iod = malloc(ifbuf->length, M_VPCSW, M_NOWAIT | M_ZERO);
	if (iod == NULL)
		return (ENOMEM);
	rc = copyin(ioh, iod, ifbuf->length);
	if (rc) {
		free(iod, M_VPCSW);
		return (rc);
	}
	switch (ioh->vih_type) {
		case VPCSW_PORT_ADD:
			rc = vpcsw_port_add(vs, (struct vpcsw_port *)iod);
			break;
		case VPCSW_PORT_DEL:
			rc = vpcsw_port_delete(vs, (struct vpcsw_port *)iod);
			break;
		case VPCSW_PORT_UPLINK:
			rc = vpcsw_port_uplink(vs, (struct vpcsw_port *)iod);
			break;
		default:
			rc = ENOTSUP;
	}
	return (rc);
}

static int
vpcsw_mbuf_to_qid(struct ifnet *ifp, struct mbuf *m)
{
	return (0);
}

static int
vpcsw_attach_post(if_ctx_t ctx)
{
	struct ifnet *ifp;

	ifp = iflib_get_ifp(ctx);

	ifp->if_transmit = vpcsw_transmit;
	ifp->if_transmit_txq = vpcsw_transmit;
	ifp->if_mbuf_to_qid = vpcsw_mbuf_to_qid;
	return (0);
}

static int
clear_bridge(void *data __unused, const unsigned char *key __unused, uint32_t key_len __unused, void *value)
{
	uint16_t *ifindexp = value;
	struct ifnet *ifp;

	ifp = vpc_ic->ic_ifps[*ifindexp];
	if (ifp == NULL)
		return (0);
	if (ifp->if_flags & IFF_DYING) {
		GROUPTASK_ENQUEUE(&vpc_ifp_task);
		return (0);
	}
	ifp->if_bridge = NULL;
	return (0);
}

static int
vpcsw_detach(if_ctx_t ctx)
{
	struct vpcsw_softc *vs = iflib_get_softc(ctx);
	struct vpcsw_mcast_queue *vmq;
	struct mbuf *m;

	if (vs->vs_refcnt != 0)
		return (EBUSY);

	ck_epoch_synchronize(&vpc_global_record);

	vmq = &vs->vs_vmq;
	while (vmq->vmq_mh != NULL) {
		m = vmq->vmq_mh;
		vmq->vmq_mh = m->m_nextpkt;
		m_freem(m);
	}
	if (vs->vs_ifdefault != NULL) {
		vs->vs_ifdefault->if_input = vs->vs_oinput;
		if_rele(vs->vs_ifdefault);
	}

	art_iter(vs->vs_ftable_rw, clear_bridge, NULL);
	mtx_destroy(&vs->vs_lock);
	vpc_art_free(vs->vs_ftable_ro, M_VPCSW);
	vpc_art_free(vs->vs_ftable_rw, M_VPCSW);
	destroy_dev(vs->vs_vpcswctldev);
	refcount_release(&modrefcnt);
	return (0);
}

static void
vpcsw_init(if_ctx_t ctx)
{
}

static void
vpcsw_stop(if_ctx_t ctx)
{
}

static device_method_t vpcsw_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, vpcsw_cloneattach),
	DEVMETHOD(ifdi_attach_post, vpcsw_attach_post),
	DEVMETHOD(ifdi_detach, vpcsw_detach),
	DEVMETHOD(ifdi_init, vpcsw_init),
	DEVMETHOD(ifdi_stop, vpcsw_stop),
	DEVMETHOD(ifdi_priv_ioctl, vpcsw_priv_ioctl),
	DEVMETHOD_END
};

static driver_t vpcsw_iflib_driver = {
	"vpcsw", vpcsw_if_methods, sizeof(struct vpcsw_softc)
};

char vpcsw_driver_version[] = "0.0.1";

static struct if_shared_ctx vpcsw_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_driver_version = vpcsw_driver_version,
	.isc_driver = &vpcsw_iflib_driver,
	.isc_flags = IFLIB_PSEUDO,
	.isc_name = "vpcsw",
};

if_shared_ctx_t vpcsw_sctx = &vpcsw_sctx_init;


static if_pseudo_t vpcsw_pseudo;

static int
vpcsw_module_init(void)
{
	vpcsw_pseudo = iflib_clone_register(vpcsw_sctx);

	return (vpcsw_pseudo == NULL) ? ENXIO : 0;
}

static void
vpcsw_module_deinit(void)
{
	iflib_clone_deregister(vpcsw_pseudo);
}


static int
vpcsw_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
		case MOD_LOAD:
			if ((err = vpcsw_module_init()) != 0)
				return (err);
			break;
		case MOD_UNLOAD:
			if (modrefcnt == 0)
				vpcsw_module_deinit();
			else
				return (EBUSY);
			break;
		default:
			return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t vpcsw_moduledata = {
	"vpcsw",
	vpcsw_module_event_handler,
	NULL
};

DECLARE_MODULE(vpcsw, vpcsw_moduledata, SI_SUB_INIT_IF, SI_ORDER_ANY);
MODULE_VERSION(vpcsw, 1);
MODULE_DEPEND(vpcsw, vpc, 1, 1, 1);
MODULE_DEPEND(vpcsw, iflib, 1, 1, 1);
