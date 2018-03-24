/*
 * Copyright (C) 2017-2018 Matthew Macy <matt.macy@joyent.com>
 * Copyright (C) 2017-2018 Joyent Inc.
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
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/gtaskqueue.h>
#include <sys/limits.h>
#include <sys/queue.h>
#include <sys/smp.h>

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
#include <net/route.h>
#include <net/art.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet6/nd6.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_pageout.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/uma_int.h>

#include <ck_epoch.h>
#include <net/if_vpc.h>

#include "ifdi_if.h"

#include <machine/in_cksum.h>

#define	DPRINTF(...) do {								\
	if (__predict_false(bootverbose))					\
		printf(__VA_ARGS__);							\
} while (0)

struct vxlanhdr {
    uint32_t reserved0:4;
    uint32_t v_i:1;
    uint32_t reserved1:13;
    uint32_t reserved2:14;
    uint32_t v_vxlanid:24;
    uint32_t reserved3:8;
} __packed;

/*
 * IPv4 w/o VLAN
 */
struct vxlan_header {
    /* outer ether header */
    struct ether_header vh_ehdr;
    /* outer IP header */
    struct ip vh_iphdr;
	/* outer UDP header */
    struct udphdr vh_udphdr;
    /* outer vxlan id header */
    struct vxlanhdr vh_vxlanhdr;
} __packed;


struct vpcmux_ftable {
	uint32_t vf_vni;
	struct vpcmux_softc *vf_vs;
	art_tree vf_ftable;
};

struct egress_cache {
	uint16_t ec_hdr[3];
	uint16_t ec_pad;
	int ec_ticks;
	struct vxlan_header ec_vh;
};

struct vf_entry {
	struct sockaddr ve_addr;
};

static struct sx vpcmux_lock;
SX_SYSINIT(vpcmux, &vpcmux_lock, "VPC global");

#define VPCMUX_LOCK() sx_xlock(&vpcmux_lock)
#define VPCMUX_UNLOCK() sx_xunlock(&vpcmux_lock)


static DPCPU_DEFINE(struct egress_cache *, hdr_cache);

static MALLOC_DEFINE(M_VPCMUX, "vpcmux", "virtual private cloud mux (vxlan encap)");

struct vpcmux_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
	struct ifnet *vs_ifp;
	struct sockaddr vs_addr;
	uint16_t vs_vxlan_port;
	uint16_t vs_fibnum;
	uint16_t vs_min_port;
	uint16_t vs_max_port;
	art_tree vs_vxftable; /* vxlanid -> ftable */
	ck_epoch_record_t vs_record;
	struct ifnet *vs_underlay_ifp;
	vpc_ctx_t vs_underlay_vctx;
};

static void vpcmux_fte_print(struct vpcmux_softc *vs);

static int clone_count;

static __inline int
hdrcmp(uint16_t *lhs, uint16_t *rhs)
{
	return ((lhs[0] ^ rhs[0]) |
			(lhs[1] ^ rhs[1]) |
			(lhs[2] ^ rhs[2]));
}

static struct vpcmux_ftable *
vpcmux_vxlanid_lookup(struct vpcmux_softc *vs, uint32_t vxlanid)
{

	return (art_search(&vs->vs_vxftable, (const unsigned char *)&vxlanid));
}

static int
vpcmux_ftable_lookup(struct vpcmux_ftable *vf, struct ether_vlan_header *evh,
				  struct sockaddr *dst)
{
	struct vf_entry *vfe;

	vfe = art_search(&vf->vf_ftable, evh->evl_dhost);
	if (__predict_false(vfe == NULL))
		return (ENOENT);
	bcopy(&vfe->ve_addr, dst, sizeof(struct sockaddr));
	return (0);
}

static void
vpcmux_ftable_insert(struct vpcmux_ftable *vf, const char *evh,
					  const struct sockaddr *dst)
{
	struct vf_entry *vfe;

	vfe = malloc(sizeof(*vfe), M_VPCMUX, M_WAITOK);
	bcopy(dst, &vfe->ve_addr, sizeof(struct sockaddr));
	art_insert(&vf->vf_ftable, (const unsigned char *)evh, vfe);
}

static uint16_t
vpcmux_sport_hash(struct vpcmux_softc *vs, caddr_t data, uint16_t seed)
{
	uint16_t *hdr;
	uint16_t src, dst, hash, range;

	range = vs->vs_max_port - vs->vs_min_port;
	hdr = (uint16_t*)data;
	src = hdr[0] ^ hdr[1] ^ hdr[2];
	dst = hdr[3] ^ hdr[4] ^ hdr[5];
	hash = (src ^ dst ^ seed) % range;
	return (vs->vs_min_port + hash);
}


static void
vpcmux_ip_init(struct vpcmux_ftable *vf, struct vxlan_header *vh, struct sockaddr *dstip, int len, int mtu)
{
	struct ip *ip;
	struct sockaddr_in *sin;

	ip = (struct ip *)(uintptr_t)&vh->vh_iphdr;
	ip->ip_hl = sizeof(*ip) >> 2;
	ip->ip_v = 4; /* v4 only now */
	ip->ip_tos = 0;
	ip->ip_len = htons(len - sizeof(struct ether_header));
	ip->ip_id = 0;
	ip->ip_off = htons(IP_DF);
	ip->ip_ttl = 255;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_sum = 0;
	sin = (struct sockaddr_in *)&vf->vf_vs->vs_addr;
	ip->ip_src.s_addr = sin->sin_addr.s_addr;
	sin = (struct sockaddr_in *)dstip;
	ip->ip_dst.s_addr = sin->sin_addr.s_addr;
	if (len <= mtu)
		ip->ip_sum = in_cksum_hdr(ip);
}


static uint16_t
vpc_cksum_skip(struct mbuf *m, int len, int skip)
{
	uint16_t csum;

	if (m_ismvec(m))
		csum = mvec_cksum_skip(m, len, skip);
	else
		csum = in_cksum_skip(m, len, skip);

	if (__predict_false(csum == 0))
		csum = 0xffff;
	return (csum);
}

static void
vpcmux_vxlanhdr_init(struct vpcmux_ftable *vf, struct vxlan_header *vh, 
				  struct sockaddr *dstip, struct mbuf *m,
				  caddr_t hdr, struct vpc_pkt_info *tpi)
{
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *uh;
	struct vxlanhdr *vhdr;
	struct ifnet *ifp;
	caddr_t smac;
	int len;
	uint16_t seed;
	struct mvec_cursor mc;

	ifp = m->m_pkthdr.rcvif;
	MPASS(!(m->m_flags & M_EXT) || m_ismvec(m));
	seed = 0;
	len = m->m_pkthdr.len;
	smac = ifp->if_hw_addr;
	eh = &vh->vh_ehdr;
	if (tpi->vpi_l4_len) {
		struct tcphdr *th;

		mc.mc_idx = mc.mc_off = 0;
		th = mvec_advance(m, &mc, m->m_pkthdr.encaplen + tpi->vpi_l2_len + tpi->vpi_l3_len);
		seed = th->th_sport ^ th->th_dport;
	}

	eh->ether_type = htons(ETHERTYPE_IP); /* v4 only to start */
	/* arp resolve fills in dest */
	bcopy(smac, eh->ether_shost, ETHER_ADDR_LEN);

	vpcmux_ip_init(vf, vh, dstip, m->m_pkthdr.len, ifp->if_mtu);

	uh = (struct udphdr*)(uintptr_t)&vh->vh_udphdr;
	uh->uh_sport = htons(vpcmux_sport_hash(vf->vf_vs, hdr, seed));
	//m->m_pkthdr.rsstype = M_HASHTYPE_OPAQUE;
	//m->m_pkthdr.flowid = uh->uh_sport;
	uh->uh_dport = vf->vf_vs->vs_vxlan_port;
	uh->uh_ulen = htons(len - sizeof(*ip) - sizeof(*eh));
	ip = (struct ip *)(uintptr_t)&vh->vh_iphdr;
	uh->uh_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
						   htons(ip->ip_p + len - sizeof(*eh) - sizeof(*ip)));

	vhdr = (struct vxlanhdr *)(uintptr_t)&vh->vh_vxlanhdr;
	vhdr->v_i = 1;
	vhdr->v_vxlanid = htonl(vf->vf_vni) >> 8;
	if (!(ifp->if_capenable & IFCAP_TXCSUM)) {
		uh->uh_sum = vpc_cksum_skip(m, ntohs(ip->ip_len) + sizeof(*eh), sizeof(*ip) + sizeof(*eh));
	}
}

static int
vpcmux_cache_lookup(struct vpcmux_softc *vs, struct mbuf *m, struct ether_vlan_header *evh)
{
	struct egress_cache *ecp;

	_critical_enter();
	ecp = DPCPU_GET(hdr_cache);
	if (__predict_false(ecp->ec_ticks == 0))
		goto skip;
	/*
	 * Is still in caching window
	 */
	if (__predict_false(ticks - ecp->ec_ticks < hz/4)) {
		ecp->ec_ticks = 0;
		goto skip;
	}

	/*
	 * dmac & vxlanid match
	 */
	if (hdrcmp(ecp->ec_hdr, (uint16_t *)evh->evl_dhost) == 0 &&
		(m->m_pkthdr.vxlanid == ecp->ec_vh.vh_vxlanhdr.v_vxlanid)) {
		/* re-use last header */
		bcopy(&ecp->ec_vh, m->m_data, sizeof(struct vxlan_header));
		_critical_exit();
		return (1);
	}
	skip:
	_critical_exit();
	return (0);
}

static void
vpcmux_cache_update(struct mbuf *m, struct ether_vlan_header *evh)
{
	struct egress_cache *ecp;
	uint16_t *src;

	src = (uint16_t *)evh->evl_dhost;
	_critical_enter();
	/* update pcpu cache */
	ecp = DPCPU_GET(hdr_cache);
	ecp->ec_hdr[0] = src[0];
	ecp->ec_hdr[1] = src[1];
	ecp->ec_hdr[2] = src[2];
	bcopy(m->m_data, &ecp->ec_vh, sizeof(struct vxlan_header));
	ecp->ec_ticks = ticks;
	_critical_exit();
}


static int
vpcmux_nd_lookup(struct vpcmux_softc *vs, const struct sockaddr *dst, uint8_t *ether_addr)
{
	int rc;
	if_t ifp;

	ifp = vs->vs_underlay_ifp;
	/* get dmac */
	switch(dst->sa_family) {
		case AF_INET:
			rc = arpresolve(ifp, 0, NULL, dst,
							ether_addr, NULL, NULL);
			break;
		case AF_INET6:
			rc = nd6_resolve(ifp, 0, NULL, dst,
							 ether_addr, NULL, NULL);
			break;
		default:
			rc = EOPNOTSUPP;
	}
	return (rc);
}

static struct mbuf *
vpcmux_header_pullup(struct mbuf *mp, struct vpc_pkt_info *tpi)
{
	int minhlen;
	struct mbuf *m;

	minhlen = mp->m_pkthdr.encaplen + ETHER_HDR_LEN + sizeof(struct ip) + sizeof(struct tcphdr);
	MPASS(mp->m_pkthdr.len >= minhlen);
	m = m_pullup(mp, mp->m_pkthdr.encaplen + tpi->vpi_l2_len +
				 tpi->vpi_l3_len + tpi->vpi_l4_len);
	if (__predict_false(m == NULL))
		m_freem(mp);
	return (m);
}

static int
vpcmux_vxlan_encap(struct vpcmux_softc *vs, struct mbuf **mp)
{
	struct ether_vlan_header *evh, *evhvx;
	struct vxlan_header *vh;
	struct mbuf_ext *mtmp;
	struct mbuf *mh, *m;
	struct vpcmux_ftable *vf;
	struct sockaddr *dst;
	struct route ro;
	struct ifnet *ifp;
	struct vpc_pkt_info tpi;
	uint32_t oldflags;
	int rc, hdrsize;

	m = *mp;
	ETHER_BPF_MTAP(iflib_get_ifp(vs->vs_ctx), m);
	*mp = NULL;
	if (!(m->m_flags & M_VXLANTAG)) {
		m_freem(m);
		return (EINVAL);
	}
	vpc_parse_pkt(m, &tpi);

	MPASS(m->m_pkthdr.vxlanid);
	evhvx = (struct ether_vlan_header *)m->m_data;
	hdrsize = sizeof(struct vxlan_header);
	oldflags = m->m_pkthdr.csum_flags;
	m->m_nextpkt = NULL;
	/* temporary */
	if (m_ismvec(m)) {
		mh = mvec_prepend(m, hdrsize);
	} else {
		mh = m_gethdr(M_NOWAIT, MT_NOINIT);
		if (__predict_false(mh == NULL)) {
			m_freem(m);
			DPRINTF("%s failed to gethdr\n", __func__); 
			return (ENOMEM);
		}
		bcopy(&m->m_pkthdr, &mh->m_pkthdr, sizeof(struct pkthdr));
		mh->m_data = mh->m_pktdat;
		mh->m_nextpkt = NULL;
		mh->m_flags = M_PKTHDR;
		/* XXX v4 only */
		mh->m_pkthdr.len += hdrsize;
		mh->m_len = hdrsize;
		mh->m_next = m;
		m->m_flags &= ~(M_PKTHDR|M_VXLANTAG);
	}
	mh->m_pkthdr.encaplen = hdrsize;
	if ((oldflags & CSUM_TSO) &&
		(mh = vpcmux_header_pullup(mh, &tpi)) == NULL)
			return (ENOMEM);
	mh->m_pkthdr.csum_flags = CSUM_UDP;
	mh->m_pkthdr.csum_flags |= ((oldflags & CSUM_TSO) << 2);
	mh->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
	mh->m_pkthdr.rcvif = vs->vs_underlay_ifp;

	vh = (struct vxlan_header *)mh->m_data;
	evh = (struct ether_vlan_header *)&vh->vh_ehdr;
	if (__predict_true(vpcmux_cache_lookup(vs, mh, evhvx))) {
		*mp = mh;
		return (0);
	}
	/* lookup MAC->IP forwarding table */
	vf = vpcmux_vxlanid_lookup(vs, mh->m_pkthdr.vxlanid);
	if (__predict_false(vf == NULL)) {
		DPRINTF("vxlanid %d not found\n", mh->m_pkthdr.vxlanid);
		m_freem(mh);
		return (ENOENT);
	}
	dst = &ro.ro_dst;
	/*   lookup IP using encapsulated dmac */
	rc = vpcmux_ftable_lookup(vf, evhvx, dst);
	if (__predict_false(rc)) {
		DPRINTF("no forwarding entry for dmac: %*D\n",
			   ETHER_ADDR_LEN, (caddr_t)evhvx, ":");
		vpcmux_fte_print(vs);
		m_freem(mh);
		return (rc);
	}
	if ((rc = vpcmux_nd_lookup(vs, dst, evh->evl_dhost))) {
		DPRINTF("%s failed in nd_lookup\n", __func__); 
		return (rc);
	}
	ifp = vs->vs_underlay_ifp;
	mh->m_pkthdr.rcvif = ifp;
	vpcmux_vxlanhdr_init(vf, vh, dst, mh, (caddr_t)evhvx, &tpi);
	vpcmux_cache_update(mh, evhvx);

	MPASS(mh->m_pkthdr.len == m_length(mh, NULL));
	/*
	 * do soft TSO if hardware doesn't support VXLAN offload
	 */
	if ((mh->m_pkthdr.csum_flags & CSUM_VX_TSO)
		&& !(ifp->if_capabilities & IFCAP_VXLANOFLD)) {
		if (__predict_false(!m_ismvec(mh))) {
			DPRINTF("%s failed - TSO but not MVEC\n", __func__); 
			m_freem(mh);
			return (EINVAL);
		}
		mh->m_pkthdr.csum_flags &= ~CSUM_VX_TSO;
		mtmp = mvec_tso((struct mbuf_ext*)mh, hdrsize, true);
		if (__predict_false(mtmp == NULL)) {
			DPRINTF("%s mvec_tso failed\n", __func__);
			m_freem(mh);
			return (ENOMEM);
		}
		mh = (void*)mtmp;
	} else {
		if (!(mh->m_pkthdr.csum_flags & CSUM_VX_TSO))
			MPASS(mh->m_pkthdr.len - ETHER_HDR_LEN <= ifp->if_mtu);
	}
	*mp = mh;
	return (0);
}

static int
vpcmux_vxlan_encap_chain(struct vpcmux_softc *vs, struct mbuf **mp, bool *can_batch)
{
	struct mbuf *mh, *mt, *mnext, *m;
	struct ifnet *ifp;
	int rc;

	mh = mt = NULL;
	*can_batch = true;
	m = *mp;
	*mp = NULL;
	ifp = NULL;
	do {
		mnext = m->m_nextpkt;
		m->m_nextpkt = NULL;
		rc = vpcmux_vxlan_encap(vs, &m);
		if (__predict_false(rc))
			break;
		if (mh == NULL) {
			mh = mt = m;
			ifp = m->m_pkthdr.rcvif;
		} else {
			mt->m_nextpkt = m;
			mt = m;
			if (__predict_false(ifp != m->m_pkthdr.rcvif))
				*can_batch = false;
		}
		MPASS(m != mnext);
		m = mnext;
	} while (m != NULL);
	if (__predict_false(mnext != NULL)) {
		DPRINTF("%s freeing after failed encap\n", __func__); 
		m_freechain(mnext);
	}
	*mp = mh;
	return (rc);
}

static int
vpcmux_mbuf_to_qid(if_t ifp __unused, struct mbuf *m __unused)
{
	return (0);
}

static int
vpcmux_transmit(if_t ifp, struct mbuf *m)
{
	struct ifnet *oifp;
	if_ctx_t ctx;
	struct vpcmux_softc *vs;
	struct mbuf *mp, *mnext;
	bool can_batch;
	int lasterr, rc;

	ctx = ifp->if_softc;
	vs = iflib_get_softc(ctx);
	oifp = vs->vs_underlay_ifp;
	if (__predict_false(oifp == NULL)) {
		m_freechain(m);
		return (ENOBUFS);
	}
	if ((m->m_flags & M_VXLANTAG) == 0)
		return (oifp->if_transmit_txq(ifp, m));

	mp = (void*)pktchain_to_mvec(m, ifp->if_mtu, M_NOWAIT);
	if (__predict_false(mp == NULL))
		return (ENOBUFS);
	vpc_epoch_begin();
	can_batch = true;
	lasterr = vpcmux_vxlan_encap_chain(vs, &m, &can_batch);
	if (__predict_false(lasterr))
		goto done;
	if (can_batch) {
		lasterr = oifp->if_transmit_txq(ifp, m);
		goto done;
	}

	mp = m;
	lasterr = 0;
	do {
		mnext = mp->m_nextpkt;
		MPASS(mnext != (void *)0xdeadc0dedeadc0de);
		mp->m_nextpkt = NULL;
		ifp = mp->m_pkthdr.rcvif;
		mp->m_pkthdr.rcvif = NULL;
		rc = oifp->if_transmit_txq(ifp, mp);
		if (rc)
			lasterr = rc;
		mp = mnext;
	} while (mp != NULL);
 done:
	vpc_epoch_end();
	return (lasterr);
}

static struct mbuf *
vpcmux_bridge_input(if_t ifp, struct mbuf *m)
{
	struct vpcmux_softc *vs;

	vs = ifp->if_bridge;
	ETHER_BPF_MTAP(vs->vs_ifp, m);
	if (vs->vs_ifp->if_bridge == NULL)
		return (m);
	return (*(vs->vs_ifp)->if_bridge_input)(vs->vs_ifp, m);
}

static int
vpcmux_bridge_output(struct ifnet *ifp, struct mbuf *m,
					  struct sockaddr *s __unused, struct rtentry *r__unused)
{
	panic("%s should not be called", __func__);
	m_freechain(m);
	return (0);
}

static void
vpcmux_bridge_linkstate(struct ifnet *ifp __unused)
{
}


#define VPCMUX_CAPS														\
	IFCAP_TSO |IFCAP_HWCSUM | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM |	\
	IFCAP_VLAN_MTU | IFCAP_TXCSUM_IPV6 | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU | IFCAP_LINKSTATE

static int
vpcmux_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct vpcmux_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;

	atomic_add_int(&clone_count, 1);
	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	scctx->isc_capenable = VPCMUX_CAPS;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
		| CSUM_IP6_UDP | CSUM_IP6_TCP;
	/* register vs_record */
	ck_epoch_register(&vpc_epoch, &vs->vs_record, NULL);
	vs->vs_ctx = ctx;
	vs->vs_ifp = iflib_get_ifp(ctx);
	vs->vs_min_port = IPPORT_HIFIRSTAUTO;	/* 49152 */
	vs->vs_max_port = IPPORT_HILASTAUTO;	/* 65535 */

	/* init vs_vxftable */
	art_tree_init(&vs->vs_vxftable, 3 /* VXLANID is 3 bytes */);
	return (0);
}

static int
vpcmux_attach_post(if_ctx_t ctx)
{
	if_t ifp;

	ifp = iflib_get_ifp(ctx);
	if_settransmitfn(ifp, vpcmux_transmit);
	if_settransmittxqfn(ifp, vpcmux_transmit);
	if_setmbuftoqidfn(ifp, vpcmux_mbuf_to_qid);
	/*
	 * should really be pulled from the lowest
	 * interface configured, but hardcode for now
	 */
	if_setmtu(ifp, ETHERMTU - 50);
	return (0);
}


static int
vpcmux_ftable_free_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	free(value, M_VPCMUX);
	return (0);
}

static int
vpcmux_vxftable_free_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct vpcmux_ftable *ftable = value;

	art_iter(&ftable->vf_ftable, vpcmux_ftable_free_callback, NULL);
	free(value, M_VPCMUX);
	return (0);
}


static int
vpcmux_detach(if_ctx_t ctx)
{
	struct vpcmux_softc *vs = iflib_get_softc(ctx);
	struct ifreq ifr;
	struct ifnet *ifp;

	ck_epoch_unregister(&vs->vs_record);
	art_iter(&vs->vs_vxftable, vpcmux_vxftable_free_callback, NULL);
	if (vs->vs_underlay_vctx) {
		ifr.ifr_index = 0;
		ifp = vs->vs_underlay_ifp;
		(void)ifp->if_ioctl(ifp, SIOCSIFVXLANPORT, (caddr_t)&ifr);
		ifp->if_bridge = NULL;
		wmb();
		ifp->if_bridge_input = NULL;
		ifp->if_bridge_output = NULL;
		ifp->if_bridge_linkstate = NULL;
		vmmnet_rele(vs->vs_underlay_vctx);
	}
	atomic_add_int(&clone_count, -1);
	return (0);
}

static void
vpcmux_init(if_ctx_t ctx)
{
}

static void
vpcmux_stop(if_ctx_t ctx)
{
}

static int
vpcmux_set_listen(struct vpcmux_softc *vs, const struct sockaddr *addr)
{
	const struct sockaddr_in *sin;

	/* v4 only XXX */
	sin = (const struct sockaddr_in *)addr;
	vs->vs_vxlan_port = sin->sin_port;
	bcopy(sin, &vs->vs_addr, sizeof(*sin));
	return (0);
}

static int
vpcmux_underlay_attach(struct vpcmux_softc *vs, const vpc_id_t *id)
{
	struct ifnet *ifp;
	struct ifreq ifr;
	vpc_ctx_t vctx;
	if_ctx_t ethctx;
	device_t dev;
	vpc_handle_type_t *htype;
	uint8_t objtype;
	int rc;

	dev = iflib_get_dev(vs->vs_ctx);
	if (vs->vs_vxlan_port == 0) {
		device_printf(dev, "%s vxlan port not set", __func__);
		return (EAGAIN);
	}
	vctx = vmmnet_lookup(id);
	htype = (void *)&vctx->v_obj_type;
	objtype = htype->vht_obj_type;
	if (objtype != VPC_OBJ_ETHLINK) {
		if (bootverbose)
			device_printf(dev,"bad type passed to %s id: %16D type: %d expected type: %d\n",
				   __func__, id, ":", objtype, VPC_OBJ_ETHLINK);
		return (EINVAL);
	}
	if (vctx->v_ifp == NULL) {
		if (bootverbose)
			device_printf(dev, "underlay ethlink not attached %s id: %16D\n",
				   __func__, id, ":");
		return (EAGAIN);

	}
	ethctx = vctx->v_ifp->if_softc;
	ifp = ethlink_ifp_get(ethctx);
	if (!(ifp->if_capabilities & IFCAP_VXLANDECAP)) {
		if (bootverbose)
			device_printf(dev, "%s underlay interface %s id: %16D doesn't support vxlan decap\n",
				   __func__, ifp->if_xname, id, ":");
		return (EOPNOTSUPP);
	}

	ifr.ifr_index = vs->vs_vxlan_port;

	rc = ifp->if_ioctl(ifp, SIOCSIFVXLANPORT, (caddr_t)&ifr);
	if (rc == 0) {
		vmmnet_ref(vctx);
		vs->vs_underlay_vctx = vctx;
		vs->vs_underlay_ifp = ifp;
		ifp->if_bridge_input = vpcmux_bridge_input;
		ifp->if_bridge_output = vpcmux_bridge_output;
		ifp->if_bridge_linkstate = vpcmux_bridge_linkstate;
		wmb();
		ifp->if_bridge = vs;
	}
	return (rc);
}


static int
vpcmux_fte_update(struct vpcmux_softc *vs, const struct vpcmux_fte *vfte, bool add)
{
	struct vpcmux_ftable *ftable;
	uint32_t addr, *addrp;
	char buf[ETHER_ADDR_LEN];

	/* XXX v4 */
	if (vfte->vf_protoaddr.sa_family != AF_INET)
		return (EAFNOSUPPORT);
	addr = ((const struct sockaddr_in *)(&vfte->vf_protoaddr))->sin_addr.s_addr; /* XXX v4 */
	ftable = vpcmux_vxlanid_lookup(vs, vfte->vf_vni);
	if (ftable == NULL) {
		if (add == false)
			return (0);
		ftable = malloc(sizeof(*ftable), M_VPCMUX, M_WAITOK|M_ZERO);
		art_tree_init(&ftable->vf_ftable, ETHER_ADDR_LEN);
		ftable->vf_vni = vfte->vf_vni;
		ftable->vf_vs = vs;
		art_insert(&vs->vs_vxftable, (const char *)&vfte->vf_vni, ftable);
	}
	if (add == false) {
		addrp = art_delete(&ftable->vf_ftable, (const char *)&addr);
		free(addrp, M_VPCMUX);
		if (art_size(&ftable->vf_ftable) == 0) {
			art_delete(&vs->vs_vxftable, (const char *)&vfte->vf_vni);
			free(ftable, M_VPCMUX);
		}
	} else {
		/* do an arp resolve on proto addr so that it's in cache */
		(void)vpcmux_nd_lookup(vs, &vfte->vf_protoaddr, buf);
		vpcmux_ftable_insert(ftable, (const char *)vfte->vf_hwaddr,
							  &vfte->vf_protoaddr);
	}
	return (0);
}

static int
vpcmux_ftable_print_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	char buf[5];

	buf[4] = 0;
	inet_ntoa_r(((struct sockaddr_in *)value)->sin_addr, buf);
	DPRINTF("vni: 0x%x dmac: %*D ip: %s\n",
		   *(uint32_t *)data, ETHER_ADDR_LEN, key, ":", buf);
	return (0);
}

static int
vpcmux_vxftable_print_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct vpcmux_ftable *ftable = value;

	art_iter(&ftable->vf_ftable, vpcmux_ftable_print_callback, (void*)(uintptr_t)key);
	return (0);
}

static void
vpcmux_fte_print(struct vpcmux_softc *vs)
{

	art_iter(&vs->vs_vxftable, vpcmux_vxftable_print_callback, NULL);
}

static int
vpcmux_ftable_count_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	uint32_t *count = data;
	(*count)++;
	return (0);
}

static int
vpcmux_vxftable_count_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct vpcmux_ftable *ftable = value;

	art_iter(&ftable->vf_ftable, vpcmux_ftable_count_callback, data);
	return (0);
}

static int
vpc_fte_count(struct vpcmux_softc *vs)
{
	uint32_t count = 0;

	art_iter(&vs->vs_vxftable, vpcmux_vxftable_count_callback, &count);
	return (count);
}

static int
vpcmux_fte_list(struct vpcmux_softc *vs, struct vpcmux_fte_list **vflp, size_t *length)
{
	struct vpcmux_fte_list *vfl;

	if (*length == sizeof(struct vpcmux_fte_list)) {
		vfl = malloc(sizeof(*vfl), M_TEMP, M_WAITOK|M_ZERO);
		vfl->vfl_count = vpc_fte_count(vs);
		*vflp = vfl;
		return (0);
	}
#if 0
	if (length != (sizeof(struct vpcmux_fte_list) +
				   vfl->vfl_count*sizeof(struct vpcmux_fte)))
		return (EINVAL);
#endif	
	/* XXX implement me */
	return (EOPNOTSUPP);
}


int
vpcmux_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
				 size_t *outlen, void **outdata)
{
	struct ifnet *ifp = ctx->v_ifp;
	if_ctx_t ifctx = ifp->if_softc;
	struct vpcmux_softc *vs = iflib_get_softc(ifctx);

	switch(op) {
		case VPC_VPCMUX_OP_LISTEN: {
			const struct sockaddr *vl_addr = in;

			if (inlen != sizeof(*vl_addr))
				return (EBADRPC);
			return (vpcmux_set_listen(vs, vl_addr));
			break;
		}
		case VPC_VPCMUX_OP_UNDERLAY_ATTACH: {
			const vpc_id_t *id = in;

			if (inlen != sizeof(*id))
				return (EBADRPC);
			return (vpcmux_underlay_attach(vs, id));
		}
		case VPC_VPCMUX_OP_FTE_DEL:
		case VPC_VPCMUX_OP_FTE_SET: {
			const struct vpcmux_fte *vfte = in;

			if (inlen != sizeof(*vfte))
				return (EBADRPC);
			return (vpcmux_fte_update(vs, vfte, op == VPC_VPCMUX_FTE_SET));
			break;
		}
		case VPC_VPCMUX_OP_FTE_LIST: {
			struct vpcmux_fte_list *vfl;
			int rc;

			if ((rc = vpcmux_fte_list(vs, &vfl, outlen)))
				return (rc);
			*outdata = vfl;
			break;
		}
	}
	return (EOPNOTSUPP);
}

static device_method_t vpcmux_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, vpcmux_cloneattach),
	DEVMETHOD(ifdi_attach_post, vpcmux_attach_post),
	DEVMETHOD(ifdi_detach, vpcmux_detach),
	DEVMETHOD(ifdi_init, vpcmux_init),
	DEVMETHOD(ifdi_stop, vpcmux_stop),
	DEVMETHOD_END
};

static driver_t vpcmux_iflib_driver = {
	"vpcmux", vpcmux_if_methods, sizeof(struct vpcmux_softc)
};

char vpcmux_driver_version[] = "0.0.1";

static struct if_shared_ctx vpcmux_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_driver_version = vpcmux_driver_version,
	.isc_driver = &vpcmux_iflib_driver,
	.isc_flags = IFLIB_PSEUDO,
	.isc_name = "vpcmux",
};

if_shared_ctx_t vpcmux_sctx = &vpcmux_sctx_init;
static if_pseudo_t vpcmux_pseudo;

static int
vpcmux_module_init(void)
{
	struct egress_cache **ecpp, *ecp;
	int i, ec_size;

	vpcmux_pseudo = iflib_clone_register(vpcmux_sctx);
	if (vpcmux_pseudo == NULL)
		return (ENXIO);

	/* DPCPU hdr_cache init */
	ec_size = roundup(sizeof(*ecp), CACHE_LINE_SIZE);
	ecp = malloc(ec_size*mp_ncpus, M_VPCMUX, M_WAITOK|M_ZERO);

	CPU_FOREACH(i) {
		ecpp = DPCPU_ID_PTR(i, hdr_cache);
		*ecpp = ecp;
		ecp = (struct egress_cache *)(((caddr_t)ecp) + ec_size);
	}

	return (0);
}

static void
vpcmux_module_deinit(void)
{
	struct egress_cache *ecp;

	VPCMUX_LOCK();
	VPCMUX_UNLOCK();
	ecp = DPCPU_ID_GET(0, hdr_cache);
	free(ecp, M_VPCMUX);
	iflib_clone_deregister(vpcmux_pseudo);
}


static int
vpcmux_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
		case MOD_LOAD:
			if ((err = vpcmux_module_init()) != 0)
				return (err);
			break;
		case MOD_UNLOAD:
			if (clone_count == 0)
				vpcmux_module_deinit();
			else
				return (EBUSY);
			break;
		default:
			return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t vpcmux_moduledata = {
	"vpcmux",
	vpcmux_module_event_handler,
	NULL
};

DECLARE_MODULE(vpcmux, vpcmux_moduledata, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(vpcmux, 1);
MODULE_DEPEND(vpcmux, iflib, 1, 1, 1);
