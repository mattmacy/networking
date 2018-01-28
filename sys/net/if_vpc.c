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

#include <net/if_vpc.h>

#include <ck_epoch.h>

#include "ifdi_if.h"

#include <machine/in_cksum.h>

static ck_epoch_t vpc_epoch;

#define VPC_DEBUG

#ifdef VPC_DEBUG
#define  DPRINTF printf
#else
#define DPRINTF(...)
#endif

#ifdef notyet
typedef struct vxlan_tables {
	art_tree *vt_ipv4_rt;
	art_tree *vt_ipv4_rt_ro;
	art_tree *vt_ipv6_rt;
	art_tree *vt_ipv6_rt_ro;
	art_tree *vt_vxl;
	art_tree *vt_vxl_ro;
} *vxtbl_t;
#endif

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


struct vpc_ftable {
	uint32_t vf_vni;
	struct vpc_softc *vf_vs;
	art_tree vf_ftable;
};

struct egress_cache {
	uint16_t ec_hdr[3];
	uint16_t ec_ifindex;
	int ec_ticks;
	struct vxlan_header ec_vh;
};

struct vf_entry {
	struct sockaddr ve_addr;
};

struct tso_pkt_info {
	uint16_t tpi_etype;
	uint8_t tpi_l2_len;
	uint8_t tpi_l3_len;
	uint8_t tpi_l4_len;
	uint8_t tpi_v6:1;
	uint8_t tpi_proto:7;
};

extern int mp_ncpus;
static int vpc_ifindex_target;
static bool exiting = false;
static struct ifp_cache *vpc_ic;
static struct grouptask vpc_ifp_task;
static struct sx vpc_lock;
SX_SYSINIT(vpc, &vpc_lock, "VPC global");

#define VPC_LOCK() sx_xlock(&vpc_lock)
#define VPC_UNLOCK() sx_xunlock(&vpc_lock)


DPCPU_DEFINE(struct egress_cache *, hdr_cache);
DPCPU_DEFINE(ck_epoch_record_t *, vpc_epoch_record);
ck_epoch_record_t vpc_global_record;

/*
 * ifconfig ixl0 alias 10.1.3.4
 *
 * # Virtual Private Cloud
 * ifconfig vpc0 create
 * ifconfig vpc0 az az0
 * ifconfig vpc0 listen 10.1.3.4:3947
 *
 * ifconfig vpcb0 addm vpc0
 *
 */

static MALLOC_DEFINE(M_VPC, "vpc", "virtual private cloud");

struct ifp_cache {
	uint16_t ic_ifindex_max;
	uint16_t ic_size;
	uint32_t ic_pad;
	struct ifnet *ic_ifps[0];
};

struct vpc_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
	struct sockaddr vs_addr;
	uint16_t vs_vxlan_port;
	uint16_t vs_fibnum;
	uint16_t vs_min_port;
	uint16_t vs_max_port;
	art_tree vs_vxftable; /* vxlanid -> ftable */
	ck_epoch_record_t vs_record;
	/* XXX temporary */
	void	(*vs_old_if_input)		/* input routine (from h/w driver) */
		(struct ifnet *, struct mbuf *);
	struct ifnet *vs_ifparent;
};

static void vpc_fte_print(struct vpc_softc *vs);

static int clone_count;

static int
hdrcmp(uint16_t *lhs, uint16_t *rhs)
{
	return ((lhs[0] ^ rhs[0]) |
			(lhs[1] ^ rhs[1]) |
			(lhs[2] ^ rhs[2]));
}

static void *
m_advance(struct mbuf **pm, int *poffset, int len)
{
	struct mbuf *m = *pm;
	int offset = *poffset;
	uintptr_t p = 0;

	MPASS(!m_ismvec(m));
	MPASS(len > 0);

	for (;;) {
		if (offset + len < m->m_len) {
			offset += len;
			p = mtod(m, uintptr_t) + offset;
			break;
		}
		len -= m->m_len - offset;
		m = m->m_next;
		offset = 0;
		MPASS(m != NULL);
	}
	*poffset = offset;
	*pm = m;
	return ((void *)p);
}

static void *
mvec_advance(const struct mbuf *m, struct mvec_cursor *mc, int offset)
{
	const struct mbuf_ext *mext = (const struct mbuf_ext *)m;
	const struct mvec_ent *me = mext->me_ents;
	const struct mvec_header *mh = &mext->me_mh;
	int rem;

	if (offset >= m->m_pkthdr.len)
		return (NULL);
	rem = offset;

	me += mh->mh_start + mc->mc_idx ;
	MPASS(me->me_len);
	MPASS(me->me_cl);
	mc->mc_off += offset;
	while (mc->mc_off >= me->me_len) {
		mc->mc_off -= me->me_len;
		mc->mc_idx++;
		me++;
	}
	return (void *)(me_data(me) + mc->mc_off);
}

static inline int
parse_encap_pkt(struct mbuf *m0, struct tso_pkt_info *tpi)
{
	struct ether_vlan_header *evh;
	struct tcphdr *th;
	struct mvec_cursor mc;
	struct mbuf *m;
	int eh_type, offset, ipproto;
	int l2len, l3len;
	void *l3hdr;

	MPASS(m_ismvec(m0));

	offset = mc.mc_idx = mc.mc_off = 0;
	m = m0;
	if (m0->m_len < ETHER_HDR_LEN)
		return (0);

	evh = (void*)m0->m_data;
	eh_type = ntohs(evh->evl_encap_proto);
	if (eh_type == ETHERTYPE_VLAN) {
		eh_type = ntohs(evh->evl_proto);
		l2len = sizeof(*evh);
	} else
		l2len = ETHER_HDR_LEN;

	if (__predict_true(m_ismvec(m)))
		l3hdr = mvec_advance(m, &mc, l2len);
	else
		l3hdr = m_advance(&m, &offset, l2len);

	switch(eh_type) {
#ifdef INET6
	case ETHERTYPE_IPV6:
	{
		struct ip6_hdr *ip6 = l3hdr;

		l3len = sizeof(*ip6);
		ipproto = ip6->ip6_nxt;
		tpi->tpi_v6 = 1;
		break;
	}
#endif
#ifdef INET
	case ETHERTYPE_IP:
	{
		struct ip *ip = l3hdr;

		l3len = ip->ip_hl << 2;
		ipproto = ip->ip_p;
		tpi->tpi_v6 = 0;
		break;
	}
#endif
	case ETHERTYPE_ARP:
	default:
		l3len = 0;
		ipproto = 0;
		tpi->tpi_v6 = 0;
		break;
	}
	tpi->tpi_etype = eh_type;
	tpi->tpi_proto = ipproto;
	tpi->tpi_l2_len = l2len;
	tpi->tpi_l3_len = l3len;

	if (ipproto != IPPROTO_TCP) {
		return (0);
	} else if (__predict_true(m_ismvec(m)))
		th = mvec_advance(m, &mc, l3len);
	else
		th = m_advance(&m, &offset, l3len);
	tpi->tpi_l4_len = th->th_off << 2;
	MPASS(l2len && l3len && tpi->tpi_l4_len); 
	return (1);
}

static void
_task_fn_ifp_update(void *context __unused)
{
	struct ifnet **ifps, **ifps_orig;
	int i, max, count;

	if (vpc_ifindex_target > vpc_ic->ic_size) {
		/* grow and replace after wait */
	}
	max = vpc_ic->ic_ifindex_max;
	ifps = malloc(sizeof(ifps)*max, M_VPC, M_WAITOK|M_ZERO);
	ifps_orig = vpc_ic->ic_ifps;
	for (count = i = 0; i < max; i++) {
		if (ifps_orig[i] == NULL)
			continue;
		if (!(ifps_orig[i]->if_flags & IFF_DYING))
			continue;
		ifps[i] = ifps_orig[i];
		ifps_orig[i] = NULL;
		count++;
	}
	if (count == 0)
		goto done;
	ck_epoch_synchronize(&vpc_global_record);
	for (i = 0; i < max && count; i++){
		if (ifps[i] == NULL)
			continue;
		if_rele(ifps[i]);
		count--;
	}
 done:
	free(ifps, M_VPC);
	if (__predict_false(exiting)) {
		VPC_LOCK();
		free(vpc_ic, M_VPC);
		vpc_ic = NULL;
		wakeup(&exiting);
		VPC_UNLOCK();
	}
}

static struct vpc_ftable *
vpc_vxlanid_lookup(struct vpc_softc *vs, uint32_t vxlanid)
{

	return (art_search(&vs->vs_vxftable, (const unsigned char *)&vxlanid));
}

static int
vpc_ftable_lookup(struct vpc_ftable *vf, struct ether_vlan_header *evh,
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
vpc_ftable_insert(struct vpc_ftable *vf, caddr_t evh,
				  struct sockaddr *dst)
{
	struct vf_entry *vfe;

	vfe = malloc(sizeof(*vfe), M_VPC, M_WAITOK);
	bcopy(dst, &vfe->ve_addr, sizeof(struct sockaddr));
	art_insert(&vf->vf_ftable, (const unsigned char *)evh, vfe);
}

static uint16_t
vpc_sport_hash(struct vpc_softc *vs, caddr_t data, uint16_t seed)
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
vpc_ip_init(struct vpc_ftable *vf, struct vxlan_header *vh, struct sockaddr *dstip, int len, int mtu)
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
vpc_vxlanhdr_init(struct vpc_ftable *vf, struct vxlan_header *vh, 
				  struct sockaddr *dstip, struct ifnet *ifp, struct mbuf *m,
				  caddr_t hdr, struct tso_pkt_info *tpi)
{
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *uh;
	struct vxlanhdr *vhdr;
	caddr_t smac;
	int len, offset;
	uint16_t seed;
	struct mvec_cursor mc;

	seed = 0;
	len = m->m_pkthdr.len;
	smac = ifp->if_hw_addr;
	eh = &vh->vh_ehdr;
	if (tpi->tpi_l4_len) {
		struct tcphdr *th;

		if (m_ismvec(m)) {
			mc.mc_idx = mc.mc_off = 0;
			th = mvec_advance(m, &mc, m->m_pkthdr.encaplen + tpi->tpi_l2_len + tpi->tpi_l3_len);
		} else {
			offset = 0;
			th = m_advance(&m, &offset,  m->m_pkthdr.encaplen + tpi->tpi_l2_len + tpi->tpi_l3_len);
		}
		seed = th->th_sport ^ th->th_dport;
	}

	eh->ether_type = htons(ETHERTYPE_IP); /* v4 only to start */
	/* arp resolve fills in dest */
	bcopy(smac, eh->ether_shost, ETHER_ADDR_LEN);

	vpc_ip_init(vf, vh, dstip, m->m_pkthdr.len, ifp->if_mtu);

	uh = (struct udphdr*)(uintptr_t)&vh->vh_udphdr;
	uh->uh_sport = htons(vpc_sport_hash(vf->vf_vs, hdr, seed));
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
vpc_cache_lookup(struct vpc_softc *vs, struct mbuf *m, struct ether_vlan_header *evh)
{
	struct egress_cache *ecp;
	struct ifnet *ifp;

	_critical_enter();
	ecp = DPCPU_GET(hdr_cache);
	if (__predict_false(ecp->ec_ticks == 0))
		goto skip;
	/*
	 * Is still in caching window
	 */
	if (__predict_false(ticks - ecp->ec_ticks < hz/5)) {
		ecp->ec_ticks = 0;
		goto skip;
	}
	ifp = vpc_ic->ic_ifps[ecp->ec_ifindex];
	if (ifp == NULL) {
		ecp->ec_ticks = 0;
		goto skip;
	}
	if (ifp->if_flags & IFF_DYING) {
		ecp->ec_ticks = 0;
		GROUPTASK_ENQUEUE(&vpc_ifp_task);
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
		m->m_pkthdr.rcvif = ifp;
		return (1);
	}
	skip:
	_critical_exit();
	return (0);
}

static void
vpc_cache_update(struct mbuf *m, struct ether_vlan_header *evh, uint16_t ifindex)
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
	ecp->ec_ifindex = ifindex;
	_critical_exit();
}

static int
vpc_ifp_cache(struct vpc_softc *vs, struct ifnet *ifp)
{
	if (__predict_false(vpc_ic->ic_size -1 < ifp->if_index)) {
#ifndef INVARIANTS
		struct ifp_cache *newcache;

		newcache = realloc(vpc_ic, sizeof(ifp)*ifp->if_index+1, M_VPC, M_NOWAIT);
		if (newcache == NULL) {
			GROUPTASK_ENQUEUE(&vpc_ifp_task);
			return (1);
		}
		vpc_ic->ic_size = ifp->if_index+1;
#else
		GROUPTASK_ENQUEUE(&vpc_ifp_task);
		return (1);
#endif
	}
	if (vpc_ic->ic_ifps[ifp->if_index] == ifp)
		return (0);

	/* XXX -- race if reference twice  -- need to actually serialize with VPC_LOCK */
	if (vpc_ic->ic_ifindex_max < ifp->if_index)
		vpc_ic->ic_ifindex_max = ifp->if_index;
	MPASS(vpc_ic->ic_ifps[ifp->if_index] == NULL);
	if_ref(ifp);
	vpc_ic->ic_ifps[ifp->if_index] = ifp;
	return (0);
}

static int
vpc_nd_lookup(struct vpc_softc *vs, if_t *ifpp, struct sockaddr *dst, uint8_t *ether_addr)
{
	struct rtentry *rt;
	int rc;
	if_t ifp;

	if (*ifpp == NULL)  {
		rt = rtalloc1_fib(dst, 0, 0, vs->vs_fibnum);
		if (__predict_false(rt == NULL))
			return (ENETUNREACH);
		if (__predict_false(!(rt->rt_flags & RTF_UP) ||
							(rt->rt_ifp == NULL) ||
							!RT_LINK_IS_UP(rt->rt_ifp))) {
		RTFREE_LOCKED(rt);
		return (ENETUNREACH);
		}
		ifp = rt->rt_ifp;
		rc = vpc_ifp_cache(vs, ifp);
		RTFREE_LOCKED(rt);

		if (__predict_false(rc)) {
			DPRINTF("failed to cache interface reference\n");
			return (EDOOFUS);
		}
	} else
		ifp = *ifpp;
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
	*ifpp = ifp;
	return (rc);
}

static struct mbuf *
vpc_header_pullup(struct mbuf *mp, struct tso_pkt_info *tpi)
{
	int minhlen;
	struct mbuf *m;

	minhlen = mp->m_pkthdr.encaplen + ETHER_HDR_LEN + sizeof(struct ip) + sizeof(struct tcphdr);
	MPASS(mp->m_pkthdr.len >= minhlen);
	m = m_pullup(mp, mp->m_pkthdr.encaplen + tpi->tpi_l2_len + 
				 tpi->tpi_l3_len + tpi->tpi_l4_len);
	if (__predict_false(m == NULL))
		m_freem(mp);
	return (m);
}

static int
vpc_vxlan_encap(struct vpc_softc *vs, struct mbuf **mp)
{
	struct ether_vlan_header *evh, *evhvx;
	struct vxlan_header *vh;
	struct mbuf_ext *mtmp;
	struct mbuf *mh, *m;
	struct vpc_ftable *vf;
	struct sockaddr *dst;
	struct route ro;
	struct ifnet *ifp;
	struct tso_pkt_info tpi;
	uint32_t oldflags;
	int rc, hdrsize;

	m = *mp;
	ETHER_BPF_MTAP(iflib_get_ifp(vs->vs_ctx), m);
	*mp = NULL;
	if (!(m->m_flags & M_VXLANTAG)) {
		m_freem(m);
		return (EINVAL);
	}
	parse_encap_pkt(m, &tpi);

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
		(mh = vpc_header_pullup(mh, &tpi)) == NULL)
			return (ENOMEM);
	mh->m_pkthdr.csum_flags = CSUM_UDP;
	mh->m_pkthdr.csum_flags |= ((oldflags & CSUM_TSO) << 2);
	mh->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);

	vh = (struct vxlan_header *)mh->m_data;
	evh = (struct ether_vlan_header *)&vh->vh_ehdr;
	if (__predict_true(vpc_cache_lookup(vs, mh, evhvx))) {
		*mp = mh;
		return (0);
	}
	/* lookup MAC->IP forwarding table */
	vf = vpc_vxlanid_lookup(vs, mh->m_pkthdr.vxlanid);
	if (__predict_false(vf == NULL)) {
		DPRINTF("vxlanid %d not found\n", mh->m_pkthdr.vxlanid);
		m_freem(mh);
		return (ENOENT);
	}
	dst = &ro.ro_dst;
	/*   lookup IP using encapsulated dmac */
	rc = vpc_ftable_lookup(vf, evhvx, dst);
	if (__predict_false(rc)) {
		DPRINTF("no forwarding entry for dmac: %*D\n",
			   ETHER_ADDR_LEN, (caddr_t)evhvx, ":");
		vpc_fte_print(vs);
		m_freem(mh);
		return (rc);
	}
	ifp = NULL;
	if ((rc = vpc_nd_lookup(vs, &ifp, dst, evh->evl_dhost))) {
		DPRINTF("%s failed in nd_lookup\n", __func__); 
		return (rc);
	}
	mh->m_pkthdr.rcvif = ifp;
	vpc_vxlanhdr_init(vf, vh, dst, ifp, mh, (caddr_t)evhvx, &tpi);
	vpc_cache_update(mh, evhvx, ifp->if_index);

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
vpc_vxlan_encap_chain(struct vpc_softc *vs, struct mbuf **mp, bool *can_batch)
{
	struct mbuf *mh, *mt, *mnext, *m;
	struct ifnet *ifp;
	int rc;

	mh = mt = NULL;
	*can_batch = true;
	m = *mp;
	*mp = NULL;
	do {
		mnext = m->m_nextpkt;
		m->m_nextpkt = NULL;
		rc = vpc_vxlan_encap(vs, &m);
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
vpc_mbuf_to_qid(if_t ifp __unused, struct mbuf *m __unused)
{
	return (0);
}

static int
vpc_transmit(if_t ifp, struct mbuf *m)
{
	if_ctx_t ctx = ifp->if_softc;
	struct vpc_softc *vs = iflib_get_softc(ctx);
	struct mbuf *mp, *mnext;
	bool can_batch;
	int lasterr, rc;

	can_batch = true;
	if ((m->m_flags & M_VXLANTAG) == 0) {
		DPRINTF("got untagged packet\n");
		m_freechain(m);
		return (EINVAL);
	}
	_critical_enter();
	sched_pin();
	ck_epoch_begin(DPCPU_GET(vpc_epoch_record), NULL);
	_critical_exit();

	lasterr = vpc_vxlan_encap_chain(vs, &m, &can_batch);
	if (__predict_false(lasterr))
		goto done;
	ifp = m->m_pkthdr.rcvif;
	if (can_batch) {
		lasterr = ifp->if_transmit_txq(ifp, m);
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
		rc = ifp->if_transmit_txq(ifp, mp);
		if (rc)
			lasterr = rc;
		mp = mnext;
	} while (mp != NULL);
 done:
	_critical_enter();
	ck_epoch_end(DPCPU_GET(vpc_epoch_record), NULL);
	sched_unpin();
	_critical_exit();
	return (lasterr);
}

#define VPC_CAPS														\
	IFCAP_TSO |IFCAP_HWCSUM | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM |	\
	IFCAP_VLAN_MTU | IFCAP_TXCSUM_IPV6 | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU | IFCAP_LINKSTATE

static int
vpc_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct vpc_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;

	atomic_add_int(&clone_count, 1);
	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	scctx->isc_capenable = VPC_CAPS;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
		| CSUM_IP6_UDP | CSUM_IP6_TCP;
	/* register vs_record */
	ck_epoch_register(&vpc_epoch, &vs->vs_record, NULL);
	vs->vs_ctx = ctx;
	vs->vs_min_port = IPPORT_HIFIRSTAUTO;	/* 49152 */
	vs->vs_max_port = IPPORT_HILASTAUTO;	/* 65535 */

	/* init vs_vxftable */
	art_tree_init(&vs->vs_vxftable, 3 /* VXLANID is 3 bytes */);
	return (0);
}

static int
vpc_attach_post(if_ctx_t ctx)
{
	if_t ifp;

	ifp = iflib_get_ifp(ctx);
	if_settransmitfn(ifp, vpc_transmit);
	if_settransmittxqfn(ifp, vpc_transmit);
	if_setmbuftoqidfn(ifp, vpc_mbuf_to_qid);
	/*
	 * should really be pulled from the lowest
	 * interface configured, but hardcode for now
	 */
	if_setmtu(ifp, ETHERMTU - 50);
	return (0);
}


static int
vpc_ftable_free_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	free(value, M_VPC);
	return (0);
}

static int
vpc_vxftable_free_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct vpc_ftable *ftable = value;

	art_iter(&ftable->vf_ftable, vpc_ftable_free_callback, NULL);
	free(value, M_VPC);
	return (0);
}


static int
vpc_detach(if_ctx_t ctx)
{
	struct vpc_softc *vs = iflib_get_softc(ctx);

	ck_epoch_unregister(&vs->vs_record);
	vs->vs_ifparent->if_input = vs->vs_old_if_input;
	vs->vs_ifparent->if_pspare[3] = NULL;
	art_iter(&vs->vs_vxftable, vpc_vxftable_free_callback, NULL);

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

static void
vpc_if_input(struct ifnet *ifp, struct mbuf *m)
{
	struct vpc_softc *vs;
	struct ifnet *vsifp;
	struct ether_header *eh;

	vs = ifp->if_pspare[3];
	vsifp = iflib_get_ifp(vs->vs_ctx);
	eh = mtod(m, struct ether_header*);
	ETHER_BPF_MTAP(vsifp, m);
	if (ntohs(eh->ether_type) == ETHERTYPE_ARP) {
		m->m_pkthdr.rcvif = ifp;
		vs->vs_old_if_input(ifp, m);
	} else {
		m->m_pkthdr.rcvif = vsifp;
		vsifp->if_input(vsifp, m);
	}
}

static int
vpc_set_listen(struct vpc_softc *vs, struct vpc_listen *vl)
{
	struct route ro;
	struct ifnet *ifp;
	struct ifreq ifr;
	struct rtentry *rt;
	struct sockaddr_in *sin;
	int rc;

	rc = 0;
	/* v4 only XXX */
	sin = (struct sockaddr_in *)&vl->vl_addr;
	vs->vs_vxlan_port = sin->sin_port;
	bcopy(sin, &vs->vs_addr, sizeof(*sin));
	bzero(&ro, sizeof(ro));
	bcopy(sin, &ro.ro_dst, sizeof(struct sockaddr));
	/* lookup route to find interface */
	in_rtalloc_ign(&ro, 0, vs->vs_fibnum);
	rt = ro.ro_rt;
	if (__predict_false(rt == NULL))
		return (ENETUNREACH);
	if (__predict_false(!(rt->rt_flags & RTF_UP) ||
						(rt->rt_ifp == NULL))) {
		rc = ENETUNREACH;
		goto fail;
	}
	ifp = rt->rt_ifp;
	if (!(ifp->if_capabilities & IFCAP_VXLANDECAP)) {
		rc = EOPNOTSUPP;
		goto fail;
	}
	/* XXX temporary until we have vpcb in place */
	if (vs->vs_ifparent == NULL) {
		vs->vs_old_if_input = ifp->if_input;
		vs->vs_ifparent = ifp;
	}
	ifp->if_pspare[3] = vs;
	ifp->if_input = vpc_if_input;
	ifr.ifr_index = vs->vs_vxlan_port;

	rc = ifp->if_ioctl(ifp, SIOCSIFVXLANPORT, (caddr_t)&ifr);
 fail:
	RTFREE(rt);
	return (rc);
}

static int
vpc_fte_update(struct vpc_softc *vs, struct vpc_fte_update *vfu, bool add)
{
	struct vpc_ftable *ftable;
	struct vpc_fte *vfte;
	uint32_t addr, *addrp;
	char buf[ETHER_ADDR_LEN];
	if_t ifp;

	vfte = &vfu->vfu_vfte;
	if (vfte->vf_protoaddr.sa_family != AF_INET)
		return (EAFNOSUPPORT);
	addr = ((struct sockaddr_in *)(&vfte->vf_protoaddr))->sin_addr.s_addr; /* XXX v4 */
	ftable = vpc_vxlanid_lookup(vs, vfte->vf_vni);
	if (ftable == NULL) {
		if (add == false)
			return (0);
		ftable = malloc(sizeof(*ftable), M_VPC, M_WAITOK|M_ZERO);
		art_tree_init(&ftable->vf_ftable, ETHER_ADDR_LEN);
		ftable->vf_vni = vfte->vf_vni;
		ftable->vf_vs = vs;
		art_insert(&vs->vs_vxftable, (caddr_t)&vfte->vf_vni, ftable);
	}
	if (add == false) {
		addrp = art_delete(&ftable->vf_ftable, (caddr_t)&addr);
		free(addrp, M_VPC);
		if (art_size(&ftable->vf_ftable) == 0) {
			art_delete(&vs->vs_vxftable, (caddr_t)&vfte->vf_vni);
			free(ftable, M_VPC);
		}
	} else {
		ifp = NULL;
		/* do an arp resolve on proto addr so that it's in cache */
		(void)vpc_nd_lookup(vs, &ifp, &vfte->vf_protoaddr, buf);
		vpc_ftable_insert(ftable,(caddr_t)vfte->vf_hwaddr,
						  &vfte->vf_protoaddr);
	}
	return (0);
}
static int
vpc_ftable_count_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	uint32_t *count = data;
	(*count)++;
	return (0);
}

static int
vpc_vxftable_count_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct vpc_ftable *ftable = value;

	art_iter(&ftable->vf_ftable, vpc_ftable_count_callback, data);
	return (0);
}
static int
vpc_fte_count(struct vpc_softc *vs)
{
	uint32_t count = 0;

	art_iter(&vs->vs_vxftable, vpc_vxftable_count_callback, &count);
	return (count);
}

static int
vpc_ftable_print_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	char buf[5];

	buf[4] = 0;
	inet_ntoa_r(((struct sockaddr_in *)value)->sin_addr, buf);
	DPRINTF("vni: 0x%x dmac: %*D ip: %s\n",
		   *(uint32_t *)data, ETHER_ADDR_LEN, key, ":", buf);
	return (0);
}

static int
vpc_vxftable_print_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct vpc_ftable *ftable = value;

	art_iter(&ftable->vf_ftable, vpc_ftable_print_callback, (void*)(uintptr_t)key);
	return (0);
}

static void
vpc_fte_print(struct vpc_softc *vs)
{

	art_iter(&vs->vs_vxftable, vpc_vxftable_print_callback, NULL);
}

static int
vpc_fte_list(struct vpc_softc *vs, struct vpc_fte_list *vfl, int length)
{
	if (length == sizeof(struct vpc_fte_list) &&
		vfl->vfl_count == 0) {
		vfl->vfl_count = vpc_fte_count(vs);
		return (0);
	}
	if (length != (sizeof(struct vpc_fte_list) +
				   vfl->vfl_count*sizeof(struct vpc_fte)))
		return (EINVAL);


	/* XXX implement me */
	return (EOPNOTSUPP);
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
	if (ioh->vih_type != VPC_FTE_ALL &&
		IOCPARM_LEN(ioh->vih_type) != ifbuf->length) {
		DPRINTF("IOCPARM_LEN: %d ifbuf->length: %d\n",
			   (int)IOCPARM_LEN(ioh->vih_type), (int)ifbuf->length);
			   return (EINVAL);
	}
#ifdef notyet
	/* need sx lock for iflib context */
	iod = malloc(ifbuf->length, M_VPC, M_WAITOK | M_ZERO);
#endif
	iod = malloc(ifbuf->length, M_VPC, M_NOWAIT | M_ZERO);
	if (iod == NULL)
		return (ENOMEM);
	rc = copyin(ioh, iod, ifbuf->length);
	if (rc) {
		free(iod, M_VPC);
		return (rc);
	}
	switch (ioh->vih_type) {
		case VPC_LISTEN:
			rc = vpc_set_listen(vs, (struct vpc_listen *)iod);
			break;
		case VPC_FTE_SET:
			rc = vpc_fte_update(vs, (struct vpc_fte_update *)iod, true);
			break;
		case VPC_FTE_DEL:
			rc = vpc_fte_update(vs, (struct vpc_fte_update *)iod, false);
			break;
		case VPC_FTE_ALL:
			if (ifbuf->length < sizeof(struct vpc_fte_list))
				return (EINVAL);
			rc = vpc_fte_list(vs, (struct vpc_fte_list *)iod, ifbuf->length);
			if (!rc)
				rc = copyout(iod, ioh, ifbuf->length);
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
	.isc_flags = IFLIB_PSEUDO,
	.isc_name = "vpc",
};

if_shared_ctx_t vpc_sctx = &vpc_sctx_init;


#define IC_START_COUNT 512
static if_pseudo_t vpc_pseudo;	

static int
vpc_module_init(void)
{
	struct egress_cache **ecpp, *ecp;
	ck_epoch_record_t **erpp, *erp;
	int i, ec_size, er_size;

	vpc_pseudo = iflib_clone_register(vpc_sctx);
	if (vpc_pseudo == NULL)
		return (ENXIO);
	ck_epoch_init(&vpc_epoch);
	ck_epoch_register(&vpc_epoch, &vpc_global_record, NULL);
	iflib_config_gtask_init(NULL, &vpc_ifp_task, _task_fn_ifp_update, "ifp update");

	/* DPCPU hdr_cache init */
	/* DPCPU vpc epoch record init */
	ec_size = roundup(sizeof(*ecp), CACHE_LINE_SIZE);
	er_size = roundup(sizeof(*erp), CACHE_LINE_SIZE);

	ecp = malloc(ec_size*mp_ncpus, M_VPC, M_WAITOK|M_ZERO);
	erp = malloc(er_size*mp_ncpus, M_VPC, M_WAITOK);
	vpc_ic = malloc(sizeof(uint64_t) + (sizeof(struct ifnet *)*IC_START_COUNT),
					M_VPC, M_WAITOK|M_ZERO);
	vpc_ic->ic_size = IC_START_COUNT;

	CPU_FOREACH(i) {
		ck_epoch_register(&vpc_epoch, erp, NULL);

		ecpp = DPCPU_ID_PTR(i, hdr_cache);
		erpp = DPCPU_ID_PTR(i, vpc_epoch_record);
		*ecpp = ecp;
		*erpp = erp;
		ecp = (struct egress_cache *)(((caddr_t)ecp) + ec_size);
		erp = (ck_epoch_record_t *)(((caddr_t)erp) + er_size);
	}

	return (0);
}

static void
vpc_module_deinit(void)
{
	struct egress_cache *ecp;
	ck_epoch_record_t *erp;

	exiting = true;
	VPC_LOCK();
	GROUPTASK_ENQUEUE(&vpc_ifp_task);
	sx_sleep(&exiting, &vpc_lock, PDROP, "vpc exiting", 0);
	ecp = DPCPU_ID_GET(0, hdr_cache);
	erp = DPCPU_ID_GET(0, vpc_epoch_record);
	free(ecp, M_VPC);
	free(erp, M_VPC);
	iflib_config_gtask_deinit(&vpc_ifp_task);
	iflib_clone_deregister(vpc_pseudo);
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
				vpc_module_deinit();
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
