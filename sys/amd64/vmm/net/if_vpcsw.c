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
#include <sys/conf.h>
#include <sys/file.h>
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
#define ARPHRD_ETHER 	1	/* ethernet hardware format */
#define	ARPOP_REPLY	2	/* response to previous request */
struct arphdr_ether {
	u_short	ar_hrd;		/* format of hardware address */
	u_short	ar_pro;		/* format of protocol address */
	u_char	ar_hln;		/* length of hardware address */
	u_char	ar_pln;		/* length of protocol address */
	u_short	ar_op;		/* one of: */
	u_char	ar_sha[ETHER_ADDR_LEN];	/* sender hardware address */
	in_addr_t	ar_spa;	/* sender protocol address */
	u_char	ar_tha[ETHER_ADDR_LEN];	/* target hardware address */
	in_addr_t	ar_tpa;	/* target protocol address */
	u_char ar_pad[60 - ETHER_HDR_LEN - 24 /*arphdr*/];
};

struct vpcsw_request_priv {
	TAILQ_ENTRY(vpcsw_request_priv) vrp_entry;
	vpc_id_t vrp_id;
	struct mbuf *vrp_m;
};

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

static volatile int32_t modrefcnt;

struct vpcsw_mcast_queue {
	int vmq_mcount;
	TAILQ_HEAD(vrp_head, vpcsw_request_priv) vmq_head;
};

struct vpcsw_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
	if_t vs_ifp;
	volatile int32_t vs_refcnt;
	struct mtx vs_lock;

	struct vpcsw_mcast_queue vs_vmq;
	art_tree *vs_ftable_ro;
	art_tree *vs_ftable_rw;
	struct ifnet *vs_ifdefault;
	vpc_id_t vs_uplink_id;
	struct grouptask vs_vtep_gtask;
	uint32_t vs_vni;
	/* pad */
	struct vpcsw_request_priv *vs_req_pending;
	struct arphdr_ether vs_arp_template;
	struct vpc_copy_info vs_vci;
};

static int
vpcsw_knote_event(if_ctx_t ctx, struct knote *kn, int hint)
{
	struct mbuf *m;
	struct kevent *kev;
	struct vpcsw_softc *vs;
	struct vpcsw_request_priv *vrp;
	char *uaddr;
	void *usize;
	int32_t size;
	int rc;

	vs = iflib_get_softc(ctx);
	if (hint == 0) {
		GROUPTASK_ENQUEUE(&vs->vs_vtep_gtask);
		return (0);
	}
	vrp = vs->vs_req_pending;
	kev = &kn->kn_kevent;
	usize = (void*)kev->ext[VPCSW_SIZE_IDX];
	uaddr = (void*)kev->ext[VPCSW_ADDR_IDX];
	if (usize == NULL)
		return (0);
	vs->vs_vci.vci_proc = kn->kn_hook;
	if (uaddr == NULL) {
		size = EFAULT;
		rc = vpc_async_copyout(&vs->vs_vci, &size, usize, sizeof(size));
		if (rc)
			goto fail;
	}
	m = vrp->vrp_m;
	size = m->m_len + sizeof(vrp->vrp_id);
	rc = vpc_async_copyout(&vs->vs_vci, &size, usize, sizeof(size));
	if (rc)
		goto fail;
	rc = vpc_async_copyout(&vs->vs_vci, &vrp->vrp_id, uaddr, sizeof(vrp->vrp_id));
	if (rc)
		goto fail;
	rc = vpc_async_copyout(&vs->vs_vci, m->m_data, uaddr + sizeof(vrp->vrp_id), m->m_len);
	if (rc)
		goto fail;
	vs->vs_vci.vci_proc = NULL;
	return (1);
 fail:
	vs->vs_vci.vci_proc = NULL;
	return (0);
}

static void
_task_fn_vtep(void *arg)
{
	struct vpcsw_softc *vs;
	struct vpcsw_mcast_queue *vmq;
	struct vpcsw_request_priv *vrp;
	if_ctx_t ctx;

	ctx = arg;
	vs = iflib_get_softc(ctx);
	vmq = &vs->vs_vmq;

	mtx_lock(&vs->vs_lock);
	if (TAILQ_EMPTY(&vmq->vmq_head)) {
		MPASS(vmq->vmq_mcount == 0);
		mtx_unlock(&vs->vs_lock);
		return;
	}
	vrp = TAILQ_FIRST(&vmq->vmq_head);
	TAILQ_REMOVE(&vmq->vmq_head, vrp, vrp_entry);
	vmq->vmq_mcount--;
	mtx_unlock(&vs->vs_lock);
	vs->vs_req_pending = vrp;
	iflib_event_signal(ctx, 1);
	vs->vs_req_pending = NULL;
	m_freem(vrp->vrp_m);
	free(vrp, M_VPCSW);
}

#ifdef notyet
static const char *opcode_map[] = {
	"",
	"VPCSW_REQ_NDv4",
	"VPCSW_REQ_NDv6",
	"VPCSW_REQ_DHCPv4",
	"VPCSW_REQ_DHCPv6",
};
#endif

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
vpcsw_cache_lookup(struct vpcsw_cache_ent *cache, struct mbuf *m)
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
	vcep = &cache[curcpu];

	if (__predict_false(vcep->vce_ticks == 0))
		goto skip;
	/*
	 * Is still in caching window
	 */
	if (__predict_false(ticks - vcep->vce_ticks > hz/4))
		goto skip;
	if ((ifp = vpc_if_lookup(vcep->vce_ifindex)) == NULL)
		goto skip;
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
vpcsw_cache_update(struct vpcsw_cache_ent *cache, struct mbuf *m)
{
	struct vpcsw_cache_ent *vcep;
	struct vpcsw_source *vsrc;
	struct ether_header *eh;
	uint16_t *mac;

	eh = (void*)m->m_data;
	mac = (uint16_t *)eh->ether_dhost;
	_critical_enter();
	vcep = &cache[curcpu];
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
	struct mbuf *m, *msrc;

	msrc = (struct mbuf *)data;
	if ((ifp = vpc_if_lookup(*ifindexp)) == NULL)
		return (0);
	MPASS(msrc->m_pkthdr.rcvif != NULL);
	if (msrc->m_pkthdr.rcvif == ifp)
		return (0);
	m = mvec_dup(msrc, M_NOWAIT);
	if (__predict_false(m == NULL))
		return (ENOMEM);
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
	if ((m->m_flags & M_HOLBLOCKING) ||
		(m->m_flags & (M_VXLANTAG|M_TRUNK)) == M_VXLANTAG) {
		mp = mvec_dup(m, M_NOWAIT);
		m_freem(m);
		m = mp;
		*msrc = m;
		if (m == NULL)
			return (ENOMEM);
	}
	if ((m->m_flags & (M_VXLANTAG|M_TRUNK)) == M_VXLANTAG) {
		struct vpcsw_request_priv *vrp;

		vrp = malloc(sizeof(*vrp), M_VPCSW, M_NOWAIT);
		if (vrp == NULL) {
			m_freem(m);
			*msrc = NULL;
			return (ENOMEM);
		}
		vpcp_get_id(m->m_pkthdr.rcvif, &vrp->vrp_id);

		mtx_lock(&vs->vs_lock);
		TAILQ_INSERT_HEAD(&vmq->vmq_head, vrp, vrp_entry);
		if (vmq->vmq_mcount >= 128) {
			vrp = TAILQ_LAST(&vmq->vmq_head, vrp_head);
			TAILQ_REMOVE(&vmq->vmq_head, vrp, vrp_entry);
			m_freem(vrp->vrp_m);
			free(vrp, M_VPCSW);
		} else
			vmq->vmq_mcount++;
		mtx_unlock(&vs->vs_lock);
		GROUPTASK_ENQUEUE(&vs->vs_vtep_gtask);
		*msrc = NULL;
		rc = 0;
	} else if (!(m->m_flags & M_VXLANTAG)) {
		art_iter(vs->vs_ftable_ro, vpc_broadcast_one, m);
		rc = 0;
	} else {
		m_freem(m);
		rc = EINVAL;
		*msrc = NULL;
	}
	return (rc);
}

static int
vpcsw_process_one(struct vpcsw_softc *vs, struct vpcsw_cache_ent *cache, struct mbuf **mp)
{
	struct ether_header *eh;
	struct mbuf *m;
	uint16_t *vif;
	struct ifnet *ifp;

	m = *mp;
	eh = (void*)m->m_data;
	if (__predict_false(ETHER_IS_MULTICAST(eh->ether_dhost)))
		return (vpcsw_process_mcast(vs, mp));
	if (vpcsw_cache_lookup(cache, m))
		return (0);
	vif = art_search(vs->vs_ftable_ro, (const unsigned char *)eh->ether_dhost);
	if (vif != NULL)
		ifp = vpc_if_lookup(*vif);
	else
		ifp = vs->vs_ifdefault;
	if (__predict_false(ifp == NULL)) {
		m_freem(m);
		*mp = NULL;
		return (ENOBUFS);
	}
	m->m_pkthdr.rcvif = ifp;
	vpcsw_cache_update(cache, m);
	return (0);
}

static int
vpcsw_transit(struct vpcsw_softc *vs, struct vpcsw_cache_ent *cache, struct mbuf *m, struct mbuf **mret)
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
		rc = vpcsw_process_one(vs, cache, &m);
		if (m == NULL) {
			m = mnext;
			continue;
		}
		if (__predict_false(rc))
			break;
		if (__predict_false(m->m_pkthdr.rcvif == NULL)) {
			if (mret && *mret == NULL)
				*mret = m;
			else
				m_freem(m);
			goto next;
		}
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
	next:
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

	panic("unsupported\n");
	return (EOPNOTSUPP);
}

int
vpcsw_transmit_ext(struct ifnet *ifp, struct mbuf *m, void *cache)
{
	if_ctx_t ctx = ifp->if_softc;
	struct vpcsw_softc *vs;

	vs = iflib_get_softc(ctx);
	return (vpcsw_transit(vs, cache, m, NULL));
}

static int
vpcsw_bridge_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *s __unused, struct rtentry *r __unused)
{
	struct vpcsw_softc *vs;
	if_ctx_t ctx;
	struct vpcsw_cache_ent *cache;

	MPASS(ifp->if_bridge != NULL);
	vs = ifp->if_bridge;
	ctx = ifp->if_softc;
	cache = vpcp_get_pcpu_cache(ctx);
	MPASS(cache != NULL);
	return (vpcsw_transit(vs, cache, m, NULL));
}

static void
vpcsw_bridge_linkstate(if_t ifp __unused)
{
}

static struct mbuf *
vpcsw_bridge_input(if_t ifp, struct mbuf *m)
{
	struct vpcsw_softc *vs;
	if_ctx_t ctx;
	struct vpcsw_cache_ent *cache;
	struct mbuf *mp;

	MPASS(ifp->if_bridge != NULL);
	mp = NULL;
	vs = ifp->if_bridge;
	ctx = ifp->if_softc;
	cache = vpcp_get_pcpu_cache(ctx);
	MPASS(cache != NULL);

	vpcsw_transit(vs, cache, m, &mp);
	return (mp);
}

static int
vpcsw_object_info_get(if_ctx_t ctx, void *arg, int size)
{
	struct vpcsw_softc *vs = iflib_get_softc(ctx);
	vpc_obj_info_t *voi = arg;

	if (size != sizeof(*voi))
		return (EBADRPC);
	voi->vswitch.vni = vs->vs_vni;
	return (0);
}

#define VPCSW_CAPS														\
	IFCAP_TSO |IFCAP_HWCSUM | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM |	\
	IFCAP_VLAN_MTU | IFCAP_TXCSUM_IPV6 | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU | IFCAP_LINKSTATE

static void
vpcsw_arp_tmpl_init(struct vpcsw_softc *vs)
{
	struct arphdr_ether *ae = &vs->vs_arp_template;

	bzero(ae, sizeof(*ae));
	ae->ar_hrd = htons(ARPHRD_ETHER);
	ae->ar_pro = htons(ETHERTYPE_IP);
	ae->ar_hln = ETHER_ADDR_LEN;
	ae->ar_pln = sizeof(in_addr_t);
	ae->ar_op = htons(ARPOP_REPLY);
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

	refcount_acquire(&modrefcnt);

	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	scctx->isc_capenable = VPCSW_CAPS;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
		| CSUM_IP6_UDP | CSUM_IP6_TCP;
	vs->vs_ctx = ctx;
	vs->vs_ifp = iflib_get_ifp(ctx);
	refcount_init(&vs->vs_refcnt, 0);
	mtx_init(&vs->vs_lock, "vpcsw sc internal", NULL, MTX_DEF);
	vs->vs_ftable_ro = malloc(sizeof(art_tree), M_VPCSW, M_WAITOK|M_ZERO);
	vs->vs_ftable_rw = malloc(sizeof(art_tree), M_VPCSW, M_WAITOK|M_ZERO);
	art_tree_init(vs->vs_ftable_ro, ETHER_ADDR_LEN);
	art_tree_init(vs->vs_ftable_rw, ETHER_ADDR_LEN);
	iflib_config_gtask_init(vs->vs_ctx, &vs->vs_vtep_gtask, _task_fn_vtep, "vtep task");
	vs->vs_vci.vci_pages = malloc(sizeof(vm_page_t *)*(ARG_MAX/PAGE_SIZE), M_VPCSW, M_WAITOK|M_ZERO);
	vs->vs_vci.vci_max_count = ARG_MAX/PAGE_SIZE;
	vpcsw_arp_tmpl_init(vs);
	return (0);
}


static int
vpcsw_port_add(struct vpcsw_softc *vs, const vpc_id_t *vp_id)
{
	struct ifnet *ifp;
	struct ifreq ifr;
	if_ctx_t ctx;
	void *cache;
	int rc;

	if (vmmnet_lookup(vp_id) != NULL) {
		if (bootverbose)
			printf("%s can't add %16D -- already in vpc_uuid_table\n",
				   __func__, vp_id, ":");
		return (EEXIST);
	}
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "vpcp");
	if ((rc = if_clone_create(ifr.ifr_name, sizeof(ifr.ifr_name), NULL)))
		return (rc);
	if ((ifp = ifunit_ref(ifr.ifr_name)) == NULL) {
		if (bootverbose)
			printf("couldn't reference %s\n", ifr.ifr_name);
		return (ENXIO);
	}
	cache = malloc(sizeof(struct vpcsw_cache_ent)*MAXCPU, M_VPCSW, M_WAITOK|M_ZERO);
	ctx = ifp->if_softc;
	vpcp_set_pcpu_cache(ctx, cache);
	vpcp_set_ifswitch(ctx, iflib_get_ifp(vs->vs_ctx));
	ifp->if_bridge = vs;
	ifp->if_bridge_input = vpcsw_bridge_input;
	ifp->if_bridge_output = vpcsw_bridge_output;
	ifp->if_bridge_linkstate = vpcsw_bridge_linkstate;
	iflib_set_mac(ctx, vp_id->node);
	vmmnet_insert(vp_id, ifp, VPC_OBJ_PORT);
	vpc_ifp_cache(ifp);
	ctx = ifp->if_softc;
	if_rele(ifp);
	return (0);
}

static int
vpcsw_port_delete(struct vpcsw_softc *vs, const vpc_id_t *vp_id)
{
	struct ifnet *ifp;
	if_ctx_t ctx;
	vpc_ctx_t vctx;
	void *cache;

	vctx = vmmnet_lookup(vp_id);
	if (vctx == NULL)
		return (ENOENT);
	ifp = vctx->v_ifp;

	vmmnet_delete(vp_id);
	ctx = ifp->if_softc;
	cache = vpcp_get_pcpu_cache(ctx);
	free(cache, M_VPCSW);
	vpcp_clear_ifswitch(ctx);
	ifp->if_bridge = NULL;
	ifp->if_bridge_input = NULL;
	ifp->if_bridge_output = NULL;
	ifp->if_bridge_linkstate = NULL;
	if_clone_destroy(ifp->if_xname);
	return (0);
}

static int
vpcsw_port_uplink_create(struct vpcsw_softc *vs, const vpc_id_t *vp_id)
{
	struct ifnet *ifp;
	void *cache;
	if_ctx_t ctx;
	struct ifreq ifr;
	int rc;

	if (vs->vs_ifdefault != NULL) {
		if (bootverbose)
			printf("%s: can't set port to %16D, vs->vs_ifdefault already set -- if: %s\n",
				   __func__, vp_id, ":", vs->vs_ifdefault->if_xname);
		return (EEXIST);
	}
	if (vmmnet_lookup(vp_id) != NULL) {
		if (bootverbose)
			printf("%s set uplink port to %16D -- already in vpc_uuid_table\n",
				   __func__, vp_id, ":");
		return (EEXIST);
	}

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "vpcp");
	if ((rc = if_clone_create(ifr.ifr_name, sizeof(ifr.ifr_name), NULL)))
		return (rc);
	if ((ifp = ifunit_ref(ifr.ifr_name)) == NULL) {
		if (bootverbose)
			printf("couldn't reference %s\n", ifr.ifr_name);
		if_clone_destroy(ifr.ifr_name);
		return (ENXIO);
	}
	rc = vmmnet_insert(vp_id, ifp, VPC_OBJ_PORT);
	if (rc) {
		if_rele(ifp);
		if_clone_destroy(ifr.ifr_name);
		return (rc);
	}
	cache = malloc(sizeof(struct vpcsw_cache_ent)*MAXCPU, M_VPCSW, M_WAITOK|M_ZERO);
	ctx = ifp->if_softc;
	if (bootverbose)
		printf("switch uplink set to id: %16D - default: %s\n",
			   vp_id, ":", ifp->if_xname);
	vpcp_set_pcpu_cache(ctx, cache);
	iflib_set_mac(ctx, vp_id->node);
	vpcp_set_ifswitch(ctx, iflib_get_ifp(vs->vs_ctx));
	vs->vs_ifdefault = ifp;
	memcpy(&vs->vs_uplink_id, vp_id, sizeof(vpc_id_t));
	return (0);
}

static int
vpcsw_port_uplink_get(struct vpcsw_softc *vs, vpc_id_t *vp_id)
{
	if (vs->vs_ifdefault == NULL)
		return (ENOENT);

	memcpy(vp_id, &vs->vs_uplink_id, sizeof(vpc_id_t));
	return (0);
}

static int
vpcsw_resp_send(struct vpcsw_softc *vs, const struct vpcsw_response *rsp)
{
	struct mbuf *m;
	int len;

	len = rsp->vrs_context.voc_len;
	m = (struct mbuf *)mvec_alloc(1, len, M_WAITOK);
	if (rsp->vrs_context.voc_vni) {
		m->m_pkthdr.vxlanid = rsp->vrs_context.voc_vni;
		m->m_flags |= M_VXLANTAG;
	}
	if (rsp->vrs_context.voc_vtag) {
		m->m_pkthdr.ether_vtag = rsp->vrs_context.voc_vtag;
		m->m_flags |= M_VLANTAG;
	}
	memcpy(m->m_data, rsp->vrs_data, len);
	m->m_len = len;
	m->m_pkthdr.len = len;
	return (vpcsw_transit(vs, NULL, m, NULL));
}

int
vpcsw_ctl(vpc_ctx_t vctx, vpc_op_t op, size_t inlen, const void *in,
				 size_t *outlen, void **outdata)
{
	if_ctx_t ctx = vctx->v_ifp->if_softc;
	struct vpcsw_softc *vs = iflib_get_softc(ctx);
	int rc = 0;
	vpc_id_t *out;

	switch (op) {
		case VPC_VPCSW_OP_PORT_ADD:
		case VPC_VPCSW_OP_PORT_DEL:
		case VPC_VPCSW_OP_PORT_UPLINK_SET:
			if (inlen != sizeof(vpc_id_t))
				return (EBADRPC);
			break;
	}
	switch (op) {
		case VPC_VPCSW_OP_PORT_ADD:
			rc = vpcsw_port_add(vs, in);
			break;
		case VPC_VPCSW_OP_PORT_DEL:
			rc = vpcsw_port_delete(vs, in);
			break;
		case VPC_VPCSW_OP_PORT_UPLINK_SET:
			rc = vpcsw_port_uplink_create(vs, in);
			break;
		case VPC_VPCSW_OP_PORT_UPLINK_GET:
			out = malloc(sizeof(*out), M_TEMP, M_WAITOK|M_ZERO);
			*outdata = out;
			*outlen = sizeof(*out);
			rc = vpcsw_port_uplink_get(vs, out);
			break;
		case VPC_VPCSW_OP_STATE_GET: {
			uint64_t *out;
			if (*outlen < sizeof(uint64_t))
				return (EOVERFLOW);
			out = malloc(sizeof(uint64_t), M_TEMP, M_WAITOK);
			*out = 0x1;
			*outdata = out;
		}
		case VPC_VPCSW_OP_STATE_SET: {
			//const uint64_t *flags = in;

			if (inlen != sizeof(uint64_t))
				return (EBADRPC);
			/* do something with the flags */
		}
		case VPC_VPCSW_OP_RESET:
			/* hrrrm.... */
			break;
		case VPC_VPCSW_OP_RESPONSE:
			return (vpcsw_resp_send(vs, in));
		default:
			rc = ENOTSUP;
	}
	return (rc);
}

static int
vpcsw_ro_update(struct vpcsw_softc *vs)
{
	art_tree *newftable, *oldftable;
	int rc;

	rc = vpc_art_tree_clone(vs->vs_ftable_rw, &newftable, M_VPCSW);
	if (rc)
		return (rc);
	oldftable = vs->vs_ftable_ro;
	vs->vs_ftable_ro = newftable;
	ck_epoch_synchronize(&vpc_global_record);
	vpc_art_free(oldftable, M_VPCSW);
	return (0);
}

int
vpcsw_port_connect(if_ctx_t switchctx, struct ifnet *portifp, struct ifnet *devifp)
{
	struct vpcsw_softc *vs;
	struct sockaddr_dl *sdl;
	uint16_t *ifindexp;

	sdl = (struct sockaddr_dl *)devifp->if_addr->ifa_addr;
	if (sdl->sdl_type != IFT_ETHER)
		return (EINVAL);

	vs = iflib_get_softc(switchctx);
	if (art_search(vs->vs_ftable_rw, LLADDR(sdl)) != NULL) {
		if (bootverbose)
			printf("port already in forward table can't insert %6D\n", LLADDR(sdl), ":");
		return (ENOENT);
	}

	ifindexp = malloc(sizeof(uint16_t), M_VPCSW, M_WAITOK);
	*ifindexp = portifp->if_index;

	vpc_ifp_cache(devifp);
	vpc_ifp_cache(portifp);
	if (bootverbose)
		printf("storing ifindexp= %d in switch ART for %6D\n", *ifindexp, LLADDR(sdl), ":");
	art_insert(vs->vs_ftable_rw, LLADDR(sdl), ifindexp);

	return (vpcsw_ro_update(vs));
}

int
vpcsw_port_disconnect(if_ctx_t switchctx, struct ifnet *portifp)
{
	struct vpcsw_softc *vs;
	struct sockaddr_dl *sdl;
	uint16_t *ifindexp;

	vs = iflib_get_softc(switchctx);
	sdl = (struct sockaddr_dl *)portifp->if_addr->ifa_addr;
	if (sdl->sdl_type != IFT_ETHER)
		return (EINVAL);
	/* Verify ifnet in table */
	if (art_search(vs->vs_ftable_rw, LLADDR(sdl)) == NULL) {
		if (bootverbose)
			printf("port not found in forward table can't delete %6D\n", LLADDR(sdl), ":");
		return (ENOENT);
	}
	ifindexp = art_delete(vs->vs_ftable_rw, LLADDR(sdl));
	free(ifindexp, M_VPCSW);
	return (vpcsw_ro_update(vs));
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
clear_bridge(void *data __unused, const unsigned char *key, uint32_t key_len __unused, void *value)
{
	uint16_t *ifindexp = value;
	struct ifnet *ifp;

	printf("clearing bridge for key %6D\n", key, ":");
	if ((ifp = vpc_if_lookup(*ifindexp)) == NULL)
		return (0);
	ifp->if_bridge = NULL;
	return (0);
}

static int
vpcsw_detach(if_ctx_t ctx)
{
	struct vpcsw_softc *vs = iflib_get_softc(ctx);
	struct vpcsw_mcast_queue *vmq;
	struct vpcsw_request_priv *vrp;

	if (vs->vs_refcnt != 0)
		return (EBUSY);

	ck_epoch_synchronize(&vpc_global_record);

	mtx_lock(&vs->vs_lock);
	vrp = vs->vs_req_pending;
	vs->vs_req_pending = NULL;
	m_freem(vrp->vrp_m);
	free(vrp, M_VPCSW);

	vmq = &vs->vs_vmq;
	while (!TAILQ_EMPTY(&vmq->vmq_head)) {
		vrp = TAILQ_FIRST(&vmq->vmq_head);
		TAILQ_REMOVE(&vmq->vmq_head, vrp, vrp_entry);
		m_freem(vrp->vrp_m);
		free(vrp, M_VPCSW);
	}
	mtx_unlock(&vs->vs_lock);
	iflib_config_gtask_deinit(&vs->vs_vtep_gtask);
	art_iter(vs->vs_ftable_rw, clear_bridge, NULL);
	if (vs->vs_ifdefault) {
		if_ctx_t ifctx = vs->vs_ifdefault->if_softc;
		vpc_ctx_t vctx;
		void *cache;

		cache = vpcp_get_pcpu_cache(ifctx);
		free(cache, M_VPCSW);
		vctx = vmmnet_lookup(&vs->vs_uplink_id);
		MPASS(vctx != NULL);
		MPASS(vctx->v_ifp != NULL);
		if_clone_destroy(vctx->v_ifp->if_xname);
		vctx->v_ifp = NULL;
		vmmnet_delete(&vs->vs_uplink_id);
	}
	mtx_destroy(&vs->vs_lock);
	vpc_art_free(vs->vs_ftable_ro, M_VPCSW);
	vpc_art_free(vs->vs_ftable_rw, M_VPCSW);

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
	DEVMETHOD(ifdi_knote_event, vpcsw_knote_event),
	DEVMETHOD(ifdi_object_info_get, vpcsw_object_info_get),
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

DECLARE_MODULE(vpcsw, vpcsw_moduledata, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(vpcsw, 1);
MODULE_DEPEND(vpcsw, vpc, 1, 1, 1);
MODULE_DEPEND(vpcsw, iflib, 1, 1, 1);
