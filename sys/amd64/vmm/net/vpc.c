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

/*
 * Generic VPC services
 */
struct grouptask vpc_ifp_task;
struct ifp_cache *vpc_ic;
ck_epoch_t vpc_epoch;

static int vpc_ifindex_target;
static bool exiting = false;

static struct sx vpc_lock;
SX_SYSINIT(vpc, &vpc_lock, "VPC global");

#define VPC_LOCK() sx_xlock(&vpc_lock)
#define VPC_UNLOCK() sx_xunlock(&vpc_lock)

DPCPU_DEFINE(ck_epoch_record_t *, vpc_epoch_record);
ck_epoch_record_t vpc_global_record;
#define IC_START_COUNT 1024


static MALLOC_DEFINE(M_VPC, "vpc", "virtual private cloud utilities");

int
vpc_async_copyout(struct vpc_copy_info *vci, const void *kaddr, void *uaddr, size_t len)
{
	struct knote *kn = vci->vci_kn;
	struct proc *p = kn->kn_hook;
	vm_page_t *pages = vci->vci_pages;
	const char *ckaddr = kaddr;
	int off, count, rem, copylen;

	if (vci->vci_max_count*PAGE_SIZE < len)
		return (E2BIG);

	if (len == 0)
		return (0);
	count = vm_fault_quick_hold_pages(&p->p_vmspace->vm_map, (vm_offset_t)uaddr, len, VM_PROT_WRITE, pages,
								   vci->vci_max_count);
	if (count == 0)
		return (0);
	if (count == -1)
		return (EFAULT);
	rem = len;
	off = 0;
	do { 
		copylen = min(rem, PAGE_SIZE);
		bcopy(ckaddr + off, (void*)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(*pages)), copylen);
		off += copylen;
		rem -= copylen;
		pages++;
	} while (rem);
	pages = vci->vci_pages;
	do {
		vm_page_lock(*pages);
		vm_page_unhold(*pages);
		vm_page_unlock(*pages);
		pages++;
		count--;
	} while (count);
	return (0);
}

static __inline int
alloc_size(void *addr)
{
	uma_slab_t slab;
	int size;

	MPASS(addr);
	slab = vtoslab((vm_offset_t)addr & (~UMA_SLAB_MASK));
	if (__predict_false(slab == NULL))
		panic("free_domain: address %p(%p) has not been allocated.\n",
		    addr, (void *)((u_long)addr & (~UMA_SLAB_MASK)));

	if (!(slab->us_flags & UMA_SLAB_MALLOC)) {
		size = slab->us_keg->uk_size;
	} else {
		size = slab->us_size;
	}
	return (size);
}

struct art_tree_info {
	art_tree *tree;
	struct malloc_type *type;
};

static int
art_copy_one(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct art_tree_info *info = data;
	art_tree *dst = info->tree;
	void *newvalue;
	int size;

	size = alloc_size(value);
	newvalue = malloc(size, info->type, M_WAITOK);
	memcpy(newvalue, value, size);

	art_insert(dst, key, newvalue);
	return (0);
}

static int
art_free_one(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct malloc_type *type = data;

	free(value, type);
	return (0);
}

void
vpc_art_free(art_tree *tree, struct malloc_type *type)
{
	art_iter(tree, art_free_one, type);
	art_tree_destroy(tree);
	free(tree, type);
}

int
vpc_art_tree_clone(art_tree *src, art_tree **dstp, struct malloc_type *type)
{
	art_tree *dst;
	struct art_tree_info info;
	int rc;

	info.type = type;
	info.tree = dst = malloc(sizeof(art_tree), type, M_WAITOK);
	art_tree_init(dst, src->key_len);
	rc = art_iter(src, art_copy_one, &info);
	if (rc) {
		vpc_art_free(dst, type);
	} else
		*dstp = dst;
	return (rc);
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

int
vpc_parse_pkt(struct mbuf *m0, struct vpc_pkt_info *tpi)
{
	struct ether_vlan_header *evh;
	struct tcphdr *th;
	struct mvec_cursor mc;
	struct mbuf *m;
	int eh_type, ipproto;
	int l2len, l3len, offset;
	void *l3hdr;
	void *l4hdr;
	bool ismvec;

	mc.mc_off = mc.mc_idx = 0;
	m = m0;
	if (m0->m_len < ETHER_HDR_LEN)
		return (0);

	offset = 0;
	ismvec = m_ismvec(m);
	evh = (void*)m0->m_data;
	eh_type = ntohs(evh->evl_encap_proto);
	if (eh_type == ETHERTYPE_VLAN) {
		eh_type = ntohs(evh->evl_proto);
		l2len = sizeof(*evh);
	} else
		l2len = ETHER_HDR_LEN;
	if (ismvec)
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
		tpi->vpi_v6 = 1;
		break;
	}
#endif
#ifdef INET
	case ETHERTYPE_IP:
	{
		struct ip *ip = l3hdr;

		l3len = ip->ip_hl << 2;
		ipproto = ip->ip_p;
		tpi->vpi_v6 = 0;
		break;
	}
#endif
	case ETHERTYPE_ARP:
	default:
		l3len = 0;
		ipproto = 0;
		tpi->vpi_v6 = 0;
		break;
	}
	tpi->vpi_etype = eh_type;
	tpi->vpi_proto = ipproto;
	m->m_pkthdr.l2hlen = tpi->vpi_l2_len = l2len;
	m->m_pkthdr.l3hlen = tpi->vpi_l3_len = l3len;
	if (l3len == 0)
		return (0);

	if (ismvec)
		l4hdr = mvec_advance(m, &mc, l3len);
	else
	    l4hdr = m_advance(&m, &offset, l3len);

	if (ipproto == IPPROTO_TCP) {
		th = l4hdr;
		m->m_pkthdr.l4hlen = tpi->vpi_l4_len = th->th_off << 2;
	} else if (ipproto == IPPROTO_UDP) {
		m->m_pkthdr.l4hlen = tpi->vpi_l4_len = sizeof(struct udphdr);
	} else {
		return (0);
	}
	MPASS(l2len && l3len && tpi->vpi_l4_len);
	return (1);
}

static void
task_fn_ifp_update_(void *context __unused)
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
		if (__predict_true(!(ifps_orig[i]->if_flags & IFF_DYING) && !exiting))
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

int
vpc_ifp_cache(struct ifnet *ifp)
{
	if (__predict_false(vpc_ic->ic_size -1 < ifp->if_index)) {
		GROUPTASK_ENQUEUE(&vpc_ifp_task);
		return (1);
	}
	if (vpc_ic->ic_ifps[ifp->if_index] == ifp)
		return (0);

	/* XXX -- race if reference twice  -- need to actually serialize with VPCLINK_LOCK */
	if (vpc_ic->ic_ifindex_max < ifp->if_index)
		vpc_ic->ic_ifindex_max = ifp->if_index;
	MPASS(vpc_ic->ic_ifps[ifp->if_index] == NULL);
	if_ref(ifp);
	vpc_ic->ic_ifps[ifp->if_index] = ifp;
	return (0);
}

struct ifnet *
vpc_if_lookup(uint32_t ifindex)
{
	struct ifnet *ifp;

	KASSERT(ifindex <= vpc_ic->ic_ifindex_max,
			("passed ifindex %d exceeds vpc_ic->ic_ifindex_max: %d",
			 ifindex,vpc_ic->ic_ifindex_max));
	if (__predict_false(((ifp = vpc_ic->ic_ifps[ifindex]) == NULL)))
		return (NULL);
	if (__predict_false(ifp->if_flags & IFF_DYING)) {
		GROUPTASK_ENQUEUE(&vpc_ifp_task);
		return (NULL);
	}
	return (ifp);
}

static int
vpc_module_init(void)
{
	ck_epoch_record_t **erpp, *erp;
	int i, er_size;

	ck_epoch_init(&vpc_epoch);
	ck_epoch_register(&vpc_epoch, &vpc_global_record, NULL);
	iflib_config_gtask_init(NULL, &vpc_ifp_task, task_fn_ifp_update_, "ifp update");

	/* DPCPU vpc epoch record init */
	er_size = roundup(sizeof(*erp), CACHE_LINE_SIZE);
	erp = malloc(er_size*mp_ncpus, M_VPC, M_WAITOK);
	vpc_ic = malloc(sizeof(uint64_t) + (sizeof(struct ifnet *)*IC_START_COUNT),
					M_VPC, M_WAITOK|M_ZERO);
	vpc_ic->ic_size = IC_START_COUNT;

	CPU_FOREACH(i) {
		ck_epoch_register(&vpc_epoch, erp, NULL);
		erpp = DPCPU_ID_PTR(i, vpc_epoch_record);
		*erpp = erp;
		erp = (ck_epoch_record_t *)(((caddr_t)erp) + er_size);
	}
	return (0);
}

static void
vpc_module_deinit(void)
{
	ck_epoch_record_t *erp;

	VPC_LOCK();
	exiting = true;
	GROUPTASK_ENQUEUE(&vpc_ifp_task);
	sx_sleep(&exiting, &vpc_lock, PDROP, "vpc exiting", 0);

	erp = DPCPU_ID_GET(0, vpc_epoch_record);
	free(erp, M_VPC);
	iflib_config_gtask_deinit(&vpc_ifp_task);
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
			vpc_module_deinit();
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

DECLARE_MODULE(vpc, vpc_moduledata, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(vpc, 1);
MODULE_DEPEND(vpc, iflib, 1, 1, 1);
