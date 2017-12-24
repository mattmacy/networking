/*
 * Copyright (C) 2017 Joyent Inc.
 * Copyright (C) 2017 Matthew Macy <matt.macy@joyent.com>
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/cpuset.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/sbuf.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/ioccom.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/sockio.h>
#include <sys/limits.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>

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

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/sctp.h>

#include <dev/pci/pcivar.h>
#include <dev/virtio/virtio_config.h>
#include <dev/virtio/virtio_ring.h>
#include <dev/virtio/pci/virtio_pci.h>
#include <dev/virtio/network/virtio_net.h>

#include <machine/vmm.h>
#include <machine/vmm_dev.h>

#include "vmm_ktr.h"
#include "vmm_ioport.h"
#include "vmm_lapic.h"
#include "vtnet_be.h"
#include "ifdi_if.h"

#define VB_MAX_TX_SEGS	64
#define VB_RXQ_IDX 0
#define VB_TXQ_IDX 1

#define VB_TSO_SIZE		(65535 + sizeof(struct ether_vlan_header))
#define VB_TSO_SEG_SIZE		USHRT_MAX
#define VB_MAX_SCATTER VB_MAX_TX_SEGS
#define VB_CAPS									\
	IFCAP_TSO4 | IFCAP_TXCSUM | IFCAP_RXCSUM | IFCAP_VLAN_HWFILTER | IFCAP_WOL_MAGIC | \
	IFCAP_WOL_MCAST | IFCAP_WOL | IFCAP_VLAN_HWTSO | IFCAP_HWCSUM | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM | \
	IFCAP_VLAN_HWTSO | IFCAP_VLAN_MTU | IFCAP_TXCSUM_IPV6 | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU;

static MALLOC_DEFINE(M_VTNETBE, "vtnet", "virtio-net backend");

#ifdef VB_DEBUG

#define DPRINTF printf

static void
vb_print_vhdr(struct virtio_net_hdr_mrg_rxbuf *vh)
{
	struct virtio_net_hdr *h = &vh->hdr;
	if (h->flags | h->gso_type | h->hdr_len | h->gso_size |
		h->csum_start | h->csum_offset)
		printf("vhdr:\n \tflags: %d gso_type: %d hdr_len: %d\n"
			   "\tgso_size: %d, csum_start: %d, csum_offset: %d\n"
			   "\tnum_buffers: %d\n",
			   h->flags, h->gso_type, h->hdr_len, h->gso_size,
			   h->csum_start, h->csum_offset, vh->num_buffers);
}

#else
#define DPRINTF(...)
static void  vb_print_vhdr(struct virtio_net_hdr_mrg_rxbuf *vh __unused) {}
#endif

#define RXDEBUG

#ifdef RXDEBUG
#define RXDPRINTF printf
#else
#define RXDPRINTF(...)
#endif

/*
 * This is an in-kernel backend for the guest virtio net driver.
 *
 * It uses iflib device cloning for node creation. The path
 * through the driver is an idiosyncratic inverted ifnet.
 *
 * Assuming an iflib hardware driver, [hw] represents the hw ifp value
 * and [vb] represents the vtnet_be ifp, the path follows what we see below.
 *
 * On receive:
 * (wire) -> iflib_rxeof -> ifp[hw]->if_input() [vb_hw_if_input] ->
 *	  vb_rxswitch -> ifp[vb]->if_transmit [iflib_if_transmit] ->
 *	  vb_txd_encap -> (guest)
 *
 * On transmit:
 * (guest) -> iflib_rxeof -> vb_rxd_pkt_get();
 *	  ifp[vb]->if_input() [vb_if_input] -> vb_rxswitch ->
 *	  ifp[hw]->if_transmit() [iflib_if_transmit] -> (wire)
 *
 */


/*
 * TODO:
 *  - completely initialize all structures --- DONE?
 *  - verify the correctnes of tx descriptor updates in rxd_pkt_get
 *  - move the avail/use queue structures in to vb_txq / vb_rxq
 *  - test ...
 */

struct vb_softc;

struct vtnet_be {
	SLIST_ENTRY(vtnet_be) next;
	SLIST_HEAD(, vb_softc) dev;
	struct vm *vm;
	const char *name;	/* can point back to VM name */
};

/* Packet parse info */
struct pinfo {
	uint16_t *csum;
	uint16_t etype;
	uint8_t	 ehdrlen;	/* eth header len, includes VLAN tag */
	uint8_t	 l3size;	/* size of l3 header */
	uint8_t	 l3valid;	/* size of l3 header */
	uint8_t	 l4type;	/* layer 4 protocol type */
};

static SLIST_HEAD(, vtnet_be) vb_head;

struct vb_queue {
	uint16_t  vq_qsize;
	uint32_t  vq_lastpfn;
	uint32_t  vq_pfn;
	uint16_t  vq_msix_idx;

	/* queue mgmt */
	volatile struct vring_desc  *vq_desc;
	volatile struct vring_avail *vq_avail;
	volatile struct vring_used  *vq_used;

	vm_offset_t vq_addr;
#ifdef GUEST_OVERCOMMIT
	uint16_t  vq_pages;
	vm_page_t vq_m[54];	/* 54 pages for 16k descriptors */
#endif
};

#define VS_ENQUEUED  0x01
#define VS_VERSION_1 0x02
#define VS_READY 0x04
#define VS_OWNED 0x08

#define VB_CIDX_VALID (1 << 18)

struct vb_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
#define tx_num_queues shared->isc_ntxqsets
#define rx_num_queues shared->isc_nrxqsets
	struct vtnet_be *vs_vn;
	struct vb_rxq *vs_rx_queues;
	struct vb_txq *vs_tx_queues;
	struct ifnet *vs_ifparent;
	struct proc *vs_proc;  /* proc that did the cloneattach  */
	void (*vs_oinput)(struct ifnet *, struct mbuf *);
	SLIST_ENTRY(vb_softc) vs_next;
	uint32_t vs_flags;
	uint16_t vs_gpa_hint;

	/* virtio state */
	uint64_t   vs_generation;
	uint16_t   vs_io_start;
	uint16_t   vs_io_size;
	uint8_t	   vs_msix_enabled;
	uint8_t    vs_curq;
	uint8_t	   vs_nvq;
	uint8_t    vs_status;
	uint8_t    vs_origmac[6];
	uint32_t   vs_hv_caps;
	uint32_t   vs_negotiated_caps;
	struct {
		uint8_t mac[6];
		uint16_t status;
	} __packed vs_cfg;
	struct {
		uint64_t addr;
		uint64_t data;
	} vs_msix[3];

	struct vb_queue vs_queues[2];
};

#define VB_HDR_MAX 18 + 40

struct vb_rxq {
	uint16_t vr_cidx;
	struct vb_softc *vr_vs;
	caddr_t *vr_sdcl;
	uint16_t *vr_avail;
	struct vring_desc *vr_base;
	uint16_t vr_used[4096];
	char vr_pkttmp[VB_HDR_MAX] __aligned(CACHE_LINE_SIZE);
};

struct vb_txq {
	struct vb_softc *vt_vs;
	struct vring_desc *vt_base;
	int16_t vt_cidx; /* iflib current index */
	qidx_t vt_vpidxs[VB_MAX_TX_SEGS];
	bus_dma_segment_t vt_segs[VB_MAX_TX_SEGS];
};

static if_pseudo_t vb_clone_register(void);
static void vb_intr_msix(struct vb_softc *vs, int q);
static void vb_rxq_init(struct vb_softc *vs, struct vb_rxq *rxq);
static void vb_txq_init(struct vb_softc *vs, struct vb_txq *txq);

static int
vb_txd_encap(void *arg, if_pkt_info_t pi)
{
	struct vb_softc *vs = arg;
	struct vb_txq *txq = &vs->vs_tx_queues[pi->ipi_qsidx];
	struct vm *vm = vs->vs_vn->vm;
	if_softc_ctx_t scctx = vs->shared;
	volatile struct vring_used *vu;
	volatile struct vring_avail *va;
	volatile struct vring_used_elem *vue;
	bus_dma_segment_t *segs, *tx_segs;
	struct virtio_net_hdr_mrg_rxbuf *vhd;
	struct vring_desc *txd;
	int i, total, freespc, ndesc, pidx, mask;
	int soff, doff, sidx, didx;
	uint16_t *vpidxs;
	uint16_t vidx;

	pidx = pi->ipi_pidx;
	ndesc = vs->vs_queues[VB_RXQ_IDX].vq_avail->idx - pidx;
	if (ndesc < 0)
		ndesc += scctx->isc_nrxd[0];

	DPRINTF("%s called pidx: %d nsegs: %d %d ndesc avail\n", __func__, pidx, pi->ipi_nsegs, ndesc);

	if (__predict_false(vs->vs_queues[VB_RXQ_IDX].vq_avail->idx == pidx)) {
		DPRINTF("%s called -- no space\n", __func__);
		return (ENOBUFS);
	}
	segs = pi->ipi_segs;
	tx_segs = txq->vt_segs;

#ifdef INVARIANTS
	for (total = i = 0; i < pi->ipi_nsegs; i++) {
		total += segs[i].ds_len;
		DPRINTF("\t data: %p len: %ld\n",
				(void *)segs[i].ds_addr, segs[i].ds_len);
	}
	MPASS(pi->ipi_len == total);
#endif
	ndesc = min(ndesc, VB_MAX_TX_SEGS);
	mask = scctx->isc_nrxd[0] - 1;
	vpidxs = txq->vt_vpidxs;
	va = vs->vs_queues[VB_RXQ_IDX].vq_avail;

	/*
	 * Determine how much space the ring has -- the TSO segs check
	 * should be sufficient to avoid missing out here
	 */
	DPRINTF("vpidxs: ");
	for (freespc = i = 0; freespc < pi->ipi_len && i < ndesc; i++) {
		vm_offset_t kva;
		uint16_t vpidx;

		vpidx = va->ring[pidx];
		vpidxs[i] = vpidx;
		/* Can we always assume 1:1 between avail and descriptors? */
		txd = &txq->vt_base[vpidx];
		kva = vm_gpa_to_kva(vm, txd->addr, txd->len, &vs->vs_gpa_hint);
		if (__predict_false(kva == 0)) {
			panic("XXX do vm_gpa_hold");
		}
		tx_segs[i].ds_addr = kva;
		tx_segs[i].ds_len = txd->len;
		freespc += txd->len;
		pidx = (pidx + 1) & mask;
	}
	DPRINTF("\n");
	if (__predict_false(freespc < pi->ipi_len)) {
		DPRINTF("freespc=%d < len=%d\n", freespc, pi->ipi_len);
		return (EFBIG);
	}
	vhd = (void *)tx_segs[0].ds_addr;
	bzero(vhd, sizeof(*vhd));
	vhd->num_buffers = i;

	if (pi->ipi_csum_flags & CSUM_DATA_VALID) {
		vhd->hdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM |
		    VIRTIO_NET_HDR_F_DATA_VALID;
		vhd->hdr.csum_start = pi->ipi_ehdrlen + pi->ipi_ip_hlen;
		switch (pi->ipi_ipproto) {
			case IPPROTO_TCP:
			vhd->hdr.csum_offset =
			    offsetof(struct tcphdr, th_sum);
				break;
			case IPPROTO_UDP:
				vhd->hdr.csum_offset =
					offsetof(struct udphdr, uh_sum);
				break;
			case IPPROTO_SCTP:
				vhd->hdr.csum_offset =
					offsetof(struct sctphdr, checksum);
				break;
			default:
				vhd->hdr.flags = 0;
				vhd->hdr.csum_start = 0;
				break;
		}
	}
	doff = sizeof(*vhd);
	ndesc = i;
	total = pi->ipi_len;
	soff = didx = sidx = 0;
	vu = vs->vs_queues[VB_RXQ_IDX].vq_used;
	vidx = vu->idx;
	
	DPRINTF("vidx:%d vu->idx: %d vu->flags: %x\n",
			vidx, vu->idx, vu->flags);
	do {
		/* copy length / source delta / destination delta */
		int len, sdel, ddel, dlen;
		char *src, *dst;
		bool update_used;

		update_used = false;
		sdel = segs[sidx].ds_len - soff;
		dlen = tx_segs[didx].ds_len;
		ddel = dlen - doff;
		src = (caddr_t)segs[sidx].ds_addr + soff;
		dst = (caddr_t)tx_segs[didx].ds_addr + doff;
		/*
		 * Mark size of last descriptor and end loop
		 */
		if (total == sdel) {
			txd = &txq->vt_base[(pi->ipi_pidx + didx) & mask];
			dlen = doff + sdel;
			DPRINTF("last descriptor: %d len: %d\n",
					(pi->ipi_pidx + didx) & mask, dlen);
			if (sdel < ddel)
				update_used = true;
		}
		if (sdel < ddel) {
			len = sdel;
			doff += len;
			soff = 0;
			sidx++;
		} else if (sdel > ddel) {
			len = ddel;
			soff += len;
			doff = 0;
			update_used = true;
		} else {
			len = sdel;
			doff = soff = 0;
			sidx++;
			update_used = true;
		}
		total -= len;
		bcopy(src, dst, len);
		if (update_used) {
			vue = &vu->ring[vidx++ & mask];
			vue->id = /* pi->ipi_pidx + didx */ vpidxs[didx]; 
			vue->len = dlen;
			DPRINTF("vidx: %d vue->id: %d vue->len: %d vpidxs[%d]: %d\n",
				   vidx, vue->id, vue->len, didx, vpidxs[didx]);
			didx++;
		}
	} while (didx < ndesc);

	pi->ipi_new_pidx = pidx;
	/* Update used ring to reflect final state */
	wmb();
	vu->idx = vidx;
	wmb();
	return (0);
}

static void
vb_txd_flush(void *arg, uint16_t txqid __unused, qidx_t pidx __unused)
{
	struct vb_softc *vs = arg;

	/* Interrupt the guest */
	vb_intr_msix(vs, VB_RXQ_IDX);
}

static int
vb_txd_credits_update(void *arg, uint16_t txqid, bool clear)
{

	struct vb_softc *vs = arg;
	if_softc_ctx_t scctx = vs->shared;
	struct vb_txq *txq = &vs->vs_tx_queues[txqid];
	int16_t vpidx;
	int32_t delta;

	vpidx = vs->vs_queues[VB_RXQ_IDX].vq_avail->idx % scctx->isc_ntxd[0];

	/* credits updated should reflect new
	 * descriptors available in the ring --
	 * so long as we copy in to the guest the
	 * mbuf chain can be freed instantly
	 */
	delta = vpidx - txq->vt_cidx;
	if (delta < 0)
		delta += scctx->isc_ntxd[0];
	DPRINTF("%s vt_cidx: %d vpidx: %d delta: %d\n",
		   __func__, txq->vt_cidx, vpidx, delta);

	if (clear && delta)
		txq->vt_cidx = vpidx;
	MPASS(delta < scctx->isc_ntxd[0]);
	return (delta);
}

static void
vb_rxd_refill(void *arg __unused, if_rxd_update_t iru __unused)
{
	//panic("XXX %s shouldn't be called for vtnet_be", __func__);
	// log refill
}

static void
vb_rxd_flush(void *arg __unused, uint16_t rxqid __unused,
			 uint8_t flid __unused, qidx_t pidx __unused)
{
	// keep private update in rx_notify
	// txq interrupt?
}

static caddr_t
vb_rxcl_map(struct vb_softc *vs, struct vring_desc *rxd)
{
	struct vm *vm = vs->vs_vn->vm;

	return ((caddr_t)vm_gpa_to_kva(vm, rxd->addr, rxd->len, &vs->vs_gpa_hint));
}

static int
vb_rxd_available(void *arg, qidx_t rxqid, qidx_t cidx, qidx_t budget)
{
	struct vb_softc *vs = arg;
	uint16_t idx;
	int cnt;

	idx =  vs->vs_queues[VB_TXQ_IDX].vq_avail->idx;
	idx %= vs->shared->isc_nrxd[0];
	cnt = (int32_t)idx - (int32_t)cidx;
	if (cnt < 0)
		cnt += vs->shared->isc_nrxd[0];
	return (cnt);
}

static int
vb_pparse(caddr_t data, struct pinfo *pinfo)
{
	struct ether_vlan_header *eh;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;
	struct udphdr *udp;
	int ehdrlen;
	int l3valid, l3size, l4type;
	uint16_t etype;
	uint16_t *csum;

	csum = NULL;
	eh = (struct ether_vlan_header *)data;
	if (eh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		etype = ntohs(eh->evl_proto);
		ehdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
	} else {
		etype = ntohs(eh->evl_encap_proto);
		ehdrlen = ETHER_HDR_LEN;
	}

	switch (etype) {
	case ETHERTYPE_IP:
		ip = (struct ip *)(data + ehdrlen);
		l3valid = 1;
		l3size = ip->ip_hl << 2;
		l4type = ip->ip_p;
		break;
	case ETHERTYPE_IPV6:
		ip6 = (struct ip6_hdr *)(data + ehdrlen);
		l3valid = 1;
		l3size = sizeof(struct ip6_hdr);
		/* XXX lasthdr */
		l4type = ip6->ip6_nxt;
		break;
	default:
		l3valid = 0;
		l3size = 0;
		l4type = 0;
	}
	pinfo->etype = etype;
	pinfo->ehdrlen = ehdrlen;
	pinfo->l3valid = l3valid;
	pinfo->l3size = l3size;
	pinfo->l4type = l4type;
	if (!l3valid) {
		pinfo->csum = NULL;
		return (1);
	}

	switch (l4type) {
		case IPPROTO_TCP:
			tcp = (struct tcphdr *)(data + ehdrlen + l3size);
			csum = &tcp->th_sum;
			break;
		case IPPROTO_UDP:
			udp = (struct udphdr *)(data + ehdrlen + l3size);
			csum = &udp->uh_sum;
			break;
	}
	pinfo->csum = csum;
	return (1);
}

static int
vb_rxflags(struct vring_desc **rxdp, struct vb_rxq *rxq, if_rxd_info_t ri,
		   uint16_t vcidx)
{
	caddr_t cl;
	//	caddr_t scratch;
	struct pinfo pinfo;
	struct vring_desc *rxd = *rxdp;
	uint32_t flags = 0;

	cl = rxq->vr_sdcl[vcidx];
	pinfo.etype = 0;

	if (__predict_true(rxd->len >= VB_HDR_MAX)) {
		vb_pparse(cl + ri->iri_pad, &pinfo);
	} else {
		/* XXX --- too small */
	}
	switch (pinfo.etype) {
		case ETHERTYPE_IP:
			switch (pinfo.l4type) {
				case IPPROTO_TCP:
					flags = CSUM_TCP;
					break;
				case IPPROTO_UDP:
					flags = CSUM_UDP;
					break;
				case IPPROTO_SCTP:
					flags = CSUM_SCTP;
			}
			break;
		case ETHERTYPE_IPV6:
			switch (pinfo.l4type) {
				case IPPROTO_TCP:
					flags = CSUM_TCP_IPV6;
				case IPPROTO_UDP:
					flags = CSUM_UDP_IPV6;
				case IPPROTO_SCTP:
					flags = CSUM_SCTP_IPV6;
			}
			break;
	}
	ri->iri_csum_flags = flags;
	return (0);
}

static int
vb_rxd_pkt_get(void *arg, if_rxd_info_t ri)
{
	struct virtio_net_hdr_mrg_rxbuf *vh;
	struct vb_softc *vs = arg;
	if_softc_ctx_t scctx = vs->shared;
	struct vb_rxq *rxq = &vs->vs_rx_queues[ri->iri_qsidx];
	struct vring_desc *rxd;
	int i, cidx, vcidx, count, mask;
	bool parse_header;

	MPASS(ri->iri_cidx < scctx->isc_nrxd[0]);
	i = 0;
	parse_header = false;
	cidx = ri->iri_cidx;
	vcidx = rxq->vr_avail[cidx];
	mask = scctx->isc_nrxd[0]-1;
	if (cidx != (rxq->vr_cidx & mask))
		printf("mismatch cidx: %d vr_cidx_masked:%d vr_cidx: %d",
			   cidx, rxq->vr_cidx & mask, rxq->vr_cidx);

	rxq->vr_used[rxq->vr_cidx & 4095] = vcidx;
	/* later passed to ext_free to return used descriptors */
	ri->iri_cookie1 = (void *)rxq;
	ri->iri_cookie2 = (rxq->vr_cidx | VB_CIDX_VALID);

	ri->iri_cidx = (rxq->vr_cidx++) & (scctx->isc_nrxd[0]-1);
	rxd = (struct vring_desc *)&rxq->vr_base[vcidx];


	if (__predict_false(rxd->len < sizeof(*vh))) {
		DPRINTF("%s rxd->len short: %d\n", __func__, rxd->len);
		return (ENXIO);
	}
	rxq->vr_sdcl[vcidx] = vb_rxcl_map(vs, rxd);
	if (__predict_false(rxq->vr_sdcl[vcidx] == NULL))
		return (ENXIO);
	vh = (struct virtio_net_hdr_mrg_rxbuf *)rxq->vr_sdcl[vcidx];
	if (__predict_true(rxd->len == sizeof(*vh))) {
		rxq->vr_sdcl[vcidx] = NULL;
		if (__predict_true(rxd->flags & VRING_DESC_F_NEXT)) {
			vcidx = rxd->next;
			rxq->vr_sdcl[vcidx] = vb_rxcl_map(vs, rxd);
			if (__predict_false(rxq->vr_sdcl[vcidx] == NULL))
				return (ENXIO);
		} else {
			return (ENXIO);
		}
		if (__predict_false(vcidx >= scctx->isc_nrxd[0]))
			return (ENXIO);
	} else {
		RXDPRINTF("didn't get separate vhdr assuming it's inplace rxd->len: %d\n",
				rxd->len);
		ri->iri_pad = sizeof(*vh);
	}

	vb_print_vhdr(vh);
	switch (vh->hdr.gso_type) {
		case VIRTIO_NET_HDR_GSO_TCPV4:
			ri->iri_tso_segsz = vh->hdr.gso_size;
			ri->iri_csum_data = vh->hdr.csum_offset;
			ri->iri_csum_flags = CSUM_TSO | CSUM_TCP;
			break;
		case VIRTIO_NET_HDR_GSO_TCPV6:
			ri->iri_tso_segsz = vh->hdr.gso_size;
			ri->iri_csum_data = vh->hdr.csum_offset;
			ri->iri_csum_flags = CSUM_IP6_TSO | CSUM_TCP_IPV6;
			break;
		default:
			parse_header = true;
			break;
	}
	if ((vh->hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) && parse_header) {
		rxd = (struct vring_desc *)&rxq->vr_base[vcidx];
		if (vb_rxflags(&rxd, rxq, ri, vcidx))
			return (ENXIO);
		ri->iri_csum_data = vh->hdr.csum_offset;
	}

	do {
		if (__predict_false(vcidx >= scctx->isc_nrxd[0])) {
			RXDPRINTF("descriptor out of range: %d\n", vcidx);
			return (ENXIO);
		}
		if (__predict_false(i == IFLIB_MAX_RX_SEGS)) {
			RXDPRINTF("descriptor chain too long: %d\n", vcidx);
			return (ENXIO);
		}
		rxd = (struct vring_desc *)&rxq->vr_base[vcidx];
		if ((int)ri->iri_len + (int)rxd->len > VB_TSO_SIZE) {
			RXDPRINTF("chain exceeds maximum size: %d\n",
					(int)ri->iri_len + (int)rxd->len);
			return (ENXIO);
		}
		if (__predict_false(rxd->flags & VRING_DESC_F_INDIRECT)) {
			RXDPRINTF("indirect not supported!!!!\n");
			return (ENXIO);
		}
		rxq->vr_sdcl[vcidx] = vb_rxcl_map(vs, rxd);
		if (__predict_false(rxq->vr_sdcl[vcidx] == NULL)) {
			RXDPRINTF("failed cluster map\n");
			return (ENXIO);
		}
		ri->iri_frags[i].irf_idx = vcidx;
		ri->iri_frags[i].irf_len = rxd->len;
		ri->iri_len += rxd->len;
		i++;
		vcidx = rxd->next;
	} while (rxd->flags & VRING_DESC_F_NEXT);

	count = i;
	for (i = 0; i < count; i++)
		CTR5(KTR_SPARE3, "cidx: %d [%d].irf_idx: %d [%d].irf_len: %d\n",
				  cidx, i, ri->iri_frags[i].irf_idx, i,
				  ri->iri_frags[i].irf_len);
	ri->iri_nfrags = count;
	return (0);
}

static void
vb_rx_completion(struct mbuf *m)
{
	volatile struct vring_used *vu;
	volatile struct vring_used_elem *vue;
	struct vb_rxq *rxq;
	struct vb_softc *vs;
	uint16_t vidx;
	int cidx, idx, mask;

	if ((m->m_flags & M_PKTHDR) == 0)
		return;

#ifdef GUEST_OVERCOMMIT
	/*
	 * Unpin the page now that the host NIC has completed the tx
	 * and no longer needs it to be resident.
	 */
	vm_gpa_release(vb->vb_mb[vidx].cookie);
#endif
	rxq = (struct vb_rxq *)m->m_ext.ext_arg1;
	MPASS(rxq != NULL);
	vs = rxq->vr_vs;
	cidx = (int)m->m_ext.ext_arg2;
	MPASS(cidx & VB_CIDX_VALID);
	cidx &= ~VB_CIDX_VALID;
	idx = rxq->vr_used[cidx & 4095];
	mask = vs->shared->isc_nrxd[0]-1;

	/* Update the element in the used ring */
	vu = vs->vs_queues[VB_TXQ_IDX].vq_used;
	vidx = vu->idx;
	if (cidx != vidx)
		printf("mismatch cidx: %d vidx: %d\n", cidx, vidx);

	vue = &vu->ring[vidx++ & mask];
	vue->id = idx;
	vue->len = m->m_pkthdr.len;
	CTR4(KTR_SPARE3, "%s -- idx: %d vidx: %d len: %d\n",
		   __func__, idx, vidx, vue->len);
	/* ensure that all prior vue updates are written first */
	wmb();
	vu->idx = vidx;
	/* ensure that idx is visible */
	wmb();

	/* Generate an interrupt if allowed --- 
	 * XXX defer until full batch is sent off
	 */
	vb_intr_msix(vs, VB_TXQ_IDX);
}

static int
vb_intr(void *arg)
{
	return (0);
}

static struct if_txrx vb_txrx = {
	vb_txd_encap, /* copy packet in to rx ring */
	vb_txd_flush, /* mark RX "dma complete" up to doorbell */
	vb_txd_credits_update, /* all descriptors sent to  */
	vb_rxd_available, /* # of descriptors in the tx ring */
	vb_rxd_pkt_get, /* get packet from tx ring */
	vb_rxd_refill,  /* nop -- never called */
	vb_rxd_flush, /* nop  -- never called */
	vb_intr
};

static struct mtx vb_mtx;
#define VB_LOCK	mtx_lock(&vb_mtx)
#define VB_UNLOCK	mtx_unlock(&vb_mtx)
static void vb_dev_kick(struct vb_softc *vs, uint32_t q);
static void vb_dev_pfn(struct vb_softc *vs, uint32_t pfn);
static void vb_vring_munmap(struct vb_softc *vs, int q);

/*
 * Utility routines
 */
static struct vtnet_be *
vb_find_vmname(char *vmname)
{
	struct vtnet_be *vb;

	VB_LOCK;
	SLIST_FOREACH(vb, &vb_head, next) {
		if (!strcmp(vmname, vb->name))
			break;
	}
	VB_UNLOCK;

	return (vb);
}

static int
vb_ifnet_inuse(struct ifnet *ifp)
{
	struct vtnet_be *vb;
	struct vb_softc *vs;

	VB_LOCK;
	SLIST_FOREACH(vb, &vb_head, next) {
		SLIST_FOREACH(vs, &vb->dev, vs_next) {
			if (vs->vs_ifparent == ifp) {
				goto done;
			}
		}
	}
 done:
	VB_UNLOCK;

	return (vb != NULL);
}

static void
vb_status_change(struct vb_softc *vs, uint32_t val)
{
	struct ifnet *ifp = iflib_get_ifp(vs->vs_ctx);

	/*
	 * For legacy guest drivers - e.g. FreeBSD
	 */
	if (val == VIRTIO_CONFIG_STATUS_RESET) {
		DPRINTF("VIRTIO_CONFIG_STATUS_RESET\n");
		if_setflagbits(ifp, 0, IFF_UP);
		ifp->if_init(vs->vs_ctx);
	}
	if (val & VIRTIO_CONFIG_STATUS_DRIVER)
		DPRINTF("VIRTIO_CONFIG_STATUS_DRIVER ");
	if (val & VIRTIO_CONFIG_STATUS_ACK)
		DPRINTF("VIRTIO_CONFIG_STATUS_ACK ");
	if (val & VIRTIO_CONFIG_STATUS_NEEDS_RESET) {
		DPRINTF("VIRTIO_CONFIG_STATUS_NEEDS_RESET ");
		if_setflagbits(ifp, 0, IFF_UP);
		ifp->if_init(vs->vs_ctx);
	}
	if (val & VIRTIO_CONFIG_STATUS_DRIVER_OK) {
		DPRINTF("VIRTIO_CONFIG_STATUS_DRIVER_OK ");
		/* Up interface */
		if_setflagbits(ifp, IFF_UP, 0);
		ifp->if_init(vs->vs_ctx);
	}
	if (val & VIRTIO_CONFIG_STATUS_FEATURES_OK) {
		DPRINTF("VIRTIO_CONFIG_STATUS_FEATURES_OK\n");
		vs->vs_flags |= VS_VERSION_1;
	}
	if (val & VIRTIO_CONFIG_STATUS_FAILED) {
		DPRINTF("VIRTIO_CONFIG_STATUS_FAILED");
		if_setflagbits(ifp, 0, IFF_UP);
		ifp->if_init(vs->vs_ctx);
	}
	DPRINTF("\n");
	vs->vs_status = val | VIRTIO_CONFIG_STATUS_FEATURES_OK;
}

/*
 * Virtio register-handling code
 */
static int
vb_handle_config(struct vb_softc *vs, int offset, bool in, int bytes,
    uint32_t *val)
{
	uint8_t *ptr;

	ptr = (uint8_t *)&vs->vs_cfg + offset;

	if (in) {
		memcpy(val, ptr, bytes);
	} else {
		if (offset < 6) {
			memcpy(ptr, val, bytes);
		}
	}

	return (0);
}

static int
vb_handle(struct vm *vm, int vcpuid, bool in, int port, int bytes,
    uint32_t *val, void *arg)
{
	struct vb_softc *vs = arg;
	int cfgoffset, offset;

	offset = port - vs->vs_io_start;

	cfgoffset = VIRTIO_PCI_CONFIG_OFF(vs->vs_msix_enabled);

	/* Handle the device-specific config region */
	if (offset >= cfgoffset) {
		offset -= cfgoffset;
		return (vb_handle_config(vs, offset, in, bytes, val));
	}
	DPRINTF("%s %s offset: %x val: %x\n", __func__, in ? "in" : "out",
			offset, *val);

	if (in) {
		switch (offset) {
		case VIRTIO_PCI_HOST_FEATURES:
			*val = vs->vs_hv_caps;
			break;
		case VIRTIO_PCI_GUEST_FEATURES:
			*val = vs->vs_negotiated_caps;
			break;
		case VIRTIO_PCI_QUEUE_PFN:
			if (vs->vs_curq < vs->vs_nvq)
				*val = vs->vs_queues[vs->vs_curq].vq_pfn;
			else
				*val = 0;
			break;
		case VIRTIO_PCI_QUEUE_NUM:
			if (vs->vs_curq < vs->vs_nvq)
				*val = vs->vs_queues[vs->vs_curq].vq_qsize;
			else
				*val = 0;
			break;
		case VIRTIO_PCI_QUEUE_SEL:
			*val = vs->vs_curq;
			break;
		case VIRTIO_PCI_QUEUE_NOTIFY:
			/* write-only reg */
			*val = 0;
			break;
		case VIRTIO_PCI_STATUS:
			/* return what was written */
			*val = vs->vs_status | VIRTIO_CONFIG_STATUS_FEATURES_OK;
			break;
		case VIRTIO_PCI_ISR:
			/* only used for legacy interrupts */
			*val = 0;
			break;
		case VIRTIO_MSI_CONFIG_VECTOR:
			/* not supported */
			*val = 0;
			break;
		case VIRTIO_MSI_QUEUE_VECTOR:
			if (vs->vs_curq < vs->vs_nvq)
				*val = vs->vs_queues[vs->vs_curq].vq_msix_idx;
			else
				*val = VIRTIO_MSI_NO_VECTOR;
			break;
		default:
			printf("vtnet_be: illegal reg read %d (%d)\n",
			      port, offset);
		  ;
		}
	} else {
		/*
		 *  Register writes
		 */
		switch (offset) {
		case VIRTIO_PCI_HOST_FEATURES:
			/* r/o reg */
			break;
			case VIRTIO_PCI_GUEST_FEATURES:
				printf("hv_caps: %08x hv_capenable: %08x\n",
					   vs->vs_hv_caps, *val & vs->vs_hv_caps);
			vs->vs_negotiated_caps = *val & vs->vs_hv_caps;
			break;
		case VIRTIO_PCI_QUEUE_PFN:
			vb_dev_pfn(vs, *val);
			break;
		case VIRTIO_PCI_QUEUE_NUM:			
			/* r/o reg */
			break;
		case VIRTIO_PCI_QUEUE_SEL:
			vs->vs_curq = *val;
			break;
		case VIRTIO_PCI_QUEUE_NOTIFY:
			vb_dev_kick(vs, *val);
			break;
		case VIRTIO_PCI_STATUS:
			vb_status_change(vs, *val);
			break;
		case VIRTIO_PCI_ISR:
			/* ignore */
			break;
		case VIRTIO_MSI_CONFIG_VECTOR:
			/* ignore */
			break;
		case VIRTIO_MSI_QUEUE_VECTOR:
			if (vs->vs_curq < vs->vs_nvq)
				vs->vs_queues[vs->vs_curq].vq_msix_idx = *val;
			break;
		default:
			printf("vtnet_be: illegal reg write %d (%d)\n",
			      port, offset);
			break;
		}
	}
	return (0);
}

static void
vb_intr_msix(struct vb_softc *vs, int q)
{
	uint64_t addr, data;
	int midx;

	if (vs->vs_msix_enabled &&
	    !(vs->vs_queues[q].vq_avail->flags &
	      VRING_AVAIL_F_NO_INTERRUPT)) {
		midx = vs->vs_queues[q].vq_msix_idx;
		KASSERT(midx < 3, ("vtnet_be: msi idx range err"));
		addr = vs->vs_msix[midx].addr;
		data = vs->vs_msix[midx].data;
		lapic_intr_msi(vs->vs_vn->vm, addr, data);
	}
}

static void
vb_txflags(struct mbuf *m, struct pinfo *pinfo)
{
	if ((m->m_pkthdr.csum_flags &
		 (CSUM_TCP|CSUM_IP6_TCP|CSUM_IP6_TSO|CSUM_IP_TSO)) &&
		pinfo->csum && (*pinfo->csum != 0))
		*pinfo->csum = 0;

	m->m_pkthdr.tso_segsz = m->m_pkthdr.fibnum;
	m->m_pkthdr.fibnum = 0;
}

static void
vb_input_process(struct ifnet *ifp, struct mbuf *m)
{
	struct pinfo pinfo;
	caddr_t hdr;
	
	do {
		/* set mbuf flags for transmit */
		ETHER_BPF_MTAP(ifp, m);
		hdr = mtod(m, caddr_t);
		vb_pparse(hdr, &pinfo);
		vb_txflags(m, &pinfo);
		m = m->m_nextpkt;
	} while (m != NULL);
}

/*
 * Input from vtnet_be iflib_rxeof
 */
static void
vb_if_input(struct ifnet *vbifp, struct mbuf *m)
{
	if_ctx_t ctx = vbifp->if_softc;
	struct vb_softc *vs = iflib_get_softc(ctx);
	struct ifnet *hwifp = vs->vs_ifparent;
	struct mbuf *mnext;

	vb_input_process(vbifp, m);
	if (hwifp->if_capabilities & IFCAP_TXBATCH) {
		(void)hwifp->if_transmit(hwifp, m);
	} else {
		do {
			mnext = m->m_nextpkt;
			m->m_nextpkt = NULL;
			(void)hwifp->if_transmit(hwifp, m);
			m = mnext;
		} while (m);
	}
}

/*
 * Input from physical NIC
 */
static void
vb_hw_if_input(struct ifnet *hwifp, struct mbuf *m)
{
	struct vb_softc *vs;
	struct ifnet *vbifp;

	/* XXX UGH - add parent ifp -> to vs mapping */
	vs = hwifp->if_pspare[3];
	vbifp = iflib_get_ifp(vs->vs_ctx);

	vb_input_process(hwifp, m);
	(void)vbifp->if_transmit(vbifp, m);
}

static void
vb_dev_kick(struct vb_softc *vs, uint32_t q)
{

	switch (q) {
		case 0:
			iflib_tx_intr_deferred(vs->vs_ctx, 0 /* XXX single queue */);
			break;
		case 1:
			iflib_rx_intr_deferred(vs->vs_ctx, 0 /* XXX single queue */);
			break;
	default:
		panic("vtnet_be: unknown queue %d kick\n", q);
	}
}

static void
vb_vring_munmap(struct vb_softc *vs, int q)
{
#ifdef GUEST_OVERCOMMIT
	int i;

	if (vs->vs_queues[q].vq_addr == 0)
		return;

	pmap_qremove(vs->vs_queues[q].vq_addr, vs->vs_queues[q].vq_pages);

	kva_free(vs->vs_queues[q].vq_addr,
	    vs->vs_queues[q].vq_pages * PAGE_SIZE);

	for (i = 0; i < vs->vs_queues[q].vq_pages; i++) {
		/* Free this up */
		vm_gpa_release(vs->vs_queues[q].vq_m[i]);
		vs->vs_queues[q].vq_m[i] = NULL;
	}

#endif
	vs->vs_queues[q].vq_lastpfn = 0;
	vs->vs_queues[q].vq_addr = 0;
	vs->vs_queues[q].vq_avail = NULL;
	vs->vs_queues[q].vq_used = NULL;

	if (q == VB_RXQ_IDX) {
		/* XXX multiq fix ... */
		vs->vs_tx_queues[0].vt_base = NULL;
	} else if (q == VB_TXQ_IDX) {
		vs->vs_rx_queues[0].vr_base = NULL;
		vs->vs_rx_queues[0].vr_avail = NULL;
	}

	iflib_link_state_change(vs->vs_ctx, LINK_STATE_DOWN, IF_Gbps(25));
}

static void
vb_vring_mmap(struct vb_softc *vs, uint32_t pfn, int q)
{
	vm_offset_t vaddr;
	uint64_t gpa;
	int qsz, len;
	struct ifnet *ifp;

	gpa = pfn << PAGE_SHIFT;

	/*
	 * Guest memory is linear and direct-mapped: the translation
	 * to a host virtual address is a simple base+offset.
	 * The use of 'lastpfn' to try and cache mappings is not
	 * needed, but since it's used in common code it's probably
	 * worth keeping in sync.
	 */
#ifdef GUEST_OVERCOMMIT
	/*
	 * In bhyve, guest memory may not be contiguous, or even
	 * present, in host memory. To simplify the virtio implementation,
	 * the pages will be wired in host memory, and then remapped
	 * to contiguous host virtual memory.
	 */

	/* First, release the current set of pages if any */
	vb_vring_munmap(vs, q);

	/* Alloc new mapping */
	vaddr = kva_alloc(vs->vs_queues[q].vq_pages * PAGE_SIZE);
	KASSERT(vaddr != 0, ("vtnet_be: kva_alloc NULL"));
	for (int i = 0; i < vs->vs_queues[q].vq_pages; i++) {
		void *vret;
		vm_paddr_t tgpa;

		tgpa = gpa + (i * PAGE_SIZE);
		vret = vm_gpa_hold(vs->vs_vn->vm, 0 /* XXX */, tgpa, PAGE_SIZE,
				   VM_PROT_RW,
				   (void **) &vs->vs_queues[q].vq_m[i]);
		KASSERT(vret != NULL, ("vtnet_be: NULL gpa_hold"));
	}
	pmap_qenter(vaddr, vs->vs_queues[q].vq_m,
		    vs->vs_queues[q].vq_pages);
	
#endif
	/*
	 * Set up queue pointers. Same logic as bhyve's vi_vq_init()
	 */
	qsz = vs->vs_queues[q].vq_qsize;
	vaddr = vm_gpa_to_kva(vs->vs_vn->vm, gpa, qsz*sizeof(struct vring_desc),
						  &vs->vs_gpa_hint);
	MPASS(vaddr);
	vs->vs_queues[q].vq_addr = vaddr;
	vs->vs_queues[q].vq_desc = (struct vring_desc *)vaddr;

	gpa += qsz * sizeof(struct vring_desc);
	len = (2 + qsz + 1) * sizeof(uint16_t);
	vaddr = vm_gpa_to_kva(vs->vs_vn->vm, gpa, len, &vs->vs_gpa_hint);
	MPASS(vaddr);
	vs->vs_queues[q].vq_avail = (struct vring_avail *)vaddr;
	if (q == VB_RXQ_IDX) {
		vs->vs_tx_queues[0].vt_base = (void *)(uintptr_t)vs->vs_queues[VB_RXQ_IDX].vq_desc;
	} else if (q == VB_TXQ_IDX) {
		vs->vs_rx_queues[0].vr_base = (void *)(uintptr_t)vs->vs_queues[VB_TXQ_IDX].vq_desc;
		vs->vs_rx_queues[0].vr_avail = (void *)(uintptr_t)vs->vs_queues[VB_TXQ_IDX].vq_avail->ring;
	}
	gpa += (2 + qsz + 1) * sizeof(uint16_t); 
	gpa = roundup2(gpa, PAGE_SIZE);
	len = (2 + qsz + 1) * sizeof(uint16_t);
	vaddr = vm_gpa_to_kva(vs->vs_vn->vm, gpa, (2 + qsz + 1) * sizeof(uint16_t),
						  &vs->vs_gpa_hint);
	/* XXX should fail out if it's outside the range of the guest */
	MPASS(vaddr);
	vs->vs_queues[q].vq_used = (struct vring_used *)vaddr;
	printf("[%d].vq_used = %p flags: %d qsize: %d len: %d\n", q, (void *)vaddr, vs->vs_queues[q].vq_used->flags, qsz, len);

	ifp = iflib_get_ifp(vs->vs_ctx);
	iflib_link_state_change(vs->vs_ctx, LINK_STATE_DOWN, IF_Gbps(25));
	/* XXX unsafe */
	if_setflagbits(ifp, 0, IFF_UP);
	ifp->if_init(vs->vs_ctx);

	if_setflagbits(ifp, IFF_UP, 0);
	ifp->if_init(vs->vs_ctx);
	iflib_link_state_change(vs->vs_ctx, LINK_STATE_UP, IF_Gbps(25));
}

static void
vb_dev_pfn(struct vb_softc *vs,  uint32_t pfn)
{
	int q;

	q = vs->vs_curq;
	if (q >= vs->vs_nvq)
		return;

	/* Only map if the pfn has changed */
	if (vs->vs_queues[q].vq_lastpfn != pfn && pfn == 0) {
		vb_vring_munmap(vs, q);
		return;
	}
	/* Only map if the pfn has changed */
	if (vs->vs_queues[q].vq_lastpfn != pfn)
		vb_vring_mmap(vs, pfn, q);
	
	vs->vs_queues[q].vq_pfn = pfn;
}

static void
vb_dev_reset(struct vb_softc *vs)
{
	vs->vs_generation++;

	vs->vs_status = 0;
	vs->vs_curq = 0;
	vs->vs_negotiated_caps = 0;

	vs->vs_queues[VB_RXQ_IDX].vq_qsize = vs->shared->isc_nrxd[0];
	vs->vs_queues[VB_RXQ_IDX].vq_lastpfn = vs->vs_queues[VB_RXQ_IDX].vq_pfn;
	vs->vs_queues[VB_RXQ_IDX].vq_pfn = 0;
	vs->vs_queues[VB_RXQ_IDX].vq_msix_idx = 0;

	vs->vs_queues[VB_TXQ_IDX].vq_qsize = vs->shared->isc_ntxd[0];
	vs->vs_queues[VB_TXQ_IDX].vq_lastpfn = vs->vs_queues[VB_TXQ_IDX].vq_pfn;
	vs->vs_queues[VB_TXQ_IDX].vq_pfn = 0;
	vs->vs_queues[VB_TXQ_IDX].vq_msix_idx = 0;
}

static int
vb_dev_msix(struct vb_softc *vs, struct vb_msix *vx)
{
	if (vs->vs_proc != curproc)
		return (EINVAL);

	vs->vs_msix_enabled = vx->status;

	if (vx->status) {
		vs->vs_msix[0].addr = vx->queue[0].addr;
		vs->vs_msix[0].data = vx->queue[0].msg;
		vs->vs_msix[1].addr = vx->queue[1].addr;
		vs->vs_msix[1].data = vx->queue[1].msg;
		vs->vs_msix[2].addr = vx->queue[2].addr;
		vs->vs_msix[2].data = vx->queue[2].msg;
	}

	return (0);
}

struct vtnet_be *
vtnet_be_init(struct vm *vm)
{
	struct vtnet_be *vb;

	vb = malloc(sizeof(struct vtnet_be), M_VTNETBE, M_WAITOK | M_ZERO);
	vb->vm = vm;
	vb->name = vm_name(vm);

	VB_LOCK;
	SLIST_INSERT_HEAD(&vb_head, vb, next);
	VB_UNLOCK;
			 
	return (vb);
}

void
vtnet_be_cleanup(struct vtnet_be *vb)
{
	struct vb_softc *vs;
	device_t dev;
	int i;

	VB_LOCK;
	while (!SLIST_EMPTY(&vb->dev)) {
		vs = SLIST_FIRST(&vb->dev);
		SLIST_REMOVE(&vb->dev, vs, vb_softc, vs_next);
		VB_UNLOCK;
		vs->vs_flags &= ~VS_ENQUEUED;

		/*
		 * Only destroy the interface if it was
		 * created by bhyve
		 */
		if (vs->vs_flags & VS_OWNED) {
			dev = iflib_get_dev(vs->vs_ctx);
			if_clone_destroy(device_get_nameunit(dev));
		} else {
			vs->vs_vn = NULL;
			vs->vs_proc = NULL;
			vs->vs_negotiated_caps = 0;
			vs->vs_io_start = 0;
			vs->vs_io_size = 0;
			for (i = 0; i < vs->shared->isc_nrxqsets; i++)
				bzero(&vs->vs_rx_queues[i], sizeof(struct vb_rxq));
			for (i = 0; i < vs->shared->isc_ntxqsets; i++)
				bzero(&vs->vs_tx_queues[i], sizeof(struct vb_txq));
		}
		VB_LOCK;
	}
	SLIST_REMOVE(&vb_head, vb, vtnet_be, next);
	VB_UNLOCK;

	free(vb, M_VTNETBE);
}

static if_pseudo_t vb_pseudo;

void
vmm_vtnet_be_modinit(void)
{
	vb_pseudo = vb_clone_register();
	mtx_init(&vb_mtx, "vtnet_be", NULL, MTX_DEF);
}

void
vmm_vtnet_be_modunload(void)
{
	iflib_clone_deregister(vb_pseudo);
	mtx_destroy(&vb_mtx);
}

static void
vb_rxq_init(struct vb_softc *vs, struct vb_rxq *rxq)
{
	rxq->vr_vs = vs;
	rxq->vr_cidx = 0;
}

static void
vb_txq_init(struct vb_softc *vs, struct vb_txq *txq)
{
	txq->vt_vs = vs;
	txq->vt_cidx = 0;
}

static int
vb_if_attach(struct vb_softc *vs, struct vb_if_attach *via)
{
	struct ifnet *ifp;

	if ((ifp = ifunit_ref(via->via_ifparent)) == NULL) {
		printf("ifunit_ref failed\n");
		return (ENXIO);
	}

	/* Verify ifnet not already in use */
	if (vb_ifnet_inuse(ifp)) {
		via->via_ifparent[IFNAMSIZ-1] = '\0';
		printf("vtnet_be: ifp %s in use\n", via->via_ifparent);
		if_rele(ifp);
		return (EBUSY);
	}
	vs->vs_ifparent = ifp;
	/* Add additional capabilities based on underlying ifnet */
	if (vs->vs_ifparent->if_capabilities & IFCAP_TXCSUM)
		vs->vs_hv_caps |= VIRTIO_NET_F_CSUM;
	if (vs->vs_ifparent->if_capabilities & IFCAP_TSO4)
		vs->vs_hv_caps |= VIRTIO_NET_F_HOST_TSO4;
	if (vs->vs_ifparent->if_capabilities & IFCAP_TSO6)
		vs->vs_hv_caps |= VIRTIO_NET_F_HOST_TSO6;
	if ((vs->vs_ifparent->if_capabilities & (IFCAP_RXCSUM | IFCAP_RXCSUM_IPV6)) ==
		(IFCAP_RXCSUM | IFCAP_RXCSUM_IPV6))
		vs->vs_hv_caps |= VIRTIO_NET_F_GUEST_CSUM;
	if (vs->vs_ifparent->if_capabilities & IFCAP_LRO)
		vs->vs_hv_caps |= VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6;

	return (0);
}

static int
vb_vm_attach(struct vb_softc *vs, struct vb_vm_attach *vva)
{
	struct vtnet_be *vb;
	int rc;

	vva->vva_vmparent[VMNAMSIZ-1] = '\0';
	if (strlen(vva->vva_ifparent)) {
		if ((rc = vb_if_attach(vs, (struct vb_if_attach *)vva)))
			return (rc);
	}

	/* Locate VM */
	vb = vb_find_vmname(vva->vva_vmparent);
	if (vb == NULL) {
		printf("vtnet_be: vmname %s doesn't exist\n", vva->vva_vmparent);
		return (ENOENT);
	}
	vs->vs_vn = vb;

	vs->vs_proc = curproc;
	vs->vs_io_start = vva->vva_io_start;
	vs->vs_io_size = vva->vva_io_size;

	memcpy(vs->vs_cfg.mac, vva->vva_macaddr, 6);
	vs->vs_cfg.status = VIRTIO_NET_S_LINK_UP;
	vs->vs_hv_caps |= VIRTIO_NET_F_HOST_TSO6;
	/* Register the memory region with the VM */
	rc = vm_register_ioport(vs->vs_vn->vm, vb_handle, vs,
	          vs->vs_io_start, vs->vs_io_size);

	if (rc) {
		printf("vm_register_ioport failed: %d\n", rc);
		vs->vs_proc = NULL;
		return (rc);
	}
	VB_LOCK;
	SLIST_INSERT_HEAD(&vb->dev, vs, vs_next);
	VB_UNLOCK;
	vs->vs_flags |= VS_ENQUEUED;

	return (0);
}

static int
vb_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct vb_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;
	struct vb_vm_attach va;
	int rc;

	if (params != NULL) {
		if ((rc = copyin(params, &va, sizeof(va)))) {
			printf("param copyin failed: %d\n", rc);
			return (rc);
		}
		if ((rc = vb_vm_attach(vs, &va))) {
			printf("vb_vm_attach failed %d\n", rc);
			return (rc);
		}
		vs->vs_flags |= VS_OWNED;
	}

	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	vs->vs_ctx = ctx;

	vs->vs_gpa_hint = 0;

	scctx->isc_tx_nsegments = VB_MAX_SCATTER;
	scctx->isc_tx_tso_segments_max = scctx->isc_tx_nsegments;
	scctx->isc_tx_tso_size_max = VB_TSO_SIZE;
	scctx->isc_tx_tso_segsize_max = VB_TSO_SEG_SIZE;
	scctx->isc_nrxqsets_max = scctx->isc_ntxqsets_max = 1;
	scctx->isc_capenable = VB_CAPS;
	scctx->isc_txrx = &vb_txrx;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
			| CSUM_IP6_UDP | CSUM_IP6_TCP;
#ifdef notyet
	scctx->isc_tx_csum_flags |= CSUM_SCTP | CSUM_IP6_SCTP;
#endif

	vs->vs_nvq = 2;	/* tx and rx, for now */

	/* Set up host capabilities */
	vs->vs_hv_caps = VIRTIO_NET_F_MAC | VIRTIO_NET_F_MRG_RXBUF |
		VIRTIO_NET_F_STATUS | VIRTIO_F_NOTIFY_ON_EMPTY;

	return (0);
}

static int
vb_attach_post(if_ctx_t ctx)
{
	struct vb_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;
	struct ifnet *ifp;
	char buf[32];
	int i;

	scctx = vs->shared;
	MPASS(scctx->isc_nrxqsets);
	MPASS(scctx->isc_ntxqsets);
	vs->vs_rx_queues = malloc(sizeof(struct vb_rxq)*scctx->isc_nrxqsets,
							  M_VTNETBE, M_WAITOK|M_ZERO);
	vs->vs_tx_queues = malloc(sizeof(struct vb_txq)*scctx->isc_ntxqsets,
							  M_VTNETBE, M_WAITOK|M_ZERO);
	for (i = 0; i < scctx->isc_nrxqsets; i++) {
		vb_rxq_init(vs, &vs->vs_rx_queues[i]);
		snprintf(buf, sizeof(buf), "rxq%d", i);
		iflib_softirq_alloc_generic(ctx, NULL, IFLIB_INTR_RX, i, buf);
	}
	for (i = 0; i < scctx->isc_ntxqsets; i++) {
		vb_txq_init(vs, &vs->vs_tx_queues[i]);
		snprintf(buf, sizeof(buf), "txq%d", i);
		iflib_softirq_alloc_generic(ctx, NULL, IFLIB_INTR_TX, i, buf);
	}
	vb_dev_reset(vs);
	scctx->isc_min_tx_latency = 1;

	/*
	 * If interface was created by bhyve
	 * plug everything together here
	 */
	if (vs->vs_flags & VS_OWNED) {
		ifp = iflib_get_ifp(ctx);
		ifp->if_input = vb_if_input;
		/* XXX provide state pointer for hw if_input :-( */
		vs->vs_ifparent->if_pspare[3] = vs;
		vs->vs_oinput = vs->vs_ifparent->if_input;
		vs->vs_ifparent->if_input = vb_hw_if_input;

		/* Put the interface into promisc mode */
		ifpromisc(vs->vs_ifparent, 1);
	}
	return (0);
}


static int
vb_detach(if_ctx_t ctx)
{
	struct vb_softc *vs = iflib_get_softc(ctx);
	struct vtnet_be *vb = vs->vs_vn;
	int i;

	if (vs->vs_flags & VS_ENQUEUED) {
		VB_LOCK;
		SLIST_REMOVE(&vb->dev, vs, vb_softc, vs_next);
		VB_UNLOCK;
	}
	if (vs->vs_oinput != NULL) {
		ifpromisc(vs->vs_ifparent, 0);
		vs->vs_ifparent->if_input = vs->vs_oinput;
	}

	for (i = 0; i < vs->vs_nvq; i++) {
		vb_vring_munmap(vs, i);
	}
	free(vs->vs_rx_queues, M_VTNETBE);
	free(vs->vs_tx_queues, M_VTNETBE);
	return (0);
}

static void
vb_init(if_ctx_t ctx)
{
}

static void
vb_stop(if_ctx_t ctx)
{
	struct vb_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = vs->shared;
	int i, j;

	MPASS(scctx->isc_nrxqsets);
	MPASS(scctx->isc_nrxd[0]);

	for (i = 0; i < scctx->isc_nrxqsets; i++)
		for (j = 0; j < scctx->isc_nrxd[0]; j++)
			vs->vs_rx_queues[i].vr_sdcl[j] = NULL;
	for (i = 0; i < scctx->isc_ntxqsets; i++)
		vs->vs_tx_queues[i].vt_cidx = 0;
	for (i = 0; i < scctx->isc_nrxqsets; i++)
		vb_rxq_init(vs, &vs->vs_rx_queues[i]);
}

static void
vb_rx_clset(if_ctx_t ctx, uint16_t fl __unused, uint16_t qidx,
			caddr_t *sdcl)
{
	struct vb_softc *vs = iflib_get_softc(ctx);

	vs->vs_rx_queues[qidx].vr_sdcl = sdcl;
}

static int
vb_priv_ioctl(if_ctx_t ctx, u_long command, caddr_t data)
{
	struct vb_softc *sc = iflib_get_softc(ctx);
	struct ifreq *ifr = (struct ifreq *)data;
	struct ifreq_buffer *ifbuf = &ifr->ifr_ifru.ifru_buffer;
	struct vb_ioctl_header *ioh =
	    (struct vb_ioctl_header *)(ifbuf->buffer);
	int rc = ENOTSUP;
	struct vb_ioctl_data *iod = NULL;

	if (command != SIOCGPRIVATE_0)
		return (EINVAL);

	if ((rc = priv_check(curthread, PRIV_DRIVER)) != 0)
		return (rc);
#ifdef notyet
	/* need sx lock for iflib context */
	iod = malloc(ifbuf->length, M_VTNETBE, M_WAITOK | M_ZERO);
#endif
	iod = malloc(ifbuf->length, M_VTNETBE, M_NOWAIT | M_ZERO);
	copyin(ioh, iod, ifbuf->length);

	switch (ioh->vih_type) {
		case VB_MSIX:
			rc = vb_dev_msix(sc, (struct vb_msix *)iod);
			break;
		default:
			rc = ENOIOCTL;
			break;
	}
	free(iod, M_VTNETBE);
	return (rc);
}

static int
vb_if_txq_intr_enable(if_ctx_t ctx, uint16_t txqid)
{
	return (0);
}

static int
vb_if_rxq_intr_enable(if_ctx_t ctx, uint16_t rxqid)
{
	return (0);
}

static device_method_t vb_if_methods[] = {
	DEVMETHOD(ifdi_rx_queue_intr_enable, vb_if_rxq_intr_enable),
	DEVMETHOD(ifdi_tx_queue_intr_enable, vb_if_txq_intr_enable),
	DEVMETHOD(ifdi_cloneattach, vb_cloneattach),
	DEVMETHOD(ifdi_attach_post, vb_attach_post),
	DEVMETHOD(ifdi_detach, vb_detach),
	DEVMETHOD(ifdi_init, vb_init),
	DEVMETHOD(ifdi_stop, vb_stop),
	DEVMETHOD(ifdi_priv_ioctl, vb_priv_ioctl),
	DEVMETHOD(ifdi_rx_clset, vb_rx_clset),
	DEVMETHOD_END
};

static driver_t vb_iflib_driver = {
	"vmi", vb_if_methods, sizeof(struct vb_softc)
};

char vb_driver_version[] = "0.0.1";

#define VB_MIN_TXD		128
#define VB_MAX_TXD		4096
#define VB_DEFAULT_TXD          1024
#define VB_MIN_RXD		128
#define VB_MAX_RXD		4096
#define VB_DEFAULT_RXD          1024

static struct if_shared_ctx vb_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_tx_maxsize = VB_TSO_SIZE,
	.isc_tx_maxsegsize = USHRT_MAX,
	.isc_rx_maxsize = USHRT_MAX,
	.isc_rx_nsegments = 1,
	.isc_rx_maxsegsize = USHRT_MAX,
	.isc_nfl = 1,
	.isc_nrxqs = 2,
	.isc_ntxqs = 1,
	.isc_driver_version = vb_driver_version,
	.isc_driver = &vb_iflib_driver,
	.isc_flags = IFLIB_TXD_ENCAP_PIO | IFLIB_RX_COMPLETION |	\
	IFLIB_SKIP_CLREFILL | IFLIB_HAS_RXCQ,

	.isc_nrxd_min = {VB_MIN_RXD, VB_MIN_RXD},
	.isc_ntxd_min = {VB_MIN_TXD},
	.isc_nrxd_max = {VB_MAX_RXD, VB_MAX_RXD},
	.isc_ntxd_max = {VB_MAX_TXD},
	.isc_nrxd_default = {VB_DEFAULT_RXD, VB_DEFAULT_RXD},
	.isc_ntxd_default = {VB_DEFAULT_TXD},
	.isc_name = "vmi",
	.isc_rx_completion = vb_rx_completion,
};

if_shared_ctx_t vb_sctx = &vb_sctx_init;

static if_pseudo_t
vb_clone_register(void)
{
	return (iflib_clone_register(vb_sctx));
}
