/*
 * Copyright (C) 2017-2018 Joyent Inc.
 * Copyright (C) 2017-2018 Matthew Macy <matt.macy@joyent.com>
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
#include <sys/module.h>
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
#include <net/if_vpc.h>
#include <net/if_bridgevar.h>

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
#include "if_vmnic.h"
#include "ifdi_if.h"

const char * pci_cmds[] = {
   "VIRTIO_PCI_HOST_FEATURES",
   "BAD1",
   "BAD2",
   "BAD3",
   "VIRTIO_PCI_GUEST_FEATURES",
   "BAD5",
   "BAD6",
   "BAD7",
   "VIRTIO_PCI_QUEUE_PFN",
   "BAD9",
   "BAD10",
   "BAD11",
   "VIRTIO_PCI_QUEUE_NUM",
   "BAD13",
   "VIRTIO_PCI_QUEUE_SEL",
   "BAD15",
   "VIRTIO_PCI_QUEUE_NOTIFY",
   "BAD17",
   "VIRTIO_PCI_STATUS",
   "VIRTIO_PCI_ISR",
   "VIRTIO_MSI_CONFIG_VECTOR",
   "BAD21",
   "VIRTIO_MSI_QUEUE_VECTOR",
};
#define VIRTIO_CMD_MAX VIRTIO_MSI_QUEUE_VECTOR

#define VB_MAX_TX_SEGS	64
#define VB_RXQ_IDX 0
#define VB_TXQ_IDX 1

#define VB_TSO_SIZE		(65535 + sizeof(struct ether_vlan_header))
#define VB_TSO_SEG_SIZE		USHRT_MAX
#define VB_MAX_SCATTER VB_MAX_TX_SEGS
#define VB_CAPS						  \
	(IFCAP_TSO | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTSO | IFCAP_HWCSUM | \
	IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM | IFCAP_VLAN_MTU |			\
	 IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU)

static MALLOC_DEFINE(M_VMNIC, "vmnic", "virtio-net backend");

static volatile int32_t modrefcnt;

#define DEVEL_BRINGUP

#ifdef VB_STATUS_DEBUG
#define SDPRINTF printf
#else
#define SDPRINTF(...)
#endif

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

static int
vq2txq(int vq)
{
	return (vq - 1) / 2;
}

static int
txq2vq(int txq)
{
	return txq * 2 + 1;
}
static int
vq2rxq(int vq)
{
	return vq / 2;
}

static int
rxq2vq(int rxq)
{
	return rxq * 2;
}

/*
 * This is an in-kernel backend for the guest virtio net driver.
 *
 * For the interface see:
 * http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1570001
 *
 * It uses iflib device cloning for node creation. The path
 * through the driver is an idiosyncratic inverted ifnet.
 *
 * Assuming an iflib hardware driver, [hw] represents the hw ifp value
 * and [vb] represents the vtnet_be ifp, the path follows what we see below.
 *
 * On receive:
 * (wire) -> iflib_rxeof -> ifp[hw]->if_input() [vmbridge_input] ->
 *	  vb_hw_if_input() ->
 *	  ifp[vb]->if_transmit [iflib_if_transmit] ->
 *	  vb_txd_encap -> (guest)
 *
 * On transmit:
 * (guest) -> iflib_rxeof -> vb_rxd_pkt_get();
 *	  ifp[vb]->if_input() [vb_if_input] ->
 *	  vmbridge_transmit() -> [vpc_transmit()] ->
 *	  ifp[hw]->if_transmit() [iflib_if_transmit] -> (wire)
 *
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
	uint16_t etype;
	uint8_t	 ehdrlen;	/* eth header len, includes VLAN tag */
	uint8_t	 l4type;	/* layer 4 protocol type */
	uint8_t	 l3size:7;	/* size of l3 header */
	uint8_t	 l4size;	/* layer 4 protocol type */
	uint8_t	 l3valid:1;	/* size of l3 header */
};

static SLIST_HEAD(, vtnet_be) vb_head;

struct vb_queue {
	uint16_t  vq_qsize;
	uint32_t  vq_lastpfn;
	uint32_t  vq_pfn;
	uint16_t  vq_id;
	uint16_t  vq_msix_idx;
	uint16_t  vq_avail_idx;

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

#define VS_ENQUEUED		0x001
#define VS_VERS_1		0x002
#define VS_READY		0x004
#define VS_OWNED		0x008
#define VS_ATTACHED		0x010
#define VS_IMMUTABLE		0x020

#define VS_NQS_CHANGED		0x100

#define VB_CIDX_VALID (1 << 18)

struct vb_softc {
	if_softc_ctx_t shared;
	if_ctx_t vs_ctx;
#define tx_num_queues shared->isc_ntxqsets
#define rx_num_queues shared->isc_nrxqsets
	struct vtnet_be *vs_vn;
	struct vb_rxq *vs_rx_queues;
	struct vb_txq *vs_tx_queues;
	struct proc *vs_proc;  /* proc that did the cloneattach  */
	SLIST_ENTRY(vb_softc) vs_next;
	uint32_t vs_flags;
	uint16_t vs_gpa_hint;

	/* virtio state */
	uint64_t   vs_generation;
	uint16_t   vs_io_start;
	uint16_t   vs_io_size;
	uint16_t   vs_nqs;
	uint16_t   vs_nvqs;
	uint8_t	   vs_msix_enabled;
	uint8_t    vs_curq;
	uint8_t    vs_status;
	uint8_t    vs_origmac[6];
	uint32_t   vs_hv_caps;
	uint32_t   vs_negotiated_caps;

	struct virtio_net_config vs_cfg;
	struct grouptask vs_deferred_uptask;
	struct vb_msix_vector *vs_msix;
	struct vb_queue *vs_queues;
	struct vb_queue *vs_cvq;
};

#define VB_HDR_MAX 18 + 40

struct vb_rxq {
	uint16_t vr_cidx;
	uint16_t vr_pidx;
	struct vb_softc *vr_vs;
	caddr_t *vr_sdcl;
	uint16_t *vr_avail;
	struct vring_desc *vr_base;
	uint8_t *vr_completion;
	uint16_t *vr_used;
	uint8_t vr_shift;
	uint8_t vr_idx;
	char vr_pkttmp[VB_HDR_MAX] __aligned(CACHE_LINE_SIZE);
};

struct vb_txq {
	struct vb_softc *vt_vs;
	struct vring_desc *vt_base;
	uint16_t vt_cidx; /* iflib current index */
	uint8_t vt_idx;
	qidx_t vt_vpidxs[VB_MAX_TX_SEGS];
	bus_dma_segment_t vt_segs[VB_MAX_TX_SEGS];
};

static if_pseudo_t vb_clone_register(void);
static void vb_intr_msix(struct vb_softc *vs, int q);
static void vb_rxq_init(struct vb_softc *vs, struct vb_rxq *rxq, int i);
static void vb_txq_init(struct vb_softc *vs, struct vb_txq *txq, int i);
static int vb_pparse(caddr_t data, struct pinfo *pinfo);

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
	uint16_t vidx, rxvq;

	pidx = pi->ipi_pidx;
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
	ndesc = VB_MAX_TX_SEGS;
	mask = scctx->isc_nrxd[0] - 1;
	vpidxs = txq->vt_vpidxs;
	rxvq = rxq2vq(pi->ipi_qsidx);
	va = vs->vs_queues[rxvq].vq_avail;

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
		return (ENOBUFS);
	}
	vhd = (void *)tx_segs[0].ds_addr;
	bzero(vhd, sizeof(*vhd));
	vhd->num_buffers = i;
	if (__predict_true(pi->ipi_csum_flags & CSUM_DATA_VALID)) {
		vhd->hdr.flags = VIRTIO_NET_HDR_F_DATA_VALID;
		vhd->hdr.csum_start = pi->ipi_ehdrlen + pi->ipi_ip_hlen;
		switch (pi->ipi_ipproto) {
			case IPPROTO_TCP:
			vhd->hdr.csum_offset =
			    offsetof(struct tcphdr, th_sum);
			if (pi->ipi_len > vs->vs_cfg.mtu) {
				caddr_t hdr = (caddr_t)segs[0].ds_addr;
				struct pinfo pinfo;
				int hdrlen;
				vb_pparse(hdr, &pinfo);
				hdrlen = pi->ipi_ehdrlen + pi->ipi_ip_hlen +
					max(sizeof(struct tcphdr), pinfo.l4size);
				vhd->hdr.gso_size = vs->vs_cfg.mtu - hdrlen;
#if 0
				printf("len: %d mtu: %d ehdrlen: %d iphlen: %d tcp_hlen: %d gso_size: %d\n",
					   pi->ipi_len, vs->vs_cfg.mtu, pi->ipi_ehdrlen, pi->ipi_ehdrlen,
				   pinfo.l4size, vhd->hdr.gso_size);
#endif
				if (pi->ipi_etype == ETHERTYPE_IP)
					vhd->hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
				else if (pi->ipi_etype == ETHERTYPE_IPV6)
					vhd->hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
			}
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
	if (pi->ipi_nsegs > 1)
		vb_print_vhdr(vhd);
	doff = sizeof(*vhd);
	ndesc = i;
	total = pi->ipi_len;
	soff = didx = sidx = 0;
	vu = vs->vs_queues[rxvq].vq_used;
	vidx = vu->idx;
	
	DPRINTF("vidx:%d vu->idx: %d vu->flags: %x\n",
			vidx, vu->idx, vu->flags);
	do {
		/* copy length / source delta / destination delta */
		int len, srem, drem, dlen;
		char *src, *dst;
		bool update_used;

		update_used = false;
		srem = segs[sidx].ds_len - soff;
		dlen = tx_segs[didx].ds_len;
		drem = dlen - doff;
		src = (caddr_t)segs[sidx].ds_addr + soff;
		dst = (caddr_t)tx_segs[didx].ds_addr + doff;
		/*
		 * Mark size of last descriptor and end loop
		 */
		if (total == srem && (srem <= drem)) {
			txd = &txq->vt_base[(pi->ipi_pidx + didx) & mask];

			dlen = doff + srem;
			DPRINTF("last descriptor: %d len: %d doff: %d, srem: %d, dsize: %lu\n",
				   (pi->ipi_pidx + didx) & mask, dlen, doff, srem, tx_segs[didx].ds_len);
			MPASS(dlen <= tx_segs[didx].ds_len);
			update_used = true;
		}
		if (srem < drem) {
			len = srem;
			doff += len;
			soff = 0;
			sidx++;
		} else if (srem > drem) {
			len = drem;
			soff += len;
			doff = 0;
			update_used = true;
		} else {
			len = srem;
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
			didx++;
			if ((vidx & 63) == 0)
				DPRINTF("%s called pidx: %d nsegs: %d %d ndesc avail "
					   "vidx: %d vue->id: %d vue->len: %d vpidxs[%d]: %d\n",
						__func__, pidx, pi->ipi_nsegs, ndesc,
						vidx, vue->id, vue->len, didx, vpidxs[didx]);
		}
	} while (didx < ndesc);

	pi->ipi_new_pidx = pidx;
	/* Update used ring to reflect final state */
	wmb();
	vu->idx = vidx;
	return (0);
}

static void
vb_txd_flush(void *arg, uint16_t txqid, qidx_t pidx __unused)
{
	struct vb_softc *vs = arg;

	/* Interrupt the guest */
	vb_intr_msix(vs, rxq2vq(txqid));
}

static int
vb_txd_credits_update(void *arg, uint16_t txqid, bool clear)
{

	struct vb_softc *vs = arg;
	if_softc_ctx_t scctx = vs->shared;
	struct vb_txq *txq = &vs->vs_tx_queues[txqid];
	int16_t vpidx, rxvq;
	int32_t delta;

	rxvq = rxq2vq(txqid);
	vpidx = vs->vs_queues[rxvq].vq_avail->idx & (scctx->isc_ntxd[0]-1);

	/* credits updated should reflect new
	 * descriptors available in the ring --
	 * so long as we copy in to the guest the
	 * mbuf chain can be freed instantly
	 */
	delta = (int)vpidx - (int)txq->vt_cidx;
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

#define idx2gen(rxq, idx) ((uint8_t)(!(((idx) >> (rxq)->vr_shift) & 1UL)))

static void
vb_rxd_reclaim(struct vb_rxq *rxq)
{
	struct vb_softc *vs = rxq->vr_vs;
	volatile struct vring_used *vu;
	volatile struct vring_used_elem *vue;
	uint16_t idx, vidx, pidx, nrxd;
	int mask, mask_used;
#ifdef INVARIANTS
	int count = 0;
#endif

	if (__predict_false(!(vs->vs_flags & VS_READY)))
		return;

	nrxd = vs->shared->isc_nrxd[0];
	mask_used = (nrxd*4)-1;
	mask = nrxd-1;

	pidx = rxq->vr_pidx;
	/* Update the element in the used ring */
	vu = vs->vs_queues[txq2vq(rxq->vr_idx)].vq_used;
	MPASS(vu);
	vidx = vu->idx;
	for (pidx = rxq->vr_pidx; rxq->vr_completion[pidx & mask] == idx2gen(rxq, pidx); pidx++) {
		idx = rxq->vr_used[pidx & mask_used];
		vue = &vu->ring[vidx++ & mask];
		vue->id = idx;
		MPASS(count++ < nrxd);
	}
	/* ensure that all prior vue updates are written first */
	wmb();
	vu->idx = vidx;
	rxq->vr_pidx = pidx;
	vb_intr_msix(vs, txq2vq(rxq->vr_idx));
}

static void
vb_rxd_flush(void *arg, uint16_t rxqid,
			 uint8_t flid __unused, qidx_t pidx __unused)
{
}

static void *
vb_cl_map(struct vb_softc *vs, volatile struct vring_desc *desc)
{

	struct vm *vm = vs->vs_vn->vm;

	return ((void *)vm_gpa_to_kva(vm, desc->addr, desc->len, &vs->vs_gpa_hint));
}

static int
vb_rxd_available(void *arg, qidx_t rxqid, qidx_t cidx, qidx_t budget)
{
	struct vb_softc *vs = arg;
	struct vb_rxq *rxq = &vs->vs_rx_queues[rxqid];
	uint16_t idx, nrxd = vs->shared->isc_nrxd[0];
	int cnt;

	idx =  vs->vs_queues[txq2vq(rxqid)].vq_avail->idx;
	idx &= (nrxd-1);
	cnt = (int32_t)idx - (int32_t)cidx;
	if (cnt < 0)
		cnt += nrxd;
	if (__predict_false(abs(rxq->vr_pidx - rxq->vr_cidx) >= (nrxd >> 4)))
		vb_rxd_reclaim(rxq);

	return (cnt);
}

static int
vb_pparse(caddr_t data, struct pinfo *pinfo)
{
	struct ether_vlan_header *eh;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct tcphdr *th;
	int ehdrlen;
	int l3valid, l3size, l4type;
	uint16_t etype;

	eh = (struct ether_vlan_header *)data;
	if (eh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		etype = ntohs(eh->evl_proto);
		ehdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
	} else {
		etype = ntohs(eh->evl_encap_proto);
		ehdrlen = ETHER_HDR_LEN;
	}
	th = NULL;
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
	if (l4type == IPPROTO_TCP) {
		th = (void*)(((caddr_t)ip) + l3size);
		pinfo->l4size = th->th_off << 2;
	}
	pinfo->etype = etype;
	pinfo->ehdrlen = ehdrlen;
	pinfo->l3valid = l3valid;
	pinfo->l3size = l3size;
	pinfo->l4type = l4type;
	return (1);
}
static void
vb_rx_vhdr_process(struct virtio_net_hdr_mrg_rxbuf *vh,
				   struct vring_desc *rxd, caddr_t buf,
				   if_rxd_info_t ri)
{
	struct pinfo pinfo;
	int flags;

	switch (vh->hdr.gso_type) {
		case VIRTIO_NET_HDR_GSO_TCPV4:
			ri->iri_tso_segsz = vh->hdr.gso_size;
			ri->iri_csum_data = vh->hdr.csum_offset;
			ri->iri_csum_flags = CSUM_TSO | CSUM_TCP;
			return;
			break;
		case VIRTIO_NET_HDR_GSO_TCPV6:
			ri->iri_tso_segsz = vh->hdr.gso_size;
			ri->iri_csum_data = vh->hdr.csum_offset;
			ri->iri_csum_flags = CSUM_IP6_TSO | CSUM_TCP_IPV6;
			return;
			break;
		default:
			break;
	}
	if ((vh->hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) == 0)
		return;

	vb_pparse(buf, &pinfo);
	flags = 0;
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
					break;
				case IPPROTO_UDP:
					flags = CSUM_UDP_IPV6;
					break;
				case IPPROTO_SCTP:
					flags = CSUM_SCTP_IPV6;
					break;
			}
			break;
	}
	if (__predict_false(flags == 0))
		printf("XXX no flags, l4type: %d\n", pinfo.l4type);
	ri->iri_csum_flags = flags;
	ri->iri_csum_data = vh->hdr.csum_offset;
}

static int
vb_rxd_pkt_get(void *arg, if_rxd_info_t ri)
{
	struct virtio_net_hdr_mrg_rxbuf *vh;
	struct vb_softc *vs = arg;
	if_softc_ctx_t scctx = vs->shared;
	struct vb_rxq *rxq = &vs->vs_rx_queues[ri->iri_qsidx];
	struct vring_desc *rxd;
	int i, cidx, vcidx, count, mask, used_mask;
	caddr_t data;

	MPASS(ri->iri_cidx < scctx->isc_nrxd[0]);
	i = 0;
	cidx = ri->iri_cidx;
	vcidx = rxq->vr_avail[cidx];
	mask = scctx->isc_nrxd[0]-1;
	used_mask = (4*scctx->isc_nrxd[0])-1;
	if (cidx != (rxq->vr_cidx & mask))
		printf("mismatch cidx: %d vr_cidx_masked:%d vr_cidx: %d",
			   cidx, rxq->vr_cidx & mask, rxq->vr_cidx);

	rxq->vr_used[rxq->vr_cidx & used_mask] = vcidx;
	/* later passed to ext_free to return used descriptors */
	ri->iri_cookie1 = (void *)rxq;
	ri->iri_cookie2 = (rxq->vr_cidx++ | VB_CIDX_VALID);

	ri->iri_cidx = rxq->vr_cidx & (scctx->isc_nrxd[0]-1);
	rxd = (struct vring_desc *)&rxq->vr_base[vcidx];

	if (__predict_false(rxd->len < sizeof(*vh))) {
		DPRINTF("%s rxd->len short: %d\n", __func__, rxd->len);
		return (ENXIO);
	}
	rxq->vr_sdcl[vcidx] = vb_cl_map(vs, rxd);
	vh = (void *)rxq->vr_sdcl[vcidx];
	if (vh == NULL)
		return (ENXIO);
	if (__predict_true(rxd->len == sizeof(*vh))) {
		rxq->vr_sdcl[vcidx] = NULL;
		if (__predict_true(rxd->flags & VRING_DESC_F_NEXT)) {
			vcidx = rxd->next;
			rxq->vr_sdcl[vcidx] = vb_cl_map(vs, rxd);
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
	rxd = (struct vring_desc *)&rxq->vr_base[vcidx];
	data = rxq->vr_sdcl[vcidx] = vb_cl_map(vs, rxd);
	vb_rx_vhdr_process(vh, rxd, data, ri);

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
		rxq->vr_sdcl[vcidx] = vb_cl_map(vs, rxd);
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
	struct vb_softc *vs;
	struct vb_rxq *rxq;
	int cidx, mask, skip;

	if ((m->m_flags & M_PKTHDR) == 0)
		return;

	rxq = (struct vb_rxq *)m->m_ext.ext_arg1;
	MPASS(rxq != NULL);
	vs = rxq->vr_vs;
	cidx = (uintptr_t)m->m_ext.ext_arg2;
	/*
	 * Is this just a buffer post-processing?
	 */
	skip = (m->m_flags & M_PROTO1);
	if (m_ismvec(m))
		mvec_free((void*)m);
	if (skip)
		return;

	MPASS(cidx & VB_CIDX_VALID);
	cidx &= ~VB_CIDX_VALID;
	mask = vs->shared->isc_nrxd[0]-1;
	rxq->vr_completion[cidx & mask] = idx2gen(rxq, cidx);
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
vb_find_vmname(const char *vmname)
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

static void
deferred_up(void *arg)
{
	if_ctx_t ctx = arg;
	struct ifnet *ifp = iflib_get_ifp(ctx);
	struct mtx *ctxlock;

	ctxlock = iflib_ctx_lock_get(ctx);
	mtx_lock(ctxlock);
	if_setflagbits(ifp, IFF_UP, 0);
	iflib_link_state_change(ctx, LINK_STATE_UP, IF_Gbps(200));
	mtx_unlock(ctxlock);
	ifp->if_init(ctx);
}

static void
deferred_up_timer(void *arg)
{
	struct vb_softc *vs = arg;

	GROUPTASK_ENQUEUE(&vs->vs_deferred_uptask);
}

static void
vb_status_change(struct vb_softc *vs, uint32_t val)
{
	struct ifnet *ifp = iflib_get_ifp(vs->vs_ctx);

	/*
	 * For legacy guest drivers - e.g. FreeBSD
	 */
	if (val == VIRTIO_CONFIG_STATUS_RESET) {
		SDPRINTF("VIRTIO_CONFIG_STATUS_RESET\n");
		if_setflagbits(ifp, 0, IFF_UP);
		ifp->if_init(vs->vs_ctx);
	}
	if (val & VIRTIO_CONFIG_STATUS_DRIVER)
		SDPRINTF("VIRTIO_CONFIG_STATUS_DRIVER ");
	if (val & VIRTIO_CONFIG_STATUS_ACK)
		SDPRINTF("VIRTIO_CONFIG_STATUS_ACK ");
	if (val & VIRTIO_CONFIG_STATUS_NEEDS_RESET) {
		SDPRINTF("VIRTIO_CONFIG_STATUS_NEEDS_RESET ");
		if_setflagbits(ifp, 0, IFF_UP);
		ifp->if_init(vs->vs_ctx);
	}
	if (val & VIRTIO_CONFIG_STATUS_DRIVER_OK) {
		SDPRINTF("VIRTIO_CONFIG_STATUS_DRIVER_OK ");
		/* Up interface */
		timeout(deferred_up_timer, vs, hz*5);
	}
	if (val & VIRTIO_CONFIG_STATUS_FEATURES_OK) {
		SDPRINTF("VIRTIO_CONFIG_STATUS_FEATURES_OK ");
		vs->vs_flags |= VS_VERS_1;
	}
	if (val & VIRTIO_CONFIG_STATUS_FAILED) {
		SDPRINTF("VIRTIO_CONFIG_STATUS_FAILED");
		if_setflagbits(ifp, 0, IFF_UP);
		ifp->if_init(vs->vs_ctx);
	}
	SDPRINTF("\n");
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

	SDPRINTF("%s %s offset: %d len: %d val: %x\n", __func__, in ? "in" : "out",
		   offset, bytes, *val);

	ptr = (uint8_t *)&vs->vs_cfg + offset;
	if (in) {
		if (bytes + offset <= sizeof(struct virtio_net_config))
			memcpy(val, ptr, bytes);
		else
			memset(val, -1, bytes);
	} else if (offset + bytes <= ETHER_ADDR_LEN) {
		memcpy(ptr, val, bytes);
	}

	return (0);
}

static int
vb_handle(struct vm *vm, int vcpuid, bool in, int port, int bytes,
    uint32_t *val, void *arg)
{
	struct vb_softc *vs = arg;
	int cfgoffset;
	uint16_t offset;
#ifdef VB_STATUS_DEBUG
	const char *cmd;
#endif
	offset = port - vs->vs_io_start;

	cfgoffset = VIRTIO_PCI_CONFIG_OFF(vs->vs_msix_enabled);

	/* Handle the device-specific config region */
	if (offset >= cfgoffset) {
		offset -= cfgoffset;
		return (vb_handle_config(vs, offset, in, bytes, val));
	}
#ifdef VB_STATUS_DEBUG
	cmd = offset > VIRTIO_CMD_MAX ? "invalid offset" : pci_cmds[offset];
#endif
	if (in) {
		switch (offset) {
		case VIRTIO_PCI_HOST_FEATURES:
			*val = vs->vs_hv_caps;
			break;
		case VIRTIO_PCI_GUEST_FEATURES:
			*val = vs->vs_negotiated_caps;
			break;
		case VIRTIO_PCI_QUEUE_PFN:
			if (vs->vs_curq < vs->vs_nvqs)
				*val = vs->vs_queues[vs->vs_curq].vq_pfn;
			else
				*val = 0;
			break;
		case VIRTIO_PCI_QUEUE_NUM:
			if (vs->vs_curq < vs->vs_nvqs)
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
			if (vs->vs_curq < vs->vs_nvqs)
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
			if (vs->vs_curq < vs->vs_nvqs)
				vs->vs_queues[vs->vs_curq].vq_msix_idx = *val;
			break;
		default:
			printf("vtnet_be: illegal reg write %d (%d)\n",
			      port, offset);
			break;
		}
	}
	SDPRINTF("%s %s cmd: %s val: %x\n", __func__, in ? "in" : "out",
			cmd, *val);
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
		if (midx > vs->vs_nvqs)
			return;
		addr = vs->vs_msix[midx].addr;
		data = vs->vs_msix[midx].msg;
		lapic_intr_msi(vs->vs_vn->vm, addr, data);
	}
}

/*
 * Input from vtnet_be iflib_rxeof (output from guest)
 */
static void
vb_if_input(struct ifnet *ifp, struct mbuf *m)
{

	if (ifp->if_bridge == NULL) {
		m_freechain(m);
		return;
	}
	(void)(*(ifp)->if_bridge_output)(ifp, m, NULL, NULL);
}

static void
vb_dev_kick(struct vb_softc *vs, uint32_t q)
{
	if (__predict_false(q == vs->vs_nvqs-1)) {
		iflib_admin_intr_deferred(vs->vs_ctx);
		return;
	}
	switch (q & 1) {
		case VB_RXQ_IDX:
			iflib_tx_intr_deferred(vs->vs_ctx, vq2rxq(q));
			break;
		case VB_TXQ_IDX:
			iflib_rx_intr_deferred(vs->vs_ctx, vq2txq(q));
			break;
	}
}

static void
vb_vring_munmap(struct vb_softc *vs, int q)
{
	int qid;

#ifdef GUEST_OVERCOMMIT
	int i;

	if (vs->vs_queues[q].vq_addr == 0)
		return;

	vs->vs_flags &= ~VS_READY;
	pmap_qremove(vs->vs_queues[q].vq_addr, vs->vs_queues[q].vq_pages);

	kva_free(vs->vs_queues[q].vq_addr,
	    vs->vs_queues[q].vq_pages * PAGE_SIZE);

	for (i = 0; i < vs->vs_queues[q].vq_pages; i++) {
		/* Free this up */
		vm_gpa_release(vs->vs_queues[q].vq_m[i]);
		vs->vs_queues[q].vq_m[i] = NULL;
	}
#else
	vs->vs_flags &= ~VS_READY;
#endif
	vs->vs_queues[q].vq_lastpfn = 0;
	vs->vs_queues[q].vq_addr = 0;
	vs->vs_queues[q].vq_avail = NULL;
	vs->vs_queues[q].vq_used = NULL;

	if (q == vs->vs_nvqs-1) {
		vs->vs_cvq = NULL;
	} else if ((q & 1) == VB_RXQ_IDX) {
		qid = vq2rxq(q);
		vs->vs_tx_queues[qid].vt_base = NULL;
	} else if ((q & 1) == VB_TXQ_IDX) {
		qid = vq2txq(q);
		vs->vs_rx_queues[qid].vr_base = NULL;
		vs->vs_rx_queues[qid].vr_avail = NULL;
	}
}

static void
vb_vring_mmap(struct vb_softc *vs, uint32_t pfn, int q)
{
	vm_offset_t vaddr;
	uint64_t gpa, pfn64;
	int qsz, len, qid;

	pfn64 = pfn;
	gpa = pfn64 << PAGE_SHIFT;

	if (q >= vs->vs_nvqs)
		return;
	if (q >= vs->vs_nvqs)
		vs->vs_nvqs = q+1;
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
	if (q == vs->vs_nvqs-1) {
		vs->vs_cvq = (void *)(uintptr_t)&vs->vs_queues[q];
	} else if ((q & 1) == VB_RXQ_IDX) {
		qid = vq2rxq(q);
		vs->vs_tx_queues[qid].vt_base = (void *)(uintptr_t)vs->vs_queues[q].vq_desc;
	} else if ((q & 1) == VB_TXQ_IDX) {
		qid = vq2txq(q);
		vs->vs_rx_queues[qid].vr_base = (void *)(uintptr_t)vs->vs_queues[q].vq_desc;
		vs->vs_rx_queues[qid].vr_avail = (void *)(uintptr_t)vs->vs_queues[q].vq_avail->ring;
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

	if (q == vs->vs_nvqs-1)
		vs->vs_flags |= VS_READY;
}

static void
vb_dev_pfn(struct vb_softc *vs,  uint32_t pfn)
{
	int q;

	q = vs->vs_curq;
	if (q >= vs->vs_nvqs)
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
	int i;

	vs->vs_generation++;

	vs->vs_status = 0;
	vs->vs_curq = 0;
	vs->vs_negotiated_caps = 0;
	vs->vs_cvq = NULL;

	for (i = 0; i < vs->vs_nvqs; i++) {
		vs->vs_queues[i].vq_qsize = vs->shared->isc_nrxd[0];
		vs->vs_queues[i].vq_lastpfn = vs->vs_queues[i].vq_pfn;
		vs->vs_queues[i].vq_pfn = 0;
		vs->vs_queues[i].vq_msix_idx = 0;
		vs->vs_queues[i].vq_id = i;
	}
}

static int
vb_dev_msix(struct vb_softc *vs, const struct vb_msix *vx, int length)
{
	int i, size;

	if (vs->vs_proc != curproc)
		return (EINVAL);

	size = sizeof(*vx) + vx->vm_count*sizeof(struct vb_msix_vector);
	if (length != (sizeof(*vx) + vx->vm_count*sizeof(struct vb_msix_vector))) {
		printf("__func__, bad length for vb_msix %d -- expected %d \n", length, size);
		return (EINVAL);
	}
	if (vx->vm_count < 3 || vx->vm_count > (2*VB_QUEUES_MAX) + 1) {
		printf("%s bad count %d\n", __func__, vx->vm_count);
		return (EINVAL);
	}

	vs->vs_msix_enabled = vx->vm_status;
	if (vx->vm_status) {
		for (i = 0; i < vx->vm_count; i++) {
			vs->vs_msix[i].addr = vx->vm_q[i].addr;
			vs->vs_msix[i].msg = vx->vm_q[i].msg;
		}
	}
	return (0);
}

static struct vtnet_be *
vtnet_be_init_(struct vm *vm)
{
	struct vtnet_be *vb;

	vb = malloc(sizeof(struct vtnet_be), M_VMNIC, M_WAITOK | M_ZERO);
	vb->vm = vm;
	vb->name = vm_name(vm);

	VB_LOCK;
	SLIST_INSERT_HEAD(&vb_head, vb, next);
	VB_UNLOCK;
			 
	return (vb);
}

static void
vtnet_be_cleanup_(struct vtnet_be *vb)
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

	free(vb, M_VMNIC);
}

static if_pseudo_t vb_pseudo;

static int
vmnic_module_init(void)
{
	vb_pseudo = vb_clone_register();
	mtx_init(&vb_mtx, "vtnet_be", NULL, MTX_DEF);
	vtnet_be_cleanup = vtnet_be_cleanup_;
	vtnet_be_init = vtnet_be_init_;
	return (0);
}

static void
vmnic_module_deinit(void)
{
	/* XXX refcount --- check */
	iflib_clone_deregister(vb_pseudo);
	mtx_destroy(&vb_mtx);
	vtnet_be_cleanup = NULL;
	vtnet_be_init = NULL;
}

static void
vb_rxq_init(struct vb_softc *vs, struct vb_rxq *rxq, int idx)
{
	rxq->vr_vs = vs;
	rxq->vr_pidx = rxq->vr_cidx = 0;
	rxq->vr_idx = idx;
	/* one bit beyond indicates whether we've wrapped an
	 * even or odd number of times
	 */
	rxq->vr_shift = ffs(vs->shared->isc_nrxd[0])-1;
	rxq->vr_used = malloc(sizeof(uint16_t)*vs->shared->isc_nrxd[0]*4,
						  M_VMNIC, M_WAITOK|M_ZERO);
	rxq->vr_completion =  malloc(sizeof(uint8_t)*vs->shared->isc_nrxd[0],
						  M_VMNIC, M_WAITOK|M_ZERO);
}

static void
vb_rxq_deinit(struct vb_softc *vs, struct vb_rxq *rxq)
{
	free(rxq->vr_used, M_VMNIC);
	free(rxq->vr_completion, M_VMNIC);
}

static void
vb_txq_init(struct vb_softc *vs, struct vb_txq *txq, int idx)
{
	txq->vt_idx = idx;
	txq->vt_vs = vs;
	txq->vt_cidx = 0;
}
static int
vb_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct vb_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;

	vs->vs_nqs = 1;
	vs->vs_nvqs = 3;
	scctx = vs->shared = iflib_get_softc_ctx(ctx);
	vs->vs_ctx = ctx;
	vs->vs_gpa_hint = 0;

	scctx->isc_tx_nsegments = VB_MAX_SCATTER;
	scctx->isc_tx_tso_segments_max = scctx->isc_tx_nsegments;
	scctx->isc_tx_tso_size_max = VB_TSO_SIZE;
	scctx->isc_tx_tso_segsize_max = VB_TSO_SEG_SIZE;
	scctx->isc_nrxqsets_max = scctx->isc_ntxqsets_max = 
		scctx->isc_nrxqsets = scctx->isc_ntxqsets = vs->vs_nqs;
	scctx->isc_capenable = VB_CAPS;
	scctx->isc_txrx = &vb_txrx;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
			| CSUM_IP6_UDP | CSUM_IP6_TCP;
#ifdef notyet
	scctx->isc_tx_csum_flags |= CSUM_SCTP | CSUM_IP6_SCTP;
#endif

	/* Set up host capabilities */
	vs->vs_hv_caps |= VIRTIO_NET_F_MAC | VIRTIO_NET_F_MRG_RXBUF |
		VIRTIO_NET_F_STATUS | VIRTIO_F_NOTIFY_ON_EMPTY | VIRTIO_NET_F_CTRL_VQ |	\
		VIRTIO_NET_F_MQ;
	return (0);
}

static int
vb_attach_post(if_ctx_t ctx)
{
	struct vb_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = vs->shared;
	struct ifnet *ifp;
	char buf[32];
	int i, nvq;

	MPASS(scctx->isc_nrxqsets);
	MPASS(scctx->isc_ntxqsets);
	MPASS(scctx->isc_ntxqsets == scctx->isc_nrxqsets);
	vs->vs_nqs = scctx->isc_nrxqsets;
	nvq = vs->vs_nvqs;
	vs->vs_queues = malloc(nvq*sizeof(struct vb_queue), M_VMNIC, M_WAITOK|M_ZERO);
	vs->vs_msix = malloc(nvq*sizeof(struct vb_msix), M_VMNIC, M_WAITOK|M_ZERO);
	vs->vs_rx_queues = malloc(sizeof(struct vb_rxq)*scctx->isc_nrxqsets,
							  M_VMNIC, M_WAITOK|M_ZERO);
	vs->vs_tx_queues = malloc(sizeof(struct vb_txq)*scctx->isc_ntxqsets,
							  M_VMNIC, M_WAITOK|M_ZERO);
	MPASS(scctx->isc_nrxqsets >= 1);
	MPASS(scctx->isc_ntxqsets >= 1);
	for (i = 0; i < scctx->isc_nrxqsets; i++) {
		vb_rxq_init(vs, &vs->vs_rx_queues[i], i);
		snprintf(buf, sizeof(buf), "rxq%d", i);
		iflib_softirq_alloc_generic(ctx, NULL, IFLIB_INTR_RX, i, buf);
	}
	for (i = 0; i < scctx->isc_ntxqsets; i++) {
		vb_txq_init(vs, &vs->vs_tx_queues[i], i);
		snprintf(buf, sizeof(buf), "txq%d", i);
		iflib_softirq_alloc_generic(ctx, NULL, IFLIB_INTR_TX, i, buf);
	}
	vb_dev_reset(vs);
	iflib_config_gtask_init(vs->vs_ctx, &vs->vs_deferred_uptask, deferred_up, "deferred up");
	scctx->isc_min_tx_latency = 1;
	scctx->isc_rx_mvec_enable = 1;
	/*
	 * If interface was created by bhyve
	 * plug everything together here
	 */
	ifp = iflib_get_ifp(ctx);
	ifp->if_input = vb_if_input;
	return (0);
}

static int
vb_if_attach(struct vb_softc *vs)
{
	struct ifnet *ifp = iflib_get_ifp(vs->vs_ctx);

	if (ifp->if_capabilities & IFCAP_TXCSUM)
		vs->vs_hv_caps |= VIRTIO_NET_F_CSUM;
	if (ifp->if_capabilities & IFCAP_TSO4)
		vs->vs_hv_caps |= VIRTIO_NET_F_HOST_TSO4;
	if (ifp->if_capabilities & IFCAP_TSO6)
		vs->vs_hv_caps |= VIRTIO_NET_F_HOST_TSO6;
	if ((ifp->if_capabilities & (IFCAP_RXCSUM | IFCAP_RXCSUM_IPV6)) ==
		(IFCAP_RXCSUM | IFCAP_RXCSUM_IPV6))
		vs->vs_hv_caps |= VIRTIO_NET_F_GUEST_CSUM;
	if (ifp->if_capabilities & IFCAP_LRO)
		vs->vs_hv_caps |= VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6;

	vs->vs_hv_caps |= VIRTIO_NET_F_MTU;
	if (bootverbose) {
		printf("caps: %016lx encaps: %016lx hv_caps: %08x\n",
			   ifp->if_capabilities, ifp->if_capenable, vs->vs_hv_caps);
		printf("mac: %6D status: %x max_vq_pairs: %d mtu: %d\n",
			   vs->vs_cfg.mac, ":", vs->vs_cfg.status, vs->vs_cfg.max_virtqueue_pairs,
			   vs->vs_cfg.mtu);
	}
	return (0);
}

static int
vb_vm_attach(struct vb_softc *vs, const struct vb_vm_attach *vva)
{
	struct vtnet_be *vb;
	int rc;

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
	vs->vs_cfg.status = VIRTIO_NET_S_LINK_UP;
	vs->vs_cfg.max_virtqueue_pairs = vs->vs_nqs;
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

/* reset queue sizes and redrive attach */
static int
vb_vm_deferred_attach(struct vb_softc *vs, const struct vb_vm_attach *va)
{
	int rc;

	if ((rc = vb_vm_attach(vs, va))) {
		printf("vb_vm_attach failed %d\n", rc);
		return (rc);
	}
	if ((rc = vb_if_attach(vs)))
		return (rc);
	if (vs->vs_flags & VS_NQS_CHANGED) {
		rc = iflib_device_reinit(vs->vs_ctx);
		if (!rc)
			vs->vs_flags &= ~VS_NQS_CHANGED;
	}
	return (rc);
}

static int
vb_detach(if_ctx_t ctx)
{
	struct vb_softc *vs = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = vs->shared;
	struct vtnet_be *vb = vs->vs_vn;
	struct ifnet *ifp = iflib_get_ifp(ctx);;
	int i;

	if (vs->vs_flags & VS_ENQUEUED) {
		VB_LOCK;
		SLIST_REMOVE(&vb->dev, vs, vb_softc, vs_next);
		VB_UNLOCK;
	}
	for (i = 0; i < vs->vs_nvqs; i++) {
		vb_vring_munmap(vs, i);
	}
	if (ifp->if_bridge)
		vpcp_port_disconnect_ifp(ifp);
	MPASS(ifp->if_bridge == NULL);
	iflib_link_state_change(vs->vs_ctx, LINK_STATE_DOWN, IF_Gbps(200));

	for (i = 0; i < scctx->isc_nrxqsets; i++)
		vb_rxq_deinit(vs, &vs->vs_rx_queues[i]);
	iflib_config_gtask_deinit(&vs->vs_deferred_uptask);
	free(vs->vs_rx_queues, M_VMNIC);
	free(vs->vs_tx_queues, M_VMNIC);
	free(vs->vs_msix, M_VMNIC);
	free(vs->vs_queues, M_VMNIC);

	return (0);
}

static int
vmnic_mtu_set(if_ctx_t ctx, uint32_t mtu)
{
	struct vb_softc *vs = iflib_get_softc(ctx);
	struct ifnet *ifp = iflib_get_ifp(ctx);

	if (vs->vs_flags & VS_IMMUTABLE)
		return (EBUSY);
	ifp->if_mtu = mtu;
	vs->vs_cfg.mtu = mtu;
	return (0);
}

static int
vmnic_mac_set(if_ctx_t ctx, const uint8_t *mac)
{
	struct vb_softc *vs = iflib_get_softc(ctx);
	struct ifnet *ifp;
	struct sockaddr_dl *sdl;

	if (vs->vs_flags & VS_IMMUTABLE)
		return (EBUSY);
	ifp = iflib_get_ifp(ctx);
	memcpy(vs->vs_origmac, mac, ETHER_ADDR_LEN);
	memcpy(vs->vs_cfg.mac, mac, ETHER_ADDR_LEN);
	sdl = (struct sockaddr_dl *)ifp->if_addr->ifa_addr;
	MPASS(sdl->sdl_type == IFT_ETHER);
	memcpy(LLADDR(sdl), vs->vs_origmac, ETHER_ADDR_LEN);
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

	for (i = 0; i < scctx->isc_nrxqsets; i++) {
		if (vs->vs_rx_queues[i].vr_sdcl) {
			for (j = 0; j < scctx->isc_nrxd[0]; j++)
				vs->vs_rx_queues[i].vr_sdcl[j] = NULL;
		}
	}
	for (i = 0; i < scctx->isc_ntxqsets; i++)
		vs->vs_tx_queues[i].vt_cidx = 0;
}

static void
vb_rx_clset(if_ctx_t ctx, uint16_t fl __unused, uint16_t qidx,
			caddr_t *sdcl)
{
	struct vb_softc *vs = iflib_get_softc(ctx);

	vs->vs_rx_queues[qidx].vr_sdcl = sdcl;
}

int
vmnic_ctl(vpc_ctx_t vctx, vpc_op_t op, size_t inlen, const void *in,
				 size_t *outlen, void **outdata)
{
	if_ctx_t ctx = vctx->v_ifp->if_softc;
	struct vb_softc *vs = iflib_get_softc(ctx);
	int rc;

	rc = 0;
	switch (op) {
		case VPC_VMNIC_OP_NQUEUES_GET: {
			uint16_t *nqsp;

			if (*outlen < sizeof(uint16_t))
				return (EOVERFLOW);
			*outlen = sizeof(uint16_t);
			nqsp = malloc(sizeof(uint16_t), M_TEMP, M_WAITOK);
			*nqsp = vs->vs_nqs;
			*outdata = nqsp;
			break;
		}
		case VPC_VMNIC_OP_NQUEUES_SET: {
			const uint16_t *nqsp = in;

			if (vs->vs_flags & VS_IMMUTABLE)
				return (EBUSY);
			if (inlen != sizeof(uint16_t))
				return (EBADRPC);
			if (*nqsp == 0)
				return (ENXIO);
			if (*nqsp > VB_QUEUES_MAX)
				return (E2BIG);
			if (vs->vs_nqs != *nqsp) {
				vs->vs_nqs = *nqsp;
				vs->vs_nvqs = (vs->vs_nqs * 2) + 1;
				vs->vs_flags |= VS_NQS_CHANGED;
			}
			break;
		}
		case VPC_VMNIC_OP_ATTACH: {
#ifdef DEVEL_BRINGUP
			iflib_set_mtu(ctx, 1500);
#else
			if (!(vs->vs_flags & VS_IMMUTABLE))
				return (EINPROGRESS);
#endif
			vs->vs_proc = curproc;
			rc = vb_vm_deferred_attach(vs, in);
			break;
		}
		case VPC_VMNIC_OP_MSIX:
			rc = vb_dev_msix(vs, (const struct vb_msix *)in, inlen);
			break;
		case VPC_VMNIC_OP_FREEZE:
			vs->vs_flags |= VS_IMMUTABLE;
			break;
		case VPC_VMNIC_OP_UNFREEZE:
			if (vs->vs_flags & VS_ATTACHED)
				return (EBUSY);
			vs->vs_flags &= ~VS_IMMUTABLE;
			break;
		default:
			rc = ENOIOCTL;
			break;
	}
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


typedef int (*ctrl_cmd_handler_t)(struct vb_softc *vs, int cmd, void *arg, int len);
static int vb_ctrl_rx(struct vb_softc *vs, int cmd, void *arg, int len) { return (ENOTSUP); }
static int vb_ctrl_mac(struct vb_softc *vs, int cmd, void *arg, int len) { return (ENOTSUP); }
static int vb_ctrl_vlan(struct vb_softc *vs, int cmd, void *arg, int len) { return (ENOTSUP); }
static int vb_ctrl_announce(struct vb_softc *vs, int cmd, void *arg, int len) { return (ENOTSUP); }
static int vb_ctrl_mq(struct vb_softc *vs, int cmd, void *arg, int len);
static int vb_ctrl_guest_offloads(struct vb_softc *vs, int cmd, void *arg, int len) { return (ENOTSUP); }
static ctrl_cmd_handler_t handlers[] = {
	vb_ctrl_rx,
	vb_ctrl_mac,
	vb_ctrl_vlan,
	vb_ctrl_announce,
	vb_ctrl_mq,
	vb_ctrl_guest_offloads
};

static int
vb_ctrl_mq(struct vb_softc *vs, int cmd, void *arg, int len)
{
	struct virtio_net_ctrl_mq *mq = arg;
	uint16_t requested;

	if (cmd != VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET) {
		printf("unexpected command %u in %s\n", cmd, __func__);
		return (EINVAL);
	}
	requested = mq->virtqueue_pairs;
	if (requested < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN ||
		requested > vs->vs_cfg.max_virtqueue_pairs) {
		printf("attempted to set bad value virtqueue_pairs=%d -- limit is 1-%d\n",
			   requested, vs->vs_cfg.max_virtqueue_pairs);
		return (EINVAL);
	}
	printf("%s cmd: %d requested: %d\n",
		   __func__, cmd, requested);
	if (requested != vs->vs_nqs) {
		vs->vs_nqs = requested;
		vs->vs_nvqs = 2*requested + 1;
		vb_dev_reset(vs);
	}
	return (0);
}

static int
vb_ctrl_cmd_dispatch(struct vb_softc *vs, struct virtio_net_ctrl_hdr *hdr, void *data, int len)
{

	if (hdr->class > VIRTIO_NET_CTRL_GUEST_OFFLOADS)
		return (EINVAL);
	return (handlers[hdr->class])(vs, hdr->cmd, data, len);
}

static void
vb_update_admin_status(if_ctx_t ctx)
{
	struct vb_softc *vs = iflib_get_softc(ctx);
	struct vb_queue *cvq = vs->vs_cvq;
	volatile struct vring_desc *desc;
	volatile struct vring_used_elem *vue;
	struct virtio_net_ctrl_hdr *hdr;
	int aidx, didx, vidx, len, rc, mask;
	uint8_t *ackp;

	/* We aren't set up yet */
	if (cvq == NULL) {
		DPRINTF("%s called - cvq not setup\n", __func__);
		return;
	}
	mask = cvq->vq_qsize-1;
	vidx = cvq->vq_used->idx;
	/* handle queue requests */
	for (aidx = cvq->vq_avail_idx; aidx != cvq->vq_avail->idx; aidx++) {
		len = 0;
		didx = cvq->vq_avail->ring[aidx];
		desc = &cvq->vq_desc[didx];
		if (desc->len != sizeof(*hdr)) {
			printf("control fail: desc->len=%d\n", desc->len);
			goto update_used;
		}
		len = desc->len;
		hdr = vb_cl_map(vs, desc);
		if (hdr == NULL || !(desc->flags & VRING_DESC_F_NEXT) ||
			desc->next >= cvq->vq_qsize) {
			printf("control fail 1) flags=%x next=%d\n", desc->flags, desc->next);
			goto update_used;
		}
		desc = &cvq->vq_desc[desc->next];
		len += desc->len;
		rc = vb_ctrl_cmd_dispatch(vs, hdr, vb_cl_map(vs, desc), desc->len);
		if (rc || !(desc->flags & VRING_DESC_F_NEXT) ||
			(desc->next >= cvq->vq_qsize)) {
			printf("control fail 2) flags=%x next=%d\n", desc->flags, desc->next);
			goto update_used;
		}
		desc = &cvq->vq_desc[desc->next];
		if ((!(desc->flags & VRING_DESC_F_WRITE)) ||
			desc->len != sizeof(uint8_t)) {
			goto update_used;
		}
		len += desc->len;
		ackp = vb_cl_map(vs, desc);
		*ackp = VIRTIO_NET_OK;
	update_used:
		vue = &cvq->vq_used->ring[vidx++ & mask];
		vue->id = didx;
		vue->len = len;
	}
/* Update used ring to reflect final state */
	wmb();
	cvq->vq_used->idx = vidx;
	cvq->vq_avail_idx = aidx;
	vb_intr_msix(vs, cvq->vq_id);
}

static void
vmnic_watchdog_reset_queue(if_ctx_t ctx, uint16_t qid)
{
	struct vb_softc *vs = iflib_get_softc(ctx);

	vb_intr_msix(vs, qid);
}

static device_method_t vb_if_methods[] = {
	DEVMETHOD(ifdi_rx_queue_intr_enable, vb_if_rxq_intr_enable),
	DEVMETHOD(ifdi_tx_queue_intr_enable, vb_if_txq_intr_enable),
	DEVMETHOD(ifdi_cloneattach, vb_cloneattach),
	DEVMETHOD(ifdi_attach_post, vb_attach_post),
	DEVMETHOD(ifdi_watchdog_reset_queue, vmnic_watchdog_reset_queue),
	DEVMETHOD(ifdi_detach, vb_detach),
	DEVMETHOD(ifdi_mtu_set, vmnic_mtu_set),
	DEVMETHOD(ifdi_mac_set, vmnic_mac_set),
	DEVMETHOD(ifdi_init, vb_init),
	DEVMETHOD(ifdi_stop, vb_stop),
	DEVMETHOD(ifdi_rx_clset, vb_rx_clset),
	DEVMETHOD(ifdi_update_admin_status, vb_update_admin_status),
	DEVMETHOD_END
};

static driver_t vb_iflib_driver = {
	"vmnic", vb_if_methods, sizeof(struct vb_softc)
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
	IFLIB_SKIP_CLREFILL | IFLIB_HAS_RXCQ | IFLIB_NO_HANG_RESET |	\
	IFLIB_VIRTUAL,

	.isc_nrxd_min = {VB_MIN_RXD, VB_MIN_RXD},
	.isc_ntxd_min = {VB_MIN_TXD},
	.isc_nrxd_max = {VB_MAX_RXD, VB_MAX_RXD},
	.isc_ntxd_max = {VB_MAX_TXD},
	.isc_nrxd_default = {VB_DEFAULT_RXD, VB_DEFAULT_RXD},
	.isc_ntxd_default = {VB_DEFAULT_TXD},
	.isc_name = "vmnic",
	.isc_rx_completion = vb_rx_completion,
};

if_shared_ctx_t vb_sctx = &vb_sctx_init;

static if_pseudo_t
vb_clone_register(void)
{
	return (iflib_clone_register(vb_sctx));
}

static int
vmnic_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
	case MOD_LOAD:
		if ((err = vmnic_module_init()) != 0)
			return (err);
		break;
	case MOD_UNLOAD:
		if (modrefcnt == 0)
			vmnic_module_deinit();
		else
			return (EBUSY);
		break;
	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t vmnic_moduledata = {
	"vmnic",
	vmnic_module_event_handler,
	NULL
};
DECLARE_MODULE(vmnic, vmnic_moduledata, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(vmnic, 1);
MODULE_DEPEND(vmnic, iflib, 1, 1, 1);
MODULE_DEPEND(vmnic, vmm, 1, 1, 1);
