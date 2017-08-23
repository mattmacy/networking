/******************************************************************************

  Copyright (c) 2001-2017, Intel Corporation
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   3. Neither the name of the Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/
/* $FreeBSD$*/


#include "opt_inet.h"
#include "opt_inet6.h"

#include "ixgbe.h"
#include "ifdi_if.h"

/************************************************************************
 * Driver version
 ************************************************************************/
char ixv_driver_version[] = "1.5.13-k";

/************************************************************************
 * PCI Device ID Table
 *
 *   Used by probe to select devices to load on
 *   Last field stores an index into ixv_strings
 *   Last entry must be all 0s
 *
 *  { Vendor ID, Device ID, SubVendor ID, SubDevice ID, String Index }
 *********************************************************************/

static pci_vendor_info_t ixv_vendor_info_array[] =
{
	PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_82599_VF, "Intel(R) PRO/10GbE Virtual Function Network Driver"),
	PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X540_VF, "Intel(R) PRO/10GbE Virtual Function Network Driver"),
	PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550_VF, "Intel(R) PRO/10GbE Virtual Function Network Driver"),
	PVID(IXGBE_INTEL_VENDOR_ID, IXGBE_DEV_ID_X550EM_X_VF, "Intel(R) PRO/10GbE Virtual Function Network Driver"),
	/* required last entry */
PVID_END
};

/*********************************************************************
 *  Function prototypes
 *********************************************************************/
static void     *ixv_register(device_t dev);
static int      ixv_if_attach_pre(if_ctx_t ctx);
static int      ixv_if_attach_post(if_ctx_t ctx);
static int      ixv_if_detach(if_ctx_t ctx);

static int      ixv_if_tx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nqs, int nqsets);
static int      ixv_if_rx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nqs, int nqsets);
static void     ixv_if_queues_free(if_ctx_t ctx);
static void     ixv_identify_hardware(if_ctx_t ctx);
static int      ixv_allocate_pci_resources(if_ctx_t ctx);
static void	ixv_free_pci_resources(if_ctx_t ctx);
static int      ixv_setup_interface(if_ctx_t ctx);
static void     ixv_if_media_status(if_ctx_t , struct ifmediareq *);
static int      ixv_if_media_change(if_ctx_t ctx); 
static void     ixv_if_update_admin_status(if_ctx_t ctx);
static int      ixv_if_msix_intr_assign(if_ctx_t ctx, int msix);

static int      ixv_if_mtu_set(if_ctx_t ctx, uint32_t mtu);
static void	ixv_if_init(if_ctx_t ctx);
static void     ixv_if_local_timer(if_ctx_t ctx, uint16_t qid);
static void     ixv_if_stop(if_ctx_t ctx);

static void     ixv_initialize_transmit_units(if_ctx_t ctx); 
static void     ixv_initialize_receive_units(if_ctx_t ctx);

static void	ixv_setup_vlan_support(if_ctx_t ctx);
static void	ixv_configure_ivars(struct adapter *);
static void     ixv_if_enable_intr(if_ctx_t ctx); 
static void     ixv_if_disable_intr(if_ctx_t ctx);
static void     ixv_if_set_multi(if_ctx_t ctx); 

static void	ixv_if_register_vlan(if_ctx_t, u16);
static void	ixv_if_unregister_vlan(if_ctx_t, u16);
static void	ixv_save_stats(struct adapter *);
static void	ixv_init_stats(struct adapter *);
static void	ixv_update_stats(struct adapter *);
static void	ixv_add_stats_sysctls(struct adapter *adapter); 

static int	ixv_sysctl_debug(SYSCTL_HANDLER_ARGS);
static void	ixv_set_ivar(struct adapter *, u8, u8, s8);

static u8 *	ixv_mc_array_itr(struct ixgbe_hw *, u8 **, u32 *);
#ifdef old
static void	ixv_set_sysctl_value(struct adapter *, const char *,
				     const char *, int *, int);
#endif

/* The MSI/X Interrupt handlers */
static int	ixv_msix_que(void *);
static int	ixv_msix_mbx(void *);

/*********************************************************************
 *  FreeBSD Device Interface Entry Points
 *********************************************************************/

/************************************************************************
 * FreeBSD Device Interface Entry Points
 ************************************************************************/
static device_method_t ixv_methods[] = {
	/* Device interface */
	DEVMETHOD(device_register, ixv_register),
	DEVMETHOD(device_probe, iflib_device_probe),
	DEVMETHOD(device_attach, iflib_device_attach),
	DEVMETHOD(device_detach, iflib_device_detach),
	DEVMETHOD(device_shutdown, iflib_device_shutdown),
	DEVMETHOD_END
};

static driver_t ixv_driver = {
	"ixv", ixv_methods, sizeof(struct adapter),
};

devclass_t ixv_devclass;
DRIVER_MODULE(ixv, pci, ixv_driver, ixv_devclass, 0, 0);
MODULE_DEPEND(ixv, pci, 1, 1, 1);
MODULE_DEPEND(ixv, ether, 1, 1, 1);

static device_method_t ixv_if_methods[] = {
	DEVMETHOD(ifdi_attach_pre, ixv_if_attach_pre),
	DEVMETHOD(ifdi_attach_post, ixv_if_attach_post),
	DEVMETHOD(ifdi_tx_queues_alloc, ixv_if_tx_queues_alloc),
	DEVMETHOD(ifdi_rx_queues_alloc, ixv_if_rx_queues_alloc),
	DEVMETHOD(ifdi_queues_free, ixv_if_queues_free),
	DEVMETHOD(ifdi_detach, ixv_if_detach),
	DEVMETHOD(ifdi_media_status, ixv_if_media_status),
        DEVMETHOD(ifdi_media_change, ixv_if_media_change),
        DEVMETHOD(ifdi_update_admin_status, ixv_if_update_admin_status),
        DEVMETHOD(ifdi_mtu_set, ixv_if_mtu_set),
	DEVMETHOD(ifdi_init, ixv_if_init),
	DEVMETHOD(ifdi_multi_set, ixv_if_set_multi), 
	DEVMETHOD(ifdi_timer, ixv_if_local_timer), 
	DEVMETHOD(ifdi_stop, ixv_if_stop),
	DEVMETHOD(ifdi_msix_intr_assign, ixv_if_msix_intr_assign),
	DEVMETHOD(ifdi_intr_enable, ixv_if_enable_intr),
	DEVMETHOD(ifdi_intr_disable, ixv_if_disable_intr),
	DEVMETHOD(ifdi_vlan_register, ixv_if_register_vlan),
	DEVMETHOD(ifdi_vlan_unregister, ixv_if_unregister_vlan),
	DEVMETHOD_END
};

static driver_t ixv_if_driver = {
  "ixv_if", ixv_if_methods, sizeof(struct adapter)
};

/*
 * TUNEABLE PARAMETERS:
 */

/*
 * AIM: Adaptive Interrupt Moderation
 * which means that the interrupt rate
 * is varied over time based on the
 * traffic for that interrupt vector
 */
static int ixv_enable_aim = FALSE;
TUNABLE_INT("hw.ixv.enable_aim", &ixv_enable_aim);

/* How many packets rxeof tries to clean at a time */
static int ixv_rx_process_limit = 256;
TUNABLE_INT("hw.ixv.rx_process_limit", &ixv_rx_process_limit);

/* Flow control setting, default to full */
static int ixv_flow_control = ixgbe_fc_full;
TUNABLE_INT("hw.ixv.flow_control", &ixv_flow_control);

/*
 * Header split: this causes the hardware to DMA
 * the header into a separate mbuf from the payload,
 * it can be a performance win in some workloads, but
 * in others it actually hurts, its off by default.
 */
static int ixv_header_split = FALSE;
TUNABLE_INT("hw.ixv.hdr_split", &ixv_header_split);

/*
 * Number of TX descriptors per ring,
 * setting higher than RX as this seems
 * the better performing choice.
 */
static int ixv_txd = DEFAULT_TXD;
TUNABLE_INT("hw.ixv.txd", &ixv_txd);

/* Number of RX descriptors per ring */
static int ixv_rxd = DEFAULT_RXD;
TUNABLE_INT("hw.ixv.rxd", &ixv_rxd);

/*
 * Shadow VFTA table, this is needed because
 * the real filter table gets cleared during
 * a soft reset and we need to repopulate it.
 */
static u32 ixv_shadow_vfta[IXGBE_VFTA_SIZE];
extern struct if_txrx ixgbe_txrx; 

static struct if_shared_ctx ixv_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_q_align = PAGE_SIZE,/* max(DBA_ALIGN, PAGE_SIZE) */
	.isc_tx_maxsize = IXGBE_TSO_SIZE,

	.isc_tx_maxsegsize = PAGE_SIZE*4,

	.isc_rx_maxsize = PAGE_SIZE*4,
	.isc_rx_nsegments = 1,
	.isc_rx_maxsegsize = PAGE_SIZE*4,
	.isc_nfl = 1,
	.isc_ntxqs = 1,
	.isc_nrxqs = 1,
	.isc_admin_intrcnt = 1,
	.isc_vendor_info = ixv_vendor_info_array,
	.isc_driver_version = ixv_driver_version,
	.isc_driver = &ixv_if_driver,
};

if_shared_ctx_t ixv_sctx = &ixv_sctx_init;

static void *
ixv_register(device_t dev)
{
	
	return (ixv_sctx);
}

static int
ixv_if_tx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int ntxqs, int ntxqsets)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	struct ix_tx_queue *que;
	int i, error;

#ifdef PCI_IOV
	enum ixgbe_iov_mode iov_mode;
#endif
	MPASS(adapter->num_tx_queues == ntxqsets);
	MPASS(ntxqs == 1);

	/* Allocate queue structure memory */
	if (!(adapter->tx_queues =
	      (struct ix_tx_queue *) malloc(sizeof(struct ix_tx_queue) * ntxqsets,
					    M_DEVBUF, M_NOWAIT | M_ZERO))) {
	  device_printf(iflib_get_dev(ctx), "Unable to allocate TX ring memory\n");
	  return (ENOMEM);
	}

#ifdef PCI_IOV
	iov_mode = ixgbe_get_iov_mode(adapter);
	adapter->pool = ixgbe_max_vfs(iov_mode);
#else
	adapter->pool = 0;
#endif

	for (i = 0, que = adapter->tx_queues; i < ntxqsets; i++, que++) {
		struct tx_ring		*txr = &que->txr;

		if (!(txr->tx_rsq = (qidx_t *) malloc(sizeof(qidx_t) * scctx->isc_ntxd[0], M_DEVBUF, M_NOWAIT | M_ZERO))) {
			device_printf(iflib_get_dev(ctx), "failed to allocate qidx memory\n");
			error = ENOMEM;
			goto fail;
		}
#ifdef PCI_IOV
	        txr->me = ixgbe_pf_que_index(iov_mode, i);
#else
		txr->me = i;
#endif
		txr->adapter =  que->adapter = adapter;
		adapter->active_queues |= (u64)1 << txr->me;

		/* get the virtual and physical address of the hardware queues */
		txr->tail = IXGBE_TDT(txr->me);
		txr->tx_base = (union ixgbe_adv_tx_desc *)vaddrs[i];
		txr->tx_paddr = paddrs[i];
		txr->bytes = 0;
		txr->total_packets = 0;

#ifdef IXGBE_FDIR
	/* Set the rate at which we sample packets */
	if (adapter->hw.mac.type != ixgbe_mac_82598EB)
		txr->atr_sample = atr_sample_rate;
#endif

	}

	device_printf(iflib_get_dev(ctx), "allocated for %d queues\n", adapter->num_tx_queues);
	return (0);

 fail:
	ixv_if_queues_free(ctx);
	return (error);
}

static int
ixv_if_rx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nrxqs, int nrxqsets)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	struct ix_rx_queue *que;
	int i, error;

#ifdef PCI_IOV
	enum ixgbe_iov_mode iov_mode;
#endif
	MPASS(adapter->num_rx_queues == nrxqsets);
	MPASS(nrxqs == 1);

	/* Allocate queue structure memory */
	if (!(adapter->rx_queues =
	      (struct ix_rx_queue *) malloc(sizeof(struct ix_rx_queue) *nrxqsets,
					  M_DEVBUF, M_NOWAIT | M_ZERO))) {
	  device_printf(iflib_get_dev(ctx), "Unable to allocate TX ring memory\n");
	  return (ENOMEM);
	}

#ifdef PCI_IOV
	iov_mode = ixgbe_get_iov_mode(adapter);
	adapter->pool = ixgbe_max_vfs(iov_mode);
#else
	adapter->pool = 0;
#endif

	for (i = 0, que = adapter->rx_queues; i < nrxqsets; i++, que++) {
		struct rx_ring 		*rxr = &que->rxr;
#ifdef PCI_IOV
	        rxr->me = ixgbe_pf_que_index(iov_mode, i);
#else
		rxr->me = i;
#endif
		rxr->adapter = que->adapter = adapter;


		/* get the virtual and physical address of the hardware queues */

		rxr->tail = IXGBE_RDT(rxr->me);
		rxr->rx_base = (union ixgbe_adv_rx_desc *)vaddrs[i];
		rxr->rx_paddr = paddrs[i];
		rxr->bytes = 0;
		rxr->que = que;
	}

	device_printf(iflib_get_dev(ctx), "allocated for %d rx queues\n", adapter->num_rx_queues);
	return (0);

	ixv_if_queues_free(ctx);
	return (error);
}

static void
ixv_if_queues_free(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	struct ix_tx_queue *que = adapter->tx_queues;
        int i;

	if (que == NULL)
		goto free;

        for (i = 0; i < adapter->num_tx_queues; i++, que++) {
		struct tx_ring		*txr = &que->txr;
		if (txr->tx_rsq == NULL)
		  break;

		free(txr->tx_rsq, M_DEVBUF);
		txr->tx_rsq = NULL;
	}
	if (adapter->tx_queues != NULL)
		free(adapter->tx_queues, M_DEVBUF);
free:
	if (adapter->rx_queues != NULL)
		free(adapter->rx_queues, M_DEVBUF);
	adapter->tx_queues = NULL;
	adapter->rx_queues = NULL;
}

/************************************************************************
 * ixv_attach - Device initialization routine
 *
 *   Called when the driver is being loaded.
 *   Identifies the type of hardware, allocates all resources
 *   and initializes the hardware.
 *
 *   return 0 on success, positive on failure
 ************************************************************************/
static int
ixv_if_attach_pre(if_ctx_t ctx)
{
	device_t dev; 
	struct adapter *adapter;
	if_softc_ctx_t scctx;
	struct ixgbe_hw *hw;
	int             error = 0;

	INIT_DEBUGOUT("ixv_attach: begin");
	dev = iflib_get_dev(ctx); 

	/*
	 * Make sure BUSMASTER is set, on a VM under
	 * KVM it may not be and will break things.
	 */
	pci_enable_busmaster(dev);

	/* Allocate, clear, and link in our adapter structure */
	adapter = iflib_get_softc(ctx);
	adapter->dev = dev; 
	adapter->ctx = ctx;
	scctx = adapter->shared = iflib_get_softc_ctx(ctx);
	adapter->media = iflib_get_media(ctx);
	hw = &adapter->hw;

	/* SYSCTL APIs */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)), OID_AUTO, "debug",
	    CTLTYPE_INT | CTLFLAG_RW, adapter, 0, ixv_sysctl_debug, "I",
	    "Debug Info");

	SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)), OID_AUTO,
	    "enable_aim", CTLFLAG_RW, &ixv_enable_aim, 1,
	    "Interrupt Moderation");

	/* Determine hardware revision */
	ixv_identify_hardware(ctx);
	adapter->shared->isc_tx_nsegments = IXGBE_82599_SCATTER;

	/* Do base PCI setup - map BAR0 */
	if (ixv_allocate_pci_resources(ctx)) {
		device_printf(dev, "ixv_allocate_pci_resources() failed!\n");
		error = ENXIO;
		goto err;
	}

	/* Setup the mailbox */
	ixgbe_init_mbx_params_vf(hw);

	/* Set the right number of segments */
	adapter->num_segs = IXGBE_82599_SCATTER;

	error = hw->mac.ops.reset_hw(hw);
	if (error == IXGBE_ERR_RESET_FAILED)
		device_printf(dev, "...reset_hw() failure: Reset Failed!\n");
	else if (error)
		device_printf(dev, "...reset_hw() failed with error %d\n",
		    error);
	if (error) {
		error = EIO;
		goto err_out;
	}

	error = hw->mac.ops.init_hw(hw);
	if (error) {
		device_printf(dev, "...init_hw() failed with error %d\n",
		    error);
		error = EIO;
		goto err_out;
	}

	/* Negotiate mailbox API version */
	error = ixgbevf_negotiate_api_version(hw, ixgbe_mbox_api_12);
	if (error) {
		device_printf(dev, "MBX API 1.2 negotiation failed! Error %d\n",
		    error);
		error = EIO;
		goto err_out;
	}

	/* If no mac address was assigned, make a random one */
	if (!ixv_check_ether_addr(hw->mac.addr)) {
		u8 addr[ETHER_ADDR_LEN];
		arc4rand(&addr, sizeof(addr), 0);
		addr[0] &= 0xFE;
		addr[0] |= 0x02;
		bcopy(addr, hw->mac.addr, sizeof(addr));
		bcopy(addr, hw->mac.perm_addr, sizeof(addr));
	}

	if (scctx->isc_ntxd[0] == 0)
		scctx->isc_ntxd[0] = DEFAULT_TXD;
	if (scctx->isc_nrxd[0] == 0)
		scctx->isc_nrxd[0] = DEFAULT_RXD;
	if (scctx->isc_nrxd[0] < MIN_RXD || scctx->isc_nrxd[0] > MAX_RXD) {
		device_printf(dev, "nrxd: %d not within permitted range of %d-%d setting to default value: %d\n",
			      scctx->isc_nrxd[0], MIN_RXD, MAX_RXD, DEFAULT_RXD);
		scctx->isc_nrxd[0] = DEFAULT_RXD;
	}
	if (scctx->isc_ntxd[0] < MIN_TXD || scctx->isc_ntxd[0] > MAX_TXD) {
		device_printf(dev, "ntxd: %d not within permitted range of %d-%d setting to default value: %d\n",
			      scctx->isc_ntxd[0], MIN_TXD, MAX_TXD, DEFAULT_TXD);
		scctx->isc_ntxd[0] = DEFAULT_TXD;
	}
	scctx->isc_txqsizes[0] = roundup2(scctx->isc_ntxd[0] * sizeof(union ixgbe_adv_tx_desc) +
							  sizeof(u32), DBA_ALIGN),
	scctx->isc_rxqsizes[0] = roundup2(scctx->isc_nrxd[0] * sizeof(union ixgbe_adv_rx_desc), DBA_ALIGN);

	scctx->isc_txrx = &ixgbe_txrx;
	/*
	** Initialize the shared code: its
	** at this point the mac type is set.
	*/
	error = ixgbe_init_shared_code(hw);
	if (error) {
		device_printf(dev, "ixgbe_init_shared_code() failed!\n");
		error = EIO;
		goto err;
	}

	/* Setup the mailbox */
	ixgbe_init_mbx_params_vf(hw);

	/* Reset mbox api to 1.0 */
	error = ixgbe_reset_hw(hw);
	if (error == IXGBE_ERR_RESET_FAILED)
		device_printf(dev, "ixgbe_reset_hw() failure: Reset Failed!\n");
	else if (error)
		device_printf(dev, "ixgbe_reset_hw() failed with error %d\n", error);
	if (error) {
		error = EIO;
		goto err;
	}

	/* Negotiate mailbox API version */
	error = ixgbevf_negotiate_api_version(hw, ixgbe_mbox_api_11);
	if (error) {
		device_printf(dev, "MBX API 1.1 negotiation failed! Error %d\n", error);
		error = EIO;
		goto err;
	}

	error = ixgbe_init_hw(hw);
	if (error) {
		device_printf(dev, "ixgbe_init_hw() failed!\n");
		error = EIO;
		goto err;
	}
	
	/* If no mac address was assigned, make a random one */
	if (!ixv_check_ether_addr(hw->mac.addr)) {
		u8 addr[ETHER_ADDR_LEN];
		arc4rand(&addr, sizeof(addr), 0);
		addr[0] &= 0xFE;
		addr[0] |= 0x02;
		bcopy(addr, hw->mac.addr, sizeof(addr));
	}

	INIT_DEBUGOUT("ixv_attach: end");
	return (0);

err_out:
err:
	ixv_free_pci_resources(ctx);
	return (error);

}

static int
ixv_if_attach_post(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx);
        device_t dev = iflib_get_dev(ctx); 
        int error = 0; 
	
    	/* Setup OS specific network interface */
	error = ixv_setup_interface(ctx); 
	if (error) {
		device_printf(dev, "Interface setup failed: %d\n", error);
		goto end;
	}
	
	/* Do the stats setup */
	ixv_save_stats(adapter);
	ixv_init_stats(adapter);
	ixv_add_stats_sysctls(adapter);

	INIT_DEBUGOUT("ixv_attachpost: end");

end:
	return error; 
}

static int
ixv_allocate_pci_resources(if_ctx_t ctx)
{
	int             rid;
	struct adapter *adapter = iflib_get_softc(ctx);
	device_t        dev = iflib_get_dev(ctx);

	rid = PCIR_BAR(0);
	adapter->pci_mem = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
						  &rid, RF_ACTIVE);

	if (!(adapter->pci_mem)) {
		device_printf(dev,"Unable to allocate bus resource: memory\n");
		return (ENXIO);
	}

	adapter->osdep.mem_bus_space_tag =
		rman_get_bustag(adapter->pci_mem);
	adapter->osdep.mem_bus_space_handle =
		rman_get_bushandle(adapter->pci_mem);
	adapter->hw.hw_addr = (u8 *) &adapter->osdep.mem_bus_space_handle;
	adapter->hw.back = adapter;
	return (0);
}

/************************************************************************
 * ixv_detach - Device removal routine
 *
 *   Called when the driver is being removed.
 *   Stops the adapter and deallocates all the resources
 *   that were allocated for driver operation.
 *
 *   return 0 on success, positive on failure
 ************************************************************************/
static int
ixv_if_detach(if_ctx_t ctx)
{
	INIT_DEBUGOUT("ixv_detach: begin");

	ixv_free_pci_resources(ctx); 

	return (0);
} /* ixv_detach */

static int
ixv_if_mtu_set(if_ctx_t ctx, uint32_t mtu)
{
	struct adapter *adapter = iflib_get_softc(ctx);
        struct ifnet *ifp = iflib_get_ifp(ctx);
	int error = 0; 
	
	IOCTL_DEBUGOUT("ioctl: SIOCSIFMTU (Set Interface MTU)");
	if (mtu > IXGBE_MAX_FRAME_SIZE - IXGBE_MTU_HDR) {
			error = EINVAL;
	} else {
		ifp->if_mtu = mtu;
		adapter->max_frame_size =
			ifp->if_mtu + IXGBE_MTU_HDR;
	}
	return error; 
}

/*********************************************************************
 *  Init entry point
 *
 *  This routine is used in two ways. It is used by the stack as
 *  init entry point in network interface structure. It is also used
 *  by the driver as a hw/sw initialization routine to get to a
 *  consistent state.
 *
 *  return 0 on success, positive on failure
 **********************************************************************/
#define IXGBE_MHADD_MFS_SHIFT 16

static void
ixv_if_init(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx); 
	struct ifnet	*ifp = iflib_get_ifp(ctx); 
	device_t 	dev = iflib_get_dev(ctx); 
	struct ixgbe_hw *hw = &adapter->hw;
	int error = 0;

	INIT_DEBUGOUT("ixv_init: begin");
	hw->adapter_stopped = FALSE;

        /* reprogram the RAR[0] in case user changed it. */
        ixgbe_set_rar(hw, 0, hw->mac.addr, 0, IXGBE_RAH_AV);

	/* Get the latest mac address, User can use a LAA */
	bcopy(IF_LLADDR(adapter->ifp), hw->mac.addr,
	     IXGBE_ETH_LENGTH_OF_ADDRESS);
        ixgbe_set_rar(hw, 0, hw->mac.addr, 0, 1);
	hw->addr_ctrl.rar_used_count = 1;

	/* Reset VF and renegotiate mailbox API version */
	ixgbe_reset_hw(hw);
	error = ixgbevf_negotiate_api_version(hw, ixgbe_mbox_api_11);
	if (error)
		device_printf(dev, "MBX API 1.1 negotiation failed! Error %d\n", error);

	ixv_initialize_transmit_units(ctx);

	/* Setup Multicast table */
	ixv_if_set_multi(ctx);

	/*
	** Determine the correct mbuf pool
	** for doing jumbo/headersplit
	*/
	if (ifp->if_mtu > ETHERMTU)
		adapter->rx_mbuf_sz = MJUMPAGESIZE;
	else
		adapter->rx_mbuf_sz = MCLBYTES;

	/* Configure RX settings */
	ixv_initialize_receive_units(ctx);

	/* Set the various hardware offload abilities */
	ifp->if_hwassist = 0;
	if (ifp->if_capenable & IFCAP_TSO4)
		ifp->if_hwassist |= CSUM_TSO;
	if (ifp->if_capenable & IFCAP_TXCSUM) {
		ifp->if_hwassist |= (CSUM_TCP | CSUM_UDP);
#if __FreeBSD_version >= 800000
		ifp->if_hwassist |= CSUM_SCTP;
#endif
	}
	/* Set up VLAN offload and filter */
	ixv_setup_vlan_support(ctx); 

	/* Set up MSI-X routing */
	ixv_configure_ivars(adapter);

	/* Set up auto-mask */
	IXGBE_WRITE_REG(hw, IXGBE_VTEIAM, IXGBE_EICS_RTX_QUEUE);

	/* Set moderation on the Link interrupt */
	IXGBE_WRITE_REG(hw, IXGBE_VTEITR(adapter->vector), IXGBE_LINK_ITR);

	/* Stats init */
	ixv_init_stats(adapter);

}

/*
 * MSI-X Interrupt Handlers and Tasklets
 */

static inline void
ixv_enable_queue(struct adapter *adapter, u32 vector)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32             queue = 1 << vector;
	u32             mask;

	mask = (IXGBE_EIMS_RTX_QUEUE & queue);
	IXGBE_WRITE_REG(hw, IXGBE_VTEIMS, mask);
} /* ixv_enable_queue */

static inline void
ixv_disable_queue(struct adapter *adapter, u32 vector)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u64             queue = (u64)(1 << vector);
	u32             mask;

	mask = (IXGBE_EIMS_RTX_QUEUE & queue);
	IXGBE_WRITE_REG(hw, IXGBE_VTEIMC, mask);
} /* ixv_disable_queue */

static inline void
ixv_rearm_queues(struct adapter *adapter, u64 queues)
{
	u32 mask = (IXGBE_EIMS_RTX_QUEUE & queues);
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_VTEICS, mask);
}


/*********************************************************************
 *
 *  MSI Queue Interrupt Service routine
 *
 **********************************************************************/
static int
ixv_msix_que(void *arg)
{
	struct ix_rx_queue	*que = arg;
	struct adapter  *adapter = que->adapter;
	struct rx_ring	*rxr = &que->rxr;
	u32		newitr = 0;
#ifdef notyet
	struct tx_ring	*txr = &que->txr;
#endif
	
	ixv_disable_queue(adapter, que->msix);
	++que->irqs;

	/* Do AIM now? */

	if (ixv_enable_aim == FALSE)
		goto no_calc;
	/*
	 * Do Adaptive Interrupt Moderation:
	 *  - Write out last calculated setting
	 *  - Calculate based on average size over
	 *    the last interval.
	 */
	if (que->eitr_setting)
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_VTEITR(que->msix),
		    que->eitr_setting);

#ifdef notyet                                
	if ((txr->bytes) && (txr->packets))
               	newitr = txr->bytes/txr->packets;
#endif
	if (rxr->bytes == 0)
		goto no_calc;

	if ((rxr->bytes) && (rxr->packets))
		newitr = max(newitr, (rxr->bytes / rxr->packets));
	newitr += 24; /* account for hardware frame, crc */

	/* set an upper boundary */
	newitr = min(newitr, 3000);

	/* Be nice to the mid range */
	if ((newitr > 300) && (newitr < 1200))
		newitr = (newitr / 3);
	else
		newitr = (newitr / 2);

	newitr |= newitr << 16;

#if 0
        /* Reset state */
        txr->bytes = 0;
        txr->packets = 0;
#endif	
        rxr->bytes = 0;
        rxr->packets = 0;

no_calc:
	return (FILTER_SCHEDULE_THREAD); 
}

static int
ixv_msix_mbx(void *arg)
{
	struct adapter  *adapter = arg;
	struct ixgbe_hw *hw = &adapter->hw;
	u32             reg;

	++adapter->link_irq;

	/* First get the cause */
	reg = IXGBE_READ_REG(hw, IXGBE_VTEICS);
	/* Clear interrupt with write */
	IXGBE_WRITE_REG(hw, IXGBE_VTEICR, reg);

	/* Link status change */
	if (reg & IXGBE_EICR_LSC)
		iflib_admin_intr_deferred(adapter->ctx); 

	IXGBE_WRITE_REG(hw, IXGBE_VTEIMS, IXGBE_EIMS_OTHER);
	return (FILTER_HANDLED); 
}

/************************************************************************
 * ixv_media_status - Media Ioctl callback
 *
 *   Called whenever the user queries the status of
 *   the interface using ifconfig.
 ************************************************************************/
static void
ixv_if_media_status(if_ctx_t ctx, struct ifmediareq * ifmr)
{
	struct adapter *adapter = iflib_get_softc(ctx); 

	INIT_DEBUGOUT("ixv_media_status: begin");
        ixv_if_update_admin_status(ctx); 

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (!adapter->link_active) {
		return;
	}

	ifmr->ifm_status |= IFM_ACTIVE;

	switch (adapter->link_speed) {
		case IXGBE_LINK_SPEED_1GB_FULL:
			ifmr->ifm_active |= IFM_1000_T | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_10GB_FULL:
			ifmr->ifm_active |= IFM_10G_T | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_100_FULL:
			ifmr->ifm_active |= IFM_100_TX | IFM_FDX;
			break;
		case IXGBE_LINK_SPEED_10_FULL:
			ifmr->ifm_active |= IFM_10_T | IFM_FDX;
			break;
	}
} /* ixv_media_status */

/************************************************************************
 * ixv_media_change - Media Ioctl callback
 *
 *   Called when the user changes speed/duplex using
 *   media/mediopt option with ifconfig.
 ************************************************************************/
static int
ixv_if_media_change(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx); 
	struct ifmedia *ifm = adapter->media;

	INIT_DEBUGOUT("ixv_media_change: begin");

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
		return (EINVAL);

	switch (IFM_SUBTYPE(ifm->ifm_media)) {
	case IFM_AUTO:
		break;
	default:
		device_printf(adapter->dev, "Only auto media type\n");
		return (EINVAL);
	}

	return (0);
} /* ixv_media_change */


/************************************************************************
 * ixv_set_multi - Multicast Update
 *
 *   Called whenever multicast address list is updated.
 ************************************************************************/
static void
ixv_if_set_multi(if_ctx_t ctx) 
{
	struct adapter *adapter = iflib_get_softc(ctx);
	if_t ifp = iflib_get_ifp(ctx);
	u8	mta[MAX_NUM_MULTICAST_ADDRESSES * IXGBE_ETH_LENGTH_OF_ADDRESS];
	u8	*update_ptr;
	struct	ifmultiaddr *ifma;
	int	mcnt = 0;

	IOCTL_DEBUGOUT("ixv_set_multi: begin");

	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != AF_LINK)
			continue;
		bcopy(LLADDR((struct sockaddr_dl *)ifma->ifma_addr),
		    &mta[mcnt * IXGBE_ETH_LENGTH_OF_ADDRESS],
		    IXGBE_ETH_LENGTH_OF_ADDRESS);
		mcnt++;
	}

	update_ptr = mta;

	adapter->hw.mac.ops.update_mc_addr_list(&adapter->hw, update_ptr, mcnt,
	    ixv_mc_array_itr, TRUE);
} /* ixv_set_multi */

/************************************************************************
 * ixv_mc_array_itr
 *
 *   An iterator function needed by the multicast shared code.
 *   It feeds the shared code routine the addresses in the
 *   array of ixv_set_multi() one by one.
 ************************************************************************/
static u8 *
ixv_mc_array_itr(struct ixgbe_hw *hw, u8 **update_ptr, u32 *vmdq)
{
	u8 *addr = *update_ptr;
	u8 *newptr;
	*vmdq = 0;

	newptr = addr + IXGBE_ETH_LENGTH_OF_ADDRESS;
	*update_ptr = newptr;

	return addr;
} /* ixv_mc_array_itr */

/************************************************************************
 * ixv_local_timer - Timer routine
 *
 *   Checks for link status, updates statistics,
 *   and runs the watchdog check.
 ************************************************************************/
static void
ixv_if_local_timer(if_ctx_t ctx, uint16_t qid)
{
	struct adapter	*adapter = iflib_get_softc(ctx); 
	struct ix_tx_queue	*que = &adapter->tx_queues[qid]; 
	u64		queues = 0;

        ixv_if_update_admin_status(ctx); 
	
	/* Stats Update */
	ixv_update_stats(adapter);

	/* Keep track of queues with work for soft irq */
	if (que->txr.busy)
		queues |= ((u64)1 << que->txr.me);

	if (que->txr.busy == IXGBE_QUEUE_HUNG) {
		/* Mark the queue as inactive */
		adapter->active_queues &= ~((u64)1 << que->txr.me);
	} else {
		/* Check if we've come back from hung */
		if ((adapter->active_queues & ((u64)1 << que->txr.me)) == 0)
			adapter->active_queues |= ((u64)1 << que->txr.me);
	}
	if (que->txr.busy >= IXGBE_MAX_TX_BUSY) {
		que->txr.busy = IXGBE_QUEUE_HUNG;
	}

	if (queues != 0) { /* Force an IRQ on queues with work */
		ixv_rearm_queues(adapter, queues);
	}
}

/************************************************************************
 * ixv_update_link_status - Update OS on link state
 *
 * Note: Only updates the OS on the cached link state.
 *       The real check of the hardware only happens with
 *       a link interrupt.
 ************************************************************************/
static void
ixv_if_update_admin_status(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx); 
	device_t dev = iflib_get_dev(ctx); 

	if (adapter->link_up) {
		if (adapter->link_active == FALSE) {
			if (bootverbose)
				device_printf(dev,"Link is up %d Gbps %s \n",
				    ((adapter->link_speed == 128) ? 10 : 1),
				    "Full Duplex");
			adapter->link_active = TRUE;
			iflib_link_state_change(ctx, LINK_STATE_UP,  IF_Gbps(10));
		}
	} else { /* Link down */
		if (adapter->link_active == TRUE) {
			if (bootverbose)
				device_printf(dev,"Link is Down\n");
			iflib_link_state_change(ctx, LINK_STATE_DOWN,  0);
			adapter->link_active = FALSE;
		}
	}
} /* ixv_update_link_status */


/************************************************************************
 * ixv_stop - Stop the hardware
 *
 *   Disables all traffic on the adapter by issuing a
 *   global reset on the MAC and deallocates TX/RX buffers.
 ************************************************************************/
static void
ixv_if_stop(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx); 
	struct ixgbe_hw *hw = &adapter->hw;

	INIT_DEBUGOUT("ixv_stop: begin\n");

	hw->mac.ops.reset_hw(hw);
	adapter->hw.adapter_stopped = FALSE;
	ixgbe_stop_adapter(hw);

	/* reprogram the RAR[0] in case user changed it. */
	hw->mac.ops.set_rar(hw, 0, hw->mac.addr, 0, IXGBE_RAH_AV);
} /* ixv_stop */


/*********************************************************************
 *
 *  Determine hardware revision.
 *
 **********************************************************************/
static void
ixv_identify_hardware(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx); 
	device_t        dev = iflib_get_dev(ctx); 
	struct ixgbe_hw *hw = &adapter->hw;

	/* Save off the information about this board */
	hw->vendor_id = pci_get_vendor(dev);
	hw->device_id = pci_get_device(dev);
	hw->revision_id = pci_read_config(dev, PCIR_REVID, 1);
	hw->subsystem_vendor_id =
	    pci_read_config(dev, PCIR_SUBVEND_0, 2);
	hw->subsystem_device_id =
	    pci_read_config(dev, PCIR_SUBDEV_0, 2);

	adapter->osdep.mem_bus_space_tag = rman_get_bustag(adapter->pci_mem);
	adapter->osdep.mem_bus_space_handle =
	    rman_get_bushandle(adapter->pci_mem);
	adapter->hw.hw_addr = (u8 *)&adapter->osdep.mem_bus_space_handle;
}

/*********************************************************************
 *
 *  Setup MSIX Interrupt resources and handlers 
 *
 **********************************************************************/
static int
ixv_if_msix_intr_assign(if_ctx_t ctx, int msix)
{
	struct adapter *adapter = iflib_get_softc(ctx); 
	device_t	dev = iflib_get_dev(ctx); 
	struct 		ix_rx_queue *que = adapter->rx_queues;
	struct 		ix_tx_queue *tx_que = adapter->tx_queues;
	int 		error, rid, vector = 0;
	char buf[16]; 

	/* Admin Que is vector 0*/
	rid = vector + 1;
	for (int i = 0; i < adapter->num_rx_queues; i++, vector++, que++) {
		rid = vector + 1;

		snprintf(buf, sizeof(buf), "rxq%d", i);
		error = iflib_irq_alloc_generic(ctx, &que->que_irq, rid, IFLIB_INTR_RX,
										ixv_msix_que, que, que->rxr.me, buf);

		if (error) {
			device_printf(iflib_get_dev(ctx), "Failed to allocate que int %d err: %d", i, error);
			adapter->num_rx_queues = i + 1;
			goto fail;
		}

		que->msix = vector;
        	adapter->active_queues |= (u64)(1 << que->msix);

	}

	for (int i = 0; i < adapter->num_tx_queues; i++, tx_que++) {	
		snprintf(buf, sizeof(buf), "txq%d", i);
		iflib_softirq_alloc_generic(ctx, i + 1, IFLIB_INTR_TX, tx_que, tx_que->txr.me, buf);
	}
	rid = vector + 1;
	error = iflib_irq_alloc_generic(ctx, &adapter->irq, rid, IFLIB_INTR_ADMIN,
						ixv_msix_mbx, adapter, 0, "aq");
	if (error) {
		device_printf(iflib_get_dev(ctx), "Failed to register admin handler");
		return (error);
	}

	adapter->vector = vector;
	/*
	** Due to a broken design QEMU will fail to properly
	** enable the guest for MSIX unless the vectors in
	** the table are all set up, so we must rewrite the
	** ENABLE in the MSIX control register again at this
	** point to cause it to successfully initialize us.
	*/
	if (adapter->hw.mac.type == ixgbe_mac_82599_vf) {
		int msix_ctrl;
		pci_find_cap(dev, PCIY_MSIX, &rid);
		rid += PCIR_MSIX_CTRL;
		msix_ctrl = pci_read_config(dev, rid, 2);
		msix_ctrl |= PCIM_MSIXCTRL_MSIX_ENABLE;
		pci_write_config(dev, rid, msix_ctrl, 2);
	}

	return (0);

fail:
	iflib_irq_free(ctx, &adapter->irq);
	que = adapter->rx_queues;
	for (int i = 0; i < adapter->num_rx_queues; i++, que++)
		iflib_irq_free(ctx, &que->que_irq);
	return (error); 
}

static void
ixv_free_pci_resources(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx); 
	struct 		ix_rx_queue *que = adapter->rx_queues;
	device_t	dev = iflib_get_dev(ctx); 

/* Release all msix queue resources */
	if (adapter->intr_type == IFLIB_INTR_MSIX)
		iflib_irq_free(ctx, &adapter->irq);

	for (int i = 0; i < adapter->num_rx_queues; i++, que++) {
		iflib_irq_free(ctx, &que->que_irq);
	}

	/* Clean the Legacy or Link interrupt last */
	if (adapter->pci_mem != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY,
				     PCIR_BAR(0), adapter->pci_mem);
}

/************************************************************************
 * ixv_setup_interface
 *
 *  Setup networking device structure and register an interface.
 *
 **********************************************************************/
static int
ixv_setup_interface(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	struct ifnet   *ifp = iflib_get_ifp(ctx);
        uint64_t cap = 0; 
	
	INIT_DEBUGOUT("ixv_setup_interface: begin");

	if_setbaudrate(ifp, 1000000000);
	ifp->if_snd.ifq_maxlen = scctx->isc_ntxd[0] - 2;

	adapter->max_frame_size = ifp->if_mtu + IXGBE_MTU_HDR;

	/*
	 * Tell the upper layer(s) we support long frames.
	 */

	cap |= IFCAP_HWCSUM | IFCAP_TSO4 | IFCAP_VLAN_HWCSUM;
	cap |= IFCAP_JUMBO_MTU;
	cap |= IFCAP_VLAN_HWTAGGING  |  IFCAP_VLAN_HWTSO  |  IFCAP_VLAN_MTU;
	cap |= IFCAP_LRO;

	if_setifheaderlen(ifp, sizeof(struct ether_vlan_header));
	if_setcapabilitiesbit(ifp, cap, 0);
	if_setcapenable(ifp, if_getcapabilities(ifp));
	

	ifmedia_set(adapter->media, IFM_ETHER | IFM_AUTO);
	return 0;
}

/************************************************************************
 * ixv_initialize_transmit_units - Enable transmit unit.
 ************************************************************************/
static void
ixv_initialize_transmit_units(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	struct ix_tx_queue *que = adapter->tx_queues;
	struct ixgbe_hw	*hw = &adapter->hw;
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++, que++) {
		struct tx_ring *txr = &que->txr; 
		u64	tdba = txr->tx_paddr;
		u32	txctrl, txdctl;
		int     j = txr->me; 

		/* Set WTHRESH to 8, burst writeback */
		txdctl = IXGBE_READ_REG(hw, IXGBE_VFTXDCTL(j));
		txdctl |= (8 << 16);
		IXGBE_WRITE_REG(hw, IXGBE_VFTXDCTL(j), txdctl);

		/* Set the HW Tx Head and Tail indices */
	    	IXGBE_WRITE_REG(&adapter->hw, IXGBE_VFTDH(j), 0);
	    	IXGBE_WRITE_REG(&adapter->hw, IXGBE_VFTDT(j), 0);

		/* Set Tx Tail register */
		txr->tail = IXGBE_VFTDT(j);

		/* Set Ring parameters */
		IXGBE_WRITE_REG(hw, IXGBE_VFTDBAL(j),
		       (tdba & 0x00000000ffffffffULL));
		IXGBE_WRITE_REG(hw, IXGBE_VFTDBAH(j), (tdba >> 32));
		IXGBE_WRITE_REG(hw, IXGBE_VFTDLEN(j),
		    scctx->isc_ntxd[0] *
		    sizeof(struct ixgbe_legacy_tx_desc));
		txctrl = IXGBE_READ_REG(hw, IXGBE_VFDCA_TXCTRL(j));
		txctrl &= ~IXGBE_DCA_TXCTRL_DESC_WRO_EN;
		IXGBE_WRITE_REG(hw, IXGBE_VFDCA_TXCTRL(j), txctrl);

		/* Now enable */
		txdctl = IXGBE_READ_REG(hw, IXGBE_VFTXDCTL(j));
		txdctl |= IXGBE_TXDCTL_ENABLE;
		IXGBE_WRITE_REG(hw, IXGBE_VFTXDCTL(j), txdctl);
	}
} /* ixv_initialize_transmit_units */


/************************************************************************
 * ixv_initialize_rss_mapping
 ************************************************************************/
static void
ixv_initialize_rss_mapping(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32             reta = 0, mrqc, rss_key[10];
	int             queue_id;
	int             i, j;
	u32             rss_hash_config;

	if (adapter->feat_en & IXGBE_FEATURE_RSS) {
		/* Fetch the configured RSS key */
		rss_getkey((uint8_t *)&rss_key);
	} else {
		/* set up random bits */
		arc4rand(&rss_key, sizeof(rss_key), 0);
	}

	/* Now fill out hash function seeds */
	for (i = 0; i < 10; i++)
		IXGBE_WRITE_REG(hw, IXGBE_VFRSSRK(i), rss_key[i]);

	/* Set up the redirection table */
	for (i = 0, j = 0; i < 64; i++, j++) {
		if (j == adapter->num_rx_queues)
			j = 0;

		if (adapter->feat_en & IXGBE_FEATURE_RSS) {
			/*
			 * Fetch the RSS bucket id for the given indirection
			 * entry. Cap it at the number of configured buckets
			 * (which is num_queues.)
			 */
			queue_id = rss_get_indirection_to_bucket(i);
			queue_id = queue_id % adapter->num_rx_queues;
		} else
			queue_id = j;

		/*
		 * The low 8 bits are for hash value (n+0);
		 * The next 8 bits are for hash value (n+1), etc.
		 */
		reta >>= 8;
		reta |= ((uint32_t)queue_id) << 24;
		if ((i & 3) == 3) {
			IXGBE_WRITE_REG(hw, IXGBE_VFRETA(i >> 2), reta);
			reta = 0;
		}
	}

	/* Perform hash on these packet types */
	if (adapter->feat_en & IXGBE_FEATURE_RSS)
		rss_hash_config = rss_gethashconfig();
	else {
		/*
		 * Disable UDP - IP fragments aren't currently being handled
		 * and so we end up with a mix of 2-tuple and 4-tuple
		 * traffic.
		 */
		rss_hash_config = RSS_HASHTYPE_RSS_IPV4
		                | RSS_HASHTYPE_RSS_TCP_IPV4
		                | RSS_HASHTYPE_RSS_IPV6
		                | RSS_HASHTYPE_RSS_TCP_IPV6;
	}

	mrqc = IXGBE_MRQC_RSSEN;
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV4)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4;
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV4)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4_TCP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV6)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6;
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV6)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_TCP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV6_EX)
		device_printf(adapter->dev, "%s: RSS_HASHTYPE_RSS_IPV6_EX defined, but not supported\n",
		    __func__);
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV6_EX)
		device_printf(adapter->dev, "%s: RSS_HASHTYPE_RSS_TCP_IPV6_EX defined, but not supported\n",
		    __func__);
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV4)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4_UDP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV4_EX)
		device_printf(adapter->dev, "%s: RSS_HASHTYPE_RSS_UDP_IPV4_EX defined, but not supported\n",
		    __func__);
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV6)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_UDP;
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV6_EX)
		device_printf(adapter->dev, "%s: RSS_HASHTYPE_RSS_UDP_IPV6_EX defined, but not supported\n",
		    __func__);
	IXGBE_WRITE_REG(hw, IXGBE_VFMRQC, mrqc);
} /* ixv_initialize_rss_mapping */


/************************************************************************
 * ixv_initialize_receive_units - Setup receive registers and features.
 ************************************************************************/
static void
ixv_initialize_receive_units(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	struct ixgbe_hw *hw = &adapter->hw;
	struct ifnet    *ifp = adapter->ifp;
	struct ix_rx_queue *que = adapter->rx_queues;
	u32             bufsz, rxcsum, psrtype;

	if (ifp->if_mtu > ETHERMTU)
		bufsz = 4096 >> IXGBE_SRRCTL_BSIZEPKT_SHIFT;
	else
		bufsz = 2048 >> IXGBE_SRRCTL_BSIZEPKT_SHIFT;

	psrtype = IXGBE_PSRTYPE_TCPHDR
	        | IXGBE_PSRTYPE_UDPHDR
	        | IXGBE_PSRTYPE_IPV4HDR
	        | IXGBE_PSRTYPE_IPV6HDR
	        | IXGBE_PSRTYPE_L2HDR;

	if (adapter->num_rx_queues > 1)
		psrtype |= 1 << 29;

	IXGBE_WRITE_REG(hw, IXGBE_VFPSRTYPE, psrtype);

	/* Tell PF our max_frame size */
	ixgbevf_rlpml_set_vf(hw, adapter->max_frame_size);
	scctx = adapter->shared;

	for (int i = 0; i < adapter->num_rx_queues; i++, que++) {
		struct rx_ring *rxr = &que->rxr; 
		u64 rdba = rxr->rx_paddr;
		u32 reg, rxdctl;
		int j = rxr->me; 

		/* Disable the queue */
		rxdctl = IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(j));
		rxdctl &= ~IXGBE_RXDCTL_ENABLE;
		IXGBE_WRITE_REG(hw, IXGBE_VFRXDCTL(j), rxdctl);
		for (int k = 0; k < 10; k++) {
			if (IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(j)) &
			    IXGBE_RXDCTL_ENABLE)
				msec_delay(1);
			else
				break;
		}
		wmb();
		/* Setup the Base and Length of the Rx Descriptor Ring */
		IXGBE_WRITE_REG(hw, IXGBE_VFRDBAL(j),
		    (rdba & 0x00000000ffffffffULL));
		IXGBE_WRITE_REG(hw, IXGBE_VFRDBAH(j),
		    (rdba >> 32));
		IXGBE_WRITE_REG(hw, IXGBE_VFRDLEN(j),
				scctx->isc_nrxd[0] * sizeof(union ixgbe_adv_rx_desc));

		/* Reset the ring indices */
		IXGBE_WRITE_REG(hw, IXGBE_VFRDH(rxr->me), 0);
		IXGBE_WRITE_REG(hw, IXGBE_VFRDT(rxr->me), 0);

		/* Set up the SRRCTL register */
		reg = IXGBE_READ_REG(hw, IXGBE_VFSRRCTL(j));
		reg &= ~IXGBE_SRRCTL_BSIZEHDR_MASK;
		reg &= ~IXGBE_SRRCTL_BSIZEPKT_MASK;
		reg |= bufsz;
		reg |= IXGBE_SRRCTL_DESCTYPE_ADV_ONEBUF;
		IXGBE_WRITE_REG(hw, IXGBE_VFSRRCTL(j), reg);

		/* Capture Rx Tail index */
		rxr->tail = IXGBE_VFRDT(rxr->me);

		/* Do the queue enabling last */
		rxdctl |= IXGBE_RXDCTL_ENABLE | IXGBE_RXDCTL_VME;
		IXGBE_WRITE_REG(hw, IXGBE_VFRXDCTL(j), rxdctl);
		for (int l = 0; l < 10; l++) {
			if (IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(j)) &
			    IXGBE_RXDCTL_ENABLE)
				break;
			msec_delay(1);
		}
		wmb();

		/* Set the Tail Pointer */
		/*
		 * In netmap mode, we must preserve the buffers made
		 * available to userspace before the if_init()
		 * (this is true by default on the TX side, because
		 * init makes all buffers available to userspace).
		 *
		 * netmap_reset() and the device specific routines
		 * (e.g. ixgbe_setup_receive_rings()) map these
		 * buffers at the end of the NIC ring, so here we
		 * must set the RDT (tail) register to make sure
		 * they are not overwritten.
		 *
		 * In this driver the NIC ring starts at RDH = 0,
		 * RDT points to the last slot available for reception (?),
		 * so RDT = num_rx_desc - 1 means the whole ring is available.
		 */
			IXGBE_WRITE_REG(hw, IXGBE_VFRDT(rxr->me),
					scctx->isc_nrxd[0] - 1);
	}

	rxcsum = IXGBE_READ_REG(hw, IXGBE_RXCSUM);

	ixv_initialize_rss_mapping(adapter);

	if (adapter->num_rx_queues > 1) {
		/* RSS and RX IPP Checksum are mutually exclusive */
		rxcsum |= IXGBE_RXCSUM_PCSD;
	}

	if (ifp->if_capenable & IFCAP_RXCSUM)
		rxcsum |= IXGBE_RXCSUM_PCSD;

	if (!(rxcsum & IXGBE_RXCSUM_PCSD))
		rxcsum |= IXGBE_RXCSUM_IPPCSE;

	IXGBE_WRITE_REG(hw, IXGBE_RXCSUM, rxcsum);
} /* ixv_initialize_receive_units */

/************************************************************************
 * ixv_setup_vlan_support
 ************************************************************************/
static void
ixv_setup_vlan_support(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx); 
	struct ixgbe_hw *hw = &adapter->hw;
	u32             ctrl, vid, vfta, retry;

	/*
	 * We get here thru init_locked, meaning
	 * a soft reset, this has already cleared
	 * the VFTA and other state, so if there
	 * have been no vlan's registered do nothing.
	 */
	if (adapter->num_vlans == 0)
		return;

	/* Enable the queues */
	for (int i = 0; i < adapter->num_rx_queues; i++) {
		struct rx_ring *rxr = &adapter->rx_queues[i].rxr;
		ctrl = IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(i));
		ctrl |= IXGBE_RXDCTL_VME;
		IXGBE_WRITE_REG(hw, IXGBE_VFRXDCTL(i), ctrl);
		/*
		 * Let Rx path know that it needs to store VLAN tag
		 * as part of extra mbuf info.
		 */
		rxr->vtag_strip = TRUE;
	}

	/*
	 * A soft reset zero's out the VFTA, so
	 * we need to repopulate it now.
	 */
	for (int i = 0; i < IXGBE_VFTA_SIZE; i++) {
		if (ixv_shadow_vfta[i] == 0)
			continue;
		vfta = ixv_shadow_vfta[i];
		/*
		 * Reconstruct the vlan id's
		 * based on the bits set in each
		 * of the array ints.
		 */
		for (int j = 0; j < 32; j++) {
			retry = 0;
			if ((vfta & (1 << j)) == 0)
				continue;
			vid = (i * 32) + j;
			/* Call the shared code mailbox routine */
			while (hw->mac.ops.set_vfta(hw, vid, 0, TRUE, FALSE)) {
				if (++retry > 5)
					break;
			}
		}
	}
} /* ixv_setup_vlan_support */

/************************************************************************
 * ixv_register_vlan
 *
 *   Run via a vlan config EVENT, it enables us to use the
 *   HW Filter table since we can get the vlan id. This just
 *   creates the entry in the soft version of the VFTA, init
 *   will repopulate the real table.
 ************************************************************************/
static void
ixv_if_register_vlan(if_ctx_t ctx, u16 vtag)
{
	struct adapter	*adapter = iflib_get_softc(ctx);
	u16		index, bit;

	index = (vtag >> 5) & 0x7F;
	bit = vtag & 0x1F;
	ixv_shadow_vfta[index] |= (1 << bit);
	++adapter->num_vlans;
}

/************************************************************************
 * ixv_unregister_vlan
 *
 *   Run via a vlan unconfig EVENT, remove our entry
 *   in the soft vfta.
 ************************************************************************/
static void
ixv_if_unregister_vlan(if_ctx_t ctx, u16 vtag)
{
	struct adapter	*adapter = iflib_get_softc(ctx);
	u16		index, bit;

	index = (vtag >> 5) & 0x7F;
	bit = vtag & 0x1F;
	ixv_shadow_vfta[index] &= ~(1 << bit);
	--adapter->num_vlans;
}

/************************************************************************
 * ixv_enable_intr
 ************************************************************************/
static void
ixv_if_enable_intr(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx); 
	struct ixgbe_hw *hw = &adapter->hw;
	struct ix_rx_queue *que = adapter->rx_queues;
	u32 mask = (IXGBE_EIMS_ENABLE_MASK & ~IXGBE_EIMS_RTX_QUEUE);

	IXGBE_WRITE_REG(hw, IXGBE_VTEIMS, mask);

	mask = IXGBE_EIMS_ENABLE_MASK;
	mask &= ~(IXGBE_EIMS_OTHER | IXGBE_EIMS_LSC);
	IXGBE_WRITE_REG(hw, IXGBE_VTEIAC, mask);

        for (int i = 0; i < adapter->num_rx_queues; i++, que++)
		ixv_enable_queue(adapter, que->msix);

	IXGBE_WRITE_FLUSH(hw);
} /* ixv_enable_intr */

/************************************************************************
 * ixv_disable_intr
 ************************************************************************/
static void
ixv_if_disable_intr(if_ctx_t ctx)
{
	struct adapter *adapter = iflib_get_softc(ctx); 
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_VTEIAC, 0);
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_VTEIMC, ~0);
	IXGBE_WRITE_FLUSH(&adapter->hw);
} /* ixv_disable_intr */

/************************************************************************
 * ixv_set_ivar
 *
 *   Setup the correct IVAR register for a particular MSI-X interrupt
 *    - entry is the register array entry
 *    - vector is the MSI-X vector for this queue
 *    - type is RX/TX/MISC
 ************************************************************************/
static void
ixv_set_ivar(struct adapter *adapter, u8 entry, u8 vector, s8 type)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32             ivar, index;

	vector |= IXGBE_IVAR_ALLOC_VAL;

	if (type == -1) { /* MISC IVAR */
		ivar = IXGBE_READ_REG(hw, IXGBE_VTIVAR_MISC);
		ivar &= ~0xFF;
		ivar |= vector;
		IXGBE_WRITE_REG(hw, IXGBE_VTIVAR_MISC, ivar);
	} else {          /* RX/TX IVARS */
		index = (16 * (entry & 1)) + (8 * type);
		ivar = IXGBE_READ_REG(hw, IXGBE_VTIVAR(entry >> 1));
		ivar &= ~(0xFF << index);
		ivar |= (vector << index);
		IXGBE_WRITE_REG(hw, IXGBE_VTIVAR(entry >> 1), ivar);
	}
} /* ixv_set_ivar */

/************************************************************************
 * ixv_configure_ivars
 ************************************************************************/
static void
ixv_configure_ivars(struct adapter *adapter)
{
	struct  ix_rx_queue *que = adapter->rx_queues;

	MPASS(adapter->num_rx_queues == adapter->num_tx_queues);

	for (int i = 0; i < adapter->num_rx_queues; i++, que++) {
		/* First the RX queue entry */
		ixv_set_ivar(adapter, i, que->msix, 0);
		/* ... and the TX */
		ixv_set_ivar(adapter, i, que->msix, 1);
		/* Set an initial value in EITR */
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_VTEITR(que->msix),
		    IXGBE_EITR_DEFAULT);
	}

	/* For the mailbox interrupt */
	ixv_set_ivar(adapter, 1, adapter->vector, -1);
} /* ixv_configure_ivars */

/*
** The VF stats registers never have a truely virgin
** starting point, so this routine tries to make an
** artificial one, marking ground zero on attach as
** it were.
*/
static void
ixv_save_stats(struct adapter *adapter)
{
	if (adapter->stats.vf.vfgprc || adapter->stats.vf.vfgptc) {
		adapter->stats.vf.saved_reset_vfgprc +=
		    adapter->stats.vf.vfgprc - adapter->stats.vf.base_vfgprc;
		adapter->stats.vf.saved_reset_vfgptc +=
		    adapter->stats.vf.vfgptc - adapter->stats.vf.base_vfgptc;
		adapter->stats.vf.saved_reset_vfgorc +=
		    adapter->stats.vf.vfgorc - adapter->stats.vf.base_vfgorc;
		adapter->stats.vf.saved_reset_vfgotc +=
		    adapter->stats.vf.vfgotc - adapter->stats.vf.base_vfgotc;
		adapter->stats.vf.saved_reset_vfmprc +=
		    adapter->stats.vf.vfmprc - adapter->stats.vf.base_vfmprc;
	}
} /* ixv_save_stats */

/************************************************************************
 * ixv_init_stats
 ************************************************************************/
static void
ixv_init_stats(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;

	adapter->stats.vf.last_vfgprc = IXGBE_READ_REG(hw, IXGBE_VFGPRC);
	adapter->stats.vf.last_vfgorc = IXGBE_READ_REG(hw, IXGBE_VFGORC_LSB);
	adapter->stats.vf.last_vfgorc |=
	    (((u64)(IXGBE_READ_REG(hw, IXGBE_VFGORC_MSB))) << 32);

	adapter->stats.vf.last_vfgptc = IXGBE_READ_REG(hw, IXGBE_VFGPTC);
	adapter->stats.vf.last_vfgotc = IXGBE_READ_REG(hw, IXGBE_VFGOTC_LSB);
	adapter->stats.vf.last_vfgotc |=
	    (((u64)(IXGBE_READ_REG(hw, IXGBE_VFGOTC_MSB))) << 32);

	adapter->stats.vf.last_vfmprc = IXGBE_READ_REG(hw, IXGBE_VFMPRC);

	adapter->stats.vf.base_vfgprc = adapter->stats.vf.last_vfgprc;
	adapter->stats.vf.base_vfgorc = adapter->stats.vf.last_vfgorc;
	adapter->stats.vf.base_vfgptc = adapter->stats.vf.last_vfgptc;
	adapter->stats.vf.base_vfgotc = adapter->stats.vf.last_vfgotc;
	adapter->stats.vf.base_vfmprc = adapter->stats.vf.last_vfmprc;
} /* ixv_init_stats */

#define UPDATE_STAT_32(reg, last, count)                \
{                                                       \
	u32 current = IXGBE_READ_REG(hw, reg);          \
	if (current < last)                             \
		count += 0x100000000LL;                 \
	last = current;                                 \
	count &= 0xFFFFFFFF00000000LL;                  \
	count |= current;                               \
}

#define UPDATE_STAT_36(lsb, msb, last, count)           \
{                                                       \
	u64 cur_lsb = IXGBE_READ_REG(hw, lsb);          \
	u64 cur_msb = IXGBE_READ_REG(hw, msb);          \
	u64 current = ((cur_msb << 32) | cur_lsb);      \
	if (current < last)                             \
		count += 0x1000000000LL;                \
	last = current;                                 \
	count &= 0xFFFFFFF000000000LL;                  \
	count |= current;                               \
}

/************************************************************************
 * ixv_update_stats - Update the board statistics counters.
 ************************************************************************/
void
ixv_update_stats(struct adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct ixgbevf_hw_stats *stats = &adapter->stats.vf;

        UPDATE_STAT_32(IXGBE_VFGPRC, adapter->stats.vf.last_vfgprc,
	    adapter->stats.vf.vfgprc);
        UPDATE_STAT_32(IXGBE_VFGPTC, adapter->stats.vf.last_vfgptc,
	    adapter->stats.vf.vfgptc);
        UPDATE_STAT_36(IXGBE_VFGORC_LSB, IXGBE_VFGORC_MSB,
	    adapter->stats.vf.last_vfgorc, adapter->stats.vf.vfgorc);
        UPDATE_STAT_36(IXGBE_VFGOTC_LSB, IXGBE_VFGOTC_MSB,
	    adapter->stats.vf.last_vfgotc, adapter->stats.vf.vfgotc);
        UPDATE_STAT_32(IXGBE_VFMPRC, adapter->stats.vf.last_vfmprc,
	    adapter->stats.vf.vfmprc);

	/* Fill out the OS statistics structure */
	IXGBE_SET_IPACKETS(adapter, stats->vfgprc);
	IXGBE_SET_OPACKETS(adapter, stats->vfgptc);
	IXGBE_SET_IBYTES(adapter, stats->vfgorc);
	IXGBE_SET_OBYTES(adapter, stats->vfgotc);
	IXGBE_SET_IMCASTS(adapter, stats->vfmprc);
} /* ixv_update_stats */

/************************************************************************
 * ixv_add_stats_sysctls - Add statistic sysctls for the VF.
 ************************************************************************/
static void
ixv_add_stats_sysctls(struct adapter *adapter)
{
	device_t dev = adapter->dev;

	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(dev);
	struct sysctl_oid *tree = device_get_sysctl_tree(dev);
	struct sysctl_oid_list *child = SYSCTL_CHILDREN(tree);
	struct ixgbevf_hw_stats *stats = &adapter->stats.vf;
	struct sysctl_oid       *stat_node;
	struct sysctl_oid_list  *stat_list;

	/* Driver Statistics */
	SYSCTL_ADD_ULONG(ctx, child, OID_AUTO, "watchdog_events",
	    CTLFLAG_RD, &adapter->watchdog_events, "Watchdog timeouts");
	SYSCTL_ADD_ULONG(ctx, child, OID_AUTO, "link_irq",
	    CTLFLAG_RD, &adapter->link_irq, "Link MSI-X IRQ Handled");

	stat_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, "mac",
	    CTLFLAG_RD, NULL, "VF Statistics (read from HW registers)");
	stat_list = SYSCTL_CHILDREN(stat_node);

	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_pkts_rcvd",
	    CTLFLAG_RD, &stats->vfgprc, "Good Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_octets_rcvd",
	    CTLFLAG_RD, &stats->vfgorc, "Good Octets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "mcast_pkts_rcvd",
	    CTLFLAG_RD, &stats->vfmprc, "Multicast Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_pkts_txd",
	    CTLFLAG_RD, &stats->vfgptc, "Good Packets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_octets_txd",
			CTLFLAG_RD, &stats->vfgotc, 
			"Good Octets Transmitted"); 

}
#ifdef old
static void 
ixv_set_sysctl_value(struct adapter *adapter, const char *name,
	const char *description, int *limit, int value)
{
	*limit = value;
	SYSCTL_ADD_INT(device_get_sysctl_ctx(adapter->dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(adapter->dev)),
	    OID_AUTO, name, CTLFLAG_RW, limit, value, description);
} /* ixv_set_sysctl_value */
#endif

/************************************************************************
 * ixv_print_debug_info
 *
 *   Called only when em_display_debug_stats is enabled.
 *   Provides a way to take a look at important statistics
 *   maintained by the driver and hardware.
 ************************************************************************/
static void
ixv_print_debug_info(struct adapter *adapter)
{
        device_t dev = adapter->dev;
        struct ixgbe_hw         *hw = &adapter->hw;

        device_printf(dev,"Error Byte Count = %u \n",
            IXGBE_READ_REG(hw, IXGBE_ERRBC));

        device_printf(dev,"MBX IRQ Handled: %lu\n",
            (long)adapter->link_irq);
}
/************************************************************************
 * ixv_sysctl_debug
 ************************************************************************/
static int
ixv_sysctl_debug(SYSCTL_HANDLER_ARGS)
{
	struct adapter *adapter;
	int            error, result;

	result = -1;
	error = sysctl_handle_int(oidp, &result, 0, req);

	if (error || !req->newptr)
		return (error);

	if (result == 1) {
		adapter = (struct adapter *)arg1;
		ixv_print_debug_info(adapter);
	}

	return error;
} /* ixv_sysctl_debug */

#ifdef notyet
/************************************************************************
 * ixv_init_device_features
 ************************************************************************/
static void
ixv_init_device_features(struct adapter *adapter)
{
	adapter->feat_cap = IXGBE_FEATURE_VF
	                  | IXGBE_FEATURE_RSS
	                  | IXGBE_FEATURE_LEGACY_TX;

	/* A tad short on feature flags for VFs, atm. */
	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82599_vf:
		break;
	case ixgbe_mac_X540_vf:
		break;
	case ixgbe_mac_X550_vf:
	case ixgbe_mac_X550EM_x_vf:
	case ixgbe_mac_X550EM_a_vf:
		adapter->feat_cap |= IXGBE_FEATURE_NEEDS_CTXD;
		break;
	default:
		break;
	}

	/* Enabled by default... */
	/* Is a virtual function (VF) */
	if (adapter->feat_cap & IXGBE_FEATURE_VF)
		adapter->feat_en |= IXGBE_FEATURE_VF;
	/* Receive-Side Scaling (RSS) */
	if (adapter->feat_cap & IXGBE_FEATURE_RSS)
		adapter->feat_en |= IXGBE_FEATURE_RSS;
	/* Needs advanced context descriptor regardless of offloads req'd */
	if (adapter->feat_cap & IXGBE_FEATURE_NEEDS_CTXD)
		adapter->feat_en |= IXGBE_FEATURE_NEEDS_CTXD;

	/* Enabled via sysctl... */
} /* ixv_init_device_features */
#endif
