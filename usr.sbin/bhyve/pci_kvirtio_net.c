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

/*
 * Proxy for the kernel vtnet_be pseudo device
 *
 * Configuration is either SOHO - configuration by bhyve:
 *
 *  -s <bsd>,kvirtio-net,<ifname><unit>[,macaddr=x:x:x:x:x:x,]
 *
 *    e.g.   -s  2:3:0,kvirtio-net,<vxlan1|igb0>,mac=00:bd:5d:32:00:e7
 *
 *
 * Where the MAC address can be specified on the command line. If not, 
 * it will be synthesized and will be unique for a given guest b/s/f, 
 * vm name, and host UUID.
 *
 * or DC - independent configuration:
 *
 *  -s <bsd>,kvirtio-net,vmi<unit>
 *
 *    e.g.   -s  2:3:0,kvirtio-net,vmi7
 *
 * Communication with the kernel module is via ioctls to the cloned interface
 * named:
 *  vmi<unit>
 *
 *   NB:
 *   - MSI-x is always used
 *   - The BAR will not be modified during run-time of the VM (not the
 *     case with UEFI)
 *   - currently single-queue only
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/ioctl.h>
#include <sys/cpuset.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <md5.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sysexits.h>

#include "bhyverun.h"
#include "pci_emul.h"
#include "virtio.h"

#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <vmmapi.h>


#define VTNET_BE_REGSZ		(20 + 4 + 8)	/* virtio + MSI-x + config */
#define MAX_VMS				256

struct vtnet_be_softc {
	struct pci_devinst *vbs_pi;
	uint8_t vbs_origmac[6];			/* original MAC address */
	int vbs_fd;				/* socket descriptor for config */
	const char *vbs_vm_intf;
	const char *vbs_hw_intf;
};

static void
vtnet_be_msix(struct vmctx *ctx, int vcpu, struct pci_devinst *pi, int on)
{
	struct vtnet_be_softc *vbs;
	struct vb_msix vmsix;
	struct ifreq ifr;
	int err;

	vbs = pi->pi_arg;
	vmsix.status = on;

	vmsix.va_ioh.vih_magic = VB_MAGIC;
	vmsix.va_ioh.vih_type = VB_MSIX;
	ifr.ifr_buffer.length = sizeof(vmsix);
	ifr.ifr_buffer.buffer = &vmsix;
	strncpy(ifr.ifr_name, vbs->vbs_vm_intf, IFNAMSIZ-1);
	if (on) {
		vmsix.queue[0].msg  = pi->pi_msix.table[0].msg_data;
		vmsix.queue[0].addr = pi->pi_msix.table[0].addr;
		vmsix.queue[1].msg  = pi->pi_msix.table[1].msg_data;
		vmsix.queue[1].addr = pi->pi_msix.table[1].addr;
		vmsix.queue[2].msg  = pi->pi_msix.table[2].msg_data;
		vmsix.queue[2].addr = pi->pi_msix.table[2].addr;
	}

	err = ioctl(vbs->vbs_fd, SIOCGPRIVATE_0, &ifr);
	assert(err == 0);
}

static uint64_t
vtnet_be_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
    int baridx, uint64_t offset, int size)
{

	assert(baridx == 1);
	return (pci_emul_msix_tread(pi, offset, size));
}

void
vtnet_be_write(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
    int baridx, uint64_t offset, int size, uint64_t value)
{

	assert(baridx == 1);
	pci_emul_msix_twrite(pi, offset, size, value);
	vtnet_be_msix(ctx, vcpu, pi, 1);
}

static int
vtnet_be_macaddr(struct vtnet_be_softc *vbs, char *macaddr)
{
	int err;

	err = 0;

	if (macaddr != NULL) {
		struct ether_addr *ea;
		char *tmpstr;
		char zero_addr[ETHER_ADDR_LEN] = { 0, 0, 0, 0, 0, 0 };

		err = 1;
		tmpstr = strsep(&macaddr, "=");
		if (macaddr != NULL && !strcmp(tmpstr, "mac")) {
			ea = ether_aton(macaddr);
			if (ea == NULL || ETHER_IS_MULTICAST(ea->octet) ||
			    !memcmp(ea->octet, zero_addr, ETHER_ADDR_LEN)) {
				/* invalid MAC address */
			} else {
				err = 0;
				memcpy(vbs->vbs_origmac, ea->octet,
				    ETHER_ADDR_LEN);
			}

		}
	} else if (vbs->vbs_vm_intf == NULL) {
		MD5_CTX mdctx;
		struct pci_devinst *pi;
		char nstr[100];
		unsigned char digest[16];

		/*
		 * Generate a pseudo-random, deterministic MAC
		 * address based on the UUID (if passed),the VM name,
		 * and the guest b/s/f.
		 * The (obsolete) DEC OUI of aa-00-00 is used.
		 */
		pi = vbs->vbs_pi;
		snprintf(nstr, sizeof(nstr), "%s: %d-%d-%d %s\n",
		    guest_uuid_str ? guest_uuid_str : "no-guid",
		    pi->pi_bus, pi->pi_slot, pi->pi_func,
		    vmname);

		MD5Init(&mdctx);
                MD5Update(&mdctx, nstr, strlen(nstr));
                MD5Final(digest, &mdctx);

		vbs->vbs_origmac[0] = 0xAA;
		vbs->vbs_origmac[1] = 0x00;
		vbs->vbs_origmac[2] = 0x00;
		vbs->vbs_origmac[3] = digest[0];
		vbs->vbs_origmac[4] = digest[1];
		vbs->vbs_origmac[5] = digest[2];
	}
	/* else set elsewhere */
	return (err);
}

static int
vtnet_be_parseopts(struct vtnet_be_softc *vbs, char *opts)
{
	char *intf, *mac;

	if (opts == NULL)
		return (1);

	vbs->vbs_vm_intf = vbs->vbs_hw_intf = NULL;

	intf = mac = strdup(opts);
	(void) strsep(&mac, ",");
	if (strstr(intf, "vmi") != NULL)
		vbs->vbs_vm_intf = intf;
	else
		vbs->vbs_hw_intf = intf;
	return (vtnet_be_macaddr(vbs, mac));
}

static int
vtnet_be_clone(struct vtnet_be_softc *vbs)
{
	struct vb_vm_attach va;
	struct ifreq ifr;
	int i, s, flags;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		return (errno);
	}
#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_IOCTL);
	if (cap_rights_limit(s, &rights) == -1 && errno != ENOSYS)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif
	vbs->vbs_fd = s;
	bzero(&va, sizeof(va));
	ifr.ifr_data = (caddr_t)&va;

	va.vva_io_start = vbs->vbs_pi->pi_bar[0].addr;
	va.vva_io_size = VTNET_BE_REGSZ;
	va.vva_num_queues = 0;	/* accept default */
	va.vva_queue_size = 0;	/* accept default */
	strncpy(va.vva_vmparent, vmname, VMNAMSIZ-1);
	/*
	 * We've been given a preconfigured interface
	 * just attach and go
	 */
	if (vbs->vbs_vm_intf != NULL) {
		strncpy(ifr.ifr_name, vbs->vbs_vm_intf, IFNAMSIZ-1);
		va.vva_ioh.vih_magic = VB_MAGIC;
		va.vva_ioh.vih_type = VB_VM_ATTACH;;
		return (ioctl(s, SIOCGPRIVATE_0, &ifr));
	}

	strncpy(va.vva_ifparent, vbs->vbs_hw_intf, IFNAMSIZ-1);
	memcpy(va.vva_macaddr, vbs->vbs_origmac, ETHER_ADDR_LEN);
	for (i = 0; i < MAX_VMS; i++) {
		sprintf(ifr.ifr_name, "vmi%d", i);
		if (ioctl(s, SIOCIFCREATE2, &ifr) == 0) {
			vbs->vbs_vm_intf = strdup(ifr.ifr_name);
			break;
		}
	}
	if (i == MAX_VMS)
		return (ENOSPC);

	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		perror("SIOCGIFFLAGS");
		return (errno);
	}

	flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
	flags |= IFF_UP;
	ifr.ifr_flags = flags & 0xffff;
	ifr.ifr_flagshigh = flags >> 16;
#if 0
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		perror("SIOCSIFFLAGS");
		return (errno);
	}
	strncpy(ifr.ifr_name, vbs->vbs_hw_intf, IFNAMSIZ-1);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		perror("SIOCGIFFLAGS");
		return (errno);
	}
	flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
	flags |= IFF_UP;
	ifr.ifr_flags = flags & 0xffff;
	ifr.ifr_flagshigh = flags >> 16;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		perror("SIOCSIFFLAGS");
		return (errno);
	}
#endif	
	return (0);
}

static int
vtnet_be_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	struct vtnet_be_softc *vbs;
	int memflags;

	memflags = vm_get_memflags(ctx);
	if (!(memflags & VM_MEM_F_WIRED)) {
		warnx("kvirtio-net requires guest memory to be wired");
		return (1);
	}
	vbs = calloc(1, sizeof(struct vtnet_be_softc));

	pi->pi_arg = vbs;
	vbs->vbs_pi = pi;

	if (vtnet_be_parseopts(vbs, opts)) {
		fprintf(stderr, "kvirtio-net: parse issue with \"%s\"\n",
			opts ? opts : "(null)");
		return (1);
	}

	pci_set_cfgdata16(pi, PCIR_DEVICE, VIRTIO_DEV_NET);
	pci_set_cfgdata16(pi, PCIR_VENDOR, VIRTIO_VENDOR);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_NETWORK);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, VIRTIO_TYPE_NET);

	pci_emul_alloc_bar(pi, 0, PCIBAR_IO, VTNET_BE_REGSZ);

	/*
	 * MSI-x BAR at 1.
	 * 3 IRQs - event queue (not implemented), rx, and tx
	 */
	if (pci_emul_add_msixcap(pi, 3 + 1, 1))
		return (1);

	/* Attempt to open the char dev for this device */
	if (vtnet_be_clone(vbs))
		return (1);

	return (0);
}

struct pci_devemu pci_de_vtnet_be = {
	.pe_emu =	"kvirtio-net",
	.pe_init =	vtnet_be_init,
	.pe_barread =	vtnet_be_read,
	.pe_barwrite =	vtnet_be_write,
	.pe_msix =	vtnet_be_msix,
};
PCI_EMUL_SET(pci_de_vtnet_be);
