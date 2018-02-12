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
 * Configuration is
 *
 *  -s <bsd>,kvirtio-net,intf=vpcp<unit>[,mac=x:x:x:x:x:x][,mtu=<n>][,queues=<nq>]
 *
 *    e.g.   -s  2:3:0,kvirtio-net,intf=vpcp1,mac=00:bd:5d:32:00:e7,mtu=1450,queues=8
 *
 *
 * If mac is not specified it will be synthesized and will be unique for a given 
 * guest b/s/f, vm name, and host UUID.
 *
 * nq: Can be 1 - VM_MAXCPU, if not specified defaults to 1
 *
 * Communication with the kernel module is via ioctls to the cloned interface
 * named:
 *  vmnic<unit>
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

#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif


#define VTNET_BE_REGSZ		(20 + 4 + 8)	/* virtio + MSI-x + config */

struct vtnet_be_softc {
	struct pci_devinst *vbs_pi;
	uint8_t vbs_origmac[6];			/* original MAC address */
	int vbs_fd;				/* socket descriptor for config */
	int vbs_nqs;
	int vbs_nvqs;
	int vbs_mtu;
	const char *vbs_vm_intf;
	const char *vbs_port_intf;
};

static void
vtnet_be_msix(struct vmctx *ctx, int vcpu, struct pci_devinst *pi, int on)
{
	struct vtnet_be_softc *vbs;
	struct vb_msix *vmsix;
	struct ifreq ifr;
	int i, err, size, nvqs;

	vbs = pi->pi_arg;
	nvqs = vbs->vbs_nvqs;
	size = sizeof(*vmsix) + nvqs*sizeof(struct vb_msix_vector);

	vmsix = malloc(size);
	vmsix->vm_status = on;
	vmsix->vm_count = nvqs;
	vmsix->vm_ioh.vih_magic = VB_MAGIC;
	vmsix->vm_ioh.vih_type = VB_MSIX;
	ifr.ifr_buffer.length = size;
	ifr.ifr_buffer.buffer = vmsix;
	strncpy(ifr.ifr_name, vbs->vbs_vm_intf, IFNAMSIZ-1);
	if (on) {
		for (i = 0; i < nvqs; i++) {
			vmsix->vm_q[i].msg = pi->pi_msix.table[i].msg_data;
			vmsix->vm_q[i].addr = pi->pi_msix.table[i].addr;
		}
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
	int err = 0;

	if (macaddr != NULL) {
		struct ether_addr *ea;
		char zero_addr[ETHER_ADDR_LEN] = { 0, 0, 0, 0, 0, 0 };

		err = 1;
		if (macaddr != NULL) {
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
		 * The FreeBSD Foundation OUI of 58-9C-FC is used.
		 */
		pi = vbs->vbs_pi;
		snprintf(nstr, sizeof(nstr), "%s: %d-%d-%d %s\n",
		    guest_uuid_str ? guest_uuid_str : "no-guid",
		    pi->pi_bus, pi->pi_slot, pi->pi_func,
		    vmname);

		MD5Init(&mdctx);
                MD5Update(&mdctx, nstr, strlen(nstr));
                MD5Final(digest, &mdctx);

		vbs->vbs_origmac[0] = 0x58;
		vbs->vbs_origmac[1] = 0x9C;
		vbs->vbs_origmac[2] = 0xFC;
		vbs->vbs_origmac[3] = digest[0];
		vbs->vbs_origmac[4] = digest[1];
		vbs->vbs_origmac[5] = digest[2];
	}
	/* else set elsewhere */
	return (err);
}
struct token_value {
	char *token;
	int type;
};

#define KW_INTF 0x1
#define KW_MAC 0x2
#define KW_MTU 0x3
#define KW_QUEUES 0x4
#define KW_MAX KW_QUEUES

struct token_value token_map[] = {
	{"intf", KW_INTF},
	{"mac", KW_MAC},
	{"mtu", KW_MTU},
	{"queues", KW_QUEUES},
};

static int
strtype(char *token) {
	int i;

	for (i = 0; i < KW_MAX; i++) {
		if (strstr(token, token_map[i].token) != NULL)
			return (token_map[i].type);
	}
	return (-1);
}

static char *
tokenval(char *token)
{

	strsep(&token, "=");
	return (token);
}

static int
vtnet_be_parseopts(struct vtnet_be_softc *vbs, char *opts)
{
	char *mac, *input, *token;
	int id, nqs;

	if (opts == NULL)
		return (1);

	mac = NULL;
	vbs->vbs_vm_intf = vbs->vbs_port_intf = NULL;
	vbs->vbs_nqs = 1;
	vbs->vbs_nvqs = 3;
	input = strdup(opts);
	while ((token = strsep(&input, ",")) != NULL) {
		id = strtype(token);
		switch(id) {
			case KW_INTF:
				vbs->vbs_port_intf = tokenval(token);
				break;
			case KW_MTU:
				vbs->vbs_mtu = atoi(tokenval(token));
				assert(vbs->vbs_mtu > 250 &&
					   vbs->vbs_mtu < 16*1024);
				break;
			case KW_MAC:
				mac = tokenval(token);
				break;
			case KW_QUEUES:
				nqs = atoi(tokenval(token));
				vbs->vbs_nqs = min(VB_QUEUES_MAX, max(1, nqs));
				vbs->vbs_nvqs = 2*vbs->vbs_nqs + 1;
				break;
		}
	}
	if (vbs->vbs_port_intf == NULL)
		return (1);
	return (vtnet_be_macaddr(vbs, mac));
}

static int
vtnet_be_clone(struct vtnet_be_softc *vbs)
{
	struct vb_vm_attach va;
	struct ifreq ifr;
	int i, s, flags, err;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t vb_ioctls[] = { SIOCGPRIVATE_0 };
#endif

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		return (errno);
	}
	err = 0;
	vbs->vbs_fd = s;
	bzero(&va, sizeof(va));
	ifr.ifr_data = (caddr_t)&va;

	va.vva_io_start = vbs->vbs_pi->pi_bar[0].addr;
	va.vva_io_size = VTNET_BE_REGSZ;
	va.vva_num_queues = vbs->vbs_nqs;
	va.vva_mtu = vbs->vbs_mtu;
	va.vva_queue_size = 0;	/* accept default */
	strncpy(va.vva_vmparent, vmname, VMNAMSIZ-1);
	strncpy(va.vva_ifparent, vbs->vbs_port_intf, IFNAMSIZ-1);
	memcpy(va.vva_macaddr, vbs->vbs_origmac, ETHER_ADDR_LEN);
	vbs->vbs_vm_intf = NULL;
	for (i = 0; i < VB_VMNIC_MAX; i++) {
		sprintf(ifr.ifr_name, "vmnic%d", i);
		if (ioctl(s, SIOCIFCREATE2, &ifr) == 0) {
			vbs->vbs_vm_intf = strdup(ifr.ifr_name);
			break;
		}
	}
	if (i == VB_VMNIC_MAX)
		return (ENOSPC);

	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		perror("SIOCGIFFLAGS");
		return (errno);
	}

	flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
	flags |= IFF_UP;
	ifr.ifr_flags = flags & 0xffff;
	ifr.ifr_flagshigh = flags >> 16;
#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_IOCTL);
	if (cap_rights_limit(s, &rights) == -1 && errno != ENOSYS)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (cap_ioctls_limit(s, vb_ioctls, nitems(vb_ioctls)) == -1 && errno != ENOSYS)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif
	return (err);
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
	if (pci_emul_add_msixcap(pi, vbs->vbs_nvqs + 1, 1))
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
