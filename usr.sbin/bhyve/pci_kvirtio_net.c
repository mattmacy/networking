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
 * Proxy for the kernel vmnic pseudo device
 *
 * Configuration is
 *
 *  -s <bsd>,kvirtio-net,id=<uuid>
 *
 *    e.g.   -s  2:3:0,kvirtio-net,id=01234567-89ab-cdef-0123-456789abcdef
 *
 * Where uuid is a value associated with host side network object from a
 * previous vpc_open. The attach will fail if the host side network object
 * has not been marked as 'immutable' indicating that the required configuration
 * parameters have been set.
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
#include <sys/cpuset.h>
#include <sys/syscall.h>
#include <sys/endian.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_vpc.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <sysexits.h>
#include <uuid.h>
#include <unistd.h>

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


static int
vpc_open(const vpc_id_t *vpc_id, vpc_type_t obj_type, vpc_flags_t flags)
{
	return syscall(SYS_vpc_open, vpc_id, obj_type, flags);
}

static int
vpc_ctl(int vpcd, vpc_op_t op, size_t keylen, const void *key, size_t *vallen, void *buf)
{
	return syscall(SYS_vpc_ctl, vpcd, op, keylen, key, vallen, buf);
}

#define VTNET_BE_REGSZ		(20 + 4 + 8)	/* virtio + MSI-x + config */

struct vtnet_be_softc {
	struct pci_devinst *vbs_pi;
	int vbs_fd;				/* vpc descriptor for config */
	uint16_t vbs_nqs;
	uint16_t vbs_nvqs;
	vpc_id_t vbs_id;
};

static void
vtnet_be_msix(struct vmctx *ctx, int vcpu, struct pci_devinst *pi, int on)
{
	struct vtnet_be_softc *vbs;
	struct vb_msix *vmsix;
	int i, err, size, nvqs;

	vbs = pi->pi_arg;
	nvqs = vbs->vbs_nvqs;
	size = sizeof(*vmsix) + nvqs*sizeof(struct vb_msix_vector);

	vmsix = malloc(size);
	vmsix->vm_status = on;
	vmsix->vm_count = nvqs;
	if (on) {
		for (i = 0; i < nvqs; i++) {
			vmsix->vm_q[i].msg = pi->pi_msix.table[i].msg_data;
			vmsix->vm_q[i].addr = pi->pi_msix.table[i].addr;
		}
	}
	err = vpc_ctl(vbs->vbs_fd, VPC_VMNIC_OP_MSIX, size, vmsix, NULL, NULL);
	free(vmsix);
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

struct token_value {
	char *token;
	int type;
};

#define KW_ID 0x1
#define KW_MAX KW_ID

struct token_value token_map[] = {
	{"id", KW_ID},
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
	int id, s;
	uint32_t status;
	struct uuid uuidtmp;
	size_t osize;
	uint16_t nqs;
	uint64_t type;
	vpc_handle_type_t *typep;

	if (opts == NULL)
		return (1);

	mac = NULL;
	input = strdup(opts);
	status =  uuid_s_bad_version;
	while ((token = strsep(&input, ",")) != NULL) {
		id = strtype(token);
		switch(id) {
			case KW_ID:
				uuid_from_string(tokenval(token), &uuidtmp, &status);
				if (status != uuid_s_ok)
					return (1);
				uuid_enc_be(&vbs->vbs_id, &uuidtmp);
				break;
			default:
				printf("bad value to kvirtio %s", token);
				return (1);
		}
	}
	type = 0;
	typep = (void *)&type;
	typep->vht_version = 1;
	typep->vht_obj_type = VPC_OBJ_VMNIC;
	type = htobe64(type);
	if ((s = vpc_open(&vbs->vbs_id, type, VPC_F_WRITE|VPC_F_OPEN)) < 0)
		return (1);
	vbs->vbs_fd = s;
	osize = sizeof(nqs);
	if (vpc_ctl(s, VPC_VMNIC_OP_NQUEUES_GET, 0, NULL, &osize, &nqs))
		return (1);
	vbs->vbs_nqs = nqs;
	vbs->vbs_nvqs = 2*nqs + 1;

	return (status != uuid_s_ok);
}

static int
vtnet_be_clone(struct vtnet_be_softc *vbs)
{
	int s;
	struct vb_vm_attach va;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	s = vbs->vbs_fd;
	bzero(&va, sizeof(va));
	va.vva_ioh.vih_magic = VB_MAGIC;
	va.vva_io_start = vbs->vbs_pi->pi_bar[0].addr;
	va.vva_io_size = VTNET_BE_REGSZ;
	strncpy(va.vva_vmparent, vmname, VMNAMSIZ-1);
	if (vpc_ctl(s, VPC_VMNIC_OP_CONNECT, sizeof(va), &va, NULL, NULL))
		return (errno);

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_VPC_READ|CAP_VPC_PRIVWRITE);
	if (cap_rights_limit(s, &rights) == -1 && errno != ENOSYS)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
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
