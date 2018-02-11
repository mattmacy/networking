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
#include <sys/conf.h>
#include <sys/eventhandler.h>
#include <sys/sockio.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/priv.h>
#include <sys/mutex.h>
#include <sys/module.h>
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
#include <net/if_vlan_var.h>
#include <net/iflib.h>
#include <net/if.h>
#include <net/if_clone.h>

#include <net/if_vpc.h>

#include "ifdi_if.h"

static MALLOC_DEFINE(M_VPCSWCTL, "vpcswctl", "virtual private cloud bridge control");

/*
 * ifconfig vpcsw0 create
 * ifconfig vpcsw0 addm vpc0
 * ifconfig vpcsw0 priority vpc0 200
 * ifconfig vpcsw0 vpc-resolver 127.0.0.1:5000
 * ifconfig vpcsw0 addm vmi7
 * ifconfig vpcsw0 pathcost vmi7 2000000
 */

static int open_count = 0;

static d_ioctl_t vpcswctl_ioctl;
static d_open_t vpcswctl_open;
static d_close_t vpcswctl_close;

static struct cdevsw vpcswctl_cdevsw = {
       .d_version =    D_VERSION,
       .d_flags =      0,
       .d_open =       vpcswctl_open,
       .d_close =      vpcswctl_close,
       .d_ioctl =      vpcswctl_ioctl,
       .d_name =       "vpcswctl",
};

static int
vpcswctl_open(struct cdev *dev, int flags, int fmp, struct thread *td)
{
	atomic_add_int(&open_count, 1);
	return (0);
}

static int
vpcswctl_close(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	atomic_add_int(&open_count, -1);
	return (0);
}

static const char *opcode_map[] = {
	"",
	"VPCSW_REQ_NDv4",
	"VPCSW_REQ_NDv6",
	"VPCSW_REQ_DHCPv4",
	"VPCSW_REQ_DHCPv6",
};

static int
vpcsw_poll_dispatch(struct vpcsw_request *vr)
{
	static int calls = 0;
	uint32_t randval, opcode;
	int rc;
	uint8_t *eth;

	randval = arc4random();
	rc = 0;

	if (calls++ & 1) {
		printf("blocking for %d seconds\n", randval % 30);
		tsleep(&calls, PCATCH, "vpcsw_poll", (randval % 30)*hz);
	}
	opcode = (randval % 3) + 1;
	vr->vrq_header.voh_version = VPCSW_VERSION;
	vr->vrq_header.voh_op = opcode;
	vr->vrq_context.voc_vni = 150;
	vr->vrq_context.voc_vlanid = 0; 
	printf("version: %x opcode: %s vni: %d vlanid: %d\n",
		   VPCSW_VERSION, opcode_map[opcode], 150, 0);
	eth = vr->vrq_context.voc_smac;
	eth[0] = 0x58;
	eth[1] = 0x9C;
	eth[2] = 0xFC;
	eth[3] = 0x1;
	eth[4] = 0x2;
	eth[5] = 0x3;
	switch (opcode) {
		case VPCSW_RESPONSE_NDv4:
			 rc = inet_pton(AF_INET, "192.168.1.10",
							&vr->vrq_data.vrqd_ndv4.target);
			 break;
		case VPCSW_RESPONSE_NDv6:
			rc = inet_pton(AF_INET6, "fe80::2bd:44ff:fede:7e09%zt97bteb5hu3748",
						   &vr->vrq_data.vrqd_ndv6.target);

		case VPCSW_RESPONSE_DHCPv4:
		case VPCSW_RESPONSE_DHCPv6:
			break;
	}
	return (rc);
}

static int 
vpcsw_response_dispatch(unsigned long cmd, struct vpcsw_response *vrs)
{
	if (vrs->vrs_header.voh_op < 1 ||
		vrs->vrs_header.voh_op > VPCSW_REQ_MAX) {
		printf("invalid opcode %d\n",
			   vrs->vrs_header.voh_op);
		return (EINVAL);
	}
	if (vrs->vrs_header.voh_version != VPCSW_VERSION) {
		printf("invalid version %d\n",
			   vrs->vrs_header.voh_version);
		return (EINVAL);
	}
	printf("version: %x opcode: %s vni: %d vlanid: %d\n",
		   vrs->vrs_header.voh_version,
		   opcode_map[vrs->vrs_header.voh_op],
		   vrs->vrs_context.voc_vni,
		   vrs->vrs_context.voc_vlanid);
	switch (cmd) {
		case VPCSW_RESPONSE_NDv6:
		case VPCSW_RESPONSE_NDv4:
			printf("data: %6D", vrs->vrs_data.vrsd_ndv4.ether_addr, ":");
			break;
		case VPCSW_RESPONSE_DHCPv4:
		case VPCSW_RESPONSE_DHCPv6:
			break;
	}
	return (0);
}

static int
vpcswctl_ioctl(struct cdev *dev, unsigned long cmd, caddr_t data,
    int fflag, struct thread *td)
{

	switch (cmd) {
		case VPCSW_POLL:
			return (vpcsw_poll_dispatch((struct vpcsw_request *)data));
			break;
		case VPCSW_RESPONSE_NDv4:
		case VPCSW_RESPONSE_NDv6:
		case VPCSW_RESPONSE_DHCPv4:
		case VPCSW_RESPONSE_DHCPv6:
			return (vpcsw_response_dispatch(cmd, (struct vpcsw_response *)data));
			break;
	}
	return (0);
}

static struct cdev *vpcswdev;

static int
vpcswctl_module_init(void)
{
	vpcswdev = make_dev(&vpcswctl_cdevsw, 0 /* unit no */,
					   UID_ROOT, GID_VPC, 0660, "%s", "vpcswctl");
	if (vpcswdev == NULL)
		return (ENOMEM);
	return (0);
}

static int
vpcswctl_module_deinit(void)
{

	destroy_dev(vpcswdev);
	return (0);
}

static int
vpcswctl_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
		case MOD_LOAD:
			if ((err = vpcswctl_module_init()) != 0)
				return (err);
			break;
		case MOD_UNLOAD:
			if (open_count == 0)
				vpcswctl_module_deinit();
			else
				return (EBUSY);
			break;
		default:
			return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t vpcswctl_moduledata = {
	"vpcswctl",
	vpcswctl_module_event_handler,
	NULL
};

DECLARE_MODULE(vpc, vpcswctl_moduledata, SI_SUB_INIT_IF, SI_ORDER_ANY);
MODULE_VERSION(vpcswctl, 1);

