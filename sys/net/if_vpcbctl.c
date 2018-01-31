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

static MALLOC_DEFINE(M_VPCBCTL, "vpcbctl", "virtual private cloud bridge control");

/*
 * ifconfig vpcb0 create
 * ifconfig vpcb0 addm vpc0
 * ifconfig vpcb0 priority vpc0 200
 * ifconfig vpcb0 vpc-resolver 127.0.0.1:5000
 * ifconfig vpcb0 addm vmi7
 * ifconfig vpcb0 pathcost vmi7 2000000
 */

static int open_count = 0;

static d_ioctl_t vpcbctl_ioctl;
static d_open_t vpcbctl_open;
static d_close_t vpcbctl_close;

static struct cdevsw vpcbctl_cdevsw = {
       .d_version =    D_VERSION,
       .d_flags =      0,
       .d_open =       vpcbctl_open,
       .d_close =      vpcbctl_close,
       .d_ioctl =      vpcbctl_ioctl,
       .d_name =       "vpcbctl",
};

static int
vpcbctl_open(struct cdev *dev, int flags, int fmp, struct thread *td)
{
	atomic_add_int(&open_count, 1);
	return (0);
}

static int
vpcbctl_close(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	atomic_add_int(&open_count, -1);
	return (0);
}


static int
vpcb_poll_dispatch(struct vpcb_request *vr)
{
	uint32_t randval, opcode;
	static int calls = 0;
	uint8_t *eth;

	randval = arc4random();
	
	if (calls++ & 1)
		tsleep(&calls, PCATCH, "vpcb_poll", (randval % 30)*hz);

	opcode = (randval % 3) + 1;
	vr->vrq_header.voh_version = VPCB_VERSION;
	vr->vrq_header.voh_op = opcode;
	vr->vrq_context.voc_vni = 150;
	vr->vrq_context.voc_vlanid = 0; 
	eth = vr->vrq_context.voc_smac;
	eth[0] = 0x58;
	eth[1] = 0x9C;
	eth[2] = 0xFC;
	eth[3] = 0x1;
	eth[4] = 0x2;
	eth[5] = 0x3;
	switch (opcode) {
		case VPCB_REQ_NDv4:
			return (inet_pton(AF_INET, "192.168.1.10",
							  &vr->vrq_data.vrqd_ndv4.target));
			break;
		case VPCB_REQ_NDv6:
			return (inet_pton(AF_INET6, "fe80::2bd:44ff:fede:7e09%zt97bteb5hu3748",
							  &vr->vrq_data.vrqd_ndv6.target));
			break;
		case VPCB_REQ_DHCPv4:
		case VPCB_REQ_DHCPv6:
			/* just use smac */
			break;
	};
	return (0);
}

static int 
vpcb_response_dispatch(unsigned long cmd, struct vpcb_response *vrs)
{
	return (0);
}

static int
vpcbctl_ioctl(struct cdev *dev, unsigned long cmd, caddr_t data,
    int fflag, struct thread *td)
{
	if (priv_check(td, PRIV_DRIVER))
		return (EPERM);

	switch (cmd) {
		case VPCB_POLL:
			return (vpcb_poll_dispatch((struct vpcb_request *)data));
			break;
		case VPCB_RESPONSE_NDv4:
		case VPCB_RESPONSE_NDv6:
		case VPCB_RESPONSE_DHCPv4:
		case VPCB_RESPONSE_DHCPv6:
			return (vpcb_response_dispatch(cmd, (struct vpcb_response *)data));
			break;
	}
	return (0);
}

static struct cdev *vpcbdev;

static int
vpcbctl_module_init(void)
{
	vpcbdev = make_dev(&vpcbctl_cdevsw, 0 /* unit no */,
					   UID_ROOT, GID_VPC, 0660, "%s", "vpcbctl");
	if (vpcbdev == NULL)
		return (ENOMEM);
	return (0);
}

static int
vpcbctl_module_deinit(void)
{

	destroy_dev(vpcbdev);
	return (0);
}

static int
vpcbctl_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
		case MOD_LOAD:
			if ((err = vpcbctl_module_init()) != 0)
				return (err);
			break;
		case MOD_UNLOAD:
			if (open_count == 0)
				vpcbctl_module_deinit();
			else
				return (EBUSY);
			break;
		default:
			return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t vpcbctl_moduledata = {
	"vpcbctl",
	vpcbctl_module_event_handler,
	NULL
};

DECLARE_MODULE(vpc, vpcbctl_moduledata, SI_SUB_INIT_IF, SI_ORDER_ANY);
MODULE_VERSION(vpcbctl, 1);

