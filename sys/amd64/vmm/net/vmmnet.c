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
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/socket.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
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


static MALLOC_DEFINE(M_VMMNET, "vmmnet", "vmm networking");


#ifndef _SYS_SYSPROTO_H_
struct vpc_open_args {
	const vpc_id_t *vpc_id;
	vpc_type_t obj_type;
	vpc_flags_t flags;
};
#endif
int
sys_vpc_open(struct thread *td, struct vpc_open_args *uap)
{
	return (ENOSYS);
}

#ifndef _SYS_SYSPROTO_H_
struct vpc_ctl_args {
	int vpcd;
	vpc_op_t op;
	size_t keylen;
	const void *key;
	size_t *vallen;
	void *buf;
};
#endif
int
sys_vpc_ctl(struct thread *td, struct vpc_ctl_args *uap)
{
	return (ENOSYS);
}

static struct sysent vpc_open_sysent = {
	.sy_narg = 3,
	.sy_call = (sy_call_t *)sys_vpc_open,
};

static struct sysent vpc_ctl_sysent = {
	.sy_narg = 6,
	.sy_call = (sy_call_t *)sys_vpc_ctl,
};
	
static int
vmmnet_module_init(void)
{
	int rc, off;
	struct sysent oldent;

	off = SYS_vpc_open;
	rc = syscall_register(&off, &vpc_open_sysent, &oldent, 0);
	if (rc)
		return (rc);
	off = SYS_vpc_ctl;
	rc = syscall_register(&off, &vpc_ctl_sysent, &oldent, 0);
	if (rc) {
		off = SYS_vpc_open;
		syscall_deregister(&off, &oldent);
		return (rc);
	}
	return (0);
}

static void
vmmnet_module_deinit(void)
{
	int off;
	struct sysent oldent;

	off = SYS_vpc_open;
	syscall_deregister(&off, &oldent);
	off = SYS_vpc_ctl;
	syscall_deregister(&off, &oldent);
}


static int
vmmnet_module_event_handler(module_t mod, int what, void *arg)
{
	switch (what) {
		case MOD_LOAD:
			return (vmmnet_module_init());
			break;
		case MOD_UNLOAD:
			vmmnet_module_deinit();
			break;
		default:
			return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t vmmnet_moduledata = {
	"vmmnet",
	vmmnet_module_event_handler,
	NULL
};

DECLARE_MODULE(vmmnet, vmmnet_moduledata, SI_SUB_INIT_IF, SI_ORDER_ANY);
MODULE_VERSION(vmmnet, 1);
MODULE_DEPEND(vmmnet, vpc, 1, 1, 1);
