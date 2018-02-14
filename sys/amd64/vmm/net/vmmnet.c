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
#include <sys/capsicum.h>
#include <sys/conf.h>
#include <sys/eventhandler.h>
#include <sys/sockio.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
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
#include <sys/syslimits.h>
#include <sys/queue.h>
#include <sys/uuid.h>

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
static art_tree vpc_uuid_table;

static struct sx vmmnet_lock;


SX_SYSINIT(vmmnet, &vmmnet_lock, "vmmnet global");

#define VMMNET_LOCK() sx_xlock(&vmmnet_lock)
#define VMMNET_UNLOCK() sx_xunlock(&vmmnet_lock)

#define VPC_CTX_F_DESTROYED 0x1

struct vpcctx {
	struct ifnet *v_ifp;
	vpc_id_t v_id;
	volatile u_int v_refcnt;
	uint32_t v_flags;
};
typedef struct {
	uint64_t vht_version:4;
	uint64_t vht_pad1:4;
	uint64_t vht_obj_type:8;
	uint64_t vht_pad2:48;
} vpc_handle_type_t;

static fo_close_t vpcd_close;
static fo_stat_t vpcd_stat;
static fo_fill_kinfo_t vpcd_fill_kinfo;
static fo_poll_t vpcd_poll;
static fo_ioctl_t vpcd_ioctl;

struct fileops vpcd_fileops  = {
	.fo_close = vpcd_close,
	.fo_stat = vpcd_stat,
	.fo_fill_kinfo = vpcd_fill_kinfo,
	.fo_poll = vpcd_poll,
	.fo_ioctl = vpcd_ioctl,
	.fo_flags = DFLAG_PASSABLE,
};


static int
vpcd_close(struct file *fp, struct thread *td)
{
	struct vpcctx *ctx;

	if ((ctx = fp->f_data) == NULL)
		return (0);
	if (refcount_release(&ctx->v_refcnt) == 0) {
		VMMNET_LOCK();
		art_delete(&vpc_uuid_table, (const char *)&ctx->v_id);
		VMMNET_UNLOCK();
		if_rele(ctx->v_ifp);
		if_clone_destroy(ctx->v_ifp->if_xname);
		free(ctx, M_VMMNET);
	}
	return (0);
}

static int
vpcd_stat(struct file *fp, struct stat *st, struct ucred *active_cred,
    struct thread *td)
{
	return (ENXIO);
}

static int
vpcd_fill_kinfo(struct file *fp, struct kinfo_file *kif, struct filedesc *fdp)
{

	kif->kf_type = KF_TYPE_UNKNOWN;
	return (0);
}

static int
vpcd_poll(struct file *fp, int events, struct ucred *active_cred,
    struct thread *td)
{
	return (ENXIO);
}

static int
vpcd_ioctl(struct file *fp, u_long cmd, void *data,
    struct ucred *active_cred, struct thread *td)
{
	return (ENXIO);
}
char *if_names[] = {
	"NONE",
	"vpcsw",
	"vpcp",
	"vpcr",
	"vpcnat",
	"vpclink",
	"vmnic",
};

static int
kern_vpc_open(struct thread *td, const vpc_id_t *vpc_id,
			  vpc_type_t obj_type, vpc_flags_t flags,
			  int *vpcd)
{
	struct filedesc *fdp;
	struct file *fp;
	struct vpcctx *ctx;
	struct ifnet *ifp;
	vpc_handle_type_t *type;
	char buf[IFNAMSIZ];
	int rc, fflags, fd;

	type = (vpc_handle_type_t*)&obj_type;
	if (type->vht_obj_type == 0 || type->vht_obj_type > VPC_OBJ_MAX)
		return (EINVAL);

	if (((flags & (VPC_F_CREATE|VPC_F_OPEN)) == 0) ||
		(flags & (VPC_F_CREATE|VPC_F_OPEN)) == (VPC_F_CREATE|VPC_F_OPEN))
		return (EINVAL);

	VMMNET_LOCK();
	ctx = art_search(&vpc_uuid_table, (const unsigned char *)vpc_id);
	if ((flags & VPC_F_CREATE) && (ctx != NULL)) {
		rc = EEXIST;
		goto unlock;
	}
	if (flags & VPC_F_OPEN) {
		if (ctx == NULL) {
			rc = ENOENT;
			goto unlock;
		}
		refcount_acquire(&ctx->v_refcnt);
	} else {
		ctx = malloc(sizeof(*ctx), M_VMMNET, M_WAITOK);
		strncpy(buf, if_names[type->vht_obj_type], IFNAMSIZ-1);
		rc = if_clone_create(buf, sizeof(buf), NULL);
		if (rc)
			goto unlock;
		if ((ifp = ifunit_ref(buf)) == NULL) {
			if (bootverbose)
				printf("couldn't reference %s\n", buf);
			if_clone_destroy(buf);
			rc = ENXIO;
			goto unlock;
		}
		/*
		 * One reference for ART and one for descriptor
		 */
		refcount_init(&ctx->v_refcnt, 2);
		ctx->v_ifp = ifp;
		memcpy(&ctx->v_id, vpc_id, sizeof(*vpc_id));
		art_insert(&vpc_uuid_table, (const char *)vpc_id, ctx);
	}

	fflags = O_CLOEXEC;
	fdp = td->td_proc->p_fd;
	rc = falloc(td, &fp, &fd, fflags);
	if (rc) {
		if (flags & VPC_F_CREATE) {
			if_rele(ifp);
			if_clone_destroy(buf);
			art_delete(&vpc_uuid_table, (const char *)vpc_id);
			free(ctx, M_VMMNET);
		} else
			refcount_release(&ctx->v_refcnt);
		goto unlock;
	}
	finit(fp, fflags, DTYPE_VPCFD, ctx, &vpcd_fileops);
	fdrop(fp, td);
	td->td_retval[0] = fd;
 unlock:
	VMMNET_UNLOCK();
	return (rc);
}

static int
kern_vpc_ctl(struct thread *td, int vpcd, vpc_op_t op, size_t keylen,
			 const void *key, size_t *vallen, void **buf, bool *docopy)
{
	cap_rights_t rights;
	struct file *fp;
	struct vpcctx *ctx;
	int rc;

	if (op == 0 || op > VPC_OP_MAX)
		return (EOPNOTSUPP);

	if (fget(td, vpcd, cap_rights_init(&rights, CAP_VPC_CTL), &fp) != 0)
		return (EBADF);
	if ((fp->f_type != DTYPE_VPCFD) ||
		(fp->f_data == NULL)) {
		fdrop(fp, td);
		return (EBADF);
	}
	ctx = fp->f_data;
	rc = 0;
	switch (op) {
		case VPC_OP_DESTROY:
			ctx->v_flags |= VPC_CTX_F_DESTROYED;
			refcount_release(&ctx->v_refcnt);
			break;
		case VPC_OP_INVALID:
		default:
			rc = ENOTSUP;
			break;
	}
	fdrop(fp, td);
	return (rc);
}

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
	vpc_id_t *vpc_id;
	int rc, vpcd;

	vpc_id = malloc(sizeof(*vpc_id), M_TEMP, M_WAITOK);
	if (copyin(vpc_id, (void*)(uintptr_t)uap->vpc_id, sizeof(*vpc_id)))
		return (EFAULT);
	rc = kern_vpc_open(td, vpc_id, uap->obj_type, uap->flags, &vpcd);
	if (rc)
		goto done;
	td->td_retval[0] = vpcd;
	td->td_retval[1] = 0;
 done:
	free(vpc_id, M_TEMP);
	return (rc);
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
	size_t vlen;
	void *value, *keyp;
	bool docopy;
	int rc;

	if (uap->keylen > ARG_MAX)
		return (E2BIG);

	value = NULL;
	vlen = 0;
	docopy = false;
	keyp = malloc(uap->keylen, M_TEMP, M_WAITOK);
	if (copyin(keyp, (void *)(uintptr_t)uap->key, uap->keylen)) {
		free(keyp, M_TEMP);
		return (EFAULT);
	}
	if (uap->buf != NULL) {
		if (copyin(&vlen, uap->vallen, sizeof(vlen)))
			return (EFAULT);
		if (vlen > ARG_MAX)
			return (E2BIG);
		value = malloc(vlen, M_TEMP, M_WAITOK);
		if ((rc = copyin(value, uap->buf, vlen)))
			goto done;
	}
	rc = kern_vpc_ctl(td, uap->vpcd, uap->op, uap->keylen, keyp, &vlen, &value, &docopy);
	if (!rc && docopy) {
		if ((rc = copyout(&vlen, uap->vallen, sizeof(vlen))))
			goto done;
		if ((rc = copyout(value, uap->buf, vlen)))
			goto done;
	}
 done:
	free(keyp, M_TEMP);
	free(value, M_TEMP);
	return (rc);
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
	art_tree_init(&vpc_uuid_table, sizeof(vpc_id_t));
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
