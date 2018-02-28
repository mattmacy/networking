/*
 * Copyright (C) 2018 Matthew Macy <matt.macy@joyent.com>
 * Copyright (C) 2018 Joyent Inc.
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
#include <sys/endian.h>

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
#define VPC_CTX_F_COMMITTED 0x2

struct vpcctx {
	struct ifnet *v_ifp;
	vpc_type_t v_obj_type;
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

static struct fileops vpcd_fileops  = {
	.fo_close = vpcd_close,
	.fo_stat = vpcd_stat,
	.fo_fill_kinfo = vpcd_fill_kinfo,
	.fo_poll = vpcd_poll,
	.fo_ioctl = vpcd_ioctl,
	.fo_flags = DFLAG_PASSABLE,
};

static int
vpcd_print_uuid_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	MPASS(key_len == sizeof(vpc_id_t));

	printf("%16D\n", key, ":");
	return (0);
}

struct typecount_info {
	uint32_t type;
	uint32_t count;
};

static int
vpcd_typecount_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct typecount_info  *ti = data;
	struct vpcctx *ctx = value;

	if (ti->type == ctx->v_obj_type || ti->type == VPC_OBJ_TYPE_ANY)
		ti->count++;
	return (0);
}


struct objget_info {
	caddr_t ptr;
	uint32_t max_count;
	uint32_t count;
	uint16_t type;
	/* pad ?*/
};

#ifdef notyet
static int
vpcd_objget_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct objget_info  *oi = data;
	struct vpcctx *ctx = value;
	vpc_obj_info_t *voi;

	if (oi->type != ctx->v_obj_type && oi->type != VPC_OBJ_TYPE_ANY)
		return (0);
	if (oi->count == oi->max_count)
		return (ENOSPC);
}
#endif

static int
vpcd_hdrget_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct objget_info  *oi = data;
	struct vpcctx *ctx = value;
	vpc_obj_header_t *voh;


	if (oi->type != ctx->v_obj_type && oi->type != VPC_OBJ_MGMT)
		return (0);
	if (oi->count == oi->max_count)
		return (ENOSPC);
	voh = (void *)oi->ptr;
	voh->voh_type = ctx->v_obj_type;
	memcpy(&voh->voh_id, key, sizeof(vpc_id_t));
	oi->count++;
	oi->ptr += sizeof(*voh);
	return (0);
}

static void
vpcd_print_uuids(void)
{
	VMMNET_LOCK();
	art_iter(&vpc_uuid_table, vpcd_print_uuid_callback, NULL);
	VMMNET_UNLOCK();
}

static int
vpcd_close(struct file *fp, struct thread *td)
{
	struct vpcctx *ctx, *value;

	if ((ctx = fp->f_data) == NULL)
		return (0);
	fp->f_data = NULL;
	if (ctx->v_obj_type == VPC_OBJ_PORT)
		return (0);
	VMMNET_LOCK();
	if (refcount_release(&ctx->v_refcnt)) {
		value = art_delete(&vpc_uuid_table, (const char *)&ctx->v_id);

#ifdef INVARIANTS
		if (ctx->v_obj_type != VPC_OBJ_MGMT && value != ctx) {
			printf("%16D  --- vpc_id not found\n", &ctx->v_id, ":");
			vpcd_print_uuids();
		}
#endif
		/* run object dtor */
		if (ctx->v_ifp)
			if_clone_destroy(ctx->v_ifp->if_xname);
		free(ctx, M_VMMNET);
	}
	VMMNET_UNLOCK();
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

static char *if_names[] = {
	"NONE",
	"vpcsw",
	"vpcp",
	"vpcrtr",
	"vpcnat",
	"vpclink",
	"vmnic",
	"NONE",
	"l2link",
	"NONE",
	"NONE"
};

int
vmmnet_insert(const vpc_id_t *id, if_t ifp, vpc_type_t type)
{
	struct vpcctx *ctx;

	sx_assert(&vmmnet_lock, SA_XLOCKED);
	if (art_search(&vpc_uuid_table, (const char*)id) != NULL) {
		if (bootverbose)
			printf("%s can't add %16D -- already in vpc_uuid_table\n",
				   __func__, id, ":");
		return (EEXIST);
	}
	ctx = malloc(sizeof(*ctx), M_VMMNET, M_WAITOK|M_ZERO);
	if_ref(ifp);
	ctx->v_ifp = ifp;
	memcpy(&ctx->v_id, id, sizeof(*id));
	ctx->v_obj_type = type;
	refcount_init(&ctx->v_refcnt, 1);
	art_insert(&vpc_uuid_table, (const char *)id, ctx);
	return (0);
}

vpc_ctx_t
vmmnet_lookup(const vpc_id_t *id)
{

	sx_assert(&vmmnet_lock, SA_XLOCKED);
	return ((vpc_ctx_t)art_search(&vpc_uuid_table, (const char*)id));
}

vpc_ctx_t
vmmnet_delete(const vpc_id_t *id)
{

	sx_assert(&vmmnet_lock, SA_XLOCKED);
	return ((vpc_ctx_t)art_delete(&vpc_uuid_table, (const char*)id));
}

static int
kern_vpc_open(struct thread *td, const vpc_id_t *vpc_id,
			  vpc_type_t obj_type_full, vpc_flags_t flags,
			  int *vpcd)
{
	struct filedesc *fdp;
	struct file *fp;
	struct vpcctx *ctx;
	struct ifnet *ifp;
	vpc_handle_type_t *type;
	char buf[IFNAMSIZ];
	int rc, fflags, fd;
	uint8_t obj_type;

	type = (vpc_handle_type_t*)&obj_type_full;
	obj_type = type->vht_obj_type;
	ifp = NULL;
	if (ETHER_IS_MULTICAST(vpc_id->node))
		return (EADDRNOTAVAIL);
	if (obj_type == 0 || obj_type > VPC_OBJ_TYPE_MAX ||
		obj_type == VPC_OBJ_META || obj_type == VPC_OBJ_TYPE_ANY) {
		printf("obj_type=%d\n", obj_type);
		return (ENOPROTOOPT);
	}
	if ((flags & (VPC_F_CREATE|VPC_F_OPEN)) == 0)
		return (EINVAL);
	if ((flags & (VPC_F_CREATE|VPC_F_OPEN)) == (VPC_F_CREATE|VPC_F_OPEN))
		return (EINVAL);
	if ((flags & VPC_F_CREATE) && (obj_type != VPC_OBJ_MGMT) &&
		(priv_check(td, PRIV_DRIVER) != 0))
		return (EPERM);
	VMMNET_LOCK();
	ctx = art_search(&vpc_uuid_table, (const unsigned char *)vpc_id);
	if ((flags & VPC_F_CREATE) && (ctx != NULL)) {
		rc = EEXIST;
		goto unlock;
	}
	if ((flags & VPC_F_CREATE) && (obj_type == VPC_OBJ_PORT)) {
		rc = ENODEV;
		goto unlock;
	}
	if (flags & VPC_F_OPEN) {
		if (ctx == NULL) {
			rc = ENOENT;
			goto unlock;
		}
		if (ctx->v_obj_type != obj_type) {
			rc = ENODEV;
			goto unlock;
		}
		refcount_acquire(&ctx->v_refcnt);
	} else {
		ctx = malloc(sizeof(*ctx), M_VMMNET, M_WAITOK|M_ZERO);

		if (obj_type != VPC_OBJ_MGMT) {
			strncpy(buf, if_names[obj_type], IFNAMSIZ-1);
			rc = if_clone_create(buf, sizeof(buf), NULL);
			if (rc) {
				printf("if_clone_create with %s failed with %d\n",
					   buf, rc);
				goto unlock;
			}
			if ((ifp = ifunit_ref(buf)) == NULL) {
				if (bootverbose)
					printf("couldn't reference %s\n", buf);
				if_clone_destroy(buf);
				free(ctx, M_VMMNET);
				rc = ENXIO;
				goto unlock;
			}
		}
		/*
		 * One reference for ART and one for descriptor
		 */
		refcount_init(&ctx->v_refcnt, 1);
		ctx->v_ifp = ifp;
		ctx->v_obj_type = obj_type;
		memcpy(&ctx->v_id, vpc_id, sizeof(*vpc_id));
		if (priv_check(td, PRIV_DRIVER) == 0) {
			art_insert(&vpc_uuid_table, (const char *)vpc_id, ctx);
#ifdef INVARIANTS
			{
				struct vpcctx *tmpctx = art_search(&vpc_uuid_table, (const char *)vpc_id);

				MPASS(tmpctx != NULL);
				MPASS(tmpctx == ctx);
			}
#endif
		}
	}

	fflags = O_CLOEXEC;
	if (flags & VPC_F_WRITE)
		fflags |= FWRITE;
	if (priv_check(td, PRIV_DRIVER) == 0)
		fflags |= O_APPEND;

	fdp = td->td_proc->p_fd;
	rc = falloc(td, &fp, &fd, fflags);
	if (rc) {
		if (flags & VPC_F_CREATE) {
			if (ifp) {
				if_rele(ifp);
				if_clone_destroy(buf);
			}
			if (priv_check(td, PRIV_DRIVER) == 0)
				art_delete(&vpc_uuid_table, (const char *)vpc_id);
			free(ctx, M_VMMNET);
		} else
			refcount_release(&ctx->v_refcnt);
		goto unlock;
	}
	if ((flags & VPC_F_CREATE) &&
		(ctx->v_ifp != NULL)) {
		if_ctx_t ifctx;
		int macrc;

		ifctx = ctx->v_ifp->if_softc;
		macrc = iflib_set_mac(ifctx, vpc_id->node);
		if (macrc && bootverbose)
			printf("set_mac failed: %d\n", macrc);
	}
	finit(fp, fflags, DTYPE_VPCFD, ctx, &vpcd_fileops);
	*vpcd = fd;
 unlock:
	VMMNET_UNLOCK();
	if (rc == 0)
		fdrop(fp, td);
	return (rc);
}

static int
vpcnat_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
				 size_t *outlen, void **outdata)
{
	return (EOPNOTSUPP);
}

int
vpcrtr_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t inlen, const void *in,
				 size_t *outlen, void **outdata)
{
	return (EOPNOTSUPP);
}


static int
vpcmgmt_ctl(vpc_ctx_t ctx, vpc_op_t op, size_t innbyte, const void *in,
				 size_t *outnbyte, void **outp)
{
	int rc = 0;

	switch (op) {
		case VPC_OBJ_OP_TYPE_COUNT_GET: {
			const uint16_t *qtype = in;
			uint16_t *typecount;
			struct typecount_info ti;

			if (innbyte != sizeof(uint16_t))
				return (EBADRPC);
			if (*outnbyte < sizeof(uint32_t))
				return (EOVERFLOW);

			ti.type = *qtype;
			*outnbyte = sizeof(uint16_t);
			typecount = malloc(sizeof(uint16_t), M_TEMP, M_WAITOK);
			ti.count = 0;
			VMMNET_LOCK();
			art_iter(&vpc_uuid_table, vpcd_typecount_callback, &ti);
			VMMNET_UNLOCK();
			*typecount = ti.count;
			*outp = typecount;
		}
		case VPC_OBJ_OP_HDR_GET_ALL: {
			const uint16_t *qtype = in;
			struct objget_info oi;

			if (innbyte != sizeof(uint16_t))
				return (EBADRPC);
			if (*outnbyte < sizeof(vpc_obj_header_t))
				return (EOVERFLOW);

			oi.type = *qtype;
			oi.count = 0;
			oi.max_count = *outnbyte/sizeof(vpc_obj_header_t);
			oi.ptr = malloc(*outnbyte, M_TEMP, M_WAITOK);
			VMMNET_LOCK();
			rc = art_iter(&vpc_uuid_table, vpcd_hdrget_callback, &oi);
			VMMNET_UNLOCK();
			*outnbyte = oi.count*sizeof(vpc_obj_header_t);
			*outp = oi.ptr;
		}
		default:
			rc = ENOTSUP;
			break;
	}
	return (rc);
}

static vpc_ctl_fn vpc_ctl_dispatch[] = {
	NULL,
	vpcsw_ctl,
	vpcp_ctl,
	vpcrtr_ctl,
	vpcnat_ctl,
	vpclink_ctl,
	vmnic_ctl,
	vpcmgmt_ctl,
	l2link_ctl
};
static int
kern_vpc_ctl(struct thread *td, int vpcd, vpc_op_t op, size_t innbyte,
			 const void *in, size_t *outnbyte, void **outp)
{
	struct ifnet *ifp;
	cap_rights_t rights;
	struct file *fp;
	vpc_op_t objop;
	vpc_type_t objtype;
	struct vpcctx *ctx;
	uint64_t caps;
	int rc;

	objtype = VPC_OBJ_TYPE(op);
	objop = VPC_OBJ_OP(op);
	rc = 0;
	if (objtype == 0 || objtype > VPC_OBJ_TYPE_MAX)
		return (EOPNOTSUPP);

	caps = CAP_VPC_READ;
	if (op & IOC_PRIVMUT)
		caps |= CAP_VPC_PRIVWRITE;
	else if (op & IOC_PRIV)
		caps |= CAP_VPC_PRIVREAD;
	else if (op & IOC_MUT)
		caps |= CAP_VPC_WRITE;

	if (fget(td, vpcd, cap_rights_init(&rights, caps), &fp) != 0)
		return (EBADF);
	if ((fp->f_type != DTYPE_VPCFD) ||
		(fp->f_data == NULL)) {
		rc = EBADF;
		goto done;
	}
	ctx = fp->f_data;
	if ((objtype != VPC_OBJ_META) && (ctx->v_obj_type != objtype)) {
		rc = ENODEV;
		goto done;
	}
	if ((op & IOC_PRIV) && ((fp->f_flag & O_APPEND) == 0)) {
		rc = EPERM;
		goto done;
	}
	if ((op & IOC_MUT) && ((fp->f_flag & FWRITE) == 0)) {
		rc = EPERM;
		goto done;
	}
	if (objtype != VPC_OBJ_META) {
		VMMNET_LOCK();
		rc = vpc_ctl_dispatch[objtype]((vpc_ctx_t)ctx, op, innbyte, in, outnbyte, outp);
		VMMNET_UNLOCK();
		goto done;
	}

	ifp = ctx->v_ifp;
	switch (op) {
		case VPC_OBJ_OP_DESTROY:
			if ((ctx->v_flags & (VPC_CTX_F_DESTROYED|VPC_CTX_F_COMMITTED)) !=
				VPC_CTX_F_COMMITTED) {
				rc = EAGAIN;
				goto done;
			}
			ctx->v_flags |= VPC_CTX_F_DESTROYED;
			rc = refcount_release(&ctx->v_refcnt);
			MPASS(rc == 0);
			break;
		case VPC_OBJ_OP_COMMIT:
			if (ctx->v_flags & (VPC_CTX_F_DESTROYED|VPC_CTX_F_COMMITTED)) {
				rc = EALREADY;
				goto done;
			}
			ctx->v_flags |= VPC_CTX_F_COMMITTED;
			refcount_acquire(&ctx->v_refcnt);
			break;
		case VPC_OBJ_OP_TYPE_GET: {
			uint8_t *typep;

			*outnbyte = 1;
			typep = malloc(sizeof(uint8_t), M_TEMP, M_WAITOK);
			*typep = ctx->v_obj_type;
			break;
		}
		case VPC_OBJ_OP_MAC_SET: {
			if_ctx_t ifctx;
			const uint8_t *mac = in;

			if ((ctx->v_obj_type == VPC_OBJ_L2LINK) ||
				(innbyte != ETHER_ADDR_LEN)) {
				rc = EBADRPC;
				goto done;
			}
			ifctx = ifp->if_softc;
			iflib_set_mac(ifctx, mac);
			break;
		}
		case VPC_OBJ_OP_MAC_GET: {
			struct sockaddr_dl *sdl;
			uint8_t *mac;

			if (ctx->v_ifp == NULL) {
				rc = EINPROGRESS;
				goto done;
			}
			if (*outnbyte < ETHER_ADDR_LEN) {
				rc = EOVERFLOW;
				goto done;
			}
			*outnbyte = ETHER_ADDR_LEN;
			mac = malloc(ETHER_ADDR_LEN, M_TEMP, M_WAITOK);
			sdl = (struct sockaddr_dl *)ifp->if_addr->ifa_addr;
			MPASS(sdl->sdl_type == IFT_ETHER);
			memcpy(mac, LLADDR(sdl), ETHER_ADDR_LEN);
			break;
		}
		case VPC_OBJ_OP_MTU_SET: {
			if_ctx_t ifctx;
			const uint32_t *mtu = in;

			if (innbyte != sizeof(uint32_t)) {
				rc = EBADRPC;
				goto done;
			}
			ifctx = ifp->if_softc;
			iflib_set_mtu(ifctx, *mtu);
			break;
		}
		case VPC_OBJ_OP_MTU_GET: {
			uint32_t *mtu;

			if (ifp == NULL) {
				rc = EINPROGRESS;
				goto done;
			}
			if (*outnbyte < sizeof(uint32_t)) {
				rc = EOVERFLOW;
				goto done;
			}
			*outnbyte = sizeof(uint32_t);
			mtu = malloc(*outnbyte, M_TEMP, M_WAITOK);
			*mtu = ifp->if_mtu;
			break;
		}
		case VPC_OBJ_OP_ID_GET: {
			vpc_id_t *id;

			if (*outnbyte < sizeof(*id)) {
				rc = EOVERFLOW;
				goto done;
			}
			*outnbyte = sizeof(*id);
			id = malloc(sizeof(*id), M_TEMP, M_WAITOK);
			memcpy(id, &ctx->v_id, sizeof(*id));
			break;
		}
		default:
			rc = ENOTSUP;
			break;
	}
 done:
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
	if (copyin(uap->vpc_id, vpc_id, sizeof(*vpc_id)))
		return (EFAULT);
	if (bootverbose)
		printf("%s vpc_id: %16D\n", __func__, vpc_id, ":");
	rc = kern_vpc_open(td, vpc_id, htobe64(uap->obj_type), uap->flags, &vpcd);
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
	size_t innbyte;
	const void *in;
	size_t *outnbyte;
	void *out;
};
#endif

int
sys_vpc_ctl(struct thread *td, struct vpc_ctl_args *uap)
{
	size_t koutlen;
	void *kout, *kin;
	vpc_type_t objtype;
	int rc;

	if (uap->innbyte > ARG_MAX)
		return (E2BIG);

	kin = kout = NULL;
	objtype = VPC_OBJ_TYPE(uap->op);
	koutlen = 0;
	if (objtype == 0 || objtype > VPC_OBJ_TYPE_MAX)
		return (ENXIO);
	if (uap->op & IOC_IN) {
		if (uap->innbyte == 0)
			return (EFAULT);
		kin = malloc(uap->innbyte, M_TEMP, M_WAITOK);
		if (copyin(uap->in, kin, uap->innbyte)) {
			rc = EFAULT;
			goto done;
		}
		if (bootverbose && uap->innbyte == 16)
			printf("ctl in: %16D\n", kin, ":");
	}
	if (uap->op & IOC_OUT) {
		if ((uap->outnbyte == NULL) || (uap->out == NULL)) {
			rc = EFAULT;
			goto done;
		}
		if (copyin(uap->outnbyte, &koutlen, sizeof(size_t))) {
			rc = EFAULT;
			goto done;
		}
		if (koutlen == 0) {
			rc = ENOSPC;
			goto done;
		}
	}
	rc = kern_vpc_ctl(td, uap->vpcd, uap->op, uap->innbyte, kin, &koutlen, &kout);
	if (uap->op & IOC_OUT) {
		if ((rc = copyout(&koutlen, uap->outnbyte, sizeof(size_t))))
			goto done;
		if ((rc = copyout(kout, uap->out, koutlen)))
			goto done;
	}
 done:
	free(kin, M_TEMP);
	free(kout, M_TEMP);
	return (rc);
}

static int      filt_vpcattach(struct knote *kn);
static void     filt_vpcdetach(struct knote *kn);
static int      filt_vpcevent(struct knote *kn, long hint);

static struct filterops vpc_filtops = {
       .f_isfd = 1,
       .f_attach = filt_vpcattach,
       .f_detach = filt_vpcdetach,
       .f_event = filt_vpcevent,
};

int
filt_vpcattach(struct knote *kn)
{
	vpc_ctx_t vctx;
	if_ctx_t ctx;

	if (kn->kn_fp->f_type != DTYPE_VPCFD)
		return (EBADF);

	vctx = kn->kn_fp->f_data;
	if (vctx->v_obj_type == VPC_OBJ_MGMT ||
		vctx->v_obj_type == VPC_OBJ_L2LINK)
		return (EBADF);
	ctx = vctx->v_ifp->if_softc;
	return (iflib_knlist_add(ctx, kn));
}

static void
filt_vpcdetach(struct knote *kn)
{
	vpc_ctx_t vctx;
	if_ctx_t ctx;

	MPASS(kn->kn_fp->f_type == DTYPE_VPCFD);
	vctx = kn->kn_fp->f_data;
	MPASS(vctx->v_obj_type != VPC_OBJ_SWITCH &&
		  vctx->v_obj_type != VPC_OBJ_L2LINK);
	ctx = vctx->v_ifp->if_softc;
	iflib_knlist_remove(ctx, kn);
}

static int
filt_vpcevent(struct knote *kn, long hint)
{
	if_ctx_t ctx;
	vpc_ctx_t vctx;

	MPASS(kn->kn_fp->f_type == DTYPE_VPCFD);
	vctx = kn->kn_fp->f_data;
	MPASS(vctx->v_obj_type == VPC_OBJ_SWITCH);
	ctx = vctx->v_ifp->if_softc;

	return (iflib_knote_event(ctx, kn, hint));
}

static struct syscall_helper_data vmmnet_syscalls[] = {
	SYSCALL_INIT_HELPER(vpc_open),
	SYSCALL_INIT_HELPER(vpc_ctl),
	SYSCALL_INIT_LAST
};
	
static int
vmmnet_module_init(void)
{
	int rc;

	if ((rc = syscall_helper_register(vmmnet_syscalls, 0))) {
		printf("vmmnet syscall register failed %d\n", rc);
		return (rc);
	}
	if ((rc = kqueue_add_filteropts(EVFILT_VPC, &vpc_filtops))) {
		syscall_helper_unregister(vmmnet_syscalls);
		printf("failed to register vpcsw_filtops %d\n", rc);
		return (rc);
	}
	art_tree_init(&vpc_uuid_table, sizeof(vpc_id_t));
	return (0);
}

static void
vmmnet_module_deinit(void)
{
	syscall_helper_unregister(vmmnet_syscalls);
	kqueue_del_filteropts(EVFILT_VPC);
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

DECLARE_MODULE(vmmnet, vmmnet_moduledata, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(vmmnet, 1);
MODULE_DEPEND(vmmnet, vpc, 1, 1, 1);
