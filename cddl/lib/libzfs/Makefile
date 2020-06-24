# $FreeBSD$

.PATH: ${SRCTOP}/sys/contrib/openzfs/module/icp
.PATH: ${SRCTOP}/sys/contrib/openzfs/module/zcommon
.PATH: ${SRCTOP}/sys/contrib/openzfs/lib/libzfs
.PATH: ${SRCTOP}/sys/contrib/openzfs/lib/libzfs/os/freebsd

PACKAGE=	runtime
LIB=	zfs
LIBADD=	md pthread umem util uutil m avl bsdxml geom nvpair z zfs_core zutil

USER_C = \
        libzfs_changelist.c \
        libzfs_config.c \
        libzfs_crypto.c \
        libzfs_dataset.c \
        libzfs_diff.c \
        libzfs_import.c \
        libzfs_iter.c \
        libzfs_mount.c \
        libzfs_pool.c \
        libzfs_sendrecv.c \
        libzfs_status.c \
        libzfs_util.c


USER_C += \
        libzfs_fsshare.c \
        libzfs_compat.c \
        libzfs_ioctl_compat.c \
        libzfs_zmount.c



KERNEL_C = \
        algs/sha2/sha2.c \
        cityhash.c \
        zfeature_common.c \
        zfs_comutil.c \
        zfs_deleg.c \
        zfs_fletcher.c \
        zfs_fletcher_aarch64_neon.c \
        zfs_fletcher_avx512.c \
        zfs_fletcher_intel.c \
        zfs_fletcher_sse.c \
        zfs_fletcher_superscalar.c \
        zfs_fletcher_superscalar4.c \
        zfs_namecheck.c \
        zfs_prop.c \
        zfs_uio.c \
        zpool_prop.c \
        zprop_common.c



SRCS= $(USER_C) $(KERNEL_C)

WARNS?=	2
SHLIB_MAJOR= 3
CSTD=	c99
CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/module/icp/include
CFLAGS+= -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -DHAVE_ISSETUGID
CFLAGS+= -include ${SRCTOP}/sys/modules/zfs/zfs_config.h


.include <bsd.lib.mk>
