# $FreeBSD$

.PATH:		${ZFSSRC}
SRCS+=		zfs.c nvlist.c skein.c skein_block.c list.c
.PATH:		${SYSDIR}/crypto/skein
.PATH:		${SYSDIR}/contrib/openzfs/module/os/freebsd/spl
.PATH:		${SYSDIR}/contrib/openzfs/module/zstd/lib

SRCS+=		zstd.c zstd_shim.c


CFLAGS+=	-I${LDRSRC}
CFLAGS+=	-I${SYSDIR}/cddl/boot/zfs
CFLAGS+=	-I${SYSDIR}/crypto/skein
ZFS_CFLAGS=	 -D_KERNEL  -D__KERNEL__ -DIN_BASE -D_SYS_VMEM_H_ \
		 -DZFS_CONTEXT_OS_H_ -DKLD_MODULE \
		 -I${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/ \
		 -I${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl \
		 -I${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/zfs \
		 -I${SRCTOP}/sys/contrib/openzfs/include \
		 -I${SRCTOP}/sys/contrib/ck/include \

CFLAGS.skein_block.c+=	-DSKEIN_LOOP=111
CFLAGS.zfs.c+=	-I${SRCTOP}/sys/cddl/contrib/opensolaris/common/lz4 -I${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl
CFLAGS.nvlist.c+= -I${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl
CFLAGS.list.c=	-include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h ${ZFS_CFLAGS}
CFLAGS.zstd_shim.c+= ${ZFS_CFLAGS} -D_SYS_RWLOCK_H_ -D_SYS_MALLOC_H_ -D_OPENSOLARIS_SYS_KMEM_H_  -D_SPL_KMEM_CACHE_H -D_SYS_SPA_H  -Wno-include-next-absolute-path -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/types.h -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/param.h -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/debug.h  -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/proc.h  -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/time.h -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/mutex.h -I${SYSDIR}/contrib/openzfs/module/zstd

CFLAGS+=	-Wformat -Wall
