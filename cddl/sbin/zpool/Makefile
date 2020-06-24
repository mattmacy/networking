# $FreeBSD$

.PATH: ${SRCTOP}/sys/contrib/openzfs/cmd/zpool
.PATH: ${SRCTOP}/sys/contrib/openzfs/cmd/zpool/os/freebsd


PACKAGE=	runtime
PROG=	zpool
#MAN=	zpool.8 zpool-features.7
MAN=

SRCS = \
	zpool_iter.c \
	zpool_main.c \
	zpool_util.c \
	zpool_util.h \
	zpool_vdev.c


SRCS += zpool_vdev_os.c

WARNS?=	2
CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/cmd/zpool
CFLAGS+= -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -DHAVE_ISSETUGID
CFLAGS+= -include ${SRCTOP}/sys/modules/zfs/zfs_config.h
CFLAGS+= -DSYSCONFDIR=\"/etc\"

LIBADD=	geom nvpair uutil zfs zutil avl spl tpool zfs_core m
LDADD+= 	-pthread
.include <bsd.prog.mk>
