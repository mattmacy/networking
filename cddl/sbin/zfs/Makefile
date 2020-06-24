# $FreeBSD$

.PATH: ${SRCTOP}/sys/contrib/openzfs/cmd/zfs
.PATH: ${SRCTOP}/sys/contrib/openzfs/module/os/freebsd/spl

PACKAGE=	runtime
PROG=	zfs
MAN=
#MAN=	zfs.8 zfs-program.8
SRCS = \
	zfs_iter.c \
	zfs_iter.h \
	zfs_main.c \
	zfs_util.h \
	zfs_project.c \
	zfs_projectutil.h

WARNS?=	2
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

CFLAGS+= -I${SRCTOP}/sys/modules/zfs

LIBADD=	jail avl nvpair geom  uutil zfs_core spl tpool zutil zfs m
LDADD+=	-pthread
.include <bsd.prog.mk>
