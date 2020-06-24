# $FreeBSD$

.PATH: ${SRCTOP}/sys/contrib/openzfs/cmd/zstream

PROG=	zstream
INCS=	zstream.h
SRCS=	zstream.c zstream_dump.c zstream_redup.c \
	zstream_token.c


MAN=

WARNS?=	2
CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/module/icp/include
CFLAGS+= -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -DHAVE_ISSETUGID
CFLAGS+= -include ${SRCTOP}/sys/modules/zfs/zfs_config.h

LIBADD=	geom m nvpair umem uutil avl spl zfs_core zfs zutil zpool

.include <bsd.prog.mk>
