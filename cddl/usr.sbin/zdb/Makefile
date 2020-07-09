# $FreeBSD$

.PATH: ${SRCTOP}/sys/contrib/openzfs/cmd/zdb

PROG=	zdb
#MAN=	zdb.8
MAN=
INCS=	zdb.h
SRCS=	zdb.c zdb_il.c

WARNS?=	2
CSTD=	c99
CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd/spl
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -DHAVE_ISSETUGID
LIBADD=	nvpair umem uutil zfs spl avl zutil zpool

CFLAGS.gcc+= -fms-extensions
# Since there are many asserts in this program, it makes no sense to compile
# it without debugging.
CFLAGS+=	-g -DDEBUG=1 -DZFS_DEBUG=1

.include <bsd.prog.mk>
