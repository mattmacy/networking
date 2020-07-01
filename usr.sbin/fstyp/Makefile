# $FreeBSD$

.include <src.opts.mk>

PROG=	fstyp
SRCS=	apfs.c cd9660.c exfat.c ext2fs.c fstyp.c geli.c hammer.c	\
	hammer2.c hfsplus.c msdosfs.c ntfs.c ufs.c

.if ${MK_ZFS} != "no"
SRCS +=	zfs.c
.endif

MAN=	fstyp.8

WARNS?=	2

.if ${MK_ICONV} == "yes"
CFLAGS+=	-DWITH_ICONV
.endif

.include <bsd.endian.mk>

.if ${TARGET_ENDIANNESS} == 1234
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.endif

.if ${MK_ZFS} != "no"
IGNORE_PRAGMA=  YES


WARNS?=	0
CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/module/icp/include
CFLAGS+= -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -D_MACHINE_ENDIAN_H_ -DHAVE_ISSETUGID 
CFLAGS+= -include ${SRCTOP}/sys/modules/zfs/zfs_config.h
.endif

CFLAGS+=-I${SRCTOP}/sys

LIBADD=	geom md ufs

.if ${MK_ZFS} != "no"
LIBADD+=nvpair zfs
.endif

.include <bsd.prog.mk>
