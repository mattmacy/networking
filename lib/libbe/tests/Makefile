# $FreeBSD$

PACKAGE=	tests

ATF_TESTS_SH+= be_create

PROGS=		target_prog
SRCS_target_prog=	target_prog.c
BINDIR_target_prog=	${TESTSDIR}

LIBADD+= zfs
LIBADD+= nvpair
LIBADD+= be

CFLAGS+= -I${SRCTOP}/lib/libbe
CFLAGS+= -DIN_BASE -DHAVE_RPC_TYPES
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -D_MACHINE_ENDIAN_H_ -DHAVE_ISSETUGID 

.include <bsd.test.mk>
