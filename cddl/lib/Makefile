# $FreeBSD$

.include <src.opts.mk>

SUBDIR=	${_drti} \
	libavl \
	libctf \
	${_libdtrace} \
	libnvpair \
	${_libspl} \
	${_libtpool} \
	libumem \
	libuutil \
	${_libzfs_core} \
	${_libzfs} \
	${_libzpool} \
	${_libzutil} 

SUBDIR.${MK_TESTS}+= tests

.if ${MK_ZFS} != "no"
_libzfs_core=	libzfs_core
_libzfs=	libzfs
_libzutil=	libzutil
.if ${MK_LIBTHR} != "no"
_libzpool=	libzpool
_libspl=	libspl
_libtpool=	libtpool
.endif
.endif

.if ${MACHINE_CPUARCH} != "sparc64"
_drti=		drti
_libdtrace=	libdtrace
.endif

SUBDIR_DEPEND_libdtrace=	libctf
SUBDIR_DEPEND_libtpool=		libspl
SUBDIR_DEPEND_libuutil=		libavl libspl
SUBDIR_DEPEND_libzfs_core=	libnvpair
SUBDIR_DEPEND_libzfs=	libavl libnvpair libumem libuutil libzfs_core libzutil
SUBDIR_DEPEND_libzpool=	libavl libnvpair libumem
SUBDIR_DEPEND_libzutil=	libavl libtpool

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
