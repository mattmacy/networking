# $FreeBSD$

OPENSOLARIS_USR_DISTDIR= ${.CURDIR}/../../../cddl/contrib/opensolaris
OPENSOLARIS_SYS_DISTDIR= ${.CURDIR}/../../../sys/cddl/contrib/opensolaris

IGNORE_PRAGMA=	YES

CFLAGS+=	-DNEED_SOLARIS_BOOLEAN

WARNS?=		6

# Do not lint the CDDL stuff. It is all externally maintained and
# lint output is wasteful noise here.

NO_LINT=

.if defined(CAN_USE_STATIC_LIBZPOOL)
# For ease of testing older builds, set WITH_STATIC_ZDB.  This is required
# for static ztest as well, so that is also honored.
.if defined(WITH_STATIC_ZDB) || defined(WITH_STATIC_ZTEST)
NO_SHARED=	yes

# For programs, link in libzpool.a from the object tree.
.if defined(PROG)
LDADD+=	${.OBJDIR}/../../lib/libzpool/libzpool.a
_LA:=	${LIBADD}
LIBADD=	${_LA:S/zpool//}
.endif
.endif
.endif
