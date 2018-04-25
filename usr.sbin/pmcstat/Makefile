#
# $FreeBSD$
#

PROG=	pmcstat
MAN=	pmcstat.8

LIBADD=	kvm pmc m ncursesw pmcstat elf

SRCS=	pmcstat.c pmcstat.h pmcstat_log.c \
pmcpl_callgraph.c pmcpl_gprof.c pmcpl_annotate.c \
pmcpl_annotate_cg.c pmcpl_calltree.c

.if (${MACHINE_CPUARCH} == "aarch64" || ${MACHINE_CPUARCH} == "amd64" || \
	${MACHINE_CPUARCH} == "powerpc")
.if ${MACHINE_CPUARCH} == "aarch64"
EVENT_ARCH="arm64"
.elif ${MACHINE_CPUARCH} == "amd64"
EVENT_ARCH="x86"
.elif ${MACHINE_CPUARCH} == "powerpc"
EVENT_ARCH="powerpc"
.endif

.if defined(HOST_OBJTOP)
JEVENTS= ${HOST_OBJTOP}/${RELDIR}/pmu-events/jevents
.else
JEVENTS= pmu-events/jevents
.endif

pmu_events.c: ${JEVENTS}
	${JEVENTS} ${EVENT_ARCH} pmu-events/arch pmu_events.c
SRCS+= pmu_events.c
CFLAGS+= -I${.CURDIR}
.endif

.include <bsd.prog.mk>
