# $FreeBSD$

.PATH: ${SRCTOP}/sys/netpfil/npf

KMOD=	npf
SRCS+=	npf.c npf_conf.c npf_ctl.c npf_handler.c npf_mbuf.c npf_bpf.c
SRCS+=	npf_params.c npf_ruleset.c npf_rproc.c npf_tableset.c npf_if.c
SRCS+=	npf_inet.c npf_conn.c npf_connkey.c npf_conndb.c npf_state.c
SRCS+=	npf_state_tcp.c npf_nat.c npf_portmap.c npf_alg.c npf_sendpkt.c
SRCS+=	npf_worker.c

SRCS+=	npf_os.c npf_ifaddr.c

SRCS+= opt_inet.h opt_inet6.h opt_ipdivert.h

CFLAGS+= -I${SRCTOP}/sys/netpfil/npf
CFLAGS+= -include ${SRCTOP}/sys/netpfil/npf/npf_shim.h


.include <bsd.kmod.mk>
