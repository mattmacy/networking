# $FreeBSD$

.PATH: ${SRCTOP}/sys/net

KMOD=	if_vpcbctl
SRCS=	if_vpcbctl.c
SRCS+=	opt_inet.h opt_inet6.h ifdi_if.h device_if.h bus_if.h

CFLAGS+= -I${SRCTOP}/sys/contrib/ck/include

.include <bsd.kmod.mk>
