# $FreeBSD$

.PATH: ${SRCTOP}/sys/net

KMOD=	if_vpc
SRCS=	if_vpc.c
SRCS+=	opt_inet.h opt_inet6.h ifdi_if.h device_if.h bus_if.h

CFLAGS+= -I${SRCTOP}/sys/contrib/ck/include

.include <bsd.kmod.mk>
