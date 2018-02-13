# $FreeBSD$

.PATH: ${SRCTOP}/sys/net

KMOD=	vmmnet
SRCS=	if_vpci.c
SRCS+=	opt_inet.h opt_inet6.h ifdi_if.h device_if.h bus_if.h pci_if.h

CFLAGS+= -DVMM_KEEP_STATS -DSMP
CFLAGS+= -I${SRCTOP}/sys/amd64/vmm
CFLAGS+= -I${SRCTOP}/sys/amd64/vmm/io
CFLAGS+= -I${SRCTOP}/sys/amd64/vmm/net
CFLAGS+= -I${SRCTOP}/sys/amd64/vmm/intel
CFLAGS+= -I${SRCTOP}/sys/amd64/vmm/amd
CFLAGS+= -I${SRCTOP}/sys/contrib/ck/include

.PATH: ${SRCTOP}/sys/amd64/vmm/net
SRCS+=	art.c \
	if_vmnic.c \
	if_vpc.c \
	if_vpcp.c \
	if_vpcsw.c \
	vmmnet.c

.include <bsd.kmod.mk>
