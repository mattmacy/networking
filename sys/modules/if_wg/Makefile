# $FreeBSD$                                                                                                        

.PATH:	${SRCTOP}/sys/contrib/libb2
.PATH:	${SRCTOP}/sys/crypto/blake2
.PATH: ${SRCTOP}/sys/net


KMOD=   if_wg

SRCS=   if_wg.c
SRCS+=  opt_inet.h opt_inet6.h ifdi_if.h device_if.h bus_if.h

CFLAGS += -DINET6  -DINET

CFLAGS	+= -I${SRCTOP}/sys/contrib/libb2
CFLAGS	+= -I${SRCTOP}/sys/crypto/blake2
CFLAGS	+= -I${SRCTOP}/sys/crypto/libsodium
CFLAGS	+= -I${SRCTOP}/sys/contrib/libsodium/src/libsodium/include

.include <bsd.kmod.mk>




