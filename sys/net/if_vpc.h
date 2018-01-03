/*
 * Copyright (C) 2017 Matthew Macy <matt.macy@joyent.com>
 * Copyright (C) 2017 Joyent Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef __IF_VPC_H_
#define __IF_VPC_H_

#define VPC_VERS 0x20171228
struct vpc_ioctl_header {
	uint64_t vih_magic;
	uint64_t vih_type;
};
struct vpc_listen {
	struct vpc_ioctl_header vl_vih;
	struct sockaddr vl_addr;
};

struct vpc_fte {
	uint32_t vf_vni;
	uint8_t vf_hwaddr[ETHER_ADDR_LEN];
	struct sockaddr vf_protoaddr;
};

struct vpc_fte_update {
	struct vpc_ioctl_header vfu_vih;
	struct vpc_fte vfu_vfte;
};

struct vpc_fte_list {
	struct vpc_ioctl_header vfl_vih;
	uint32_t vfl_count;
	struct vpc_fte vfl_vftes[0];
};

#define VPC_LISTEN								\
	_IOW('k', 1, struct vpc_listen)
#define VPC_FTE_SET								\
	_IOW('k', 2, struct vpc_fte_update)
#define VPC_FTE_DEL								\
	_IOW('k', 3, struct vpc_fte_update)
#define VPC_FTE_ALL								\
	_IOWR('k', 4, struct vpc_fte_list)


struct vpci_attach {
	struct vpc_ioctl_header va_vih;
	char va_ifname[IFNAMSIZ];
};
struct vpci_vni {
	struct vpc_ioctl_header vv_vih;
	uint32_t vv_vni;
};

#define VPCI_ATTACH								\
	_IOW('k', 1, struct vpci_attach)
#define VPCI_ATTACHED_GET			   			\
	_IOWR('k', 2, struct vpci_attach)
#define VPCI_DETACH								\
	_IOW('k', 3, struct vpc_ioctl_header)
#define VPCI_VNI_SET							\
	_IOW('k', 4, struct vpci_vni)
#define VPCI_VNI_GET							\
	_IOWR('k', 5, struct vpci_vni)


struct vpcb_resolver {
};

struct vpcb_port_add {
};

struct vpcb_port_remove {
};

#define VPCB_RESOLVER									\
	_IOW('k', 1, struct vpcb_resolver)
#define VPCB_PORT_ADD									\
	_IOW('k', 1, struct vpcb_port_add)
#define VPCB_PORT_REMOVE									\
	_IOW('k', 1, struct vpcb_port_remove)


#endif
