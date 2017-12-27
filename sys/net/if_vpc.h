#ifndef __IF_VPC_H_
#define __IF_VPC_H_

#define VB_MAGIC 0x20171202
struct vpc_ioctl_header {
	uint64_t vih_magic;
	uint64_t vih_type;
};
struct vpc_listen {
	struct vpc_ioctl_header vl_vih;
	struct sockaddr vl_addr;
	uint16_t vl_port;
};

#define VPC_LISTEN									\
	_IOW('k', 1, struct vpc_listen)

struct vpci_attach {
	struct vpc_ioctl_header vl_vih;
	char va_ifname[IFNAMSIZ];
};

#define VPCI_ATTACH									\
	_IOW('k', 1, struct vpci_attach)


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
