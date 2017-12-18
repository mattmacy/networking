#ifndef __IF_VPC_H_
#define __IF_VPC_H_

#define VB_MAGIC 0x20171202
struct vpc_ioctl_header {
	uint64_t vih_magic;
	uint64_t vih_type;
};
struct vpc_listen {
};

#define VPC_LISTEN									\
	_IOW('k', 1, struct vpc_listen)


#endif
