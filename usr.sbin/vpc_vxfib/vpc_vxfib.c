#include <sys/types.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sysexits.h>
#include <sys/sockio.h>
#include <sys/syscall.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_vpc.h>
#include <net/route.h>

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <uuid.h>

static int
vpc_open(const vpc_id_t *vpc_id, vpc_type_t obj_type, vpc_flags_t flags)
{
	return syscall(SYS_vpc_open, vpc_id, obj_type, flags);
}

static int
vpc_ctl(int vpcd, vpc_op_t op, size_t keylen, const void *key, size_t *vallen, void *buf)
{
	return syscall(SYS_vpc_ctl, vpcd, op, keylen, key, vallen, buf);
}

#ifdef notyet
		   "\tdelete all forwarding table entries:\n"
		   "\t\t%s -d -i <uuid> -v <vni>\n",
#endif

static void
usage(char *name)
{
	printf("usage:\n"
		   "\tlist forwarding table:\n"
		   "\t\t%s -l -i <uuid>\n"
		   "\tadd forwarding table entry:\n"
		   "\t\t%s -s -i <uuid> -v <vni> -f <forward mac> -p <forward ip> \n"
		   "\tdelete forwarding table entry:\n"
		   "\t\t%s -d -i <uuid> -v <vni> -f <forward mac>\n",
		   name, name, name);
	exit(EX_USAGE);
}

static const char *default_fmac = "00:00:00:00:00:00";

static void
fte_list_display(struct vpcmux_fte_list *list)
{
	struct vpcmux_fte *e = list->vfl_vftes;
	struct sockaddr_in *sin;

	printf("forwarding table:\n");
	for (uint32_t i = 0; i < list->vfl_count; i++, e++) {
		sin = (void *)&e->vf_protoaddr;
		printf("\thwaddr: %s protoaddr: %s vtag: %d vni: %d\n",
		       ether_ntoa((const struct ether_addr*)e->vf_hwaddr), inet_ntoa(sin->sin_addr),
		       e->vf_vlanid, e->vf_vni);
	}
}

#define true 1
#define false 0

int
main(int argc, char **argv)
{
	const char *fmac, *uuid;
	int rc, s, set, del, list;
	uint32_t forward_ip, status, vni;
	uint64_t size;
	struct uuid uuidtmp, uuidarg;
	uint64_t type, command;
	vpc_handle_type_t *typep;
	struct vpcmux_fte vfte;
	struct vpcmux_fte_list ftelist, *ftelistp;
	struct sockaddr_in sin;
	struct ether_addr *ea;
	char ch;

	set = del = false;
	uuid = NULL;
	fmac = default_fmac;
	vni = command = forward_ip = 0;
	del = set = list = false;
	while ((ch = getopt(argc, argv, "df:i:lp:sv:")) != -1) {
		switch (ch) {
			case 'd':
				del = true;
				command = VPC_VPCMUX_OP_FTE_DEL;
				break;
			case 'f':
				fmac = optarg;
				break;
			case 'i':
				uuid = optarg;
				break;
			case 'l':
				list = true;
				command = VPC_VPCMUX_OP_FTE_LIST;
				break;
			case 'p':
				forward_ip = inet_addr(optarg);
				break;
			case 's':
				set = true;
				command = VPC_VPCMUX_OP_FTE_SET;
				break;
			case 'v':
				vni = htonl(atoi(optarg)) >> 8;
				break;
			case '?':
			default:
				usage(argv[0]);
				break;
		}
	}
	if (uuid == NULL) {
		warnx("uuid required");	
		usage(argv[0]);
	}
	if ((del | set | list) == 0)  {
		warnx("an operation must be passed");
		usage(argv[0]);
	}
	if (fmac && (ea = ether_aton(fmac)) == NULL) {
		warnx("invalid ethernet address '%s'", fmac);
		usage(argv[0]);
	}
	if (del && set) {
		warnx("-d and -s are mutually exclusive");
		usage(argv[0]);
	}
	if (list && (del || set)) {
		warnx("-l can only be used by itself");
		usage(argv[0]);
	}
	if (set && fmac == default_fmac) {
		warnx("forwarding mac must be supplied with set");
		usage(argv[0]);
	}
	if (set && forward_ip == 0) {
		warnx("forwarding ip must be supplied with set");
		usage(argv[0]);
	}
	if ((set | del) && vni == 0) {
		warnx("non-zero vni must be passed for set or delete");
		usage(argv[0]);
	}
	uuid_from_string(uuid, &uuidtmp, &status);
	if (status != uuid_s_ok) {
		warnx("bad uuid %s", uuid);
		usage(argv[0]);
	}
	uuid_enc_be(&uuidarg, &uuidtmp);
	type = 0;
	typep = (void *)&type;
	typep->vht_version = 1;
	typep->vht_obj_type = VPC_OBJ_VPCMUX;
	type = htobe64(type);
	if ((s = vpc_open(&uuidarg, type, VPC_F_WRITE|VPC_F_OPEN)) < 0) {
		warnx("vpc_open(%s, ...) failed", uuid);
		usage(argv[0]);		
	}
	bzero(&sin, sizeof(sin));
	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr.s_addr = forward_ip;
	if (set)
		bcopy(&sin, &vfte.vf_protoaddr, sizeof(sin));
	if (del || set) {
		bcopy(ea, vfte.vf_hwaddr, ETHER_ADDR_LEN);
		vfte.vf_vni = vni;
	}
	if (!list) {
		rc = vpc_ctl(s, command, sizeof(vfte), &vfte, NULL, NULL);
		if (rc) {
			perror("update failed");
			exit(1);
		}
	} else {
		size = sizeof(ftelist);
		rc = vpc_ctl(s, command, 0, NULL, &size, &ftelist);
		if (rc) {
			perror("failed to get fte list count");
			exit(1);
		}
		size = sizeof(struct vpcmux_fte_list) +
			ftelist.vfl_count*sizeof(struct vpcmux_fte);
		ftelistp = malloc(size);
		if (ftelistp == NULL) {
			warnx("out of memory");
			exit(1);
		}
		rc = vpc_ctl(s, command, 0, NULL, &size, ftelistp);
		if (rc) {
			perror("failed to get fte list data");
			exit(1);
		}
		fte_list_display(ftelistp);
	}
	return (0);
}
