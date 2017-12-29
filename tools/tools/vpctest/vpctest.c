#include <sys/types.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sysexits.h>
#include <sys/sockio.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_vpc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(char *name)
{
	printf("usage: %s -l <listen ip> -f <forward mac> -i <forward ip>\n", name);
	exit(EX_USAGE);
}

static uint64_t
mac_parse(char *input)
{
	char *idx, *mac = strdup(input);
	const char *del = ":";
	uint64_t mac_num = 0;
	uint8_t *mac_nump = (uint8_t *)&mac_num;
	int i;

	for (i = 0; ((idx = strsep(&mac, del)) != NULL) && i < ETHER_ADDR_LEN; i++)
		mac_nump[i] = (uint8_t)strtol(idx, NULL, 16);
	free(mac);
	if (i < ETHER_ADDR_LEN)
		return 0;
	return	mac_num;
}

int
main(int argc, char **argv)
{
	struct ifreq ifr;
	struct ifreq_buffer *ifbuf;
	struct vpci_attach va;
	struct vpci_vni vv;
	struct vpc_listen vl;
	struct vpc_fte_update vfu;
	uint64_t forward_mac;
	uint32_t forward_ip, listen_ip;
	struct sockaddr_in *sin;
	struct vpc_fte *vfte;
	int s, ch;

	/* not done:
	 *  - setting IP on vpci0
	 *  - setting MAC for vpci0 on peer (peer overlay address)
	 */
	listen_ip = forward_mac = forward_ip = 0;
	ifbuf = &ifr.ifr_ifru.ifru_buffer;
	while ((ch = getopt(argc, argv, "l:f:i:")) != -1) {
		switch (ch) {
			case 'l':
				listen_ip = inet_addr(optarg);
				break;
			case 'f':
				forward_mac = mac_parse(optarg);
				break;
			case 'i':
				forward_ip = inet_addr(optarg);
				break;
			case '?':
			default:
				usage(argv[0]);
		}
	}
	
	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		exit(EX_SOFTWARE);
	}
	strcpy(ifr.ifr_name, "vpci0");
	ifbuf->buffer = &va;
	ifbuf->length = sizeof(va);
	/* attach vpci */
	va.va_vih.vih_magic = VPC_VERS;
	va.va_vih.vih_type = VPCI_ATTACH;
	strcpy(va.va_ifname, "vpc0");
	if (ioctl(s, SIOCGPRIVATE_0, &ifr)) {
		perror("attach failed\n");
		exit(EX_IOERR);
	}
	bzero(va.va_ifname, IFNAMSIZ);
	va.va_vih.vih_type = VPCI_ATTACHED_GET;
	/* get attach interface */
	if (ioctl(s, SIOCGPRIVATE_0, &ifr)) {
		perror("attached get failed\n");
		exit(EX_IOERR);
	}
	printf("attached to %s\n", va.va_ifname);
	/* set VNI for vpci */
	ifbuf->buffer = &vv;
	ifbuf->length = sizeof(vv);
	vv.vv_vih.vih_magic = VPC_VERS;
	vv.vv_vih.vih_type = VPCI_VNI_SET;
	vv.vv_vni = 150;
	if (ioctl(s, SIOCGPRIVATE_0, &ifr)) {
		perror("vni set failed\n");
		exit(EX_IOERR);
	}
	/* get VNI for vpci */
	vv.vv_vih.vih_type = VPCI_VNI_GET;
	vv.vv_vni = 0;
	if (ioctl(s, SIOCGPRIVATE_0, &ifr)) {
		perror("vni get failed\n");
		exit(EX_IOERR);
	}
	printf("vni set to %d\n", vv.vv_vni);
	/* set VPC listen */
	ifbuf->buffer = &vl;
	ifbuf->length = sizeof(vl);
	vl.vl_vih.vih_magic = VPC_VERS;
	vl.vl_vih.vih_type = VPC_LISTEN;
	sin = (struct sockaddr_in *)&vl.vl_addr;
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_port = htons(4789);
	sin->sin_addr.s_addr = listen_ip;
	if (ioctl(s, SIOCGPRIVATE_0, &ifr)) {
		perror("failed to set listen ip:port\n");
		exit(EX_IOERR);
	}
	/* add FTE for peer */
	ifbuf->buffer = &vfu;
	ifbuf->length = sizeof(vfu);
	vfu.vfu_vih.vih_magic = VPC_VERS;
	vfu.vfu_vih.vih_type = VPC_FTE_SET;
	vfte = &vfu.vfu_vfte;
	vfte->vf_vni = 150;
	bcopy(&forward_mac, vfte->vf_hwaddr, ETHER_ADDR_LEN);
	sin = (struct sockaddr_in *)&vfte->vf_protoaddr;
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = forward_ip;
	if (ioctl(s, SIOCGPRIVATE_0, &ifr)) {
		perror("failed to set forward ip\n");
		exit(EX_IOERR);
	}
	return (0);
}
