#include <sys/types.h>
#include <sys/param.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sysexits.h>
#include <sys/sockio.h>
#include <sys/cpuset.h>

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

#include <machine/vmm.h>
#include <machine/vmm_dev.h>

/*
 * host0:
 *  doas ifconfig vpc create
 *  doas ifconfig vtnet0 alias 10.247.1.1 netmask 0xfffffe00
 *  doas ifconfig vpci0 192.168.0.1
 *  doas ./tools/tools/vpctest/vpctest -l 10.247.1.1 -f 58:9c:fc:e9:b3:8e -i 10.247.1.2 -o 192.168.0.2
 *
 * host1:
 *  doas ifconfig vpci create
 *  doas ifconfig vpc create
 *  doas ifconfig vtnet0 alias 10.247.1.2 netmask 0xfffffe00
 *  doas ifconfig vpci0 192.168.0.2
 *  doas ./tools/tools/vpctest/vpctest -l 10.247.1.2 -f 58:9c:fc:36:59:93 -i 10.247.1.1 -o 192.168.0.1
 *
 */

static int flags;
static time_t	expire_time;

static void
usage(char *name)
{
	printf("usage: %s -l <listen ip> -f <forward mac> -i <forward ip> -o <overlay ip>\n", name);
	exit(EX_USAGE);
}


/*
 * Returns true if the type is a valid one for ARP.
 */
static int
valid_type(int type)
{

	switch (type) {
	case IFT_ETHER:
	case IFT_FDDI:
	case IFT_INFINIBAND:
	case IFT_ISO88023:
	case IFT_ISO88024:
	case IFT_ISO88025:
	case IFT_L2VLAN:
	case IFT_BRIDGE:
		return (1);
	default:
		return (0);
	}
}

static struct rt_msghdr *
rtmsg(int cmd, struct sockaddr_in *dst, struct sockaddr_dl *sdl)
{
	static int seq;
	int rlen;
	int l;
	struct sockaddr_in so_mask, *som = &so_mask;
	static int s = -1;
	static pid_t pid;

	static struct	{
		struct	rt_msghdr m_rtm;
		char	m_space[512];
	}	m_rtmsg;

	struct rt_msghdr *rtm = &m_rtmsg.m_rtm;
	char *cp = m_rtmsg.m_space;

	if (s < 0) {	/* first time: open socket, get pid */
		s = socket(PF_ROUTE, SOCK_RAW, 0);
		if (s < 0)
			err(1, "socket");
		pid = getpid();
	}
	bzero(&so_mask, sizeof(so_mask));
	so_mask.sin_len = 8;
	so_mask.sin_addr.s_addr = 0xffffffff;

	/*
	 * XXX RTM_DELETE relies on a previous RTM_GET to fill the buffer
	 * appropriately.
	 */
	if (cmd == RTM_DELETE)
		goto doit;
	bzero((char *)&m_rtmsg, sizeof(m_rtmsg));
	rtm->rtm_flags = flags;
	rtm->rtm_version = RTM_VERSION;

	switch (cmd) {
	default:
		errx(1, "internal wrong cmd");
	case RTM_ADD:
		rtm->rtm_addrs |= RTA_GATEWAY;
		rtm->rtm_rmx.rmx_expire = expire_time;
		rtm->rtm_inits = RTV_EXPIRE;
		rtm->rtm_flags |= (RTF_HOST | RTF_STATIC | RTF_LLDATA);
		/* FALLTHROUGH */
	case RTM_GET:
		rtm->rtm_addrs |= RTA_DST;
	}
#define NEXTADDR(w, s)						\
	do {							\
		if ((s) != NULL && rtm->rtm_addrs & (w)) {	\
			bcopy((s), cp, sizeof(*(s)));		\
			cp += SA_SIZE(s);			\
		}						\
	} while (0)

	NEXTADDR(RTA_DST, dst);
	NEXTADDR(RTA_GATEWAY, sdl);
	NEXTADDR(RTA_NETMASK, som);

	rtm->rtm_msglen = cp - (char *)&m_rtmsg;
doit:
	l = rtm->rtm_msglen;
	rtm->rtm_seq = ++seq;
	rtm->rtm_type = cmd;
	if ((rlen = write(s, (char *)&m_rtmsg, l)) < 0) {
		if (errno != ESRCH || cmd != RTM_DELETE) {
			warn("writing to routing socket");
			return (NULL);
		}
	}
	do {
		l = read(s, (char *)&m_rtmsg, sizeof(m_rtmsg));
	} while (l > 0 && (rtm->rtm_type != cmd || rtm->rtm_seq != seq ||
	    rtm->rtm_pid != pid));
	if (l < 0)
		warn("read from routing socket");
	return (rtm);
}


static struct sockaddr_in *
getaddr(char *host)
{
	struct hostent *hp;
	static struct sockaddr_in reply;

	bzero(&reply, sizeof(reply));
	reply.sin_len = sizeof(reply);
	reply.sin_family = AF_INET;
	reply.sin_addr.s_addr = inet_addr(host);
	if (reply.sin_addr.s_addr == INADDR_NONE) {
		if (!(hp = gethostbyname(host))) {
			warnx("%s: %s", host, hstrerror(h_errno));
			return (NULL);
		}
		bcopy((char *)hp->h_addr, (char *)&reply.sin_addr,
			sizeof reply.sin_addr);
	}
	return (&reply);
}
/*
 * Set an individual arp entry
 */
static int
setarp(char *host, char *eaddr)
{
	struct sockaddr_in *addr;
	struct sockaddr_in *dst;	/* what are we looking for */
	struct sockaddr_dl *sdl;
	struct rt_msghdr *rtm;
	struct ether_addr *ea, *ea1;
	struct sockaddr_dl sdl_m;


	bzero(&sdl_m, sizeof(sdl_m));
	sdl_m.sdl_len = sizeof(sdl_m);
	sdl_m.sdl_family = AF_LINK;

	dst = getaddr(host);
	if (dst == NULL)
		return (1);
	ea = (struct ether_addr *)LLADDR(&sdl_m);
	ea1 = ether_aton(eaddr);
	if (ea1 == NULL) {
		warnx("invalid Ethernet address '%s'", eaddr);
		return (1);
	} else {
		*ea = *ea1;
		sdl_m.sdl_alen = ETHER_ADDR_LEN;
	}

	/*
	 * In the case a proxy-arp entry is being added for
	 * a remote end point, the RTF_ANNOUNCE flag in the
	 * RTM_GET command is an indication to the kernel
	 * routing code that the interface associated with
	 * the prefix route covering the local end of the
	 * PPP link should be returned, on which ARP applies.
	 */
	rtm = rtmsg(RTM_GET, dst, NULL);
	if (rtm == NULL) {
		warn("%s", host);
		return (1);
	}
	addr = (struct sockaddr_in *)(rtm + 1);
	sdl = (struct sockaddr_dl *)(SA_SIZE(addr) + (char *)addr);

	if ((sdl->sdl_family != AF_LINK) ||
	    (rtm->rtm_flags & RTF_GATEWAY) ||
	    !valid_type(sdl->sdl_type)) {
		warnx("cannot intuit interface index and type for %s", host);
		return (1);
	}
	sdl_m.sdl_type = sdl->sdl_type;
	sdl_m.sdl_index = sdl->sdl_index;
	return (rtmsg(RTM_ADD, dst, &sdl_m) == NULL);
}

int
main(int argc, char **argv)
{
	struct ifreq ifr;
	struct ifreq_buffer *ifbuf;
	struct vb_vni vv;
	struct vpc_listen vl;
	struct vpc_fte_update vfu;
	struct ether_addr *ea;
	uint32_t forward_ip, listen_ip;
	char *forward_mac, *overlay_ip;
	struct sockaddr_in *sin;
	struct vpc_fte *vfte;
	int s, ch;


	listen_ip = forward_ip = 0;
	forward_mac = overlay_ip = NULL;
	ifbuf = &ifr.ifr_ifru.ifru_buffer;
	while ((ch = getopt(argc, argv, "l:f:i:o:")) != -1) {
		switch (ch) {
			case 'l':
				listen_ip = inet_addr(optarg);
				break;
			case 'f':
				forward_mac = optarg;
				break;
			case 'i':
				forward_ip = inet_addr(optarg);
				break;
			case 'o':
				overlay_ip = optarg;
				break;
			case '?':
			default:
				usage(argv[0]);
		}
	}
	if (!listen_ip || !forward_mac || !forward_ip || !overlay_ip)
		usage(argv[0]);
	
	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		exit(EX_SOFTWARE);
	}
	ea = ether_aton(forward_mac);
	if (ea == NULL) {
		warnx("invalid Ethernet address '%s'", forward_mac);
		exit(EX_USAGE);
	}

	setarp(overlay_ip, forward_mac);

	/* set VNI for vmi */
	strcpy(ifr.ifr_name, "vmi0");
	ifbuf->buffer = &vv;
	ifbuf->length = sizeof(vv);
	vv.vv_ioh.vih_magic = VB_MAGIC;
	vv.vv_ioh.vih_type = VB_VNI;
	vv.vv_vni = 150;
	if (ioctl(s, SIOCGPRIVATE_0, &ifr)) {
		perror("vni set failed\n");
		exit(EX_IOERR);
	}
#ifdef notyet	
	/* get VNI for vpci */
	vv.vv_vih.vih_type = VPCI_VNI_GET;
	vv.vv_vni = 0;
	if (ioctl(s, SIOCGPRIVATE_0, &ifr)) {
		perror("vni get failed\n");
		exit(EX_IOERR);
	}
	printf("vni set to %d\n", vv.vv_vni);
#endif	
	/* set VPC listen */
	strcpy(ifr.ifr_name, "vpc0");
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
		perror("failed to set listen ip:port ");
		exit(EX_IOERR);
	}
	/* add FTE for peer */
	ifbuf->buffer = &vfu;
	ifbuf->length = sizeof(vfu);
	vfu.vfu_vih.vih_magic = VPC_VERS;
	vfu.vfu_vih.vih_type = VPC_FTE_SET;
	vfte = &vfu.vfu_vfte;
	vfte->vf_vni = 150;
	bcopy(ea, vfte->vf_hwaddr, ETHER_ADDR_LEN);
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
