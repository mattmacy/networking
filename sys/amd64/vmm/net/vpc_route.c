/*
 * Copyright (C) 2018 Matthew Macy <matt.macy@joyent.com>
 * Copyright (C) 2018 Joyent Inc.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/priv.h>
#include <sys/mutex.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/taskqueue.h>
#include <sys/limits.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if_vlan_var.h>
#include <net/iflib.h>
#include <net/if.h>
#include <net/if_clone.h>
#include <net/if_media.h>
#include <net/route.h>
#include <net/radix.h>

#include <net/if_vpc.h>

static MALLOC_DEFINE(M_VPCROUTE, "vpcrte", "virtual private cloud routing table");

/*
 * Do not require radix to compare more than actual IPv4/IPv6 address
 */
#define KEY_LEN_INET	(offsetof(struct sockaddr_in, sin_addr) + sizeof(in_addr_t))
#define KEY_LEN_INET6	(offsetof(struct sa_in6, sin6_addr) + sizeof(struct in6_addr))

#define OFF_LEN_INET	(8 * offsetof(struct sockaddr_in, sin_addr))
#define OFF_LEN_INET6	(8 * offsetof(struct sa_in6, sin6_addr))
#define KEY_LEN(v)	*((uint8_t *)&(v))

struct radix_addr_entry {
	struct radix_node	rn[2];
	struct sockaddr_in	addr;
	uint32_t		value;
	uint8_t			masklen;
};

struct sa_in6 {
	uint8_t			sin6_len;
	uint8_t			sin6_family;
	uint8_t			pad[2];
	struct in6_addr		sin6_addr;
};

struct radix_addr_xentry {
	struct radix_node	rn[2];
	struct sa_in6		addr6;
	uint32_t		value;
	uint8_t			masklen;
};

struct rt_buf
{
	void *ent_ptr;
	struct sockaddr	*addr_ptr;
	struct sockaddr	*mask_ptr;
	union {
		struct {
			struct sockaddr_in sa;
			struct sockaddr_in ma;
		} a4;
		struct {
			struct sa_in6 sa;
			struct sa_in6 ma;
		} a6;
	} addr;
};

struct rtr_ctx {
	struct radix_node_head *rc_rnh4;
	struct radix_node_head *rc_rnh6;
	uint32_t rc_cnt4;
	uint32_t rc_cnt6;
	struct rt_buf rc_tb;
};

/* Apply ipv6 mask on ipv6 addr */
#define APPLY_MASK(addr,mask)                          \
    (addr)->__u6_addr.__u6_addr32[0] &= (mask)->__u6_addr.__u6_addr32[0]; \
    (addr)->__u6_addr.__u6_addr32[1] &= (mask)->__u6_addr.__u6_addr32[1]; \
    (addr)->__u6_addr.__u6_addr32[2] &= (mask)->__u6_addr.__u6_addr32[2]; \
    (addr)->__u6_addr.__u6_addr32[3] &= (mask)->__u6_addr.__u6_addr32[3];

#ifdef INET6
static inline void ipv6_writemask(struct in6_addr *addr6, uint8_t mask);

static inline void
ipv6_writemask(struct in6_addr *addr6, uint8_t mask)
{
	uint32_t *cp;

	for (cp = (uint32_t *)addr6; mask >= 32; mask -= 32)
		*cp++ = 0xFFFFFFFF;
	if (mask > 0)
		*cp = htonl(mask ? ~((1 << (32 - mask)) - 1) : 0);
}
#endif

static int
addr_to_sockaddr_ent(void *paddr, struct sockaddr *sa,
					struct sockaddr *ma, uint8_t mlen, int family)
{
#ifdef INET
	struct sockaddr_in *addr, *mask;
#endif
#ifdef INET6
	struct sa_in6 *addr6, *mask6;
#endif
	in_addr_t a4;

	if (family == AF_INET) {
#ifdef INET
		addr = (struct sockaddr_in *)sa;
		mask = (struct sockaddr_in *)ma;
		/* Set 'total' structure length */
		KEY_LEN(*addr) = KEY_LEN_INET;
		KEY_LEN(*mask) = KEY_LEN_INET;
		addr->sin_family = AF_INET;
		mask->sin_addr.s_addr =
		    htonl(mlen ? ~((1 << (32 - mlen)) - 1) : 0);
		a4 = *((in_addr_t *)paddr);
		addr->sin_addr.s_addr = a4 & mask->sin_addr.s_addr;
		return (mlen != 32);
#endif
#ifdef INET6
	} else if (family == AF_INET6) {
		/* IPv6 case */
		addr6 = (struct sa_in6 *)sa;
		mask6 = (struct sa_in6 *)ma;
		/* Set 'total' structure length */
		KEY_LEN(*addr6) = KEY_LEN_INET6;
		KEY_LEN(*mask6) = KEY_LEN_INET6;
		addr6->sin6_family = AF_INET6;
		ipv6_writemask(&mask6->sin6_addr, mlen);
		memcpy(&addr6->sin6_addr, paddr, sizeof(struct in6_addr));
		APPLY_MASK(&addr6->sin6_addr, &mask6->sin6_addr);
		return (mlen != 128);
#endif
	}
	return (0);
}

static int
rtr_ctx_pre_del(void *paddr,
				struct rt_buf *tb, uint8_t mlen, int family)
{
	struct sockaddr *addr, *mask;
	int set_mask;

	if (family == AF_INET) {
		if (mlen > 32)
			return (EINVAL);

		addr = (struct sockaddr *)&tb->addr.a4.sa;
		mask = (struct sockaddr *)&tb->addr.a4.ma;
#ifdef INET6
	} else if (family == AF_INET6) {
		if (mlen > 128)
			return (EINVAL);

		addr = (struct sockaddr *)&tb->addr.a6.sa;
		mask = (struct sockaddr *)&tb->addr.a6.ma;
#endif
	} else
		return (EINVAL);

	set_mask = addr_to_sockaddr_ent(paddr, addr, mask, mlen, family);
	tb->addr_ptr = addr;
	if (set_mask)
		tb->mask_ptr = mask;

	return (0);
}

static int
rtr_ctx_pre_add(void *paddr,
				struct rt_buf *tb, uint8_t mlen, int family)
{
	struct radix_addr_entry *ent;
#ifdef INET6
	struct radix_addr_xentry *xent;
#endif
	struct sockaddr *addr, *mask;
	int set_mask;

	if (family == AF_INET) {
#ifdef INET
		if (mlen > 32)
			return (EINVAL);
		ent = malloc(sizeof(*ent), M_VPCROUTE, M_WAITOK | M_ZERO);
		ent->masklen = mlen;

		addr = (struct sockaddr *)&ent->addr;
		mask = (struct sockaddr *)&tb->addr.a4.ma;
		tb->ent_ptr = ent;
#endif
#ifdef INET6
	} else if (family == AF_INET6) {
		/* IPv6 case */
		if (mlen > 128)
			return (EINVAL);
		xent = malloc(sizeof(*xent), M_VPCROUTE, M_WAITOK | M_ZERO);
		xent->masklen = mlen;

		addr = (struct sockaddr *)&xent->addr6;
		mask = (struct sockaddr *)&tb->addr.a6.ma;
		tb->ent_ptr = xent;
#endif
	} else {
		/* Unknown CIDR type */
		return (EINVAL);
	}

	set_mask = addr_to_sockaddr_ent(paddr, addr, mask, mlen, family);
	/* Set pointers */
	tb->addr_ptr = addr;
	if (set_mask)
		tb->mask_ptr = mask;

	return (0);
}

static void
rtr_ctx_add(struct rtr_ctx *rc, uint32_t value, struct rt_buf *tb, int family)
{
	struct radix_node_head *rnh;
	struct radix_node *rn;

	if (family == AF_INET) {
		rnh = rc->rc_rnh4;
		((struct radix_addr_entry *)tb->ent_ptr)->value = value;
	} else {
		rnh = rc->rc_rnh6;
		((struct radix_addr_xentry *)tb->ent_ptr)->value = value;
	}
	rn = rn_lookup_flags(tb->addr_ptr, tb->mask_ptr, &rnh->rh, M_WAITOK);
	if (rn != NULL)
		return;

	rn_addroute_flags(tb->addr_ptr, tb->mask_ptr, &rnh->rh, tb->ent_ptr, M_WAITOK);
	if (family == AF_INET)
		rc->rc_cnt4++;
	else
		rc->rc_cnt6++;
	tb->ent_ptr = NULL;
}

static int
rtr_ctx_del(struct rtr_ctx *rc, struct rt_buf *tb, int family)
{
	struct radix_node_head *rnh;
	struct radix_node *rn;

	if (family == AF_INET) {
		rnh = rc->rc_rnh4;
	} else {
		rnh = rc->rc_rnh6;
	}
	rn = rn_delete_flags(tb->addr_ptr, tb->mask_ptr, &rnh->rh, M_WAITOK);
	if (rn == NULL)
		return (0);

	tb->ent_ptr = rn;
	
	if (family == AF_INET)
		rc->rc_cnt4--;
	else
		rc->rc_cnt6--;

	return (0);
}

int
vpc_rtr_add(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen, int family)
{
	struct rt_buf *tb = &rc->rc_tb;
	int error;

	if ((error = rtr_ctx_pre_add(paddr, tb, mlen, family)))
		return (error);
	rtr_ctx_add(rc, value, tb, family);
	return (0);
}

int
vpc_rtr_addv4(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen)
{
	return (vpc_rtr_add(rc, paddr, value, mlen, AF_INET));
}

int
vpc_rtr_addv6(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen)
{
	return (vpc_rtr_add(rc, paddr, value, mlen, AF_INET6));
}

int
vpc_rtr_del(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen, int family)
{
	struct rt_buf *tb = &rc->rc_tb;
	int error;

	if ((error = rtr_ctx_pre_del(paddr, tb, mlen, family)))
		return (error);
	rtr_ctx_del(rc, tb, family);
	return (0);
}

int
vpc_rtr_delv4(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen)
{
	return (vpc_rtr_del(rc, paddr, value, mlen, AF_INET));
}

int
vpc_rtr_delv6(rtr_ctx_t rc, void *paddr, uint32_t value, uint8_t mlen)
{
	return (vpc_rtr_del(rc, paddr, value, mlen, AF_INET6));
}

int
vpc_rtr_lookup(rtr_ctx_t rc, void *key, uint32_t *val, int family)
{
	struct radix_node_head *rnh;

	if (family == AF_INET) {
		struct radix_addr_entry *ent;
		struct sockaddr_in sa;
		KEY_LEN(sa) = KEY_LEN_INET;
		sa.sin_addr.s_addr = *((in_addr_t *)key);
		rnh = rc->rc_rnh4;
		ent = (struct radix_addr_entry *)(rnh->rnh_matchaddr(&sa, &rnh->rh));
		if (ent != NULL) {
			*val = ent->value;
			return (1);
		}
	} else {
		struct radix_addr_xentry *xent;
		struct sa_in6 sa6;
		KEY_LEN(sa6) = KEY_LEN_INET6;
		memcpy(&sa6.sin6_addr, key, sizeof(struct in6_addr));
		rnh = rc->rc_rnh6;
		xent = (struct radix_addr_xentry *)(rnh->rnh_matchaddr(&sa6, &rnh->rh));
		if (xent != NULL) {
			*val = xent->value;
			return (1);
		}
	}

	return (0);
}

int
vpc_rtr_lookupv4(rtr_ctx_t rc, void *key, uint32_t *val)
{
	return (vpc_rtr_lookup(rc, key, val, AF_INET));
}

int
vpc_rtr_lookupv6(rtr_ctx_t rc, void *key, uint32_t *val)
{
	return (vpc_rtr_lookup(rc, key, val, AF_INET6));
}

rtr_ctx_t
vpc_rtr_ctx_alloc(void)
{
	rtr_ctx_t rc;

	rc = malloc(sizeof(*rc), M_VPCROUTE, M_ZERO|M_WAITOK);

	rn_inithead_flags((void **)&rc->rc_rnh4, OFF_LEN_INET, M_WAITOK);
	rn_inithead_flags((void **)&rc->rc_rnh6, OFF_LEN_INET6, M_WAITOK);
	return (rc);
}

static int
free_radix_entry(struct radix_node *rn, void *arg)
{
	struct radix_node_head * const rnh = arg;
	struct radix_addr_entry *ent;

	ent = (struct radix_addr_entry *)
		rn_delete_flags(rn->rn_key, rn->rn_mask, &rnh->rh, M_WAITOK);
	if (ent != NULL)
		free(ent, M_VPCROUTE);
	return (0);
}

void
vpc_rtr_ctx_free(rtr_ctx_t rc)
{
	struct radix_node_head *rnh;

	rnh = rc->rc_rnh4;
	rnh->rnh_walktree(&rnh->rh, free_radix_entry, rnh);
	rn_detachhead((void**)&rc->rc_rnh4);

	rnh = rc->rc_rnh6; 
	rnh->rnh_walktree(&rnh->rh, free_radix_entry, rnh);
	rn_detachhead((void **)&rc->rc_rnh6);

	free(rc, M_VPCROUTE);
}
