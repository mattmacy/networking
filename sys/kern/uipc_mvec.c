/*
 * Copyright (C) 2017 Matthew Macy <matt.macy@joyent.com>
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

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/smp.h>
#include <sys/sysctl.h>

#include <machine/in_cksum.h>


#define MVEC_DEBUG

#ifdef MVEC_DEBUG
#define  DPRINTF printf
#else
#define DPRINTF(...)
#endif

static MALLOC_DEFINE(M_MVEC, "mvec", "mbuf vector");

static int type2len[] = {-1, MCLBYTES, -1, MJUMPAGESIZE, MJUM9BYTES, MJUM16BYTES, -1, MSIZE};
static int validtypes = ((1<<EXT_CLUSTER)|(1<<EXT_JUMBOP)|(1<<EXT_JUMBO9)|(1<<EXT_JUMBO16)|(1<<EXT_MBUF));


#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE32							  \
    {									  \
	q_util.q = sum;							  \
	sum = q_util.s[0] + q_util.s[1] + q_util.s[2] + q_util.s[3];	  \
    }
#define REDUCE16							  \
    {									  \
	q_util.q = sum;							  \
	l_util.l = q_util.s[0] + q_util.s[1] + q_util.s[2] + q_util.s[3]; \
	sum = l_util.s[0] + l_util.s[1];				  \
	ADDCARRY(sum);							  \
    }

uint64_t in_cksumdata(const void *buf, int len);

union l_util {
	u_int16_t s[2];
	u_int32_t l;
};
union q_util {
	u_int16_t s[4];
	u_int32_t l[2];
	u_int64_t q;
};


#ifdef INVARIANTS
static void
mvec_sanity(struct mbuf *m)
{
	struct mbuf_ext *mext;
	struct mvec_header *mh;
	struct mvec_ent *me;
	int i, total;

	mext = (void*)m;
	mh = &mext->me_mh;
	me = &mext->me_ents[mh->mh_start];
	total = 0;
	MPASS(m->m_len == me->me_len);
	MPASS(m->m_data == (me->me_cl + me->me_off));
	MPASS(mh->mh_count >= (mh->mh_start + mh->mh_used));
	for (i = mh->mh_start; i < mh->mh_used + mh->mh_start; i++, me++) {
		if (__predict_false(me->me_len == 0))
			continue;

		MPASS(me->me_cl);
		MPASS(me->me_cl != (void *)0xdeadc0dedeadc0de);
		total += me->me_len;
	}
	MPASS(total == m->m_pkthdr.len);
}
#else
static void
mvec_sanity(struct mbuf *m) {}
#endif

static void
mvec_buffer_free(struct mbuf *m)
{
	struct mvec_header *mh;

	mh = MBUF2MH(m);
	switch (mh->mh_mvtype) {
		case MVALLOC_MALLOC:
			free(m, M_MVEC);
			break;
		case MVALLOC_MBUF:
#ifdef INVARIANTS
			m->m_flags &= ~M_NOFREE;
#endif
			uma_zfree_arg(zone_mbuf, m, (void *)MB_DTOR_SKIP);
			break;
	}
}


static void
mvec_clfree(struct mvec_ent *me, m_refcnt_t *refcntp, bool dupref)
{
	bool free = true;
	struct mbuf *mref;
	volatile uint32_t *refcnt;

	mref = NULL;
	if (dupref) {
		if (me->me_ext_flags & EXT_FLAG_EMBREF) {
			refcnt = &refcntp->ext_count;
		} else {
			refcnt = refcntp->ext_cnt;
		}
		free = (*refcnt == 1 || atomic_fetchadd_int(refcnt, -1) == 1);
	}
	if (!free)
		return;
	if (!(me->me_ext_flags & EXT_FLAG_NOFREE))
		mref =  __containerof(refcnt, struct mbuf, m_ext.ext_count);

	switch (me->me_ext_type) {
		case EXT_CLUSTER:
			uma_zfree(zone_clust, me->me_cl);
			break;
		case EXT_JUMBOP:
			uma_zfree(zone_jumbop, me->me_cl);
			break;
		case EXT_JUMBO9:
			uma_zfree(zone_jumbo9, me->me_cl);
			break;
		case EXT_JUMBO16:
			uma_zfree(zone_jumbo16, me->me_cl);
			break;
		default:
			panic("unsupported ext_type: %d\n", me->me_ext_type);
	}
	if (mref != NULL)
		uma_zfree_arg(zone_mbuf, mref, (void *)MB_DTOR_SKIP);
}

static void
mvec_ent_free(struct mvec_header *mh, int idx)
{
	struct mvec_ent *me = (struct mvec_ent *)(mh + 1);
	m_refcnt_t *me_count = (m_refcnt_t *)(me + mh->mh_count);

	me += idx;
	me_count += idx;
	switch (me->me_type) {
		case MVEC_MBUF:
			uma_zfree_arg(zone_mbuf, me->me_cl, (void *)MB_DTOR_SKIP);
			break;
		case MVEC_MANAGED:
			mvec_clfree(me, me_count, mh->mh_multiref);
			break;
		default:
			/* ... */
			break;
	}
}

void
mvec_seek(struct mbuf *m, struct mvec_cursor *mc, int offset)
{
	struct mvec_ent *me = MBUF2ME(m);
	struct mvec_header *mh = MBUF2MH(m);
	int rem;

	mc->mc_idx = mc->mc_off = 0;
	MPASS(offset <= m->m_pkthdr.len);
	rem = offset;

	me = MHMEI(m, mh, 0);
	do {
		if (rem > me->me_len) {
			rem -= me->me_len;
			me++;
			mc->mc_idx++;
		} else if (rem < me->me_len) {
			rem = 0;
			mc->mc_off = rem;
		} else {
			rem = 0;
			mc->mc_idx++;
		}
	} while(rem);
}

static void
mvec_trim_head(struct mbuf *m, int offset)
{
	struct mvec_header *mh = MBUF2MH(m);
	struct mvec_ent *me = MBUF2ME(m);
	int rem;
	bool owned;

	MPASS(offset <= m->m_pkthdr.len);
	rem = offset;
	if (m->m_ext.ext_flags & EXT_FLAG_EMBREF) {
		owned = (m->m_ext.ext_count == 1);
	} else {
		owned = (*(m->m_ext.ext_cnt) == 1);
	}
	do {
		if (rem > me->me_len) {
			rem -= me->me_len;
			if (owned)
				mvec_ent_free(mh, mh->mh_start);
			mh->mh_start++;
			mh->mh_used--;
			me++;
		} else if (rem < me->me_len) {
			rem = 0;
			me->me_off += rem;
			me->me_len -= rem;
		} else {
			rem = 0;
			mvec_ent_free(mh, mh->mh_start);
			mh->mh_start++;
			mh->mh_used--;
		}
	} while(rem);
	m->m_pkthdr.len -= offset;
	m->m_data = ME_SEG(m, mh, 0);
}

static void
mvec_trim_tail(struct mbuf *m, int offset)
{
	struct mvec_header *mh = MBUF2MH(m);
	struct mvec_ent *me = MBUF2ME(m);
	int i, rem;
	bool owned;

	MPASS(offset <= m->m_pkthdr.len);
	rem = offset;
	if (m->m_ext.ext_flags & EXT_FLAG_EMBREF) {
		owned = (m->m_ext.ext_count == 1);
	} else {
		owned = (*(m->m_ext.ext_cnt) == 1);
	}
	i = mh->mh_count-1;
	me = &me[i];
	do {
		if (rem > me->me_len) {
			rem -= me->me_len;
			me->me_len = 0;
			if (owned)
				mvec_ent_free(mh, i);
			me--;
			mh->mh_used--;
		} else if (rem < me->me_len) {
			rem = 0;
			me->me_len -= rem;
		} else {
			rem = 0;
			me->me_len = 0;
			if (owned)
				mvec_ent_free(mh, i);
			mh->mh_used--;
		}
		i++;
	} while(rem);
	m->m_pkthdr.len -= offset;
}

void
mvec_adj(struct mbuf *m, int req_len)
{
	if (__predict_false(req_len == 0))
		return;
	if (req_len > 0)
		mvec_trim_head(m, req_len);
	else
		mvec_trim_tail(m, req_len);
}

void
mvec_copydata(const struct mbuf *m, int off, int len, caddr_t cp)
{
	panic("%s unimplemented", __func__);
}

struct mbuf *
mvec_dup(const struct mbuf *m, int how)
{
	panic("%s unimplemented", __func__);
	return (NULL);
}

struct mbuf *
mvec_defrag(const struct mbuf *m, int how)
{
	panic("%s unimplemented", __func__);
	return (NULL);
}

struct mbuf *
mvec_collapse(struct mbuf *m, int how, int maxfrags)
{
	panic("%s unimplemented", __func__);
	return (NULL);
}

uint16_t
mvec_cksum_skip(struct mbuf *m, int len, int skip)
{
	u_int64_t sum = 0;
	int mlen = 0;
	int clen = 0;
	caddr_t addr;
	union q_util q_util;
	union l_util l_util;
	struct mvec_cursor mc;
	struct mvec_header mh;
	struct mvec_ent *me;

	MPASS((m->m_flags & M_EXT) && (m->m_ext.ext_type == EXT_MVEC));

	len -= skip;
	mvec_seek(m, &mc, skip);
	mh = *(MBUF2MH(m));

	/* XXX */
	if (mh.mh_multipkt)
		return (0);

	me = MHMEI(m, &mh, mc.mc_idx);
	addr = me->me_cl + me->me_off;
	goto skip_start;

	for (; mh.mh_used && len; me++) {
		mh.mh_used--;
		if (me->me_len == 0)
			continue;
		mlen = me->me_len;
		addr = me->me_cl + me->me_off;
skip_start:
		if (len < mlen)
			mlen = len;
		if ((clen ^ (long) addr) & 1)
		    sum += in_cksumdata(addr, mlen) << 8;
		else
		    sum += in_cksumdata(addr, mlen);

		clen += mlen;
		len -= mlen;
	}
	REDUCE16;
	return (~sum & 0xffff);
}

struct mbuf *
mvec_prepend(struct mbuf *m, int size)
{
	struct mvec_header *mh;
	struct mvec_ent *me;
	struct mbuf *data;
	struct mbuf_ext *mext;

	MPASS(size <= MSIZE);
	if (__predict_false((data = m_get(M_NOWAIT, MT_NOINIT)) == NULL))
		return (NULL);

	mext = (struct mbuf_ext *)m;
	mh = &mext->me_mh;
	if (__predict_true(mh->mh_start)) {
		mh->mh_start--;
		mh->mh_used++;
		me = MHMEI(m, mh, 0);
		me->me_len = size;
		me->me_cl = (caddr_t)data;
		me->me_off = 0;
		me->me_type = MVEC_MBUF;
		me->me_eop = 0;
		me->me_ext_flags = 0;
		me->me_ext_type = EXT_MBUF;
		m->m_pkthdr.len += size;
		m->m_len = size;
		m->m_data = me->me_cl;
	} else {
		panic("implement fallback path for %s", __func__);
	}
	return (m);
}

struct mbuf *
mvec_append(struct mbuf *m, caddr_t cl, uint16_t off,
						 uint16_t len, uint8_t cltype)
{
	struct mvec_header *mh;
	struct mvec_ent *me;

	mh = MBUF2MH(m);
	KASSERT(mh->mh_used < mh->mh_count,
			("need to add support for growing mvec on append"));
	me = MHMEI(m, mh, mh->mh_used);
	me->me_cl = cl;
	me->me_off = off;
	me->me_len = len;
	me->me_ext_type = cltype;
	me->me_ext_flags = 0;
	m->m_pkthdr.len += len;
	if (mh->mh_used == 0) {
		m->m_len = len;
		m->m_data = (cl + off);
	}
	mh->mh_used++;
	return (m);
}

int
mvec_init_mbuf(struct mbuf *m, uint8_t count, uint8_t type)
{
	struct mvec_header *mh;
	int rc;

	mh = MBUF2MH(m);
	*((uint64_t *)mh) = 0;
	mh->mh_count = count;
	mh->mh_mvtype = type;
	/* leave room for prepend */
	mh->mh_start = 1;
	rc = m_init(m, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (__predict_false(rc))
		return (rc);

	m->m_next = m->m_nextpkt = NULL;
	m->m_len = 0;
	m->m_data = NULL;
	m->m_flags = M_PKTHDR|M_NOFREE|M_EXT;
	m->m_ext.ext_free = NULL;
	m->m_ext.ext_arg1 = m->m_ext.ext_arg2 = NULL;
	m->m_ext.ext_flags = EXT_FLAG_EMBREF;
	m->m_ext.ext_type = EXT_MVEC;
	m->m_ext.ext_size = MSIZE;
	m->m_ext.ext_buf = (caddr_t)m;
	m->m_ext.ext_cnt = NULL;
	m->m_ext.ext_count = 1;
	return (0);
}

struct mbuf_ext *
mvec_alloc(uint8_t count, int len, int how)
{
	int size;
	uint8_t type;
	struct mbuf_ext *m;

	size = sizeof(*m) + count*sizeof(struct mvec_ent);
	size += len;
	if (size <= MSIZE) {
		m = (void*)m_get(how, MT_NOINIT);
		type = MVALLOC_MBUF;
	} else {
		m = malloc(size, M_MVEC, how);
		type = MVALLOC_MALLOC;
	}
	if (__predict_false(m == NULL))
		return (NULL);
	mvec_init_mbuf((struct mbuf *)m, count, type);
	return (m);
}

static int
mvec_ent_size(struct mvec_ent *me)
{
	int type;

	MPASS(me->me_ext_type && (me->me_ext_type < 32));

	type = me->me_ext_type;
	MPASS((1<<type) & validtypes);
	return (type2len[type]);
}

struct mbuf *
mvec_pullup(struct mbuf *m, int count)
{
	struct mvec_header *mh;
	struct mvec_ent *mecur, *menxt;
	int tailroom, size, copylen, doff, i, len;

	mvec_sanity(m);
	MPASS(count <= m->m_pkthdr.len);
	mh = MBUF2MH(m);
	mecur = MHMEI(m, mh, 0);
	size = mvec_ent_size(mecur);
	tailroom = size - mecur->me_off - mecur->me_len;
	MPASS(tailroom >= 0);
	copylen = count - mecur->me_len;

	if (__predict_false(count <= mecur->me_len))
		return (m);
	/*
	 * XXX - If we're not the exclusive owner we need to allocate a new
	 * buffer regardless.
	 */
	if (copylen > size) {
		/* allocate new buffer */
		panic("allocate new buffer copylen=%d size=%d", copylen, size);
	} else if (copylen > tailroom) {
		/*
		 * move data up if possible
		 * else allocate new buffer
		 */
		panic("relocate data copylen=%d size=%d tailroom=%d", copylen, size, tailroom);
	}
	doff = mecur->me_off + mecur->me_len;
	i = 1;
	do {
		menxt = MHMEI(m, mh, i);
		len = min(copylen, menxt->me_len);
		bcopy(ME_SEG(m, mh, i), mecur->me_cl + doff, len);
		doff += len;
		mecur->me_len += len;
		menxt->me_off += len;
		menxt->me_len -= len;
		copylen -= len;
		i++;
	} while (copylen);
	m->m_data = ME_SEG(m, mh, 0);
	m->m_len = ME_LEN(m, mh, 0);
	mvec_sanity(m);
	return (m);
}

void
mvec_free(struct mbuf *m)
{
	struct mvec_header *mh;
	struct mvec_ent *me;
	m_refcnt_t *me_count;
	int i;

	mh = (struct mvec_header *)m->m_pktdat + sizeof(struct m_ext);
	me = (struct mvec_ent *)(mh + 1);
	me_count = (m_refcnt_t *)(me + mh->mh_count);

	for (i = 0; i < mh->mh_count; i++, me_count++, me++) {
		if (__predict_false(me->me_cl == NULL))
			continue;
		switch (me->me_type) {
			case MVEC_MBUF:
				uma_zfree_arg(zone_mbuf, me->me_cl, (void *)MB_DTOR_SKIP);
				break;
			case MVEC_MANAGED:
				mvec_clfree(me, me_count, mh->mh_multiref);
				break;
			default:
				/* ... */
				break;
		}
	}
	mvec_buffer_free(m);
}

struct mbuf_ext *
mchain_to_mvec(struct mbuf *m, int how)
{
	struct mbuf *mp, *mnext;
	struct mbuf_ext *mnew;
	struct mvec_header *mh;
	struct mvec_ent *me;
	int count, size;
	bool dupref;
	m_refcnt_t *me_count;

	size = count = 0;
	mp = m;
	dupref = false;
	do {
		mnext = mp->m_next;
		count++;
		if (mp->m_flags & M_EXT) {
			/*
			 * bail on ext_free -- we can't efficiently pass an mbuf
			 * at free time and m_ext adds up to a lot of space
			 */
			if (mp->m_ext.ext_free != NULL) {
				DPRINTF("%s ext_free is set: %p\n", __func__, mp->m_ext.ext_free);
				return (NULL);
			}
			if (!(mp->m_ext.ext_flags & EXT_FLAG_EMBREF && mp->m_ext.ext_count == 1))
				dupref = true;
		}
		mp = mnext;
	} while (mp);

	/* add spare */
	count++;
	if (dupref)
		size = count*sizeof(void*);
	mnew = mvec_alloc(count, size, how);

	if (mnew == NULL) {
		DPRINTF("%s malloc failed\n", __func__);
		return (NULL);
	}
	mh = &mnew->me_mh;
	mh->mh_used = count-1;
	MPASS(mh->mh_count == mh->mh_used+1);
	mh->mh_multiref = dupref;
	/* leave first entry open for encap */
	bcopy(&m->m_pkthdr, &mnew->me_mbuf.m_pkthdr, sizeof(struct pkthdr));

	me = mnew->me_ents;
	MPASS(mh->mh_start == 1);
	me->me_cl = NULL;
	me->me_off = me->me_len = 0;
	me++;
	me_count = MBUF2REF(mnew);
	if (dupref)
		bzero(me_count, count*sizeof(void *));
	me_count++;
	mp = m;
	do {
		mnext = mp->m_next;
		if (mp->m_flags & M_EXT) {
			me->me_cl = mp->m_ext.ext_buf;
			me->me_off = ((uintptr_t)mp->m_data - (uintptr_t)mp->m_ext.ext_buf);
			me->me_type = MVEC_MANAGED;
			me->me_ext_flags = mp->m_ext.ext_flags;
			me->me_ext_type = mp->m_ext.ext_type;
		} else {
			me->me_cl = (caddr_t)mp;
			me->me_off = ((uintptr_t)(mp->m_data) - (uintptr_t)mp);
			me->me_type = MVEC_MBUF;
			me->me_ext_flags = 0;
			me->me_ext_type = EXT_MBUF;
		}
		me->me_len = mp->m_len;
		me->me_eop = 0;
		if (dupref) {
			if (m->m_flags & M_EXT) {
				if (mp->m_ext.ext_flags & EXT_FLAG_EMBREF) {
					me_count->ext_cnt = &mp->m_ext.ext_count;
					me->me_ext_flags &= ~EXT_FLAG_EMBREF;
				} else
					me_count->ext_cnt = mp->m_ext.ext_cnt;
			}
			if (mp->m_flags & M_NOFREE)
				me->me_ext_flags |= EXT_FLAG_NOFREE;
		}
		me_count++;
		mp = mnext;
		me++;
	} while (mp);
	mnew->me_mbuf.m_len = mnew->me_ents[1].me_len;
	mnew->me_mbuf.m_data = (mnew->me_ents[1].me_cl + mnew->me_ents[1].me_off);
	mh = MBUF2MH(mnew);
	MPASS(mh->mh_count == mh->mh_start + mh->mh_used);
	mvec_sanity((void*)mnew);
	return (mnew);
}

struct mbuf *
pktchain_to_mvec(struct mbuf *m, int mtu, int how)
{
	struct mbuf *mh, *mt, *mp, *mnext;
	struct mbuf_ext *mnew;

	mp = m;
	mt = mh = NULL;
	while (mp) {
		mnext = mp->m_nextpkt;
		if (!m_ismvec(mp) && mp->m_pkthdr.len > mtu) {
			mnew = mchain_to_mvec(mp, how);
			if (__predict_false(mnew == NULL)) {
				m_freem(mp);
			} else
				mp = (void*)mnew;
		}
		MPASS(mp);
		if (mh == NULL) {
			mh = mt = mp;
		} else {
			mt->m_nextpkt = mp;
			mt = mp;
		}
		mp = mnext;
	}
	return (mh);
}

static void
m_ext_init(struct mbuf *m, struct mbuf_ext *head, struct mvec_header *mh)
{
	struct mvec_ent *me;
	struct mbuf *headm;
	bool doref;

	headm = &head->me_mbuf;
	doref = true;
	me = &head->me_ents[head->me_mh.mh_start];
	m->m_ext.ext_buf = me->me_cl;
	m->m_ext.ext_arg1 = headm->m_ext.ext_arg1;
	m->m_ext.ext_arg2 = headm->m_ext.ext_arg2;
	m->m_ext.ext_free = headm->m_ext.ext_free;
	m->m_ext.ext_type = me->me_ext_type;
	if (me->me_ext_type) {
		m->m_ext.ext_flags = me->me_ext_flags;
		m->m_ext.ext_size = mvec_ent_size(me);
	} else {
		m->m_ext.ext_flags = EXT_FLAG_NOFREE;
		/* Only used by m_sanity so just call it our size */
		m->m_ext.ext_size = me->me_len;
	}
	/*
	 * There are 3 cases for refcount transfer:
	 *  1) all clusters are owned by the mvec [default]
	 *     - point at mvec refcnt and increment
	 *  2) cluster has a normal external refcount
	 */
	if (__predict_true(!head->me_mh.mh_multiref)) {
		m->m_ext.ext_flags = EXT_FLAG_MVECREF;
		if (headm->m_ext.ext_flags & EXT_FLAG_EMBREF)
			m->m_ext.ext_cnt = &headm->m_ext.ext_count;
		else
			m->m_ext.ext_cnt = headm->m_ext.ext_cnt;
	} else {
		m_refcnt_t *ref = MHREFI(headm, mh, 0);

		m->m_ext.ext_cnt = ref->ext_cnt;
		if (ref->ext_cnt == NULL) {
			m->m_ext.ext_flags |= EXT_FLAG_EMBREF;
			m->m_ext.ext_count = 1;
			doref = false;
		}
	}
	if (doref)
		atomic_add_int(m->m_ext.ext_cnt, 1);
}

static struct mbuf *
mvec_to_mchain_pkt(struct mbuf_ext *mp, struct mvec_header *mhdr, int how)
{
	struct mvec_ent *me;
	struct mbuf *m, *mh, *mt, *mpm;

	if (__predict_false((mh = m_gethdr(how, MT_DATA)) == NULL))
		return (NULL);

	mpm = &mp->me_mbuf;
	me = MHMEI(mp, mhdr, 0);
	mh->m_flags |= M_EXT;
	mh->m_flags |= mpm->m_flags & (M_BCAST|M_MCAST|M_PROMISC|M_VLANTAG|M_VXLANTAG);
	/* XXX update csum_data after encap */
	mh->m_pkthdr.csum_data = mpm->m_pkthdr.csum_data;
	mh->m_pkthdr.csum_flags = mpm->m_pkthdr.csum_flags;
	mh->m_pkthdr.vxlanid = mpm->m_pkthdr.vxlanid;
	m_ext_init(mh, mp, mhdr);
	mh->m_data = me->me_cl + me->me_off;
	mh->m_pkthdr.len = mh->m_len = me->me_len;
	mhdr->mh_start++;
	mhdr->mh_used--;
	mt = mh;
	while (!me->me_eop && mhdr->mh_used) {
		if (__predict_false((m = m_get(how, MT_DATA)) == NULL))
			goto fail;
		me++;
		mhdr->mh_start++;
		mhdr->mh_used--;
		mt->m_next = m;
		mt = m;
		mt->m_flags |= M_EXT;
		m_ext_init(mt, mp, mhdr);
		mt->m_len = me->me_len;
		mh->m_pkthdr.len += mt->m_len;
		mt->m_data = me->me_cl + me->me_off;
	}
#ifdef INVARIANTS
	m_sanity(mh, 0);
#endif
	return (mh);
 fail:
	if (mh)
		m_freem(mh);
	return (NULL);
}

struct mbuf *
mvec_to_mchain(struct mbuf *mp, int how)
{
	struct mvec_header *pmhdr, mhdr;
	struct mbuf *mh, *mt, *m;

	mvec_sanity(mp);
	pmhdr = MBUF2MH(mp);
	bcopy(pmhdr, &mhdr, sizeof(mhdr));
	mh = mt = NULL;
	while (mhdr.mh_used) {
		if (__predict_false((m = mvec_to_mchain_pkt((struct mbuf_ext *)mp, &mhdr, how)) == NULL)) {
			DPRINTF("mvec_to_mchain_pkt failed\n");
			goto fail;
		}
		if (mh != NULL) {
			mt->m_nextpkt = m;
			mt = m;
		} else
			mh = mt = m;
	}
#ifdef INVARIANTS
	m_sanity(mh, 0);
#endif
	return (mh);
 fail:
	m_freechain(mh);
	return (NULL);
}

/*
 * Move the below to net/ once working 
 */

#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <net/iflib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <machine/in_cksum.h>

#define MIN_HDR_LEN   (ETHER_HDR_LEN + sizeof(struct ip) + sizeof(struct tcphdr))

static int
mvec_parse_header(struct mbuf_ext *mp, int prehdrlen, if_pkt_info_t pi)
{
	struct ether_vlan_header *evh;
	struct mvec_header *mh = &mp->me_mh;
	struct mbuf *m;

	m = (void*)mp;
	mvec_sanity(m);
	if (__predict_false(m->m_len < MIN_HDR_LEN + prehdrlen) &&
		__predict_false(mvec_pullup(m, prehdrlen + MIN_HDR_LEN) == NULL))
			return (ENOMEM);
	evh = (struct ether_vlan_header *)(ME_SEG(m, mh, 0) + prehdrlen);
	if (evh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		pi->ipi_etype = ntohs(evh->evl_proto);
		pi->ipi_ehdrlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
	} else {
		pi->ipi_etype = ntohs(evh->evl_encap_proto);
		pi->ipi_ehdrlen = ETHER_HDR_LEN;
	}
	switch (pi->ipi_etype) {
		case ETHERTYPE_IP: {
			struct ip *ip = NULL;
			struct tcphdr *th = NULL;
			int minthlen;

			minthlen = pi->ipi_ehdrlen + sizeof(*ip) + sizeof(*th);
			if (__predict_false(m->m_len < minthlen + prehdrlen) &&
				__predict_false(mvec_pullup(m, prehdrlen + minthlen) == NULL))
				return (ENOMEM);
			ip = (struct ip *)(ME_SEG(m, mh, 0) + prehdrlen + pi->ipi_ehdrlen);
			pi->ipi_ip_hlen = ip->ip_hl << 2;
			pi->ipi_ipproto = ip->ip_p;
			if (ip->ip_p != IPPROTO_TCP)
				return (EINVAL);
			minthlen = pi->ipi_ehdrlen + pi->ipi_ip_hlen + sizeof(*th);
			if (__predict_false(m->m_len < minthlen + prehdrlen) &&
				__predict_false(mvec_pullup(m, prehdrlen + minthlen) == NULL))
				return (ENOMEM);
			th = (struct tcphdr *)(ME_SEG(m, mh, 0) + prehdrlen + pi->ipi_ehdrlen + pi->ipi_ip_hlen);
			pi->ipi_tcp_hflags = th->th_flags;
			pi->ipi_tcp_hlen = th->th_off << 2;
			pi->ipi_tcp_seq = th->th_seq;
			minthlen = pi->ipi_ehdrlen + pi->ipi_ip_hlen + pi->ipi_tcp_hlen;
			if (__predict_false(m->m_len < minthlen + prehdrlen) &&
				__predict_false(mvec_pullup(m, prehdrlen + minthlen) == NULL))
				return (ENOMEM);
			if (prehdrlen == 0) {
				th->th_sum = in_pseudo(ip->ip_src.s_addr,
									   ip->ip_dst.s_addr, htons(IPPROTO_TCP));
				ip->ip_sum = 0;
				ip->ip_len = htons(pi->ipi_ip_hlen + pi->ipi_tcp_hlen + pi->ipi_tso_segsz);

			}
			break;
		}
		case ETHERTYPE_IPV6: {
			break;
		}
		default:
			/* XXX unsupported -- error */
			break;
	}
	mvec_sanity(m);
	return (0);
}

struct tso_state {
	if_pkt_info_t ts_pi;
	uint16_t ts_idx;
	uint16_t ts_prehdrlen;
	tcp_seq ts_seq;
};

static void
tso_init(struct tso_state *state, caddr_t hdr, if_pkt_info_t pi, int prehdrlen)
{
	struct ip *ip;

	ip = (struct ip *)(hdr + prehdrlen + pi->ipi_ehdrlen);
	state->ts_pi = pi;
	state->ts_idx = ntohs(ip->ip_id);
	state->ts_prehdrlen = prehdrlen;
	state->ts_seq = pi->ipi_tcp_seq;
}

static void
tso_fixup(struct tso_state *state, caddr_t hdr, int len, bool last)
{
	if_pkt_info_t pi = state->ts_pi;
	struct ip *ip;
	struct tcphdr *th;

	if (pi->ipi_etype == ETHERTYPE_IP) {
		ip = (struct ip *)(hdr + state->ts_prehdrlen + pi->ipi_ehdrlen);
		ip->ip_len = htons(len);
		ip->ip_id = htons(state->ts_idx);
		ip->ip_sum = 0;
		state->ts_idx++;
	} else if (pi->ipi_etype == ETHERTYPE_IPV6) {
		/* XXX notyet */
	} else {
		panic("bad ethertype %d in tso_fixup", pi->ipi_etype);
	}
	if (pi->ipi_ipproto == IPPROTO_TCP) {
		th = (struct tcphdr *)(hdr + state->ts_prehdrlen + pi->ipi_ehdrlen + pi->ipi_ip_hlen);
		th->th_seq = htonl(state->ts_seq);
		state->ts_seq += len;
		th->th_sum = 0;

		/* Zero the PSH and FIN TCP flags if this is not the last
		   segment. */
		if (!last)
			th->th_flags &= ~(0x8 | 0x1);
	} else {
		panic("non TCP IPPROTO %d in tso_fixup", pi->ipi_ipproto);
	}
}

struct mbuf_ext *
mvec_tso(struct mbuf_ext *mprev, int prehdrlen, bool freesrc)
{
	struct mvec_header *mh, *newmh;
	struct mvec_cursor mc;
	struct mvec_ent *me, *mesrc, *medst, *newme;
	struct mbuf_ext *mnew;
	struct mbuf *m;
	struct if_pkt_info pi;
	struct tso_state state;
	m_refcnt_t *newme_count, *medst_count, *mesrc_count;
	int segcount, soff, segrem, srem;
	int i, ntsofrags, segsz, cursegrem, nheaders, hdrsize;
	int refsize, rem, curseg, count, pktrem, srci, dsti;
	volatile uint32_t *refcnt;
	bool dupref, dofree;
	caddr_t hdrbuf;

	m = (void*)mprev;
	mvec_sanity(m);
	dofree = false;
	if (m->m_ext.ext_flags & EXT_FLAG_EMBREF) {
		refcnt = &m->m_ext.ext_count;
	} else {
		refcnt = m->m_ext.ext_cnt;
	}
	if (freesrc && (*refcnt == 1))
		dofree = true;

	segsz = m->m_pkthdr.tso_segsz;
	pktrem = m->m_pkthdr.len;
	refsize = 0;
	mh = &mprev->me_mh;
	me = mprev->me_ents;
	dupref = mh->mh_multiref;
	pi.ipi_tso_segsz = segsz;
	if (mvec_parse_header(mprev, prehdrlen, &pi))
		return (NULL);
	hdrsize = prehdrlen + pi.ipi_ehdrlen + pi.ipi_ip_hlen + pi.ipi_tcp_hlen;
	pktrem -= hdrsize;
	nheaders = pktrem / segsz;
	if (nheaders*segsz != pktrem)
		nheaders++;
	for (segcount = i = 0; i < mh->mh_count; i++, me++) {
		if (__predict_false(me->me_len == 0))
			continue;
		rem = me->me_len;
		if (rem < cursegrem) {
			cursegrem -= rem;
			segcount++;
		} else if (rem == cursegrem) {
			segcount++;
			ntsofrags = 0;
			cursegrem = segsz;
		} else {
			while (rem) {
				curseg = min(rem, cursegrem);
				rem -= curseg;
				cursegrem -= curseg;
				if (!cursegrem)
					cursegrem = segsz;
				segcount++;
			}
		}
	}

	count = segcount + nheaders;
	if (mh->mh_multiref)
		refsize = count*sizeof(void*);

	refsize += (nheaders * hdrsize);
	mnew = mvec_alloc(count, refsize, M_NOWAIT);
	if (__predict_false(mnew == NULL))
		return (NULL);
	bcopy(&m->m_pkthdr, &mnew->me_mbuf.m_pkthdr, sizeof(struct pkthdr));
	newmh = &mnew->me_mh;
	newmh->mh_start = 0;
	newmh->mh_used = count;
	newmh->mh_multiref = mh->mh_multiref;
	newmh->mh_multipkt = true;
	newme = mnew->me_ents;
	newme_count = MBUF2REF(mnew);
	__builtin_prefetch(newme_count);
	medst_count = newme_count;
	medst = newme;

	/*
	 * skip past header info
	 */
	mvec_seek(m, &mc, hdrsize);
	mesrc = mprev->me_ents;
	mesrc_count = &MBUF2REF(m)[mc.mc_idx];
	soff = mc.mc_off;
	if (dupref) {
		bzero(medst_count, count*sizeof(void *));
		medst_count++;
	}
	medst[0].me_cl = NULL;
	medst[0].me_len = 0;
	/*
	 * Packet segmentation loop
	 */
	srci = mc.mc_idx;
	dsti = 1;
	for (i = 0; i < nheaders; i++) {
		MPASS(pktrem > 0);
		segrem = min(segsz, pktrem);
		do {
			MPASS(srci < mprev->me_mh.mh_count);
			MPASS(dsti < mnew->me_mh.mh_count);
			if (__predict_false(mesrc[srci].me_len == 0)) {
				srci++;
				mesrc_count++;
				continue;
			}
			if (soff == 0) {
				if (dupref) {
					*medst_count = *mesrc_count;
					if (!dofree && (mesrc_count->ext_cnt != NULL))
						atomic_add_int(mesrc_count->ext_cnt, 1);
				}
				mesrc_count++;
				medst->me_type = mesrc->me_type;
				medst->me_ext_flags = mesrc->me_ext_flags;
				medst->me_ext_type = mesrc->me_ext_type;
			} else {
				medst->me_type = MVEC_UNMANAGED;
				medst->me_ext_flags = 0;
				medst->me_ext_type = 0;
			}
			srem = mesrc[srci].me_len - soff;
			medst[dsti].me_cl = mesrc[srci].me_cl;
			medst[dsti].me_off = mesrc[srci].me_off + soff;
			if (srem == segrem) {
				medst[dsti].me_eop = 1;
				soff = 0;
				medst[dsti].me_len = srem;
				segrem = 0;
				pktrem -= segrem;
				srci++;
			} else if (srem < segrem) {
				medst[dsti].me_eop = 0;
				soff = 0;
				medst[dsti].me_len = srem;
				pktrem -= srem;
				segrem -= srem;
				srci++;
			} else {
				medst[dsti].me_eop = 1;
				soff += segrem;
				pktrem -= segrem;
				medst[dsti].me_len = segrem;
				segrem = 0;
			}
			dsti++;
			medst_count++;
		} while (segrem);

		/* skip next header */
		medst[dsti].me_cl = NULL;
		dsti++;
		medst_count++;
	}

	/*
	 * Special case first header
	 */
	medst = newme;
	mesrc = MHMEI(m, MBUF2MH(m), 0);


	/*
	 * Header initialization loop
	 */
	hdrbuf = ((caddr_t)(newme + count)) + refsize;
	tso_init(&state, mesrc->me_cl + mesrc->me_off, &pi, prehdrlen);
	pktrem = m->m_pkthdr.len - hdrsize;
	for (dsti = i = 0; i < nheaders; i++) {
		MPASS(pktrem > 0);
		/* skip ahead to next header slot */
		while (medst[dsti].me_cl != NULL)
			dsti++;
		bcopy(mesrc->me_cl + mesrc->me_off, hdrbuf, hdrsize);
		tso_fixup(&state, hdrbuf, min(pktrem, segsz), (pktrem <= segsz));
		pktrem -= segsz;
		medst[dsti].me_cl = hdrbuf;
		medst[dsti].me_off = 0;
		medst[dsti].me_len = hdrsize;
		medst[dsti].me_type = MVEC_UNMANAGED;
		medst[dsti].me_ext_flags = 0;
		medst[dsti].me_ext_type = 0;
		medst[dsti].me_eop = 0;
		hdrbuf += hdrsize;
	}

	mnew->me_mbuf.m_len = mnew->me_ents->me_len;
	mnew->me_mbuf.m_data = (mnew->me_ents->me_cl + mnew->me_ents->me_off);
	mnew->me_mbuf.m_pkthdr.len = m->m_pkthdr.len + (nheaders - 1)*hdrsize;
	mvec_sanity((struct mbuf *)mnew);
	if (dofree) {
		if (mesrc->me_cl && (mesrc->me_type == MVEC_MBUF) && mesrc->me_len == hdrsize)
			uma_zfree_arg(zone_mbuf, mesrc->me_cl, (void *)MB_DTOR_SKIP);
		mnew->me_mbuf.m_ext.ext_count = 1;
		if (!(m->m_ext.ext_flags & EXT_FLAG_EMBREF))
			mvec_buffer_free(__containerof(refcnt, struct mbuf, m_ext.ext_count));
		/* XXX we're leaking here */
		mvec_buffer_free(m);
	} else {
		if (m->m_ext.ext_flags & EXT_FLAG_EMBREF)
			mnew->me_mbuf.m_ext.ext_cnt = m->m_ext.ext_cnt;
		else
			mnew->me_mbuf.m_ext.ext_cnt = &m->m_ext.ext_count;
		atomic_add_int(mnew->me_mbuf.m_ext.ext_cnt, 1);
	}
	return (mnew);
}
