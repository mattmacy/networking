/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018, Matthew Macy <mmacy@freebsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/counter.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/pcpu_quota.h>
#include <sys/smp.h>


static MALLOC_DEFINE(M_PCPU_QUOTA, "Per-cpu", "Per-cpu resource accouting.");

#define PCPU_QUOTA_SLOP_GET(p) ((uint64_t *)((char *)(p)->pq_slop + sizeof(struct pcpu) * curcpu))

struct pcpu_quota {
	void *pq_context;
	counter_u64_t pq_slop;
	unsigned long *pq_global;
	unsigned long pq_pcpu_slop;
	int (*pq_alloc)(void *context, unsigned long incr);
	int (*pq_can_cache)(void *context);
	int pq_flags;
} __aligned(CACHE_LINE_SIZE);

void
pcpu_quota_flush(struct pcpu_quota *pq)
{
	uint64_t *p;
	uintptr_t value;

	critical_enter();
   	p = PCPU_QUOTA_SLOP_GET(pq);
	value = *p;
	*p = 0;
	critical_exit();
	if (value)
		atomic_add_long(pq->pq_global, value);
}

struct pcpu_quota *
pcpu_quota_alloc(unsigned long *global, unsigned long pcpu_slop,
    int (*alloc)(void *, unsigned long), int (*can_cache)(void *),
	void *context, int flags)
{
	struct pcpu_quota *pq;
	int mflags;

	mflags = (flags & PCPU_QUOTA_WAITOK) ? M_WAITOK : M_NOWAIT;
	
	if ((pq = malloc(sizeof(*pq), M_PCPU_QUOTA, mflags)) == NULL)
		return (NULL);
	if ((pq->pq_slop = counter_u64_alloc(mflags)) == NULL) {
		free(pq, M_PCPU_QUOTA);
		return (NULL);
	}
	pq->pq_pcpu_slop = pcpu_slop;
	pq->pq_context = context;
	pq->pq_global = global;
	pq->pq_alloc = alloc;
	pq->pq_can_cache = can_cache;
	pq->pq_flags = flags & ~PCPU_QUOTA_WAITOK;
	return (pq);
}

void
pcpu_quota_free(struct pcpu_quota *pq)
{
	counter_u64_free(pq->pq_slop);
	free(pq, M_PCPU_QUOTA);
}

void
pcpu_quota_enforce(struct pcpu_quota *pq, int enforce)
{
	if (enforce)
		pq->pq_flags |= PCPU_QUOTA_ENFORCING;
	else
		pq->pq_flags &= ~PCPU_QUOTA_ENFORCING;
}

int
pcpu_quota_incr(struct pcpu_quota *pq, unsigned long incr)
{
	uint64_t *p;

	critical_enter();
	p = PCPU_QUOTA_SLOP_GET(pq);
	if (*p >= incr) {
		*p -= incr;
		critical_exit();
		return (1);
	}
	if ((pq->pq_flags & PCPU_QUOTA_ENFORCING) &&
		pq->pq_can_cache(pq->pq_context) == 0) {
		critical_exit();
		return (pq->pq_alloc(pq->pq_context, incr));
	}
	incr -= *p;
	*p = 0;
	if (pq->pq_alloc(pq->pq_context, incr + (pq->pq_pcpu_slop >> 1)) == 0) {
		critical_exit();
		return (pq->pq_alloc(pq->pq_context, incr));
	}
	*p = pq->pq_pcpu_slop >> 1;
	critical_exit();
	return (1);
}

void
pcpu_quota_decr(struct pcpu_quota *pq, unsigned long decr)
{
	uint64_t *p;
	uintptr_t value;

	critical_enter();
	p = PCPU_QUOTA_SLOP_GET(pq);
	if ((pq->pq_flags & PCPU_QUOTA_ENFORCING) &&
		pq->pq_can_cache(pq->pq_context) == 0) {
		value = *p + decr;
		*p = 0;
		atomic_subtract_long(pq->pq_global, value);
		critical_exit();
		return;
	}
		
	if (*p + decr <= pq->pq_pcpu_slop) {
		*p += decr;
		critical_exit();
		return;
	}
	decr += (*p - (pq->pq_pcpu_slop >> 1));
	*p = pq->pq_pcpu_slop >> 1;
	atomic_subtract_long(pq->pq_global, decr);
	critical_exit();
}

