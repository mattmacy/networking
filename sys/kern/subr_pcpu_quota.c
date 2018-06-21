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
#include <vm/uma.h>


static MALLOC_DEFINE(M_PCPU_QUOTA, "Per-cpu", "Per-cpu resource accounting.");

#define PCPU_QUOTA_SLOP_GET(p) zpcpu_get((p)->pq_slop)
#define PCPU_QUOTA_CAN_CACHE 0x1

struct pcpu_quota {
	void *pq_context;
	counter_u64_t pq_slop;
	unsigned long *pq_global;
	unsigned long pq_pcpu_slop;
	int (*pq_alloc)(void *context, unsigned long incr, unsigned long *slop);
	int pq_flags;
} __aligned(CACHE_LINE_SIZE);

static void
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

void
pcpu_quota_cache_set(struct pcpu_quota *pq, int enable)
{
	if (!enable && (pq->pq_flags & PCPU_QUOTA_CAN_CACHE)) {
		if (atomic_testandclear_int(&pq->pq_flags, PCPU_QUOTA_CAN_CACHE) == 0)
			pcpu_quota_flush(pq);
	} else if (enable && (pq->pq_flags & PCPU_QUOTA_CAN_CACHE) == 0) {
		atomic_testandset_int(&pq->pq_flags,  PCPU_QUOTA_CAN_CACHE);
	}
}

struct pcpu_quota *
pcpu_quota_alloc(unsigned long *global, unsigned long pcpu_slop,
    int (*alloc)(void *, unsigned long, unsigned long*), void *context, int flags)
{
	struct pcpu_quota *pq;

	flags &= ~M_ZERO;
	if ((pq = malloc(sizeof(*pq), M_PCPU_QUOTA, flags)) == NULL)
		return (NULL);
	if ((pq->pq_slop = counter_u64_alloc(flags)) == NULL) {
		free(pq, M_PCPU_QUOTA);
		return (NULL);
	}
	pq->pq_pcpu_slop = pcpu_slop;
	pq->pq_context = context;
	pq->pq_global = global;
	pq->pq_alloc = alloc;
	pq->pq_flags = PCPU_QUOTA_CAN_CACHE;
	return (pq);
}

void
pcpu_quota_free(struct pcpu_quota *pq)
{
	counter_u64_free(pq->pq_slop);
	free(pq, M_PCPU_QUOTA);
}

int
pcpu_quota_incr(struct pcpu_quota *pq, unsigned long incr)
{
	uint64_t *p;
	int rc;

	critical_enter();
	p = PCPU_QUOTA_SLOP_GET(pq);
	if (*p >= incr) {
		*p -= incr;
		critical_exit();
		return (1);
	}
	incr -= *p;
	*p = 0;
	rc = pq->pq_alloc(pq->pq_context, incr, p);
	if ( __predict_false((pq->pq_flags & PCPU_QUOTA_CAN_CACHE) == 0) && *p > 0)
		pcpu_quota_cache_set(pq, 1);

	critical_exit();
	return (rc);
}

void
pcpu_quota_decr(struct pcpu_quota *pq, unsigned long decr)
{
	uint64_t *p;
	uintptr_t value;

	critical_enter();
	p = PCPU_QUOTA_SLOP_GET(pq);
	if (__predict_true(pq->pq_flags & PCPU_QUOTA_CAN_CACHE)) {
		if (*p + decr <= pq->pq_pcpu_slop) {
			*p += decr;
			critical_exit();
			return;
		}
		decr += (*p - (pq->pq_pcpu_slop >> 1));
		*p = pq->pq_pcpu_slop >> 1;
		atomic_subtract_long(pq->pq_global, decr);
		critical_exit();
		return;
	}
	value = *p + decr;
	*p = 0;
	atomic_subtract_long(pq->pq_global, value);
	critical_exit();
}

