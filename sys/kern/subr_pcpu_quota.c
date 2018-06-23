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
#include <sys/epoch.h>
#include <sys/systm.h>
#include <sys/counter.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/pcpu_quota.h>
#include <sys/smp.h>
#include <vm/uma.h>

#include <ck_pr.h>

static MALLOC_DEFINE(M_PCPU_QUOTA, "Per-cpu", "Per-cpu resource accounting.");

#define PCPU_QUOTA_SLOP_GET(p) zpcpu_get((p)->pq_slop)
#define PCPU_QUOTA_CAN_CACHE 0x1
#define PCPU_QUOTA_FLUSHING 0x2

struct pcpu_quota {
	void *pq_context;
	counter_u64_t pq_slop;
	unsigned long *pq_global;
	unsigned long pq_pcpu_slop;
	int (*pq_alloc)(void *context, unsigned long incr, unsigned long *slop);
	volatile int pq_flags;
} __aligned(CACHE_LINE_SIZE);

static void
pcpu_quota_flush(struct pcpu_quota *pq)
{
	int64_t *p;
	uintptr_t value;
	int cpu;

	value = 0;
	epoch_enter(global_epoch);
	CPU_FOREACH(cpu) {
		p = zpcpu_get_cpu(pq->pq_slop, cpu);
		MPASS(*p >= 0);
		value += *p;
		*p = 0;
	}
	if (value)
		atomic_subtract_long(pq->pq_global, value);
	epoch_exit(global_epoch);
}

void
pcpu_quota_cache_set(struct pcpu_quota *pq, int enable)
{
	int *flagsp;

	flagsp = (int *)(uintptr_t)&pq->pq_flags;
	if (!enable && (pq->pq_flags & PCPU_QUOTA_CAN_CACHE)) {
		if (ck_pr_btr_int(flagsp, PCPU_QUOTA_CAN_CACHE) == 0 &&
			ck_pr_bts_int(flagsp, PCPU_QUOTA_FLUSHING) == 0) {
			epoch_wait(global_epoch);
			pcpu_quota_flush(pq);
			ck_pr_btr_int(flagsp, PCPU_QUOTA_FLUSHING);
		}
	} else if (enable && (pq->pq_flags & PCPU_QUOTA_CAN_CACHE) == 0) {
		while (pq->pq_flags & PCPU_QUOTA_FLUSHING)
			cpu_spinwait();
		ck_pr_bts_int(flagsp,  PCPU_QUOTA_CAN_CACHE);
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
	int64_t *p;
	int rc;

	epoch_enter(global_epoch);
	p = PCPU_QUOTA_SLOP_GET(pq);
	if (*p >= incr) {
		*p -= incr;
		epoch_exit(global_epoch);
		return (1);
	}
	incr -= *p;
	*p = 0;
	rc = pq->pq_alloc(pq->pq_context, incr, (unsigned long *)p);
	if ( __predict_false((pq->pq_flags & PCPU_QUOTA_CAN_CACHE) == 0) && *p > 0)
		pcpu_quota_cache_set(pq, 1);

	epoch_exit(global_epoch);
	return (rc);
}

void
pcpu_quota_decr(struct pcpu_quota *pq, unsigned long decr)
{
	int64_t *p;
	int64_t value;
	long adj;

	epoch_enter(global_epoch);
	p = PCPU_QUOTA_SLOP_GET(pq);
	if (__predict_true(pq->pq_flags & PCPU_QUOTA_CAN_CACHE)) {
		if (*p + decr <= pq->pq_pcpu_slop) {
			*p += decr;
			epoch_exit(global_epoch);
			return;
		}
		adj = (pq->pq_pcpu_slop >> 1);
		value = decr + (*p - adj);
	} else {
		adj = 0;
		value = *p + decr;
	}
	MPASS(value > 0);
	*p = adj;
	atomic_subtract_long(pq->pq_global, (unsigned long)value);
	epoch_exit(global_epoch);
}

