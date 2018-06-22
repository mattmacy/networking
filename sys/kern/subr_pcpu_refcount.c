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
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/pcpu_refcount.h>
#include <sys/smp.h>

static MALLOC_DEFINE(M_PCPU_REF, "Pcpuref", "Per-cpu reference counting.");
#define PR_DYING 0x1

#define OWNER_REFCOUNT (INT_MAX >> 2)


struct pcpu_ref {
	counter_u64_t pr_pcpu_refs;
	volatile int pr_refcnt;
	int pr_flags;
} __aligned(CACHE_LINE_SIZE);

pcpu_ref_t
pcpu_ref_alloc(int flags)
{
	pcpu_ref_t pr;

	pr = malloc(sizeof(*pr), M_PCPU_REF, flags);
	if (pr == NULL)
		return (NULL);
	if ((pr->pr_pcpu_refs = counter_u64_alloc(flags)) == NULL) {
		free(pr, M_PCPU_REF);
		return (NULL);
	}
	pr->pr_flags = 0;
	pr->pr_refcnt = OWNER_REFCOUNT;
#ifdef INVARIANTS
	int cpu;
	int64_t sum = 0;
	CPU_FOREACH(cpu)
		sum += *(int64_t*)zpcpu_get_cpu(pr->pr_pcpu_refs, cpu);
	KASSERT(sum == 0, ("sum: %jd != 0", sum));
#endif
	return (pr);
}

void
pcpu_ref_free(pcpu_ref_t pr)
{
	counter_u64_free(pr->pr_pcpu_refs);
	free(pr, M_PCPU_REF);
}

void
pcpu_ref_incr(pcpu_ref_t pr, int incr)
{
	epoch_enter(global_epoch);
#ifdef INVARIANTS
	int64_t sum = 0;
	int refcount, cpu;

	refcount = pr->pr_refcnt;
	if (__predict_true((pr->pr_flags & PR_DYING) == 0)) {
		CPU_FOREACH(cpu)
			sum += *(int64_t*)zpcpu_get_cpu(pr->pr_pcpu_refs, cpu);
		refcount -= OWNER_REFCOUNT-1;
	}
	KASSERT(sum + refcount > -2, ("sum: %jd + refcount: %d <= 0", sum, refcount));
	if (sum + refcount <= 0) {
		printf("sum: %jd + refcount: %d <= 0", sum, refcount);
		kdb_backtrace();
	}
#endif	
	if (__predict_false(pr->pr_flags & PR_DYING))
		atomic_add_int(&pr->pr_refcnt, incr);
	else
		*(int64_t*)zpcpu_get(pr->pr_pcpu_refs) += incr;
	epoch_exit(global_epoch);
}

int
pcpu_ref_decr(pcpu_ref_t pr, int decr)
{
	int rc, value;
	epoch_enter(global_epoch);
#ifdef INVARIANTS
	int64_t sum = 0;
	int cpu, refcount;

	refcount = pr->pr_refcnt;
	if (__predict_true((pr->pr_flags & PR_DYING) == 0)) {
		CPU_FOREACH(cpu)
			sum += *(int64_t*)zpcpu_get_cpu(pr->pr_pcpu_refs, cpu);
		refcount -= OWNER_REFCOUNT-1;
	}

	KASSERT(sum + refcount >= decr, ("sum: %jd + refcount: %d < decr: %d",
										  sum, refcount, decr));
#endif
	rc = 0;
	if (__predict_true((pr->pr_flags & PR_DYING) == 0))
		*(int64_t*)zpcpu_get(pr->pr_pcpu_refs) -= decr;
	else {
		value = atomic_fetchadd_int(&pr->pr_refcnt, -decr);
		MPASS(value >= decr);
		if (value == decr)
			rc = 1;
	}
	epoch_exit(global_epoch);
	return (rc);
}

void
pcpu_ref_kill(pcpu_ref_t pr)
{
	int cpu, sum, value;

	MPASS((pr->pr_flags & PR_DYING) == 0);
	pr->pr_flags |= PR_DYING;
	epoch_wait(global_epoch);
	sum = 0;
	CPU_FOREACH(cpu)
		sum += *(int64_t*)zpcpu_get_cpu(pr->pr_pcpu_refs, cpu);
#ifdef INVARIANTS
	KASSERT(sum + pr->pr_refcnt >= OWNER_REFCOUNT, ("sum: %d + pr_refcnt: %d < owner: %d",
										  sum, pr->pr_refcnt, OWNER_REFCOUNT));
#endif

	value = atomic_fetchadd_int(&pr->pr_refcnt, sum-OWNER_REFCOUNT+1);
	MPASS(value + sum >= OWNER_REFCOUNT);
}
