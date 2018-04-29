/*-
 * Copyright (c) 2018, Matthew Macy <mmacy@mattmacy.io>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Neither the name of Matthew Macy nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/types.h>
#include <sys/counter.h>
#include <sys/epoch.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/turnstile.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>

#include <ck_epoch.h>

MALLOC_DEFINE(M_EPOCH, "epoch", "epoch based reclamation");


SYSCTL_NODE(_kern, OID_AUTO, epoch, CTLFLAG_RW, 0, "epoch information");
SYSCTL_NODE(_kern_epoch, OID_AUTO, stats, CTLFLAG_RW, 0, "epoch stats");


/* Stats. */
static counter_u64_t wait_count;
SYSCTL_COUNTER_U64(_kern_epoch_stats, OID_AUTO, preemption_waits, CTLFLAG_RW,
				   &wait_count, "# of times waited due to preemption");
static counter_u64_t yield_count;
SYSCTL_COUNTER_U64(_kern_epoch_stats, OID_AUTO, yields, CTLFLAG_RW,
				   &yield_count, "# of times yielded to other cpu");

struct epoch_pcpu_state {
	ck_epoch_record_t eps_record;
	volatile int eps_critnest;
	volatile int eps_waiters;
} __aligned(CACHE_LINE_SIZE);

struct epoch {
	struct ck_epoch e_epoch;
	struct epoch_pcpu_state *e_pcpu_dom[MAXMEMDOM];
	struct epoch_pcpu_state *e_pcpu[0];
};

static __read_mostly int domcount[MAXMEMDOM];
static __read_mostly int domoffsets[MAXMEMDOM];
static __read_mostly int inited;
static __read_mostly struct lock_object epoch_ts = {
	.lo_name = "epochts",
};

static void
epoch_init(void *arg __unused)
{
	int domain, count;

	count = domain = 0;
	domoffsets[0] = 0;
	for (domain = 0; domain < vm_ndomains; domain++) {
		domcount[domain] = CPU_COUNT(&cpuset_domain[domain]);
		printf("domcount[%d] %d\n", domain, domcount[domain]);;
	}
	for (domain = 1; domain < vm_ndomains; domain++)
		domoffsets[domain] = domoffsets[domain-1] + domcount[domain-1];

#ifdef INVARIANTS
	for (domain = 0; domain < vm_ndomains; domain++) {
		KASSERT(domcount[domain], ("domcount[%d] is zero", domain));
		if (vm_ndomains > 1)
			MPASS(domcount[domain] < mp_ncpus);
		else
			MPASS(domcount[domain] <= mp_ncpus);
	}
#endif
	wait_count = counter_u64_alloc(M_WAITOK);
	yield_count = counter_u64_alloc(M_WAITOK);
	inited = 1;
}
SYSINIT(epoch, SI_SUB_CPU + 1, SI_ORDER_FIRST, epoch_init, NULL);

epoch_t
epoch_alloc(void)
{
	int domain, cpu_offset;
	epoch_t epoch;
	struct epoch_pcpu_state *eps;

	if (__predict_false(!inited))
		panic("%s called too early in boot", __func__);
	epoch = malloc(sizeof(struct epoch) + mp_ncpus*sizeof(void*),
				   M_EPOCH, M_ZERO|M_WAITOK);
	ck_epoch_init(&epoch->e_epoch);

	for (domain = 0; domain < vm_ndomains; domain++) {
		eps = malloc_domain(sizeof(*eps)*domcount[domain], M_EPOCH,
							domain, M_ZERO|M_WAITOK);
		epoch->e_pcpu_dom[domain] = eps;
		cpu_offset = domoffsets[domain];
		for (int i = 0; i < domcount[domain]; i++) {
			epoch->e_pcpu[cpu_offset + i] = eps + i;
			ck_epoch_register(&epoch->e_epoch, &(eps + i)->eps_record, NULL);
		}
	}
	return (epoch);
}

void
epoch_free(epoch_t epoch)
{
	int domain;
#ifdef INVARIANTS
	struct epoch_pcpu_state *eps;
	int cpu;
	CPU_FOREACH(cpu) {
		if (CPU_ABSENT(cpu))
			continue;
		eps = epoch->e_pcpu[cpu];
		MPASS(eps->eps_critnest == 0);
	}
#endif
	for (domain = 0; domain < vm_ndomains; domain++)
		free(epoch->e_pcpu_dom[domain], M_EPOCH);
	free(epoch, M_EPOCH);
}

#define INIT_CHECK(epoch)								\
	do {											\
		if (__predict_false((epoch) == NULL))		\
			return;									\
	} while (0)

static void
epoch_turnstile_exit(epoch_t epoch)
{
	struct turnstile *ts;
	struct epoch_pcpu_state *eps;

	INIT_CHECK(epoch);
	MPASS(curthread->td_critnest);
	eps = epoch->e_pcpu[curcpu];
	if (__predict_true(eps->eps_waiters == 0))
		return;
	turnstile_chain_lock(&epoch_ts);
	ts = turnstile_lookup(&epoch_ts);
	if (ts != NULL) {
		turnstile_broadcast(ts, TS_SHARED_QUEUE);
		turnstile_unpend(ts, TS_SHARED_LOCK);
	}
	turnstile_chain_unlock(&epoch_ts);
}

void
epoch_enter(epoch_t epoch)
{
	struct epoch_pcpu_state *eps;

	INIT_CHECK(epoch);
	critical_enter();
	sched_pin();
	eps = epoch->e_pcpu[curcpu];
	eps->eps_critnest++;
	ck_epoch_begin(&eps->eps_record, NULL);
	critical_exit();
}

void
epoch_enter_nopreempt(epoch_t epoch)
{
	struct epoch_pcpu_state *eps;

	INIT_CHECK(epoch);
	critical_enter();
	eps = epoch->e_pcpu[curcpu];
	ck_epoch_begin(&eps->eps_record, NULL);
}

void
epoch_exit(epoch_t epoch)
{
	struct epoch_pcpu_state *eps;

	INIT_CHECK(epoch);
	critical_enter();
	eps = epoch->e_pcpu[curcpu];
	MPASS(eps->eps_critnest);
	sched_unpin();
	eps->eps_critnest--;
	ck_epoch_end(&eps->eps_record, NULL);
	epoch_turnstile_exit(epoch);
	critical_exit();
}

void
epoch_exit_nopreempt(epoch_t epoch)
{
	struct epoch_pcpu_state *eps;

	INIT_CHECK(epoch);
	MPASS(curthread->td_critnest);
	eps = epoch->e_pcpu[curcpu];
	ck_epoch_end(&eps->eps_record, NULL);
	critical_exit();
}

static void
epoch_block_handler(struct ck_epoch *global __unused, struct ck_epoch_record *cr __unused,
					void *arg)
{
	struct epoch_pcpu_state *eps = arg;
	struct turnstile *ts;
	int yielded;

	yielded = 0;
	while (eps->eps_critnest) {
		counter_u64_add(wait_count, 1);
		ts = turnstile_trywait(&epoch_ts);
		turnstile_wait(ts, NULL, TS_SHARED_QUEUE);
		yielded = 1;
	}
	if (!yielded) {
		counter_u64_add(yield_count, 1);
		kern_yield(PRI_UNCHANGED);
	}
}

void
epoch_wait(epoch_t epoch)
{
	struct epoch_pcpu_state *eps;
	struct turnstile *ts;

	INIT_CHECK(epoch);
	critical_enter();
	sched_pin();
	eps = epoch->e_pcpu[curcpu];
	eps->eps_waiters++;
	critical_exit();
	while (eps->eps_critnest)  {
		counter_u64_add(wait_count, 1);
		ts = turnstile_trywait(&epoch_ts);
		turnstile_wait(ts, NULL, TS_SHARED_QUEUE);
	}
	ck_epoch_synchronize_wait(&epoch->e_epoch, epoch_block_handler, eps);

	critical_enter();
	sched_unpin();
	eps->eps_waiters--;
	critical_exit();
}
