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
#include <sys/epoch.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/systm.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>

#include <ck_epoch.h>

MALLOC_DEFINE(M_EPOCH, "epoch", "epoch based reclamation");

struct epoch_pcpu_state {
	ck_epoch_record_t eps_record;
	volatile int eps_critnest;
} __aligned(CACHE_LINE_SIZE);

struct epoch {
	struct ck_epoch e_epoch;
	struct epoch_pcpu_state *e_pcpu_dom[MAXMEMDOM];
	struct epoch_pcpu_state *e_pcpu[0];
};

static int domcount[MAXMEMDOM];
static int domoffsets[MAXMEMDOM];

void
epoch_init(void)
{
	int cpu, domain;
	struct pcpu *pc;

	domain = 0;
	domoffsets[0] = 0;
	CPU_FOREACH(cpu) {
		if (CPU_ABSENT(cpu))
			continue;
		pc = pcpu_find(cpu);
		/* assumes cpus aren't somehow interleaved */
		if (domain != pc->pc_domain) {
			domoffsets[pc->pc_domain] = cpu;
			domain = pc->pc_domain;
		}
		domcount[pc->pc_domain] = cpu + 1;
	}
}

epoch_t
epoch_alloc(void)
{
	int domain, cpu_offset;
	epoch_t epoch;
	struct epoch_pcpu_state *eps;

	if (cold) {
		epoch = (void*)kmem_malloc(kernel_arena, sizeof(struct epoch) + mp_ncpus*sizeof(void*),
					M_ZERO|M_WAITOK);
	} else {
		epoch = malloc(sizeof(struct epoch) + mp_ncpus*sizeof(void*),
					M_EPOCH, M_ZERO|M_WAITOK);
	}
	ck_epoch_init(&epoch->e_epoch);

	for (domain = 0; domain < vm_ndomains; domain++) {
		if (cold) {
			eps = (void*)kmem_malloc_domain(domain, sizeof(*eps)*domcount[domain],
										   M_ZERO|M_WAITOK);
		} else {
			eps = malloc_domain(sizeof(*eps)*domcount[domain], M_EPOCH,
								domain, M_ZERO|M_WAITOK);
		} 
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
	struct epoch_pcpu_state *eps;
	int cpu;

	CPU_FOREACH(cpu) {
		if (CPU_ABSENT(cpu))
			continue;
		eps = epoch->e_pcpu[cpu];
		MPASS(eps->eps_critnest == 0);
		free(eps, M_EPOCH);
	}
	free(epoch, M_EPOCH);
}

void
epoch_enter(epoch_t epoch)
{
	struct epoch_pcpu_state *eps;

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

	critical_enter();
	eps = epoch->e_pcpu[curcpu];
	ck_epoch_begin(&eps->eps_record, NULL);
}

void
epoch_exit(epoch_t epoch)
{
	struct epoch_pcpu_state *eps;

	critical_enter();
	eps = epoch->e_pcpu[curcpu];
	MPASS(eps->eps_critnest);
	sched_unpin();
	eps->eps_critnest--;
	ck_epoch_end(&eps->eps_record, NULL);
	critical_exit();
}

void
epoch_exit_nopreempt(epoch_t epoch)
{
	struct epoch_pcpu_state *eps;

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

	kern_yield(PRI_UNCHANGED);
	while (eps->eps_critnest)
		kern_yield(PRI_UNCHANGED);
}

void
epoch_wait(epoch_t epoch)
{
	struct epoch_pcpu_state *eps;

	sched_pin();
	eps = epoch->e_pcpu[curcpu];
	while (eps->eps_critnest) {
		kern_yield(PRI_UNCHANGED);
	}
	ck_epoch_synchronize_wait(&epoch->e_epoch, epoch_block_handler, eps);
	sched_unpin();
}
