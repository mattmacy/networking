/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 Justin Hibbits
 * Copyright (c) 2005, Joseph Koshy
 * All rights reserved.
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
#include <sys/pmc.h>
#include <sys/pmckern.h>
#include <sys/systm.h>

#include <machine/pmc_mdep.h>
#include <machine/spr.h>
#include <machine/cpu.h>

#include "hwpmc_powerpc.h"

#define	POWERPC_PMC_CAPS	(PMC_CAP_INTERRUPT | PMC_CAP_USER |     \
				 PMC_CAP_SYSTEM | PMC_CAP_EDGE |	\
				 PMC_CAP_THRESHOLD | PMC_CAP_READ |	\
				 PMC_CAP_WRITE | PMC_CAP_INVERT |	\
				 PMC_CAP_QUALIFIER)
#define POWER_SET_MMCR1_PMCSEL(r, x, i)			\
	((r & ~(BESHIFT_VAL(0xff, 32 + 8*i))) | BESHIFT_VAL((0xff&x), 32 + 8*i))

#define POWER_MAX_PMCS	6

#define POWER_PMC_HAS_OVERFLOWED(x) (power_pmcn_read(x) & (0x1 << 31))

static pmc_value_t
power_pmcn_read(unsigned int pmc)
{
	switch (pmc) {
		case 0:
			return mfspr(SPR_ISA3_PMC1);
			break;
		case 1:
			return mfspr(SPR_ISA3_PMC2);
			break;
		case 2:
			return mfspr(SPR_ISA3_PMC3);
			break;
		case 3:
			return mfspr(SPR_ISA3_PMC4);
			break;
		case 4:
			return mfspr(SPR_ISA3_PMC5);
			break;
		case 5:
			return mfspr(SPR_ISA3_PMC6);
		default:
			panic("Invalid PMC number: %d\n", pmc);
	}
}

static void
power_pmcn_write(unsigned int pmc, uint32_t val)
{
	switch (pmc) {
		case 0:
			mtspr(SPR_ISA3_PMC1, val);
			break;
		case 1:
			mtspr(SPR_ISA3_PMC2, val);
			break;
		case 2:
			mtspr(SPR_ISA3_PMC3, val);
			break;
		case 3:
			mtspr(SPR_ISA3_PMC4, val);
			break;
		case 4:
			mtspr(SPR_ISA3_PMC5, val);
			break;
		case 5:
			mtspr(SPR_ISA3_PMC6, val);
			break;
		default:
			panic("Invalid PMC number: %d\n", pmc);
	}
}

static int
power_read_pmc(int cpu, int ri, pmc_value_t *v)
{
	struct pmc *pm;
	pmc_value_t tmp;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[powerpc,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < POWER_MAX_PMCS,
	    ("[powerpc,%d] illegal row index %d", __LINE__, ri));

	pm  = powerpc_pcpu[cpu]->pc_ppcpmcs[ri].phw_pmc;
	KASSERT(pm,
	    ("[core,%d] cpu %d ri %d pmc not configured", __LINE__, cpu,
		ri));

	tmp = power_pmcn_read(ri);
	PMCDBG2(MDP,REA,2,"ppc-read id=%d -> %jd", ri, tmp);
	if (PMC_IS_SAMPLING_MODE(PMC_TO_MODE(pm)))
		*v = POWERPC_PERFCTR_VALUE_TO_RELOAD_COUNT(tmp);
	else
		*v = tmp;

	return (0);
}

static int
power_write_pmc(int cpu, int ri, pmc_value_t v)
{
	struct pmc *pm;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[powerpc,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < POWER_MAX_PMCS,
	    ("[powerpc,%d] illegal row-index %d", __LINE__, ri));

	pm  = powerpc_pcpu[cpu]->pc_ppcpmcs[ri].phw_pmc;

	if (PMC_IS_SAMPLING_MODE(PMC_TO_MODE(pm)))
		v = POWERPC_RELOAD_COUNT_TO_PERFCTR_VALUE(v);
	
	PMCDBG3(MDP,WRI,1,"powerpc-write cpu=%d ri=%d v=%jx", cpu, ri, v);

	power_pmcn_write(ri, v);

	return (0);
}

static int
power_config_pmc(int cpu, int ri, struct pmc *pm)
{
	struct pmc_hw *phw;

	PMCDBG3(MDP,CFG,1, "cpu=%d ri=%d pm=%p", cpu, ri, pm);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[powerpc,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < POWER_MAX_PMCS,
	    ("[powerpc,%d] illegal row-index %d", __LINE__, ri));

	phw = &powerpc_pcpu[cpu]->pc_ppcpmcs[ri];

	KASSERT(pm == NULL || phw->phw_pmc == NULL,
	    ("[powerpc,%d] pm=%p phw->pm=%p hwpmc not unconfigured",
	    __LINE__, pm, phw->phw_pmc));

	phw->phw_pmc = pm;

	return (0);
}

static int
power_set_pmc(int cpu, int ri, int config)
{
	struct pmc *pm;
	struct pmc_hw *phw;
	register_t pmc_mmcr;

	MPASS(ri >= 0 && ri <= 3);

	phw    = &powerpc_pcpu[cpu]->pc_ppcpmcs[ri];
	pm     = phw->phw_pmc;

	pmc_mmcr = mfspr(SPR_ISA3_MMCR1);
	pmc_mmcr = POWER_SET_MMCR1_PMCSEL(pmc_mmcr, config, ri);
	mtspr(SPR_ISA3_MMCR1, pmc_mmcr);
	return (0);
}

static int
power_start_pmc(int cpu, int ri)
{
	uint32_t config;
	struct pmc *pm;
	struct pmc_hw *phw;
	uint64_t pmc_mmcr;
	int error;

	phw    = &powerpc_pcpu[cpu]->pc_ppcpmcs[ri];
	pm     = phw->phw_pmc;
	config = pm->pm_md.pm_powerpc.pm_powerpc_evsel & ~POWERPC_PMC_ENABLE;

	if ((error = power_set_pmc(cpu, ri, config)))
		return (error);
	
	/* The mask is inverted (enable is 1) compared to the flags in MMCR0, which
	 * are Freeze flags.
	 */
	config = ~pm->pm_md.pm_powerpc.pm_powerpc_evsel & POWERPC_PMC_ENABLE;

	pmc_mmcr = mfspr(SPR_ISA3_MMCR0);
	pmc_mmcr &= ~SPR_ISA3_MMCR0_FC;
	pmc_mmcr |= config;
	mtspr(SPR_ISA3_MMCR0, pmc_mmcr);
	return (0);
}

static int
power_stop_pmc(int cpu, int ri)
{

	return (power_set_pmc(cpu, ri, PMC_ISA3_N_NONE));
}

static int
power_pcpu_init(struct pmc_mdep *md, int cpu)
{
	int first_ri, i;
	struct pmc_cpu *pc;
	struct powerpc_cpu *pac;
	struct pmc_hw  *phw;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[powerpc,%d] wrong cpu number %d", __LINE__, cpu));
	PMCDBG1(MDP,INI,1,"powerpc-init cpu=%d", cpu);

	powerpc_pcpu[cpu] = pac = malloc(sizeof(struct powerpc_cpu), M_PMC,
	    M_WAITOK|M_ZERO);
	pac->pc_ppcpmcs = malloc(sizeof(struct pmc_hw) * POWER_MAX_PMCS,
	    M_PMC, M_WAITOK|M_ZERO);
	pac->pc_class = PMC_CLASS_POWER;
	pc = pmc_pcpu[cpu];
	first_ri = md->pmd_classdep[PMC_MDEP_CLASS_INDEX_POWERPC].pcd_ri;
	KASSERT(pc != NULL, ("[powerpc,%d] NULL per-cpu pointer", __LINE__));

	for (i = 0, phw = pac->pc_ppcpmcs; i < POWER_MAX_PMCS; i++, phw++) {
		phw->phw_state    = PMC_PHW_FLAG_IS_ENABLED |
		    PMC_PHW_CPU_TO_STATE(cpu) | PMC_PHW_INDEX_TO_STATE(i);
		phw->phw_pmc      = NULL;
		pc->pc_hwpmcs[i + first_ri] = phw;
	}

	/* Clear the MMCRs, and set FC, to disable all PMCs. */
	mtspr(SPR_ISA3_MMCR0, SPR_ISA3_MMCR0_FC | SPR_ISA3_MMCR0_PMAE |
		  SPR_ISA3_MMCR0_FCECE | SPR_ISA3_MMCR0_PMC1CE | SPR_ISA3_MMCR0_PMCJCE);
	mtspr(SPR_ISA3_MMCR1, 0);

	return (0);
}

static int
power_pcpu_fini(struct pmc_mdep *md, int cpu)
{
	uint64_t mmcr0 = mfspr(SPR_ISA3_MMCR0);

	mmcr0 |= SPR_ISA3_MMCR0_FC;
	mmcr0 &= ~SPR_ISA3_MMCR0_PMAE;
	mtspr(SPR_ISA3_MMCR0, mmcr0);

	free(powerpc_pcpu[cpu]->pc_ppcpmcs, M_PMC);
	free(powerpc_pcpu[cpu], M_PMC);

	return (0);
}

static int
power_allocate_pmc(int cpu, int ri, struct pmc *pm,
  const struct pmc_op_pmcallocate *a)
{
	uint32_t caps;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[powerpc,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < POWER_MAX_PMCS,
	    ("[powerpc,%d] illegal row index %d", __LINE__, ri));

	caps = a->pm_caps;
	if ((caps & ~POWERPC_PMC_CAPS) != 0) {
		printf("unrecognized PMC_CAP flags 0x%x\n",
			   caps & ~POWERPC_PMC_CAPS);
		return (EINVAL);
	}

	pm->pm_md.pm_powerpc.pm_powerpc_evsel = a->pm_md.pm_power.pm_power_config;

	PMCDBG2(MDP,ALL,2,"powerpc-allocate ri=%d -> config=0x%x", ri, config);

	return (0);
}

static int
power_release_pmc(int cpu, int ri, struct pmc *pmc)
{
	struct pmc_hw *phw;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[powerpc,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < POWER_MAX_PMCS,
	    ("[powerpc,%d] illegal row-index %d", __LINE__, ri));

	phw = &powerpc_pcpu[cpu]->pc_ppcpmcs[ri];
	KASSERT(phw->phw_pmc == NULL,
	    ("[powerpc,%d] PHW pmc %p non-NULL", __LINE__, phw->phw_pmc));

	return (0);
}

static int
power_intr(struct trapframe *tf)
{
	int i, error, retval, cpu;
	uint32_t config;
	struct pmc *pm;
	struct powerpc_cpu *pac;

	cpu = curcpu;
	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[powerpc,%d] out of range CPU %d", __LINE__, cpu));

	PMCDBG3(MDP,INT,1, "cpu=%d tf=%p um=%d", cpu, (void *) tf,
	    TRAPF_USERMODE(tf));

	retval = 0;

	pac = powerpc_pcpu[cpu];

	config  = mfspr(SPR_ISA3_MMCR0) & ~SPR_ISA3_MMCR0_FC;

	/*
	 * look for all PMCs that have interrupted:
	 * - look for a running, sampling PMC which has overflowed
	 *   and which has a valid 'struct pmc' association
	 *
	 * If found, we call a helper to process the interrupt.
	 */

	for (i = 0; i < POWER_MAX_PMCS; i++) {
		if ((pm = pac->pc_ppcpmcs[i].phw_pmc) == NULL ||
		    !PMC_IS_SAMPLING_MODE(PMC_TO_MODE(pm))) {
			continue;
		}

		if (!POWER_PMC_HAS_OVERFLOWED(i))
			continue;

		retval = 1;	/* Found an interrupting PMC. */

		if (pm->pm_state != PMC_STATE_RUNNING)
			continue;

		/* Stop the counter if logging fails. */
		error = pmc_process_interrupt(PMC_HR, pm, tf);
		if (error != 0)
			power_stop_pmc(cpu, i);

		/* reload count. */
		power_write_pmc(cpu, i, pm->pm_sc.pm_reloadcount);
	}
	if (retval)
		counter_u64_add(pmc_stats.pm_intr_processed, 1);
	else
		counter_u64_add(pmc_stats.pm_intr_ignored, 1);

	/* Re-enable PERF exceptions. */
	if (retval)
		mtspr(SPR_ISA3_MMCR0, config | SPR_ISA3_MMCR0_PMAE);

	return (retval);
}

int
pmc_power_initialize(struct pmc_mdep *pmc_mdep)
{
	struct pmc_classdep *pcd;
	int vers;

	vers = mfpvr() >> 16;
	snprintf(pmc_cpuid, sizeof(pmc_cpuid), "POWER_%04x", vers);

	pmc_mdep->pmd_cputype = -1;
	pcd = &pmc_mdep->pmd_classdep[PMC_MDEP_CLASS_INDEX_POWERPC];
	pcd->pcd_caps  = POWERPC_PMC_CAPS;
	pcd->pcd_class = PMC_CLASS_POWER;
	pcd->pcd_num   = POWER_MAX_PMCS;
	pcd->pcd_ri    = pmc_mdep->pmd_npmc;
	pcd->pcd_width = 32;	/* All PMCs are 32-bit */

	pcd->pcd_allocate_pmc   = power_allocate_pmc;
	pcd->pcd_config_pmc     = power_config_pmc;
	pcd->pcd_pcpu_fini      = power_pcpu_fini;
	pcd->pcd_pcpu_init      = power_pcpu_init;
	pcd->pcd_describe       = powerpc_describe;
	pcd->pcd_get_config     = powerpc_get_config;
	pcd->pcd_read_pmc       = power_read_pmc;
	pcd->pcd_release_pmc    = power_release_pmc;
	pcd->pcd_start_pmc      = power_start_pmc;
	pcd->pcd_stop_pmc       = power_stop_pmc;
 	pcd->pcd_write_pmc      = power_write_pmc;

	pmc_mdep->pmd_npmc   += POWER_MAX_PMCS;
	pmc_mdep->pmd_intr   =  power_intr;

	return (0);
}
