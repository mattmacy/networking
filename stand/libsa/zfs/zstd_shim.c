typedef int krw_t;
u_int cpu_feature;

extern void Free(void *p, char *file, int line);
extern void *Malloc(size_t bytes, char *file, int line);
#define M_WAITOK 0
#define M_ZERO 0
#define M_NOWAIT 0
#define MALLOC_DECLARE(x)
#define KM_SLEEP 0

#define zfs_kmem_alloc(size, flags) Malloc((size), __FILE__, __LINE__) 
#define zfs_kmem_free(p, size) Free(p, __FILE__, __LINE__)
#define kmem_zalloc(size, flags) Malloc((size), __FILE__, __LINE__) 
#define kmem_free(p, size) Free(p, __FILE__, __LINE__)

int mp_ncpus = 1;
volatile time_t time_second = 1;

#include <zfs_zstd.c>

uintptr_t *__start_set_pcpu;

uintptr_t *__stop_set_pcpu;

void
__kstat_install(kstat_t *ksp)
{

}

void
__kstat_delete(kstat_t *ksp)
{

}

kstat_t *
__kstat_create(const char *ks_module, int ks_instance,
    const char *ks_name, const char *ks_class, uchar_t ks_type,
    uint_t ks_ndata, uchar_t ks_flags)
{
	return (NULL);
}

void
_sx_xunlock(struct sx *sx, const char *file, int line)
{

}

int
sx_try_xlock_(struct sx *sx, const char *file, int line)
{
	return (1);
}

int
_sx_xlock(struct sx *sx, int opts, const char *file, int line)
{
	return (0);
}

void
sx_init_flags(struct sx *sx, const char *description, int opts)
{

}

void
sx_destroy(struct sx *sx)
{

}
