
#define	__KERNEL_RCSID(x, y)

#define kmem_alloc(len, flags) malloc((len), M_NPF, M_WAITOK)
#define kmem_zalloc(len, flags) malloc((len), M_NPF, M_WAITOK|M_ZERO)
#define kmem_free(ptr, size) free((ptr), M_NPF)

#define npf_mutex_init(mtx, type, ipl) mtx_init(mtx, #mtx, NULL, MTX_DEF)

#define mutex_enter(lck) mtx_lock((lck))
#define mutex_exit(lck) mtx_unlock((lck))
#define mutex_destroy(lck) mtx_destroy((lck))
#define mutex_owned(lck) mtx_owned((lck))

#define atomic_load_relaxed(p)  atomic_load_ptr((p))
#define atomic_store_relaxed(p, v) atomic_store_ptr((p), (v))
#define atomic_dec_uint_nv(p) (atomic_fetchadd_32(p, -1) + -1)
#define atomic_inc_uint_nv(p) (atomic_fetchadd_32(p, 1) + 1)
#define atomic_inc_uint(p) atomic_add_32(p, 1);
#define atomic_dec_uint(p) atomic_add_32(p, -1);
#define atomic_or_uint(p, v) atomic_set_int((p), (v))
#define atomic_cas_64(p, o, n) atomic_cmpset_64((p), (o), (n))
#define membar_sync() atomic_thread_fence_seq_cst()
#define membar_producer() atomic_thread_fence_rel();
#define membar_consumer() atomic_thread_fence_acq();

typedef struct ifnet ifnet_t;
typedef struct mtx kmutex_t;
typedef struct cv kcondvar_t;
typedef struct thread lwp_t;

#include <sys/types.h>

static __inline intrmask_t	splsoftnet(void)		{ return 0; }

#define __dso_public

#ifndef __arraycount
# define __arraycount(a) (sizeof(a) / sizeof(*(a)))
#endif

#define __diagused __unused

#define pool_cache_put(c, o) uma_zfree((c), (o))
#define pool_cache_get(c, flags) uma_zalloc((c), (flags))
#define pool_cache_destroy(c) uma_zdestroy((c))
/* does it make sense to use an explicit cache? */
#define pool_cache_invalidate(c) 

#define PR_NOWAIT M_NOWAIT
#define PR_WAITOK M_WAITOK

#define __UNCONST(a)	((void *)(unsigned long)(const void *)(a))

#include <sys/socket.h>
