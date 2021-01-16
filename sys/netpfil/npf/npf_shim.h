
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
#define membar_sync() atomic_thread_fence_acq()


typedef struct ifnet ifnet_t;
typedef struct mtx kmutex_t;

#define __dso_public
