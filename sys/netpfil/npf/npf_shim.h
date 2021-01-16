
#define	__KERNEL_RCSID(x, y)

#define kmem_alloc(len, flags) malloc((len), M_NPF, M_WAITOK)
#define kmem_zalloc(len, flags) malloc((len), M_NPF, M_WAITOK|M_ZERO)
#define kmem_free(ptr, size) free((ptr), M_NPF)

#define npf_mutex_init(mtx, type, ipl) mtx_init(mtx, #mtx, NULL, MTX_DEFAULT)

typedef struct ifnet ifnet_t;
typedef struct mtx kmutex_t;

#define __dso_public
