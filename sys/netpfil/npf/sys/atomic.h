#include <machine/atomic.h>

#undef atomic_swap_ptr
#define atomic_swap_ptr(p, v) (void*)(uintptr_t)atomic_swap_long((u_long *)(uintptr_t)p, (uintptr_t)v)
