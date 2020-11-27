#ifndef MODULE_H_
#define MODULE_H_

#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <sys/support.h>


#include <sys/types.h>
#include <sys/epoch.h>
#include <sys/lock.h>
#include <sys/mutex.h>



#include <crypto/curve25519.h>
#include <zinc/chacha20poly1305.h>
#include <crypto/blake2s.h>

MALLOC_DECLARE(M_WG);


enum noise_lengths {
	NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE,
	NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEY_SIZE,
	NOISE_TIMESTAMP_LEN = sizeof(uint64_t) + sizeof(uint32_t),
	NOISE_AUTHTAG_LEN = CHACHA20POLY1305_AUTHTAG_SIZE,
	NOISE_HASH_LEN = BLAKE2S_HASH_SIZE
};

#define noise_encrypted_len(plain_len) ((plain_len) + NOISE_AUTHTAG_LEN)

enum cookie_values {
	COOKIE_SECRET_MAX_AGE = 2 * 60,
	COOKIE_SECRET_LATENCY = 5,
	COOKIE_NONCE_LEN = XCHACHA20POLY1305_NONCE_SIZE,
	COOKIE_LEN = 16
};

enum limits {
	//	REJECT_AFTER_MESSAGES = __UQUAD_MAX - COUNTER_WINDOW_SIZE - 1,
	REKEY_TIMEOUT = 5,
	//REKEY_TIMEOUT_JITTER_MAX_JIFFIES = HZ / 3,
	INITIATIONS_PER_SECOND = 50,
	MAX_PEERS_PER_DEVICE = 1U << 20,
	KEEPALIVE_TIMEOUT = 10,
	MAX_TIMER_HANDSHAKES = 90 / REKEY_TIMEOUT,
	MAX_QUEUED_INCOMING_HANDSHAKES = 4096, /* TODO: replace this with DQL */
	MAX_STAGED_PACKETS = 128,
	MAX_QUEUED_PACKETS = 1024 /* TODO: replace this with DQL */
};

#define zfree(addr, type)						\
	do {										\
		explicit_bzero(addr, sizeof(*addr));	\
		free(addr, type);						\
	} while (0)

struct crypt_queue {
	//struct ptr_ring ring;
	union {
		struct {
			//struct multicore_worker __percpu *worker;
			int last_cpu;
		};
		//struct work_struct work;
	};
};

/*
 * Workaround FreeBSD's shitty typed atomic
 * accessors
 */
#define __ATOMIC_LOAD_SIZE						\
	({									\
	switch (size) {							\
	case 1: *(uint8_t *)res = *(volatile uint8_t *)p; break;		\
	case 2: *(uint16_t *)res = *(volatile uint16_t *)p; break;		\
	case 4: *(uint32_t *)res = *(volatile uint32_t *)p; break;		\
	case 8: *(uint64_t *)res = *(volatile uint64_t *)p; break;		\
	}								\
})

static inline void
__atomic_load_acq_size(volatile void *p, void *res, int size)
{
	__ATOMIC_LOAD_SIZE;
}

#define atomic_load_acq(x)						\
	({											\
	union { __typeof(x) __val; char __c[1]; } __u;			\
	__atomic_load_acq_size(&(x), __u.__c, sizeof(x));		\
	__u.__val;												\
})


int wg_ctx_init(void);
void wg_ctx_uninit(void);


#endif
