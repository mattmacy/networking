/*	$NetBSD$	*/

/*
 * Copyright (C) Ryota Ozaki <ozaki.ryota@gmail.com>
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This is an implementation of WireGuard, a fast, modern, secure VPN protocol,
 * for the NetBSD kernel and rump kernels.
 *
 * The implementation is based on the paper of WireGuard as of 2018-06-30 [1].
 * The paper is referred in the source code with label [W].  Also the
 * specification of the Noise protocol framework as of 2018-07-11 [2] is
 * referred with label [N].
 *
 * [1] https://www.wireguard.com/papers/wireguard.pdf
 * [2] http://noiseprotocol.org/noise.pdf
 */

#include <sys/cdefs.h>

#include "opt_inet.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <ck_queue.h>
#include <sys/condvar.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/ioccom.h>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/timespec.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/sysctl.h>
#include <sys/domain.h>
#include <sys/queue.h>
#include <sys/kthread.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_clone.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>

#ifdef INET6
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/udp6_var.h>
#endif /* INET6 */

#include <net/ethernet.h>
#include <net/iflib.h>
#include "ifdi_if.h"
#include <net/if_wg.h>

#include <contrib/libb2/blake2.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>

MALLOC_DEFINE(M_WG, "wg", "wireguard");

typedef struct mtx kmutex_t;
typedef struct cv kcondvar_t;
typedef struct rwlock krwlock_t;
typedef struct callout callout_t;
typedef struct thread lwp_t;


#define __diagused __unused
#define	mutex_enter mtx_lock
#define	mutex_exit mtx_unlock
#define mutex_init(lock, type, ipl) mtx_init(lock, #lock, NULL, MTX_DEF)
#define cprng_fast(buf, size) read_random(buf, size)
#define cprng_strong32() arc4random()

#define WG_MTU			1420
#define WG_ALLOWEDIPS		16

#define CURVE25519_KEY_LEN	32
#define TAI64N_LEN		sizeof(uint32_t) * 3
#define POLY1305_AUTHTAG_LEN	16
#define HMAC_BLOCK_LEN		64

/* [N] 4.1: "DHLEN must be 32 or greater."  WireGuard chooses 32. */
/* [N] 4.3: Hash functions */
#define NOISE_DHLEN		32
/* [N] 4.3: "Must be 32 or 64."  WireGuard chooses 32. */
#define NOISE_HASHLEN		32
#define NOISE_BLOCKLEN		64
#define NOISE_HKDF_OUTPUT_LEN	NOISE_HASHLEN
/* [N] 5.1: "k" */
#define NOISE_CIPHER_KEY_LEN	32
/*
 * [N] 9.2: "psk"
 *          "... psk is a 32-byte secret value provided by the application."
 */
#define NOISE_PRESHARED_KEY_LEN	32

#define WG_STATIC_KEY_LEN	CURVE25519_KEY_LEN
#define WG_TIMESTAMP_LEN	TAI64N_LEN

#define WG_PRESHARED_KEY_LEN	NOISE_PRESHARED_KEY_LEN

#define WG_COOKIE_LEN		16
#define WG_MAC_LEN		16
#define WG_RANDVAL_LEN		24

#define WG_EPHEMERAL_KEY_LEN	CURVE25519_KEY_LEN
/* [N] 5.2: "ck: A chaining key of HASHLEN bytes" */
#define WG_CHAINING_KEY_LEN	NOISE_HASHLEN
/* [N] 5.2: "h: A hash output of HASHLEN bytes" */
#define WG_HASH_LEN		NOISE_HASHLEN
#define WG_CIPHER_KEY_LEN	NOISE_CIPHER_KEY_LEN
#define WG_DH_OUTPUT_LEN	NOISE_DHLEN
#define WG_KDF_OUTPUT_LEN	NOISE_HKDF_OUTPUT_LEN
#define WG_AUTHTAG_LEN		POLY1305_AUTHTAG_LEN
#define WG_DATA_KEY_LEN		32
#define WG_SALT_LEN		24

/*
 * The protocol messages
 */
struct wg_msg{
	uint32_t	wgm_type;
} __packed;

/* [W] 5.4.2 First Message: Initiator to Responder */
struct wg_msg_init {
	uint32_t	wgmi_type;
	uint32_t	wgmi_sender;
	uint8_t		wgmi_ephemeral[WG_EPHEMERAL_KEY_LEN];
	uint8_t		wgmi_static[WG_STATIC_KEY_LEN + WG_AUTHTAG_LEN];
	uint8_t		wgmi_timestamp[WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN];
	uint8_t		wgmi_mac1[WG_MAC_LEN];
	uint8_t		wgmi_mac2[WG_MAC_LEN];
} __packed;

/* [W] 5.4.3 Second Message: Responder to Initiator */
struct wg_msg_resp {
	uint32_t	wgmr_type;
	uint32_t	wgmr_sender;
	uint32_t	wgmr_receiver;
	uint8_t		wgmr_ephemeral[WG_EPHEMERAL_KEY_LEN];
	uint8_t		wgmr_empty[0 + WG_AUTHTAG_LEN];
	uint8_t		wgmr_mac1[WG_MAC_LEN];
	uint8_t		wgmr_mac2[WG_MAC_LEN];
} __packed;

/* [W] 5.4.6 Subsequent Messages: Transport Data Messages */
struct wg_msg_data {
	uint32_t	wgmd_type;
	uint32_t	wgmd_receiver;
	uint64_t	wgmd_counter;
	uint32_t	wgmd_packet[0];
} __packed;

/* [W] 5.4.7 Under Load: Cookie Reply Message */
struct wg_msg_cookie {
	uint32_t	wgmc_type;
	uint32_t	wgmc_receiver;
	uint8_t		wgmc_salt[WG_SALT_LEN];
	uint8_t		wgmc_cookie[WG_COOKIE_LEN + WG_AUTHTAG_LEN];
} __packed;

typedef uint8_t wg_timestamp_t[WG_TIMESTAMP_LEN];

struct wg_ppsratecheck {
	struct timeval		wgprc_lasttime;
	int			wgprc_curpps;
};

#ifdef WG_DEBUG_DUMP
static void
wg_dump_buf(const char *func, const char *buf, const size_t size)
{

	log(LOG_DEBUG, "%s: ", func);
	for (int i = 0; i < size; i++)
		log(LOG_DEBUG, "%02x ", (int)(0xff & buf[i]));
	log(LOG_DEBUG, "\n");
}

static void
wg_dump_hash(const uint8_t *func, const uint8_t *name, const uint8_t *hash,
    const size_t size)
{

	log(LOG_DEBUG, "%s: %s: ", func, name);
	for (int i = 0; i < size; i++)
		log(LOG_DEBUG, "%02x ", (int)(0xff & hash[i]));
	log(LOG_DEBUG, "\n");
}

#define WG_DUMP_HASH(name, hash) \
	wg_dump_hash(__func__, name, hash, WG_HASH_LEN)
#define WG_DUMP_HASH48(name, hash) \
	wg_dump_hash(__func__, name, hash, 48)
#define WG_DUMP_BUF(buf, size) \
	wg_dump_buf(__func__, buf, size)
#else
#define WG_DUMP_HASH(name, hash)
#define WG_DUMP_HASH48(name, hash)
#define WG_DUMP_BUF(buf, size)
#endif /* WG_DEBUG_DUMP */


static void
wg_init_key_and_hash(uint8_t ckey[WG_CHAINING_KEY_LEN],
    uint8_t hash[WG_HASH_LEN])
{
	/* [W] 5.4: CONSTRUCTION */
	const char *signature = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
	/* [W] 5.4: IDENTIFIER */
	const char *id = "WireGuard v1 zx2c4 Jason@zx2c4.com";
	blake2s_state state;

	blake2s(ckey, signature, NULL, WG_CHAINING_KEY_LEN,
	    strlen(signature), 0);

	CTASSERT(WG_HASH_LEN == WG_CHAINING_KEY_LEN);
	memcpy(hash, ckey, WG_CHAINING_KEY_LEN);

	blake2s_init(&state, WG_HASH_LEN);
	blake2s_update(&state, ckey, WG_CHAINING_KEY_LEN);
	blake2s_update(&state, id, strlen(id));
	blake2s_final(&state, hash, WG_HASH_LEN);

	WG_DUMP_HASH("ckey", ckey);
	WG_DUMP_HASH("hash", hash);
}

static void
wg_algo_hash(uint8_t hash[WG_HASH_LEN], const uint8_t input[],
    const size_t inputsize)
{
	blake2s_state state;

	blake2s_init(&state, WG_HASH_LEN);
	blake2s_update(&state, hash, WG_HASH_LEN);
	blake2s_update(&state, input, inputsize);
	blake2s_final(&state, hash, WG_HASH_LEN);
}

static void
wg_algo_mac(uint8_t out[], const size_t outsize,
    const uint8_t key[], const size_t keylen,
    const uint8_t input1[], const size_t input1len,
    const uint8_t input2[], const size_t input2len)
{
	blake2s_state state;

	if (key != NULL)
		blake2s_init_key(&state, outsize, key, keylen);
	else
		blake2s_init(&state, outsize);

	blake2s_update(&state, input1, input1len);
	if (input2 != NULL)
		blake2s_update(&state, input2, input2len);
	blake2s_final(&state, out, outsize);
}

static void
wg_algo_mac_mac1(uint8_t out[], const size_t outsize,
    const uint8_t input1[], const size_t input1len,
    const uint8_t input2[], const size_t input2len)
{
	blake2s_state state;
	/* [W] 5.4: LABEL-MAC1 */
	const char *label = "mac1----";
	uint8_t key[WG_HASH_LEN];

	blake2s_init(&state, sizeof(key));
	blake2s_update(&state, label, strlen(label));
	blake2s_update(&state, input1, input1len);
	blake2s_final(&state, key, sizeof(key));

	blake2s_init_key(&state, outsize, key, sizeof(key));
	if (input2 != NULL)
		blake2s_update(&state, input2, input2len);
	blake2s_final(&state, out, outsize);
}
#ifdef notyet
static void
wg_algo_mac_cookie(uint8_t out[], const size_t outsize,
    const uint8_t input1[], const size_t input1len)
{
	blake2s_state state;
	/* [W] 5.4: LABEL-COOKIE */
	const char *label = "cookie--";

	blake2s_init(&state, outsize);
	blake2s_update(&state, label, strlen(label));
	blake2s_update(&state, input1, input1len);
	blake2s_final(&state, out, outsize);
}
#endif

static void
wg_algo_generate_keypair(uint8_t pubkey[WG_EPHEMERAL_KEY_LEN],
    uint8_t privkey[WG_EPHEMERAL_KEY_LEN])
{

	CTASSERT(WG_EPHEMERAL_KEY_LEN == crypto_scalarmult_curve25519_BYTES);

	cprng_fast(privkey, WG_EPHEMERAL_KEY_LEN);
	crypto_scalarmult_base(pubkey, privkey);
}

static void
wg_algo_dh(uint8_t out[WG_DH_OUTPUT_LEN],
    const uint8_t privkey[WG_STATIC_KEY_LEN],
    const uint8_t pubkey[WG_STATIC_KEY_LEN])
{

	CTASSERT(WG_STATIC_KEY_LEN == crypto_scalarmult_curve25519_BYTES);

	int ret __unused = crypto_scalarmult(out, privkey, pubkey);
	MPASS(ret == 0);
}

static void
wg_algo_hmac(uint8_t out[], const size_t outlen,
    const uint8_t key[], const size_t keylen,
    const uint8_t in[], const size_t inlen)
{
#define IPAD	0x36
#define OPAD	0x5c
	uint8_t hmackey[HMAC_BLOCK_LEN] = {0};
	uint8_t ipad[HMAC_BLOCK_LEN];
	uint8_t opad[HMAC_BLOCK_LEN];
	int i;
	blake2s_state state;

	MPASS(outlen == WG_HASH_LEN);
	MPASS(keylen <= HMAC_BLOCK_LEN);

	memcpy(hmackey, key, keylen);

	for (i = 0; i < sizeof(hmackey); i++) {
		ipad[i] = hmackey[i] ^ IPAD;
		opad[i] = hmackey[i] ^ OPAD;
	}

	blake2s_init(&state, WG_HASH_LEN);
	blake2s_update(&state, ipad, sizeof(ipad));
	blake2s_update(&state, in, inlen);
	blake2s_final(&state, out, WG_HASH_LEN);

	blake2s_init(&state, WG_HASH_LEN);
	blake2s_update(&state, opad, sizeof(opad));
	blake2s_update(&state, out, WG_HASH_LEN);
	blake2s_final(&state, out, WG_HASH_LEN);
#undef IPAD
#undef OPAD
}

static void
wg_algo_kdf(uint8_t out1[WG_KDF_OUTPUT_LEN], uint8_t out2[WG_KDF_OUTPUT_LEN],
    uint8_t out3[WG_KDF_OUTPUT_LEN], const uint8_t ckey[WG_CHAINING_KEY_LEN],
    const uint8_t input[], const size_t inputlen)
{
	uint8_t tmp1[WG_KDF_OUTPUT_LEN], tmp2[WG_KDF_OUTPUT_LEN + 1];
	uint8_t one[1];

	/*
	 * [N] 4.3: "an input_key_material byte sequence with length either zero
	 * bytes, 32 bytes, or DHLEN bytes."
	 */
	MPASS(inputlen == 0 || inputlen == 32 || inputlen == NOISE_DHLEN);

	WG_DUMP_HASH("ckey", ckey);
	if (input != NULL)
		WG_DUMP_HASH("input", input);
	wg_algo_hmac(tmp1, sizeof(tmp1), ckey, WG_CHAINING_KEY_LEN,
	    input, inputlen);
	WG_DUMP_HASH("tmp1", tmp1);
	one[0] = 1;
	wg_algo_hmac(out1, WG_KDF_OUTPUT_LEN, tmp1, sizeof(tmp1),
	    one, sizeof(one));
	WG_DUMP_HASH("out1", out1);
	if (out2 == NULL)
		return;
	memcpy(tmp2, out1, WG_KDF_OUTPUT_LEN);
	tmp2[WG_KDF_OUTPUT_LEN] = 2;
	wg_algo_hmac(out2, WG_KDF_OUTPUT_LEN, tmp1, sizeof(tmp1),
	    tmp2, sizeof(tmp2));
	WG_DUMP_HASH("out2", out2);
	if (out3 == NULL)
		return;
	memcpy(tmp2, out2, WG_KDF_OUTPUT_LEN);
	tmp2[WG_KDF_OUTPUT_LEN] = 3;
	wg_algo_hmac(out3, WG_KDF_OUTPUT_LEN, tmp1, sizeof(tmp1),
	    tmp2, sizeof(tmp2));
	WG_DUMP_HASH("out3", out3);
}

static void
wg_algo_dh_kdf(uint8_t ckey[WG_CHAINING_KEY_LEN],
    uint8_t cipher_key[WG_CIPHER_KEY_LEN],
    const uint8_t local_key[WG_STATIC_KEY_LEN],
    const uint8_t remote_key[WG_STATIC_KEY_LEN])
{
	uint8_t dhout[WG_DH_OUTPUT_LEN];

	wg_algo_dh(dhout, local_key, remote_key);
	wg_algo_kdf(ckey, cipher_key, NULL, ckey, dhout, sizeof(dhout));

	WG_DUMP_HASH("dhout", dhout);
	WG_DUMP_HASH("ckey", ckey);
	if (cipher_key != NULL)
		WG_DUMP_HASH("cipher_key", cipher_key);
}

static void
wg_algo_aead_enc(uint8_t out[], size_t expected_outsize, const uint8_t key[],
    const uint64_t counter, const uint8_t plain[], const size_t plainsize,
    const uint8_t auth[], size_t authlen)
{
	uint8_t nonce[(32 + 64) / 8] = {0};
	long long unsigned int outsize;
	int error __diagused;

	memcpy(&nonce[4], &counter, sizeof(counter));

	error = crypto_aead_chacha20poly1305_ietf_encrypt(out, &outsize, plain,
	    plainsize, auth, authlen, NULL, nonce, key);
	MPASS(error == 0);
	MPASS(outsize == expected_outsize);
}

#ifdef notyet
static int
wg_algo_aead_dec(uint8_t out[], size_t expected_outsize, const uint8_t key[],
    const uint64_t counter, const uint8_t encrypted[],
    const size_t encryptedsize, const uint8_t auth[], size_t authlen)
{
	uint8_t nonce[(32 + 64) / 8] = {0};
	long long unsigned int outsize;
	int error;

	memcpy(&nonce[4], &counter, sizeof(counter));

	error = crypto_aead_chacha20poly1305_ietf_decrypt(out, &outsize, NULL,
	    encrypted, encryptedsize, auth, authlen, nonce, key);
	if (error == 0)
		MPASS(outsize == expected_outsize);
	return error;
}

static void
wg_algo_xaead_enc(uint8_t out[], const size_t expected_outsize,
    const uint8_t key[], const uint8_t plain[], const size_t plainsize,
    const uint8_t auth[], size_t authlen,
    const uint8_t nonce[WG_SALT_LEN])
{
	long long unsigned int outsize;
	int error __diagused;

	CTASSERT(WG_SALT_LEN == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
	error = crypto_aead_xchacha20poly1305_ietf_encrypt(out, &outsize, plain,
	    plainsize, auth, authlen, NULL, nonce, key);
	MPASS(error == 0);
	MPASS(outsize == expected_outsize);
}

static int
wg_algo_xaead_dec(uint8_t out[], const size_t expected_outsize,
    const uint8_t key[], const uint64_t counter,
    const uint8_t encrypted[], const size_t encryptedsize,
    const uint8_t auth[], size_t authlen,
    const uint8_t nonce[WG_SALT_LEN])
{
	long long unsigned int outsize;
	int error;

	error = crypto_aead_xchacha20poly1305_ietf_decrypt(out, &outsize, NULL,
	    encrypted, encryptedsize, auth, authlen, nonce, key);
	if (error == 0)
		MPASS(outsize == expected_outsize);
	return error;
}
#endif

static void
wg_algo_tai64n(wg_timestamp_t _timestamp)
{
	struct timespec ts;
	uint32_t *timestamp = (uint32_t *)_timestamp;

	/* FIXME strict TAI64N (https://cr.yp.to/libtai/tai64.html) */
	getnanotime(&ts);
	/* TAI64 label in external TAI64 format */
	timestamp[0] = htonl(0x40000000L + (ts.tv_sec >> 32));
	/* second beginning from 1970 TAI */
	timestamp[1] = htonl((long)ts.tv_sec);
	/* nanosecond in big-endian format */
	timestamp[2] = htonl(ts.tv_nsec);
}


#define WG_MSG_TYPE_INIT		1
#define WG_MSG_TYPE_RESP		2
#define WG_MSG_TYPE_COOKIE		3
#define WG_MSG_TYPE_DATA		4
#define WG_MSG_TYPE_MAX			WG_MSG_TYPE_DATA

struct wg_worker {
	kmutex_t	wgw_lock;
	kcondvar_t	wgw_cv;
	bool		wgw_todie;
	struct socket	*wgw_so4;
	struct socket	*wgw_so6;
	int		wgw_wakeup_reasons;
#define WG_WAKEUP_REASON_RECEIVE_PACKETS_IPV4	__BIT(0)
#define WG_WAKEUP_REASON_RECEIVE_PACKETS_IPV6	__BIT(1)
#define WG_WAKEUP_REASON_PEER			__BIT(2)
};

struct wg_sockaddr {
	union {
		struct sockaddr_storage _ss;
		struct sockaddr _sa;
		struct sockaddr_in _sin;
		struct sockaddr_in6 _sin6;
	};
	//struct epoch_context wgsa_epoch_ctx;
};

struct wg_peer;
struct wg_allowedip {
	struct radix_node	wga_nodes[2];
	struct wg_sockaddr	_wga_sa_addr;
	struct wg_sockaddr	_wga_sa_mask;
#define wga_sa_addr		_wga_sa_addr._sa
#define wga_sa_mask		_wga_sa_mask._sa

	int			wga_family;
	uint8_t			wga_cidr;
	union {
		struct in_addr _ip4;
		struct in6_addr _ip6;
	} wga_addr;
#define wga_addr4	wga_addr._ip4
#define wga_addr6	wga_addr._ip6

	struct wg_peer		*wga_peer;
};

struct wg_peer {
	struct wg_softc		*wgp_sc;
	char			wgp_name[WG_PEER_NAME_MAXLEN + 1];
	CK_STAILQ_ENTRY(wg_peer)	wgp_peerlist_entry;
	struct epoch_context	wgp_epoch_ctx;
	kmutex_t		*wgp_lock;

	uint8_t	wgp_pubkey[WG_STATIC_KEY_LEN];
	struct wg_sockaddr	*wgp_endpoint;
#define wgp_ss		wgp_endpoint->_ss
#define wgp_sa		wgp_endpoint->_sa
#define wgp_sin		wgp_endpoint->_sin
#define wgp_sin6	wgp_endpoint->_sin6
	struct wg_sockaddr	*wgp_endpoint0;
	bool			wgp_endpoint_changing;
	bool			wgp_endpoint_available;

			/* The preshared key (optional) */
	uint8_t		wgp_psk[WG_PRESHARED_KEY_LEN];

	int wgp_state;
#define WGP_STATE_INIT		0
#define WGP_STATE_ESTABLISHED	1
#define WGP_STATE_GIVEUP	2
#define WGP_STATE_DESTROYING	3

	void		*wgp_si;
	//pcq_t		*wgp_q;

	struct wg_session	*wgp_session_stable;
	struct wg_session	*wgp_session_unstable;

	/* timestamp in big-endian */
	wg_timestamp_t	wgp_timestamp_latest_init;

	struct timespec		wgp_last_handshake_time;

	callout_t		wgp_rekey_timer;
	callout_t		wgp_handshake_timeout_timer;
	callout_t		wgp_session_dtor_timer;

	time_t			wgp_handshake_start_time;

	int			wgp_n_allowedips;;
	struct wg_allowedip	wgp_allowedips[WG_ALLOWEDIPS];

	time_t			wgp_latest_cookie_time;
	uint8_t			wgp_latest_cookie[WG_COOKIE_LEN];
	uint8_t			wgp_last_sent_mac1[WG_MAC_LEN];
	bool			wgp_last_sent_mac1_valid;
	uint8_t			wgp_last_sent_cookie[WG_COOKIE_LEN];
	bool			wgp_last_sent_cookie_valid;

	time_t			wgp_last_msg_received_time[WG_MSG_TYPE_MAX];

	time_t			wgp_last_genrandval_time;
	uint32_t		wgp_randval;

	struct wg_ppsratecheck	wgp_ppsratecheck;

	volatile unsigned int	wgp_tasks;
#define WGP_TASK_SEND_INIT_MESSAGE		__BIT(0)
#define WGP_TASK_ENDPOINT_CHANGED		__BIT(1)
#define WGP_TASK_SEND_KEEPALIVE_MESSAGE	__BIT(2)
#define WGP_TASK_DESTROY_PREV_SESSION		__BIT(3)
};

struct wg_session {
	struct wg_peer	*wgs_peer;
	struct epoch_context	wgs_epoch_ctx;
	kmutex_t	*wgs_lock;

	int		wgs_state;
#define WGS_STATE_UNKNOWN	0
#define WGS_STATE_INIT_ACTIVE	1
#define WGS_STATE_INIT_PASSIVE	2
#define WGS_STATE_ESTABLISHED	3
#define WGS_STATE_DESTROYING	4

	time_t		wgs_time_established;
	time_t		wgs_time_last_data_sent;
	bool		wgs_is_initiator;

	uint32_t	wgs_sender_index;
	uint32_t	wgs_receiver_index;
	volatile uint64_t
			wgs_send_counter;
	volatile uint64_t
			wgs_recv_counter;

	uint8_t		wgs_handshake_hash[WG_HASH_LEN];
	uint8_t		wgs_chaining_key[WG_CHAINING_KEY_LEN];
	uint8_t		wgs_ephemeral_key_pub[WG_EPHEMERAL_KEY_LEN];
	uint8_t		wgs_ephemeral_key_priv[WG_EPHEMERAL_KEY_LEN];
	uint8_t		wgs_ephemeral_key_peer[WG_EPHEMERAL_KEY_LEN];
	uint8_t		wgs_tkey_send[WG_DATA_KEY_LEN];
	uint8_t		wgs_tkey_recv[WG_DATA_KEY_LEN];
};

struct wg_ops;

struct wg_softc {
	if_softc_ctx_t shared;
	if_ctx_t wg_ctx;

	uint8_t		wg_privkey[WG_STATIC_KEY_LEN];
	uint8_t		wg_pubkey[WG_STATIC_KEY_LEN];
	struct wg_ops *wg_ops;

	struct wg_worker	*wg_worker;

	int		wg_npeers;
	CK_STAILQ_HEAD(, wg_peer) wg_peers;
};
static int clone_count;

static int
wg_transmit(if_t ifp, struct mbuf *m)
{
	return (0);
}

#define WG_CAPS														\
	IFCAP_TSO | IFCAP_HWCSUM | IFCAP_VLAN_HWFILTER | IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWCSUM |	\
	IFCAP_VLAN_HWTSO | IFCAP_VLAN_MTU | IFCAP_HWCSUM_IPV6 | IFCAP_JUMBO_MTU | \
	IFCAP_LINKSTATE

static int
wg_cloneattach(if_ctx_t ctx, struct if_clone *ifc, const char *name, caddr_t params)
{
	struct wg_softc *wg = iflib_get_softc(ctx);
	if_softc_ctx_t scctx;

	atomic_add_int(&clone_count, 1);
	wg->wg_ctx = ctx;

	scctx = wg->shared = iflib_get_softc_ctx(ctx);
	scctx->isc_capenable = WG_CAPS;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO | CSUM_IP6_TCP \
		| CSUM_IP6_UDP | CSUM_IP6_TCP;
	return (0);
}

static int
wg_attach_post(if_ctx_t ctx)
{
	struct ifnet *ifp;

	ifp = iflib_get_ifp(ctx);
	if_settransmitfn(ifp, wg_transmit);
	//if_settransmittxqfn(ifp, wg_transmit);
	//if_setmbuftoqidfn(ifp, wg_mbuf_to_qid);
	iflib_link_state_change(ctx, LINK_STATE_UP, IF_Gbps(50));
	return (0);
}

static int
wg_detach(if_ctx_t ctx)
{
	iflib_link_state_change(ctx, LINK_STATE_DOWN, IF_Gbps(50));
	atomic_add_int(&clone_count, -1);
	return (0);
}

static void
wg_init(if_ctx_t ctx)
{
}

static void
wg_stop(if_ctx_t ctx)
{
}

static device_method_t wg_if_methods[] = {
	DEVMETHOD(ifdi_cloneattach, wg_cloneattach),
	DEVMETHOD(ifdi_attach_post, wg_attach_post),
	DEVMETHOD(ifdi_detach, wg_detach),
	DEVMETHOD(ifdi_init, wg_init),
	DEVMETHOD(ifdi_stop, wg_stop),
	DEVMETHOD_END
};

static driver_t wg_iflib_driver = {
	"wg", wg_if_methods, sizeof(struct wg_softc)
};

char wg_driver_version[] = "0.0.1";

static struct if_shared_ctx wg_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_driver_version = wg_driver_version,
	.isc_driver = &wg_iflib_driver,
	.isc_flags = IFLIB_PSEUDO,
	.isc_name = "wg",
};

if_shared_ctx_t wg_sctx = &wg_sctx_init;


static if_pseudo_t wg_pseudo;

static int
wg_module_init(void)
{
	wg_pseudo = iflib_clone_register(wg_sctx);

	return wg_pseudo != NULL ? 0 : ENXIO;
}

static void
wg_module_deinit(void)
{
	iflib_clone_deregister(wg_pseudo);
}

static int
wg_module_event_handler(module_t mod, int what, void *arg)
{
	int err;

	switch (what) {
	case MOD_LOAD:
		if ((err = wg_module_init()) != 0)
			return (err);
		break;
	case MOD_UNLOAD:
		if (clone_count == 0)
			wg_module_deinit();
		else
			return (EBUSY);
		break;
	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

static moduledata_t wg_moduledata = {
	"wg",
	wg_module_event_handler,
	NULL
};

DECLARE_MODULE(wg, wg_moduledata, SI_SUB_INIT_IF, SI_ORDER_ANY);
MODULE_VERSION(wg, 1);
MODULE_DEPEND(wg, iflib, 1, 1, 1);

#define	ISSET(x, y)	((x) & (y))
#define	__BIT(x)	((uintmax_t)1 << (uintmax_t)(x))

#define WG_REKEY_AFTER_MESSAGES		(ULONG_MAX - (1 << 16) - 1)
#define WG_REJECT_AFTER_MESSAGES	(ULONG_MAX - (1 <<  4) - 1)
#define WG_REKEY_AFTER_TIME		120
#define WG_REJECT_AFTER_TIME		180
#define WG_REKEY_ATTEMPT_TIME		 90
#define WG_REKEY_TIMEOUT		  5
#define WG_KEEPALIVE_TIMEOUT		 10

#define WG_COOKIE_TIME			120
#define WG_RANDVAL_TIME			(2 * 60)

#define WGLOG(level, fmt, args...)	log(level, "%s: " fmt, __func__, ##args)

#ifdef WG_DEBUG_LOG
#define WG_DLOG(fmt, args...)	log(LOG_DEBUG, "%s: " fmt, __func__, ##args)
#else
#define WG_DLOG(fmt, args...)
#endif

#ifdef WG_DEBUG_TRACE
#define WG_TRACE(msg)	log(LOG_DEBUG, "%s:%d: %s\n", __func__, __LINE__, (msg))
#else
#define WG_TRACE(msg)
#endif

#define WG_PEER_READER_FOREACH(wgp, wg)					\
	CK_STAILQ_FOREACH((wgp), &(wg)->wg_peers, wgp_peerlist_entry)
#define WG_PEER_WRITER_FOREACH(wgp, wg)					\
	CK_STAILQ_FOREACH((wgp), &(wg)->wg_peers, struct wg_peer, wgp_peerlist_entry)
#define WG_PEER_WRITER_INSERT_HEAD(wgp, wg)				\
	CK_STAILQ_INSERT_HEAD(&(wg)->wg_peers, (wgp), wgp_peerlist_entry)
#define WG_PEER_WRITER_REMOVE(wgp)					\
	CK_STAILQ_REMOVE(&(wg)->wg_peers, (wgp), struct wg_peer, wgp_peerlist_entry)
struct wg_ops {
	int (*send_hs_msg)(struct wg_peer *, struct mbuf *);
	int (*send_data_msg)(struct wg_peer *, struct mbuf *);
	void (*input)(struct ifnet *, struct mbuf *, const int);
	int (*bind_port)(struct wg_softc *, const uint16_t);
};

#define WG_REKEY_AFTER_MESSAGES		(ULONG_MAX - (1 << 16) - 1)
#define WG_REJECT_AFTER_MESSAGES	(ULONG_MAX - (1 <<  4) - 1)
#define WG_REKEY_AFTER_TIME		120
#define WG_REJECT_AFTER_TIME		180
#define WG_REKEY_ATTEMPT_TIME		 90
#define WG_REKEY_TIMEOUT		  5
#define WG_KEEPALIVE_TIMEOUT		 10

#define WG_COOKIE_TIME			120
#define WG_RANDVAL_TIME			(2 * 60)

//static uint64_t wg_rekey_after_messages = WG_REKEY_AFTER_MESSAGES;
//static uint64_t wg_reject_after_messages = WG_REJECT_AFTER_MESSAGES;
//static time_t wg_rekey_after_time = WG_REKEY_AFTER_TIME;
//static time_t wg_reject_after_time = WG_REJECT_AFTER_TIME;
//static time_t wg_rekey_attempt_time = WG_REKEY_ATTEMPT_TIME;
static time_t wg_rekey_timeout = WG_REKEY_TIMEOUT;
//static time_t wg_keepalive_timeout = WG_KEEPALIVE_TIMEOUT;

static void
wg_clear_states(struct wg_session *wgs)
{

	wgs->wgs_send_counter = 0;
	wgs->wgs_recv_counter = 0;

#define wgs_clear(v)	explicit_bzero(wgs->wgs_##v, sizeof(wgs->wgs_##v))
	wgs_clear(handshake_hash);
	wgs_clear(chaining_key);
	wgs_clear(ephemeral_key_pub);
	wgs_clear(ephemeral_key_priv);
	wgs_clear(ephemeral_key_peer);
#undef wgs_clear
}


static void
wg_send_keepalive_msg(struct wg_peer *wgp, struct wg_session *wgs)
{
	//struct mbuf *m;

	/*
	 * [W] 6.5 Passive Keepalive
	 * "A keepalive message is simply a transport data message with
	 *  a zero-length encapsulated encrypted inner-packet."
	 */
	//m = m_gethdr(M_WAITOK, MT_DATA);
	//wg_send_data_msg(wgp, wgs, m);
	// XXX
	panic("");
}

static struct wg_session *
wg_lock_unstable_session(struct wg_peer *wgp)
{
	struct wg_session *wgs;

	//mutex_enter(wgp->wgp_lock);
	wgs = wgp->wgp_session_unstable;
	//mutex_enter(wgs->wgs_lock);
	//mutex_exit(wgp->wgp_lock);
	return wgs;
}


static struct wg_session *
wg_get_unstable_session(struct wg_peer *wgp)
{
	//int s;
	struct wg_session *wgs;

	//s = pserialize_read_enter();
	wgs = wgp->wgp_session_unstable;
	//psref_acquire(psref, &wgs->wgs_psref, wg_psref_class);
	//pserialize_read_exit(s);
	return wgs;
}

static struct wg_session *
wg_get_stable_session(struct wg_peer *wgp)
{
	//int s;
	struct wg_session *wgs;

	//s = pserialize_read_enter();
	wgs = wgp->wgp_session_stable;
	//psref_acquire(psref, &wgs->wgs_psref, wg_psref_class);
	//pserialize_read_exit(s);
	return wgs;
}

static void
wg_get_session(struct wg_session *wgs)
{

	MPASS(in_epoch(net_epoch));
}

static void
wg_put_session(struct wg_session *wgs)
{

	MPASS(!in_epoch(net_epoch));
}

static void
wg_get_peer(struct wg_peer *p)
{

}

static void
wg_put_peer(struct wg_peer *p)
{

}

static void
wg_schedule_handshake_timeout_timer(struct wg_peer *wgp)
{

	mutex_enter(wgp->wgp_lock);
	if (__predict_true(wgp->wgp_state != WGP_STATE_DESTROYING)) {
		callout_schedule(&wgp->wgp_handshake_timeout_timer,
		    wg_rekey_timeout * hz);
	}
	mutex_exit(wgp->wgp_lock);
}

#ifdef notyet
static void
wg_stop_handshake_timeout_timer(struct wg_peer *wgp)
{

	//callout_halt(&wgp->wgp_handshake_timeout_timer, NULL);
}

static void
wg_receive_packets(struct wg_softc *wg, const int af)
{

	while (true) {
		int error, flags;
		struct socket *so;
		struct mbuf *m = NULL;
		struct uio dummy_uio;
		struct mbuf *paddr = NULL;
		struct sockaddr *src;

		so = wg_get_so_by_af(wg->wg_worker, af);
		flags = MSG_DONTWAIT;
		dummy_uio.uio_resid = 1000000000;

		error = so->so_receive(so, &paddr, &dummy_uio, &m, NULL, &flags);
		if (error || m == NULL) {
			//if (error == EWOULDBLOCK)
			return;
		}

		MPASS(paddr != NULL);
		src = mtod(paddr, struct sockaddr *);

		wg_handle_packet(wg, m, src);
	}
}
#endif

/*
 * Handshake patterns
 *
 * [W] 5: "These messages use the "IK" pattern from Noise"
 * [N] 7.5. Interactive handshake patterns (fundamental)
 *     "The first character refers to the initiator’s static key:"
 *     "I = Static key for initiator Immediately transmitted to responder,
 *          despite reduced or absent identity hiding"
 *     "The second character refers to the responder’s static key:"
 *     "K = Static key for responder Known to initiator"
 *     "IK:
 *        <- s
 *        ...
 *        -> e, es, s, ss
 *        <- e, ee, se"
 * [N] 9.4. Pattern modifiers
 *     "IKpsk2:
 *        <- s
 *        ...
 *        -> e, es, s, ss
 *        <- e, ee, se, psk"
 */
static void
wg_fill_msg_init(struct wg_softc *wg, struct wg_peer *wgp,
    struct wg_session *wgs, struct wg_msg_init *wgmi)
{
	uint8_t ckey[WG_CHAINING_KEY_LEN]; /* [W] 5.4.2: Ci */
	uint8_t hash[WG_HASH_LEN]; /* [W] 5.4.2: Hi */
	uint8_t cipher_key[WG_CIPHER_KEY_LEN];
	uint8_t pubkey[WG_EPHEMERAL_KEY_LEN];
	uint8_t privkey[WG_EPHEMERAL_KEY_LEN];

	wgmi->wgmi_type = WG_MSG_TYPE_INIT;
	wgmi->wgmi_sender = cprng_strong32();

	/* [W] 5.4.2: First Message: Initiator to Responder */

	/* Ci := HASH(CONSTRUCTION) */
	/* Hi := HASH(Ci || IDENTIFIER) */
	wg_init_key_and_hash(ckey, hash);
	/* Hi := HASH(Hi || Sr^pub) */
	wg_algo_hash(hash, wgp->wgp_pubkey, sizeof(wgp->wgp_pubkey));

	WG_DUMP_HASH("hash", hash);

	/* [N] 2.2: "e" */
	/* Ei^priv, Ei^pub := DH-GENERATE() */
	wg_algo_generate_keypair(pubkey, privkey);
	/* Ci := KDF1(Ci, Ei^pub) */
	wg_algo_kdf(ckey, NULL, NULL, ckey, pubkey, sizeof(pubkey));
	/* msg.ephemeral := Ei^pub */
	memcpy(wgmi->wgmi_ephemeral, pubkey, sizeof(wgmi->wgmi_ephemeral));
	/* Hi := HASH(Hi || msg.ephemeral) */
	wg_algo_hash(hash, pubkey, sizeof(pubkey));

	WG_DUMP_HASH("ckey", ckey);
	WG_DUMP_HASH("hash", hash);

	/* [N] 2.2: "es" */
	/* Ci, k := KDF2(Ci, DH(Ei^priv, Sr^pub)) */
	wg_algo_dh_kdf(ckey, cipher_key, privkey, wgp->wgp_pubkey);

	/* [N] 2.2: "s" */
	/* msg.static := AEAD(k, 0, Si^pub, Hi) */
	wg_algo_aead_enc(wgmi->wgmi_static, sizeof(wgmi->wgmi_static),
	    cipher_key, 0, wg->wg_pubkey, sizeof(wg->wg_pubkey),
	    hash, sizeof(hash));
	/* Hi := HASH(Hi || msg.static) */
	wg_algo_hash(hash, wgmi->wgmi_static, sizeof(wgmi->wgmi_static));

	WG_DUMP_HASH48("wgmi_static", wgmi->wgmi_static);

	/* [N] 2.2: "ss" */
	/* Ci, k := KDF2(Ci, DH(Si^priv, Sr^pub)) */
	wg_algo_dh_kdf(ckey, cipher_key, wg->wg_privkey, wgp->wgp_pubkey);

	/* msg.timestamp := AEAD(k, TIMESTAMP(), Hi) */
	wg_timestamp_t timestamp;
	wg_algo_tai64n(timestamp);
	wg_algo_aead_enc(wgmi->wgmi_timestamp, sizeof(wgmi->wgmi_timestamp),
	    cipher_key, 0, timestamp, sizeof(timestamp), hash, sizeof(hash));
	/* Hi := HASH(Hi || msg.timestamp) */
	wg_algo_hash(hash, wgmi->wgmi_timestamp, sizeof(wgmi->wgmi_timestamp));

	/* [W] 5.4.4 Cookie MACs */
	wg_algo_mac_mac1(wgmi->wgmi_mac1, sizeof(wgmi->wgmi_mac1),
	    wgp->wgp_pubkey, sizeof(wgp->wgp_pubkey),
	    (uint8_t *)wgmi, offsetof(struct wg_msg_init, wgmi_mac1));
	/* Need mac1 to decrypt a cookie from a cookie message */
	memcpy(wgp->wgp_last_sent_mac1, wgmi->wgmi_mac1,
	    sizeof(wgp->wgp_last_sent_mac1));
	wgp->wgp_last_sent_mac1_valid = true;

	if (wgp->wgp_latest_cookie_time == 0 ||
	    (time_uptime - wgp->wgp_latest_cookie_time) >= WG_COOKIE_TIME)
		memset(wgmi->wgmi_mac2, 0, sizeof(wgmi->wgmi_mac2));
	else {
		wg_algo_mac(wgmi->wgmi_mac2, sizeof(wgmi->wgmi_mac2),
		    wgp->wgp_latest_cookie, WG_COOKIE_LEN,
		    (uint8_t *)wgmi, offsetof(struct wg_msg_init, wgmi_mac2),
		    NULL, 0);
	}

	memcpy(wgs->wgs_ephemeral_key_pub, pubkey, sizeof(pubkey));
	memcpy(wgs->wgs_ephemeral_key_priv, privkey, sizeof(privkey));
	memcpy(wgs->wgs_handshake_hash, hash, sizeof(hash));
	memcpy(wgs->wgs_chaining_key, ckey, sizeof(ckey));
	wgs->wgs_sender_index = wgmi->wgmi_sender;
	WG_DLOG("%s: sender=%x\n", __func__, wgs->wgs_sender_index);
}

static int
wg_send_handshake_msg_init(struct wg_softc *wg, struct wg_peer *wgp)
{
	int error;
	struct mbuf *m;
	struct wg_msg_init *wgmi;
	struct wg_session *wgs;

	wgs = wg_lock_unstable_session(wgp);
	if (wgs->wgs_state == WGS_STATE_DESTROYING) {
		WG_TRACE("Session destroying");
		mutex_exit(wgs->wgs_lock);
		/* XXX should wait? */
		return EBUSY;
	}
	if (wgs->wgs_state == WGS_STATE_INIT_ACTIVE) {
		WG_TRACE("Sesssion already initializing, skip starting a new one");
		mutex_exit(wgs->wgs_lock);
		return EBUSY;
	}
	if (wgs->wgs_state == WGS_STATE_INIT_PASSIVE) {
		WG_TRACE("Sesssion already initializing, destroying old states");
		wg_clear_states(wgs);
	}
	wgs->wgs_state = WGS_STATE_INIT_ACTIVE;
	wg_get_session(wgs);
	mutex_exit(wgs->wgs_lock);

	m = m_gethdr(M_WAITOK, MT_DATA);
	m->m_pkthdr.len = m->m_len = sizeof(*wgmi);
	wgmi = mtod(m, struct wg_msg_init *);

	wg_fill_msg_init(wg, wgp, wgs, wgmi);

	error = wg->wg_ops->send_hs_msg(wgp, m);
	if (error == 0) {
		WG_TRACE("init msg sent");

		if (wgp->wgp_handshake_start_time == 0)
			wgp->wgp_handshake_start_time = time_uptime;
		wg_schedule_handshake_timeout_timer(wgp);
	} else {
		mutex_enter(wgs->wgs_lock);
		MPASS(wgs->wgs_state == WGS_STATE_INIT_ACTIVE);
		wgs->wgs_state = WGS_STATE_UNKNOWN;
		mutex_exit(wgs->wgs_lock);
	}
	wg_put_session(wgs);

	return error;
}

static void
wg_process_peer_tasks(struct wg_softc *wg)
{
	struct wg_peer *wgp;
	struct epoch_tracker et;

	/* XXX should avoid checking all peers */
	NET_EPOCH_ENTER(et);
	WG_PEER_READER_FOREACH(wgp, wg) {
		unsigned int tasks;

		if (wgp->wgp_tasks == 0)
			continue;

		wg_get_peer(wgp);
		NET_EPOCH_EXIT(et);

	restart:
		tasks = atomic_swap_int(&wgp->wgp_tasks, 0);
		MPASS(tasks != 0);

		WG_DLOG("tasks=%x\n", tasks);

		if (ISSET(tasks, WGP_TASK_SEND_INIT_MESSAGE)) {
			struct wg_session *wgs;

			WG_TRACE("WGP_TASK_SEND_INIT_MESSAGE");
			if (!wgp->wgp_endpoint_available) {
				WGLOG(LOG_DEBUG, "No endpoint available\n");
				/* XXX should do something? */
				goto skip_init_message;
			}
			wgs = wg_get_stable_session(wgp);
			if (wgs->wgs_state == WGS_STATE_UNKNOWN) {
				wg_put_session(wgs);
				wg_send_handshake_msg_init(wg, wgp);
			} else {
				wg_put_session(wgs);
				/* rekey */
				wgs = wg_get_unstable_session(wgp);
				if (wgs->wgs_state != WGS_STATE_INIT_ACTIVE)
					wg_send_handshake_msg_init(wg, wgp);
				wg_put_session(wgs);
			}
		}
	skip_init_message:
		if (ISSET(tasks, WGP_TASK_ENDPOINT_CHANGED)) {
			WG_TRACE("WGP_TASK_ENDPOINT_CHANGED");
			mutex_enter(wgp->wgp_lock);
			if (wgp->wgp_endpoint_changing) {
				wgp->wgp_endpoint_changing = false;
			}
			mutex_exit(wgp->wgp_lock);
		}
		if (ISSET(tasks, WGP_TASK_SEND_KEEPALIVE_MESSAGE)) {
			struct wg_session *wgs;

			WG_TRACE("WGP_TASK_SEND_KEEPALIVE_MESSAGE");
			wgs = wg_get_stable_session(wgp);
			wg_send_keepalive_msg(wgp, wgs);
			wg_put_session(wgs);
		}
		if (ISSET(tasks, WGP_TASK_DESTROY_PREV_SESSION)) {
			struct wg_session *wgs;

			WG_TRACE("WGP_TASK_DESTROY_PREV_SESSION");
			mutex_enter(wgp->wgp_lock);
			wgs = wgp->wgp_session_unstable;
			mutex_enter(wgs->wgs_lock);
			if (wgs->wgs_state == WGS_STATE_DESTROYING) {
				//pserialize_perform(wgp->wgp_psz);
				wg_clear_states(wgs);
				wgs->wgs_state = WGS_STATE_UNKNOWN;
			}
			mutex_exit(wgs->wgs_lock);
			mutex_exit(wgp->wgp_lock);
		}

		/* New tasks may be scheduled during processing tasks */
		WG_DLOG("wgp_tasks=%d\n", wgp->wgp_tasks);
		if (wgp->wgp_tasks != 0)
			goto restart;

		NET_EPOCH_ENTER(et);
		wg_put_peer(wgp);
	}
	NET_EPOCH_EXIT(et);
}

#ifdef notyet
static void
wg_worker(void *arg)
{
	struct wg_softc *wg = arg;
	struct wg_worker *wgw = wg->wg_worker;

	MPASS(wg != NULL);
	MPASS(wgw != NULL);

	while (!wgw->wgw_todie) {
		int reasons;

		mutex_enter(&wgw->wgw_lock);
		/* New tasks may come during task handling */
		if (wgw->wgw_wakeup_reasons == 0)
			cv_wait(&wgw->wgw_cv, &wgw->wgw_lock);
		reasons = wgw->wgw_wakeup_reasons;
		wgw->wgw_wakeup_reasons = 0;
		mutex_exit(&wgw->wgw_lock);

		if (ISSET(reasons, WG_WAKEUP_REASON_RECEIVE_PACKETS_IPV4))
			wg_receive_packets(wg, AF_INET);
		if (ISSET(reasons, WG_WAKEUP_REASON_RECEIVE_PACKETS_IPV6))
			wg_receive_packets(wg, AF_INET6);
		if (!ISSET(reasons, WG_WAKEUP_REASON_PEER))
			continue;

		wg_process_peer_tasks(wg);
	}
	kthread_exit();
}
#endif
