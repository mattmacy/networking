#ifndef IF_WG_PRIVATE_H_
#define IF_WG_PRIVATE_H_

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

MALLOC_DEFINE(M_WG, "wg", "wireguard");

typedef struct mtx kmutex_t;
typedef struct cv kcondvar_t;
typedef struct rwlock krwlock_t;
typedef struct callout callout_t;
typedef struct thread lwp_t;

typedef uint8_t wg_timestamp_t[WG_TIMESTAMP_LEN];

#define __diagused __unused
#define	mutex_enter mtx_lock
#define	mutex_exit mtx_unlock
#define mutex_init(lock, type, ipl) mtx_init(lock, #lock, NULL, MTX_DEF)
#define cprng_fast(buf, size) read_random(buf, size)
#define cprng_strong32() arc4random()

static __inline void
sockaddr_in_init1(struct sockaddr_in *sin, const struct in_addr *addr,
    in_port_t port)
{
	sin->sin_port = port;
	sin->sin_addr = *addr;
	memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
}

static __inline void
sockaddr_in_init(struct sockaddr_in *sin, const struct in_addr *addr,
    in_port_t port)
{
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);
	sockaddr_in_init1(sin, addr, port);
}

static __inline void
sockaddr_in6_init1(struct sockaddr_in6 *sin6, const struct in6_addr *addr,
    in_port_t port, uint32_t flowinfo, uint32_t scope_id)
{
	sin6->sin6_port = port;
	sin6->sin6_flowinfo = flowinfo;
	sin6->sin6_addr = *addr;
	sin6->sin6_scope_id = scope_id;
}

static __inline void
sockaddr_in6_init(struct sockaddr_in6 *sin6, const struct in6_addr *addr,
    in_port_t port, uint32_t flowinfo, uint32_t scope_id)
{
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(*sin6);
	sockaddr_in6_init1(sin6, addr, port, flowinfo, scope_id);
}

#define satocsin(src) ((const struct sockaddr_in *)(src))
#define satocsin6(src) ((const struct sockaddr_in6 *)(src))

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

#define WG_MSG_TYPE_INIT		1
#define WG_MSG_TYPE_RESP		2
#define WG_MSG_TYPE_COOKIE		3
#define WG_MSG_TYPE_DATA		4
#define WG_MSG_TYPE_MAX			WG_MSG_TYPE_DATA



static inline void
wg_algo_hash(uint8_t hash[WG_HASH_LEN], const uint8_t input[],
    const size_t inputsize)
{
	blake2s_state state;

	blake2s_init(&state, WG_HASH_LEN);
	blake2s_update(&state, hash, WG_HASH_LEN);
	blake2s_update(&state, input, inputsize);
	blake2s_final(&state, hash, WG_HASH_LEN);
}

static inline void
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

static inline void
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

static inline void
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

static inline void
wg_algo_generate_keypair(uint8_t pubkey[WG_EPHEMERAL_KEY_LEN],
    uint8_t privkey[WG_EPHEMERAL_KEY_LEN])
{

	CTASSERT(WG_EPHEMERAL_KEY_LEN == crypto_scalarmult_curve25519_BYTES);

	cprng_fast(privkey, WG_EPHEMERAL_KEY_LEN);
	crypto_scalarmult_base(pubkey, privkey);
}

static inline void
wg_algo_dh(uint8_t out[WG_DH_OUTPUT_LEN],
    const uint8_t privkey[WG_STATIC_KEY_LEN],
    const uint8_t pubkey[WG_STATIC_KEY_LEN])
{

	CTASSERT(WG_STATIC_KEY_LEN == crypto_scalarmult_curve25519_BYTES);

	int ret __unused = crypto_scalarmult(out, privkey, pubkey);
	MPASS(ret == 0);
}

static inline void
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

static inline void
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

static inline void
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

static inline void
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

static inline void
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

static inline void
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

#endif
