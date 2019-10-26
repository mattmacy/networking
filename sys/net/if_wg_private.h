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

#define WG_MSG_TYPE_INIT		1
#define WG_MSG_TYPE_RESP		2
#define WG_MSG_TYPE_COOKIE		3
#define WG_MSG_TYPE_DATA		4
#define WG_MSG_TYPE_MAX			WG_MSG_TYPE_DATA
