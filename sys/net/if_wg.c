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
#include <sys/uio.h>

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

#include <contrib/libb2/blake2.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>

#include <net/ethernet.h>
#include <net/iflib.h>
#include "ifdi_if.h"
#include <net/if_wg.h>
#include <net/if_wg_private.h>


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

struct wg_ppsratecheck {
	struct timeval		wgprc_lasttime;
	int			wgprc_curpps;
};

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

	struct radix_node_head	*wg_rtable_ipv4;
	struct radix_node_head	*wg_rtable_ipv6;
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

#ifdef notyet
#define WG_LOG_RATECHECK(wgprc, level, fmt, args...)	do {		\
	if (ppsratecheck(&(wgprc)->wgprc_lasttime,			\
	    &(wgprc)->wgprc_curpps, 1)) {				\
		log(level, fmt, ##args);				\
	}								\
} while (0)
#else
#define WG_LOG_RATECHECK(wgprc, level, fmt, args...)
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
	void (*input)(if_ctx_t, struct mbuf *, const int);
	int (*bind_port)(struct wg_softc *, const uint16_t);
};


static struct wg_peer * wg_pick_peer_by_sa(struct wg_softc *wg,
    const struct sockaddr *sa);

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
static time_t wg_rekey_after_time = WG_REKEY_AFTER_TIME;
static time_t wg_reject_after_time = WG_REJECT_AFTER_TIME;
//static time_t wg_rekey_attempt_time = WG_REKEY_ATTEMPT_TIME;
static time_t wg_rekey_timeout = WG_REKEY_TIMEOUT;
static time_t wg_keepalive_timeout = WG_KEEPALIVE_TIMEOUT;

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
wg_calculate_keys(struct wg_session *wgs, const bool initiator)
{

	/* [W] 5.4.5: Ti^send = Tr^recv, Ti^recv = Tr^send := KDF2(Ci = Cr, e) */
	if (initiator) {
		wg_algo_kdf(wgs->wgs_tkey_send, wgs->wgs_tkey_recv, NULL,
		    wgs->wgs_chaining_key, NULL, 0);
	} else {
		wg_algo_kdf(wgs->wgs_tkey_recv, wgs->wgs_tkey_send, NULL,
		    wgs->wgs_chaining_key, NULL, 0);
	}
	WG_DUMP_HASH("wgs_tkey_send", wgs->wgs_tkey_send);
	WG_DUMP_HASH("wgs_tkey_recv", wgs->wgs_tkey_recv);
}

/* Inspired by pppoe_get_mbuf */
static struct mbuf *
wg_get_mbuf(size_t leading_len, size_t len)
{
	struct mbuf *m;

	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (m == NULL)
		return NULL;
	if (len + leading_len > MHLEN) {
		m_clget(m, M_NOWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return NULL;
		}
	}
	m->m_data += leading_len;
	m->m_pkthdr.len = m->m_len = len;

	return m;
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

static struct radix_node_head *
wg_rnh(struct wg_softc *wg, const int family)
{

	switch (family) {
		case AF_INET:
			return wg->wg_rtable_ipv4;
#ifdef INET6
		case AF_INET6:
			return wg->wg_rtable_ipv6;
#endif
		default:
			return NULL;
	}
}

static struct wg_peer *
wg_pick_peer_by_sa(struct wg_softc *wg, const struct sockaddr *sa)
{
	struct radix_node_head *rnh;
	struct radix_node *rn;
	struct wg_peer *wgp = NULL;
	struct wg_allowedip *wga;

#ifdef WG_DEBUG_LOG
	char addrstr[128];
	sockaddr_format(sa, addrstr, sizeof(addrstr));
	WG_DLOG("sa=%s\n", addrstr);
#endif

	//rw_enter(wg->wg_rwlock, RW_READER);

	rnh = wg_rnh(wg, sa->sa_family);
	if (rnh == NULL)
		goto out;

	rn = rnh->rnh_matchaddr(__DECONST(void *, sa), &rnh->rh);
	if (rn == NULL || (rn->rn_flags & RNF_ROOT) != 0)
		goto out;

	WG_TRACE("success");

	wga = (struct wg_allowedip *)rn;
	wgp = wga->wga_peer;
	wg_get_peer(wgp);

out:
	//rw_exit(wg->wg_rwlock);
	return wgp;
}

static struct wg_peer *
wg_lookup_peer_by_pubkey(struct wg_softc *wg,
    const uint8_t pubkey[WG_STATIC_KEY_LEN])
{
	struct wg_peer *wgp;

	//int s = pserialize_read_enter();
	/* XXX O(n) */
	WG_PEER_READER_FOREACH(wgp, wg) {
		if (memcmp(wgp->wgp_pubkey, pubkey, sizeof(wgp->wgp_pubkey)) == 0)
			break;
	}
	if (wgp != NULL)
		wg_get_peer(wgp);
	//pserialize_read_exit(s);

	return wgp;
}

static struct wg_session *
wg_lookup_session_by_index(struct wg_softc *wg, const uint32_t index)
{
	struct wg_peer *wgp;
	struct wg_session *wgs;

	//int s = pserialize_read_enter();
	/* XXX O(n) */
	WG_PEER_READER_FOREACH(wgp, wg) {
		wgs = wgp->wgp_session_stable;
		WG_DLOG("index=%x wgs_sender_index=%x\n",
		    index, wgs->wgs_sender_index);
		if (wgs->wgs_sender_index == index)
			break;
		wgs = wgp->wgp_session_unstable;
		WG_DLOG("index=%x wgs_sender_index=%x\n",
		    index, wgs->wgs_sender_index);
		if (wgs->wgs_sender_index == index)
			break;
		wgs = NULL;
	}
	//if (wgs != NULL)
	//psref_acquire(psref, &wgs->wgs_psref, wg_psref_class);
	//pserialize_read_exit(s);

	return wgs;
}

static bool
wg_validate_inner_packet(char *packet, size_t decrypted_len, int *af)
{
	uint16_t packet_len;
	struct ip *ip;

	if (__predict_false(decrypted_len < sizeof(struct ip)))
		return false;

	ip = (struct ip *)packet;
	if (ip->ip_v == 4)
		*af = AF_INET;
	else if (ip->ip_v == 6)
		*af = AF_INET6;
	else
		return false;

	WG_DLOG("af=%d\n", *af);

	if (*af == AF_INET) {
		packet_len = ntohs(ip->ip_len);
	} else {
		struct ip6_hdr *ip6;

		if (__predict_false(decrypted_len < sizeof(struct ip6_hdr)))
			return false;

		ip6 = (struct ip6_hdr *)packet;
		packet_len = sizeof(struct ip6_hdr) + ntohs(ip6->ip6_plen);
	}

	WG_DLOG("packet_len=%u\n", packet_len);
	if (packet_len > decrypted_len)
		return false;

	return true;
}

static bool
wg_validate_route(struct wg_softc *wg, struct wg_peer *wgp_expected,
    int af, char *packet)
{
	struct sockaddr_storage ss;
	struct sockaddr *sa;
	struct wg_peer *wgp;
	bool ok;

	/*
	 * II CRYPTOKEY ROUTING
	 * "it will only accept it if its source IP resolves in the table to the
	 *  public key used in the secure session for decrypting it."
	 */

	if (af == AF_INET) {
		struct ip *ip = (struct ip *)packet;
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		sockaddr_in_init(sin, &ip->ip_src, 0);
		sa = sintosa(sin);
#ifdef INET6
	} else {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		sockaddr_in6_init(sin6, &ip6->ip6_src, 0, 0, 0);
		sa = sin6tosa(sin6);
#endif
	}

	wgp = wg_pick_peer_by_sa(wg, sa);
	ok = (wgp == wgp_expected);
	if (wgp != NULL)
		wg_put_peer(wgp);

	return ok;
}

static bool
wg_need_to_send_init_message(struct wg_session *wgs)
{
	/*
	 * [W] 6.2 Transport Message Limits
	 * "if a peer is the initiator of a current secure session,
	 *  WireGuard will send a handshake initiation message to begin
	 *  a new secure session ... if after receiving a transport data
	 *  message, the current secure session is (REJECT-AFTER-TIME --
	 *  KEEPALIVE-TIMEOUT -- REKEY-TIMEOUT) seconds old and it has
	 *  not yet acted upon this event."
	 */
	return wgs->wgs_is_initiator && wgs->wgs_time_last_data_sent == 0 &&
	    (time_uptime - wgs->wgs_time_established) >=
	    (wg_reject_after_time - wg_keepalive_timeout - wg_rekey_timeout);
}

static void
wg_schedule_peer_task(struct wg_peer *wgp, int task)
{

#ifdef notyet
	atomic_or_uint(&wgp->wgp_tasks, task);
	WG_DLOG("tasks=%d, task=%d\n", wgp->wgp_tasks, task);
	wg_wakeup_worker(wgp->wgp_sc->wg_worker, WG_WAKEUP_REASON_PEER);
#else
	panic("XXX");
#endif
}

static void
wg_session_dtor_timer(void *arg)
{
	struct wg_peer *wgp = arg;

	WG_TRACE("enter");

	mutex_enter(wgp->wgp_lock);
	if (__predict_false(wgp->wgp_state == WGP_STATE_DESTROYING)) {
		mutex_exit(wgp->wgp_lock);
		return;
	}
	mutex_exit(wgp->wgp_lock);

	wg_schedule_peer_task(wgp, WGP_TASK_DESTROY_PREV_SESSION);
}

static void
wg_schedule_session_dtor_timer(struct wg_peer *wgp)
{

	/* 1 second grace period */
	callout_schedule(&wgp->wgp_session_dtor_timer, hz);
}

static void
wg_stop_session_dtor_timer(struct wg_peer *wgp)
{

	callout_stop(&wgp->wgp_session_dtor_timer);
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

static void
wg_stop_handshake_timeout_timer(struct wg_peer *wgp)
{

   callout_stop(&wgp->wgp_handshake_timeout_timer);
}


static void
wg_schedule_rekey_timer(struct wg_peer *wgp)
{
	int timeout = wg_rekey_after_time;

	callout_schedule(&wgp->wgp_rekey_timer, timeout * hz);
}

static struct socket *
wg_get_so_by_af(struct wg_worker *wgw, const int af)
{

	return (af == AF_INET) ? wgw->wgw_so4 : wgw->wgw_so6;
}

static int
sockaddr_cmp(const struct sockaddr *sa1, const struct sockaddr *sa2)
{

	panic("XXX");
	return (0);
}

static bool
sockaddr_port_match(const struct sockaddr *sa1, const struct sockaddr *sa2)
{
	if (sa1->sa_family != sa2->sa_family)
		return false;

	switch (sa1->sa_family) {
	case AF_INET:
		return satocsin(sa1)->sin_port == satocsin(sa2)->sin_port;
	case AF_INET6:
		return satocsin6(sa1)->sin6_port == satocsin6(sa2)->sin6_port;
	default:
		return true;
	}
}

static void
wg_change_endpoint(struct wg_peer *wgp, const struct sockaddr *new)
{

#ifdef notyet
	mtx_assert(&wgp->wgp_lock, MA_OWNED);
	
	WG_TRACE("Changing endpoint");

	memcpy(wgp->wgp_endpoint0, new, new->sa_len);
	wgp->wgp_endpoint0 = atomic_swap_ptr((volatile uintptr_t *)&wgp->wgp_endpoint,
	    (uintptr_t)wgp->wgp_endpoint0);
	if (!wgp->wgp_endpoint_available)
		wgp->wgp_endpoint_available = true;
	wgp->wgp_endpoint_changing = true;
	wg_schedule_peer_task(wgp, WGP_TASK_ENDPOINT_CHANGED);
#else
	panic("XXX");
#endif
}

static void
wg_swap_sessions(struct wg_peer *wgp)
{
#ifdef notyet
	KASSERT(mutex_owned(wgp->wgp_lock));

	wgp->wgp_session_unstable = atomic_swap_ptr(&wgp->wgp_session_stable,
	    wgp->wgp_session_unstable);
	KASSERT(wgp->wgp_session_stable->wgs_state == WGS_STATE_ESTABLISHED);
#else
	panic("XXX");
#endif
}

static void
wg_update_endpoint_if_necessary(struct wg_peer *wgp,
    const struct sockaddr *src)
{

#ifdef WG_DEBUG_LOG
	char oldaddr[128], newaddr[128];
	sockaddr_format(&wgp->wgp_sa, oldaddr, sizeof(oldaddr));
	sockaddr_format(src, newaddr, sizeof(newaddr));
	WG_DLOG("old=%s, new=%s\n", oldaddr, newaddr);
#endif

	/*
	 * III: "Since the packet has authenticated correctly, the source IP of
	 * the outer UDP/IP packet is used to update the endpoint for peer..."
	 */
	if (__predict_false(sockaddr_cmp(src, &wgp->wgp_sa) != 0 ||
	                    !sockaddr_port_match(src, &wgp->wgp_sa))) {
		mutex_enter(wgp->wgp_lock);
		/* XXX We can't change the endpoint twice in a short period */
		if (!wgp->wgp_endpoint_changing) {
			wg_change_endpoint(wgp, src);
		}
		mutex_exit(wgp->wgp_lock);
	}
}

static bool
wg_is_underload(struct wg_softc *wg, struct wg_peer *wgp, int msgtype)
{
#if 0
#ifdef WG_DEBUG_PARAMS
	if (wg_force_underload)
		return true;
#endif

	/*
	 * XXX we don't have a means of a load estimation.  The purpose of
	 * the mechanism is a DoS mitigation, so we consider frequent handshake
	 * messages as (a kind of) load; if a message of the same type comes
	 * to a peer within 1 second, we consider we are under load.
	 */
	time_t last = wgp->wgp_last_msg_received_time[msgtype];
	wgp->wgp_last_msg_received_time[msgtype] = time_uptime;
	return (time_uptime - last) == 0;
#endif
	return false;
}



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
1 */
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

static void
wg_fill_msg_cookie(struct wg_softc *wg, struct wg_peer *wgp,
    struct wg_msg_cookie *wgmc, const uint32_t sender,
    const uint8_t mac1[WG_MAC_LEN], const struct sockaddr *src)
{
	uint8_t cookie[WG_COOKIE_LEN];
	uint8_t key[WG_HASH_LEN];
	uint8_t addr[sizeof(struct in6_addr)];
	size_t addrlen;
	uint16_t uh_sport; /* be */

	wgmc->wgmc_type = WG_MSG_TYPE_COOKIE;
	wgmc->wgmc_receiver = sender;
	cprng_fast(wgmc->wgmc_salt, sizeof(wgmc->wgmc_salt));

	/*
	 * [W] 5.4.7: Under Load: Cookie Reply Message
	 * "The secret variable, Rm , changes every two minutes to a random value"
	 */
	if ((time_uptime - wgp->wgp_last_genrandval_time) > WG_RANDVAL_TIME) {
		wgp->wgp_randval = cprng_strong32();
		wgp->wgp_last_genrandval_time = time_uptime;
	}

	switch (src->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = satocsin(src);
		addrlen = sizeof(sin->sin_addr);
		memcpy(addr, &sin->sin_addr, addrlen);
		uh_sport = sin->sin_port;
		break;
	    }
#ifdef INET6
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 = satocsin6(src);
		addrlen = sizeof(sin6->sin6_addr);
		memcpy(addr, &sin6->sin6_addr, addrlen);
		uh_sport = sin6->sin6_port;
		break;
	    }
#endif
	default:
		panic("invalid af=%d", wgp->wgp_sa.sa_family);
	}

	wg_algo_mac(cookie, sizeof(cookie),
	    (uint8_t *)&wgp->wgp_randval, sizeof(wgp->wgp_randval),
	    addr, addrlen, (uint8_t *)&uh_sport, sizeof(uh_sport));
	wg_algo_mac_cookie(key, sizeof(key), wg->wg_pubkey,
	    sizeof(wg->wg_pubkey));
	wg_algo_xaead_enc(wgmc->wgmc_cookie, sizeof(wgmc->wgmc_cookie), key,
	    cookie, sizeof(cookie), mac1, WG_MAC_LEN, wgmc->wgmc_salt);

	/* Need to store to calculate mac2 */
	memcpy(wgp->wgp_last_sent_cookie, cookie, sizeof(cookie));
	wgp->wgp_last_sent_cookie_valid = true;
}

static int
wg_send_cookie_msg(struct wg_softc *wg, struct wg_peer *wgp,
    const uint32_t sender, const uint8_t mac1[WG_MAC_LEN],
    const struct sockaddr *src)
{
	int error;
	struct mbuf *m;
	struct wg_msg_cookie *wgmc;

	m = m_gethdr(M_WAITOK, MT_DATA);
	m->m_pkthdr.len = m->m_len = sizeof(*wgmc);
	wgmc = mtod(m, struct wg_msg_cookie *);
	wg_fill_msg_cookie(wg, wgp, wgmc, sender, mac1, src);

	error = wg->wg_ops->send_hs_msg(wgp, m);
	if (error == 0)
		WG_TRACE("cookie msg sent");
	return error;
}

static void
wg_fill_msg_resp(struct wg_softc *wg, struct wg_peer *wgp,
    struct wg_msg_resp *wgmr, const struct wg_msg_init *wgmi)
{
	uint8_t ckey[WG_CHAINING_KEY_LEN]; /* [W] 5.4.3: Cr */
	uint8_t hash[WG_HASH_LEN]; /* [W] 5.4.3: Hr */
	uint8_t cipher_key[WG_KDF_OUTPUT_LEN];
	uint8_t pubkey[WG_EPHEMERAL_KEY_LEN];
	uint8_t privkey[WG_EPHEMERAL_KEY_LEN];
	struct wg_session *wgs;

	wgs = wg_get_unstable_session(wgp);
	memcpy(hash, wgs->wgs_handshake_hash, sizeof(hash));
	memcpy(ckey, wgs->wgs_chaining_key, sizeof(ckey));

	wgmr->wgmr_type = WG_MSG_TYPE_RESP;
	wgmr->wgmr_sender = cprng_strong32();
	wgmr->wgmr_receiver = wgmi->wgmi_sender;

	/* [W] 5.4.3 Second Message: Responder to Initiator */

	/* [N] 2.2: "e" */
	/* Er^priv, Er^pub := DH-GENERATE() */
	wg_algo_generate_keypair(pubkey, privkey);
	/* Cr := KDF1(Cr, Er^pub) */
	wg_algo_kdf(ckey, NULL, NULL, ckey, pubkey, sizeof(pubkey));
	/* msg.ephemeral := Er^pub */
	memcpy(wgmr->wgmr_ephemeral, pubkey, sizeof(wgmr->wgmr_ephemeral));
	/* Hr := HASH(Hr || msg.ephemeral) */
	wg_algo_hash(hash, pubkey, sizeof(pubkey));

	WG_DUMP_HASH("ckey", ckey);
	WG_DUMP_HASH("hash", hash);

	/* [N] 2.2: "ee" */
	/* Cr := KDF1(Cr, DH(Er^priv, Ei^pub)) */
	wg_algo_dh_kdf(ckey, NULL, privkey, wgs->wgs_ephemeral_key_peer);

	/* [N] 2.2: "se" */
	/* Cr := KDF1(Cr, DH(Er^priv, Si^pub)) */
	wg_algo_dh_kdf(ckey, NULL, privkey, wgp->wgp_pubkey);

	/* [N] 9.2: "psk" */
    {
	uint8_t kdfout[WG_KDF_OUTPUT_LEN];
	/* Cr, r, k := KDF3(Cr, Q) */
	wg_algo_kdf(ckey, kdfout, cipher_key, ckey, wgp->wgp_psk,
	    sizeof(wgp->wgp_psk));
	/* Hr := HASH(Hr || r) */
	wg_algo_hash(hash, kdfout, sizeof(kdfout));
    }

	/* msg.empty := AEAD(k, 0, e, Hr) */
	wg_algo_aead_enc(wgmr->wgmr_empty, sizeof(wgmr->wgmr_empty), cipher_key,
	    0, NULL, 0, hash, sizeof(hash));
	/* Hr := HASH(Hr || msg.empty) */
	wg_algo_hash(hash, wgmr->wgmr_empty, sizeof(wgmr->wgmr_empty));

	WG_DUMP_HASH("wgmr_empty", wgmr->wgmr_empty);

	/* [W] 5.4.4: Cookie MACs */
	/* msg.mac1 := MAC(HASH(LABEL-MAC1 || Sm'^pub), msg_a) */
	wg_algo_mac_mac1(wgmr->wgmr_mac1, sizeof(wgmi->wgmi_mac1),
	    wgp->wgp_pubkey, sizeof(wgp->wgp_pubkey),
	    (uint8_t *)wgmr, offsetof(struct wg_msg_resp, wgmr_mac1));
	/* Need mac1 to decrypt a cookie from a cookie message */
	memcpy(wgp->wgp_last_sent_mac1, wgmr->wgmr_mac1,
	    sizeof(wgp->wgp_last_sent_mac1));
	wgp->wgp_last_sent_mac1_valid = true;

	if (wgp->wgp_latest_cookie_time == 0 ||
	    (time_uptime - wgp->wgp_latest_cookie_time) >= WG_COOKIE_TIME)
		/* msg.mac2 := 0^16 */
		memset(wgmr->wgmr_mac2, 0, sizeof(wgmr->wgmr_mac2));
	else {
		/* msg.mac2 := MAC(Lm, msg_b) */
		wg_algo_mac(wgmr->wgmr_mac2, sizeof(wgmi->wgmi_mac2),
		    wgp->wgp_latest_cookie, WG_COOKIE_LEN,
		    (uint8_t *)wgmr, offsetof(struct wg_msg_resp, wgmr_mac2),
		    NULL, 0);
	}

	memcpy(wgs->wgs_handshake_hash, hash, sizeof(hash));
	memcpy(wgs->wgs_chaining_key, ckey, sizeof(ckey));
	memcpy(wgs->wgs_ephemeral_key_pub, pubkey, sizeof(pubkey));
	memcpy(wgs->wgs_ephemeral_key_priv, privkey, sizeof(privkey));
	wgs->wgs_sender_index = wgmr->wgmr_sender;
	wgs->wgs_receiver_index = wgmi->wgmi_sender;
	WG_DLOG("sender=%x\n", wgs->wgs_sender_index);
	WG_DLOG("receiver=%x\n", wgs->wgs_receiver_index);
	wg_put_session(wgs);
}

static int
wg_send_handshake_msg_resp(struct wg_softc *wg, struct wg_peer *wgp,
    const struct wg_msg_init *wgmi)
{
	int error;
	struct mbuf *m;
	struct wg_msg_resp *wgmr;

	m = m_gethdr(M_WAITOK, MT_DATA);
	m->m_pkthdr.len = m->m_len = sizeof(*wgmr);
	wgmr = mtod(m, struct wg_msg_resp *);
	wg_fill_msg_resp(wg, wgp, wgmr, wgmi);

	error = wg->wg_ops->send_hs_msg(wgp, m);
	if (error == 0)
		WG_TRACE("resp msg sent");
	return error;
}

static void
wg_handle_msg_init(struct wg_softc *wg, const struct wg_msg_init *wgmi,
    const struct sockaddr *src)
{
	uint8_t ckey[WG_CHAINING_KEY_LEN]; /* [W] 5.4.2: Ci */
	uint8_t hash[WG_HASH_LEN]; /* [W] 5.4.2: Hi */
	uint8_t cipher_key[WG_CIPHER_KEY_LEN];
	uint8_t peer_pubkey[WG_STATIC_KEY_LEN];
	struct wg_peer *wgp;
	struct wg_session *wgs;
	bool reset_state_on_error = false;
	int error, ret;
	uint8_t mac1[WG_MAC_LEN];

	WG_TRACE("init msg received");

	/*
	 * [W] 5.4.2: First Message: Initiator to Responder
	 * "When the responder receives this message, it does the same
	 *  operations so that its final state variables are identical,
	 *  replacing the operands of the DH function to produce equivalent
	 *  values."
	 *  Note that the following comments of operations are just copies of
	 *  the initiator's ones.
	 */

	/* Ci := HASH(CONSTRUCTION) */
	/* Hi := HASH(Ci || IDENTIFIER) */
	wg_init_key_and_hash(ckey, hash);
	/* Hi := HASH(Hi || Sr^pub) */
	wg_algo_hash(hash, wg->wg_pubkey, sizeof(wg->wg_pubkey));

	/* [N] 2.2: "e" */
	/* Ci := KDF1(Ci, Ei^pub) */
	wg_algo_kdf(ckey, NULL, NULL, ckey, wgmi->wgmi_ephemeral,
	    sizeof(wgmi->wgmi_ephemeral));
	/* Hi := HASH(Hi || msg.ephemeral) */
	wg_algo_hash(hash, wgmi->wgmi_ephemeral, sizeof(wgmi->wgmi_ephemeral));

	WG_DUMP_HASH("ckey", ckey);

	/* [N] 2.2: "es" */
	/* Ci, k := KDF2(Ci, DH(Ei^priv, Sr^pub)) */
	wg_algo_dh_kdf(ckey, cipher_key, wg->wg_privkey, wgmi->wgmi_ephemeral);

	WG_DUMP_HASH48("wgmi_static", wgmi->wgmi_static);

	/* [N] 2.2: "s" */
	/* msg.static := AEAD(k, 0, Si^pub, Hi) */
	error = wg_algo_aead_dec(peer_pubkey, WG_STATIC_KEY_LEN, cipher_key, 0,
	    wgmi->wgmi_static, sizeof(wgmi->wgmi_static), hash, sizeof(hash));
	if (error != 0) {
		WG_LOG_RATECHECK(&wg->wg_ppsratecheck, LOG_DEBUG,
		    "wg_algo_aead_dec for secret key failed\n");
		return;
	}
	/* Hi := HASH(Hi || msg.static) */
	wg_algo_hash(hash, wgmi->wgmi_static, sizeof(wgmi->wgmi_static));

	wgp = wg_lookup_peer_by_pubkey(wg, peer_pubkey);
	if (wgp == NULL) {
		WG_DLOG("peer not found\n");
		return;
	}

	wgs = wg_lock_unstable_session(wgp);
	if (wgs->wgs_state == WGS_STATE_DESTROYING) {
		/*
		 * We can assume that the peer doesn't have an established
		 * session, so clear it now.
		 */
		WG_TRACE("Session destroying, but force to clear");
		wg_stop_session_dtor_timer(wgp);
		wg_clear_states(wgs);
		wgs->wgs_state = WGS_STATE_UNKNOWN;
	}
	if (wgs->wgs_state == WGS_STATE_INIT_ACTIVE) {
		WG_TRACE("Sesssion already initializing, ignoring the message");
		mutex_exit(wgs->wgs_lock);
		goto out_wgp;
	}
	if (wgs->wgs_state == WGS_STATE_INIT_PASSIVE) {
		WG_TRACE("Sesssion already initializing, destroying old states");
		wg_clear_states(wgs);
	}
	wgs->wgs_state = WGS_STATE_INIT_PASSIVE;
	reset_state_on_error = true;
	wg_get_session(wgs);
	mutex_exit(wgs->wgs_lock);

	wg_algo_mac_mac1(mac1, sizeof(mac1),
	    wg->wg_pubkey, sizeof(wg->wg_pubkey),
	    (const uint8_t *)wgmi, offsetof(struct wg_msg_init, wgmi_mac1));

	/*
	 * [W] 5.3: Denial of Service Mitigation & Cookies
	 * "the responder, ..., must always reject messages with an invalid
	 *  msg.mac1"
	 */
	if (memcmp(mac1, wgmi->wgmi_mac1, sizeof(mac1)) != 0) {
		WG_DLOG("mac1 is invalid\n");
		goto out;
	}

	if (__predict_false(wg_is_underload(wg, wgp, WG_MSG_TYPE_INIT))) {
		WG_TRACE("under load");
		/*
		 * [W] 5.3: Denial of Service Mitigation & Cookies
		 * "the responder, ..., and when under load may reject messages
		 *  with an invalid msg.mac2.  If the responder receives a
		 *  message with a valid msg.mac1 yet with an invalid msg.mac2,
		 *  and is under load, it may respond with a cookie reply
		 *  message"
		 */
		uint8_t zero[WG_MAC_LEN] = {0};
		if (memcmp(wgmi->wgmi_mac2, zero, sizeof(zero)) == 0) {
			WG_TRACE("sending a cookie message: no cookie included");
			(void)wg_send_cookie_msg(wg, wgp, wgmi->wgmi_sender,
			    wgmi->wgmi_mac1, src);
			goto out;
		}
		if (!wgp->wgp_last_sent_cookie_valid) {
			WG_TRACE("sending a cookie message: no cookie sent ever");
			(void)wg_send_cookie_msg(wg, wgp, wgmi->wgmi_sender,
			    wgmi->wgmi_mac1, src);
			goto out;
		}
		uint8_t mac2[WG_MAC_LEN];
		wg_algo_mac(mac2, sizeof(mac2), wgp->wgp_last_sent_cookie,
		    WG_COOKIE_LEN, (const uint8_t *)wgmi,
		    offsetof(struct wg_msg_init, wgmi_mac2), NULL, 0);
		if (memcmp(mac2, wgmi->wgmi_mac2, sizeof(mac2)) != 0) {
			WG_DLOG("mac2 is invalid\n");
			goto out;
		}
		WG_TRACE("under load, but continue to sending");
	}

	/* [N] 2.2: "ss" */
	/* Ci, k := KDF2(Ci, DH(Si^priv, Sr^pub)) */
	wg_algo_dh_kdf(ckey, cipher_key, wg->wg_privkey, wgp->wgp_pubkey);

	/* msg.timestamp := AEAD(k, TIMESTAMP(), Hi) */
	wg_timestamp_t timestamp;
	error = wg_algo_aead_dec(timestamp, sizeof(timestamp), cipher_key, 0,
	    wgmi->wgmi_timestamp, sizeof(wgmi->wgmi_timestamp),
	    hash, sizeof(hash));
	if (error != 0) {
		WG_LOG_RATECHECK(&wgp->wgp_ppsratecheck, LOG_DEBUG,
		    "wg_algo_aead_dec for timestamp failed\n");
		goto out;
	}
	/* Hi := HASH(Hi || msg.timestamp) */
	wg_algo_hash(hash, wgmi->wgmi_timestamp, sizeof(wgmi->wgmi_timestamp));

	/*
	 * [W] 5.1 "The responder keeps track of the greatest timestamp received per
	 *      peer and discards packets containing timestamps less than or
	 *      equal to it."
	 */
	ret = memcmp(timestamp, wgp->wgp_timestamp_latest_init,
	    sizeof(timestamp));
	if (ret <= 0) {
		WG_LOG_RATECHECK(&wgp->wgp_ppsratecheck, LOG_DEBUG,
		    "invalid init msg: timestamp is old\n");
		goto out;
	}
	memcpy(wgp->wgp_timestamp_latest_init, timestamp, sizeof(timestamp));

	memcpy(wgs->wgs_handshake_hash, hash, sizeof(hash));
	memcpy(wgs->wgs_chaining_key, ckey, sizeof(ckey));
	memcpy(wgs->wgs_ephemeral_key_peer, wgmi->wgmi_ephemeral,
	    sizeof(wgmi->wgmi_ephemeral));

	wg_update_endpoint_if_necessary(wgp, src);

	(void)wg_send_handshake_msg_resp(wg, wgp, wgmi);

	wg_calculate_keys(wgs, false);
	wg_clear_states(wgs);

	wg_put_session(wgs);
	wg_put_peer(wgp);
	return;

out:
	if (reset_state_on_error) {
		mutex_enter(wgs->wgs_lock);
		MPASS(wgs->wgs_state == WGS_STATE_INIT_PASSIVE);
		wgs->wgs_state = WGS_STATE_UNKNOWN;
		mutex_exit(wgs->wgs_lock);
	}
	wg_put_session(wgs);
out_wgp:
	wg_put_peer(wgp);
}


static void
wg_handle_msg_cookie(struct wg_softc *wg, const struct wg_msg_cookie *wgmc)
{
	struct wg_session *wgs;
	struct wg_peer *wgp;
	int error;
	uint8_t key[WG_HASH_LEN];
	uint8_t cookie[WG_COOKIE_LEN];

	WG_TRACE("cookie msg received");
	wgs = wg_lookup_session_by_index(wg, wgmc->wgmc_receiver);
	if (wgs == NULL) {
		WG_TRACE("No session found");
		return;
	}
	wgp = wgs->wgs_peer;

	if (!wgp->wgp_last_sent_mac1_valid) {
		WG_TRACE("No valid mac1 sent (or expired)");
		goto out;
	}

	wg_algo_mac_cookie(key, sizeof(key), wgp->wgp_pubkey,
	    sizeof(wgp->wgp_pubkey));
	error = wg_algo_xaead_dec(cookie, sizeof(cookie), key, 0,
	    wgmc->wgmc_cookie, sizeof(wgmc->wgmc_cookie),
	    wgp->wgp_last_sent_mac1, sizeof(wgp->wgp_last_sent_mac1),
	    wgmc->wgmc_salt);
	if (error != 0) {
		WG_LOG_RATECHECK(&wgp->wgp_ppsratecheck, LOG_DEBUG,
		    "wg_algo_aead_dec for cookie failed: error=%d\n", error);
		goto out;
	}
	/*
	 * [W] 6.6: Interaction with Cookie Reply System
	 * "it should simply store the decrypted cookie value from the cookie
	 *  reply message, and wait for the expiration of the REKEY-TIMEOUT
	 *  timer for retrying a handshake initiation message."
	 */
	wgp->wgp_latest_cookie_time = time_uptime;
	memcpy(wgp->wgp_latest_cookie, cookie, sizeof(wgp->wgp_latest_cookie));
out:
	wg_put_session(wgs);
}

static void
wg_handle_msg_resp(struct wg_softc *wg, const struct wg_msg_resp *wgmr,
    const struct sockaddr *src)
{
	uint8_t ckey[WG_CHAINING_KEY_LEN]; /* [W] 5.4.3: Cr */
	uint8_t hash[WG_HASH_LEN]; /* [W] 5.4.3: Kr */
	uint8_t cipher_key[WG_KDF_OUTPUT_LEN];
	struct wg_peer *wgp;
	struct wg_session *wgs;
	int error;
	uint8_t mac1[WG_MAC_LEN];
	struct wg_session *wgs_prev;

	WG_TRACE("resp msg received");
	wgs = wg_lookup_session_by_index(wg, wgmr->wgmr_receiver);
	if (wgs == NULL) {
		WG_TRACE("No session found");
		return;
	}

	wgp = wgs->wgs_peer;

	wg_algo_mac_mac1(mac1, sizeof(mac1),
	    wg->wg_pubkey, sizeof(wg->wg_pubkey),
	    (const uint8_t *)wgmr, offsetof(struct wg_msg_resp, wgmr_mac1));

	/*
	 * [W] 5.3: Denial of Service Mitigation & Cookies
	 * "the responder, ..., must always reject messages with an invalid
	 *  msg.mac1"
	 */
	if (memcmp(mac1, wgmr->wgmr_mac1, sizeof(mac1)) != 0) {
		WG_DLOG("mac1 is invalid\n");
		goto out;
	}

	if (__predict_false(wg_is_underload(wg, wgp, WG_MSG_TYPE_RESP))) {
		WG_TRACE("under load");
		/*
		 * [W] 5.3: Denial of Service Mitigation & Cookies
		 * "the responder, ..., and when under load may reject messages
		 *  with an invalid msg.mac2.  If the responder receives a
		 *  message with a valid msg.mac1 yet with an invalid msg.mac2,
		 *  and is under load, it may respond with a cookie reply
		 *  message"
		 */
		uint8_t zero[WG_MAC_LEN] = {0};
		if (memcmp(wgmr->wgmr_mac2, zero, sizeof(zero)) == 0) {
			WG_TRACE("sending a cookie message: no cookie included");
			(void)wg_send_cookie_msg(wg, wgp, wgmr->wgmr_sender,
			    wgmr->wgmr_mac1, src);
			goto out;
		}
		if (!wgp->wgp_last_sent_cookie_valid) {
			WG_TRACE("sending a cookie message: no cookie sent ever");
			(void)wg_send_cookie_msg(wg, wgp, wgmr->wgmr_sender,
			    wgmr->wgmr_mac1, src);
			goto out;
		}
		uint8_t mac2[WG_MAC_LEN];
		wg_algo_mac(mac2, sizeof(mac2), wgp->wgp_last_sent_cookie,
		    WG_COOKIE_LEN, (const uint8_t *)wgmr,
		    offsetof(struct wg_msg_resp, wgmr_mac2), NULL, 0);
		if (memcmp(mac2, wgmr->wgmr_mac2, sizeof(mac2)) != 0) {
			WG_DLOG("mac2 is invalid\n");
			goto out;
		}
		WG_TRACE("under load, but continue to sending");
	}

	memcpy(hash, wgs->wgs_handshake_hash, sizeof(hash));
	memcpy(ckey, wgs->wgs_chaining_key, sizeof(ckey));

	/*
	 * [W] 5.4.3 Second Message: Responder to Initiator
	 * "When the initiator receives this message, it does the same
	 *  operations so that its final state variables are identical,
	 *  replacing the operands of the DH function to produce equivalent
	 *  values."
	 *  Note that the following comments of operations are just copies of
	 *  the initiator's ones.
	 */

	/* [N] 2.2: "e" */
	/* Cr := KDF1(Cr, Er^pub) */
	wg_algo_kdf(ckey, NULL, NULL, ckey, wgmr->wgmr_ephemeral,
	    sizeof(wgmr->wgmr_ephemeral));
	/* Hr := HASH(Hr || msg.ephemeral) */
	wg_algo_hash(hash, wgmr->wgmr_ephemeral, sizeof(wgmr->wgmr_ephemeral));

	WG_DUMP_HASH("ckey", ckey);
	WG_DUMP_HASH("hash", hash);

	/* [N] 2.2: "ee" */
	/* Cr := KDF1(Cr, DH(Er^priv, Ei^pub)) */
	wg_algo_dh_kdf(ckey, NULL, wgs->wgs_ephemeral_key_priv,
	    wgmr->wgmr_ephemeral);

	/* [N] 2.2: "se" */
	/* Cr := KDF1(Cr, DH(Er^priv, Si^pub)) */
	wg_algo_dh_kdf(ckey, NULL, wg->wg_privkey, wgmr->wgmr_ephemeral);

	/* [N] 9.2: "psk" */
    {
	uint8_t kdfout[WG_KDF_OUTPUT_LEN];
	/* Cr, r, k := KDF3(Cr, Q) */
	wg_algo_kdf(ckey, kdfout, cipher_key, ckey, wgp->wgp_psk,
	    sizeof(wgp->wgp_psk));
	/* Hr := HASH(Hr || r) */
	wg_algo_hash(hash, kdfout, sizeof(kdfout));
    }

    {
	uint8_t out[sizeof(wgmr->wgmr_empty)]; /* for safety */
	/* msg.empty := AEAD(k, 0, e, Hr) */
	error = wg_algo_aead_dec(out, 0, cipher_key, 0, wgmr->wgmr_empty,
	    sizeof(wgmr->wgmr_empty), hash, sizeof(hash));
	WG_DUMP_HASH("wgmr_empty", wgmr->wgmr_empty);
	if (error != 0) {
		WG_LOG_RATECHECK(&wgp->wgp_ppsratecheck, LOG_DEBUG,
		    "wg_algo_aead_dec for empty message failed\n");
		goto out;
	}
	/* Hr := HASH(Hr || msg.empty) */
	wg_algo_hash(hash, wgmr->wgmr_empty, sizeof(wgmr->wgmr_empty));
    }

	memcpy(wgs->wgs_handshake_hash, hash, sizeof(wgs->wgs_handshake_hash));
	memcpy(wgs->wgs_chaining_key, ckey, sizeof(wgs->wgs_chaining_key));
	wgs->wgs_receiver_index = wgmr->wgmr_sender;
	WG_DLOG("receiver=%x\n", wgs->wgs_receiver_index);

	wgs->wgs_state = WGS_STATE_ESTABLISHED;
	wgs->wgs_time_established = time_uptime;
	wgs->wgs_time_last_data_sent = 0;
	wgs->wgs_is_initiator = true;
	wg_calculate_keys(wgs, true);
	wg_clear_states(wgs);
	WG_TRACE("WGS_STATE_ESTABLISHED");

	mutex_enter(wgp->wgp_lock);
	wg_swap_sessions(wgp);
	wgs_prev = wgp->wgp_session_unstable;
	mutex_enter(wgs_prev->wgs_lock);

	getnanotime(&wgp->wgp_last_handshake_time);
	wg_stop_handshake_timeout_timer(wgp);
	wgp->wgp_handshake_start_time = 0;
	wgp->wgp_last_sent_mac1_valid = false;
	wgp->wgp_last_sent_cookie_valid = false;
	mutex_exit(wgp->wgp_lock);

	wg_schedule_rekey_timer(wgp);

	wg_update_endpoint_if_necessary(wgp, src);

	/*
	 * Send something immediately (same as the official implementation)
	 * XXX if there are pending data packets, we don't need to send
	 *     a keepalive message.
	 */
	wg_send_keepalive_msg(wgp, wgs);

#if 0
	/* Anyway run a softint to flush pending packets */
	kpreempt_disable();
	softint_schedule(wgp->wgp_si);
	kpreempt_enable();
	WG_TRACE("softint scheduled");
#endif
	if (wgs_prev->wgs_state == WGS_STATE_ESTABLISHED) {
		wgs_prev->wgs_state = WGS_STATE_DESTROYING;
		/* We can't destroy the old session immediately */
		wg_schedule_session_dtor_timer(wgp);
	}
	mutex_exit(wgs_prev->wgs_lock);

out:
	wg_put_session(wgs);
}

static void
wg_handle_msg_data(struct wg_softc *wg, struct mbuf *m,
    const struct sockaddr *src)
{
	struct wg_msg_data *wgmd;
	char *encrypted_buf = NULL, *decrypted_buf;
	size_t encrypted_len, decrypted_len;
	struct wg_session *wgs;
	struct wg_peer *wgp;
	size_t mlen;
	int error, af;
	bool free_encrypted_buf = false, ok;
	struct mbuf *n;

	if (m->m_len < sizeof(struct wg_msg_data)) {
		m = m_pullup(m, sizeof(struct wg_msg_data));
		if (m == NULL)
			return;
	}
	wgmd = mtod(m, struct wg_msg_data *);

	//KASSERT(wgmd->wgmd_type == WG_MSG_TYPE_DATA);
	WG_TRACE("data");

	wgs = wg_lookup_session_by_index(wg, wgmd->wgmd_receiver);
	if (wgs == NULL) {
		WG_TRACE("No session found");
		m_freem(m);
		return;
	}
	wgp = wgs->wgs_peer;

	mlen = m_length(m, NULL);
	encrypted_len = mlen - sizeof(*wgmd);

	if (encrypted_len < WG_AUTHTAG_LEN) {
		WG_DLOG("Short encrypted_len: %lu\n", encrypted_len);
		goto out;
	}

	n = m_pullup(m, sizeof(*wgmd) + encrypted_len);
	if (n != NULL) {
		m = n;
		encrypted_buf = mtod(m, char *) + sizeof(*wgmd);
	} else {
		encrypted_buf = malloc(encrypted_len, M_WG, M_NOWAIT);
		if (encrypted_buf == NULL) {
			WG_DLOG("failed to allocate encrypted_buf\n");
			goto out;
		}
		m_copydata(m, sizeof(*wgmd), encrypted_len, encrypted_buf);
		free_encrypted_buf = true;
	}
	/* m_ensure_contig may change m regardless of its result */
	wgmd = mtod(m, struct wg_msg_data *);

	decrypted_len = encrypted_len - WG_AUTHTAG_LEN;
	if (decrypted_len > MCLBYTES) {
		/* FIXME handle larger data than MCLBYTES */
		WG_DLOG("couldn't handle larger data than MCLBYTES\n");
		goto out;
	}

	n = wg_get_mbuf(0, decrypted_len + WG_AUTHTAG_LEN); /* To avoid zero length */
	if (n == NULL) {
		WG_DLOG("wg_get_mbuf failed\n");
		goto out;
	}
	decrypted_buf = mtod(n, char *);

	WG_DLOG("mlen=%lu, encrypted_len=%lu\n", mlen, encrypted_len);
	error = wg_algo_aead_dec(decrypted_buf,
	    encrypted_len - WG_AUTHTAG_LEN /* can be 0 */,
	    wgs->wgs_tkey_recv, wgmd->wgmd_counter, encrypted_buf,
	    encrypted_len, NULL, 0);
	if (error != 0) {
		WG_LOG_RATECHECK(&wgp->wgp_ppsratecheck, LOG_DEBUG,
		    "failed to wg_algo_aead_dec\n");
		m_freem(n);
		goto out;
	}
	WG_DLOG("outsize=%u\n", (u_int)decrypted_len);

	/* TODO deal with reordering with a sliding window */
	if (wgs->wgs_recv_counter != 0 &&
	    wgmd->wgmd_counter <= wgs->wgs_recv_counter) {
		WG_LOG_RATECHECK(&wgp->wgp_ppsratecheck, LOG_DEBUG,
		    "wgmd_counter is equal to or smaller than wgs_recv_counter:"
		    " %"PRIu64" <= %"PRIu64"\n", wgmd->wgmd_counter,
		    wgs->wgs_recv_counter);
		m_freem(n);
		goto out;
	}
	wgs->wgs_recv_counter = wgmd->wgmd_counter;

	m_freem(m);
	m = NULL;
	wgmd = NULL;

	ok = wg_validate_inner_packet(decrypted_buf, decrypted_len, &af);
	if (!ok) {
		/* something wrong... */
		m_freem(n);
		goto out;
	}

	wg_update_endpoint_if_necessary(wgp, src);

	ok = wg_validate_route(wg, wgp, af, decrypted_buf);
	if (ok) {
		wg->wg_ops->input(wg->wg_ctx, n, af);
	} else {
		WG_LOG_RATECHECK(&wgp->wgp_ppsratecheck, LOG_DEBUG,
		    "invalid source address\n");
		m_freem(n);
		/*
		 * The inner address is invalid however the session is valid
		 * so continue the session processing below.
		 */
	}
	n = NULL;

	if (wgs->wgs_state == WGS_STATE_INIT_PASSIVE) {
		struct wg_session *wgs_prev;

		//KASSERT(wgs == wgp->wgp_session_unstable);
		wgs->wgs_state = WGS_STATE_ESTABLISHED;
		wgs->wgs_time_established = time_uptime;
		wgs->wgs_time_last_data_sent = 0;
		wgs->wgs_is_initiator = false;
		WG_TRACE("WGS_STATE_ESTABLISHED");

		mutex_enter(wgp->wgp_lock);
		wg_swap_sessions(wgp);
		wgs_prev = wgp->wgp_session_unstable;
		mutex_enter(wgs_prev->wgs_lock);
		getnanotime(&wgp->wgp_last_handshake_time);
		wgp->wgp_handshake_start_time = 0;
		wgp->wgp_last_sent_mac1_valid = false;
		wgp->wgp_last_sent_cookie_valid = false;
		mutex_exit(wgp->wgp_lock);

		if (wgs_prev->wgs_state == WGS_STATE_ESTABLISHED) {
			wgs_prev->wgs_state = WGS_STATE_DESTROYING;
			/* We can't destroy the old session immediately */
			wg_schedule_session_dtor_timer(wgp);
		} else {
			wg_clear_states(wgs_prev);
			wgs_prev->wgs_state = WGS_STATE_UNKNOWN;
		}
		mutex_exit(wgs_prev->wgs_lock);

#if 0
		/* Anyway run a softint to flush pending packets */
		//KASSERT(cpu_softintr_p());
		softint_schedule(wgp->wgp_si);
#endif
	} else {
		if (__predict_false(wg_need_to_send_init_message(wgs))) {
			wg_schedule_peer_task(wgp, WGP_TASK_SEND_INIT_MESSAGE);
		}
		/*
		 * [W] 6.5 Passive Keepalive
		 * "If a peer has received a validly-authenticated transport
		 *  data message (section 5.4.6), but does not have any packets
		 *  itself to send back for KEEPALIVE-TIMEOUT seconds, it sends
		 *  a keepalive message."
		 */
		WG_DLOG("time_uptime=%lu wgs_time_last_data_sent=%lu\n",
		    time_uptime, wgs->wgs_time_last_data_sent);
		if ((time_uptime - wgs->wgs_time_last_data_sent) >=
		    wg_keepalive_timeout) {
			WG_TRACE("Schedule sending keepalive message");
			/*
			 * We can't send a keepalive message here to avoid
			 * a deadlock;  we already hold the solock of a socket
			 * that is used to send the message.
			 */
			wg_schedule_peer_task(wgp, WGP_TASK_SEND_KEEPALIVE_MESSAGE);
		}
	}
out:
	wg_put_session(wgs);
	if (m != NULL)
		m_freem(m);
	if (free_encrypted_buf)
		free(encrypted_buf, M_WG);
}

static void
wg_handle_packet(struct wg_softc *wg, struct mbuf *m, const struct sockaddr *src)
{
	struct wg_msg *wgm;

	wgm = mtod(m, struct wg_msg *);
	switch (wgm->wgm_type) {
	case WG_MSG_TYPE_INIT:
		wg_handle_msg_init(wg, (struct wg_msg_init *)wgm, src);
		break;
	case WG_MSG_TYPE_RESP:
		wg_handle_msg_resp(wg, (struct wg_msg_resp *)wgm, src);
		break;
	case WG_MSG_TYPE_COOKIE:
		wg_handle_msg_cookie(wg, (struct wg_msg_cookie *)wgm);
		break;
	case WG_MSG_TYPE_DATA:
		wg_handle_msg_data(wg, m, src);
		break;
	default:
		WG_LOG_RATECHECK(&wg->wg_ppsratecheck, LOG_DEBUG,
		    "Unexpected msg type: %u\n", wgm->wgm_type);
		m_freem(m);
		break;
	}
}

static void
wg_receive_packets(struct wg_softc *wg, const int af)
{

	while (true) {
		int error, flags;
		struct socket *so;
		struct mbuf *m = NULL;
		struct uio dummy_uio;
		struct sockaddr *src;

		so = wg_get_so_by_af(wg->wg_worker, af);
		flags = MSG_DONTWAIT;
		dummy_uio.uio_resid = 1000000000;

		//error = so->so_receive(so, &paddr, &dummy_uio, &m, NULL, &flags);
		error = soreceive(so, &src, &dummy_uio, &m, NULL, &flags);
		if (error || m == NULL) {
			//if (error == EWOULDBLOCK)
			return;
		}

		wg_handle_packet(wg, m, src);
	}
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
