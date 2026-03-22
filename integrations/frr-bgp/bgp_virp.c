// SPDX-License-Identifier: Apache-2.0
/*
 * BGP VIRP (Verified Infrastructure Response Protocol) Module
 *
 * Loadable FRR module that hooks BGP events and produces HMAC-signed
 * observations for the VIRP Observation Channel. Follows the same
 * module pattern as bgp_bmp.c (BGP Monitoring Protocol).
 *
 * Architecture:
 *   bgpd ──[hooks]──> bgp_virp.c ──[signed obs]──> O-Node (chain.db)
 *
 * Wire format: canonical packed header (network byte order) + JSON
 * payload + HMAC-SHA256 over serialized header + payload.
 *
 * This module is strictly Observation Channel — it never modifies
 * routing state. All observations are read-only attestations.
 *
 * Copyright (C) 2026 Third Level IT LLC / Nate Howard
 * VIRP Specification: draft-howard-virp-01
 */

#include <zebra.h>

#include "lib/version.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_virp.h"

#include "lib/sockunion.h"
#include "lib/vty.h"
#include "lib/command.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/log.h"
#include "lib/hook.h"
#include "lib/frr_pthread.h"
#include "lib/libfrr.h"

#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

/* Memory type for VIRP allocations */
DEFINE_MTYPE_STATIC(BGPD, VIRP, "BGP VIRP");

#define VIRP_JSON_BUF    VIRP_MAX_PAYLOAD
#define VIRP_ADDR_STRLEN INET6_ADDRSTRLEN

/* Module-global config — single instance */
static struct virp_config virp_cfg = {
	.enabled = false,
	.onode_socket_path = "/tmp/virp-onode.sock",
	.hmac_key_path = "/etc/virp/bgp.key",
	.onode_fd = -1,
	.sequence = 0,
	.producer_id = 0,
	.obs_signed = 0,
	.obs_delivered = 0,
	.obs_build_fail = 0,
	.obs_sign_fail = 0,
	.obs_send_fail = 0,
};

/* ================================================================
 * Byte-order helpers
 * ================================================================ */

static uint64_t virp_hton64(uint64_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return ((uint64_t)htonl((uint32_t)(v >> 32))) |
	       ((uint64_t)htonl((uint32_t)(v & 0xffffffffU)) << 32);
#else
	return v;
#endif
}

/* ================================================================
 * Time
 * ================================================================ */

uint64_t virp_get_time_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;

	return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

/* ================================================================
 * Zeroize
 * ================================================================ */

static void virp_zeroize(void *p, size_t len)
{
	volatile uint8_t *vp = (volatile uint8_t *)p;

	while (len-- > 0)
		*vp++ = 0;
}

/* ================================================================
 * JSON helpers
 * ================================================================ */

size_t virp_json_escape(char *dst, size_t dst_size, const char *src)
{
	size_t di = 0;
	const unsigned char *s = (const unsigned char *)src;

	if (!dst || dst_size == 0)
		return 0;

	if (!src) {
		dst[0] = '\0';
		return 0;
	}

	while (*s && di + 1 < dst_size) {
		unsigned char c = *s++;

		switch (c) {
		case '"':
		case '\\':
			if (di + 2 >= dst_size)
				goto out;
			dst[di++] = '\\';
			dst[di++] = (char)c;
			break;
		case '\n':
			if (di + 2 >= dst_size)
				goto out;
			dst[di++] = '\\';
			dst[di++] = 'n';
			break;
		case '\r':
			if (di + 2 >= dst_size)
				goto out;
			dst[di++] = '\\';
			dst[di++] = 'r';
			break;
		case '\t':
			if (di + 2 >= dst_size)
				goto out;
			dst[di++] = '\\';
			dst[di++] = 't';
			break;
		default:
			if (c < 0x20) {
				if (di + 6 >= dst_size)
					goto out;
				di += snprintf(dst + di, dst_size - di,
					       "\\u%04x", c);
			} else {
				dst[di++] = (char)c;
			}
			break;
		}
	}

out:
	dst[di] = '\0';
	return di;
}

static int virp_json_append(char *buf, size_t buf_sz, size_t *off,
			    const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

static int virp_json_append(char *buf, size_t buf_sz, size_t *off,
			    const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!buf || !off || *off >= buf_sz)
		return -1;

	va_start(ap, fmt);
	n = vsnprintf(buf + *off, buf_sz - *off, fmt, ap);
	va_end(ap);

	if (n < 0)
		return -1;

	if ((size_t)n >= buf_sz - *off) {
		*off = buf_sz;
		return -1;
	}

	*off += (size_t)n;
	return 0;
}

/* ================================================================
 * Address / identity rendering (inet_ntop, no %pI4)
 * ================================================================ */

static int virp_in_addr_to_str(const struct in_addr *addr,
			       char *buf, size_t len)
{
	if (!addr || !buf || len == 0)
		return -1;

	if (!inet_ntop(AF_INET, addr, buf, len))
		return -1;

	return 0;
}

static void virp_peer_identity(struct peer *peer,
			       char *peer_buf, size_t peer_len,
			       char *peer_addr_buf, size_t peer_addr_len)
{
	const char *name = "unknown";
	char peer_addr_raw[VIRP_ADDR_STRLEN];

	if (peer && PEER_HOSTNAME(peer))
		name = PEER_HOSTNAME(peer);

	virp_json_escape(peer_buf, peer_len, name);

	if (peer && peer->connection && peer->connection->su_remote)
		sockunion2str(peer->connection->su_remote, peer_addr_raw,
			      sizeof(peer_addr_raw));
	else
		strlcpy(peer_addr_raw, "0.0.0.0", sizeof(peer_addr_raw));

	virp_json_escape(peer_addr_buf, peer_addr_len, peer_addr_raw);
}

static void virp_router_id_json(const struct bgp *bgp,
				char *out, size_t out_len)
{
	char tmp[VIRP_ADDR_STRLEN];

	if (!bgp || virp_in_addr_to_str(&bgp->router_id, tmp, sizeof(tmp)) != 0)
		strlcpy(tmp, "0.0.0.0", sizeof(tmp));

	virp_json_escape(out, out_len, tmp);
}

static void virp_nexthop_json(const struct attr *attr,
			      char *out, size_t out_len)
{
	char tmp[VIRP_ADDR_STRLEN];

	if (!attr || virp_in_addr_to_str(&attr->nexthop, tmp, sizeof(tmp)) != 0)
		strlcpy(tmp, "0.0.0.0", sizeof(tmp));

	virp_json_escape(out, out_len, tmp);
}

static void virp_aspath_json(const struct attr *attr,
			     char *out, size_t out_len)
{
	const char *aspath = "";

	if (attr && attr->aspath) {
		const char *printed = aspath_print(attr->aspath);
		if (printed)
			aspath = printed;
	}

	virp_json_escape(out, out_len, aspath);
}

/* BGP FSM state names for observation payloads */
static const char *virp_fsm_state_name(enum bgp_fsm_status status)
{
	switch (status) {
	case Idle:        return "Idle";
	case Connect:     return "Connect";
	case Active:      return "Active";
	case OpenSent:    return "OpenSent";
	case OpenConfirm: return "OpenConfirm";
	case Established: return "Established";
	case Clearing:    return "Clearing";
	case Deleted:     return "Deleted";
	default:          return "Unknown";
	}
}

/* ================================================================
 * HMAC Key Loading
 * ================================================================ */

int virp_load_hmac_key(struct virp_config *cfg)
{
	FILE *f;
	size_t nread;

	if (!cfg || !cfg->hmac_key_path[0])
		return -1;

	f = fopen(cfg->hmac_key_path, "rb");
	if (!f) {
		zlog_err("VIRP: cannot open HMAC key file %s: %s",
			 cfg->hmac_key_path, strerror(errno));
		return -1;
	}

	nread = fread(cfg->hmac_key, 1, sizeof(cfg->hmac_key), f);
	fclose(f);

	while (nread > 0 &&
	       (cfg->hmac_key[nread - 1] == '\n' ||
		cfg->hmac_key[nread - 1] == '\r'))
		nread--;

	if (nread < VIRP_MIN_KEY_LEN) {
		zlog_err("VIRP: HMAC key too short after trimming (%zu bytes, minimum %u)",
			 nread, VIRP_MIN_KEY_LEN);
		virp_zeroize(cfg->hmac_key, sizeof(cfg->hmac_key));
		cfg->hmac_key_len = 0;
		return -1;
	}

	cfg->hmac_key_len = nread;
	zlog_info("VIRP: loaded %zu-byte HMAC key from %s",
		  nread, cfg->hmac_key_path);
	return 0;
}

/* ================================================================
 * Record Construction (canonical wire header)
 * ================================================================ */

int virp_record_init(struct virp_record *rec,
		     uint8_t obs_type,
		     uint8_t trust_tier,
		     uint32_t producer_id,
		     uint32_t sequence,
		     uint64_t timestamp_ns,
		     const uint8_t *payload,
		     size_t payload_len)
{
	if (!rec)
		return -1;

	if (payload_len > VIRP_MAX_PAYLOAD)
		return -1;

	memset(rec, 0, sizeof(*rec));

	rec->hdr.magic_be        = htonl(VIRP_MAGIC);
	rec->hdr.version         = VIRP_VERSION;
	rec->hdr.obs_type        = obs_type;
	rec->hdr.trust_tier      = trust_tier;
	rec->hdr.flags           = 0;
	rec->hdr.timestamp_ns_be = virp_hton64(timestamp_ns);
	rec->hdr.sequence_be     = htonl(sequence);
	rec->hdr.payload_len_be  = htonl((uint32_t)payload_len);
	rec->hdr.producer_id_be  = htonl(producer_id);

	rec->payload_len = payload_len;

	if (payload_len > 0 && payload)
		memcpy(rec->payload, payload, payload_len);

	return 0;
}

/* ================================================================
 * Signing — HMAC-SHA256 over serialized wire header + payload
 * ================================================================ */

int virp_sign_record(struct virp_config *cfg, struct virp_record *rec)
{
	HMAC_CTX *ctx = NULL;
	unsigned int hlen = 0;
	int rc = -1;

	if (!cfg || !rec || cfg->hmac_key_len == 0) {
		if (cfg)
			cfg->obs_sign_fail++;
		return -1;
	}

	ctx = HMAC_CTX_new();
	if (!ctx)
		goto out;

	if (HMAC_Init_ex(ctx,
			 cfg->hmac_key,
			 (int)cfg->hmac_key_len,
			 EVP_sha256(),
			 NULL) != 1)
		goto out;

	if (HMAC_Update(ctx,
			(const unsigned char *)&rec->hdr,
			sizeof(rec->hdr)) != 1)
		goto out;

	if (rec->payload_len > 0 &&
	    HMAC_Update(ctx, rec->payload, rec->payload_len) != 1)
		goto out;

	if (HMAC_Final(ctx, rec->hmac, &hlen) != 1)
		goto out;

	if (hlen != VIRP_HMAC_LEN)
		goto out;

	rc = 0;

out:
	if (rc != 0 && cfg)
		cfg->obs_sign_fail++;

	if (ctx)
		HMAC_CTX_free(ctx);

	return rc;
}

/* ================================================================
 * Transport — AF_UNIX SOCK_STREAM to O-Node
 * ================================================================ */

static int virp_send_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;
	size_t sent = 0;

	while (sent < len) {
		ssize_t n = write(fd, p + sent, len - sent);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;

		sent += (size_t)n;
	}

	return 0;
}

static int virp_connect_onode(struct virp_config *cfg)
{
	struct sockaddr_un addr;
	int fd;

	if (!cfg || !cfg->onode_socket_path[0])
		return -1;

	if (cfg->onode_fd >= 0)
		return 0;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		zlog_err("VIRP: socket() failed: %s", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, cfg->onode_socket_path, sizeof(addr.sun_path));

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		zlog_err("VIRP: connect to O-Node %s failed: %s",
			 cfg->onode_socket_path, strerror(errno));
		close(fd);
		return -1;
	}

	cfg->onode_fd = fd;
	zlog_info("VIRP: connected to O-Node at %s", cfg->onode_socket_path);
	return 0;
}

int virp_send_record(struct virp_config *cfg, const struct virp_record *rec)
{
	if (!cfg || !rec)
		return -1;

	if (virp_connect_onode(cfg) < 0) {
		cfg->obs_send_fail++;
		return -1;
	}

	/* Wire: header || payload || HMAC */
	if (virp_send_all(cfg->onode_fd, &rec->hdr, sizeof(rec->hdr)) < 0)
		goto fail;

	if (rec->payload_len > 0 &&
	    virp_send_all(cfg->onode_fd, rec->payload, rec->payload_len) < 0)
		goto fail;

	if (virp_send_all(cfg->onode_fd, rec->hmac, VIRP_HMAC_LEN) < 0)
		goto fail;

	return 0;

fail:
	zlog_err("VIRP: send to O-Node failed: %s", strerror(errno));
	close(cfg->onode_fd);
	cfg->onode_fd = -1;
	cfg->obs_send_fail++;
	return -1;
}

/* ================================================================
 * virp_emit_json — single wrapper for all handlers
 *
 * Does init → sign → send and manages obs_signed / obs_delivered /
 * obs_build_fail / obs_sign_fail / obs_send_fail counters.
 * ================================================================ */

static int virp_emit_json(uint8_t obs_type,
			  uint8_t trust_tier,
			  const char *json,
			  size_t json_len)
{
	struct virp_record rec;
	uint64_t ts;

	if (!virp_cfg.enabled)
		return 0;

	if (!json)
		return -1;

	if (json_len > VIRP_MAX_PAYLOAD) {
		zlog_warn("VIRP: JSON payload too large (%zu > %u)",
			  json_len, VIRP_MAX_PAYLOAD);
		virp_cfg.obs_build_fail++;
		return -1;
	}

	ts = virp_get_time_ns();

	if (virp_record_init(&rec,
			     obs_type,
			     trust_tier,
			     virp_cfg.producer_id,
			     ++virp_cfg.sequence,
			     ts,
			     (const uint8_t *)json,
			     json_len) != 0) {
		virp_cfg.obs_build_fail++;
		return -1;
	}

	if (virp_sign_record(&virp_cfg, &rec) != 0) {
		virp_cfg.obs_sign_fail++;
		return -1;
	}

	virp_cfg.obs_signed++;

	if (virp_send_record(&virp_cfg, &rec) != 0) {
		virp_cfg.obs_send_fail++;
		zlog_info("VIRP[%u]: local-fallback type=%u tier=%u payload=%.*s",
			  virp_cfg.sequence, obs_type, trust_tier,
			  (int)json_len, json);
		return -1;
	}

	virp_cfg.obs_delivered++;
	zlog_debug("VIRP[%u]: type=%u tier=%u len=%zu",
		   virp_cfg.sequence, obs_type, trust_tier, json_len);
	return 0;
}

/* ================================================================
 * Producer ID — derived from BGP router-id
 * ================================================================ */

static uint32_t virp_get_producer_id(const struct bgp *bgp)
{
	if (!bgp)
		return 0;
	return ntohl(bgp->router_id.s_addr);
}

static void virp_update_producer_id(const struct bgp *bgp)
{
	uint32_t pid = virp_get_producer_id(bgp);

	if (pid != 0)
		virp_cfg.producer_id = pid;
}

/* ================================================================
 * BGP Hook Handlers
 *
 * Each constructs JSON via virp_json_append(), then calls
 * virp_emit_json() which does init/sign/send.
 * ================================================================ */

/*
 * Hook: peer_status_changed
 * Fires on every BGP FSM state transition.
 */
static int virp_peer_status_changed(struct peer *peer)
{
	char buf[VIRP_JSON_BUF];
	char peer_id[256];
	char peer_addr[256];
	char router_id[64];
	size_t off = 0;
	enum bgp_fsm_status old_st, new_st;
	enum virp_trust_tier tier = VIRP_TIER_GREEN;

	if (!virp_cfg.enabled || !peer || !peer->connection || !peer->bgp)
		return 0;

	old_st = peer->connection->ostatus;
	new_st = peer->connection->status;

	if (old_st == Established && new_st != Established)
		tier = VIRP_TIER_YELLOW;

	virp_update_producer_id(peer->bgp);
	virp_peer_identity(peer,
			   peer_id, sizeof(peer_id),
			   peer_addr, sizeof(peer_addr));
	virp_router_id_json(peer->bgp, router_id, sizeof(router_id));

	if (virp_json_append(buf, sizeof(buf), &off,
			     "{"
			     "\"domain\":\"bgp\","
			     "\"event\":\"peer_state_change\","
			     "\"peer\":\"%s\","
			     "\"peer_addr\":\"%s\","
			     "\"peer_as\":%u,"
			     "\"local_as\":%u,"
			     "\"old_state\":\"%s\","
			     "\"new_state\":\"%s\","
			     "\"router_id\":\"%s\","
			     "\"producer_id\":%u"
			     "}",
			     peer_id,
			     peer_addr,
			     peer->as,
			     peer->local_as,
			     virp_fsm_state_name(old_st),
			     virp_fsm_state_name(new_st),
			     router_id,
			     virp_cfg.producer_id) != 0)
		return 0;

	(void)virp_emit_json(VIRP_OBS_BGP_PEER_STATE, tier, buf, off);
	return 0;
}

/*
 * Hook: peer_backward_transition
 * Fires specifically when a peer drops OUT of Established.
 */
static int virp_peer_backward_transition(struct peer *peer)
{
	char buf[VIRP_JSON_BUF];
	char peer_id[256];
	char peer_addr[256];
	char router_id[64];
	size_t off = 0;

	if (!virp_cfg.enabled || !peer || !peer->connection || !peer->bgp)
		return 0;

	virp_update_producer_id(peer->bgp);
	virp_peer_identity(peer,
			   peer_id, sizeof(peer_id),
			   peer_addr, sizeof(peer_addr));
	virp_router_id_json(peer->bgp, router_id, sizeof(router_id));

	if (virp_json_append(buf, sizeof(buf), &off,
			     "{"
			     "\"domain\":\"bgp\","
			     "\"event\":\"peer_down\","
			     "\"peer\":\"%s\","
			     "\"peer_addr\":\"%s\","
			     "\"peer_as\":%u,"
			     "\"local_as\":%u,"
			     "\"last_state\":\"%s\","
			     "\"last_event\":%d,"
			     "\"uptime\":%ld,"
			     "\"router_id\":\"%s\","
			     "\"producer_id\":%u"
			     "}",
			     peer_id,
			     peer_addr,
			     peer->as,
			     peer->local_as,
			     virp_fsm_state_name(peer->connection->ostatus),
			     peer->last_major_event,
			     (long)peer->uptime,
			     router_id,
			     virp_cfg.producer_id) != 0)
		return 0;

	(void)virp_emit_json(VIRP_OBS_BGP_PEER_BACKWARD, VIRP_TIER_YELLOW,
			     buf, off);
	return 0;
}

/*
 * Hook: bgp_process
 * Fires when BGP processes a route from a peer.
 */
static int virp_bgp_process(struct bgp *bgp, afi_t afi, safi_t safi,
			    struct bgp_dest *dest, struct peer *peer,
			    bool withdraw)
{
	char buf[VIRP_JSON_BUF];
	char prefix_str[PREFIX_STRLEN];
	char peer_id[256];
	char peer_addr[256];
	char router_id[64];
	const struct prefix *p;
	size_t off = 0;

	if (!virp_cfg.enabled || !bgp || !dest || !peer)
		return 0;

	p = bgp_dest_get_prefix(dest);
	if (!p)
		return 0;

	virp_update_producer_id(bgp);
	prefix2str(p, prefix_str, sizeof(prefix_str));
	virp_peer_identity(peer,
			   peer_id, sizeof(peer_id),
			   peer_addr, sizeof(peer_addr));
	virp_router_id_json(bgp, router_id, sizeof(router_id));

	if (virp_json_append(buf, sizeof(buf), &off,
			     "{"
			     "\"domain\":\"bgp\","
			     "\"event\":\"%s\","
			     "\"prefix\":\"%s\","
			     "\"peer\":\"%s\","
			     "\"peer_addr\":\"%s\","
			     "\"peer_as\":%u,"
			     "\"afi\":%d,"
			     "\"safi\":%d,"
			     "\"router_id\":\"%s\","
			     "\"producer_id\":%u"
			     "}",
			     withdraw ? "route_withdraw" : "route_announce",
			     prefix_str,
			     peer_id,
			     peer_addr,
			     peer->as,
			     afi,
			     safi,
			     router_id,
			     virp_cfg.producer_id) != 0)
		return 0;

	(void)virp_emit_json(VIRP_OBS_BGP_ROUTE_EVENT, VIRP_TIER_GREEN,
			     buf, off);
	return 0;
}

/*
 * Path JSON builder for bestpath_change old/new sub-objects.
 */
static int virp_append_path_json(char *buf, size_t buf_sz, size_t *off,
				 const char *field_name,
				 struct bgp_path_info *route)
{
	char peer_id[256];
	char peer_addr[256];
	char nexthop[64];
	char aspath[768];

	if (!route || !route->attr)
		return virp_json_append(buf, buf_sz, off,
					"\"%s\":null", field_name);

	virp_peer_identity(route->peer,
			   peer_id, sizeof(peer_id),
			   peer_addr, sizeof(peer_addr));
	virp_nexthop_json(route->attr, nexthop, sizeof(nexthop));
	virp_aspath_json(route->attr, aspath, sizeof(aspath));

	return virp_json_append(buf, buf_sz, off,
				"\"%s\":{"
				"\"peer\":\"%s\","
				"\"peer_addr\":\"%s\","
				"\"peer_as\":%u,"
				"\"nexthop\":\"%s\","
				"\"as_path\":\"%s\","
				"\"med\":%u,"
				"\"local_pref\":%u,"
				"\"origin\":%u"
				"}",
				field_name,
				peer_id,
				peer_addr,
				route->peer ? route->peer->as : 0,
				nexthop,
				aspath,
				route->attr->med,
				route->attr->local_pref,
				route->attr->origin);
}

/*
 * Hook: bgp_route_update
 * Fires on best-path changes with full old/new attributes.
 */
static int virp_bgp_route_update(struct bgp *bgp, afi_t afi, safi_t safi,
				 struct bgp_dest *dest,
				 struct bgp_path_info *old_route,
				 struct bgp_path_info *new_route)
{
	char buf[VIRP_JSON_BUF];
	char prefix_str[PREFIX_STRLEN];
	char router_id[64];
	const struct prefix *p;
	size_t off = 0;

	if (!virp_cfg.enabled || !bgp || !dest)
		return 0;

	if (!old_route && !new_route)
		return 0;

	p = bgp_dest_get_prefix(dest);
	if (!p)
		return 0;

	virp_update_producer_id(bgp);
	prefix2str(p, prefix_str, sizeof(prefix_str));
	virp_router_id_json(bgp, router_id, sizeof(router_id));

	if (virp_json_append(buf, sizeof(buf), &off,
			     "{"
			     "\"domain\":\"bgp\","
			     "\"event\":\"bestpath_change\","
			     "\"prefix\":\"%s\","
			     "\"afi\":%d,"
			     "\"safi\":%d,"
			     "\"router_id\":\"%s\","
			     "\"producer_id\":%u,",
			     prefix_str,
			     afi,
			     safi,
			     router_id,
			     virp_cfg.producer_id) != 0)
		return 0;

	if (virp_append_path_json(buf, sizeof(buf), &off, "old", old_route) != 0)
		return 0;

	if (virp_json_append(buf, sizeof(buf), &off, ",") != 0)
		return 0;

	if (virp_append_path_json(buf, sizeof(buf), &off, "new", new_route) != 0)
		return 0;

	if (virp_json_append(buf, sizeof(buf), &off, "}") != 0)
		return 0;

	(void)virp_emit_json(VIRP_OBS_BGP_BESTPATH_CHANGE, VIRP_TIER_GREEN,
			     buf, off);
	return 0;
}

/* ================================================================
 * VTY Commands
 *
 *   router bgp 65000
 *     virp enable
 *     virp onode-socket /tmp/virp-onode.sock
 *     virp hmac-key /etc/virp/bgp.key
 *   !
 *   show bgp virp status
 *   show bgp virp statistics
 * ================================================================ */

DEFUN(virp_enable,
      virp_enable_cmd,
      "virp enable",
      "VIRP Observation Protocol\n"
      "Enable VIRP signed observations\n")
{
	if (virp_cfg.hmac_key_len == 0) {
		if (virp_load_hmac_key(&virp_cfg) < 0) {
			vty_out(vty, "%% Cannot load HMAC key from %s\n",
				virp_cfg.hmac_key_path);
			return CMD_WARNING;
		}
	}

	virp_cfg.enabled = true;
	virp_connect_onode(&virp_cfg);

	vty_out(vty, "VIRP: observation signing enabled\n");
	return CMD_SUCCESS;
}

DEFUN(virp_disable,
      virp_disable_cmd,
      "no virp enable",
      NO_STR
      "VIRP Observation Protocol\n"
      "Disable VIRP signed observations\n")
{
	virp_cfg.enabled = false;

	if (virp_cfg.onode_fd >= 0) {
		close(virp_cfg.onode_fd);
		virp_cfg.onode_fd = -1;
	}

	vty_out(vty, "VIRP: observation signing disabled\n");
	return CMD_SUCCESS;
}

DEFUN(virp_onode_socket,
      virp_onode_socket_cmd,
      "virp onode-socket WORD",
      "VIRP Observation Protocol\n"
      "Set O-Node Unix socket path\n"
      "Socket path\n")
{
	strlcpy(virp_cfg.onode_socket_path, argv[2]->arg,
		sizeof(virp_cfg.onode_socket_path));

	if (virp_cfg.onode_fd >= 0) {
		close(virp_cfg.onode_fd);
		virp_cfg.onode_fd = -1;
	}

	vty_out(vty, "VIRP: O-Node socket set to %s\n",
		virp_cfg.onode_socket_path);
	return CMD_SUCCESS;
}

DEFUN(virp_hmac_key_path,
      virp_hmac_key_path_cmd,
      "virp hmac-key WORD",
      "VIRP Observation Protocol\n"
      "Set HMAC key file path\n"
      "Key file path\n")
{
	strlcpy(virp_cfg.hmac_key_path, argv[2]->arg,
		sizeof(virp_cfg.hmac_key_path));

	if (virp_load_hmac_key(&virp_cfg) < 0) {
		vty_out(vty, "%% Failed to load key from %s\n",
			virp_cfg.hmac_key_path);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(show_bgp_virp_status,
      show_bgp_virp_status_cmd,
      "show bgp virp status",
      SHOW_STR
      BGP_STR
      "VIRP Observation Protocol\n"
      "Show VIRP status\n")
{
	vty_out(vty, "VIRP Status\n");
	vty_out(vty, "  Enabled:        %s\n",
		virp_cfg.enabled ? "yes" : "no");
	vty_out(vty, "  O-Node socket:  %s\n",
		virp_cfg.onode_socket_path);
	vty_out(vty, "  O-Node state:   %s\n",
		virp_cfg.onode_fd >= 0 ? "connected" : "disconnected");
	vty_out(vty, "  HMAC key:       %s (%zu bytes)\n",
		virp_cfg.hmac_key_path, virp_cfg.hmac_key_len);
	vty_out(vty, "  Producer ID:    %u\n", virp_cfg.producer_id);
	vty_out(vty, "  Sequence:       %u\n", virp_cfg.sequence);
	vty_out(vty, "  Obs signed:     %lu\n",
		(unsigned long)virp_cfg.obs_signed);
	vty_out(vty, "  Obs delivered:  %lu\n",
		(unsigned long)virp_cfg.obs_delivered);
	vty_out(vty, "  Build failures: %lu\n",
		(unsigned long)virp_cfg.obs_build_fail);
	vty_out(vty, "  Sign failures:  %lu\n",
		(unsigned long)virp_cfg.obs_sign_fail);
	vty_out(vty, "  Send failures:  %lu\n",
		(unsigned long)virp_cfg.obs_send_fail);
	return CMD_SUCCESS;
}

DEFUN(show_bgp_virp_statistics,
      show_bgp_virp_statistics_cmd,
      "show bgp virp statistics",
      SHOW_STR
      BGP_STR
      "VIRP Observation Protocol\n"
      "Show VIRP statistics\n")
{
	vty_out(vty, "VIRP Statistics\n");
	vty_out(vty, "  Observations signed:    %lu\n",
		(unsigned long)virp_cfg.obs_signed);
	vty_out(vty, "  Observations delivered: %lu\n",
		(unsigned long)virp_cfg.obs_delivered);
	vty_out(vty, "  Build failures:         %lu\n",
		(unsigned long)virp_cfg.obs_build_fail);
	vty_out(vty, "  Sign failures:          %lu\n",
		(unsigned long)virp_cfg.obs_sign_fail);
	vty_out(vty, "  Send failures:          %lu\n",
		(unsigned long)virp_cfg.obs_send_fail);
	vty_out(vty, "  Current sequence:       %u\n",
		virp_cfg.sequence);
	vty_out(vty, "  Producer ID:            %u\n",
		virp_cfg.producer_id);
	return CMD_SUCCESS;
}

void bgp_virp_vty_init(void)
{
	install_element(BGP_NODE, &virp_enable_cmd);
	install_element(BGP_NODE, &virp_disable_cmd);
	install_element(BGP_NODE, &virp_onode_socket_cmd);
	install_element(BGP_NODE, &virp_hmac_key_path_cmd);

	install_element(VIEW_NODE, &show_bgp_virp_status_cmd);
	install_element(ENABLE_NODE, &show_bgp_virp_status_cmd);
	install_element(VIEW_NODE, &show_bgp_virp_statistics_cmd);
	install_element(ENABLE_NODE, &show_bgp_virp_statistics_cmd);
}

/* ================================================================
 * Module Init / Fini — FRR_MODULE_SETUP pattern
 * ================================================================ */

static int bgp_virp_module_fini(void);

static int bgp_virp_init(struct event_loop *tm)
{
	bgp_virp_vty_init();
	zlog_info("VIRP: BGP observation module initialized "
		  "(draft-howard-virp-01)");
	return 0;
}

static int bgp_virp_module_init(void)
{
	hook_register(peer_status_changed, virp_peer_status_changed);
	hook_register(peer_backward_transition, virp_peer_backward_transition);
	hook_register(bgp_process, virp_bgp_process);
	hook_register(bgp_route_update, virp_bgp_route_update);

	hook_register(frr_late_init, bgp_virp_init);
	hook_register(frr_fini, bgp_virp_module_fini);

	return 0;
}

static int bgp_virp_module_fini(void)
{
	virp_cfg.enabled = false;

	hook_unregister(peer_status_changed, virp_peer_status_changed);
	hook_unregister(peer_backward_transition, virp_peer_backward_transition);
	hook_unregister(bgp_process, virp_bgp_process);
	hook_unregister(bgp_route_update, virp_bgp_route_update);
	hook_unregister(frr_late_init, bgp_virp_init);
	hook_unregister(frr_fini, bgp_virp_module_fini);

	if (virp_cfg.onode_fd >= 0) {
		close(virp_cfg.onode_fd);
		virp_cfg.onode_fd = -1;
	}

	virp_zeroize(virp_cfg.hmac_key, sizeof(virp_cfg.hmac_key));
	virp_cfg.hmac_key_len = 0;

	zlog_info("VIRP: module shutdown — signed=%lu delivered=%lu build_fail=%lu sign_fail=%lu send_fail=%lu",
		  (unsigned long)virp_cfg.obs_signed,
		  (unsigned long)virp_cfg.obs_delivered,
		  (unsigned long)virp_cfg.obs_build_fail,
		  (unsigned long)virp_cfg.obs_sign_fail,
		  (unsigned long)virp_cfg.obs_send_fail);
	return 0;
}

FRR_MODULE_SETUP(.name = "bgpd_virp",
		 .version = FRR_VERSION,
		 .description = "VIRP signed BGP observation module "
				"(draft-howard-virp-01)",
		 .init = bgp_virp_module_init,
);
