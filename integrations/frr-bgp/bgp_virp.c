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
 * This module is strictly Observation Channel — it never modifies
 * routing state. All observations are read-only attestations.
 *
 * Copyright (C) 2026 Third Level IT LLC / Nate Howard
 * VIRP Specification: draft-howard-virp-01
 */

#include <zebra.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_virp.h"

#include "lib/vty.h"
#include "lib/command.h"
#include "lib/memory.h"
#include "lib/network.h"
#include "lib/log.h"
#include "lib/hook.h"
#include "lib/frr_pthread.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

/* Memory type for VIRP allocations */
DEFINE_MTYPE_STATIC(BGPD, VIRP, "BGP VIRP");

/* Module-global config — single instance */
static struct virp_config virp_cfg = {
	.enabled = false,
	.onode_socket_path = "/tmp/virp-onode.sock",
	.hmac_key_path = "/etc/virp/bgp.key",
	.onode_fd = -1,
	.sequence = 0,
	.obs_signed = 0,
	.obs_delivered = 0,
	.obs_dropped = 0,
	.sign_failures = 0,
	.send_failures = 0,
};

/*
 * virp_json_escape — escape a string for safe embedding in JSON.
 * Handles \, ", control characters. Returns bytes written (excluding NUL),
 * or dst_size-1 if truncated. Output is always NUL-terminated.
 */
static size_t virp_json_escape(char *dst, size_t dst_size, const char *src)
{
	size_t di = 0;
	const char *s;

	if (!dst || dst_size == 0)
		return 0;

	for (s = src; *s && di < dst_size - 1; s++) {
		unsigned char c = (unsigned char)*s;
		switch (c) {
		case '"':
		case '\\':
			if (di + 2 > dst_size - 1)
				goto out;
			dst[di++] = '\\';
			dst[di++] = (char)c;
			break;
		case '\n':
			if (di + 2 > dst_size - 1)
				goto out;
			dst[di++] = '\\';
			dst[di++] = 'n';
			break;
		case '\r':
			if (di + 2 > dst_size - 1)
				goto out;
			dst[di++] = '\\';
			dst[di++] = 'r';
			break;
		case '\t':
			if (di + 2 > dst_size - 1)
				goto out;
			dst[di++] = '\\';
			dst[di++] = 't';
			break;
		default:
			if (c < 0x20) {
				/* \u00XX for other control chars */
				if (di + 6 > dst_size - 1)
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

/* ----------------------------------------------------------------
 * HMAC Signing
 * ----------------------------------------------------------------
 * Signs observation data with HMAC-SHA256. In production, this calls
 * into libvirp. For the reference implementation, we use OpenSSL
 * directly so the module compiles standalone.
 */

static int virp_load_hmac_key(void)
{
	FILE *f;
	size_t nread;

	f = fopen(virp_cfg.hmac_key_path, "rb");
	if (!f) {
		zlog_err("VIRP: cannot open HMAC key file %s: %s",
			 virp_cfg.hmac_key_path, strerror(errno));
		return -1;
	}

	nread = fread(virp_cfg.hmac_key, 1, sizeof(virp_cfg.hmac_key), f);
	fclose(f);

	if (nread < 16) {
		zlog_err("VIRP: HMAC key too short (%zu bytes, minimum 16)",
			 nread);
		return -1;
	}

	/* Strip trailing \r and \n (handles \n, \r\n, \r) */
	while (nread > 0 && (virp_cfg.hmac_key[nread - 1] == '\n'
			     || virp_cfg.hmac_key[nread - 1] == '\r'))
		nread--;

	virp_cfg.hmac_key_len = nread;
	zlog_info("VIRP: loaded %zu-byte HMAC key from %s",
		  nread, virp_cfg.hmac_key_path);
	return 0;
}

static int virp_sign_observation(struct virp_observation *obs)
{
	unsigned int hmac_len = 0;
	unsigned char *result;

	/*
	 * HMAC covers header + actual payload bytes (not zero padding).
	 * This matches the wire format: header + payload_len bytes.
	 */
	size_t sign_len = offsetof(struct virp_observation, payload)
			  + obs->payload_len;

	result = HMAC(EVP_sha256(),
		      virp_cfg.hmac_key, (int)virp_cfg.hmac_key_len,
		      (unsigned char *)obs, sign_len,
		      obs->hmac, &hmac_len);

	if (!result || hmac_len != VIRP_HMAC_LEN) {
		virp_cfg.sign_failures++;
		zlog_err("VIRP: HMAC-SHA256 signing failed (seq %u)",
			 obs->sequence);
		return -1;
	}

	return 0;
}

/* ----------------------------------------------------------------
 * O-Node Socket Communication
 * ----------------------------------------------------------------
 * Connects to the VIRP O-Node daemon over Unix domain socket.
 * The O-Node receives signed observations and appends them to
 * chain.db (SQLite chain store).
 */

static int virp_connect_onode(void)
{
	struct sockaddr_un addr;
	int fd;

	if (virp_cfg.onode_fd >= 0)
		return 0; /* already connected */

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		zlog_err("VIRP: socket() failed: %s", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, virp_cfg.onode_socket_path,
		sizeof(addr.sun_path));

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		zlog_err("VIRP: connect to O-Node %s failed: %s",
			 virp_cfg.onode_socket_path, strerror(errno));
		close(fd);
		return -1;
	}

	virp_cfg.onode_fd = fd;
	zlog_info("VIRP: connected to O-Node at %s",
		  virp_cfg.onode_socket_path);
	return 0;
}

/*
 * virp_send_all — loop on partial writes and handle EINTR.
 * Returns 0 on success, -1 on fatal error.
 */
static int virp_send_all(int fd, const void *data, size_t len)
{
	const uint8_t *p = data;
	size_t remaining = len;

	while (remaining > 0) {
		ssize_t n = write(fd, p, remaining);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += n;
		remaining -= (size_t)n;
	}
	return 0;
}

static int virp_send_observation(struct virp_observation *obs)
{
	size_t header_plus_payload;

	/* Reconnect if needed */
	if (virp_cfg.onode_fd < 0) {
		if (virp_connect_onode() < 0) {
			virp_cfg.send_failures++;
			return -1;
		}
	}

	/*
	 * Wire format: [header 24B][payload N bytes][HMAC 32B]
	 *
	 * The HMAC field is at the end of the struct (after the full
	 * VIRP_MAX_PAYLOAD buffer), so we cannot write the struct as
	 * one contiguous block. Send header+payload, then HMAC.
	 */
	header_plus_payload = offsetof(struct virp_observation, payload)
			      + obs->payload_len;

	/* Send header + payload */
	if (virp_send_all(virp_cfg.onode_fd, obs, header_plus_payload) < 0) {
		zlog_err("VIRP: write header+payload to O-Node failed: %s",
			 strerror(errno));
		close(virp_cfg.onode_fd);
		virp_cfg.onode_fd = -1;
		virp_cfg.send_failures++;
		return -1;
	}

	/* Send HMAC */
	if (virp_send_all(virp_cfg.onode_fd, obs->hmac, VIRP_HMAC_LEN) < 0) {
		zlog_err("VIRP: write HMAC to O-Node failed: %s",
			 strerror(errno));
		close(virp_cfg.onode_fd);
		virp_cfg.onode_fd = -1;
		virp_cfg.send_failures++;
		return -1;
	}

	return 0;
}

/* ----------------------------------------------------------------
 * Observation Builders
 * ----------------------------------------------------------------
 * Each function constructs a JSON payload from BGP event data,
 * signs it, and sends it to the O-Node.
 */

static uint64_t virp_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int virp_emit(enum virp_bgp_obs_type type,
		     enum virp_trust_tier tier,
		     const char *json_payload, size_t json_len)
{
	struct virp_observation obs;

	if (!virp_cfg.enabled)
		return 0;

	if (json_len >= VIRP_MAX_PAYLOAD) {
		zlog_warn("VIRP: observation payload too large (%zu bytes)",
			  json_len);
		json_len = VIRP_MAX_PAYLOAD - 1;
	}

	/* Zero only the fixed header, not the full VIRP_MAX_PAYLOAD buffer */
	memset(&obs, 0, offsetof(struct virp_observation, payload));
	obs.magic = htonl(VIRP_MAGIC);
	obs.version = VIRP_VERSION;
	obs.obs_type = (uint8_t)type;
	obs.trust_tier = (uint8_t)tier;
	obs.timestamp_ns = virp_now_ns();
	obs.sequence = ++virp_cfg.sequence;
	obs.payload_len = (uint32_t)json_len;
	memcpy(obs.payload, json_payload, json_len);
	obs.payload[json_len] = '\0'; /* NUL-terminate for safety */

	if (virp_sign_observation(&obs) < 0)
		return -1;

	virp_cfg.obs_signed++;

	if (virp_send_observation(&obs) < 0) {
		virp_cfg.obs_dropped++;
		/* Log locally even if O-Node is down */
		zlog_info("VIRP[%u]: (O-Node unreachable) type=%d tier=%d: %.*s",
			  obs.sequence, type, tier,
			  (int)json_len, json_payload);
		return -1;
	}

	virp_cfg.obs_delivered++;

	zlog_debug("VIRP[%u]: type=%d tier=%d len=%u",
		   obs.sequence, type, tier, obs.payload_len);
	return 0;
}

/* ----------------------------------------------------------------
 * BGP Hook Handlers
 * ----------------------------------------------------------------
 * These are the four integration points into FRR's BGP daemon.
 * Each constructs a JSON observation and calls virp_emit().
 */

/*
 * Hook: peer_status_changed
 * Fires on every BGP FSM state transition.
 */
static int virp_peer_status_changed(struct peer *peer)
{
	char buf[VIRP_MAX_PAYLOAD];
	char esc_peer[256];
	char esc_rid[64];
	int len;
	enum virp_trust_tier tier = VIRP_TIER_GREEN;
	enum bgp_fsm_status old_st, new_st;

	if (!virp_cfg.enabled || !peer || !peer->connection)
		return 0;

	old_st = peer->connection->ostatus;
	new_st = peer->connection->status;

	/* Backward transition from Established = YELLOW */
	if (old_st == Established && new_st != Established)
		tier = VIRP_TIER_YELLOW;

	virp_json_escape(esc_peer, sizeof(esc_peer), PEER_HOSTNAME(peer));
	snprintf(esc_rid, sizeof(esc_rid), "%pI4", &peer->bgp->router_id);

	len = snprintf(buf, sizeof(buf),
		"{"
		"\"domain\":\"bgp\","
		"\"event\":\"peer_state_change\","
		"\"peer_ip\":\"%s\","
		"\"peer_as\":%u,"
		"\"local_as\":%u,"
		"\"old_state\":\"%s\","
		"\"new_state\":\"%s\","
		"\"router_id\":\"%s\""
		"}",
		esc_peer,
		peer->as,
		peer->local_as,
		virp_fsm_state_name(old_st),
		virp_fsm_state_name(new_st),
		esc_rid);

	if (len < 0 || (size_t)len >= sizeof(buf))
		return 0;

	virp_emit(VIRP_BGP_PEER_STATE_CHANGE, tier, buf, (size_t)len);
	return 0;
}

/*
 * Hook: peer_backward_transition
 * Fires specifically when a peer drops OUT of Established.
 * This is the alert-grade observation — a neighbor went down.
 */
static int virp_peer_backward_transition(struct peer *peer)
{
	char buf[VIRP_MAX_PAYLOAD];
	char esc_peer[256];
	char esc_rid[64];
	int len;

	if (!virp_cfg.enabled || !peer || !peer->connection)
		return 0;

	virp_json_escape(esc_peer, sizeof(esc_peer), PEER_HOSTNAME(peer));
	snprintf(esc_rid, sizeof(esc_rid), "%pI4", &peer->bgp->router_id);

	len = snprintf(buf, sizeof(buf),
		"{"
		"\"domain\":\"bgp\","
		"\"event\":\"peer_down\","
		"\"peer_ip\":\"%s\","
		"\"peer_as\":%u,"
		"\"local_as\":%u,"
		"\"last_state\":\"%s\","
		"\"last_event\":%d,"
		"\"uptime\":%ld,"
		"\"router_id\":\"%s\""
		"}",
		esc_peer,
		peer->as,
		peer->local_as,
		virp_fsm_state_name(peer->connection->ostatus),
		peer->last_major_event,
		(long)peer->uptime,
		esc_rid);

	if (len < 0 || (size_t)len >= sizeof(buf))
		return 0;

	virp_emit(VIRP_BGP_PEER_BACKWARD_TRANS, VIRP_TIER_YELLOW,
		  buf, (size_t)len);
	return 0;
}

/*
 * Hook: bgp_process
 * Fires when BGP processes a route from a peer.
 * The 'withdraw' flag indicates route withdrawal vs announcement.
 */
static int virp_bgp_process(struct bgp *bgp, afi_t afi, safi_t safi,
			    struct bgp_dest *dest, struct peer *peer,
			    bool withdraw)
{
	char buf[VIRP_MAX_PAYLOAD];
	char prefix_str[PREFIX_STRLEN];
	char esc_peer[256];
	char esc_rid[64];
	const struct prefix *p;
	int len;

	if (!virp_cfg.enabled || !dest || !peer)
		return 0;

	p = bgp_dest_get_prefix(dest);
	if (!p)
		return 0;

	prefix2str(p, prefix_str, sizeof(prefix_str));
	virp_json_escape(esc_peer, sizeof(esc_peer), PEER_HOSTNAME(peer));
	snprintf(esc_rid, sizeof(esc_rid), "%pI4", &bgp->router_id);

	len = snprintf(buf, sizeof(buf),
		"{"
		"\"domain\":\"bgp\","
		"\"event\":\"%s\","
		"\"prefix\":\"%s\","
		"\"peer_ip\":\"%s\","
		"\"peer_as\":%u,"
		"\"afi\":%d,"
		"\"safi\":%d,"
		"\"router_id\":\"%s\""
		"}",
		withdraw ? "route_withdraw" : "route_announce",
		prefix_str,
		esc_peer,
		peer->as,
		afi, safi,
		esc_rid);

	if (len < 0 || (size_t)len >= sizeof(buf))
		return 0;

	virp_emit(VIRP_BGP_ROUTE_PROCESS, VIRP_TIER_GREEN,
		  buf, (size_t)len);
	return 0;
}

/*
 * Hook: bgp_route_update
 * Fires on best-path changes. This is the crown jewel — we get both
 * old and new best paths with full attributes (AS path, nexthop, MED,
 * local-pref, origin). A signed attestation of best-path selection.
 */
static int virp_bgp_route_update(struct bgp *bgp, afi_t afi, safi_t safi,
				 struct bgp_dest *dest,
				 struct bgp_path_info *old_route,
				 struct bgp_path_info *new_route)
{
	char buf[VIRP_MAX_PAYLOAD];
	char prefix_str[PREFIX_STRLEN];
	char esc_rid[64];
	char esc_peer[256];
	char esc_nh[64];
	char esc_aspath[512];
	const struct prefix *p;
	int len;
	int off = 0;

	if (!virp_cfg.enabled || !dest)
		return 0;

	/* Must have at least one path to observe */
	if (!old_route && !new_route)
		return 0;

	p = bgp_dest_get_prefix(dest);
	if (!p)
		return 0;

	prefix2str(p, prefix_str, sizeof(prefix_str));
	snprintf(esc_rid, sizeof(esc_rid), "%pI4", &bgp->router_id);

	off = snprintf(buf, sizeof(buf),
		"{"
		"\"domain\":\"bgp\","
		"\"event\":\"bestpath_change\","
		"\"prefix\":\"%s\","
		"\"afi\":%d,"
		"\"safi\":%d,"
		"\"router_id\":\"%s\",",
		prefix_str,
		afi, safi,
		esc_rid);

	if (off < 0 || (size_t)off >= sizeof(buf))
		return 0;

	/* Old best path */
	if (old_route && old_route->attr) {
		virp_json_escape(esc_peer, sizeof(esc_peer),
			old_route->peer ? PEER_HOSTNAME(old_route->peer) : "none");
		snprintf(esc_nh, sizeof(esc_nh), "%pI4",
			 &old_route->attr->nexthop);
		virp_json_escape(esc_aspath, sizeof(esc_aspath),
			old_route->attr->aspath
				? aspath_print(old_route->attr->aspath)
				: "");

		off += snprintf(buf + off, sizeof(buf) - off,
			"\"old\":{"
			"\"peer_ip\":\"%s\","
			"\"peer_as\":%u,"
			"\"nexthop\":\"%s\","
			"\"as_path\":\"%s\","
			"\"med\":%u,"
			"\"local_pref\":%u,"
			"\"origin\":%d"
			"},",
			esc_peer,
			old_route->peer ? old_route->peer->as : 0,
			esc_nh,
			esc_aspath,
			old_route->attr->med,
			old_route->attr->local_pref,
			old_route->attr->origin);
	} else {
		off += snprintf(buf + off, sizeof(buf) - off,
			"\"old\":null,");
	}

	if (off < 0 || (size_t)off >= sizeof(buf))
		return 0;

	/* New best path */
	if (new_route && new_route->attr) {
		virp_json_escape(esc_peer, sizeof(esc_peer),
			new_route->peer ? PEER_HOSTNAME(new_route->peer) : "none");
		snprintf(esc_nh, sizeof(esc_nh), "%pI4",
			 &new_route->attr->nexthop);
		virp_json_escape(esc_aspath, sizeof(esc_aspath),
			new_route->attr->aspath
				? aspath_print(new_route->attr->aspath)
				: "");

		off += snprintf(buf + off, sizeof(buf) - off,
			"\"new\":{"
			"\"peer_ip\":\"%s\","
			"\"peer_as\":%u,"
			"\"nexthop\":\"%s\","
			"\"as_path\":\"%s\","
			"\"med\":%u,"
			"\"local_pref\":%u,"
			"\"origin\":%d"
			"}",
			esc_peer,
			new_route->peer ? new_route->peer->as : 0,
			esc_nh,
			esc_aspath,
			new_route->attr->med,
			new_route->attr->local_pref,
			new_route->attr->origin);
	} else {
		off += snprintf(buf + off, sizeof(buf) - off,
			"\"new\":null");
	}

	if (off < 0 || (size_t)off >= sizeof(buf))
		return 0;

	/* Close JSON */
	off += snprintf(buf + off, sizeof(buf) - off, "}");

	if (off < 0 || (size_t)off >= sizeof(buf))
		return 0;

	len = off;

	virp_emit(VIRP_BGP_BESTPATH_CHANGE, VIRP_TIER_GREEN,
		  buf, (size_t)len);
	return 0;
}

/* ----------------------------------------------------------------
 * VTY Commands
 * ----------------------------------------------------------------
 * FRR CLI integration for configuring and monitoring VIRP.
 *
 *   router bgp 65000
 *     virp enable
 *     virp onode-socket /tmp/virp-onode.sock
 *     virp hmac-key /etc/virp/bgp.key
 *   !
 *   show bgp virp status
 *   show bgp virp statistics
 */

DEFUN(virp_enable,
      virp_enable_cmd,
      "virp enable",
      "VIRP Observation Protocol\n"
      "Enable VIRP signed observations\n")
{
	if (virp_cfg.hmac_key_len == 0) {
		if (virp_load_hmac_key() < 0) {
			vty_out(vty, "%% Cannot load HMAC key from %s\n",
				virp_cfg.hmac_key_path);
			return CMD_WARNING;
		}
	}

	virp_cfg.enabled = true;
	virp_connect_onode(); /* best-effort, will retry on emit */

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

	/* Reconnect if already running */
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

	if (virp_load_hmac_key() < 0) {
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
	vty_out(vty, "  Sequence:       %u\n", virp_cfg.sequence);
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
	vty_out(vty, "  Observations dropped:   %lu\n",
		(unsigned long)virp_cfg.obs_dropped);
	vty_out(vty, "  Current sequence:       %u\n",
		virp_cfg.sequence);
	vty_out(vty, "  Sign failures:          %lu\n",
		(unsigned long)virp_cfg.sign_failures);
	vty_out(vty, "  Send failures:          %lu\n",
		(unsigned long)virp_cfg.send_failures);
	return CMD_SUCCESS;
}

void bgp_virp_vty_init(void)
{
	/* Config commands under 'router bgp' */
	install_element(BGP_NODE, &virp_enable_cmd);
	install_element(BGP_NODE, &virp_disable_cmd);
	install_element(BGP_NODE, &virp_onode_socket_cmd);
	install_element(BGP_NODE, &virp_hmac_key_path_cmd);

	/* Show commands */
	install_element(VIEW_NODE, &show_bgp_virp_status_cmd);
	install_element(ENABLE_NODE, &show_bgp_virp_status_cmd);
	install_element(VIEW_NODE, &show_bgp_virp_statistics_cmd);
	install_element(ENABLE_NODE, &show_bgp_virp_statistics_cmd);
}

/* ----------------------------------------------------------------
 * Module Init / Fini
 * ----------------------------------------------------------------
 * FRR module registration — same pattern as bgp_bmp.c
 */

static int bgp_virp_init(struct event_loop *tm)
{
	bgp_virp_vty_init();
	zlog_info("VIRP: BGP observation module initialized "
		  "(draft-howard-virp-01)");
	return 0;
}

static int bgp_virp_module_init(void)
{
	/*
	 * Register hook handlers — these four hooks give us complete
	 * visibility into BGP state transitions and routing decisions.
	 *
	 * This is the Observation Channel only. No Intent Channel
	 * operations are performed. The module cannot modify routes,
	 * peer state, or any BGP configuration.
	 */
	hook_register(peer_status_changed, virp_peer_status_changed);
	hook_register(peer_backward_transition, virp_peer_backward_transition);
	hook_register(bgp_process, virp_bgp_process);
	hook_register(bgp_route_update, virp_bgp_route_update);

	hook_register(frr_late_init, bgp_virp_init);

	return 0;
}

static int bgp_virp_module_fini(void)
{
	virp_cfg.enabled = false;

	hook_unregister(peer_status_changed, virp_peer_status_changed);
	hook_unregister(peer_backward_transition, virp_peer_backward_transition);
	hook_unregister(bgp_process, virp_bgp_process);
	hook_unregister(bgp_route_update, virp_bgp_route_update);

	if (virp_cfg.onode_fd >= 0) {
		close(virp_cfg.onode_fd);
		virp_cfg.onode_fd = -1;
	}

	/* Zeroize HMAC key material before shutdown */
	explicit_bzero(virp_cfg.hmac_key, sizeof(virp_cfg.hmac_key));
	virp_cfg.hmac_key_len = 0;

	zlog_info("VIRP: module shutdown — signed=%lu delivered=%lu dropped=%lu",
		  (unsigned long)virp_cfg.obs_signed,
		  (unsigned long)virp_cfg.obs_delivered,
		  (unsigned long)virp_cfg.obs_dropped);
	return 0;
}

FRR_MODULE_SETUP(.name = "bgpd_virp",
		 .version = FRR_VERSION,
		 .description = "VIRP signed BGP observation module "
				"(draft-howard-virp-01)",
		 .init = bgp_virp_module_init,
		 .fini = bgp_virp_module_fini,
);
