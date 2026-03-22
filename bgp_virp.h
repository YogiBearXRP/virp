// SPDX-License-Identifier: Apache-2.0
/*
 * BGP VIRP (Verified Infrastructure Response Protocol) Module
 *
 * Hardened wire format with canonical packed header, network byte order
 * integers, and HMAC-SHA256 over serialized wire header + payload.
 *
 * Wire layout:
 *
 *   +---------------------------+
 *   | virp_wire_header          |  fixed size, packed, network byte order
 *   +---------------------------+
 *   | payload (UTF-8 JSON)      |  payload_len bytes
 *   +---------------------------+
 *   | HMAC-SHA256               |  32 bytes
 *   +---------------------------+
 *
 * The authenticated object is:
 *   virp_wire_header || payload
 *
 * Copyright (C) 2026 Third Level IT LLC / Nate Howard
 * VIRP Specification: draft-howard-virp-01
 */

#ifndef _BGP_VIRP_H
#define _BGP_VIRP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define VIRP_MAGIC              0x56495250U   /* "VIRP" */
#define VIRP_VERSION            1U
#define VIRP_HMAC_LEN           32U
#define VIRP_MAX_PAYLOAD        4096U
#define VIRP_MAX_JSON_FIELD     512U
#define VIRP_MAX_KEY_LEN        256U
#define VIRP_MIN_KEY_LEN        16U

enum virp_obs_type {
	VIRP_OBS_UNSPEC               = 0,
	VIRP_OBS_BGP_PEER_STATE       = 1,
	VIRP_OBS_BGP_PEER_BACKWARD    = 2,
	VIRP_OBS_BGP_ROUTE_EVENT      = 3,
	VIRP_OBS_BGP_BESTPATH_CHANGE  = 4,
};

enum virp_trust_tier {
	VIRP_TIER_GREEN  = 0,
	VIRP_TIER_YELLOW = 1,
	VIRP_TIER_RED    = 2,
	VIRP_TIER_BLACK  = 3,
};

/*
 * Canonical wire header.
 * All multibyte integer fields are transmitted in network byte order.
 */
struct virp_wire_header {
	uint32_t magic_be;
	uint8_t  version;
	uint8_t  obs_type;
	uint8_t  trust_tier;
	uint8_t  flags;
	uint64_t timestamp_ns_be;
	uint32_t sequence_be;
	uint32_t payload_len_be;
	uint32_t producer_id_be;
} __attribute__((packed));

struct virp_record {
	struct virp_wire_header hdr;
	uint8_t payload[VIRP_MAX_PAYLOAD];
	uint8_t hmac[VIRP_HMAC_LEN];
	size_t payload_len;
};

struct virp_config {
	bool enabled;
	char onode_socket_path[256];
	char hmac_key_path[256];

	int onode_fd;
	uint32_t sequence;
	uint32_t producer_id;

	uint64_t obs_signed;
	uint64_t obs_delivered;
	uint64_t obs_build_fail;
	uint64_t obs_sign_fail;
	uint64_t obs_send_fail;

	uint8_t hmac_key[VIRP_MAX_KEY_LEN];
	size_t hmac_key_len;
};

int virp_load_hmac_key(struct virp_config *cfg);

int virp_record_init(struct virp_record *rec,
		     uint8_t obs_type,
		     uint8_t trust_tier,
		     uint32_t producer_id,
		     uint32_t sequence,
		     uint64_t timestamp_ns,
		     const uint8_t *payload,
		     size_t payload_len);

int virp_sign_record(struct virp_config *cfg, struct virp_record *rec);
int virp_send_record(struct virp_config *cfg, const struct virp_record *rec);

size_t virp_json_escape(char *dst, size_t dst_size, const char *src);
uint64_t virp_get_time_ns(void);

/* FRR integration */
extern void bgp_virp_vty_init(void);

#endif /* _BGP_VIRP_H */
