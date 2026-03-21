// SPDX-License-Identifier: Apache-2.0
/*
 * BGP VIRP (Verified Infrastructure Response Protocol) Module
 *
 * Cryptographically signs BGP observations at collection time using
 * HMAC-SHA256. Hooks into FRR's BGP event system to produce signed
 * attestations of routing state changes.
 *
 * Copyright (C) 2026 Third Level IT LLC / Nate Howard
 * VIRP Specification: draft-howard-virp-01
 */

#ifndef _BGP_VIRP_H
#define _BGP_VIRP_H

#include "bgpd.h"

/*
 * VIRP Observation Types for BGP domain
 *
 * These map to the Observation Channel in the VIRP two-channel model.
 * All observations are read-only attestations of state - no Intent
 * Channel operations are performed by this module.
 */
enum virp_bgp_obs_type {
	VIRP_BGP_PEER_STATE_CHANGE = 1,   /* FSM transition */
	VIRP_BGP_PEER_BACKWARD_TRANS = 2, /* Drop from Established */
	VIRP_BGP_ROUTE_PROCESS = 3,       /* Route received/withdrawn */
	VIRP_BGP_BESTPATH_CHANGE = 4,     /* Best-path selection changed */
};

/*
 * VIRP Trust Tiers (from draft-howard-virp-01 Section 5)
 */
enum virp_trust_tier {
	VIRP_TIER_GREEN = 0,  /* Fully verified, HMAC valid */
	VIRP_TIER_YELLOW = 1, /* Verified but anomalous */
	VIRP_TIER_RED = 2,    /* Unverified or failed check */
	VIRP_TIER_BLACK = 3,  /* Rejected / tampered */
};

/*
 * Signed observation structure
 *
 * This is the wire format written to the O-Node socket.
 * The HMAC covers: obs_type + timestamp + payload (not the HMAC itself).
 */
#define VIRP_HMAC_LEN 32        /* SHA-256 digest */
#define VIRP_MAX_PAYLOAD 4096
#define VIRP_MAGIC 0x56495250   /* "VIRP" */
#define VIRP_VERSION 1

struct virp_observation {
	uint32_t magic;
	uint8_t version;
	uint8_t obs_type;
	uint8_t trust_tier;
	uint8_t _pad;
	uint64_t timestamp_ns;              /* nanosecond epoch */
	uint32_t sequence;                  /* per-session monotonic */
	uint32_t payload_len;
	char payload[VIRP_MAX_PAYLOAD];     /* JSON observation data */
	uint8_t hmac[VIRP_HMAC_LEN];       /* HMAC-SHA256 over above */
};

/*
 * Module configuration (set via FRR VTY commands)
 */
struct virp_config {
	bool enabled;
	char onode_socket_path[256];        /* Unix socket to O-Node */
	char hmac_key_path[256];            /* Path to HMAC key file */
	uint8_t hmac_key[64];              /* Loaded key material */
	size_t hmac_key_len;
	int onode_fd;                       /* Connected socket fd */
	uint32_t sequence;                  /* Monotonic counter */
	uint64_t obs_signed;               /* Observations successfully signed */
	uint64_t obs_delivered;            /* Observations delivered to O-Node */
	uint64_t obs_dropped;              /* Observations signed but not delivered */
	uint64_t sign_failures;            /* HMAC failures */
	uint64_t send_failures;            /* Socket write failures */
};

/* Module init/fini */
extern int bgp_virp_module_init(void);

/* VTY commands */
extern void bgp_virp_vty_init(void);

/* Status */
extern void bgp_virp_show_stats(struct vty *vty);

#endif /* _BGP_VIRP_H */
