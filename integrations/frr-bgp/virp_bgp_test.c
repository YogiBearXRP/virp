// SPDX-License-Identifier: Apache-2.0
/*
 * VIRP BGP Observation - Standalone Signing Test
 *
 * Verifies that the observation structure, HMAC signing, and
 * O-Node socket communication work correctly BEFORE integrating
 * into the FRR build system. Run this on your Proxmox host or
 * any Linux box with OpenSSL.
 *
 * Build:
 *   gcc -o virp_bgp_test virp_bgp_test.c -lssl -lcrypto -Wall -O2
 *
 * Run:
 *   # Generate test key
 *   echo -n "test-virp-bgp-key-2026" > /tmp/virp-test.key
 *
 *   # Run without O-Node (signing only)
 *   ./virp_bgp_test --key /tmp/virp-test.key
 *
 *   # Run with O-Node socket
 *   ./virp_bgp_test --key /tmp/virp-test.key --socket /tmp/virp-onode.sock
 *
 * Copyright (C) 2026 Third Level IT LLC / Nate Howard
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

/* ---- Observation structure (mirrors bgp_virp.h) ---- */

#define VIRP_HMAC_LEN    32
#define VIRP_MAX_PAYLOAD 4096
#define VIRP_MAGIC       0x56495250  /* "VIRP" */
#define VIRP_VERSION     1

struct virp_observation {
    uint32_t magic;
    uint8_t  version;
    uint8_t  obs_type;
    uint8_t  trust_tier;
    uint8_t  _pad;
    uint64_t timestamp_ns;
    uint32_t sequence;
    uint32_t payload_len;
    char     payload[VIRP_MAX_PAYLOAD];
    uint8_t  hmac[VIRP_HMAC_LEN];
};

/* ---- Helpers ---- */

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void hex_dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

/* ---- HMAC signing ---- */

static int sign_observation(struct virp_observation *obs,
                            const uint8_t *key, size_t key_len)
{
    unsigned int hmac_len = 0;
    size_t sign_len = offsetof(struct virp_observation, payload)
                      + obs->payload_len;

    unsigned char *result = HMAC(EVP_sha256(),
                                 key, (int)key_len,
                                 (unsigned char *)obs, sign_len,
                                 obs->hmac, &hmac_len);

    return (result && hmac_len == VIRP_HMAC_LEN) ? 0 : -1;
}

static int verify_observation(const struct virp_observation *obs,
                              const uint8_t *key, size_t key_len)
{
    uint8_t check_hmac[VIRP_HMAC_LEN];
    unsigned int hmac_len = 0;
    size_t sign_len = offsetof(struct virp_observation, payload)
                      + obs->payload_len;

    HMAC(EVP_sha256(),
         key, (int)key_len,
         (const unsigned char *)obs, sign_len,
         check_hmac, &hmac_len);

    return (hmac_len == VIRP_HMAC_LEN &&
            memcmp(check_hmac, obs->hmac, VIRP_HMAC_LEN) == 0) ? 0 : -1;
}

/* ---- Build test observations ---- */

static void build_peer_state_obs(struct virp_observation *obs, uint32_t seq)
{
    memset(obs, 0, sizeof(*obs));
    obs->magic = htonl(VIRP_MAGIC);
    obs->version = VIRP_VERSION;
    obs->obs_type = 1; /* PEER_STATE_CHANGE */
    obs->trust_tier = 0; /* GREEN */
    obs->timestamp_ns = now_ns();
    obs->sequence = seq;

    int len = snprintf(obs->payload, sizeof(obs->payload),
        "{"
        "\"domain\":\"bgp\","
        "\"event\":\"peer_state_change\","
        "\"peer_ip\":\"10.0.0.51\","
        "\"peer_as\":65001,"
        "\"local_as\":65000,"
        "\"old_state\":\"Active\","
        "\"new_state\":\"Established\","
        "\"router_id\":\"10.0.0.50\""
        "}");
    obs->payload_len = (uint32_t)len;
}

static void build_bestpath_obs(struct virp_observation *obs, uint32_t seq)
{
    memset(obs, 0, sizeof(*obs));
    obs->magic = htonl(VIRP_MAGIC);
    obs->version = VIRP_VERSION;
    obs->obs_type = 4; /* BESTPATH_CHANGE */
    obs->trust_tier = 0; /* GREEN */
    obs->timestamp_ns = now_ns();
    obs->sequence = seq;

    int len = snprintf(obs->payload, sizeof(obs->payload),
        "{"
        "\"domain\":\"bgp\","
        "\"event\":\"bestpath_change\","
        "\"prefix\":\"192.168.100.0/24\","
        "\"afi\":1,\"safi\":1,"
        "\"router_id\":\"10.0.0.50\","
        "\"old\":{"
          "\"peer_ip\":\"10.0.0.52\","
          "\"peer_as\":65002,"
          "\"nexthop\":\"10.0.0.52\","
          "\"as_path\":\"65002 65010\","
          "\"med\":0,\"local_pref\":100,\"origin\":0"
        "},"
        "\"new\":{"
          "\"peer_ip\":\"10.0.0.51\","
          "\"peer_as\":65001,"
          "\"nexthop\":\"10.0.0.51\","
          "\"as_path\":\"65001 65010\","
          "\"med\":0,\"local_pref\":200,\"origin\":0"
        "}"
        "}");
    obs->payload_len = (uint32_t)len;
}

static void build_peer_down_obs(struct virp_observation *obs, uint32_t seq)
{
    memset(obs, 0, sizeof(*obs));
    obs->magic = htonl(VIRP_MAGIC);
    obs->version = VIRP_VERSION;
    obs->obs_type = 2; /* PEER_BACKWARD_TRANS */
    obs->trust_tier = 1; /* YELLOW */
    obs->timestamp_ns = now_ns();
    obs->sequence = seq;

    int len = snprintf(obs->payload, sizeof(obs->payload),
        "{"
        "\"domain\":\"bgp\","
        "\"event\":\"peer_down\","
        "\"peer_ip\":\"10.0.0.53\","
        "\"peer_as\":65003,"
        "\"local_as\":65000,"
        "\"last_state\":\"Established\","
        "\"last_event\":13,"
        "\"uptime\":86400,"
        "\"router_id\":\"10.0.0.50\""
        "}");
    obs->payload_len = (uint32_t)len;
}

static void build_tampered_obs(struct virp_observation *obs, uint32_t seq)
{
    /* Build valid observation, then corrupt it */
    build_peer_state_obs(obs, seq);
    /* We'll sign it first, then tamper with the payload */
}

/* ---- Socket test ---- */

static int try_send_onode(const char *socket_path,
                          struct virp_observation *obs)
{
    struct sockaddr_un addr;
    int fd;
    size_t header_plus_payload;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("  Socket create failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("  O-Node connect failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /*
     * Wire format: [header 24B][payload N bytes][HMAC 32B]
     * The HMAC lives at the end of the struct (after the full 4096B
     * payload buffer), so we can't just write the struct contiguously.
     * Send header+payload first, then the HMAC separately.
     */
    header_plus_payload = offsetof(struct virp_observation, payload)
                          + obs->payload_len;

    /* Send header + payload */
    ssize_t sent = write(fd, obs, header_plus_payload);
    if (sent < 0 || (size_t)sent != header_plus_payload) {
        printf("  Write (header+payload) failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* Send HMAC */
    ssize_t sent2 = write(fd, obs->hmac, VIRP_HMAC_LEN);
    if (sent2 < 0 || (size_t)sent2 != VIRP_HMAC_LEN) {
        printf("  Write (HMAC) failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    printf("  Sent %zd bytes to O-Node\n", sent + sent2);
    return 0;
}

/* ---- Main ---- */

int main(int argc, char **argv)
{
    const char *key_path = NULL;
    const char *socket_path = NULL;
    uint8_t key[64];
    size_t key_len = 0;

    /* Parse args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            key_path = argv[++i];
        else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc)
            socket_path = argv[++i];
    }

    if (!key_path) {
        fprintf(stderr, "Usage: %s --key <keyfile> [--socket <path>]\n",
                argv[0]);
        return 1;
    }

    /* Load key */
    FILE *f = fopen(key_path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open key file: %s\n", strerror(errno));
        return 1;
    }
    key_len = fread(key, 1, sizeof(key), f);
    fclose(f);
    if (key_len > 0 && key[key_len - 1] == '\n')
        key_len--;
    printf("Loaded %zu-byte HMAC key from %s\n\n", key_len, key_path);

    int pass = 0, fail = 0;
    struct virp_observation obs;

    /* ---- Test 1: Peer state change ---- */
    printf("TEST 1: Peer state change observation\n");
    build_peer_state_obs(&obs, 1);
    if (sign_observation(&obs, key, key_len) == 0) {
        printf("  Signed OK — HMAC: ");
        hex_dump(obs.hmac, 16);
        printf("...\n");
        printf("  Payload: %.*s\n", obs.payload_len, obs.payload);
        if (verify_observation(&obs, key, key_len) == 0) {
            printf("  Verify: PASS\n");
            pass++;
        } else {
            printf("  Verify: FAIL\n");
            fail++;
        }
    } else {
        printf("  Sign: FAIL\n");
        fail++;
    }
    printf("\n");

    /* ---- Test 2: Bestpath change ---- */
    printf("TEST 2: Best-path change observation\n");
    build_bestpath_obs(&obs, 2);
    if (sign_observation(&obs, key, key_len) == 0) {
        printf("  Signed OK — HMAC: ");
        hex_dump(obs.hmac, 16);
        printf("...\n");
        printf("  Payload: %.*s\n", obs.payload_len, obs.payload);
        if (verify_observation(&obs, key, key_len) == 0) {
            printf("  Verify: PASS\n");
            pass++;
        } else {
            printf("  Verify: FAIL\n");
            fail++;
        }
    } else {
        printf("  Sign: FAIL\n");
        fail++;
    }
    printf("\n");

    /* ---- Test 3: Peer down (YELLOW tier) ---- */
    printf("TEST 3: Peer backward transition (YELLOW)\n");
    build_peer_down_obs(&obs, 3);
    if (sign_observation(&obs, key, key_len) == 0) {
        printf("  Signed OK — trust_tier=%d (YELLOW)\n", obs.trust_tier);
        printf("  Payload: %.*s\n", obs.payload_len, obs.payload);
        if (verify_observation(&obs, key, key_len) == 0) {
            printf("  Verify: PASS\n");
            pass++;
        } else {
            printf("  Verify: FAIL\n");
            fail++;
        }
    } else {
        printf("  Sign: FAIL\n");
        fail++;
    }
    printf("\n");

    /* ---- Test 4: Tamper detection ---- */
    printf("TEST 4: Tamper detection\n");
    build_tampered_obs(&obs, 4);
    sign_observation(&obs, key, key_len);
    printf("  Signed OK, now corrupting payload...\n");
    /* Flip a byte in the payload */
    obs.payload[20] ^= 0xFF;
    if (verify_observation(&obs, key, key_len) != 0) {
        printf("  Tamper detected: PASS (HMAC mismatch)\n");
        pass++;
    } else {
        printf("  Tamper NOT detected: FAIL\n");
        fail++;
    }
    printf("\n");

    /* ---- Test 5: Sequence monotonicity ---- */
    printf("TEST 5: Sequence monotonicity\n");
    struct virp_observation obs_a, obs_b;
    build_peer_state_obs(&obs_a, 100);
    build_peer_state_obs(&obs_b, 101);
    sign_observation(&obs_a, key, key_len);
    sign_observation(&obs_b, key, key_len);
    if (obs_b.sequence > obs_a.sequence &&
        obs_b.timestamp_ns >= obs_a.timestamp_ns) {
        printf("  seq %u < %u, timestamps ordered: PASS\n",
               obs_a.sequence, obs_b.sequence);
        pass++;
    } else {
        printf("  Ordering check: FAIL\n");
        fail++;
    }
    printf("\n");

    /* ---- Test 6: O-Node socket (optional) ---- */
    if (socket_path) {
        printf("TEST 6: O-Node socket delivery\n");
        build_bestpath_obs(&obs, 200);
        sign_observation(&obs, key, key_len);
        if (try_send_onode(socket_path, &obs) == 0) {
            printf("  O-Node delivery: PASS\n");
            pass++;
        } else {
            printf("  O-Node delivery: FAIL (is O-Node running?)\n");
            fail++;
        }
        printf("\n");
    }

    /* ---- Summary ---- */
    printf("========================================\n");
    printf("VIRP BGP Observation Signing Tests\n");
    printf("  PASS: %d  FAIL: %d\n", pass, fail);
    printf("========================================\n");

    return fail > 0 ? 1 : 0;
}
