# VIRP BGP Module — FRR Integration Guide
## draft-howard-virp-01 Reference Implementation: BGP Domain

### Architecture

```
┌─────────────────────────────────────────────────┐
│  FRR bgpd process                               │
│                                                  │
│  BGP FSM ──► peer_status_changed ──┐             │
│  BGP FSM ──► peer_backward_trans ──┤             │
│  RIB     ──► bgp_process ─────────┤  bgp_virp   │
│  RIB     ──► bgp_route_update ────┘  module      │
│                  │                               │
│           HMAC-SHA256 sign                       │
│                  │                               │
└──────────────────┼───────────────────────────────┘
                   │ Unix socket
                   ▼
           ┌──────────────┐
           │   O-Node      │
           │  chain.db     │
           │  (CT 211)     │
           └──────────────┘
```

### What Gets Signed

| Hook                      | Obs Type | Tier   | Data Captured                                    |
|---------------------------|----------|--------|--------------------------------------------------|
| `peer_status_changed`     | 1        | GREEN  | Peer IP/AS, old→new FSM state, router-id         |
| `peer_backward_transition`| 2        | YELLOW | Peer dropped from Established — alert grade      |
| `bgp_process`             | 3        | GREEN  | Prefix announce/withdraw, peer, AFI/SAFI         |
| `bgp_route_update`        | 4        | GREEN  | Old/new best-path with full attrs (AS path, NH, MED, LP) |

### Files

```
bgpd/bgp_virp.h         # Header — observation structs, config, enums
bgpd/bgp_virp.c         # Module — hook handlers, signing, VTY commands
bgpd/virp_bgp_test.c    # Standalone test harness (compiles without FRR)
```

---

## Step 1: Standalone Signing Test (Already Passing)

```bash
# On any Linux box with OpenSSL
gcc -o virp_bgp_test virp_bgp_test.c -lssl -lcrypto -Wall -O2
echo -n "your-hmac-key-here" > /tmp/virp-test.key
./virp_bgp_test --key /tmp/virp-test.key
```

Expected: 5/5 PASS — signing, verification, tamper detection, ordering.

---

## Step 2: Add to FRR Build System

### Option A: Build as Loadable Module (Recommended)

Add to `bgpd/subdir.am`:

```makefile
# VIRP observation module
if BGPD
module_LTLIBRARIES += bgpd/bgpd_virp.la
endif

bgpd_bgpd_virp_la_SOURCES = bgpd/bgp_virp.c
bgpd_bgpd_virp_la_LIBADD = -lssl -lcrypto
bgpd_bgpd_virp_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
```

Then rebuild:

```bash
cd /path/to/frr
./bootstrap.sh
./configure --enable-bgp-virp    # or just rebuild
make -j$(nproc)
sudo make install
```

### Option B: Compile Directly Into bgpd

Add to `bgpd/subdir.am` under `bgpd_bgpd_SOURCES`:

```makefile
bgpd_bgpd_SOURCES += bgpd/bgp_virp.c
```

Add `-lssl -lcrypto` to `bgpd_bgpd_LDADD`.

---

## Step 3: Deploy on Your GNS3 Lab

### 3a. Create HMAC Key

```bash
# On CT 211 (ironclaw-onode) — generate a proper key
openssl rand -hex 32 > /etc/virp/bgp.key
chmod 600 /etc/virp/bgp.key

# Copy same key to FRR host
scp /etc/virp/bgp.key frr-host:/etc/virp/bgp.key
```

### 3b. Configure FRR

```
router bgp 65000
  virp hmac-key /etc/virp/bgp.key
  virp onode-socket /tmp/virp-onode.sock
  virp enable
!
```

### 3c. Verify

```
show bgp virp status
show bgp virp statistics
```

### 3d. Test with Lab Events

```bash
# On a neighbor router, shut/no shut the BGP peer
# Watch for signed observations:

# On FRR host, check syslog
journalctl -u frr -f | grep VIRP

# Expected observations:
#   VIRP[1]: type=1 tier=0  (peer going to Established)
#   VIRP[2]: type=2 tier=1  (peer backward transition — YELLOW)
#   VIRP[3]: type=4 tier=0  (bestpath recalculation)
```

---

## Step 4: O-Node Integration

The module sends signed observations to the O-Node Unix socket in
this wire format:

```
Bytes 0-3:    Magic (0x56495250 "VIRP", network byte order)
Byte  4:      Version (1)
Byte  5:      Observation type (1-4)
Byte  6:      Trust tier (0=GREEN, 1=YELLOW, 2=RED, 3=BLACK)
Byte  7:      Padding
Bytes 8-15:   Timestamp (nanosecond epoch, host byte order)
Bytes 16-19:  Sequence number (host byte order)
Bytes 20-23:  Payload length (host byte order)
Bytes 24-N:   JSON payload (variable length)
Bytes N-N+32: HMAC-SHA256 (covers bytes 0 through end of payload)
```

The O-Node receiver on CT 211 needs to:
1. Read the header (24 bytes) to get payload_len
2. Read payload_len bytes of JSON
3. Read 32 bytes of HMAC
4. Verify HMAC over bytes 0 through end of payload
5. Insert into chain.db if valid

### Minimal O-Node Receiver (Python, for testing)

```python
#!/usr/bin/env python3
"""Minimal VIRP O-Node receiver for testing bgp_virp module."""

import socket, struct, hmac, hashlib, json, os, sys

SOCK_PATH = "/tmp/virp-onode.sock"
KEY_PATH = "/etc/virp/bgp.key"
HEADER_SIZE = 24  # magic(4) + ver(1) + type(1) + tier(1) + pad(1) + ts(8) + seq(4) + plen(4)
HMAC_LEN = 32

def load_key(path):
    with open(path, 'r') as f:
        key = f.read().strip()
    return key.encode()

def verify_hmac(data, received_hmac, key):
    computed = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(computed, received_hmac)

def main():
    key = load_key(KEY_PATH)
    
    if os.path.exists(SOCK_PATH):
        os.unlink(SOCK_PATH)
    
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(SOCK_PATH)
    sock.listen(5)
    print(f"VIRP O-Node listening on {SOCK_PATH}")
    
    while True:
        conn, _ = sock.accept()
        try:
            # Read header
            header = conn.recv(HEADER_SIZE)
            if len(header) < HEADER_SIZE:
                continue
            
            magic = struct.unpack('!I', header[0:4])[0]
            if magic != 0x56495250:
                print(f"Bad magic: {magic:#x}")
                continue
            
            version = header[4]
            obs_type = header[5]
            trust_tier = header[6]
            timestamp_ns = struct.unpack('Q', header[8:16])[0]
            sequence = struct.unpack('I', header[16:20])[0]
            payload_len = struct.unpack('I', header[20:24])[0]
            
            # Read payload + HMAC
            remaining = conn.recv(payload_len + HMAC_LEN)
            payload = remaining[:payload_len]
            received_hmac = remaining[payload_len:payload_len + HMAC_LEN]
            
            # Verify
            signed_data = header + payload
            valid = verify_hmac(signed_data, received_hmac, key)
            
            tier_names = {0: "GREEN", 1: "YELLOW", 2: "RED", 3: "BLACK"}
            status = "VERIFIED" if valid else "INVALID"
            
            print(f"[{status}] seq={sequence} type={obs_type} "
                  f"tier={tier_names.get(trust_tier, '?')} "
                  f"payload={payload.decode()}")
            
        except Exception as e:
            print(f"Error: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    main()
```

---

## Step 5: What This Proves for the RFC

With this running on your GNS3 lab (R1-R35), you demonstrate:

1. **VIRP signs at collection time** — the HMAC happens inside bgpd's
   process space, at the moment the BGP event fires. Not after the fact.

2. **Observation-only** — the module registers read-only hooks. It cannot
   modify routes, peer state, or configuration. Pure attestation.

3. **Protocol-agnostic framing** — the observation structure and signing
   work identically whether the source is BGP, DNS, or IPsec. The
   `domain` field in the JSON payload is the only thing that changes.

4. **Trust tiers in practice** — peer_backward_transition automatically
   gets YELLOW tier, normal operations get GREEN. The tier assignment
   happens at the source, not at analysis time.

5. **Tamper detection** — any modification to the observation between
   bgpd and the O-Node is caught by HMAC verification.

---

## Next: DNS (Unbound Plugin) and IPsec (strongSwan)

The observation structure, signing, and O-Node protocol are identical.
Only the hook points and JSON payloads change per domain. This is the
key argument for the RFC — VIRP is domain-agnostic by design.
