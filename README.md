> **VIRP does not let AI speak first. Reality speaks first, inside a bound session.**

# VIRP — Verified Infrastructure Response Protocol

**Cryptographic trust primitives for AI agents operating on real infrastructure.**

When an AI agent tells you your firewall policy is misconfigured, can you prove it actually checked?

When it says a BGP session is established, did it read that from a real device — or fabricate it?

When it claims a config change succeeded, where's the evidence?

**VIRP makes every agent claim verifiable. Not with prompts. Not with guardrails. With cryptography.**

---

## What VIRP Does

VIRP is an open protocol that signs every device observation at the point of collection, before the AI ever sees it.

A dedicated process — the **O-Node** — connects to your network devices, captures raw output, and signs it with HMAC-SHA256. The AI agent receives pre-signed data. It can reason about what the device returned. It cannot forge it, modify it, or fabricate it — because it never holds the signing key.

This is not a policy. It is a code path.

```
Agent: "FortiGate policy 2 allows all traffic with no AV/IPS."

VIRP:
  verdict:       VERIFIED
  HMAC:          da383afe...c18
  chain_seq:     4882
  session_id:    f84c1a3e...
  device_id:     0x00000002  (FW-01)
  command_hash:  7c2b4d3a... (show firewall policy 2)
  timestamp:     2026-03-11T14:30:22.917384Z

  Verify it yourself.
```

---

## Why This Exists

During development of IronClaw, we observed an AI system:

- Generating firewall policies with valid UUIDs that did not exist
- Reporting threats from RFC 5737 documentation addresses
- Proposing routing changes based on fabricated OSPF adjacency states

Every output was technically plausible. None of it was real.

Prompt engineering, output validation, and behavioral guardrails did not fix it. The AI fabricated output directly in its response text without invoking the signed execution path.

**VIRP is the structural fix.**

---

## Architecture

```
┌─────────────────────┐      ┌─────────────────────┐
│   AI Node (CT 210)  │      │   O-Node (CT 211)   │
│                     │      │                     │
│  Agent + LLM        │─────▶│  VIRP C Library     │
│                     │      │  Device Credentials │
│  Zero credentials   │      │  Signing Keys       │
│  Zero signing keys  │◀─────│  Chain Database     │
└─────────────────────┘      └──────────┬──────────┘
                                        │ SSH
                             ┌──────────┼──────────┐
                         Cisco IOS  FortiGate   PA-850
```

**The Cage** — three structural walls enforce isolation:

| Wall | Mechanism |
|---|---|
| 1 | AI node has no network route to devices |
| 2 | Device ACLs accept SSH from O-Node IP only |
| 3 | O-Node socket locked to authorized processes |

---

## Seven Trust Primitives

| # | Name | What It Does | Status |
|---|---|---|---|
| P1 | Verified Observation | Device output HMAC-signed at collection | Production |
| P2 | Tiered Authorization | Command classification enforced below AI | Production |
| P3 | Verified Intent | Signed proposals before execution | Implemented |
| P4 | Verified Outcome | Before/after signed comparison | Implemented |
| P5 | Baseline Memory | Deviation detection from signed history | Implemented |
| P6 | Trust Chain | SQLite tamper-evident chain | Implemented |
| P7 | Trust Federation | Ed25519 cross-tenant verification | Implemented |

---

## Quick Start

```bash
# Dependencies
sudo apt install -y build-essential git \
  libssl-dev libsodium-dev libsqlite3-dev \
  libssh2-1-dev libcurl4-openssl-dev libjson-c-dev

# Build
git clone https://github.com/nhowardtli/virp.git && cd virp
make CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1
make CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1 prod

# Test
make all-tests
make test-session
make test-session-key

# Deploy
./build/virp-tool keygen -o /etc/virp/keys/onode.key
./build/virp-onode-prod \
  -k /etc/virp/keys/onode.key \
  -s /tmp/virp-onode.sock \
  -d /etc/virp/devices.json \
  -c /var/lib/virp/chain.db
```

Systemd service: `deploy/virp-onode.service`

---

## Production Results

Tested on real hardware:

- 40 devices under active VIRP management
- 35-router BGP topology, full verification under 60 seconds
- FortiGate audit: 15 real findings, zero false positives
- Fabrication is prevented by the protocol design, assuming the O-Node is trusted and uncompromised

---

## Documentation

| Topic | Location |
|---|---|
| How a query becomes a signed observation | [Wiki: Observation Flow](../../wiki/Observation-Flow-End-to-End) |
| Session handshake deep dive | [Wiki: Session Establishment](../../wiki/Session-Establishment) |
| Wire format v1 and v2 | [Wiki: Wire Format Reference](../../wiki/Wire-Format-Reference) |
| Security architecture (The Cage) | [Wiki: The Cage](../../wiki/The-Cage-Security-Architecture) |
| Hardened KVM deployment | [Wiki: KVM Deployment](../../wiki/KVM-Hardened-Deployment) |
| Threat model | [Wiki: Threat Model](../../wiki/Threat-Model) |
| Trust tiers explained | [Wiki: Trust Tiers](../../wiki/Trust-Tiers) |
| Adding devices | [Wiki: Device Onboarding](../../wiki/Device-Onboarding) |
| FAQ | [Wiki: FAQ](../../wiki/FAQ) |
| Protocol specification | `VIRP-SPEC-RFC-v2.md` |
| Wire format specification | `VIRP-WIRE-FORMAT.md` |

---

## What's In The Box

- **C library (libvirp)** — ~8,500 lines, C11, `-Wall -Wextra -Werror -pedantic`
- **Vendor drivers** — Cisco IOS, FortiOS, PAN-OS, Cisco ASA, Linux
- **Go implementation** — 2,700+ lines, identical wire format, interop tested
- **Session handshake** — HELLO/HELLO_ACK/SESSION_BIND state machine
- **HKDF session keys** — master key never signs runtime observations directly
- **Trust chain** — SQLite, tamper-evident, crash-safe
- **Federation** — Ed25519 via libsodium
- **46 tests** — unit, integration, interop, fuzz, negative-path session tests

---

## Protocol Specification

- **RFC Draft:** `draft-howard-virp-02`
- **IETF RATS:** submitted
- **Zenodo DOI:** registered
- **License:** Apache 2.0

---

## Contributing

Infrastructure engineers · Security researchers · Driver authors (Juniper, Arista, Meraki, cloud APIs) · Protocol designers

**Nathan M. Howard** — Third Level IT LLC — nhoward@thirdlevelit.com

---

> *"A responsible system does not guess when evidence is absent.*
> *It says: I don't know, and here's why."*
