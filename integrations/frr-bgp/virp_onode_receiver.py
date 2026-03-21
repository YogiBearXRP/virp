#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
VIRP O-Node Test Receiver for BGP Observations

Minimal receiver that listens on a Unix socket, accepts signed
observations from the bgp_virp FRR module, verifies HMAC-SHA256
signatures, and logs results to stdout.

For testing the FRR integration before connecting to the production
O-Node on CT 211.

Usage:
    # Generate matching key on FRR host and here
    echo -n "your-hmac-key" > /etc/virp/bgp.key

    # Start receiver
    python3 virp_onode_receiver.py

    # Or with custom paths
    python3 virp_onode_receiver.py --socket /tmp/virp-onode.sock --key /etc/virp/bgp.key

    # With chain.db logging (SQLite)
    python3 virp_onode_receiver.py --db /var/lib/virp/chain.db

Copyright (C) 2026 Third Level IT LLC / Nate Howard
VIRP Specification: draft-howard-virp-01
"""

import argparse
import hashlib
import hmac
import json
import os
import signal
import socket
import sqlite3
import struct
import sys
import time
from datetime import datetime, timezone

# Wire format constants
VIRP_MAGIC = 0x56495250       # "VIRP"
VIRP_VERSION = 1
HEADER_SIZE = 24               # 4+1+1+1+1+8+4+4
HMAC_LEN = 32

TIER_NAMES = {0: "GREEN", 1: "YELLOW", 2: "RED", 3: "BLACK"}
OBS_TYPE_NAMES = {
    1: "PEER_STATE_CHANGE",
    2: "PEER_BACKWARD_TRANS",
    3: "ROUTE_PROCESS",
    4: "BESTPATH_CHANGE",
}


def load_key(path: str) -> bytes:
    """Load HMAC key from file, stripping trailing newline."""
    with open(path, "r") as f:
        key = f.read()
    key = key.rstrip("\n")
    return key.encode("utf-8")


def verify_hmac(signed_data: bytes, received_hmac: bytes, key: bytes) -> bool:
    """Verify HMAC-SHA256 over observation data."""
    computed = hmac.new(key, signed_data, hashlib.sha256).digest()
    return hmac.compare_digest(computed, received_hmac)


def init_chain_db(db_path: str) -> sqlite3.Connection:
    """Initialize SQLite chain database for persistent storage."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sequence INTEGER NOT NULL,
            obs_type INTEGER NOT NULL,
            obs_type_name TEXT,
            trust_tier INTEGER NOT NULL,
            trust_tier_name TEXT,
            timestamp_ns INTEGER NOT NULL,
            timestamp_human TEXT,
            payload TEXT NOT NULL,
            hmac_hex TEXT NOT NULL,
            verified INTEGER NOT NULL,
            received_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_obs_sequence
        ON observations(sequence)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_obs_type
        ON observations(obs_type)
    """)
    conn.commit()
    return conn


def store_observation(conn: sqlite3.Connection, seq: int, obs_type: int,
                      trust_tier: int, timestamp_ns: int, payload: str,
                      hmac_hex: str, verified: bool):
    """Insert a verified observation into chain.db."""
    ts_human = datetime.fromtimestamp(
        timestamp_ns / 1e9, tz=timezone.utc
    ).isoformat()

    conn.execute(
        """INSERT INTO observations
           (sequence, obs_type, obs_type_name, trust_tier, trust_tier_name,
            timestamp_ns, timestamp_human, payload, hmac_hex, verified)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            seq,
            obs_type,
            OBS_TYPE_NAMES.get(obs_type, "UNKNOWN"),
            trust_tier,
            TIER_NAMES.get(trust_tier, "UNKNOWN"),
            timestamp_ns,
            ts_human,
            payload,
            hmac_hex,
            1 if verified else 0,
        ),
    )
    conn.commit()


def recv_exact(conn: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed mid-read")
        data += chunk
    return data


def handle_connection(conn: socket.socket, key: bytes,
                      db: sqlite3.Connection | None, stats: dict):
    """Process one incoming observation from the FRR module."""
    try:
        header = recv_exact(conn, HEADER_SIZE)

        # Parse header
        magic = struct.unpack("!I", header[0:4])[0]
        if magic != VIRP_MAGIC:
            print(f"  [REJECT] Bad magic: {magic:#010x} (expected 0x56495250)")
            stats["rejected"] += 1
            return

        version = header[4]
        obs_type = header[5]
        trust_tier = header[6]
        timestamp_ns = struct.unpack("Q", header[8:16])[0]
        sequence = struct.unpack("I", header[16:20])[0]
        payload_len = struct.unpack("I", header[20:24])[0]

        if version != VIRP_VERSION:
            print(f"  [REJECT] Unknown version: {version}")
            stats["rejected"] += 1
            return

        if payload_len > 4096:
            print(f"  [REJECT] Payload too large: {payload_len}")
            stats["rejected"] += 1
            return

        # Read payload + HMAC
        remaining = recv_exact(conn, payload_len + HMAC_LEN)
        payload_bytes = remaining[:payload_len]
        received_hmac = remaining[payload_len : payload_len + HMAC_LEN]

        # Verify HMAC over header + payload
        signed_data = header + payload_bytes
        valid = verify_hmac(signed_data, received_hmac, key)

        # Format output
        tier_name = TIER_NAMES.get(trust_tier, f"UNKNOWN({trust_tier})")
        type_name = OBS_TYPE_NAMES.get(obs_type, f"UNKNOWN({obs_type})")
        ts_human = datetime.fromtimestamp(
            timestamp_ns / 1e9, tz=timezone.utc
        ).strftime("%H:%M:%S.%f")[:-3]
        hmac_hex = received_hmac.hex()

        status = "VERIFIED" if valid else "!! INVALID !!"

        payload_str = payload_bytes.decode("utf-8", errors="replace")

        # Pretty-print the payload JSON
        try:
            payload_obj = json.loads(payload_str)
            event = payload_obj.get("event", "unknown")
        except json.JSONDecodeError:
            event = "parse_error"

        print(
            f"  [{status}] seq={sequence:>5d} | {ts_human} | "
            f"{type_name:<22s} | {tier_name:<6s} | {event}"
        )

        if not valid:
            print(f"           HMAC expected != received — possible tampering")
            stats["invalid"] += 1
        else:
            stats["verified"] += 1

        # Store in chain.db if available
        if db is not None:
            store_observation(
                db, sequence, obs_type, trust_tier, timestamp_ns,
                payload_str, hmac_hex, valid
            )

        # Detailed output for bestpath changes
        if valid and obs_type == 4 and event == "bestpath_change":
            try:
                old = payload_obj.get("old")
                new = payload_obj.get("new")
                prefix = payload_obj.get("prefix", "?")
                if old and new:
                    print(
                        f"           {prefix}: "
                        f"NH {old.get('nexthop','?')} → {new.get('nexthop','?')} | "
                        f"AS {old.get('as_path','?')} → {new.get('as_path','?')} | "
                        f"LP {old.get('local_pref','?')} → {new.get('local_pref','?')}"
                    )
                elif new and not old:
                    print(
                        f"           {prefix}: NEW best via "
                        f"{new.get('nexthop','?')} AS [{new.get('as_path','?')}]"
                    )
                elif old and not new:
                    print(
                        f"           {prefix}: LOST best — was via "
                        f"{old.get('nexthop','?')}"
                    )
            except Exception:
                pass

    except ConnectionError:
        pass  # Client disconnected normally
    except Exception as e:
        print(f"  [ERROR] {e}")
        stats["errors"] += 1


def print_stats(stats: dict):
    """Print running statistics."""
    total = stats["verified"] + stats["invalid"] + stats["rejected"]
    print(
        f"\n  --- Stats: {total} received | "
        f"{stats['verified']} verified | "
        f"{stats['invalid']} invalid HMAC | "
        f"{stats['rejected']} rejected | "
        f"{stats['errors']} errors ---\n"
    )


def main():
    parser = argparse.ArgumentParser(
        description="VIRP O-Node test receiver for BGP observations"
    )
    parser.add_argument(
        "--socket", default="/tmp/virp-onode.sock",
        help="Unix socket path (default: /tmp/virp-onode.sock)"
    )
    parser.add_argument(
        "--key", default="/etc/virp/bgp.key",
        help="HMAC key file path (default: /etc/virp/bgp.key)"
    )
    parser.add_argument(
        "--db", default=None,
        help="SQLite chain.db path for persistent storage (optional)"
    )
    args = parser.parse_args()

    # Load key
    try:
        key = load_key(args.key)
        print(f"Loaded {len(key)}-byte HMAC key from {args.key}")
    except FileNotFoundError:
        print(f"ERROR: Key file not found: {args.key}")
        print(f"  Create one with: echo -n 'your-key' > {args.key}")
        sys.exit(1)

    # Init chain.db if requested
    db = None
    if args.db:
        os.makedirs(os.path.dirname(args.db) or ".", exist_ok=True)
        db = init_chain_db(args.db)
        print(f"Chain database: {args.db}")

    # Clean up old socket
    if os.path.exists(args.socket):
        os.unlink(args.socket)

    # Create listening socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(args.socket)
    os.chmod(args.socket, 0o660)
    sock.listen(16)

    stats = {"verified": 0, "invalid": 0, "rejected": 0, "errors": 0}
    obs_since_stats = 0

    print(f"VIRP O-Node receiver listening on {args.socket}")
    print(f"Waiting for signed BGP observations from bgpd_virp module...\n")
    print(f"  {'STATUS':<14s} | {'SEQ':>5s} | {'TIME':<12s} | "
          f"{'TYPE':<22s} | {'TIER':<6s} | EVENT")
    print(f"  {'-'*14}---{'-'*5}---{'-'*12}---{'-'*22}---{'-'*6}---{'-'*20}")

    def handle_signal(sig, frame):
        print(f"\n\nShutting down...")
        print_stats(stats)
        sock.close()
        if os.path.exists(args.socket):
            os.unlink(args.socket)
        if db:
            db.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    while True:
        try:
            conn, _ = sock.accept()
            handle_connection(conn, key, db, stats)
            conn.close()

            obs_since_stats += 1
            if obs_since_stats >= 25:
                print_stats(stats)
                obs_since_stats = 0

        except Exception as e:
            print(f"  [ERROR] Accept failed: {e}")


if __name__ == "__main__":
    main()
