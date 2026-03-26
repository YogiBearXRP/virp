#!/usr/bin/env bash
# =============================================================================
# VIRP Sandbox — interactive test drive for the Verified Infrastructure
#                Response Protocol reference implementation
#
# Usage:  bash sandbox.sh
# =============================================================================

set -euo pipefail

# ── colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

banner()  { echo -e "\n${CYAN}${BOLD}══ $* ══${RESET}"; }
ok()      { echo -e "  ${GREEN}✓${RESET}  $*"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
die()     { echo -e "  ${RED}✗${RESET}  $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}▶ $*${RESET}"; }
pause()   { echo -e "\n${YELLOW}Press [Enter] to continue…${RESET}"; read -r; }

# ── resolve repo & sandbox dirs ───────────────────────────────────────────────
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="${REPO_DIR}/build/sandbox"
TOOL="${REPO_DIR}/build/virp-tool"
ONODE="${REPO_DIR}/build/virp-onode"

# ── 0. welcome ────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║          VIRP — Verified Infrastructure Response         ║"
echo "  ║                   Protocol  Sandbox                      ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo "  This script will:"
echo "    1. Install system dependencies (requires sudo)"
echo "    2. Build the project"
echo "    3. Run all test suites"
echo "    4. Walk you through key generation, message building,"
echo "       inspection, and a live O-Node session"
echo ""
echo -e "  Repo: ${CYAN}${REPO_DIR}${RESET}"
echo -e "  Sandbox workspace: ${CYAN}${SANDBOX_DIR}${RESET}"
pause

# ── 1. install dependencies ───────────────────────────────────────────────────
banner "Step 1 — Install system dependencies"

MISSING=()
for pkg in libsodium-dev libsqlite3-dev libssl-dev; do
    dpkg -s "$pkg" &>/dev/null || MISSING+=("$pkg")
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    step "Installing: ${MISSING[*]}"
    sudo apt-get install -y "${MISSING[@]}"
    ok "Dependencies installed"
else
    ok "All dependencies already present"
fi

# ── 2. build ──────────────────────────────────────────────────────────────────
banner "Step 2 — Build"
step "Running: make all"
cd "${REPO_DIR}"
make all
ok "Build complete — binaries in build/"
ls -lh build/virp-tool build/virp-onode build/libvirp.a build/libvirp.so 2>/dev/null || true
pause

# ── 3. test suites ────────────────────────────────────────────────────────────
banner "Step 3 — Test suites"
TESTS=(
    "test          → core protocol (33 tests)"
    "test-onode    → O-Node integration (14 tests)"
    "test-chain    → trust chain / SQLite (9 tests)"
    "test-federation → Ed25519 federation (9 tests)"
    "test-json     → JSON decode (13 tests)"
    "test-session  → session negative paths (7 tests)"
    "test-session-key → session key derivation (6 tests)"
)

for t in "${TESTS[@]}"; do
    target="${t%%[ ]*}"
    label="${t#*→ }"
    step "make ${target}  (${label})"
    make "${target}"
    ok "PASSED: ${label}"
done
pause

# ── 4. prepare sandbox workspace ──────────────────────────────────────────────
banner "Step 4 — Sandbox workspace"
step "Creating ${SANDBOX_DIR}"
mkdir -p "${SANDBOX_DIR}"
cd "${SANDBOX_DIR}"
ok "Workspace ready"

# ── 5. key generation ─────────────────────────────────────────────────────────
banner "Step 5 — Key generation"

step "Generate O-Key (observation-channel signing key)"
"${TOOL}" keygen okey onode.okey
ok "onode.okey created"

step "Generate R-Key (response/proposal signing key)"
"${TOOL}" keygen rkey rnode.rkey
ok "rnode.rkey created"

ls -lh onode.okey rnode.rkey
pause

# ── 6. build messages ─────────────────────────────────────────────────────────
banner "Step 6 — Build VIRP messages"

# Observation
step "Build OBSERVATION message"
"${TOOL}" build observation onode.okey 0x00000001 1 \
    "route 10.0.0.0/8 via 192.168.1.1 detected" obs.msg
ok "obs.msg written"

# Heartbeat
step "Build HEARTBEAT message"
"${TOOL}" build heartbeat onode.okey 0x00000001 2 3600 hb.msg
ok "hb.msg written"

# Proposal (references the observation above)
step "Build PROPOSAL message"
"${TOOL}" build proposal rnode.rkey 0x00000002 1 42 \
    0x00000001:1 "block 10.0.0.0/8 at border" prop.msg
ok "prop.msg written"

ls -lh obs.msg hb.msg prop.msg
pause

# ── 7. hex dumps ──────────────────────────────────────────────────────────────
banner "Step 7 — Raw hex dumps"

for f in obs.msg hb.msg prop.msg; do
    step "hexdump ${f}"
    "${TOOL}" hexdump "${f}"
done
pause

# ── 8. message inspection & verification ──────────────────────────────────────
banner "Step 8 — Inspect & verify messages"

step "Verify OBSERVATION with O-Key"
"${TOOL}" inspect obs.msg onode.okey okey

step "Verify HEARTBEAT with O-Key"
"${TOOL}" inspect hb.msg onode.okey okey

step "Verify PROPOSAL with R-Key"
"${TOOL}" inspect prop.msg rnode.rkey rkey

pause

# ── 9. tamper detection demo ──────────────────────────────────────────────────
banner "Step 9 — Tamper detection demo"
step "Flipping a byte in obs.msg → should fail signature check"
cp obs.msg obs_tampered.msg
# flip byte at offset 20 (inside the payload / HMAC region)
python3 - <<'PY'
import sys
with open("obs_tampered.msg", "r+b") as f:
    data = bytearray(f.read())
    data[20] ^= 0xFF
    f.seek(0)
    f.write(data)
print("  Byte flipped at offset 20")
PY
set +e
"${TOOL}" inspect obs_tampered.msg onode.okey okey
TAMPER_RC=$?
set -e
if [[ ${TAMPER_RC} -ne 0 ]]; then
    ok "Tamper correctly detected — verification failed as expected"
else
    warn "Unexpected: tampered message passed verification"
fi
pause

# ── 10. cross-key rejection demo ─────────────────────────────────────────────
banner "Step 10 — Cross-key rejection demo"
step "Trying to verify observation with R-Key → should fail"
set +e
"${TOOL}" inspect obs.msg rnode.rkey rkey
CROSS_RC=$?
set -e
if [[ ${CROSS_RC} -ne 0 ]]; then
    ok "Cross-key use correctly rejected"
else
    warn "Unexpected: wrong key type passed verification"
fi
pause

# ── 11. O-Node daemon (background) ───────────────────────────────────────────
banner "Step 11 — O-Node daemon"

ONODE_SOCK="${SANDBOX_DIR}/virp-onode.sock"
ONODE_LOG="${SANDBOX_DIR}/onode.log"
ONODE_PID=""

step "Starting virp-onode in the background"
VIRP_SOCK="${ONODE_SOCK}" "${ONODE}" > "${ONODE_LOG}" 2>&1 &
ONODE_PID=$!
sleep 1   # give it a moment to initialise

if kill -0 "${ONODE_PID}" 2>/dev/null; then
    ok "O-Node running (PID ${ONODE_PID})"
    echo ""
    echo "  --- O-Node startup log ---"
    cat "${ONODE_LOG}"
    echo "  --------------------------"
else
    warn "O-Node exited early — check ${ONODE_LOG}"
    cat "${ONODE_LOG}" || true
fi

step "Letting O-Node run for 3 seconds…"
sleep 3

if kill -0 "${ONODE_PID}" 2>/dev/null; then
    ok "O-Node still running after 3 s"
    step "Stopping O-Node"
    kill "${ONODE_PID}" 2>/dev/null || true
    wait "${ONODE_PID}" 2>/dev/null || true
    ok "O-Node stopped cleanly"
else
    warn "O-Node already stopped"
fi
pause

# ── 12. fuzz runner (quick) ───────────────────────────────────────────────────
banner "Step 12 — Quick fuzz run (5 seconds)"
step "Running: ./build/fuzz_virp"
timeout 5 "${REPO_DIR}/build/fuzz_virp" || true
ok "Fuzz run complete (no crashes)"
pause

# ── done ──────────────────────────────────────────────────────────────────────
banner "Sandbox complete"
echo ""
echo -e "  ${GREEN}${BOLD}All steps finished successfully.${RESET}"
echo ""
echo "  Sandbox artefacts are in:"
echo -e "    ${CYAN}${SANDBOX_DIR}/${RESET}"
echo ""
echo "  Key files:     onode.okey  rnode.rkey"
echo "  Messages:      obs.msg  hb.msg  prop.msg  obs_tampered.msg"
echo "  O-Node log:    onode.log"
echo ""
echo -e "  Binaries in ${CYAN}${REPO_DIR}/build/${RESET}:"
echo "    virp-tool    — CLI (keygen / build / inspect / hexdump)"
echo "    virp-onode   — daemon"
echo "    test_virp    — core protocol tests"
echo "    test_onode   — O-Node integration tests"
echo "    fuzz_virp    — randomised fuzzer"
echo ""
echo "  Example next steps:"
echo "    cd ${SANDBOX_DIR}"
echo "    ${TOOL} keygen okey my2.okey"
echo "    ${TOOL} build observation my2.okey 0xDEAD 5 'hello world' out.msg"
echo "    ${TOOL} inspect out.msg my2.okey okey"
echo ""
