#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray: Shared Environment & Fixture Definitions for Live Kernel Tests

set -euo pipefail

# Sovereign Moray Python Controller (Primary) and L7 Lobster Adapter (Secondary)
MORAY_HOOK="python3 bridge/moray_hook.py"
LOBSTER_HOOK="$MORAY_HOOK"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Immutable Test Fixtures
VICTIM_BIN="$REPO_ROOT/bin/victim_worker"
UNLISTED_BIN="/tmp/unlisted_worker"

ensure_victim_worker() {
    if [ ! -x "$VICTIM_BIN" ] || [ "$REPO_ROOT/tests/victim_worker.c" -nt "$VICTIM_BIN" ]; then
        echo "[*] Compiling immutable test fixture worker ($VICTIM_BIN)..."
        mkdir -p "$REPO_ROOT/bin"
        gcc -Wall -Wextra -O2 -std=c11 tests/victim_worker.c -o "$VICTIM_BIN"
    fi
}

prepare_unlisted_worker() {
    ensure_victim_worker
    cp "$VICTIM_BIN" "$UNLISTED_BIN"
    chmod +x "$UNLISTED_BIN"
}

cleanup_ephemeral() {
    rm -f "$UNLISTED_BIN" /tmp/victim_*.ready /tmp/*.sock /tmp/*.json
}

stop_any_daemon() {
    pkill -TERM -f "bin/morayd" 2>/dev/null || true
    sleep 1
}

DAEMON_PID=""
ensure_baseline_daemon() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        return 0
    fi
    stop_any_daemon
    echo "[*] Launching baseline morayd loader daemon in live Ring 0 mode..."
    rm -rf /sys/fs/bpf/moray
    mkdir -p /sys/fs/bpf/moray
    ./bin/morayd --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_live.log 2>&1 &
    DAEMON_PID=$!
    sleep 2
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "[-] FATAL: morayd failed to start in baseline mode!"
        cat /tmp/morayd_live.log
        exit 1
    fi
    echo "[+] Baseline morayd is running (PID: $DAEMON_PID)."
}

run_preflight() {
echo "[*] Step 1: Checking Ring 0 LSM stack in /sys/kernel/security/lsm..."
if ! grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    echo "[-] FATAL: 'bpf' not found in /sys/kernel/security/lsm!"
    cat /sys/kernel/security/lsm 2>/dev/null || true
    exit 1
fi
echo "[+] CONFIRMED: BPF-LSM is active in running kernel: $(cat /sys/kernel/security/lsm)"

# 2. Mount bpffs
echo "[*] Step 2: Verifying BPF filesystem at /sys/fs/bpf..."
mkdir -p /sys/fs/bpf
if ! grep -q "/sys/fs/bpf" /proc/mounts; then
    mount -t bpf bpf /sys/fs/bpf
fi
echo "[+] CONFIRMED: /sys/fs/bpf mounted as bpffs (magic: $(stat -f -c %T /sys/fs/bpf))"

# 3. Ensure victim worker fixture
echo "[*] Step 3: Verifying immutable victim worker fixture..."
ensure_victim_worker
# 4. Verify unquarantined baseline execution
echo "[*] Step 4: Testing unquarantined baseline (must succeed)..."
if "$VICTIM_BIN" --baseline-exec; then
    echo "[+] Baseline verified: unquarantined process executes normally."
else
    echo "[-] FATAL: Baseline execve failed before containment!"
    exit 1
fi

# 5. Launch morayd in Live Kernel Mode
}

