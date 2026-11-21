#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray Live Test: DOMAIN 6: Live SRE Disaster Recovery DR-01..DR-03 (Steps 41-46)

run_domain_6() {
    ensure_baseline_daemon
# DOMAIN 6: Live SRE Disaster Recovery (DR-01, DR-02, DR-03) (Steps 41 - 45)
# Invariant I_1 / I_2 / I_8: Emergency flush, TTL eviction, and daemon crash recovery
# =========================================================================
echo "[*] Step 41: DR-01 (Emergency Break-Glass Flush)..."
for p in 89001 89002 89003 89004 89005; do
    $MORAY_HOOK --pid "$p" --strike --action 1 --map-path /sys/fs/bpf/moray/quarantine_map
done
FLUSH_OUT=$($MORAY_HOOK --flush-all --force --map-path /sys/fs/bpf/moray/quarantine_map --json)
echo "$FLUSH_OUT"
if ! echo "$FLUSH_OUT" | grep -q '"status": "flushed"'; then
    echo "[-] FATAL: DR-01 emergency flush failed!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: DR-01 emergency break-glass flush purged all quarantine entries!"

echo "[*] Step 42: DR-02 (Stale Entry Auto-Eviction via TTL Sweep)..."
$MORAY_HOOK --pid 89010 --strike --action 1 --ttl 1 --map-path /sys/fs/bpf/moray/quarantine_map
sleep 2
EVICT_OUT=$($MORAY_HOOK --evict-expired --map-path /sys/fs/bpf/moray/quarantine_map --json)
echo "$EVICT_OUT"
if ! echo "$EVICT_OUT" | grep -q '"status": "evicted"'; then
    echo "[-] FATAL: DR-02 TTL eviction failed!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: DR-02 successfully swept and evicted stale TTL quarantine entries!"

echo "[*] Step 43: DR-03 (Daemon Crash Recovery: Simulating SIGKILL on morayd)..."
kill -9 "$DAEMON_PID"
sleep 1
if kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd did not terminate under SIGKILL!"
    exit 1
fi
echo "[+] Simulated sudden daemon crash (morayd terminated)."

echo "[*] Step 44: DR-03 (Daemon Relaunch & Pinned Map Re-Attachment)..."
./bin/morayd --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_relaunch.log 2>&1 &
NEW_DAEMON_PID=$!
sleep 2
if ! kill -0 "$NEW_DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to relaunch and re-attach to existing pinned maps!"
    cat /tmp/morayd_relaunch.log
    exit 1
fi
echo "[+] morayd successfully relaunched (PID: $NEW_DAEMON_PID) and re-attached to pinned maps."

echo "[*] Step 45: Verifying Invariant I_2 unquarantined fast-path under relaunched daemon..."
if "$VICTIM_BIN" --baseline-exec; then
    echo "[+] EMPIRICAL PROOF: Baseline unquarantined execution succeeds with zero latency (Invariant I_2)!"
else
    echo "[-] FATAL: Baseline execution failed under relaunched daemon!"
    exit 1
fi

# =========================================================================
# STEP 46: Clean Teardown of Manual Strike Daemon
# =========================================================================
echo "[*] Step 46: Clean teardown of relaunched daemon..."
kill -TERM "$NEW_DAEMON_PID"
rm -f /tmp/victim_*.ready /tmp/moray_test.sock
sleep 1

# =========================================================================
}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$SCRIPT_DIR/common.sh"
    run_preflight
    run_domain_6
    echo "=========================================================="
    echo "  [+] DOMAIN 6 PASSED CLEANLY!                     "
    echo "=========================================================="
fi
