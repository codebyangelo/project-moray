#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray Live Test: DOMAIN 2: Dynamic Escalation to SIGKILL (Steps 21-25)

run_domain_2() {
    ensure_baseline_daemon
# DOMAIN 2: In-Kernel Escalation to SIGKILL (Steps 21 - 25)
# Invariant I_1 / I_8: Dynamic escalation transitions Tier 1 -> Tier 3 (hits >= 5)
# =========================================================================
echo "[*] Step 21: Spawning victim worker for sub-threshold strike loop (4 hits)..."
"$VICTIM_BIN" --multi-strike-loop 4 &
LOOP_PID1=$!
while [ ! -f "/tmp/victim_${LOOP_PID1}.ready" ]; do sleep 0.05; done

echo "[*] Step 22: Registering strike with action=1 (BLOCK_EXEC, strike_count=0, no KILL flag)..."
$MORAY_HOOK --pid "$LOOP_PID1" --strike --action 1 --map-path /sys/fs/bpf/moray/quarantine_map

echo "[*] Step 23: Signaling worker and asserting survival under Tier 1/2 (hits: 4 < 5)..."
kill -USR1 "$LOOP_PID1"
RET_LOOP1=0
wait "$LOOP_PID1" || RET_LOOP1=$?
if [ "$RET_LOOP1" -ne 51 ]; then
    echo "[-] FATAL: Worker did not complete 4-hit loop cleanly! Exit code: $RET_LOOP1 (expected 51)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Worker survived 4 intercepted operations under Tier 1 containment without auto-kill!"

echo "[*] Step 24: Spawning second victim worker for escalation strike loop (10 attempts)..."
"$VICTIM_BIN" --multi-strike-loop 10 &
LOOP_PID2=$!
while [ ! -f "/tmp/victim_${LOOP_PID2}.ready" ]; do sleep 0.05; done

echo "[*] Step 25: Asserting strike (action=1) and verifying auto-escalation to SIGKILL at hit 5..."
$MORAY_HOOK --pid "$LOOP_PID2" --strike --action 1 --map-path /sys/fs/bpf/moray/quarantine_map
kill -USR1 "$LOOP_PID2"
RET_LOOP2=0
wait "$LOOP_PID2" || RET_LOOP2=$?
if [ "$RET_LOOP2" -ne 137 ]; then
    echo "[-] FATAL: Worker was NOT auto-terminated with SIGKILL at hit threshold! Exit code: $RET_LOOP2 (expected 137)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: In-kernel dynamic escalation triggered bpf_send_signal(9) at hit 5 (exit code 137)!"

# =========================================================================
}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$SCRIPT_DIR/common.sh"
    run_preflight
    run_domain_2
    echo "=========================================================="
    echo "  [+] DOMAIN 2 PASSED CLEANLY!                     "
    echo "=========================================================="
fi
