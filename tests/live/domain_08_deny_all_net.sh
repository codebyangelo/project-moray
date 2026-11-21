#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray Live Test: DOMAIN 8: Autonomous Boundary Defense: DENY_ALL_NET (Steps 55-62)

run_domain_8() {
    stop_any_daemon
echo "=========================================================="
echo "  [+] DOMAIN 8: AUTONOMOUS BOUNDARY DEFENSE (DENY_ALL_NET) "
echo "=========================================================="

echo "[*] Step 55: Generating sovereign boundary manifest (Network Posture: DENY_ALL_NET)..."
ensure_victim_worker

cat << 'EOF' > /tmp/moray_boundary_deny_all.json
{
  "version": "1.0.0",
  "target_name": "moray-agent-deny-all",
  "policy_state": "ENFORCED",
  "generated_at": 1731900000,
  "boundary_policy": {
    "default_action": "AUTONOMOUS_STRIKE",
    "allowed_comms": [
      "morayd",
      "victim_worker",
      "bash",
      "sh",
      "python",
      "python3",
      "make",
      "gcc",
      "clang",
      "cat",
      "ls",
      "rm",
      "mkdir",
      "true"
    ],
    "allowed_paths": [
      "$VICTIM_BIN",
      "/bin/true",
      "/usr/bin/true",
      "/bin/sh",
      "/bin/bash"
    ],
    "network_posture": "DENY_ALL_NET",
    "cgroup_slice": "agent.slice",
    "auto_quarantine_violations": true,
    "max_strike_threshold": 5
  }
}
EOF
echo "[+] Manifest created at /tmp/moray_boundary_deny_all.json (Posture: DENY_ALL_NET, total network severance)."

echo "[*] Step 56: Launching morayd in live Ring 0 Autonomous Boundary Mode (DENY_ALL_NET)..."
rm -rf /sys/fs/bpf/moray
mkdir -p /sys/fs/bpf/moray

./bin/morayd --auto-harden /tmp/moray_boundary_deny_all.json --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_deny_all.log 2>&1 &
DENY_DAEMON_PID=$!
sleep 2

if ! kill -0 "$DENY_DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to launch in autonomous auto-harden mode under DENY_ALL_NET!"
    cat /tmp/morayd_deny_all.log
    exit 1
fi
echo "[+] morayd is running in autonomous DENY_ALL_NET mode (PID: $DENY_DAEMON_PID)."
cat /tmp/morayd_deny_all.log

if [ ! -e /sys/fs/bpf/moray/boundary_map ]; then
    echo "[-] FATAL: /sys/fs/bpf/moray/boundary_map was not pinned under DENY_ALL_NET!"
    exit 1
fi
echo "[+] Verified pinned BPF boundary map: $(ls -l /sys/fs/bpf/moray/boundary_map)"

echo "[*] Step 57: Verifying actual live in-kernel boundary_map contents against DENY_ALL_NET manifest..."
DENY_VERIFY_OUT=$($MORAY_HOOK --verify-boundary /tmp/moray_boundary_deny_all.json --boundary-map-path /sys/fs/bpf/moray/boundary_map --json)
echo "$DENY_VERIFY_OUT"
if ! echo "$DENY_VERIFY_OUT" | grep -q '"status": "verified"'; then
    echo "[-] FATAL: Live boundary map verification failed under DENY_ALL_NET!"
    exit 1
fi

DENY_BOUNDARY_DUMP=$($MORAY_HOOK --dump-boundary --boundary-map-path /sys/fs/bpf/moray/boundary_map --json)
echo "$DENY_BOUNDARY_DUMP"

if ! echo "$DENY_BOUNDARY_DUMP" | grep -q '"__moray_auto__"'; then
    echo "[-] FATAL: Sentinel __moray_auto__ missing from kernel boundary map under DENY_ALL_NET!"
    exit 1
fi
if ! echo "$DENY_BOUNDARY_DUMP" | grep -q '"victim_worker"'; then
    echo "[-] FATAL: victim_worker missing from kernel boundary map under DENY_ALL_NET!"
    exit 1
fi
if echo "$DENY_BOUNDARY_DUMP" | grep -q '"unlisted_worker"'; then
    echo "[-] FATAL: unlisted_worker unexpectedly found in kernel boundary map under DENY_ALL_NET!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: In-kernel BPF boundary map verified with exact DENY_ALL_NET permissions!"

echo "[*] Step 58: Testing listed executable (victim_worker) execution under autonomous DENY_ALL_NET..."
if "$VICTIM_BIN" --baseline-exec; then
    echo "[+] EMPIRICAL PROOF: Listed executable executed cleanly with zero latency under DENY_ALL_NET (Invariant I_2)!"
else
    echo "[-] FATAL: Listed executable failed to execute under autonomous DENY_ALL_NET!"
    exit 1
fi

UPDATED_DENY_ENTRY=$($MORAY_HOOK --dump-boundary --boundary-map-path /sys/fs/bpf/moray/boundary_map --json)
if ! echo "$UPDATED_DENY_ENTRY" | grep -A 5 '"victim_worker"' | grep -q '"hit_count": [1-9]'; then
    echo "[-] FATAL: In-kernel hit_count was not incremented for victim_worker under DENY_ALL_NET!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: In-kernel Ring 0 hit_count incremented for authorized execution under DENY_ALL_NET!"

echo "[*] Step 59: Testing unlisted binary (unlisted_worker) interception under autonomous DENY_ALL_NET..."
prepare_unlisted_worker

RET_UNLISTED_DENY=0
/tmp/unlisted_worker --assert-unlisted-exec || RET_UNLISTED_DENY=$?
if [ "$RET_UNLISTED_DENY" -ne 42 ]; then
    echo "[-] FATAL: Unlisted binary was NOT blocked with -EPERM under DENY_ALL_NET! Return code: $RET_UNLISTED_DENY (expected 42)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Unlisted executable was autonomously severed with -EPERM by Ring 0 BPF-LSM under DENY_ALL_NET!"

QUARANTINE_TABLE_DENY=$($MORAY_HOOK --list --map-path /sys/fs/bpf/moray/quarantine_map --json)
echo "$QUARANTINE_TABLE_DENY"
if ! echo "$QUARANTINE_TABLE_DENY" | grep -q '"reason": 2'; then
    echo "[-] FATAL: Autonomous strike was not recorded in moray_quarantine_map under DENY_ALL_NET (reason 2 expected)!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Unlisted binary was autonomously quarantined in Ring 0 under DENY_ALL_NET (Invariant I_9)!"

echo "[*] Step 60: Testing total local network severance (Loopback and AF_UNIX) under autonomous DENY_ALL_NET..."
RET_DENY_LOOPBACK=0
"$VICTIM_BIN" --connect-loopback 80 || RET_DENY_LOOPBACK=$?
if [ "$RET_DENY_LOOPBACK" -ne 48 ]; then
    echo "[-] FATAL: Loopback socket connect was NOT blocked with -EPERM under DENY_ALL_NET! Return code: $RET_DENY_LOOPBACK (expected 48)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Loopback socket connect severed with -EPERM under autonomous DENY_ALL_NET!"

RET_DENY_UNIX=0
"$VICTIM_BIN" --connect-unix /tmp/moray_deny_test.sock || RET_DENY_UNIX=$?
if [ "$RET_DENY_UNIX" -ne 49 ]; then
    echo "[-] FATAL: UNIX domain socket connect was NOT blocked with -EPERM under DENY_ALL_NET! Return code: $RET_DENY_UNIX (expected 49)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: AF_UNIX local IPC severed with -EPERM under autonomous DENY_ALL_NET!"

echo "[*] Step 61: Testing autonomous WAN socket severance under DENY_ALL_NET..."
RET_DENY_WAN=0
"$VICTIM_BIN" --connect-wan 1.1.1.1 80 || RET_DENY_WAN=$?
if [ "$RET_DENY_WAN" -ne 44 ]; then
    echo "[-] FATAL: WAN socket was NOT blocked with -EPERM under DENY_ALL_NET! Return code: $RET_DENY_WAN (expected 44)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: WAN socket connect severed with -EPERM under autonomous DENY_ALL_NET!"

DENY_EVENTS=$($MORAY_HOOK --events-path /sys/fs/bpf/moray/events --tail-events --count 5 --json)
echo "$DENY_EVENTS"
if ! echo "$DENY_EVENTS" | grep -q 'SOCKET'; then
    echo "[-] FATAL: Autonomous DENY_ALL_NET socket severance event not found in ringbuf!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Autonomous DENY_ALL_NET socket strike telemetry captured in Ring 0 ringbuf!"

echo "[*] Step 62: Clean teardown of autonomous DENY_ALL_NET daemon and test artifacts..."
kill -TERM "$DENY_DAEMON_PID"
rm -f /tmp/unlisted_worker /tmp/moray_boundary_deny_all.json /tmp/moray_deny_test.sock
sleep 1

}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$SCRIPT_DIR/common.sh"
    run_preflight
    run_domain_8
    echo "=========================================================="
    echo "  [+] DOMAIN 8 PASSED CLEANLY!                     "
    echo "=========================================================="
fi
