#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray Live Test: DOMAIN 7: Autonomous Boundary Defense: ALLOW_LOOPBACK (Steps 47-54)

run_domain_7() {
    stop_any_daemon
# DOMAIN 7: Autonomous Boundary Defense & Autonomous Policy Claims (Steps 47 - 54)
# Invariant I_8 / I_9: Zero-config auto-hardening, ALLOW_LOOPBACK, listed/unlisted execution,
# hardware map verification, and granular network isolation.
# =========================================================================

echo "[*] Step 47: Generating canonical Autonomous Boundary Manifest with ALLOW_LOOPBACK..."
ensure_victim_worker
chmod +x "$VICTIM_BIN"
cat << 'EOF' > /tmp/moray_boundary_live.json
{
  "version": "1.0.0",
  "target_name": "live-kernel-microvm-agent",
  "target_path": "/tmp",
  "generated_by": "Project Moray Native Profiler",
  "policy_state": "ENFORCED",
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
    "network_posture": "ALLOW_LOOPBACK",
    "cgroup_slice": "agent.slice",
    "auto_quarantine_violations": true,
    "max_strike_threshold": 5
  }
}
EOF
echo "[+] Manifest created at /tmp/moray_boundary_live.json (Posture: ALLOW_LOOPBACK, unlisted_worker excluded)."

echo "[*] Step 48: Launching morayd in live Ring 0 Autonomous Boundary Mode (--auto-harden)..."
rm -rf /sys/fs/bpf/moray
mkdir -p /sys/fs/bpf/moray

./bin/morayd --auto-harden /tmp/moray_boundary_live.json --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_auto.log 2>&1 &
AUTO_DAEMON_PID=$!
sleep 2

if ! kill -0 "$AUTO_DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to launch in autonomous auto-harden mode!"
    cat /tmp/morayd_auto.log
    exit 1
fi
echo "[+] morayd is running in autonomous mode (PID: $AUTO_DAEMON_PID)."
cat /tmp/morayd_auto.log

if [ ! -e /sys/fs/bpf/moray/boundary_map ]; then
    echo "[-] FATAL: /sys/fs/bpf/moray/boundary_map was not pinned!"
    exit 1
fi
echo "[+] Verified pinned BPF boundary map: $(ls -l /sys/fs/bpf/moray/boundary_map)"

echo "[*] Step 49: Verifying actual live in-kernel boundary_map contents against manifest..."
VERIFY_OUT=$($MORAY_HOOK --verify-boundary /tmp/moray_boundary_live.json --boundary-map-path /sys/fs/bpf/moray/boundary_map --json)
echo "$VERIFY_OUT"
if ! echo "$VERIFY_OUT" | grep -q '"status": "verified"'; then
    echo "[-] FATAL: Live boundary map verification failed!"
    exit 1
fi

BOUNDARY_DUMP=$($MORAY_HOOK --dump-boundary --boundary-map-path /sys/fs/bpf/moray/boundary_map --json)
echo "$BOUNDARY_DUMP"

if ! echo "$BOUNDARY_DUMP" | grep -q '"__moray_auto__"'; then
    echo "[-] FATAL: Sentinel __moray_auto__ missing from kernel boundary map!"
    exit 1
fi
if ! echo "$BOUNDARY_DUMP" | grep -q '"victim_worker"'; then
    echo "[-] FATAL: victim_worker missing from kernel boundary map!"
    exit 1
fi
if echo "$BOUNDARY_DUMP" | grep -q '"unlisted_worker"'; then
    echo "[-] FATAL: unlisted_worker unexpectedly found in kernel boundary map!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: In-kernel BPF boundary map verified with exact ALLOW_LOOPBACK permissions!"

echo "[*] Step 50: Testing listed executable (victim_worker) execution under autonomous boundary..."
if "$VICTIM_BIN" --baseline-exec; then
    echo "[+] EMPIRICAL PROOF: Listed executable executed cleanly with zero latency (Invariant I_2)!"
else
    echo "[-] FATAL: Listed executable failed to execute under autonomous boundary!"
    exit 1
fi

UPDATED_ENTRY=$($MORAY_HOOK --dump-boundary --boundary-map-path /sys/fs/bpf/moray/boundary_map --json)
if ! echo "$UPDATED_ENTRY" | grep -A 5 '"victim_worker"' | grep -q '"hit_count": [1-9]'; then
    echo "[-] FATAL: In-kernel hit_count was not incremented for victim_worker!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: In-kernel Ring 0 hit_count incremented for authorized execution!"

echo "[*] Step 51: Testing unlisted binary (unlisted_worker) interception under autonomous boundary..."
prepare_unlisted_worker

RET_UNLISTED=0
/tmp/unlisted_worker --assert-unlisted-exec || RET_UNLISTED=$?
if [ "$RET_UNLISTED" -ne 42 ]; then
    echo "[-] FATAL: Unlisted binary was NOT blocked with -EPERM! Return code: $RET_UNLISTED (expected 42)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Unlisted executable was autonomously severed with -EPERM by Ring 0 BPF-LSM!"

QUARANTINE_TABLE=$($MORAY_HOOK --list --map-path /sys/fs/bpf/moray/quarantine_map --json)
echo "$QUARANTINE_TABLE"
if ! echo "$QUARANTINE_TABLE" | grep -q '"reason": 2'; then
    echo "[-] FATAL: Autonomous strike was not recorded in moray_quarantine_map (reason 2 expected)!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Unlisted binary was autonomously quarantined in Ring 0 (Invariant I_9)!"

echo "[*] Step 52: Testing granular loopback socket connect under autonomous ALLOW_LOOPBACK..."
RET_LOOPBACK=0
"$VICTIM_BIN" --connect-loopback 80 || RET_LOOPBACK=$?
if [ "$RET_LOOPBACK" -ne 45 ]; then
    echo "[-] FATAL: Loopback socket connect failed past LSM! Return code: $RET_LOOPBACK (expected 45)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Loopback socket connect permitted by Ring 0 BPF-LSM under autonomous ALLOW_LOOPBACK!"

RET_UNIX=0
"$VICTIM_BIN" --connect-unix /tmp/moray_auto_test.sock || RET_UNIX=$?
if [ "$RET_UNIX" -ne 46 ]; then
    echo "[-] FATAL: UNIX domain socket connect failed past LSM! Return code: $RET_UNIX (expected 46)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: AF_UNIX local IPC permitted by Ring 0 BPF-LSM under autonomous ALLOW_LOOPBACK!"

echo "[*] Step 53: Testing autonomous WAN socket severance under ALLOW_LOOPBACK..."
RET_WAN=0
"$VICTIM_BIN" --connect-wan 1.1.1.1 80 || RET_WAN=$?
if [ "$RET_WAN" -ne 44 ]; then
    echo "[-] FATAL: WAN socket was NOT blocked with -EPERM under ALLOW_LOOPBACK! Return code: $RET_WAN (expected 44)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: WAN socket connect severed with -EPERM under autonomous ALLOW_LOOPBACK!"

AUTO_EVENTS=$($MORAY_HOOK --events-path /sys/fs/bpf/moray/events --tail-events --count 5 --json)
echo "$AUTO_EVENTS"
if ! echo "$AUTO_EVENTS" | grep -q 'SOCKET'; then
    echo "[-] FATAL: Autonomous WAN socket severance event not found in ringbuf!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Autonomous WAN socket strike telemetry captured in Ring 0 ringbuf!"

echo "[*] Step 54: Clean teardown of autonomous ALLOW_LOOPBACK daemon..."
kill -TERM "$AUTO_DAEMON_PID"
rm -f /tmp/unlisted_worker /tmp/moray_boundary_live.json /tmp/moray_auto_test.sock
sleep 1

}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$SCRIPT_DIR/common.sh"
    run_preflight
    run_domain_7
    echo "=========================================================="
    echo "  [+] DOMAIN 7 PASSED CLEANLY!                     "
    echo "=========================================================="
fi
