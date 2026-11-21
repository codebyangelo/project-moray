#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray Live Test: DOMAIN 9: Autonomous Boundary Defense: REQUIRE_WAN (Steps 63-70)

run_domain_9() {
    stop_any_daemon
echo "=========================================================="
echo "  [+] DOMAIN 9: AUTONOMOUS BOUNDARY DEFENSE (REQUIRE_WAN)  "
echo "=========================================================="

echo "[*] Step 63: Generating sovereign boundary manifest (Network Posture: REQUIRE_WAN)..."
ensure_victim_worker

cat << 'EOF' > /tmp/moray_boundary_require_wan.json
{
  "version": "1.0.0",
  "target_name": "moray-agent-require-wan",
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
    "network_posture": "REQUIRE_WAN",
    "cgroup_slice": "agent.slice",
    "auto_quarantine_violations": true,
    "max_strike_threshold": 5
  }
}
EOF
echo "[+] Manifest created at /tmp/moray_boundary_require_wan.json (Posture: REQUIRE_WAN, unlisted_worker excluded)."

echo "[*] Step 64: Launching morayd in live Ring 0 Autonomous Boundary Mode (REQUIRE_WAN)..."
rm -rf /sys/fs/bpf/moray
mkdir -p /sys/fs/bpf/moray

./bin/morayd --auto-harden /tmp/moray_boundary_require_wan.json --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_require_wan.log 2>&1 &
WAN_DAEMON_PID=$!
sleep 2

if ! kill -0 "$WAN_DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to launch in autonomous auto-harden mode under REQUIRE_WAN!"
    cat /tmp/morayd_require_wan.log
    exit 1
fi
echo "[+] morayd is running in autonomous REQUIRE_WAN mode (PID: $WAN_DAEMON_PID)."
cat /tmp/morayd_require_wan.log

if [ ! -e /sys/fs/bpf/moray/boundary_map ]; then
    echo "[-] FATAL: /sys/fs/bpf/moray/boundary_map was not pinned under REQUIRE_WAN!"
    exit 1
fi
echo "[+] Verified pinned BPF boundary map: $(ls -l /sys/fs/bpf/moray/boundary_map)"

echo "[*] Step 65: Verifying actual live in-kernel boundary_map contents against REQUIRE_WAN manifest..."
WAN_VERIFY_OUT=$($MORAY_HOOK --verify-boundary /tmp/moray_boundary_require_wan.json --boundary-map-path /sys/fs/bpf/moray/boundary_map --json)
echo "$WAN_VERIFY_OUT"
if ! echo "$WAN_VERIFY_OUT" | grep -q '"status": "verified"'; then
    echo "[-] FATAL: Live boundary map verification failed under REQUIRE_WAN!"
    exit 1
fi

WAN_BOUNDARY_DUMP=$($MORAY_HOOK --dump-boundary --boundary-map-path /sys/fs/bpf/moray/boundary_map --json)
echo "$WAN_BOUNDARY_DUMP"

if ! echo "$WAN_BOUNDARY_DUMP" | grep -q '"__moray_auto__"'; then
    echo "[-] FATAL: Sentinel __moray_auto__ missing from kernel boundary map under REQUIRE_WAN!"
    exit 1
fi
if ! echo "$WAN_BOUNDARY_DUMP" | grep -q '"victim_worker"'; then
    echo "[-] FATAL: victim_worker missing from kernel boundary map under REQUIRE_WAN!"
    exit 1
fi
if echo "$WAN_BOUNDARY_DUMP" | grep -q '"unlisted_worker"'; then
    echo "[-] FATAL: unlisted_worker unexpectedly found in kernel boundary map under REQUIRE_WAN!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: In-kernel BPF boundary map verified with exact REQUIRE_WAN permissions!"

echo "[*] Step 66: Testing listed executable (victim_worker) execution under autonomous REQUIRE_WAN..."
if "$VICTIM_BIN" --baseline-exec; then
    echo "[+] EMPIRICAL PROOF: Listed executable executed cleanly with zero latency under REQUIRE_WAN (Invariant I_2)!"
else
    echo "[-] FATAL: Listed executable failed to execute under autonomous REQUIRE_WAN!"
    exit 1
fi

UPDATED_WAN_ENTRY=$($MORAY_HOOK --dump-boundary --boundary-map-path /sys/fs/bpf/moray/boundary_map --json)
if ! echo "$UPDATED_WAN_ENTRY" | grep -A 5 '"victim_worker"' | grep -q '"hit_count": [1-9]'; then
    echo "[-] FATAL: In-kernel hit_count was not incremented for victim_worker under REQUIRE_WAN!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: In-kernel Ring 0 hit_count incremented for authorized execution under REQUIRE_WAN!"

echo "[*] Step 67: Testing unlisted binary (unlisted_worker) interception under autonomous REQUIRE_WAN..."
prepare_unlisted_worker

RET_UNLISTED_WAN=0
/tmp/unlisted_worker --assert-unlisted-exec || RET_UNLISTED_WAN=$?
if [ "$RET_UNLISTED_WAN" -ne 42 ]; then
    echo "[-] FATAL: Unlisted binary was NOT blocked with -EPERM under REQUIRE_WAN! Return code: $RET_UNLISTED_WAN (expected 42)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Unlisted executable was autonomously severed with -EPERM by Ring 0 BPF-LSM under REQUIRE_WAN!"

QUARANTINE_TABLE_WAN=$($MORAY_HOOK --list --map-path /sys/fs/bpf/moray/quarantine_map --json)
echo "$QUARANTINE_TABLE_WAN"
if ! echo "$QUARANTINE_TABLE_WAN" | grep -q '"reason": 2'; then
    echo "[-] FATAL: Autonomous strike was not recorded in moray_quarantine_map under REQUIRE_WAN (reason 2 expected)!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Unlisted binary was autonomously quarantined in Ring 0 under REQUIRE_WAN (Invariant I_9)!"

echo "[*] Step 68: Testing permitted WAN socket connect under autonomous REQUIRE_WAN..."
RET_WAN_PASS=0
"$VICTIM_BIN" --connect-wan 1.1.1.1 80 || RET_WAN_PASS=$?
if [ "$RET_WAN_PASS" -ne 43 ]; then
    echo "[-] FATAL: Outbound WAN socket connect was blocked under REQUIRE_WAN! Return code: $RET_WAN_PASS (expected 43: permitted past LSM)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Outbound WAN socket permitted by Ring 0 BPF-LSM under autonomous REQUIRE_WAN!"

echo "[*] Step 69: Testing permitted loopback and AF_UNIX socket connects under autonomous REQUIRE_WAN..."
RET_WAN_LOOP=0
"$VICTIM_BIN" --connect-loopback 80 || RET_WAN_LOOP=$?
if [ "$RET_WAN_LOOP" -ne 45 ]; then
    echo "[-] FATAL: Loopback socket connect failed past LSM under REQUIRE_WAN! Return code: $RET_WAN_LOOP (expected 45)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Loopback socket connect permitted by Ring 0 BPF-LSM under autonomous REQUIRE_WAN!"

RET_WAN_UNIX=0
"$VICTIM_BIN" --connect-unix /tmp/moray_wan_test.sock || RET_WAN_UNIX=$?
if [ "$RET_WAN_UNIX" -ne 46 ]; then
    echo "[-] FATAL: UNIX domain socket connect failed past LSM under REQUIRE_WAN! Return code: $RET_WAN_UNIX (expected 46)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: AF_UNIX local IPC permitted by Ring 0 BPF-LSM under autonomous REQUIRE_WAN!"

echo "[*] Step 70: Clean teardown of autonomous REQUIRE_WAN daemon and test artifacts..."
kill -TERM "$WAN_DAEMON_PID"
rm -f /tmp/unlisted_worker /tmp/moray_boundary_require_wan.json /tmp/moray_wan_test.sock /tmp/victim_*.ready
sleep 1

}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$SCRIPT_DIR/common.sh"
    run_preflight
    run_domain_9
    echo "=========================================================="
    echo "  [+] DOMAIN 9 PASSED CLEANLY!                     "
    echo "=========================================================="
fi
