#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray Live Test: DOMAIN 10: Workload-Scoped Boundary & Non-Interference (Steps 71-80)

run_domain_10() {
    stop_any_daemon
echo "=========================================================="
echo "  [+] DOMAIN 10: WORKLOAD-SCOPED BOUNDARY & NON-INTERFERENCE"
echo "=========================================================="

echo "[*] Step 71: Setting up dual cgroup v2 testing hierarchies (Workload A & Workload B)..."
ensure_victim_worker
CGROUP_WORKLOAD_A="/sys/fs/cgroup/moray_workload_a"
CGROUP_WORKLOAD_B="/sys/fs/cgroup/moray_workload_b"
mkdir -p "$CGROUP_WORKLOAD_A" "$CGROUP_WORKLOAD_B"
CGROUP_ID_A=$(stat -c %i "$CGROUP_WORKLOAD_A")
CGROUP_ID_B=$(stat -c %i "$CGROUP_WORKLOAD_B")
echo "[+] Workload A (Governed): $CGROUP_WORKLOAD_A (Inode/Cgroup ID: $CGROUP_ID_A)"
echo "[+] Workload B (Ungoverned): $CGROUP_WORKLOAD_B (Inode/Cgroup ID: $CGROUP_ID_B)"

echo "[*] Step 72: Generating workload-scoped boundary manifest targeting Workload A..."
cat << 'EOF' > /tmp/moray_boundary_workload.json
{
  "version": "1.0.0",
  "target_name": "moray-workload-governed",
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
    "network_posture": "ALLOW_LOOPBACK",
    "cgroup_slice": "/sys/fs/cgroup/moray_workload_a",
    "auto_quarantine_violations": true,
    "max_strike_threshold": 5
  }
}
EOF
echo "[+] Workload manifest created at /tmp/moray_boundary_workload.json (Target: Workload A, Posture: ALLOW_LOOPBACK)."

echo "[*] Step 73: Launching morayd in live Workload-Scoped Autonomous Mode..."
rm -rf /sys/fs/bpf/moray
mkdir -p /sys/fs/bpf/moray

./bin/morayd --auto-harden /tmp/moray_boundary_workload.json --cgroup "$CGROUP_WORKLOAD_A" --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_workload.log 2>&1 &
WORKLOAD_DAEMON_PID=$!
sleep 2

if ! kill -0 "$WORKLOAD_DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to launch in autonomous workload mode!"
    cat /tmp/morayd_workload.log
    exit 1
fi
echo "[+] morayd running in workload-scoped mode (PID: $WORKLOAD_DAEMON_PID)."
cat /tmp/morayd_workload.log

if [ ! -e /sys/fs/bpf/moray/workload_map ]; then
    echo "[-] FATAL: /sys/fs/bpf/moray/workload_map was not pinned!"
    exit 1
fi
echo "[+] Verified pinned BPF workload map: $(ls -l /sys/fs/bpf/moray/workload_map)"

echo "[*] Step 74: Verifying live in-kernel workload map and sentinel mode..."
WORKLOAD_A_STATUS=$($MORAY_HOOK --map-path /sys/fs/bpf/moray/quarantine_map --workload-map-path /sys/fs/bpf/moray/workload_map --workload-status "$CGROUP_ID_A" --json)
echo "$WORKLOAD_A_STATUS"
if ! echo "$WORKLOAD_A_STATUS" | grep -q '"governed": true'; then
    echo "[-] FATAL: Workload A is not governed in kernel workload map!"
    exit 1
fi
if ! echo "$WORKLOAD_A_STATUS" | grep -q '"posture": "ALLOW_LOOPBACK"'; then
    echo "[-] FATAL: Workload A does not have posture ALLOW_LOOPBACK!"
    exit 1
fi

WORKLOAD_B_STATUS=$($MORAY_HOOK --map-path /sys/fs/bpf/moray/quarantine_map --workload-map-path /sys/fs/bpf/moray/workload_map --workload-status "$CGROUP_ID_B" --json)
echo "$WORKLOAD_B_STATUS"
if echo "$WORKLOAD_B_STATUS" | grep -q '"governed": true'; then
    echo "[-] FATAL: Workload B should NOT be governed in kernel workload map!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: In-kernel workload map correctly governs Workload A and isolates Workload B!"

echo "[*] Step 75: Testing dual-workload unlisted binary (unlisted_worker) non-interference..."
prepare_unlisted_worker

# 1. Unlisted binary inside Governed Workload A -> must be severed with -EPERM (exit code 42)
RET_UNLISTED_A=0
/tmp/unlisted_worker --assert-unlisted-exec --cgroup "$CGROUP_WORKLOAD_A" || RET_UNLISTED_A=$?
if [ "$RET_UNLISTED_A" -ne 42 ]; then
    echo "[-] FATAL: Unlisted binary was NOT blocked inside governed Workload A! Return code: $RET_UNLISTED_A (expected 42)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Unlisted binary was autonomously severed with -EPERM inside governed Workload A!"

# 2. Unlisted binary inside Ungoverned Workload B -> must execute cleanly with zero latency (exit code 0)
RET_UNLISTED_B=0
/tmp/unlisted_worker --baseline-exec --cgroup "$CGROUP_WORKLOAD_B" || RET_UNLISTED_B=$?
if [ "$RET_UNLISTED_B" -ne 0 ]; then
    echo "[-] FATAL: Unlisted binary was unexpectedly blocked inside ungoverned Workload B! Return code: $RET_UNLISTED_B (expected 0)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Non-interference verified! Identical unlisted binary executed cleanly inside ungoverned Workload B!"

echo "[*] Step 76: Testing dual-workload WAN socket non-interference (same binary victim_worker)..."
# 1. Inside Governed Workload A: Outbound WAN must be blocked with -EPERM (return code 44)
RET_WAN_A=0
"$VICTIM_BIN" --connect-wan 1.1.1.1 80 --cgroup "$CGROUP_WORKLOAD_A" || RET_WAN_A=$?
if [ "$RET_WAN_A" -ne 44 ]; then
    echo "[-] FATAL: WAN socket was NOT blocked inside governed Workload A! Return code: $RET_WAN_A (expected 44)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: WAN socket severed with -EPERM for victim_worker inside governed Workload A!"

# 2. Inside Ungoverned Workload B: Outbound WAN must bypass LSM check (return code 43)
RET_WAN_B=0
"$VICTIM_BIN" --connect-wan 1.1.1.1 80 --cgroup "$CGROUP_WORKLOAD_B" || RET_WAN_B=$?
if [ "$RET_WAN_B" -ne 43 ]; then
    echo "[-] FATAL: WAN socket was blocked inside ungoverned Workload B! Return code: $RET_WAN_B (expected 43)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Non-interference verified! WAN socket permitted for identical binary inside ungoverned Workload B!"

echo "[*] Step 77: Testing dual-workload loopback socket execution under ALLOW_LOOPBACK..."
# Inside Governed Workload A: Loopback permitted (return code 45)
RET_LOOP_A=0
"$VICTIM_BIN" --connect-loopback 80 --cgroup "$CGROUP_WORKLOAD_A" || RET_LOOP_A=$?
if [ "$RET_LOOP_A" -ne 45 ]; then
    echo "[-] FATAL: Loopback socket connect failed inside governed Workload A! Return code: $RET_LOOP_A (expected 45)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Loopback socket connect permitted inside governed Workload A!"

# Inside Ungoverned Workload B: Loopback permitted (return code 45)
RET_LOOP_B=0
"$VICTIM_BIN" --connect-loopback 80 --cgroup "$CGROUP_WORKLOAD_B" || RET_LOOP_B=$?
if [ "$RET_LOOP_B" -ne 45 ]; then
    echo "[-] FATAL: Loopback socket connect failed inside ungoverned Workload B! Return code: $RET_LOOP_B (expected 45)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Loopback socket connect permitted inside ungoverned Workload B!"

echo "[*] Step 78: Testing child process hierarchy inheritance (MORAY_WORKLOAD_INHERIT_CHILDREN)..."
CGROUP_CHILD_A="$CGROUP_WORKLOAD_A/child_task"
mkdir -p "$CGROUP_CHILD_A"
echo "[+] Created nested child cgroup: $CGROUP_CHILD_A"

RET_CHILD_WAN=0
"$VICTIM_BIN" --connect-wan 1.1.1.1 80 --cgroup "$CGROUP_CHILD_A" || RET_CHILD_WAN=$?
if [ "$RET_CHILD_WAN" -ne 44 ]; then
    echo "[-] FATAL: WAN socket was NOT blocked in child cgroup! Return code: $RET_CHILD_WAN (expected 44)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Nested child cgroup inherited boundary posture from ancestor Workload A with zero re-registration!"

echo "[*] Step 79: Testing dynamic zero-downtime workload lifecycle control (register & release)..."
# Register Workload B dynamically with DENY_ALL_NET
$MORAY_HOOK --map-path /sys/fs/bpf/moray/quarantine_map --workload-map-path /sys/fs/bpf/moray/workload_map --register-workload "$CGROUP_WORKLOAD_B" --workload-posture DENY_ALL_NET
echo "[+] Dynamically registered Workload B under DENY_ALL_NET."

RET_DYNAMIC_LOOP=0
"$VICTIM_BIN" --connect-loopback 80 --cgroup "$CGROUP_WORKLOAD_B" || RET_DYNAMIC_LOOP=$?
if [ "$RET_DYNAMIC_LOOP" -ne 48 ]; then
    echo "[-] FATAL: Dynamically governed Workload B did not block loopback under DENY_ALL_NET! Return code: $RET_DYNAMIC_LOOP (expected 48)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Dynamic registration applied in Ring 0: Workload B severed from loopback!"

# Release Workload B dynamically
$MORAY_HOOK --map-path /sys/fs/bpf/moray/quarantine_map --workload-map-path /sys/fs/bpf/moray/workload_map --release-workload "$CGROUP_WORKLOAD_B"
echo "[+] Dynamically released Workload B from governance."

RET_RELEASED_LOOP=0
"$VICTIM_BIN" --connect-loopback 80 --cgroup "$CGROUP_WORKLOAD_B" || RET_RELEASED_LOOP=$?
if [ "$RET_RELEASED_LOOP" -ne 45 ]; then
    echo "[-] FATAL: Released Workload B failed to permit loopback! Return code: $RET_RELEASED_LOOP (expected 45)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Dynamic release applied in Ring 0: Workload B restored to ungoverned state!"

echo "[*] Step 80: Clean teardown of workload test environment and final verification..."
kill -TERM "$WORKLOAD_DAEMON_PID"
sleep 1
rmdir "$CGROUP_CHILD_A" "$CGROUP_WORKLOAD_A" "$CGROUP_WORKLOAD_B" 2>/dev/null || true
rm -f /tmp/unlisted_worker /tmp/moray_boundary_workload.json /tmp/victim_*.ready
rm -rf /sys/fs/bpf/moray
}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$SCRIPT_DIR/common.sh"
    run_preflight
    run_domain_10
    echo "=========================================================="
    echo "  [+] DOMAIN 10 PASSED CLEANLY!                     "
    echo "=========================================================="
fi
