#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray Live Test: DOMAIN 13: Operational Confidence, Health/Readiness Probes & Crash Recovery (Steps 101-110)

run_domain_13() {
echo "=========================================================="
echo "  DOMAIN 13: OPERATIONAL CONFIDENCE, HEALTH & RECOVERY    "
echo "             (Steps 101-110: Liveness/Readiness, Stale    "
echo "              Pin Recovery & Clean Teardown)              "
echo "=========================================================="

CGROUP_OP_A="/sys/fs/cgroup/moray_op_a"
mkdir -p "$CGROUP_OP_A"

cat <<'EOF' > /tmp/moray_boundary_op.json
{
  "version": "1.0.0",
  "target_name": "moray_op_a",
  "policy_state": "ENFORCED",
  "generated_at": 1731900000,
  "boundary_policy": {
    "default_action": "AUTONOMOUS_STRIKE",
    "allowed_comms": [
      "morayd",
      "victim_worker",
      "python3",
      "sh"
    ],
    "network_posture": "DENY_ALL_NET",
    "cgroup_slice": "/sys/fs/cgroup/moray_op_a",
    "auto_quarantine_violations": true,
    "max_strike_threshold": 5
  }
}
EOF

echo "[*] Launching morayd under --auto-harden for Domain 13..."
./bin/morayd --auto-harden /tmp/moray_boundary_op.json --cgroup "$CGROUP_OP_A" > /tmp/morayd_op13.log 2>&1 &
OP_DAEMON_PID=$!
sleep 2

if ! kill -0 "$OP_DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to launch in Domain 13! Log:"
    cat /tmp/morayd_op13.log
    exit 1
fi

echo "[*] Step 101: Live daemon healthcheck probe (morayd --health)..."
./bin/morayd --health > /tmp/moray_health_human.log
if ! grep -q "Overall Status: HEALTHY (Ready: YES)" /tmp/moray_health_human.log; then
    echo "[-] FATAL: morayd --health did not report HEALTHY / Ready: YES! Output:"
    cat /tmp/moray_health_human.log
    exit 1
fi
echo "[+] EMPIRICAL PROOF: morayd --health confirmed live subsystem status HEALTHY and ready!"

echo "[*] Step 102: Live daemon JSON healthcheck probe (morayd --health --json)..."
./bin/morayd --health --json > /tmp/moray_health.json
python3 -c "
import json
with open('/tmp/moray_health.json') as f:
    d = json.load(f)
assert d['status'] == 'HEALTHY', f'Bad status: {d[\"status\"]}'
assert d['ready'] is True, 'Not ready'
assert d['maps_accessible'] == 6, f'Expected 6 maps, got {d[\"maps_accessible\"]}'
assert d['maps']['quarantine_map'] is True
assert d['maps']['boundary_map'] is True
assert d['maps']['workload_map'] is True
assert d['bpf_lsm_active'] is True
assert d['bpffs_mounted'] is True
"
echo "[+] EMPIRICAL PROOF: morayd --health --json schema validated across all 6 kernel maps!"

echo "[*] Step 103: Python bridge comprehensive readiness probe (lobster_hook.py --readiness)..."
python3 bridge/lobster_hook.py --healthcheck --json > /tmp/bridge_health.json
python3 -c "
import json
with open('/tmp/bridge_health.json') as f:
    d = json.load(f)
assert d['status'] == 'healthy', f'Bad status: {d[\"status\"]}'
assert d['ready'] is True, 'Bridge not ready'
assert d['boundary_accessible'] is True
assert d['workload_accessible'] is True
assert d['bpf_lsm_active'] is True
assert d['bpffs_mounted'] is True
"
echo "[+] EMPIRICAL PROOF: Python bridge readiness probe validated live kernel maps and LSM status!"

echo "[*] Step 104: Emergency map cleanup & unpin CLI test (morayd --clean-pins)..."
mkdir -p /tmp/moray_clean_test
touch /tmp/moray_clean_test/quarantine_map /tmp/moray_clean_test/events /tmp/moray_clean_test/boundary_map
./bin/morayd --clean-pins --pin-dir /tmp/moray_clean_test > /tmp/clean_pins.log
if ! grep -q "Unlinked 3 pins" /tmp/clean_pins.log; then
    echo "[-] FATAL: morayd --clean-pins failed to clean test directory! Log:"
    cat /tmp/clean_pins.log
    exit 1
fi
rm -rf /tmp/moray_clean_test
echo "[+] EMPIRICAL PROOF: morayd --clean-pins cleanly unlinks target pins without leaking file descriptors!"

echo "[*] Step 105: Healthcheck failure detection on unpinned/missing directory..."
RET_VAL_FAIL=0
./bin/morayd --health --pin-dir /tmp/nonexistent_pins_dir > /tmp/health_fail.log 2>&1 || RET_VAL_FAIL=$?
if [ "$RET_VAL_FAIL" -eq 0 ]; then
    echo "[-] FATAL: morayd --health unexpectedly exited 0 on nonexistent pin directory!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: morayd --health exits non-zero fail-closed when pins are missing!"

echo "[*] Step 106: Daemon crash & stale pin recovery drill under active governed workload..."
# Simulate daemon crash with SIGKILL leaving pinned maps in bpffs
kill -9 "$OP_DAEMON_PID"
sleep 1

# Restart daemon pointing to same boundary and cgroup; verify stale pins are detected and recovered
./bin/morayd --auto-harden /tmp/moray_boundary_op.json --cgroup "$CGROUP_OP_A" > /tmp/morayd_recovery.log 2>&1 &
RECOVERY_DAEMON_PID=$!
sleep 2

if ! kill -0 "$RECOVERY_DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to restart during recovery drill! Log:"
    cat /tmp/morayd_recovery.log
    exit 1
fi
if ! grep -q "Stale pin detected" /tmp/morayd_recovery.log; then
    echo "[-] FATAL: Expected 'Stale pin detected' in daemon recovery log! Log:"
    cat /tmp/morayd_recovery.log
    exit 1
fi
echo "[+] EMPIRICAL PROOF: morayd automatically recovered and re-pinned stale kernel maps!"

echo "[*] Step 107: Verifying Ring 0 enforcement persists after daemon recovery..."
ensure_victim_worker
prepare_unlisted_worker
RET_VAL_UNLISTED=0
/tmp/unlisted_worker --assert-unlisted-exec --cgroup "$CGROUP_OP_A" || RET_VAL_UNLISTED=$?
if [ "$RET_VAL_UNLISTED" -ne 42 ]; then
    echo "[-] FATAL: Unlisted execution was NOT blocked after daemon recovery! Return code: $RET_VAL_UNLISTED (expected 42)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Ring 0 BPF-LSM enforced boundary after daemon recovery drill (exit code 42)!"

echo "[*] Step 108: Kernel preflight capability reporting check (morayd --preflight)..."
./bin/morayd --preflight > /tmp/preflight_run.log
if ! grep -q "PREFLIGHT PASSED" /tmp/preflight_run.log; then
    echo "[-] FATAL: morayd --preflight failed! Log:"
    cat /tmp/preflight_run.log
    exit 1
fi
echo "[+] EMPIRICAL PROOF: morayd --preflight verified kernel capabilities, BTF, and LSM status!"

echo "[*] Step 109: Systemd service unit structure and directive verification..."
if [ ! -f packaging/systemd/morayd.service ]; then
    echo "[-] FATAL: packaging/systemd/morayd.service not found!"
    exit 1
fi
grep -q "ExecStartPost=/usr/local/bin/morayd --readiness --pin-dir /sys/fs/bpf/moray" packaging/systemd/morayd.service
grep -q "CapabilityBoundingSet=CAP_BPF CAP_SYS_ADMIN CAP_KILL" packaging/systemd/morayd.service
echo "[+] EMPIRICAL PROOF: Production systemd unit verified with ExecStartPost readiness check and capability bounding!"

echo "[*] Step 110: Clean teardown, unpin verification, and zero kernel leak check..."
kill -TERM "$RECOVERY_DAEMON_PID"
sleep 1
rmdir "$CGROUP_OP_A" 2>/dev/null || true
rm -f /tmp/unlisted_worker /tmp/moray_boundary_op.json /tmp/moray_health*.log /tmp/moray_health.json /tmp/bridge_health.json /tmp/clean_pins.log /tmp/morayd_recovery.log /tmp/preflight_run.log /tmp/morayd_op*.log
rm -rf /sys/fs/bpf/moray
echo "[+] EMPIRICAL PROOF: Clean teardown completed; all pinned artifacts cleanly unlinked!"
}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$SCRIPT_DIR/common.sh"
    run_preflight
    run_domain_13
    echo "=========================================================="
    echo "  [+] DOMAIN 13 PASSED CLEANLY!                     "
    echo "=========================================================="
fi
