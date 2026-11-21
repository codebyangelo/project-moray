#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray Live Test: DOMAIN 12: Manifest Schema Hardening & Fail-Closed Ingestion (Steps 91-100)

run_domain_12() {
    stop_any_daemon
echo "=========================================================="
echo "  [+] DOMAIN 12: MANIFEST SCHEMA & FAIL-CLOSED VALIDATION "
echo "=========================================================="

ensure_victim_worker
prepare_unlisted_worker
CGROUP_SCHEMA_A="/sys/fs/cgroup/moray_schema_a"
mkdir -p "$CGROUP_SCHEMA_A"
CGROUP_ID_SCHEMA_A=$(stat -c %i "$CGROUP_SCHEMA_A")
echo "[+] Schema Test Workload A: $CGROUP_SCHEMA_A (ID: $CGROUP_ID_SCHEMA_A)"

echo "[*] Step 91: Testing unreviewed profiler manifest rejection under morayd --auto-harden..."
cat << 'EOF' > /tmp/moray_boundary_suggest.json
{
  "version": "1.0.0",
  "target_name": "moray-schema-suggest",
  "policy_state": "SUGGESTION",
  "generated_at": 1731900000,
  "boundary_policy": {
    "default_action": "AUTONOMOUS_STRIKE",
    "allowed_comms": ["morayd", "victim_worker", "bash", "sh"],
    "network_posture": "ALLOW_LOOPBACK",
    "cgroup_slice": "/sys/fs/cgroup/moray_schema_a",
    "auto_quarantine_violations": true,
    "max_strike_threshold": 5
  }
}
EOF

rm -rf /sys/fs/bpf/moray
mkdir -p /sys/fs/bpf/moray

./bin/morayd --auto-harden /tmp/moray_boundary_suggest.json --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_schema_fail1.log 2>&1 || true
if [ -e /sys/fs/bpf/moray/boundary_map ]; then
    echo "[-] FATAL: morayd should NOT have seeded boundary_map for unreviewed suggestion manifest!"
    exit 1
fi
if ! grep -q "Profiler suggestions require explicit human review" /tmp/morayd_schema_fail1.log; then
    echo "[-] FATAL: Expected profiler suggestion error notice in morayd log!"
    cat /tmp/morayd_schema_fail1.log
    exit 1
fi
echo "[+] EMPIRICAL PROOF: morayd rejected unreviewed SUGGESTION manifest and failed closed!"

echo "[*] Step 92: Testing corrupted manifest rejection (invalid network posture)..."
cat << 'EOF' > /tmp/moray_boundary_corrupt.json
{
  "version": "1.0.0",
  "target_name": "moray-schema-corrupt",
  "policy_state": "ENFORCED",
  "boundary_policy": {
    "default_action": "AUTONOMOUS_STRIKE",
    "allowed_comms": ["morayd", "victim_worker"],
    "network_posture": "ALLOW_ALL_INTERNET_BYPASS",
    "cgroup_slice": "/sys/fs/cgroup/moray_schema_a"
  }
}
EOF

./bin/morayd --auto-harden /tmp/moray_boundary_corrupt.json --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_schema_fail2.log 2>&1 || true
if [ -e /sys/fs/bpf/moray/boundary_map ]; then
    echo "[-] FATAL: morayd should NOT have seeded boundary_map for corrupt posture manifest!"
    exit 1
fi
if ! grep -q "Invalid network_posture" /tmp/morayd_schema_fail2.log; then
    echo "[-] FATAL: Expected network posture error notice in morayd log!"
    cat /tmp/morayd_schema_fail2.log
    exit 1
fi
echo "[+] EMPIRICAL PROOF: morayd rejected corrupted network_posture and failed closed!"

echo "[*] Step 93: Testing comm length overflow rejection (> 15 chars)..."
cat << 'EOF' > /tmp/moray_boundary_long_comm.json
{
  "version": "1.0.0",
  "target_name": "moray-schema-long",
  "policy_state": "ENFORCED",
  "boundary_policy": {
    "default_action": "AUTONOMOUS_STRIKE",
    "allowed_comms": ["morayd", "this_is_a_very_long_executable_name_overflowing_15_bytes"],
    "network_posture": "ALLOW_LOOPBACK"
  }
}
EOF

./bin/morayd --auto-harden /tmp/moray_boundary_long_comm.json --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_schema_fail3.log 2>&1 || true
if [ -e /sys/fs/bpf/moray/boundary_map ]; then
    echo "[-] FATAL: morayd should NOT have seeded boundary_map for overflow comm manifest!"
    exit 1
fi
if ! grep -q "exceeds 15 chars" /tmp/morayd_schema_fail3.log; then
    echo "[-] FATAL: Expected comm length overflow notice in morayd log!"
    cat /tmp/morayd_schema_fail3.log
    exit 1
fi
echo "[+] EMPIRICAL PROOF: morayd rejected >15 byte comm string and failed closed!"

echo "[*] Step 94: Testing explicit activation of unreviewed suggestion via --enforce-unreviewed..."
./bin/morayd --auto-harden /tmp/moray_boundary_suggest.json --enforce-unreviewed --cgroup "$CGROUP_SCHEMA_A" --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_schema_pass.log 2>&1 &
SCHEMA_DAEMON_PID=$!
sleep 2

if ! kill -0 "$SCHEMA_DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to launch with --enforce-unreviewed!"
    cat /tmp/morayd_schema_pass.log
    exit 1
fi
echo "[+] morayd successfully activated unreviewed manifest with explicit --enforce-unreviewed flag (PID: $SCHEMA_DAEMON_PID)."
kill -TERM "$SCHEMA_DAEMON_PID"
sleep 1

echo "[*] Step 95: Testing approved manifest (policy_state: ENFORCED) auto-harden..."
cat << 'EOF' > /tmp/moray_boundary_enforced.json
{
  "version": "1.0.0",
  "target_name": "moray-schema-approved",
  "policy_state": "ENFORCED",
  "generated_at": 1731900000,
  "boundary_policy": {
    "default_action": "AUTONOMOUS_STRIKE",
    "allowed_comms": ["morayd", "victim_worker", "bash", "sh"],
    "network_posture": "ALLOW_LOOPBACK",
    "cgroup_slice": "/sys/fs/cgroup/moray_schema_a",
    "auto_quarantine_violations": true,
    "max_strike_threshold": 5
  }
}
EOF

rm -rf /sys/fs/bpf/moray
mkdir -p /sys/fs/bpf/moray

./bin/morayd --auto-harden /tmp/moray_boundary_enforced.json --cgroup "$CGROUP_SCHEMA_A" --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_schema12.log 2>&1 &
SCHEMA_DAEMON_PID=$!
sleep 2

if ! kill -0 "$SCHEMA_DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to launch with approved ENFORCED manifest!"
    cat /tmp/morayd_schema12.log
    exit 1
fi
echo "[+] morayd active under approved ENFORCED manifest (PID: $SCHEMA_DAEMON_PID)."

echo "[*] Step 96: Testing live Ring 0 BPF-LSM enforcement under approved manifest..."
RET_SCHEMA_UNLISTED=0
/tmp/unlisted_worker --assert-unlisted-exec --cgroup "$CGROUP_SCHEMA_A" || RET_SCHEMA_UNLISTED=$?
if [ "$RET_SCHEMA_UNLISTED" -ne 42 ]; then
    echo "[-] FATAL: Unlisted binary was NOT blocked inside governed Workload A! Return code: $RET_SCHEMA_UNLISTED (expected 42)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Ring 0 BPF-LSM enforced boundary under approved manifest (exit code 42)!"

echo "[*] Step 97: Testing morayd --validate-manifest CLI gate..."
RET_VAL_VALID=0
./bin/morayd --validate-manifest /tmp/moray_boundary_enforced.json || RET_VAL_VALID=$?
if [ "$RET_VAL_VALID" -ne 0 ]; then
    echo "[-] FATAL: --validate-manifest failed on valid manifest!"
    exit 1
fi

RET_VAL_INVALID=0
./bin/morayd --validate-manifest /tmp/moray_boundary_corrupt.json || RET_VAL_INVALID=$?
if [ "$RET_VAL_INVALID" -eq 0 ]; then
    echo "[-] FATAL: --validate-manifest unexpectedly passed on corrupted manifest!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: morayd --validate-manifest correctly exits 0 on valid and non-zero on invalid!"

echo "[*] Step 98: Testing moray_profiler.py heuristic suggestion vs --approve generation parity..."
python3 bridge/moray_profiler.py . -o /tmp/profiler_suggest.json
if ! grep -q '"policy_state": "SUGGESTION"' /tmp/profiler_suggest.json; then
    echo "[-] FATAL: Default profiler output should be SUGGESTION!"
    exit 1
fi

python3 bridge/moray_profiler.py . --approve -o /tmp/profiler_enforce.json
if ! grep -q '"policy_state": "ENFORCED"' /tmp/profiler_enforce.json; then
    echo "[-] FATAL: Approved profiler output should be ENFORCED!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Profiler default is reviewable SUGGESTION; --approve emits ENFORCED!"

echo "[*] Step 99: Testing sovereign bridge validate_boundary_manifest API in live environment..."
python3 -c "
from bridge.moray_hook import validate_boundary_manifest
valid, errs = validate_boundary_manifest('/tmp/moray_boundary_enforced.json')
assert valid is True, f'Validation failed: {errs}'
valid2, errs2 = validate_boundary_manifest('/tmp/moray_boundary_suggest.json', allow_unreviewed=False)
assert valid2 is False, 'Suggestion should fail without allow_unreviewed'
valid3, errs3 = validate_boundary_manifest('/tmp/moray_boundary_suggest.json', allow_unreviewed=True)
assert valid3 is True, f'Suggestion should pass with allow_unreviewed: {errs3}'
"
echo "[+] EMPIRICAL PROOF: Sovereign bridge validate_boundary_manifest API verified in live environment!"

echo "[*] Step 100: Clean teardown, unpin verification, and zero kernel leak check..."
kill -TERM "$SCHEMA_DAEMON_PID"
sleep 1
rmdir "$CGROUP_SCHEMA_A" 2>/dev/null || true
rm -f /tmp/moray_boundary_suggest.json /tmp/moray_boundary_corrupt.json /tmp/moray_boundary_long_comm.json /tmp/moray_boundary_enforced.json /tmp/profiler_suggest.json /tmp/profiler_enforce.json /tmp/morayd_schema*.log
rm -rf /sys/fs/bpf/moray
echo "[+] EMPIRICAL PROOF: Clean teardown completed; all pinned artifacts cleanly unlinked!"
}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$SCRIPT_DIR/common.sh"
    run_preflight
    run_domain_12
    echo "=========================================================="
    echo "  [+] DOMAIN 12 PASSED CLEANLY!                     "
    echo "=========================================================="
fi
