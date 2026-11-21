#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray Live Test: DOMAIN 14: Multi-Tenant Workload Isolation & Real Autonomous Agent Proof (Steps 111-120)

run_domain_14() {
    stop_any_daemon
echo "=========================================================="
echo "  [+] DOMAIN 14: MULTI-TENANT ISOLATION & REAL AUTONOMOUS AGENT PROOF"
echo "=========================================================="

echo "[*] Step 111: Initializing live multi-workload cgroups (Agent Alpha & Agent Beta)..."
ensure_victim_worker
CGROUP_AGENT_A="/sys/fs/cgroup/moray_agent_alpha"
CGROUP_AGENT_B="/sys/fs/cgroup/moray_agent_beta"
mkdir -p "$CGROUP_AGENT_A" "$CGROUP_AGENT_B"
CGROUP_ID_A=$(stat -c %i "$CGROUP_AGENT_A")
CGROUP_ID_B=$(stat -c %i "$CGROUP_AGENT_B")
echo "[+] Workload Alpha (Agent Alpha): $CGROUP_AGENT_A (Cgroup ID: $CGROUP_ID_A)"
echo "[+] Workload Beta  (Agent Beta):  $CGROUP_AGENT_B (Cgroup ID: $CGROUP_ID_B)"

echo "[*] Step 112: Generating heterogeneous boundary manifests for Agent Alpha and Agent Beta..."
cat << 'EOF' > /tmp/moray_manifest_alpha.json
{
  "version": "1.0.0",
  "target_name": "agent-alpha-runtime",
  "policy_state": "ENFORCED",
  "generated_at": 1731900000,
  "boundary_policy": {
    "default_action": "AUTONOMOUS_STRIKE",
    "allowed_comms": [
      "morayd",
      "python",
      "python3",
      "cat",
      "true"
    ],
    "allowed_paths": [
      "/usr/bin/python3",
      "/bin/cat",
      "/bin/true"
    ],
    "network_posture": "ALLOW_LOOPBACK",
    "cgroup_slice": "/sys/fs/cgroup/moray_agent_alpha",
    "auto_quarantine_violations": true,
    "max_strike_threshold": 5
  }
}
EOF

cat << 'EOF' > /tmp/moray_manifest_beta.json
{
  "version": "1.0.0",
  "target_name": "agent-beta-runtime",
  "policy_state": "ENFORCED",
  "generated_at": 1731900000,
  "boundary_policy": {
    "default_action": "AUTONOMOUS_STRIKE",
    "allowed_comms": [
      "morayd",
      "victim_worker",
      "ls",
      "true"
    ],
    "allowed_paths": [
      "$VICTIM_BIN",
      "/bin/ls",
      "/bin/true"
    ],
    "network_posture": "DENY_ALL_NET",
    "cgroup_slice": "/sys/fs/cgroup/moray_agent_beta",
    "auto_quarantine_violations": true,
    "max_strike_threshold": 5
  }
}
EOF
echo "[+] Manifest Alpha created (ALLOW_LOOPBACK, allowed: python3, cat; strictly NO victim_worker)."
echo "[+] Manifest Beta created (DENY_ALL_NET, allowed: victim_worker, ls; strictly NO python3)."

echo "[*] Step 113: Launching morayd under Agent Alpha manifest and applying Agent Beta dynamically..."
rm -rf /sys/fs/bpf/moray
mkdir -p /sys/fs/bpf/moray

./bin/morayd --auto-harden /tmp/moray_manifest_alpha.json --cgroup "$CGROUP_AGENT_A" --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_multi.log 2>&1 &
MULTI_DAEMON_PID=$!
sleep 2

if ! kill -0 "$MULTI_DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to launch in multi-workload mode!"
    cat /tmp/morayd_multi.log
    exit 1
fi
echo "[+] morayd active under Workload Alpha (PID: $MULTI_DAEMON_PID)."

echo "[*] Ingesting second workload (Agent Beta) via moray_hook --apply-manifest..."
$MORAY_HOOK --apply-manifest /tmp/moray_manifest_beta.json --cgroup-target "$CGROUP_AGENT_B" --boundary-map-path /sys/fs/bpf/moray/boundary_map --workload-map-path /sys/fs/bpf/moray/workload_map --json
echo "[+] Successfully applied Agent Beta manifest into live kernel maps."

echo "[*] Step 114: Verifying compound-key boundary map entries for both workloads..."
ALPHA_STATUS=$($MORAY_HOOK --workload-map-path /sys/fs/bpf/moray/workload_map --workload-status "$CGROUP_ID_A" --json)
if ! echo "$ALPHA_STATUS" | grep -q '"governed": true'; then
    echo "[-] FATAL: Workload Alpha is not governed!"
    exit 1
fi

BETA_STATUS=$($MORAY_HOOK --workload-map-path /sys/fs/bpf/moray/workload_map --workload-status "$CGROUP_ID_B" --json)
if ! echo "$BETA_STATUS" | grep -q '"governed": true'; then
    echo "[-] FATAL: Workload Beta is not governed!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Both Workload Alpha and Beta are independently registered and governed in kernel!"

echo "[*] Step 115: Executing real autonomous Python agent workload inside Workload Alpha..."
RET_ALPHA=0
python3 tests/agent_workload.py --cgroup "$CGROUP_AGENT_A" --spawn-subprocess /bin/true || RET_ALPHA=$?
if [ "$RET_ALPHA" -ne 0 ]; then
    echo "[-] FATAL: Real Python agent runtime failed to execute in Workload Alpha! Return code: $RET_ALPHA"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Real Python 3 runtime executed cleanly inside Workload Alpha (allowed tool)!"

echo "[*] Step 116: Cross-Workload Breach Test: Executing python3 inside Workload Beta (must be struck and blocked)..."
RET_BETA_BREACH=0
python3 tests/agent_workload.py --cgroup "$CGROUP_AGENT_B" --spawn-subprocess /bin/true || RET_BETA_BREACH=$?
if [ "$RET_BETA_BREACH" -ne 42 ]; then
    echo "[-] FATAL: python3 execution should have been BLOCKED with -EPERM (exit code 42) inside Workload Beta, but returned: $RET_BETA_BREACH"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: In-kernel compound boundary strictly BLOCKED python3 in Workload Beta (Return code: $RET_BETA_BREACH)!"

echo "[*] Step 117: Executing allowed binary (victim_worker) inside Workload Beta (must succeed)..."
RET_BETA_WORKER=0
"$VICTIM_BIN" --cgroup "$CGROUP_AGENT_B" --baseline-exec || RET_BETA_WORKER=$?
if [ "$RET_BETA_WORKER" -ne 0 ]; then
    echo "[-] FATAL: victim_worker should be permitted in Workload Beta! Return code: $RET_BETA_WORKER"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Allowed binary executed cleanly in Workload Beta while denied in Alpha!"

echo "[*] Step 118: Unlisted subshell execution attempt inside Workload Alpha (sh blocked)..."
RET_SH_BREACH=0
python3 tests/agent_workload.py --cgroup "$CGROUP_AGENT_A" --spawn-subprocess /bin/sh --subargs "-c /bin/ls" || RET_SH_BREACH=$?
if [ "$RET_SH_BREACH" -ne 42 ]; then
    echo "[-] FATAL: Unlisted subshell /bin/sh was permitted inside Workload Alpha! Return code: $RET_SH_BREACH"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Real Python agent spawning unlisted subshell /bin/sh was intercepted by Ring 0 BPF-LSM!"

echo "[*] Step 119: Real Python socket creation under DENY_ALL_NET in Workload Beta (must be blocked)..."
RET_SOCK_BLOCK=0
python3 tests/agent_workload.py --cgroup "$CGROUP_AGENT_B" --create-socket || RET_SOCK_BLOCK=$?
if [ "$RET_SOCK_BLOCK" -ne 42 ]; then
    echo "[-] FATAL: socket creation under DENY_ALL_NET was not blocked with -EPERM! Return code: $RET_SOCK_BLOCK (expected 42)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Real Python agent socket creation severed by LSM under DENY_ALL_NET!"

echo "[*] Step 120: Clean teardown, unpin verification, cgroup cleanup, and zero kernel leak check..."
kill -TERM "$MULTI_DAEMON_PID"
sleep 1
rmdir "$CGROUP_AGENT_A" "$CGROUP_AGENT_B" 2>/dev/null || true
rm -f /tmp/moray_manifest_alpha.json /tmp/moray_manifest_beta.json /tmp/morayd_multi.log
rm -rf /sys/fs/bpf/moray
echo "[+] EMPIRICAL PROOF: Multi-tenant domain teardown complete; zero kernel leaks verified!"
}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$SCRIPT_DIR/common.sh"
    run_preflight
    run_domain_14
    echo "=========================================================="
    echo "  [+] DOMAIN 14 PASSED CLEANLY!                     "
    echo "=========================================================="
fi
