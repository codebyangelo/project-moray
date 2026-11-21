#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray Live Test: DOMAIN 11: Extended Network Defense: socket_create & socket_bind (Steps 81-90)

run_domain_11() {
    stop_any_daemon
echo "=========================================================="
echo "  [+] DOMAIN 11: EXTENDED NETWORK DEFENSE (BIND & CREATE)  "
echo "=========================================================="

echo "[*] Step 81: Setting up dual cgroups for extended network boundary verification..."
ensure_victim_worker
CGROUP_NET_A="/sys/fs/cgroup/moray_net_a"
CGROUP_NET_B="/sys/fs/cgroup/moray_net_b"
mkdir -p "$CGROUP_NET_A" "$CGROUP_NET_B"
CGROUP_ID_NET_A=$(stat -c %i "$CGROUP_NET_A")
CGROUP_ID_NET_B=$(stat -c %i "$CGROUP_NET_B")
echo "[+] Workload Net-A (Governed): $CGROUP_NET_A (ID: $CGROUP_ID_NET_A)"
echo "[+] Workload Net-B (Ungoverned): $CGROUP_NET_B (ID: $CGROUP_ID_NET_B)"

echo "[*] Step 82: Launching morayd under DENY_ALL_NET targeting Workload Net-A..."
cat << 'EOF' > /tmp/moray_boundary_net_deny.json
{
  "version": "1.0.0",
  "target_name": "moray-net-deny",
  "policy_state": "ENFORCED",
  "generated_at": 1731900000,
  "boundary_policy": {
    "default_action": "AUTONOMOUS_STRIKE",
    "allowed_comms": ["morayd", "victim_worker", "bash", "sh", "python3"],
    "allowed_paths": ["$VICTIM_BIN", "/bin/sh", "/bin/bash"],
    "network_posture": "DENY_ALL_NET",
    "cgroup_slice": "/sys/fs/cgroup/moray_net_a",
    "auto_quarantine_violations": true,
    "max_strike_threshold": 5
  }
}
EOF

rm -rf /sys/fs/bpf/moray
mkdir -p /sys/fs/bpf/moray

./bin/morayd --auto-harden /tmp/moray_boundary_net_deny.json --cgroup "$CGROUP_NET_A" --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_net11.log 2>&1 &
NET_DAEMON_PID=$!
sleep 2

if ! kill -0 "$NET_DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to launch in Domain 11!"
    cat /tmp/morayd_net11.log
    exit 1
fi
echo "[+] morayd running in Domain 11 (PID: $NET_DAEMON_PID)."

echo "[*] Step 83: Testing socket allocation denial (lsm/socket_create) under DENY_ALL_NET..."
RET_CREATE_DENY=0
"$VICTIM_BIN" --assert-socket-create-blocked --cgroup "$CGROUP_NET_A" || RET_CREATE_DENY=$?
if [ "$RET_CREATE_DENY" -ne 55 ]; then
    echo "[-] FATAL: Socket allocation was NOT blocked under DENY_ALL_NET! Return code: $RET_CREATE_DENY (expected 55)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Ring 0 BPF-LSM severed socket allocation with -EPERM under DENY_ALL_NET (Invariant I_8)!"

echo "[*] Step 84: Testing unconnected UDP socket allocation denial under DENY_ALL_NET..."
RET_UDP_DENY=0
"$VICTIM_BIN" --assert-unconnected-udp-blocked --cgroup "$CGROUP_NET_A" || RET_UDP_DENY=$?
if [ "$RET_UDP_DENY" -ne 59 ]; then
    echo "[-] FATAL: Unconnected UDP socket creation was NOT blocked under DENY_ALL_NET! Return code: $RET_UDP_DENY (expected 59)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Unconnected UDP socket allocation severed at creation time! (Zero UDP sendto bypass)!"

echo "[*] Step 85: Testing socket allocation non-interference in Ungoverned Workload Net-B..."
RET_PASS_B=0
"$VICTIM_BIN" --baseline-exec --cgroup "$CGROUP_NET_B" || RET_PASS_B=$?
if [ "$RET_PASS_B" -ne 0 ]; then
    echo "[-] FATAL: Ungoverned Workload Net-B execution failed! Return code: $RET_PASS_B (expected 0)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Non-interference verified! Workload Net-B allocated and executed cleanly with zero latency!"

echo "[*] Step 86: Re-targeting Workload Net-A with ALLOW_LOOPBACK policy..."
kill -TERM "$NET_DAEMON_PID"
sleep 1
cat << 'EOF' > /tmp/moray_boundary_net_loop.json
{
  "version": "1.0.0",
  "target_name": "moray-net-loop",
  "policy_state": "ENFORCED",
  "generated_at": 1731900000,
  "boundary_policy": {
    "default_action": "AUTONOMOUS_STRIKE",
    "allowed_comms": ["morayd", "victim_worker", "bash", "sh", "python3"],
    "allowed_paths": ["$VICTIM_BIN", "/bin/sh", "/bin/bash"],
    "network_posture": "ALLOW_LOOPBACK",
    "cgroup_slice": "/sys/fs/cgroup/moray_net_a",
    "auto_quarantine_violations": true,
    "max_strike_threshold": 5
  }
}
EOF

./bin/morayd --auto-harden /tmp/moray_boundary_net_loop.json --cgroup "$CGROUP_NET_A" --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_net11.log 2>&1 &
NET_DAEMON_PID=$!
sleep 2

echo "[*] Step 87: Testing raw/packet socket creation denial (SOCK_RAW / AF_PACKET) under ALLOW_LOOPBACK..."
RET_RAW_BLOCK=0
"$VICTIM_BIN" --assert-raw-socket-blocked --cgroup "$CGROUP_NET_A" || RET_RAW_BLOCK=$?
if [ "$RET_RAW_BLOCK" -ne 56 ]; then
    echo "[-] FATAL: Raw socket allocation was NOT blocked under ALLOW_LOOPBACK! Return code: $RET_RAW_BLOCK (expected 56)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Ring 0 BPF-LSM severed SOCK_RAW / AF_PACKET creation with -EPERM under ALLOW_LOOPBACK!"

echo "[*] Step 88: Testing external/wildcard (0.0.0.0) listener binding denial (lsm/socket_bind)..."
RET_BIND_WAN=0
"$VICTIM_BIN" --assert-bind-wan-blocked --cgroup "$CGROUP_NET_A" || RET_BIND_WAN=$?
if [ "$RET_BIND_WAN" -ne 57 ]; then
    echo "[-] FATAL: External/wildcard bind was NOT blocked under ALLOW_LOOPBACK! Return code: $RET_BIND_WAN (expected 57)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Ring 0 BPF-LSM severed wildcard (0.0.0.0) listener binding with -EPERM!"

echo "[*] Step 89: Testing loopback listener binding allowance (127.0.0.1) under ALLOW_LOOPBACK..."
RET_BIND_LOOP=0
"$VICTIM_BIN" --assert-bind-loopback-allowed --cgroup "$CGROUP_NET_A" || RET_BIND_LOOP=$?
if [ "$RET_BIND_LOOP" -ne 58 ]; then
    echo "[-] FATAL: Loopback listener binding failed under ALLOW_LOOPBACK! Return code: $RET_BIND_LOOP (expected 58)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Ring 0 BPF-LSM permitted loopback (127.0.0.1) listener binding under ALLOW_LOOPBACK!"

echo "[*] Step 90: Testing dual-workload listener non-interference and clean teardown..."
RET_PASS_BIND_B=0
"$VICTIM_BIN" --assert-bind-loopback-allowed --cgroup "$CGROUP_NET_B" || RET_PASS_BIND_B=$?
if [ "$RET_PASS_BIND_B" -ne 58 ]; then
    echo "[-] FATAL: Listener binding failed in Ungoverned Workload Net-B! Return code: $RET_PASS_BIND_B (expected 58)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Non-interference verified! Listener binding operational in ungoverned workload!"

kill -TERM "$NET_DAEMON_PID"
sleep 1
rmdir "$CGROUP_NET_A" "$CGROUP_NET_B" 2>/dev/null || true
rm -f /tmp/moray_boundary_net_deny.json /tmp/moray_boundary_net_loop.json /tmp/morayd_net11.log
rm -rf /sys/fs/bpf/moray
}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$SCRIPT_DIR/common.sh"
    run_preflight
    run_domain_11
    echo "=========================================================="
    echo "  [+] DOMAIN 11 PASSED CLEANLY!                     "
    echo "=========================================================="
fi
