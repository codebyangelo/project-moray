#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray: Live Ring 0 Kernel Verification Harness
# Executed inside KVM microVM with active BPF-LSM.

set -euo pipefail

echo "=========================================================="
echo "  PROJECT MORAY: LIVE RING 0 KERNEL VERIFICATION (KVM)    "
echo "=========================================================="

# 1. Verify Host Kernel LSM Stack
echo "[*] Step 1: Checking Ring 0 LSM stack in /sys/kernel/security/lsm..."
if ! grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    echo "[-] FATAL: 'bpf' not found in /sys/kernel/security/lsm!"
    cat /sys/kernel/security/lsm 2>/dev/null || true
    exit 1
fi
echo "[+] CONFIRMED: BPF-LSM is active in running kernel: $(cat /sys/kernel/security/lsm)"

# 2. Mount bpffs
echo "[*] Step 2: Verifying BPF filesystem at /sys/fs/bpf..."
mkdir -p /sys/fs/bpf
if ! grep -q "/sys/fs/bpf" /proc/mounts; then
    mount -t bpf bpf /sys/fs/bpf
fi
echo "[+] CONFIRMED: /sys/fs/bpf mounted as bpffs (magic: $(stat -f -c %T /sys/fs/bpf))"

# 3. Compile victim worker binary
echo "[*] Step 3: Compiling victim worker..."
gcc -Wall -Wextra -O2 -std=c11 tests/victim_worker.c -o /tmp/victim_worker

# 4. Verify unquarantined baseline execution
echo "[*] Step 4: Testing unquarantined baseline (must succeed)..."
if /tmp/victim_worker --baseline-exec; then
    echo "[+] Baseline verified: unquarantined process executes normally."
else
    echo "[-] FATAL: Baseline execve failed before containment!"
    exit 1
fi

# 5. Launch morayd in Live Kernel Mode
echo "[*] Step 5: Launching morayd loader daemon in live Ring 0 mode..."
rm -rf /sys/fs/bpf/moray
mkdir -p /sys/fs/bpf/moray

./bin/morayd --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o --iface lo > /tmp/morayd_live.log 2>&1 &
DAEMON_PID=$!
sleep 2

# Verify morayd is running and pinned maps exist
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "[-] FATAL: morayd failed to start in live mode!"
    cat /tmp/morayd_live.log
    exit 1
fi
echo "[+] morayd is running (PID: $DAEMON_PID)."
cat /tmp/morayd_live.log

# Verify real BPF map pins
if [ ! -e /sys/fs/bpf/moray/quarantine_map ]; then
    echo "[-] FATAL: /sys/fs/bpf/moray/quarantine_map was not pinned!"
    exit 1
fi
echo "[+] Verified pinned BPF map: $(ls -l /sys/fs/bpf/moray/quarantine_map)"

if [ ! -e /sys/fs/bpf/moray/xdp_drop_map ]; then
    echo "[-] FATAL: /sys/fs/bpf/moray/xdp_drop_map was not pinned!"
    exit 1
fi
echo "[+] Verified pinned XDP map: $(ls -l /sys/fs/bpf/moray/xdp_drop_map)"

# 6. Test Live Syscall Interception (execve denial)
echo "[*] Step 6: Testing live execve() interception via Ring 0 BPF-LSM..."
/tmp/victim_worker --wait-and-exec &
VICTIM_PID=$!
echo "[*] Victim process spawned (PID: $VICTIM_PID)"

# Wait for victim worker to be ready
while [ ! -f "/tmp/victim_${VICTIM_PID}.ready" ]; do
    sleep 0.05
done

# Strike with MORAY_ACT_BLOCK_EXEC (1) to verify pure syscall denial without immediate termination
python3 bridge/lobster_hook.py --pid "$VICTIM_PID" --strike --action 1 --map-path /sys/fs/bpf/moray/quarantine_map
echo "[+] Asserted live strike (MORAY_ACT_BLOCK_EXEC) on PID $VICTIM_PID"

# Signal victim to proceed with execve
kill -USR1 "$VICTIM_PID"

# Wait for victim process to attempt execve
RET=0
wait "$VICTIM_PID" || RET=$?
if [ "$RET" -ne 42 ]; then
    echo "[-] FATAL: execve was NOT blocked by kernel! Exit code was $RET (expected 42: -EPERM)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: execve() was blocked with -EPERM by Ring 0 BPF-LSM!"

# 7. Test Anti-Tamper Syscall Interception (bpf denial)
echo "[*] Step 7: Testing live bpf() anti-tamper interception..."
/tmp/victim_worker --wait-and-bpf &
TAMPER_PID=$!
echo "[*] Tamper victim spawned (PID: $TAMPER_PID)"

while [ ! -f "/tmp/victim_${TAMPER_PID}.ready" ]; do
    sleep 0.05
done

# Strike with anti-tamper mask (BLOCK_EXEC | BLOCK_SOCKET | DROP_NET = 7)
python3 bridge/lobster_hook.py --pid "$TAMPER_PID" --strike --action 7 --reason 3 --map-path /sys/fs/bpf/moray/quarantine_map
echo "[+] Asserted anti-tamper containment on PID $TAMPER_PID"

kill -USR1 "$TAMPER_PID"

RET_TAMPER=0
wait "$TAMPER_PID" || RET_TAMPER=$?
if [ "$RET_TAMPER" -ne 43 ]; then
    echo "[-] FATAL: sys_bpf was NOT blocked by kernel! Exit code was $RET_TAMPER (expected 43: -EPERM)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: sys_bpf() was blocked with -EPERM by Ring 0 BPF-LSM!"

# 8. Test Active Hardware-Level Termination (SIGKILL via MORAY_ACT_KILL)
echo "[*] Step 8: Testing live active termination (SIGKILL) via Ring 0 BPF-LSM..."
/tmp/victim_worker --wait-and-exec &
KILL_PID=$!
echo "[*] Termination victim spawned (PID: $KILL_PID)"

while [ ! -f "/tmp/victim_${KILL_PID}.ready" ]; do
    sleep 0.05
done

# Full strike asserts MORAY_ACT_KILL (0x08) to trigger bpf_send_signal(9)
python3 bridge/lobster_hook.py --pid "$KILL_PID" --strike --action 255 --map-path /sys/fs/bpf/moray/quarantine_map
echo "[+] Asserted full strike (MORAY_ACT_KILL) on PID $KILL_PID"

kill -USR1 "$KILL_PID"

RET_KILL=0
wait "$KILL_PID" || RET_KILL=$?
if [ "$RET_KILL" -ne 137 ]; then
    echo "[-] FATAL: Process was NOT terminated with SIGKILL! Exit code was $RET_KILL (expected 137: 128+SIGKILL)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Ring 0 BPF-LSM auto-terminated quarantined target with SIGKILL (exit code 137)!"

# 9. Verify Real Ring 0 Telemetry Ingestion from Ringbuf (/sys/fs/bpf/moray/events)
echo "[*] Step 9: Verifying live Ring 0 telemetry extraction from /sys/fs/bpf/moray/events..."
EVENTS_OUT=$(python3 bridge/lobster_hook.py --events-path /sys/fs/bpf/moray/events --tail-events --count 5 --json)
echo "[+] Live In-Kernel Telemetry Events:"
echo "$EVENTS_OUT"

if ! echo "$EVENTS_OUT" | grep -q "BPRM_CHECK_SECURITY"; then
    echo "[-] FATAL: Live BPRM event was not retrieved from ringbuf!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: In-kernel BPF ringbuf event was consumed and validated by userspace bridge!"

# 10. Test Granular Network Policy: WAN Egress Denied with -EPERM (exit code 44)
echo "[*] Step 10: Testing granular WAN egress block via BPF-LSM..."
/tmp/victim_worker --wait-and-connect-wan 1.1.1.1 80 &
WAN_PID=$!
echo "[*] WAN victim spawned (PID: $WAN_PID)"

while [ ! -f "/tmp/victim_${WAN_PID}.ready" ]; do
    sleep 0.05
done

# Assert --block-wan (BLOCK_SOCKET | ALLOW_LOOPBACK)
python3 bridge/lobster_hook.py --pid "$WAN_PID" --block-wan --map-path /sys/fs/bpf/moray/quarantine_map
echo "[+] Asserted --block-wan policy on PID $WAN_PID"

kill -USR1 "$WAN_PID"

RET_WAN=0
wait "$WAN_PID" || RET_WAN=$?
if [ "$RET_WAN" -ne 44 ]; then
    echo "[-] FATAL: WAN socket connect was NOT blocked with -EPERM! Exit code was $RET_WAN (expected 44: -EPERM)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: WAN socket connect was blocked with -EPERM by Ring 0 BPF-LSM!"

# 11. Test Granular Network Policy: Loopback Allowed past BPF-LSM (exit code 45)
echo "[*] Step 11: Testing granular loopback exemption via BPF-LSM..."
/tmp/victim_worker --wait-and-connect-loopback 80 &
LOOP_PID=$!
echo "[*] Loopback victim spawned (PID: $LOOP_PID)"

while [ ! -f "/tmp/victim_${LOOP_PID}.ready" ]; do
    sleep 0.05
done

python3 bridge/lobster_hook.py --pid "$LOOP_PID" --block-wan --map-path /sys/fs/bpf/moray/quarantine_map
echo "[+] Asserted --block-wan policy on PID $LOOP_PID"

kill -USR1 "$LOOP_PID"

RET_LOOP=0
wait "$LOOP_PID" || RET_LOOP=$?
if [ "$RET_LOOP" -ne 45 ]; then
    echo "[-] FATAL: Loopback connect was blocked by LSM! Exit code was $RET_LOOP (expected 45: permitted past LSM)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Loopback socket connect was permitted by Ring 0 BPF-LSM under --block-wan!"

# 12. Test Total Network Block: Deny All Net Blocks Loopback with -EPERM (exit code 48)
echo "[*] Step 12: Testing total network block (--deny-all-net) denying loopback with -EPERM..."
/tmp/victim_worker --wait-and-assert-loopback-blocked 80 &
DENY_PID=$!
echo "[*] Deny-all victim spawned (PID: $DENY_PID)"

while [ ! -f "/tmp/victim_${DENY_PID}.ready" ]; do
    sleep 0.05
done

python3 bridge/lobster_hook.py --pid "$DENY_PID" --deny-all-net --map-path /sys/fs/bpf/moray/quarantine_map
echo "[+] Asserted --deny-all-net policy on PID $DENY_PID"

kill -USR1 "$DENY_PID"

RET_DENY=0
wait "$DENY_PID" || RET_DENY=$?
if [ "$RET_DENY" -ne 48 ]; then
    echo "[-] FATAL: Loopback was NOT blocked under --deny-all-net! Exit code was $RET_DENY (expected 48: -EPERM)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Total network block severed loopback socket with -EPERM!"

# 13. Test Live Wire-Level XDP Drop Map Programming
echo "[*] Step 13: Testing live XDP drop map registration and inspection..."
python3 bridge/lobster_hook.py --xdp-drop-ip 198.51.100.1 --xdp-map-path /sys/fs/bpf/moray/xdp_drop_map --json
echo "[+] Programmed wire-level XDP drop for 198.51.100.1 in live kernel"

# Assert check reports dropped (exit code 1)
XDP_CHECK_RET=0
python3 bridge/lobster_hook.py --xdp-check-ip 198.51.100.1 --xdp-map-path /sys/fs/bpf/moray/xdp_drop_map || XDP_CHECK_RET=$?
if [ "$XDP_CHECK_RET" -ne 1 ]; then
    echo "[-] FATAL: XDP dropped IP was not recognized by live map check!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Live in-kernel XDP drop map registered and verified target IP!"

# Assert removal
python3 bridge/lobster_hook.py --xdp-remove-ip 198.51.100.1 --xdp-map-path /sys/fs/bpf/moray/xdp_drop_map --json
XDP_CHECK_POST=0
python3 bridge/lobster_hook.py --xdp-check-ip 198.51.100.1 --xdp-map-path /sys/fs/bpf/moray/xdp_drop_map || XDP_CHECK_POST=$?
if [ "$XDP_CHECK_POST" -ne 0 ]; then
    echo "[-] FATAL: XDP dropped IP was still present after removal!"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: Live in-kernel XDP drop map successfully removed target IP!"

# 14. Clean Teardown
echo "[*] Step 14: Terminating morayd..."
kill -TERM "$DAEMON_PID"
sleep 1

echo "=========================================================="
echo "  [+] ALL LIVE RING 0 KERNEL INTERCEPTION TESTS PASSED!   "
echo "=========================================================="
