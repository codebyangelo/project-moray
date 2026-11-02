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

./bin/morayd --pin-dir /sys/fs/bpf/moray --bpf-obj build/moray_kern.bpf.o > /tmp/morayd_live.log 2>&1 &
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

# Verify real BPF map pin
if [ ! -e /sys/fs/bpf/moray/quarantine_map ]; then
    echo "[-] FATAL: /sys/fs/bpf/moray/quarantine_map was not pinned!"
    exit 1
fi
echo "[+] Verified pinned BPF map: $(ls -l /sys/fs/bpf/moray/quarantine_map)"

# 6. Test Live Syscall Interception (execve)
echo "[*] Step 6: Testing live execve() interception via Ring 0 BPF-LSM..."
/tmp/victim_worker --wait-and-exec &
VICTIM_PID=$!
echo "[*] Victim process spawned (PID: $VICTIM_PID)"

# Wait for victim worker to be ready
while [ ! -f "/tmp/victim_${VICTIM_PID}.ready" ]; do
    sleep 0.05
done

# Strike the victim process via lobster_hook using live in-kernel BPF map
python3 bridge/lobster_hook.py --pid "$VICTIM_PID" --strike --map-path /sys/fs/bpf/moray/quarantine_map
echo "[+] Asserted live strike on PID $VICTIM_PID"

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

# 7. Test Anti-Tamper Syscall Interception (bpf)
echo "[*] Step 7: Testing live bpf() anti-tamper interception..."
/tmp/victim_worker --wait-and-bpf &
TAMPER_PID=$!
echo "[*] Tamper victim spawned (PID: $TAMPER_PID)"

while [ ! -f "/tmp/victim_${TAMPER_PID}.ready" ]; do
    sleep 0.05
done

python3 bridge/lobster_hook.py --pid "$TAMPER_PID" --report-tamper --map-path /sys/fs/bpf/moray/quarantine_map
echo "[+] Asserted anti-tamper containment on PID $TAMPER_PID"

kill -USR1 "$TAMPER_PID"

RET_TAMPER=0
wait "$TAMPER_PID" || RET_TAMPER=$?
if [ "$RET_TAMPER" -ne 43 ]; then
    echo "[-] FATAL: sys_bpf was NOT blocked by kernel! Exit code was $RET_TAMPER (expected 43: -EPERM)"
    exit 1
fi
echo "[+] EMPIRICAL PROOF: sys_bpf() was blocked with -EPERM by Ring 0 BPF-LSM!"

# 8. Clean Teardown
echo "[*] Step 8: Terminating morayd..."
kill -TERM "$DAEMON_PID"
sleep 1

echo "=========================================================="
echo "  [+] ALL LIVE RING 0 KERNEL INTERCEPTION TESTS PASSED!   "
echo "=========================================================="
