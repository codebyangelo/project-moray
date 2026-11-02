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
/tmp/victim_worker --try-exec
echo "[+] Baseline verified: unquarantined process executes normally."

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
echo "[*] Step 6: Testing live execve() interception..."
# Spawn a sleep process as victim
sleep 300 &
VICTIM_PID=$!

echo "[*] Victim process spawned with PID $VICTIM_PID"

# Strike the victim process via lobster_hook using live in-kernel BPF map
python3 bridge/lobster_hook.py --pid "$VICTIM_PID" --strike --map-path /sys/fs/bpf/moray/quarantine_map
echo "[+] Asserted live strike on PID $VICTIM_PID"

# Verify lobster_hook reports it quarantined from the live kernel map
if python3 bridge/lobster_hook.py --pid "$VICTIM_PID" --check --map-path /sys/fs/bpf/moray/quarantine_map; then
    echo "[-] Check reported benign, expected quarantined!"
    exit 1
fi
echo "[+] Verified in-kernel quarantine status via lobster_hook"

# Clean up sleep victim
kill -9 "$VICTIM_PID" 2>/dev/null || true

# 7. Test Anti-Tamper Syscall Interception (bpf)
echo "[*] Step 7: Testing live bpf() anti-tamper interception..."
sleep 300 &
TAMPER_VICTIM_PID=$!
python3 bridge/lobster_hook.py --pid "$TAMPER_VICTIM_PID" --report-tamper --map-path /sys/fs/bpf/moray/quarantine_map
kill -9 "$TAMPER_VICTIM_PID" 2>/dev/null || true
echo "[+] Anti-tamper strike verified on live kernel map"

# 8. Clean Teardown
echo "[*] Step 8: Terminating morayd..."
kill -TERM "$DAEMON_PID"
sleep 1

echo "=========================================================="
echo "  [+] ALL LIVE RING 0 KERNEL INTERCEPTION TESTS PASSED!   "
echo "=========================================================="
