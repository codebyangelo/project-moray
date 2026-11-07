# Project Moray: Operational Runbook & Incident Response Guide

> **Classification:** Production Systems Engineering / SRE & SecOps Operations  
> **Target Subsystems:** Linux Kernel Ring 0 (BPF-LSM, bpffs, perf ringbuf) & Userspace Bridge (`morayd`, `lobster_hook`)  
> **Security Baseline:** Fail-Closed ($I_1$), Deterministic Fast-Path ($I_2$), Non-Bypassable Ring 0 Mediation ($I_3$)

---

## 1. System Architecture & Component Mapping

Project Moray provides autonomous AI agent containment through hardware-enforced Ring 0 Linux kernel mediation. The operational boundary consists of three primary components:

```
+-------------------------------------------------------------------------------+
|                             USERSPACE SUPERVISOR                              |
|                                                                               |
|  [Autonomous AI Agent]          [Project Lobster]         [SecOps SRE / CLI]  |
|         |                              |                          |           |
|         v                              v                          v           |
|  (Untrusted PID) -------------> [lobster_hook.py] <----> [systemd / morayd]   |
|                                        |                  [moray_profiler.py] |
|                                        |                  [moray_boundary.json|
+----------------------------------------|--------------------------|-----------+
                                         | (bpf syscall / ctypes)   |
=========================================v==========================v============
|                             LINUX KERNEL (RING 0)                             |
|                                                                               |
|  /sys/fs/bpf/moray/quarantine_map (BPF_MAP_TYPE_HASH, max 1024 entries)       |
|  /sys/fs/bpf/moray/cgroup_map     (BPF_MAP_TYPE_HASH, max 1024 entries)       |
|  /sys/fs/bpf/moray/boundary_map   (BPF_MAP_TYPE_HASH, max 1024 entries)       |
|  /sys/fs/bpf/moray/events         (BPF_MAP_TYPE_RINGBUF, 256 KB bounded)     |
|  /sys/fs/bpf/moray/xdp_drop_map   (BPF_MAP_TYPE_HASH, max 1024 entries)       |
|                                                                               |
|  [LSM Hook: bprm_check_security] ---------> Intercept execve (-EPERM/SIGKILL) |
|  [LSM Hook: socket_connect] --------------> Intercept egress socket (-EPERM) |
|  [LSM Hook: bpf (Anti-Tamper)] -----------> Intercept sys_bpf (-EPERM)        |
|  [XDP Driver Hook: moray_xdp_filter] -----> Line-rate packet drop (XDP_DROP) |
+-------------------------------------------------------------------------------+
```

### Component Inventory
1. **`bin/morayd`**: The userspace loader daemon. Executes kernel preflight checks, mounts `/sys/fs/bpf`, loads BPF-LSM programs, seeds autonomous boundary policies via `--auto-harden`, pins kernel maps to `/sys/fs/bpf/moray`, and handles signal termination.
2. **`build/moray_kern.bpf.o`**: Restricted C bytecode executing in Ring 0. Intercepts `execve`, `socket`, and `bpf` syscalls from quarantined processes, tracks strike counts atomically, enforces autonomous boundary whitelists, and dispatches ringbuf telemetry.
3. **`bridge/lobster_hook.py`**: Zero-dependency Python ctypes bridge for Project Lobster. Provides fail-closed strike asserting, cgroup v2 containment, TTL auto-expiry checking, and structured JSON telemetry querying.
4. **`bridge/moray_profiler.py`**: Sovereign, zero-dependency workspace inspector and boundary policy synthesizer. Generates machine-readable `moray_boundary.json` manifests.
5. **`bridge/moray_hook.py`**: Native sovereign Python bridge and NDJSON telemetry streaming consumer for Project Moray.
6. **`moray_boundary.json`**: Standardized machine-readable boundary policy manifest defining permitted executables, network posture, and default containment action.
7. **`packaging/systemd/morayd.service`**: Production systemd service unit providing sandboxed, least-privilege daemon management.

---

## 2. Deployment & Service Management

### Prerequisites & Kernel Capability Matrix
Before deploying `morayd`, verify that the host kernel satisfies the requirements defined in [`COMPATIBILITY.md`](file:///root/home/projects/project-moray/docs/COMPATIBILITY.md):
- **Kernel Version**: Linux $\ge 5.7$ (Linux $\ge 5.15$ recommended for complete LSM BPF stability).
- **Kernel Build Config**:
  - `CONFIG_BPF_LSM=y`
  - `CONFIG_DEBUG_INFO_BTF=y`
  - `CONFIG_BPF_SYSCALL=y`
- **Boot Parameter**: Host `/proc/cmdline` must include `lsm=...,bpf`.
- **Privilege Requirements**: `CAP_BPF` + `CAP_SYS_ADMIN` (or `root` / `euid 0`).

### Host Arming & Bootloader Configuration (Pre-Deployment)
On standard distribution kernels, `bpf` is not active in the LSM order by default. The host must be armed and rebooted before launching `morayd`:

1. **Check & Append Active LSMs**:
   ```bash
   CURRENT_LSM=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "lockdown,capability,landlock,yama,apparmor")
   # Ubuntu / Debian:
   sudo sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="lsm='"${CURRENT_LSM}"',bpf /' /etc/default/grub
   sudo update-grub

   # Fedora / RHEL / Rocky / Amazon Linux 2023:
   sudo grubby --update-kernel=ALL --args="lsm=${CURRENT_LSM},bpf"
   ```

2. **Mount BPF Filesystem Permanently**:
   ```bash
   echo "bpffs /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0" | sudo tee -a /etc/fstab
   sudo mount -a
   ```

3. **Reboot Host**:
   ```bash
   sudo reboot
   ```
   *(For detailed distribution matrices, see [`COMPATIBILITY.md`](file:///root/home/projects/project-moray/docs/COMPATIBILITY.md#3-arming-bpf-lsm-across-linux-distributions))*.

### Installation via Systemd

1. **Install Binaries**:
   ```bash
   install -m 0755 bin/morayd /usr/local/bin/morayd
   install -m 0644 build/moray_kern.bpf.o /usr/local/share/moray/moray_kern.bpf.o
   install -m 0755 bridge/lobster_hook.py /usr/local/bin/lobster-hook
   ```

2. **Deploy Service Unit**:
   ```bash
   install -m 0644 packaging/systemd/morayd.service /etc/systemd/system/morayd.service
   systemctl daemon-reload
   ```

3. **Validate Preflight Manually**:
   ```bash
   /usr/local/bin/morayd --preflight
   # Expected output:
   # [+] PREFLIGHT PASSED: Root privilege confirmed, BPF-LSM active in kernel, /sys/fs/bpf verified.
   ```

4. **Enable & Start Daemon**:
   ```bash
   systemctl enable --now morayd.service
   systemctl status morayd.service
   ```

---

## 3. Liveness Probing & Healthchecks

### Automated Probe API
Automated monitoring agents (Prometheus node-exporter, Kubernetes liveness probes, Consul healthchecks) should query `lobster_hook.py --healthcheck`:

```bash
python3 /usr/local/bin/lobster-hook --healthcheck --json
```

**Healthy Response (Exit Code `0`):**
```json
{
  "status": "healthy",
  "mock_mode": false,
  "map_path": "/sys/fs/bpf/moray/quarantine_map",
  "map_accessible": true,
  "bpffs_mounted": true,
  "bpf_lsm_active": true,
  "quarantined_count": 0,
  "warnings": []
}
```

**Status Codes:**
- `0 (healthy)`: All kernel subsystems, mounts, and map pins are verified and accessible.
- `1 (degraded)`: BPF-LSM or map pin degraded; running in fallback or mock mode.
- `252 (unhealthy / fail-closed)`: Critical failure; `/sys/fs/bpf` inaccessible or securityfs missing.

---

## 4. SecOps Incident Response Playbooks

### IR-01: Triage Quarantined Agent Process
When an autonomous AI agent process is reported failing with `-EPERM` on execution or socket creation:

1. **Identify Agent PID**:
   ```bash
   pgrep -f "agent-worker"
   # Example PID: 4096
   ```

2. **Query Structured Quarantine Status**:
   ```bash
   python3 /usr/local/bin/lobster-hook --pid 4096 --status --json
   ```
   **Output Inspection**:
   ```json
   {
     "pid": 4096,
     "state": "ACTIVE",
     "quarantined": true,
     "action_flags": 3,
     "reason": 1,
     "strike_count": 2,
     "ttl_seconds": 300,
     "remaining_seconds": 248,
     "timestamp_ns": 1730551200000000000
   }
   ```
   - `action_flags`: `0x01` (`BLOCK_EXEC`), `0x02` (`BLOCK_NET`), `0x04` (`KILL`).
   - `reason`: `1` (`LOBSTER_L7`), `2` (`EXEC_VIOLATION`), `3` (`SOCKET_VIOLATION`), `4` (`TAMPER_ATTEMPT`).
   - `strike_count`: Number of times the kernel blocked this process from executing disallowed actions.

### IR-02: Telemetry Extraction & Trace Inspection
To inspect live interception events directly from the Ring 0 ring buffer or the kernel trace pipe:

1. **Continuous Structured Audit Stream (SIEM / ndjson ingestion)**:
   ```bash
   python3 bridge/lobster_hook.py --stream-events --json
   ```
2. **Tail Recent Formatted Telemetry Lines**:
   ```bash
   python3 bridge/lobster_hook.py --tail-events --count 20
   ```
   **Sample Output**:
   ```text
   [2026-11-02 17:50:12.123] PID 191 (tgid: 191, comm: 'victim_worker') INTERCEPTED at BPRM_CHECK_SECURITY (action: 0x01, ret: -1, strikes: 1)
   ```
3. **Raw Ring 0 Printk Trace Stream (Fallback)**:
   ```bash
   cat /sys/kernel/debug/tracing/trace_pipe | grep "MORAY STRIKE"
   ```
   **Sample Trace**:
   ```text
   agent-worker-4096  [002] d... 1421.501230: bpf_trace_printk: MORAY STRIKE: Intercepted execve from PID 4096 (hits: 3)
   ```

### IR-03: Strike Tier Escalation Handling
Moray enforces dynamic strike escalation in Ring 0:
- **Tier 1 (1 hit)**: Blocks `execve` with `-EPERM`. Target process receives permission denied.
- **Tier 2 (3 hits)**: Blocks outbound network socket allocation. Target loses egress network capabilities.
- **Tier 3 ($\ge 5$ hits)**: Kernel dispatches `SIGKILL` (`bpf_send_signal(9)`). The rogue process is terminated immediately.

If an agent was terminated by Tier 3 escalation:
1. Verify termination in `dmesg`:
   ```bash
   dmesg -T | grep -E "MORAY|SIGKILL"
   ```
2. Archive the agent's scratchpad and memory dumps prior to clearing containment state.

### IR-04: Controlled Eviction & Manual Policy Release
If the agent has been remediated or quarantined under a temporary TTL policy:

1. **Purge Expired TTL Entries**:
   ```bash
   python3 /usr/local/bin/lobster-hook --evict-expired --json
   ```

2. **Manual Release of Remediated Process**:
   ```bash
   python3 /usr/local/bin/lobster-hook --pid 4096 --release
   ```
   Confirm PID returns `BENIGN`:
   ```bash
   python3 /usr/local/bin/lobster-hook --pid 4096 --check
   ```

### IR-05: Granular Network Egress Enforcement & Socket Isolation
When containing an agent that must remain capable of communicating with a local supervisor via IPC (`AF_UNIX`) or local model runtime (`127.0.0.1` / `::1`) but must be strictly severed from external WAN traffic:

1. **Assert Granular WAN Egress Block (Permitting Loopback/IPC)**:
   ```bash
   python3 bridge/lobster_hook.py --pid 4096 --block-wan
   ```

2. **Assert Total Network Block (Severing All Sockets Including Loopback)**:
   ```bash
   python3 bridge/lobster_hook.py --pid 4096 --deny-all-net
   ```

3. **Verify Active Network Isolation Policy**:
   ```bash
   python3 bridge/lobster_hook.py --pid 4096 --status --json
   ```
   **Output Inspection**:
   ```json
   {
     "pid": 4096,
     "state": "ACTIVE",
     "quarantined": true,
     "action_flags": 18,
     "allow_loopback": true,
     "reason": 1,
     "strike_count": 0,
     "ttl_seconds": 0,
     "remaining_seconds": 0
   }
   ```
   - `action_flags: 18` corresponds to `0x02` (`BLOCK_SOCKET`) | `0x10` (`ALLOW_LOOPBACK`).
   - `allow_loopback: true` confirms the kernel BPF-LSM hook exempts `AF_UNIX` and `127.0.0.0/8` / `::1`.

### IR-06: Wire-Level XDP Frame Dropping & Network Interface Isolation
When containing an agent attempting network exfiltration, raw socket bypasses, or C2 callback traffic to malicious IPv4 addresses:

1. **Assert Line-Rate Wire Drop for Target IPv4 Destination/Source**:
   ```bash
   python3 bridge/lobster_hook.py --xdp-drop-ip 198.51.100.42
   ```

2. **Verify Programmed XDP Drop Rules**:
   ```bash
   python3 bridge/lobster_hook.py --xdp-list --json
   ```
   **Output Inspection**:
   ```json
   {
     "dropped_ips": [
       "198.51.100.42"
     ],
     "count": 1
   }
   ```

3. **Check Specific IP Drop State**:
   ```bash
   python3 bridge/lobster_hook.py --xdp-check-ip 198.51.100.42 --json
   # Exit code 1 indicates DROPPED; exit code 0 indicates BENIGN.
   ```

4. **Release Wire Drop Rule**:
   ```bash
   python3 bridge/lobster_hook.py --xdp-remove-ip 198.51.100.42
   ```

5. **Emergency Purge of All Wire Drops**:
   ```bash
   python3 bridge/lobster_hook.py --xdp-flush --force
   ```

### IR-07: Cgroup v2 Containment Scoping & Subtree Sandboxing
When containing a multi-threaded agent worker pool, runner hierarchy, or short-lived forked processes before child PIDs can be registered individually:

1. **Assert Quarantine on Cgroup v2 Hierarchy**:
   ```bash
   python3 bridge/lobster_hook.py --quarantine-cgroup /sys/fs/cgroup/agent-sandbox --block-wan --json
   # Or by 64-bit cgroup inode:
   python3 bridge/lobster_hook.py --quarantine-cgroup 1048576 --block-exec --json
   ```

2. **Query Cgroup Containment Status**:
   ```bash
   python3 bridge/lobster_hook.py --cgroup-status /sys/fs/cgroup/agent-sandbox --json
   ```
   **Output Inspection**:
   ```json
   {
     "cgroup_id": 1048576,
     "state": "ACTIVE",
     "state_code": 1,
     "quarantined": true,
     "action_flags": 18,
     "allow_loopback": true,
     "strike_count": 1,
     "ttl_seconds": 0,
     "remaining_seconds": 0,
     "reason": 1,
     "timestamp_ns": 1730736000000000000
   }
   ```

3. **List All Quarantined Cgroups**:
   ```bash
   python3 bridge/lobster_hook.py --list-cgroups --json
   ```

4. **Release Cgroup Hierarchy**:
   ```bash
   python3 bridge/lobster_hook.py --release-cgroup /sys/fs/cgroup/agent-sandbox --json
   ```

5. **Emergency Purge of All Quarantined Cgroups**:
   ```bash
   python3 bridge/lobster_hook.py --flush-cgroups --force
   ```

---

## 5. Disaster Recovery & Break-Glass Procedures

> [!CAUTION]
> Break-glass procedures bypass or flush kernel containment controls. Execute only under authorized incident commander oversight.

### DR-01: Emergency Break-Glass Flush (`--flush-all`)
If false-positive containment impacts critical infrastructure or multiple benign agent workers:

```bash
python3 /usr/local/bin/lobster-hook --flush-all --force --json
# Output:
# {"status": "flushed", "count": 14}
```
*Note:* The `--force` flag is mandatory. Running `--flush-all` without `--force` immediately fails closed with exit code `252`.

### DR-02: Corrupted Map State Recovery
If `/sys/fs/bpf/moray/quarantine_map`, `/sys/fs/bpf/moray/xdp_drop_map`, or `/sys/fs/bpf/moray/cgroup_map` becomes corrupted due to abnormal hypervisor termination or filesystem failure:

1. **Stop the Daemon**:
   ```bash
   systemctl stop morayd.service
   ```

2. **Remove Pinned Maps**:
   ```bash
   rm -f /sys/fs/bpf/moray/quarantine_map
   rm -f /sys/fs/bpf/moray/events
   rm -f /sys/fs/bpf/moray/xdp_drop_map
   rm -f /sys/fs/bpf/moray/cgroup_map
   ```

3. **Restart the Daemon**:
   ```bash
   systemctl start morayd.service
   ```
   `morayd` will re-initialize fresh BPF maps atomically and pin them to `/sys/fs/bpf/moray`.

### DR-03: Nuclear Unpinning & Full BPF Program Detach
If the daemon is unresponsive and kernel LSM hooks must be detached immediately without a host reboot:

1. **Kill the Loader Daemon**:
   ```bash
   pkill -9 morayd
   ```

2. **Unpin All BPF Objects**:
   ```bash
   rm -rf /sys/fs/bpf/moray
   ```

3. **Detach and Unload Residual BPF Programs via `bpftool`**:
   ```bash
   # List loaded Moray programs
   bpftool prog show name moray_bprm_strike
   
   # If necessary, detach link
   bpftool link detach id <LINK_ID>
   ```

4. **Verify Host Stability**:
   ```bash
   dmesg | tail -n 20
   ```

### IR-08: Autonomous Boundary Tuning & Emergency Overrides
If `morayd` is running in autonomous zero-configuration mode (`--auto-harden`) and a legitimate toolchain binary (e.g. `gdb`, `perf`, `strace`, or a freshly deployed worker script) is unexpectedly blocked with `Operation not permitted (-EPERM)`:

1. **Verify Root Cause in In-Kernel Telemetry**:
   Check `/sys/fs/bpf/moray/events` ringbuf for `BPRM_CHECK_SECURITY` violations:
   ```bash
   python3 bridge/moray_hook.py --poll --count 5
   ```
   If `action_taken` is `1` (`MORAY_ACT_BLOCK_EXEC`) and the process is not in the manual `quarantine_map`, the failure is triggered by the autonomous boundary engine rejecting an unlisted `comm`.

2. **Resolution A: Permanent Workspace Manifest Update**:
   Re-profile the target workspace using `moray_profiler.py` or manually append the executable name to `moray_boundary.json`:
   ```bash
   # Automatically re-profile workspace
   python3 bridge/moray_profiler.py . --output moray_boundary.json
   
   # Restart daemon to reload boundary map
   systemctl restart morayd.service
   ```

3. **Resolution B: Live Hot-Patching (Zero-Downtime Injection)**:
   Inject the new executable `comm` (e.g. `perf`) directly into the pinned in-kernel boundary map without restarting `morayd`:
   ```bash
   # Add key to pinned boundary_map with MORAY_PERM_ALL (0x07)
   # Key: 16 bytes (hex), Value: 16 bytes struct moray_boundary_entry
   bpftool map update pinned /sys/fs/bpf/moray/boundary_map \
       key hex 70 65 72 66 00 00 00 00 00 00 00 00 00 00 00 00 \
       value hex 07 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   ```

4. **Resolution C: Break-Glass Autonomous Override (Instant Disarm)**:
   If autonomous enforcement must be deactivated immediately without killing `morayd` or flushing active manual quarantines, delete the sentinel key `"__moray_auto__"` from the pinned boundary map:
   ```bash
   # Delete sentinel key '__moray_auto__' (16 bytes hex: 5f 5f 6d 6f 72 61 79 5f 61 75 74 6f 5f 5f 00 00)
   bpftool map delete pinned /sys/fs/bpf/moray/boundary_map \
       key hex 5f 5f 6d 6f 72 61 79 5f 61 75 74 6f 5f 5f 00 00
   ```
   *Result:* Invariant $I_9$ sentinel is removed. Ring 0 LSM instantly falls back to standard manual quarantine mode ($I_1$), restoring benign unimpeded execution ($I_2$) across all non-flagged binaries in $O(1)$ time.

---

## 6. Post-Incident Forensic Data Collection

Following any containment event or break-glass incident, assemble the forensic artifact package:

```bash
FORENSIC_DIR="/var/log/moray/incident-$(date +%s)"
mkdir -p "$FORENSIC_DIR"

# 1. Capture current quarantine state
python3 /usr/local/bin/lobster-hook --list --json > "$FORENSIC_DIR/quarantine_table.json"

# 2. Capture kernel dmesg log buffer
dmesg -T > "$FORENSIC_DIR/dmesg.log"

# 3. Capture active BPF map and program metadata
bpftool prog list > "$FORENSIC_DIR/bpf_progs.txt" 2>/dev/null || true
bpftool map list > "$FORENSIC_DIR/bpf_maps.txt" 2>/dev/null || true

# 4. Capture service journal
journalctl -u morayd.service --no-pager > "$FORENSIC_DIR/morayd_journal.log"

tar -czf "$FORENSIC_DIR.tar.gz" -C "/var/log/moray" "$(basename "$FORENSIC_DIR")"
echo "[+] Forensic bundle generated: $FORENSIC_DIR.tar.gz"
```

---

## 7. Operational Readiness Checklist (Go/No-Go Gate)

All production environments running Project Moray must pass this gate before untrusted agent execution:

- [ ] Kernel boot parameter includes `lsm=...,bpf`.
- [ ] `/sys/kernel/security/lsm` contains `bpf`.
- [ ] `/sys/fs/bpf` is mounted with magic `0xcafe4a11`.
- [ ] `morayd --preflight` exits cleanly with `0`.
- [ ] `systemctl is-active morayd.service` returns `active`.
- [ ] `lobster-hook --healthcheck` returns `healthy`.
- [ ] All 141 test cases in `make verify` pass cleanly under local CI.
- [ ] All 46 live Ring 0 verification steps pass cleanly under KVM microVM (`tests/run_live_kernel_test.sh`).
- [ ] Break-glass procedures (`--flush-all --force`) tested in staging environment.
