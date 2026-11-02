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
+----------------------------------------|--------------------------|-----------+
                                         | (bpf syscall / ctypes)   |
=========================================v==========================v============
|                             LINUX KERNEL (RING 0)                             |
|                                                                               |
|  /sys/fs/bpf/moray/quarantine_map (BPF_MAP_TYPE_HASH, max 1024 entries)       |
|  /sys/fs/bpf/moray/events         (BPF_MAP_TYPE_RINGBUF, 64 KB ceiling)      |
|                                                                               |
|  [LSM Hook: bprm_check_security] ---------> Intercept execve (-EPERM/SIGKILL) |
|  [LSM Hook: socket_create] ---------------> Intercept egress socket (-EPERM) |
+-------------------------------------------------------------------------------+
```

### Component Inventory
1. **`bin/morayd`**: The userspace loader daemon. Executes kernel preflight checks, mounts `/sys/fs/bpf`, loads BPF-LSM programs, pins kernel maps to `/sys/fs/bpf/moray`, and handles signal termination.
2. **`build/moray_kern.bpf.o`**: Restricted C bytecode executing in Ring 0. Intercepts `execve` and `socket` syscalls from quarantined processes, tracks strike counts atomically, and dispatches ringbuf telemetry.
3. **`bridge/lobster_hook.py`**: Zero-dependency Python ctypes bridge. Provides fail-closed strike asserting, TTL auto-expiry checking, structured JSON telemetry querying, and healthcheck probes.
4. **`packaging/systemd/morayd.service`**: Production systemd service unit providing sandboxed, least-privilege daemon management.

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
To inspect live interception events directly from the kernel trace pipe:

```bash
# Stream Ring 0 printk logs
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
If `/sys/fs/bpf/moray/quarantine_map` becomes corrupted due to abnormal hypervisor termination or filesystem failure:

1. **Stop the Daemon**:
   ```bash
   systemctl stop morayd.service
   ```

2. **Remove Pinned Maps**:
   ```bash
   rm -f /sys/fs/bpf/moray/quarantine_map
   rm -f /sys/fs/bpf/moray/events
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
- [ ] All 55 test cases in `make verify` pass cleanly under local CI.
- [ ] Break-glass procedures (`--flush-all --force`) tested in staging environment.
