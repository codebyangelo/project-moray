# Project Moray: Operational Confidence, Health/Readiness Probes & Crash Recovery Verification

## 1. Executive Summary

Milestone 5 of the [canonical development roadmap](file:///root/home/projects/project-moray/anotherroadmap.md) mandates:
> *"After scope and semantics are stable, tighten recovery behavior, health/readiness reporting, and supported-kernel documentation. Add another kernel configuration or deployment environment only if you intend to support it. Why: This raises confidence in the defined product without turning a focused PoC into an open-ended compatibility project."*

Prior to Milestone 5, operators and orchestration layers (e.g. systemd, Kubernetes, container runtimes) lacked an active health and readiness probe in the native `morayd` binary. In addition, an abrupt daemon termination (`SIGKILL` or kernel OOM) could leave orphaned BPF map pins in `/sys/fs/bpf/moray`, requiring manual intervention or risking `-EEXIST` during daemon relaunch.

Milestone 5 establishes production operational confidence across four pillars:
1. **Native Health & Readiness Probe Engine ([`src/morayd.c`](file:///root/home/projects/project-moray/src/morayd.c)):**
   - Added CLI commands `--health` and `--readiness`.
   - Direct kernel interrogation: verifies active `bpf` in `/sys/kernel/security/lsm`, `bpffs` mount status, and probes each of the 6 core kernel maps (`quarantine_map`, `events`, `xdp_drop_map`, `cgroup_map`, `boundary_map`, `workload_map`) via `bpf_obj_get()`.
   - Structured JSON mode (`--json`) enabling 0ms local orchestration evaluation.
   - Fail-closed evaluation: returns exit code 0 (`HEALTHY` / Ready) or 1 (`DEGRADED` / `UNHEALTHY`).
2. **Automated Stale Pin Detection & Crash Recovery ([`src/morayd.c`](file:///root/home/projects/project-moray/src/morayd.c)):**
   - Ingests existing pins gracefully upon restart, unlinks stale pinned maps, re-pins fresh kernel descriptors, and resumes workload boundary enforcement without operator intervention.
   - Added emergency break-glass CLI: `morayd --clean-pins [--pin-dir <dir>]` unlinks all pinned maps safely without requiring external Python or ctypes dependencies.
3. **Cross-Language Sovereign Bridge Hardening ([`bridge/lobster_hook.py`](file:///root/home/projects/project-moray/bridge/lobster_hook.py)):**
   - Expanded `healthcheck()` to audit all 6 kernel maps, tracking governed workloads and active boundary counts.
   - Added `--readiness` CLI command with fail-closed return codes.
4. **Production Service Unit Hardening ([`packaging/systemd/morayd.service`](file:///root/home/projects/project-moray/packaging/systemd/morayd.service)):**
   - Integrated `ExecStartPost=/usr/local/bin/morayd --readiness --pin-dir /sys/fs/bpf/moray` to guarantee systemd reports `active (running)` only when all 6 kernel maps are verified online.
5. **Live Hardware-Level QEMU/KVM MicroVM Verification (Domain 13: Steps 101–110):**
   - Expanded live microVM test suite from 100 to 110 steps, validating daemon health, JSON telemetry, crash recovery under an active governed cgroup, unlisted binary severance persistence, and clean unpinning.

---

## 2. Subsystem Health & Readiness Contract

```
┌────────────────────────────────────────────────────────┐
│              morayd --health / --readiness             │
└───────────────────────────┬────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
┌──────────────────────────────┐    ┌──────────────────────────────┐
│  Host Kernel Environment     │    │  BPF Filesystem & Map Pins   │
│  - /sys/kernel/security/lsm  │    │  - statfs(/sys/fs/bpf)       │
│  - bpf active in module list │    │  - bpf_obj_get() on 6 pins:  │
└──────────────┬───────────────┘    │    * quarantine_map          │
               │                    │    * events ringbuf          │
               │                    │    * xdp_drop_map            │
               │                    │    * cgroup_map              │
               │                    │    * boundary_map            │
               │                    │    * workload_map            │
               │                    └──────────────┬───────────────┘
               │                                   │
               └─────────────────┬─────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────┐
│ Evaluation & Exit Status:                                      │
│ - HEALTHY (Exit 0): All 6 maps online + LSM active + bpffs     │
│ - DEGRADED (Exit 1): Partial maps online                       │
│ - UNHEALTHY (Exit 1): Core maps offline or LSM inactive        │
└────────────────────────────────────────────────────────────────┘
```

### 2.1 Health Probe Telemetry Schema (`morayd --health --json`)

```json
{
  "status": "HEALTHY",
  "ready": true,
  "mock_mode": false,
  "pin_dir": "/sys/fs/bpf/moray",
  "bpf_lsm_active": true,
  "bpffs_mounted": true,
  "maps": {
    "quarantine_map": true,
    "events": true,
    "xdp_drop_map": true,
    "cgroup_map": true,
    "boundary_map": true,
    "workload_map": true
  },
  "maps_accessible": 6,
  "warnings": []
}
```

---

## 3. Crash Recovery & Stale Pin Resilience

When the `morayd` loader daemon encounters an abnormal hypervisor shutdown, crash, or `SIGKILL`, the kernel detaches the unpinned `bpf_link` instances upon file descriptor closure, while the pinned BPF maps remain anchored in `/sys/fs/bpf/moray/`.

In Milestone 5:
1. **Automatic Stale Pin Detection:** During startup, `morayd` checks each target pin path (`access(pin, F_OK)`). If present, it logs:
   `[*] Stale pin detected for '/sys/fs/bpf/moray/quarantine_map'; unlinking and recovering fresh pin...`
   and cleanly unlinks the stale pin before calling `bpf_map__pin()`.
2. **Zero Inode Collision:** Eliminates `-EEXIST` errors on daemon restart.
3. **Continuous Enforcement Post-Restart:** Once the daemon relaunches with `--auto-harden`, Ring 0 BPF-LSM programs immediately bind to the governed cgroup, and unlisted binary executions inside the governed workload continue to be severed with `-EPERM` (exit code 42).
4. **Emergency Break-Glass Tooling (`morayd --clean-pins`):** Operators can unlink all 6 maps in a single command without needing python or ctypes installed.

---

## 4. Hermetic Test Coverage

The new hermetic test suite ([`tests/test_operational_health_recovery.py`](file:///root/home/projects/project-moray/tests/test_operational_health_recovery.py)) adds 10 comprehensive tests (bringing total passing hermetic tests to 183):
- `test_morayd_health_mock_success`: Verifies `morayd --health` exit code 0 and human-readable output in mock mode.
- `test_morayd_health_mock_json_schema`: Validates strict JSON schema keys, types, and values (`status`, `ready`, `maps_accessible: 6`).
- `test_morayd_readiness_mock_success`: Verifies `morayd --readiness` exit code 0.
- `test_morayd_health_degraded_when_map_missing`: Simulates missing map file; asserts exit code 1, `DEGRADED` status, and warning.
- `test_morayd_clean_pins_removes_files`: Verifies `morayd --clean-pins` unlinks all 6 mock map files and reports exact count.
- `test_lobster_hook_healthcheck_mock_data`: Verifies Python bridge `healthcheck()` returns comprehensive dictionary including `boundary_count` and `workload_count`.
- `test_lobster_hook_healthcheck_cli_json`: Verifies `lobster_hook.py --healthcheck --json` CLI output.
- `test_lobster_hook_readiness_cli`: Verifies `lobster_hook.py --readiness` exits 0.
- `test_lobster_hook_non_bpf_path_fails_closed`: Verifies fail-closed contract when initialized against non-BPF paths.
- `test_systemd_service_file_directives`: Validates all required hardening directives (`ProtectSystem=strict`, `ExecStartPost`, `LimitMEMLOCK=infinity`, `CapabilityBoundingSet`).

---

## 5. Live MicroVM Kernel Verification Suite (Domain 13: Steps 101–110)

Implemented in [`tests/run_live_kernel_test.sh`](file:///root/home/projects/project-moray/tests/run_live_kernel_test.sh), Domain 13 proves operational confidence and crash recovery in hardware-isolated QEMU/KVM microVM:

| Step | Test Action | Expected Result | Return Code | Verification Invariant |
| :---: | :--- | :--- | :---: | :--- |
| **101** | Live daemon health probe (`morayd --health`) | Human-readable report: `HEALTHY (Ready: YES)`, 6/6 maps online | `0` | Live Health Probe |
| **102** | Live daemon JSON health probe (`morayd --health --json`) | Valid JSON output; all 6 maps validated | `0` | Operational Schema |
| **103** | Python bridge readiness probe (`lobster_hook.py --readiness`) | Confirms live kernel maps and LSM status | `0` | Cross-Language Parity |
| **104** | Emergency map cleanup CLI test (`morayd --clean-pins`) | Unlinks target pins without leaking file descriptors | `0` | Emergency Clean Pins |
| **105** | Healthcheck failure detection on unpinned/missing directory | Exits non-zero fail-closed when pins are missing | `1` | Fail-Closed Liveness |
| **106** | Daemon crash & stale pin recovery drill under governed cgroup | Daemon recovered cleanly; re-pinned all 6 maps | `0` | Stale Pin Recovery |
| **107** | Ring 0 boundary enforcement persistence post-recovery | Unlisted execution inside governed cgroup severed with `-EPERM` | `42` | Enforcement Persistence ($I_8$) |
| **108** | Kernel preflight capability reporting check (`morayd --preflight`) | Reports root privilege, BTF, and active BPF-LSM | `0` | Preflight Capability |
| **109** | Production systemd unit structure & directive verification | Validates `ExecStartPost` and capability bounding | `0` | Production Service Unit |
| **110** | Clean teardown, unpin verification, and zero kernel leak check | Sentinel detached; cgroup unlinked cleanly | `0` | Complete Lifecycle Teardown |

---

## 6. Zero-Nomenclature Inflation & Boundary Truth

In accordance with Rule 5 and the Zero Nomenclature Inflation Invariant, the guarantees of Milestone 5 are strictly bounded:
1. **Health Probe Scope:** `--health` probes the presence and accessibility of pinned maps and LSM hooks. It verifies that the containment infrastructure is armed in the kernel; it does not claim to detect task internal corruption or arbitrary userland hangs.
2. **Crash Recovery Scope:** When `morayd` is killed with `SIGKILL`, the kernel LSM hooks unbind upon link file descriptor closure. Relaunching `morayd --auto-harden` re-arms the hooks and re-populates the whitelist. Child tasks spawned during the daemon absence remain governed once the daemon re-attaches to the cgroup v2 hierarchy.
3. **Readiness Probe Guarantees:** `--readiness` fails closed with exit code 1 if even a single map is inaccessible or if BPF-LSM is not detected in the kernel securityfs.

---

## 7. Invariant Conformance

- **$I_1$ Ring 0 Kernel Enforcement:** Health probes directly verify that `bpf` is active in `/sys/kernel/security/lsm` and that all 6 BPF maps are accessible.
- **$I_2$ Zero Overhead & Non-Interference:** Probes execute purely out-of-band on demand without adding overhead to kernel fast-paths.
- **$I_8$ Autonomous Boundary Governance:** Post-restart recovery ensures that autonomous boundary governance can be restored immediately without hypervisor reboot.
- **$I_9$ Cgroup v2 Workload Jurisdiction:** Active workloads maintain their cgroup identity across daemon restarts, ensuring consistent policy application upon daemon recovery.
