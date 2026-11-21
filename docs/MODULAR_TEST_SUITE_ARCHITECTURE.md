# Project Moray: Modular Test Suite Architecture & Navigation Guide

## 1. Executive Summary

As Project Moray expanded across Milestones 1 through 6, the test suite scaled from basic unit tests into a dual-engine verification framework:
1. **Ring 0 KVM MicroVM Test Suite:** 120 steps across 15 domains asserting real in-kernel BPF-LSM behavior.
2. **Hermetic Test Suite:** 185 tests across 14 modules verifying static layouts, mock maps, schema validation, and CLI commands.

Previously, the live kernel verification suite was housed in a single monolithic script (`tests/run_live_kernel_test.sh`, 2,247 lines). This refactor modularizes the test suite into dedicated, isolated domain modules under `tests/live/` while maintaining 100% backward compatibility with existing CI pipelines, `virtme-ng` harnesses, and automation scripts.

---

## 2. Live Kernel MicroVM Suite Layout (`tests/live/`)

The monolithic `run_live_kernel_test.sh` has been partitioned into 16 focused, self-contained shell modules:

```text
tests/
├── live/
│   ├── common.sh                       # Shared fixtures, preflights, cleanup & daemon lifecycles
│   ├── domain_00_baseline.sh           # Steps 5–15:   Core LSM & baseline executions
│   ├── domain_01_cgroup_races.sh       # Steps 16–20:  Cgroup v2 subtree fork races
│   ├── domain_02_dynamic_escalation.sh # Steps 21–25:  Dynamic escalation to SIGKILL
│   ├── domain_03_smp_concurrency.sh    # Steps 26–30:  Multi-threaded SMP concurrency
│   ├── domain_04_xdp_packet_drops.sh   # Steps 31–35:  Wire-level XDP packet drops
│   ├── domain_05_ringbuf_telemetry.sh  # Steps 36–40:  Ringbuf saturation & drain
│   ├── domain_06_sre_recovery.sh       # Steps 41–46:  Live SRE disaster recovery DR-01..DR-03
│   ├── domain_07_allow_loopback.sh     # Steps 47–54:  Autonomous ALLOW_LOOPBACK
│   ├── domain_08_deny_all_net.sh       # Steps 55–62:  Autonomous DENY_ALL_NET
│   ├── domain_09_require_wan.sh        # Steps 63–70:  Autonomous REQUIRE_WAN
│   ├── domain_10_workload_boundary.sh  # Steps 71–80:  Workload-scoped boundary & non-interference
│   ├── domain_11_socket_gates.sh       # Steps 81–90:  Extended network defense (socket_create/bind)
│   ├── domain_12_manifest_schema.sh    # Steps 91–100: Manifest schema validation & fail-closed ingestion
│   ├── domain_13_operational_health.sh # Steps 101–110: Health probes, readiness, & stale pin recovery
│   └── domain_14_agent_isolation.sh    # Steps 111–120: Multi-tenant compound boundary & agent isolation
└── run_live_kernel_test.sh             # Master orchestrator (~170 lines, sources common + domains)
```

### Key Properties:
* **Dual-Mode Execution:** Each domain script is independently executable on its own (`./tests/live/domain_14_agent_isolation.sh`), or orchestratable via the master runner (`./tests/run_live_kernel_test.sh 14`).
* **Clean Reading Surface:** Individual domain scripts range between 40 and 220 lines, making auditing and reviewing specific failure steps fast and focused.
* **Deterministic Environment:** `tests/live/common.sh` establishes strict error handling (`set -euo pipefail`), root paths, compiled victim worker binaries, unlisted binary staging, daemon launch/kill helpers, and preflight sanity checks.

---

## 3. Hermetic Python Test Suite Taxonomy (`tests/test_*.py`)

The hermetic suite comprises 185 tests organized into 4 functional pillars:

| Subsystem / Pillar | Test Modules | Primary Invariants Asserted |
| :--- | :--- | :--- |
| **Boundary & Workload Maps** | `test_autonomous_boundary_e2e.py`<br>`test_workload_boundary.py`<br>`test_manifest_schema.py` | Compound key `(cgroup_id, comm)`, 4-level ancestor traversal, manifest validation, unreviewed suggestion gating |
| **Network & Wire Defense** | `test_network_policy.py`<br>`test_xdp_filter.py` | 4-stage network gate (`socket_create`, `socket_bind`, `socket_connect`), wire-rate XDP frame dropping |
| **Cgroup & Containment** | `test_cgroup_containment.py`<br>`test_lobster_hook.py`<br>`test_policy_engine.py` | Cgroup subtree quarantine, dynamic strike escalation to SIGKILL, Python bridge ctypes bindings |
| **Ops & Telemetry** | `test_operational_health_recovery.py`<br>`test_telemetry_streamer.py`<br>`test_anti_tamper.py`<br>`test_runbook_ops.py`<br>`test_daemon_smoke.py`<br>`test_adversarial.py` | Health/readiness probes, stale pin crash recovery, ringbuf telemetry serialization, anti-tamper |

---

## 4. Verification Workflow

```bash
# 1. Run entire hermetic test suite (compilation, struct layouts, pytest, ruff):
make verify

# 2. Run isolated live kernel microVM domain:
./tests/run_live_kernel_test.sh 14
# Or directly:
./tests/live/domain_14_agent_isolation.sh

# 3. Run complete 120-step regression suite inside QEMU/KVM:
./tests/run_live_kernel_test.sh all
```
