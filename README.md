# Project Moray: OS-Level Ring 0 eBPF Containment Architecture

[![CI: Build & Invariant Suite](https://github.com/codebyangelo/project-moray/actions/workflows/ci.yml/badge.svg)](https://github.com/codebyangelo/project-moray/actions/workflows/ci.yml)
[![MicroVM: 46/46 KVM Steps](https://img.shields.io/badge/MicroVM-46%2F46%20KVM%20Steps-brightgreen.svg)](#-verification--claims-truth-matrix)
[![Tests: 141 Passed](https://img.shields.io/badge/Tests-141%20Passed-brightgreen.svg)](#-building--running)
[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](LICENSE)
[![Kernel: eBPF LSM | XDP](https://img.shields.io/badge/Kernel-eBPF%20LSM%20%7C%20XDP-green.svg)](#-quick-architecture-overview)
[![Python: >=3.10](https://img.shields.io/badge/Python-%3E%3D3.10-blue.svg)](#-subsystems)
[![Ecosystem: Lobster (L7) | Moray (Ring 0) | Octopus (Auditor)](https://img.shields.io/badge/Ecosystem-Lobster%20%7C%20Moray%20%7C%20Octopus-orange.svg)](#-triad-ecosystem-integration)
[![Contract: Fail-Closed](https://img.shields.io/badge/Contract-Fail--Closed-red.svg)](docs/INVARIANTS.md)

Project Moray (`morayd`) is an ultra-lightweight, zero-dependency in-kernel containment daemon and eBPF security subsystem. Operating in Ring 0 via BPF-LSM and driver-level XDP, Moray sits beneath user-space agent frameworks to terminate compromised processes, sever unauthorized network sockets, and drop malicious frames at the driver boundary before user-space context switches complete.

---

## ⚡ Quick Architecture Overview

```mermaid
graph TD
    subgraph Layer 7: User Space & Workspace
        L[Project Lobster: L7 Proxy] -->|Detect Anomaly / Invariant Violation| B[lobster_hook.py]
        O[Project Octopus: Auditor] -.->|Cross-Repo Compliance Audit| S[SARIF 2.1.0 Reports]
        P[moray_profiler.py] -->|Inspect Workspace AST & Toolchains| J[moray_boundary.json]
        J -->|--auto-harden| D[morayd Loader Daemon]
    end

    subgraph Kernel Boundary: VFS Pinned Maps
        B -->|Pin Target PID| M["/sys/fs/bpf/moray/quarantine_map"]
        B -->|Pin Cgroup v2 Slice| C["/sys/fs/bpf/moray/cgroup_map"]
        B -->|Pin Wire IP| X["/sys/fs/bpf/moray/xdp_drop_map"]
        D -->|Seed Sentinel & Executable Whitelist| W["/sys/fs/bpf/moray/boundary_map"]
        K["/sys/fs/bpf/moray/events"] -->|NDJSON Ringbuf Telemetry| H[moray_hook.py / Consumer]
    end

    subgraph Layer 0: Linux Ring 0
        M -->|Lookup PID/TGID| LSM[BPF-LSM Hooks]
        C -->|Lookup Cgroup ID| LSM
        W -->|Lookup Binary Comm| LSM
        LSM -->|bprm_check_security| S1["Block execve -> -EPERM<br/>(Escalate >= 5 hits -> SIGKILL)"]
        LSM -->|socket_connect| S2["Sever WAN Socket -> -EPERM<br/>(Loopback / IPC Exempted)"]
        LSM -->|lsm/bpf: Anti-Tamper| S3[Block sys_bpf -> -EPERM]
        X -->|O(1) Route Lookup| XDP[XDP Driver Hook]
        XDP -->|Match Wire Drops| S4[XDP_DROP Packet]
        LSM -->|bpf_ringbuf_output| K
    end
```

Detailed architectural blueprints and biological mapping are documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).  
Formal security contracts and invariants are documented in [`docs/INVARIANTS.md`](docs/INVARIANTS.md).  
Operational procedures and disaster recovery playbooks are documented in [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

---

## 🛡️ Verification & Claims Truth Matrix

In adherence to the **Provenance & Chronology Invariant ($I_6$)** and strict human verification guardrails, this matrix delineates between what is empirically proven in real Ring 0 execution vs. what is partially emulated, planned, or explicitly out of scope:

| Category | Capability / Subsystem | Current State | Empirical Proof & Locus |
| :--- | :--- | :--- | :--- |
| **Tier 1: Empirically Tested & Live-Kernel Verified** | **Syscall Severance (`execve`)** | **Verified (Ring 0)** | Intercepted with `-EPERM` in live KVM microVM (`tests/run_live_kernel_test.sh` Step 6). |
| | **Anti-Tamper Camouflage (`sys_bpf`)** | **Verified (Ring 0)** | Intercepted with `-EPERM` via `lsm/bpf` (`run_live_kernel_test.sh` Step 7). |
| | **Dynamic Escalation (`SIGKILL`)** | **Verified (Ring 0)** | Auto-escalates from Tier 1 (`-EPERM`) to Tier 3 (`SIGKILL`, exit 137) at hit 5 via `bpf_send_signal(9)` (Steps 8, 21–25). |
| | **Live Telemetry Extraction** | **Verified (Ring 0)** | 128-byte `struct moray_event` records emitted to ringbuf and drained by userspace bridge (Step 9). |
| | **Granular Egress Control** | **Verified (Ring 0)** | External WAN connect blocked with `-EPERM`; loopback/IPC connection allowed under `--block-wan` (Steps 10–11). |
| | **Total Network Severance** | **Verified (Ring 0)** | Both WAN and loopback blocked with `-EPERM` under `--deny-all-net` (Step 12). |
| | **Wire-Level Frame Drops** | **Verified (Ring 0)** | Line-rate driver drops via `XDP_DROP` across veth pair (`moray_xdp_drop_map`, Steps 13, 31–35). |
| | **Cgroup v2 Subtree Containment** | **Verified (Ring 0)** | 100% containment of 20 concurrent ephemeral child forks within quarantined cgroup slice (Steps 16–19). |
| | **SMP Concurrency & Map Atomicity** | **Verified (Ring 0)** | 10 concurrent threads inserting, querying, and atomically incrementing 50 entries with clean baseline return (Steps 26–30). |
| | **High-Throughput Ringbuf Burst** | **Verified (Ring 0)** | 50 concurrent operations fired in <100ms with zero corruption, zero kernel panic (Steps 36–40). |
| | **Disaster Recovery (DR-01 to DR-03)** | **Verified (Ring 0)** | Break-glass flush, TTL eviction, and daemon crash recovery under `SIGKILL` with map re-attachment (Steps 41–46). |
| | **Binary Struct & Layout Alignment** | **Verified (Hermetic)** | Strict C `sizeof()` and offset assertions matching Python `ctypes` across architectures (`tests/test_struct_layout.c`). |
| | **Sovereign Boundary Profiler** | **Verified (Hermetic)** | Zero-dependency AST/toolchain analysis producing valid `moray_boundary.json` (`tests/test_autonomous_boundary_e2e.py`). |
| | **Daemon Auto-Harden Startup** | **Verified (Hermetic)** | Ingests manifest, seeds `moray_boundary_map`, enforces strict opt-in discipline (`tests/test_autonomous_boundary_e2e.py`). |
| **Tier 2: Partially Tested / Mock-Emulated** | **Cross-Repo Octopus Audit** | **Conditional CI** | Verified when Project Octopus sibling workspace is present; safely skipped without error in standalone CI runners. |
| | **Autonomous Boundary in MicroVM** | **Mock-Verified** | 100% verified in mock and daemon startup tests; live microVM harness currently focuses on 46 manual strike steps. |
| **Tier 3: Claimed in Threat Model / Roadmap** | **VFS Path Unlink Protection** | **In Progress (Phase 8)**| Pinned maps protected by OS permissions (`0700` root) and `lsm/bpf`; dedicated VFS LSM hooks (`file_unlink`) scheduled for Phase 8. |
| | **IPv6 Wire-Rate Drops** | **Roadmap** | `moray_xdp_drop_map` currently keys on `__u32` IPv4 addresses; IPv6 128-bit keying scheduled for future release. |
| | **Deep Packet Inspection (DPI)** | **Deferred to L7** | Moray operates at L0/L3/L4; semantic payload analysis and regex inspection are delegated to Project Lobster. |
| **Tier 4: Explicitly NOT Claimed (Out of Scope)** | **User-Space AI Decision Logic** | **Out of Scope** | Moray contains zero LLM weights, heuristics, or prompt-processing logic; it is a deterministic, fail-closed enforcement layer. |
| | **Container Runtime Replacement** | **Out of Scope** | Moray does not replace Docker, containerd, or runc; it overlays an in-kernel LSM containment boundary on existing runtimes. |
| | **Ring 3 Memory Corruption Fixes** | **Out of Scope** | Moray does not patch memory leaks or buffer overflows inside victim binaries; it halts their lateral movement once compromised. |

---

## 📂 Subsystems

* **`src/moray.h`**: Shared binary headers, quarantine bitmasks, boundary struct layouts, and ring buffer event schemas.
* **`src/moray_kern.bpf.c`**: Ring 0 eBPF C program implementing LSM strike mechanisms (`bprm_check_security`, `socket_connect`), autonomous boundary defense (`moray_boundary_map`), and anti-tamper camouflage (`lsm/bpf`).
* **`src/morayd.c`**: Zero-dependency C daemon mounting `/sys/fs/bpf/moray/`, seeding boundary policies, and draining ring buffer telemetry.
* **`bridge/lobster_hook.py`**: Zero-dependency Python ctypes bridge allowing Project Lobster to flag PIDs into pinned quarantine maps.
* **`bridge/moray_profiler.py`**: Sovereign, zero-dependency workspace profiler and boundary policy synthesizer.
* **`bridge/moray_hook.py`**: Native sovereign Python bridge and NDJSON telemetry consumer.
* **`moray_boundary.json`**: Machine-readable boundary specification for autonomous zero-config hardening.
* **`tests/`**: Comprehensive test suite comprising:
  - 141 hermetic unit tests verifying layout, policy engine, XDP filter, cgroups, network policy, and E2E pipeline.
  - 46 live Ring 0 kernel verification steps running inside a real KVM microVM (`run_live_kernel_test.sh`).

---

## 🚀 Building & Running

### Requirements
* Linux Kernel 5.15+ (BPF-LSM enabled via `CONFIG_BPF_LSM=y` and `lsm=...,bpf` boot parameter)
* `clang` / LLVM toolchain with BPF target support
* `gcc`, `make`, `libbpf-dev`
* Python 3.10+ (for bridge integration and test harness)

### Compilation
```bash
make
```

### Running the Loader Daemon

#### Option A: Manual Strike Mode (Supervised by Lobster / CLI)
```bash
# Mounts BPF filesystem and pins maps to /sys/fs/bpf/moray/
sudo ./bin/morayd
```

#### Option B: Autonomous Boundary Defense (Zero-Configuration Mode)
```bash
# Ingests moray_boundary.json and enforces in-kernel executable whitelist
sudo ./bin/morayd --auto-harden
```

### Profiling Workspaces (Native Profiler)
```bash
# Automatically profile workspace toolchains and emit compliant manifest
python3 bridge/moray_profiler.py . --output moray_boundary.json
```

### Quarantine Trigger (via Lobster Hook)
```bash
python3 bridge/lobster_hook.py --pid 1234 --strike
```

---

## ⚡ Triad Ecosystem Integration

1. **[Project Lobster](file:///root/home/projects/project-lobster)** (*The Shell*):
   Acts as the front-line user-space proxy intercepting inter-agent traffic, LLM prompts, and tool outputs. When a semantic breach or privilege escalation is detected, Lobster invokes `lobster_hook.py` to pin the target PID or Cgroup slice into `/sys/fs/bpf/moray/quarantine_map`.

2. **Project Moray** (*The Reef Predator*):
   Lurks silently in Ring 0. Operating at the deepest enforcement substrate, Moray terminates quarantined processes, severs unauthorized network sockets, and drops hostile wire frames before user-space context switches complete.

3. **[Project Octopus](file:///root/home/projects/project-octopus)** (*The Adversary & Auditor*):
   Red-team validation harness and SARIF 2.1.0 telemetry auditor that stresses both layers: validating L7 evasion resistance in Lobster and low-level escape resistance in Moray.
