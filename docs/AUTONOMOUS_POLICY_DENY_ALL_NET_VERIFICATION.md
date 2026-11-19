# Project Moray: Autonomous Policy End-to-End Verification (`DENY_ALL_NET`)

> **Classification:** Systems Architecture & Kernel Verification Report  
> **Subsystems:** Linux Ring 0 BPF-LSM, `morayd` Auto-Harden Daemon, `boundary_map`, `lobster_hook.py`  
> **Security Contracts:** Invariant $I_8$ (Granular Network Isolation) & Invariant $I_9$ (Autonomous Boundary Enforcement)  
> **Status:** Empirically Verified in GitHub Actions CI (62/62 KVM Steps in MicroVM Harness, 141 Hermetic Tests Passed)

---

## 1. Executive Summary & Policy Architectural Distinction

Project Moray enforces autonomous, in-kernel execution and network boundaries via BPF-LSM (`moray_boundary_map`). In Phase 7 Stage 5, the `ALLOW_LOOPBACK` network posture was verified end-to-end (Domain 7, Steps 47–54), permitting local IPC (`AF_UNIX`) and loopback (`127.0.0.1`, `::1`) while severing outbound WAN egress.

Phase 7 Stage 6 advances to the next autonomous boundary policy: **`DENY_ALL_NET`**.
Under `DENY_ALL_NET`, the containment boundary imposes **total network severance**:
- Permitted worker processes (`allowed_comms`) retain execution rights (`MORAY_PERM_EXEC`), but are denied all outbound network socket creation across all protocol families: external WAN, localhost loopback IPv4/IPv6, and local UNIX domain socket IPC.
- Any network socket `connect()` attempt by a worker process is immediately severed with `-EPERM` at the Ring 0 LSM boundary.
- The control plane daemon (`morayd`) retains `MORAY_PERM_ALL` (`0xFF`), ensuring management telemetry, ring buffer draining, and map synchronization operate unimpeded.

---

## 2. Engineering Remediation & Implementation

### A. First-Class Permission Flags (`src/moray.h`, `tests/test_struct_layout.c`)
- Codified `#define MORAY_PERM_LOOPBACK 0x04U` to explicitly distinguish loopback/IPC permissions from WAN socket permissions (`MORAY_PERM_SOCKET = 0x02U`).
- Verified static struct layout and flag alignment in `tests/test_struct_layout.c`.

### B. In-Kernel LSM Boundary Gating (`src/moray_kern.bpf.c`)
- In `moray_socket_strike`:
  - Management daemon check: processes with `(b_entry->perm_flags & MORAY_PERM_SOCKET)` (e.g. `morayd`) bypass with `hit_count` increment.
  - Posture evaluation: loopback IPv4, loopback IPv6, and `AF_UNIX` bypass logic is gated on `(sentinel->perm_flags & MORAY_PERM_LOOPBACK)`.
  - Under `DENY_ALL_NET`, the sentinel lacks `MORAY_PERM_LOOPBACK`, causing all worker socket attempts (loopback, UNIX IPC, and WAN) to fall through to `emit_strike_event` and return `-EPERM`.

### C. Daemon Manifest Parsing (`src/morayd.c`)
- In `seed_boundary_manifest()`:
  - Parses `"DENY_ALL_NET"` and `"REQUIRE_WAN"`.
  - Sets `sentinel_val.perm_flags = allow_wan ? MORAY_PERM_ALL : (deny_all ? MORAY_PERM_EXEC : (MORAY_PERM_EXEC | MORAY_PERM_LOOPBACK))`.
  - Seeds worker entries in `allowed_comms` with `allow_wan ? MORAY_PERM_ALL : MORAY_PERM_EXEC`.
  - Emits telemetry indicating active network posture (`REQUIRE_WAN`, `DENY_ALL_NET`, or `ALLOW_LOOPBACK`).

### D. Python Bridge & In-Kernel Map Verification (`bridge/moray_hook.py` Primary, `bridge/lobster_hook.py` Secondary)
- Established `bridge/moray_hook.py` as the sovereign, primary Python controller and CLI for Project Moray, while maintaining `bridge/lobster_hook.py` as a secondary L7 adapter.
- Exported `MORAY_PERM_LOOPBACK = 0x04` across all bridge interfaces.
- Updated `list_boundary()` to expose `"can_loopback": bool(entry.perm_flags & MORAY_PERM_LOOPBACK)`.
- Updated `verify_boundary_manifest()`:
  - For `DENY_ALL_NET`: asserts `sentinel["can_exec"]`, `not sentinel["can_loopback"]`, and `not sentinel["can_socket"]`.
  - For allowed worker comms (`comm_key != "morayd"`): asserts `not entry["can_socket"]`.
  - Fails closed with `MorayQuarantineError` (exit code `252`) on any mismatch.

### E. Victim Worker Test Primitives (`tests/victim_worker.c`)
- Added return code `48` to `--connect-loopback` when severed by LSM with `-EPERM` or `-EACCES`.
- Added return code `49` to `--connect-unix` when severed by LSM with `-EPERM` or `-EACCES`.
- Preserved return code `44` for WAN severance (`-EPERM`).

---

## 3. MicroVM Live Verification Suite (Domain 8: Steps 55–62)

The live KVM microVM test suite (`tests/run_live_kernel_test.sh`) is expanded to 62 steps:

| Step | Operation / Assertion | Empirical Proof & Pass Criteria |
| :--- | :--- | :--- |
| **Step 55** | Generate sovereign boundary manifest (`DENY_ALL_NET`). | Valid manifest emitted with `network_posture: "DENY_ALL_NET"`, `victim_worker` allowed, `unlisted_worker` excluded. |
| **Step 56** | Launch `morayd --auto-harden` in live Ring 0 mode (`DENY_ALL_NET`). | Verified pinned `/sys/fs/bpf/moray/boundary_map` on clean bpffs; daemon logs confirmation of `DENY_ALL_NET`. |
| **Step 57** | Hardware verification of live `boundary_map` contents against manifest. | `--verify-boundary` via primary `moray_hook.py` confirms sentinel `MORAY_PERM_EXEC` (`can_loopback == False`, `can_socket == False`) and worker permissions. Hard failure if missing. |
| **Step 58** | Test listed binary execution (`victim_worker --baseline-exec`). | Executes cleanly (exit 0); in-kernel Ring 0 `hit_count` incremented $\ge 1$. |
| **Step 59** | Test unlisted binary execution (`unlisted_worker`). | Intercepted with `-EPERM` (exit 42); autonomously quarantined in `moray_quarantine_map` with reason 2 (`EXEC_VIOLATION`). |
| **Step 60** | Test total local network severance (Loopback and AF_UNIX). | Loopback connect (`127.0.0.1:80`) severed with `-EPERM` (exit 48); AF_UNIX IPC connect severed with `-EPERM` (exit 49). |
| **Step 61** | Test autonomous WAN socket severance under `DENY_ALL_NET`. | Connect to `1.1.1.1:80` severed with `-EPERM` (exit 44); telemetry captured in Ring 0 ringbuf. |
| **Step 62** | Clean teardown of autonomous `DENY_ALL_NET` daemon and test artifacts. | Graceful signal shutdown with zero residual state. |

---

## 4. Claims Truth Matrix Elevation & Ground Truth Invariant Verification

In strict adherence to the **Top-Down Ground Truth Invariant ($I_6$)**:
- The entire 62-step live Ring 0 microVM test harness (`tests/run_live_kernel_test.sh`) was executed inside `virtme-ng` on the GitHub Actions runner.
- The dedicated CI Ground Truth Gate (`Enforce Ground Truth Invariant (Zero Fail-Green Gate)`) verified that `kvm_microvm_test.log` completed with `[+] Ground Truth Invariant Verified: All 62 steps completed without error.` and zero `FATAL` errors.
- With empirical proof established across all 62 steps, `Autonomous Boundary in MicroVM (DENY_ALL_NET)` is elevated to **Tier 1 (Verified: Ring 0)** in `README.md` and `docs/INVARIANTS.md`, and the microVM verification badge updated to **62/62 KVM Steps**.
