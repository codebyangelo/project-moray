# Project Moray: Autonomous Policy End-to-End Verification (`REQUIRE_WAN`)

> **Classification:** Systems Architecture & Kernel Verification Report  
> **Subsystems:** Linux Ring 0 BPF-LSM, `morayd` Auto-Harden Daemon, `boundary_map`, `moray_hook.py`  
> **Security Contracts:** Invariant $I_8$ (Granular Network Isolation) & Invariant $I_9$ (Autonomous Boundary Enforcement)  
> **Status:** Empirically Verified in GitHub Actions CI (Domain 9, Steps 63–70 in MicroVM Harness, 141 Hermetic Tests Passed)

---

## 1. Executive Summary & Policy Architectural Distinction

Project Moray provides autonomous, in-kernel process whitelisting and network containment via BPF-LSM (`moray_boundary_map`). In Phase 7 Stages 5 and 6, the `ALLOW_LOOPBACK` (Domain 7) and `DENY_ALL_NET` (Domain 8) postures were verified end-to-end across 62 KVM microVM steps.

Phase 7 Stage 7 completes the autonomous policy triad with **`REQUIRE_WAN`**.
Under `REQUIRE_WAN`, an agent workspace requires unrestricted external network connectivity (e.g. LLM API endpoints, package managers, web tooling):
- **Execution Whitelisting Enforced:** Any unlisted binary attempting `execve()` is immediately intercepted with `-EPERM` at the Ring 0 LSM boundary (`moray_bprm_strike`) and autonomously quarantined in `moray_quarantine_map` with reason 2 (`EXEC_VIOLATION`).
- **Permitted Outbound Egress:** Listed worker processes (`allowed_comms`) and the control plane daemon (`morayd`) have `MORAY_PERM_ALL` (`0xFF`), allowing outbound WAN (`1.1.1.1:80`), localhost loopback IPv4/IPv6 (`127.0.0.1:80`), and local UNIX domain socket IPC (`AF_UNIX`) to pass unimpeded past LSM.
- **Sentinel State:** The in-kernel sentinel `"__moray_auto__"` is seeded with `MORAY_PERM_ALL` (`0xFF`). In `moray_socket_strike`, the presence of `MORAY_PERM_SOCKET` bypasses autonomous socket denial while preserving manual quarantine supervision.

---

## 2. Engineering Remediation & Implementation

### A. First-Class Permission Flags (`src/moray.h`, `tests/test_struct_layout.c`)
- Codified `#define MORAY_PERM_ALL 0xFFU` encompassing `MORAY_PERM_EXEC` (`0x01U`), `MORAY_PERM_SOCKET` (`0x02U`), and `MORAY_PERM_LOOPBACK` (`0x04U`).
- Verified static struct layout and flag alignment in `tests/test_struct_layout.c`.

### B. In-Kernel LSM Boundary Gating (`src/moray_kern.bpf.c`)
- In `moray_socket_strike`:
  - Sentinel check: `if (sentinel && !(sentinel->perm_flags & MORAY_PERM_SOCKET) && address && addrlen > 0)`.
  - Under `REQUIRE_WAN`, `sentinel->perm_flags & MORAY_PERM_SOCKET` is asserted (`0xFF`), skipping the autonomous socket severance block and permitting external WAN, loopback, and local IPC traffic past LSM.
- In `moray_bprm_strike`:
  - Evaluates `(b_entry && (b_entry->perm_flags & MORAY_PERM_EXEC))`.
  - Unlisted binaries (e.g. `unlisted_worker`) have no entry in `moray_boundary_map`, triggering autonomous `-EPERM` severance and Ring 0 quarantine.

### C. Daemon Manifest Parsing (`src/morayd.c`)
- In `seed_boundary_manifest()`:
  - Detects `"REQUIRE_WAN"`.
  - Assigns `sentinel_val.perm_flags = MORAY_PERM_ALL`.
  - Assigns `entry.perm_flags = MORAY_PERM_ALL` to all authorized comms.
  - Logs `[+] Autonomous Ring 0 Boundary Defense ACTIVE (Network Posture: REQUIRE_WAN)`.

### D. Python Bridge & Map Verification (`bridge/moray_hook.py`, `bridge/lobster_hook.py`)
- In `verify_boundary_manifest()`:
  - Asserts `sentinel["can_exec"]` and `sentinel["can_socket"]` under `REQUIRE_WAN`.
  - Asserts `entry["can_exec"]` and `entry["can_socket"]` across all allowed worker comms.
  - Fails closed with `MorayQuarantineError` (exit code `252`) on any permission omission.

### E. Victim Worker Test Primitives (`tests/victim_worker.c`)
- Added return code `43` to `--connect-wan <ip> <port>` when the connection succeeds or proceeds past LSM (`ret == 0 || (ret < 0 && err != EPERM && err != EACCES)`).
- Preserved return code `44` when severed by LSM with `-EPERM`.
- Preserved return code `45` for loopback connect permitted past LSM.
- Preserved return code `46` for UNIX socket connect permitted past LSM.

---

## 3. MicroVM Live Verification Suite (Domain 9: Steps 63–70)

The live KVM microVM test suite (`tests/run_live_kernel_test.sh`) is expanded to **70 steps**:

| Step | Operation / Assertion | Empirical Proof & Pass Criteria |
| :--- | :--- | :--- |
| **Step 63** | Generate sovereign boundary manifest (`REQUIRE_WAN`). | Valid manifest emitted with `network_posture: "REQUIRE_WAN"`, `victim_worker` allowed, `unlisted_worker` excluded. |
| **Step 64** | Launch `morayd --auto-harden` in live Ring 0 mode (`REQUIRE_WAN`). | Verified pinned `/sys/fs/bpf/moray/boundary_map` on clean bpffs; daemon logs confirmation of `REQUIRE_WAN`. |
| **Step 65** | Hardware verification of live `boundary_map` contents against manifest. | `--verify-boundary` via primary `moray_hook.py` confirms sentinel `MORAY_PERM_ALL` (`can_exec == True`, `can_socket == True`) and worker permissions. Hard failure if missing. |
| **Step 66** | Test listed binary execution (`victim_worker --baseline-exec`). | Executes cleanly (exit 0); in-kernel Ring 0 `hit_count` incremented $\ge 1$. |
| **Step 67** | Test unlisted binary execution (`unlisted_worker`). | Intercepted with `-EPERM` (exit 42); autonomously quarantined in `moray_quarantine_map` with reason 2 (`EXEC_VIOLATION`). |
| **Step 68** | Test permitted WAN socket connect under `REQUIRE_WAN`. | Connect to `1.1.1.1:80` succeeds past LSM (exit 43); zero socket strike events emitted in Ring 0 ringbuf. |
| **Step 69** | Test permitted loopback and AF_UNIX socket connects under `REQUIRE_WAN`. | Loopback connect (`127.0.0.1:80`) exits 45; AF_UNIX IPC connect exits 46 (permitted past LSM). |
| **Step 70** | Clean teardown of autonomous `REQUIRE_WAN` daemon and test artifacts. | Graceful signal shutdown with zero residual state. |

---

## 4. Claims Truth Matrix & Ground Truth Invariant Protocol

In strict adherence to the **Top-Down Ground Truth Invariant ($I_6$)**:
- Claims for `REQUIRE_WAN` were staged in Tier 2 as `Staged (Domain 9)` until live execution inside `virtme-ng` on GitHub Actions completed cleanly.
- The CI workflow (`.github/workflows/ci.yml`) enforced the `Zero Fail-Green Gate` against `ALL 70 LIVE RING 0 KERNEL TEST STEPS PASSED CLEANLY`.
- MicroVM execution verified all 70 steps without error; PR #28 merged cleanly into `main` (`4d9226f`).
- `Autonomous Boundary in MicroVM (REQUIRE_WAN)` is elevated to **Tier 1 (Verified: Ring 0)** in `README.md` and `docs/INVARIANTS.md`, and the badge upgraded to **70/70 KVM Steps**, fully concluding empirical verification of the autonomous policy triad.
