# Project Moray: Autonomous Policy End-to-End Verification (`ALLOW_LOOPBACK`)

> **Classification:** Systems Architecture & Kernel Verification Report  
> **Subsystems:** Linux Ring 0 BPF-LSM, `morayd` Auto-Harden Daemon, `boundary_map`, `lobster_hook.py`  
> **Security Contracts:** Invariant $I_8$ (Granular Network Isolation) & Invariant $I_9$ (Autonomous Boundary Enforcement)  
> **Status:** Empirically Verified in GitHub Actions CI (54/54 KVM Steps in MicroVM Harness, 141 Unit Tests Passed)

---

## 1. Executive Summary & Defect Root Cause

Project Moray provides autonomous, zero-configuration in-kernel process whitelisting and network containment via BPF-LSM (`moray_boundary_map`). While hermetic unit tests previously verified manifest synthesis and daemon mock startup, autonomous policy claims in the live KVM microVM harness were previously confined to Tier 2 (Mock-Verified), and the live microVM suite executed only 46 manual strike steps.

During deep architectural auditing of `src/morayd.c`, an operational boundary defect was identified:
- **Locus:** `src/morayd.c` (`seed_boundary_manifest` line 474 and `seed_default_boundary` line 403).
- **Defect Mechanism:** In `seed_boundary_manifest`, all binaries listed in `allowed_comms` were seeded with `MORAY_PERM_ALL` (`0xFF`), which unconditionally asserted `MORAY_PERM_SOCKET` (`0x02`). Consequently, in `moray_kern.bpf.c` (`moray_socket_strike`), when `network_posture` was configured as `ALLOW_LOOPBACK` (`sentinel->perm_flags == MORAY_PERM_EXEC`), any listed binary attempting an external WAN connection (`1.1.1.1:80`) matched `(b_entry->perm_flags & MORAY_PERM_SOCKET)` and was granted unimpeded WAN egress, completely bypassing the `ALLOW_LOOPBACK` security boundary.

---

## 2. Engineering Remediation & Implementation

### A. Surgical Daemon Boundary Clamp (`src/morayd.c`)
- In `seed_boundary_manifest()`, `entry.perm_flags` was clamped to `allow_wan ? MORAY_PERM_ALL : MORAY_PERM_EXEC`.
- In `seed_default_boundary()`, default entries were clamped to `MORAY_PERM_EXEC`.
- `morayd` itself retains `MORAY_PERM_ALL` to ensure management operations function unimpeded.

### B. First-Class Boundary Map Bridge & Verification (`bridge/lobster_hook.py`, `bridge/moray_hook.py`)
- Codified `MorayBoundaryEntry` matching `src/moray.h` (`sizeof() == 16` bytes: `perm_flags`, `reserved`, `hit_count`).
- Added low-level `BPF_OBJ_GET`, `BPF_MAP_LOOKUP_ELEM`, and `BPF_MAP_GET_NEXT_KEY` iterators over `/sys/fs/bpf/moray/boundary_map`.
- Implemented `verify_boundary_manifest(manifest_path)` to perform hardware verification of live in-kernel maps against manifest JSON:
  - Validates sentinel entry `"__moray_auto__"` is present with exact expected posture flags.
  - Confirms every listed comm is present in the kernel map with valid permissions.
  - Verifies unlisted comms are excluded.
  - Fails closed (`FAIL_CLOSED_EXIT_CODE = 252`) if any assertion fails.
- Added `--dump-boundary` and `--verify-boundary <manifest>` CLI commands to `lobster_hook.py` and `moray_hook.py`.

### C. Autonomous Victim Worker Test Primitives (`tests/victim_worker.c`)
- Implemented `--assert-unlisted-exec`: executes `execve("/bin/true")` and asserts hardware severance with `-EPERM` (exit code 42).
- Implemented non-blocking immediate network tests: `--connect-wan`, `--connect-loopback`, `--connect-unix`.
- Returns exit code 44 on WAN severance (`-EPERM`), 45 on loopback permission (`ECONNREFUSED` / past LSM), and 46 on UNIX socket permission.

---

## 3. MicroVM Live Verification Suite (Domain 7: Steps 47–54)

The live KVM microVM test suite (`tests/run_live_kernel_test.sh`) was expanded from 46 to 54 steps, establishing end-to-end empirical proof without mocks or skipped assertions:

| Step | Operation / Assertion | Empirical Proof & Pass Criteria |
| :--- | :--- | :--- |
| **Step 47** | Generate real autonomous boundary manifest (`ALLOW_LOOPBACK`). | Valid manifest emitted with `victim_worker` allowed and `unlisted_worker` excluded. |
| **Step 48** | Launch `morayd --auto-harden` in live Ring 0 mode. | Pinned `/sys/fs/bpf/moray/boundary_map` verified on bpffs. |
| **Step 49** | Hardware verification of live `boundary_map` contents. | `--verify-boundary` confirms sentinel `MORAY_PERM_EXEC` and exact comm permissions. Hard failure if missing. |
| **Step 50** | Test listed binary execution (`victim_worker --baseline-exec`). | Executes cleanly (exit 0); in-kernel Ring 0 `hit_count` incremented $\ge 1$. |
| **Step 51** | Test unlisted binary execution (`unlisted_worker`). | Intercepted with `-EPERM` (exit 42); autonomously quarantined in `moray_quarantine_map` with reason 2 (`EXEC_VIOLATION`). |
| **Step 52** | Test granular loopback socket connect under `ALLOW_LOOPBACK`. | Loopback IPv4 (`127.0.0.1`) exits 45; AF_UNIX exits 46 (permitted past LSM). |
| **Step 53** | Test autonomous WAN socket severance under `ALLOW_LOOPBACK`. | Connect to `1.1.1.1:80` severed with `-EPERM` (exit 44); telemetry captured in Ring 0 ringbuf. |
| **Step 54** | Clean teardown of autonomous daemon. | Graceful signal shutdown with zero residual state. |

---

## 4. Claims Truth Matrix Elevation & Ground Truth Invariant Verification

In strict adherence to the **Top-Down Ground Truth Invariant** and human verification guardrails:
- The entire 54-step live Ring 0 microVM test harness (`tests/run_live_kernel_test.sh`) was executed inside `virtme-ng` on the GitHub Actions runner.
- The dedicated CI Ground Truth Gate (`Enforce Ground Truth Invariant (Zero Fail-Green Gate)`) verified that `kvm_microvm_test.log` completed with `[+] Ground Truth Invariant Verified: All 54 steps completed without error.` and zero `FATAL` errors.
- With empirical proof established across all 54 steps, `Autonomous Boundary in MicroVM (ALLOW_LOOPBACK)` is officially elevated to **Tier 1 (Verified: Ring 0)** in `README.md` and `docs/INVARIANTS.md`, and the microVM verification badge updated to **54/54 KVM Steps**.
