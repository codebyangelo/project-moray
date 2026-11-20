# Project Moray: Workload Jurisdiction & Dual-Workload Non-Interference Verification

## 1. Executive Summary

Having established and empirically proven the three autonomous network postures (`ALLOW_LOOPBACK`, `DENY_ALL_NET`, and `REQUIRE_WAN`) across 70/70 microVM steps, Project Moray addresses the jurisdictional boundary invariant:
> *"Why should morayd decide what 'victim_worker' can do globally? It shouldn't. An agent's posture belongs to the agent's cgroup, not the host. Same policy, correct workload boundary."*

This implementation upgrades Project Moray from global host-wide process-name (`comm`) whitelisting to **Cgroup v2-Scoped Workload Jurisdiction**. When a workload boundary is active, unlisted binaries and network connections executed outside the governed cgroup bypass autonomous boundary enforcement entirely ($O(1)$ fast-path, zero host interference). Inside the governed workload, all autonomous boundary constraints, network postures, and anti-tamper quarantines remain enforced at Ring 0.

---

## 2. Architecture & Data Structures

### 2.1 Struct Layout & Alignment
Defined in [`src/moray.h`](file:///root/home/projects/project-moray/src/moray.h#L110-L135) and asserted at compile-time via `_Static_assert`:

```c
struct moray_workload_entry {
    __u32 posture_flags;    /* Allowed operations: MORAY_PERM_EXEC, MORAY_PERM_SOCKET, MORAY_PERM_LOOPBACK */
    __u32 flags;            /* Workload state: MORAY_WORKLOAD_ACTIVE, MORAY_WORKLOAD_INHERIT_CHILDREN */
    __u64 strike_count;     /* Cumulative autonomous strikes inside this workload */
    __u64 hit_count;        /* Authorized executions/connects inside this workload */
};
_Static_assert(sizeof(struct moray_workload_entry) == 24, "moray_workload_entry must be 24 bytes");
```

### 2.2 Map Topology
- **Map Name:** `moray_workload_map`
- **Map Type:** `BPF_MAP_TYPE_HASH`
- **Key:** `__u64 cgroup_id` (Cgroup v2 64-bit inode)
- **Value:** `struct moray_workload_entry` (24 bytes)
- **Max Entries:** 1024
- **Pinned Path:** `/sys/fs/bpf/moray/workload_map`

### 2.3 Sentinel Mode Flags
- `MORAY_BOUNDARY_FLAG_HOSTWIDE (0x00)`: Legacy mode; applies boundary whitelisting globally across all host tasks.
- `MORAY_BOUNDARY_FLAG_WORKLOAD (0x01)`: Workload-scoped mode; restricts boundary enforcement exclusively to tasks belonging to registered cgroup v2 hierarchies.

---

## 3. Kernel Fast-Path & Ancestor Traversal

In [`src/moray_kern.bpf.c`](file:///root/home/projects/project-moray/src/moray_kern.bpf.c), `lookup_workload_entry()` resolves whether the current task is governed:

1. **Direct Lookup:** Performs hash lookup on `bpf_get_current_cgroup_id()`. If found and active, returns entry immediately.
2. **Hierarchy Inheritance (`MORAY_WORKLOAD_INHERIT_CHILDREN`):** If not found directly, inspects ancestor cgroup IDs up to 4 levels deep via `bpf_get_current_ancestor_cgroup_id(level)`. If an ancestor has `MORAY_WORKLOAD_INHERIT_CHILDREN`, governance is inherited automatically without manual registration.
3. **Non-Interference Fast Path ($I_2$):** If `w_entry == NULL` and sentinel mode is `MORAY_BOUNDARY_FLAG_WORKLOAD`, the LSM hooks return 0 immediately. Tasks outside governed workloads experience zero latency and zero interference.

---

## 4. Verification Suite & Empirical Evidence

### 4.1 Hermetic Test Suite (`tests/test_workload_boundary.py`)
Nine comprehensive unit and integration tests validate the sovereign userspace bridge:
1. `TestWorkloadLifecycle::test_register_and_lookup_workload` (PASSED)
2. `TestWorkloadLifecycle::test_release_workload` (PASSED)
3. `TestWorkloadLifecycle::test_list_and_flush_workloads` (PASSED)
4. `TestWorkloadPostureContracts::test_allow_loopback_posture` (PASSED)
5. `TestWorkloadPostureContracts::test_deny_all_net_posture` (PASSED)
6. `TestWorkloadPostureContracts::test_require_wan_posture` (PASSED)
7. `TestWorkloadPostureContracts::test_ungoverned_workload_status` (PASSED)
8. `TestDualWorkloadNonInterference::test_dual_workload_decision_logic` (PASSED)
9. `TestWorkloadCLI::test_cli_register_and_status` (PASSED)

### 4.2 MicroVM Live Kernel Verification (Domain 10: Steps 71–80)
Added to [`tests/run_live_kernel_test.sh`](file:///root/home/projects/project-moray/tests/run_live_kernel_test.sh#L1120-L1320):

| Step | Action | Expected Result | Invariant Proven |
|---|---|---|---|
| **71** | Setup dual cgroup v2 slices (`moray_workload_a`, `moray_workload_b`) | Inodes resolved, dual slices isolated | Ground Truth Setup |
| **72** | Generate workload manifest targeting Workload A | Manifest generated with `ALLOW_LOOPBACK` | Policy Contract |
| **73** | Launch `morayd` with `--cgroup /sys/fs/cgroup/moray_workload_a` | Workload-scoped sentinel mode active, maps pinned | Sentinel Initialization |
| **74** | Inspect kernel `workload_map` via `moray_hook` | Workload A governed, Workload B ungoverned | Map Integrity |
| **75** | Dual-workload unlisted binary (`unlisted_worker`) execution | Workload A: blocked (-EPERM, exit 42); Workload B: permitted (exit 0) | Non-Interference ($I_2$) |
| **76** | Dual-workload WAN socket connect (`victim_worker`) | Workload A: blocked (-EPERM, code 44); Workload B: permitted (code 43) | Network Jurisdiction |
| **77** | Dual-workload loopback socket connect under `ALLOW_LOOPBACK` | Workload A: permitted (code 45); Workload B: permitted (code 45) | Granular Loopback |
| **78** | Child process cgroup inheritance (`child_task`) | Blocked (-EPERM, code 44) via ancestor traversal | Inherit Children |
| **79** | Dynamic zero-downtime lifecycle (`register` -> `release`) | Workload B dynamic block, then restore to unhindered state | Dynamic Lifecycle |
| **80** | Clean daemon teardown and artifact unlinking | Zero leaks, clean kernel state | Fail-Closed & Hygiene |

---

## 5. Invariant Conformance

- **$I_1$ Ring 0 Kernel Enforcement:** Boundary gating is enforced strictly inside `bpf_lsm_bprm_check_security` and `bpf_lsm_socket_connect`.
- **$I_2$ Zero Overhead & Non-Interference:** Processes outside registered workloads bypass boundary inspection at $O(1)$ lookup time with zero interference.
- **$I_3$ Hermetic Sovereign Bridge:** Zero external runtime dependencies; uses native `ctypes` and `sys_bpf` system calls.
- **$I_9$ Cgroup v2 Workload Jurisdiction:** Boundary policies follow cgroup v2 hierarchies and ancestor inheritance, never superficial host-wide process names.
