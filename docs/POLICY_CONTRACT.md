# Project Moray: Formal Policy Contract & Enforcement Boundary Specification

> **Classification:** Canonical Security Contract & Operational Ground Truth  
> **Subsystems:** Linux Ring 0 BPF-LSM, `morayd` Auto-Harden Daemon, `moray_boundary_map`, `moray_hook.py`  
> **Applicable Invariants:** Invariant $I_1$ (Fail-Closed Quarantine), Invariant $I_2$ (Zero-Latency Benign Baseline), Invariant $I_8$ (Granular Network Isolation), Invariant $I_9$ (Autonomous Boundary Enforcement)  
> **Verification Status:** Empirically verified across 70/70 live KVM microVM steps (`tests/run_live_kernel_test.sh`) and 141 hermetic unit tests.

---

## 1. Scope & Architectural Purpose

This document codifies the precise operational semantics, jurisdiction, and enforcement boundaries of Project Moray's Autonomous Policy Triad:
* `ALLOW_LOOPBACK`
* `DENY_ALL_NET`
* `REQUIRE_WAN`

The objective is to eliminate semantic drift, prevent nomenclature inflation, and strictly delineate what the in-kernel Ring 0 LSM checks guarantee versus what remains out of scope.

---

## 2. Jurisdiction & Identity Model

### 2.1 Current Identity Mechanism: Short Process Name (`comm`)
In the current implementation ([`src/moray_kern.bpf.c`](file:///root/home/projects/project-moray/src/moray_kern.bpf.c#L141-L165)):
* The autonomous boundary is activated globally when `--auto-harden` seeds the sentinel key `"__moray_auto__"` into `moray_boundary_map`.
* Boundary lookups evaluate the calling task's executable name (`char comm[16]`) retrieved via `bpf_get_current_comm()`.
* **Current Operational Boundary:** The policy applies host-wide to any process executing an unlisted binary or attempting a socket connection. It does not distinguish an agent's `python3` process from an unrelated system or administrative `python3` process elsewhere on the host.

### 2.2 Target Jurisdiction Model: Workload-Scoped Cgroup v2 (Milestone 2)
To establish proper legal jurisdiction—defining *whose* rules Moray enforces:
* Moray is transitioning to **Workload-Scoped Jurisdiction** keyed on Linux Cgroup v2 identifiers (`bpf_get_current_cgroup_id()`).
* Under this contract:
  1. **Governed Workload:** Tasks residing inside the designated Cgroup v2 hierarchy are subject to the active autonomous boundary policy (executable whitelisting and network posture).
  2. **Ungoverned Host Workloads:** Tasks executing outside the governed hierarchy bypass autonomous boundary checks entirely, passing through the $O(1)$ fast path unimpeded (Invariant $I_2$).
  3. **Inheritance:** All child processes forked within a governed cgroup inherit the workload boundary.

---

## 3. The Autonomous Policy Triad Contract

The table below defines the exact semantic contract for each autonomous posture:

| Policy Posture | Sentinel Permission Bits | Allowed Comms Bits | Permitted Executables | Outbound WAN (`connect()`) | Loopback IPv4/IPv6 (`connect()`) | Local UNIX IPC (`AF_UNIX`) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`ALLOW_LOOPBACK`** | `0x05U` (`EXEC \| LOOPBACK`) | `0x01U` (`EXEC`) | Whitelisted only | **DENIED** (`-EPERM`) | **PERMITTED** | **PERMITTED** |
| **`DENY_ALL_NET`** | `0x01U` (`EXEC`) | `0x01U` (`EXEC`) | Whitelisted only | **DENIED** (`-EPERM`) | **DENIED** (`-EPERM`) | **DENIED** (`-EPERM`) |
| **`REQUIRE_WAN`** | `0xFFU` (`PERM_ALL`) | `0xFFU` (`PERM_ALL`) | Whitelisted only | **PERMITTED** | **PERMITTED** | **PERMITTED** |

---

### 3.1 Posture 1: `ALLOW_LOOPBACK`

#### Execution Semantics:
* Intercepted at `SEC("lsm/bprm_check_security")`.
* Executable name (`comm`) must be explicitly registered in `moray_boundary_map` with `MORAY_PERM_EXEC` (`0x01U`).
* Unlisted binaries receive immediate `-EPERM` and are autonomously inserted into `moray_quarantine_map` with reason code `MORAY_REASON_EXEC_VIOLATION` (`2`).

#### Network Semantics:
* Intercepted at `SEC("lsm/socket_connect")`.
* **Permitted:**
  * Local UNIX Domain Sockets (`AF_UNIX`).
  * IPv4 loopback destinations matching `127.0.0.0/8` (`sin_addr.s_addr & 0xFF000000 == 0x7F000000`).
  * IPv6 loopback destinations matching `::1`.
* **Denied:**
  * Any external IPv4 or IPv6 WAN destination is severed with `-EPERM`.
* **Empirical Verification Locus:** Live KVM microVM Steps 47–54 in [`tests/run_live_kernel_test.sh`](file:///root/home/projects/project-moray/tests/run_live_kernel_test.sh#L765-L875).

---

### 3.2 Posture 2: `DENY_ALL_NET`

#### Execution Semantics:
* Intercepted at `SEC("lsm/bprm_check_security")`.
* Identical whitelist enforcement: unlisted binaries receive `-EPERM` and trigger autonomous quarantine.

#### Network Semantics:
* Intercepted at `SEC("lsm/socket_connect")`.
* **Total Connect Severance:**
  * External WAN connection attempts (`AF_INET`, `AF_INET6`) receive `-EPERM`.
  * Local IPv4 and IPv6 loopback connection attempts (`127.0.0.1`, `::1`) receive `-EPERM`.
  * Local UNIX Domain Socket connection attempts (`AF_UNIX`) receive `-EPERM`.
* **Strict Boundary Definition (Anti-Inflation):**
  * `DENY_ALL_NET` guarantees the denial of outbound socket connection initiation via `connect()`.
  * It does **NOT** guarantee ambient network isolation of pre-existing sockets established before policy activation, nor does it intercept raw frame reception unless paired with driver-level XDP drops ([`moray_xdp_drop_map`](file:///root/home/projects/project-moray/src/moray_kern.bpf.c#L34-L40)).
* **Empirical Verification Locus:** Live KVM microVM Steps 55–62 in [`tests/run_live_kernel_test.sh`](file:///root/home/projects/project-moray/tests/run_live_kernel_test.sh#L877-L998).

---

### 3.3 Posture 3: `REQUIRE_WAN`

#### Execution Semantics:
* Intercepted at `SEC("lsm/bprm_check_security")`.
* Identical whitelist enforcement: unlisted binaries receive `-EPERM` and trigger autonomous quarantine.

#### Network Semantics:
* Intercepted at `SEC("lsm/socket_connect")`.
* The sentinel `"__moray_auto__"` and listed comms are seeded with `MORAY_PERM_ALL` (`0xFFU`).
* Because `MORAY_PERM_SOCKET` (`0x02U`) is asserted on the sentinel, the autonomous socket denial block in `moray_socket_strike` is bypassed for authorized worker processes.
* **Strict Boundary Definition (Ground Truth Invariant):**
  * `REQUIRE_WAN` proves that **Moray's Ring 0 LSM hooks do not intercept or block the outbound `connect()` syscall**.
  * It does **NOT** prove or guarantee that the host or microVM has functioning internet connectivity, working DNS, a default gateway route, or external WAN reachability.
  * In the test harness (`tests/victim_worker.c`), verification succeeds (exit code `43`) when `connect()` returns `0` OR when `connect()` fails with a routing/network error (`ECONNREFUSED`, `ENETUNREACH`, `ETIMEDOUT`) as long as the error is **not** `-EPERM` or `-EACCES`.
* **Empirical Verification Locus:** Live KVM microVM Steps 63–70 in [`tests/run_live_kernel_test.sh`](file:///root/home/projects/project-moray/tests/run_live_kernel_test.sh#L1000-L1122).

---

### 3.4 Control Plane Management Exemption

Across all three postures, the management daemon (`morayd`) is registered with `MORAY_PERM_ALL` (`0xFFU`):
* Preserves management operations, health check polling, map updates, and telemetry ring buffer emission.
* Prevents self-containment deadlock where the monitoring daemon would inadvertently sever its own operations.

---

## 4. Enforcement Boundary vs. Universal Network Isolation

To preserve technical precision, Moray explicitly distinguishes between its active enforcement points and general networking layers:

| Network Operation | Hook Point / Subsystem | Moray Status | Boundary Guarantee |
| :--- | :--- | :--- | :--- |
| **Outbound TCP/UDP Initiation** | `lsm/socket_connect` | **Enforced (Ring 0)** | Evaluated against active policy posture; blocked with `-EPERM` under `DENY_ALL_NET` or non-loopback under `ALLOW_LOOPBACK`. |
| **Local UNIX Domain Sockets** | `lsm/socket_connect` | **Enforced (Ring 0)** | Intercepted via `sa_family == AF_UNIX`; blocked under `DENY_ALL_NET`, permitted under `ALLOW_LOOPBACK` and `REQUIRE_WAN`. |
| **Specific Malicious IPv4 Wire Frames**| Driver `XDP` (`moray_xdp_drop_map`) | **Enforced (Ring 0)** | Dropped at line-rate via `XDP_DROP` before reaching kernel network stack. |
| **Pre-existing Open Sockets** | Transport State | **Not Retrospective** | `socket_connect` executes at initiation time. Connections established before policy activation remain open unless explicitly killed via PID termination. |
| **Inbound Sockets (`accept`)** | Transport / Firewall | **Out of Scope** | Inbound connection gating is governed by standard firewall rules (`nftables`/`iptables`) or user-space proxies (Project Lobster). |
| **Arbitrary L2 / Raw Socket Transmission** | Packet Sockets | **Partially Enforced** | Unlisted binaries cannot execute `raw` socket utilities; however, raw frame isolation without `connect()` relies on XDP driver drops, not `socket_connect`. |

---

## 5. Verification Locus & Claims Mapping Matrix

Every claim in the Project Moray truth matrix maps directly to an automated verification test:

| Claimed Capability | Policy / Subsystem | Verification Level | Test Locus |
| :--- | :--- | :--- | :--- |
| **Whitelisted Execution** | All Postures | **Verified (Ring 0)** | `tests/run_live_kernel_test.sh` (Steps 49, 57, 65) |
| **Unlisted Execution Severance** | All Postures | **Verified (Ring 0)** | `tests/run_live_kernel_test.sh` (Steps 50, 58, 66) |
| **Autonomous Ring 0 Quarantine** | All Postures | **Verified (Ring 0)** | `tests/run_live_kernel_test.sh` (Steps 51, 59, 67) |
| **Loopback / IPC Network Permitted**| `ALLOW_LOOPBACK` | **Verified (Ring 0)** | `tests/run_live_kernel_test.sh` (Steps 52, 53) |
| **External WAN Connect Blocked** | `ALLOW_LOOPBACK` | **Verified (Ring 0)** | `tests/run_live_kernel_test.sh` (Step 54) |
| **Total Network Connect Severance**| `DENY_ALL_NET` | **Verified (Ring 0)** | `tests/run_live_kernel_test.sh` (Steps 60, 61, 62) |
| **Non-Interception of Outbound Connect**| `REQUIRE_WAN` | **Verified (Ring 0)** | `tests/run_live_kernel_test.sh` (Steps 68, 69, 70) |
| **Struct Memory Layout & Alignment**| Shared ABI | **Verified (Hermetic)** | `tests/test_struct_layout.c` (Lines 1–150) |
| **Manifest Parsing & Auto-Harden** | Bridge & Daemon | **Verified (Hermetic)** | `tests/test_autonomous_boundary_e2e.py` |
| **Cgroup v2 Quarantine Containment**| Manual / Lobster | **Verified (Ring 0)** | `tests/run_live_kernel_test.sh` (Steps 16–19) |
| **Cgroup-Scoped Autonomous Boundary**| Planned Jurisdiction | **In Progress (Milestone 2)**| Scheduled for Phase 8 / Milestone 2 sprint |
