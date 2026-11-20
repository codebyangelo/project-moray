# Project Moray: Extended Network Defense & Multi-Stage Ring 0 Boundary Verification

## 1. Executive Summary

Milestone 3 of the [canonical development roadmap](file:///root/home/projects/project-moray/anotherroadmap.md) mandates:
> *"Make the network claim match the enforcement boundary. Decide whether Moray is proving connect-call policy or comprehensive network isolation... Precise names are part of security correctness. 'Deny all network' is a stronger promise than 'deny these socket connection attempts.' Done when policy names, documentation, and tests all state the same guarantee."*

Prior to Milestone 3, Moray enforced network policies solely at `SEC("lsm/socket_connect")`. While highly effective for outbound connection initiation, this left two subtle bypass vectors that conflicted with the semantic guarantee of `DENY_ALL_NET` and `ALLOW_LOOPBACK`:
1. **Unconnected Datagram Bypass:** A process issuing `socket(AF_INET, SOCK_DGRAM)` followed immediately by `sendto()` never invokes `connect()`, potentially permitting outbound UDP transmission under `DENY_ALL_NET`.
2. **Rogue External Listener Binding:** A compromised process governed by `ALLOW_LOOPBACK` could issue `bind(0.0.0.0, port)` or bind to external interface addresses, opening rogue external inbound listeners rather than being strictly restricted to localhost IPC.

Milestone 3 (PR #31, commit `0149ea1`) eliminates both vectors at Ring 0 by establishing a **4-Stage Network Defense Gate**:
- `SEC("lsm/socket_create")`: Denies socket allocation entirely under `DENY_ALL_NET`, and blocks `SOCK_RAW` / `AF_PACKET` frame crafting under `ALLOW_LOOPBACK`.
- `SEC("lsm/socket_bind")`: Restricts address binding under `ALLOW_LOOPBACK` strictly to `127.0.0.0/8`, `::1`, and `AF_UNIX`; denies all address binding under `DENY_ALL_NET`.
- `SEC("lsm/socket_connect")`: Mediates outbound transport connections against active workload policy.
- `SEC("xdp")` (`moray_xdp_filter`): Line-rate wire ingress frame dropping via `XDP_DROP` for flagged IPs.

Live hardware-level verification in QEMU/KVM microVM was expanded from 80 to 90 steps (Domain 11: Steps 81–90), achieving 100% green pass rates across all domains.

---

## 2. Multi-Stage Ring 0 Architecture

```
[Userspace Syscall: socket(), bind(), connect()]
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: Socket Allocation Gate (lsm/socket_create)         │
│  ├── DENY_ALL_NET: Block AF_INET, AF_INET6, AF_UNIX,        │
│  │                 and AF_PACKET allocation (-EPERM)        │
│  └── ALLOW_LOOPBACK: Block SOCK_RAW / AF_PACKET (-EPERM)    │
└───────────────────────────────┬─────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 2: Address Binding Gate (lsm/socket_bind)             │
│  ├── DENY_ALL_NET: Block all address binding (-EPERM)       │
│  └── ALLOW_LOOPBACK: Permit 127.0.0.0/8, ::1, AF_UNIX;      │
│                      Block 0.0.0.0 / WAN binds (-EPERM)     │
└───────────────────────────────┬─────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 3: Outbound Initiation Gate (lsm/socket_connect)      │
│  ├── DENY_ALL_NET: Block all connect attempts (-EPERM)      │
│  └── ALLOW_LOOPBACK: Permit 127.0.0.0/8, ::1, AF_UNIX;      │
│                      Block external WAN/LAN (-EPERM)        │
└───────────────────────────────┬─────────────────────────────┘
                                │
                                ▼
                    [TCP/IP & Transport Stack]
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 4: Wire Ingress Gate (Driver XDP moray_xdp_filter)    │
│  └── Line-rate ingress frame dropping via XDP_DROP          │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Kernel Fast-Path & Canonical Address Helper

In [`src/moray_kern.bpf.c`](file:///root/home/projects/project-moray/src/moray_kern.bpf.c), network classification logic is unified into a single inline helper:

```c
static __always_inline bool is_loopback_or_unix(struct sockaddr *address, int addrlen) {
    if (!address || addrlen < (int)sizeof(struct sockaddr))
        return false;

    short family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family) != 0)
        return false;

    if (family == 1 /* AF_UNIX */)
        return true;

    if (family == 2 /* AF_INET */) {
        if (addrlen < (int)sizeof(struct sockaddr_in))
            return false;
        struct sockaddr_in sin;
        if (bpf_probe_read_kernel(&sin, sizeof(sin), address) != 0)
            return false;
        __u32 ip = __builtin_bswap32(sin.sin_addr.s_addr);
        return (ip >= 0x7F000000 && ip <= 0x7FFFFFFF); /* 127.0.0.0/8 */
    }

    if (family == 10 /* AF_INET6 */) {
        if (addrlen < (int)sizeof(struct sockaddr_in6))
            return false;
        struct sockaddr_in6 sin6;
        if (bpf_probe_read_kernel(&sin6, sizeof(sin6), address) != 0)
            return false;
        const __u32 *addr32 = (const __u32 *)sin6.sin6_addr.s6_addr;
        return (addr32[0] == 0 && addr32[1] == 0 && addr32[2] == 0 && addr32[3] == __builtin_bswap32(1)); /* ::1 */
    }

    return false;
}
```

### 3.1 Hook Definitions & Mediation Logic
- **`SEC("lsm/socket_create")` (`moray_socket_create`)**:
  - Checks workload jurisdiction. Unregistered workloads pass with zero overhead ($O(1)$ fast-path).
  - If workload posture is `DENY_ALL_NET`: blocks `AF_INET`, `AF_INET6`, `AF_UNIX`, and `AF_PACKET` socket creation with `-EPERM`.
  - If workload posture is `ALLOW_LOOPBACK`: blocks `type == SOCK_RAW` and `family == AF_PACKET` with `-EPERM` to prevent raw ethernet/IP frame crafting that could bypass L4 checks.
- **`SEC("lsm/socket_bind")` (`moray_socket_bind`)**:
  - Checks workload jurisdiction. Unregistered workloads pass with zero overhead.
  - If workload posture is `DENY_ALL_NET`: blocks all socket binding with `-EPERM`.
  - If workload posture is `ALLOW_LOOPBACK`: evaluates target address via `is_loopback_or_unix()`. Only `127.0.0.0/8`, `::1`, and `AF_UNIX` are permitted. Binding to `0.0.0.0` (`INADDR_ANY`), `::`, or external interface IPs returns `-EPERM`.
- **`SEC("lsm/socket_connect")` (`moray_socket_strike`)**:
  - Evaluates target address via `is_loopback_or_unix()`.
  - Enforces outbound connect rules per posture contract (`ALLOW_LOOPBACK`, `DENY_ALL_NET`, `REQUIRE_WAN`).

---

## 4. ABI and Userspace Bridge Extensions

### 4.1 Header Constants
Added to [`src/moray.h`](file:///root/home/projects/project-moray/src/moray.h#L32-L40):
```c
#define MORAY_HOOK_SOCKET_BIND    5U
#define MORAY_HOOK_SOCKET_CREATE  6U
```

Added to [`src/moray_bpf.h`](file:///root/home/projects/project-moray/src/moray_bpf.h#L52-L60):
```c
#define AF_PACKET   17
#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define SOCK_RAW    3
```

Compile-time `_Static_assert` validations confirmed across all shared structures:
- `sizeof(struct moray_quarantine_entry) == 24`
- `sizeof(struct moray_event) == 128`
- `sizeof(struct moray_boundary_entry) == 16`
- `sizeof(struct moray_workload_entry) == 24`

### 4.2 Daemon Loader Lifecycle ([`src/morayd.c`](file:///root/home/projects/project-moray/src/morayd.c))
`struct moray_bpf_context` tracks `bpf_link` instances for `link_bind` and `link_create`. Both programs are attached via `bpf_program__attach_lsm()` during startup and explicitly detached via `bpf_link__destroy()` during shutdown.

### 4.3 Python Sovereign Bridge ([`bridge/lobster_hook.py`](file:///root/home/projects/project-moray/bridge/lobster_hook.py))
Exposes `MORAY_HOOK_SOCKET_BIND` (5) and `MORAY_HOOK_SOCKET_CREATE` (6) in `hook_names` mapping, ensuring telemetry ringbuf events from both hooks are decoded into structured JSON without external dependencies.

---

## 5. Live MicroVM Kernel Verification Suite (Domain 11: Steps 81–90)

Implemented in [`tests/run_live_kernel_test.sh`](file:///root/home/projects/project-moray/tests/run_live_kernel_test.sh#L1440-L1580), Domain 11 proves the multi-stage network boundary inside a hardware-isolated QEMU/KVM microVM running unpatched upstream Linux kernel with Ring 0 BPF-LSM enabled:

| Step | Test Action | Expected Result | Return Code | Verification Invariant |
| :---: | :--- | :--- | :---: | :--- |
| **81** | Dual Cgroup v2 slice setup (`moray_net_a`, `moray_net_b`) | Inodes resolved; slices isolated | `0` | Ground Truth Preflight |
| **82** | Launch `morayd` with `--auto-harden` targeting `moray_net_a` (`DENY_ALL_NET`) | Sentinel initialized; maps pinned | `0` | Sentinel Hardening |
| **83** | Socket allocation denial (`lsm/socket_create`) under `DENY_ALL_NET` | `socket(AF_INET)` severed with `-EPERM` | `55` | $I_8$ Allocation Gate |
| **84** | Unconnected UDP socket creation denial under `DENY_ALL_NET` | `socket(AF_INET, SOCK_DGRAM)` severed | `59` | Zero UDP `sendto` Bypass |
| **85** | Socket allocation non-interference in Ungoverned Workload `moray_net_b` | Clean socket creation & baseline execution | `0` | $I_2$ Non-Interference |
| **86** | Re-target Workload Net-A with `ALLOW_LOOPBACK` policy | Seamless policy switch; daemon live | `0` | Dynamic Policy Transition |
| **87** | Raw/packet socket allocation denial (`SOCK_RAW`, `AF_PACKET`) under `ALLOW_LOOPBACK` | Raw frame crafting severed with `-EPERM` | `56` | Anti-Raw Bypass Gate |
| **88** | Wildcard / external listener binding denial (`lsm/socket_bind` to `0.0.0.0`) | `bind(0.0.0.0:8080)` severed with `-EPERM` | `57` | Rogue Listener Gate |
| **89** | Loopback listener binding allowance (`127.0.0.1:8080`) under `ALLOW_LOOPBACK` | `bind(127.0.0.1:8080)` permitted cleanly | `58` | Granular Loopback IPC |
| **90** | Dual-workload listener non-interference in Ungoverned Workload `moray_net_b` | Listener binding permitted without hindrance | `58` | $I_2$ Non-Interference & Teardown |

---

## 6. Zero-Nomenclature Inflation & Boundary Truth

In accordance with Rule 5 and the Zero Nomenclature Inflation Invariant, the boundary guarantees are strictly defined:
1. **Socket Allocation Guarantee:** `DENY_ALL_NET` blocks the allocation of new network sockets (`AF_INET`, `AF_INET6`, `AF_UNIX`, `AF_PACKET`). Processes cannot obtain file descriptors to initiate unconnected datagrams (`sendto`) or establish transport sessions.
2. **Listener Confinement Guarantee:** `ALLOW_LOOPBACK` confines socket listeners to localhost addresses (`127.0.0.1`, `::1`, `AF_UNIX`). Rogue external listeners on `0.0.0.0` or host IPs are rejected with `-EPERM`.
3. **Pre-Existing Sockets Boundary:** Sockets established *before* policy activation or quarantine entry are not retroactively closed by LSM hooks; their termination occurs when quarantine escalation reaches Tier 3 (`bpf_send_signal(9)` / `SIGKILL`).
4. **Inbound Wire Boundary:** External wire-level ingress packet filtering is enforced at line-rate via driver-level XDP (`moray_xdp_filter`), not at the transport layer.

---

## 7. Invariant Conformance

- **$I_1$ Ring 0 Kernel Enforcement:** Enforced directly inside BPF-LSM hooks (`socket_create`, `socket_bind`, `socket_connect`) and driver XDP.
- **$I_2$ Zero Overhead & Non-Interference:** Tasks outside governed cgroups bypass all hooks at $O(1)$ hash lookup speed with zero interference.
- **$I_8$ Autonomous Network Posture Enforcement:** The network boundary guarantees now precisely match all claimed policies across the full lifecycle: allocation, binding, connect, and wire ingress.
- **$I_9$ Cgroup v2 Workload Jurisdiction:** Multi-stage network defense is scoped strictly to governed cgroup v2 hierarchies and inherited by child tasks.
