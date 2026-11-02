# Project Moray: Formal Invariant Specification

This document codifies the core architectural invariants of Project Moray (`morayd`). Every code change, patch, and test harness must satisfy these invariants unconditionally.

---

## 🛡️ Core Architectural Invariants

### Invariant 1: Fail-Closed Quarantine ($I_1$)
* **Definition**: Any process PID, TGID, or cgroup registered in `moray_quarantine_map` with a non-zero quarantine action flag MUST be denied execution of restricted operations (`bprm_check_security`, `socket_connect`) with `-EPERM` (`-1`).
* **Boundary Condition**: If the user-space bridge (`lobster_hook.py`) encounters an unhandled exception, missing kernel map, or corrupted descriptor, it MUST fail closed (exit code `-4` or strict error return). It must never fail open.
* **Enforcement Point**: `moray_kern.bpf.c` (LSM entry points) and `bridge/lobster_hook.py`.
* **Verification**: `tests/test_lobster_hook.py` and BPF mock strike tests.

### Invariant 2: Zero-Latency Benign Baseline ($I_2$)
* **Definition**: Benign, unflagged processes must not incur locking overhead, dynamic heap allocations, or measurable context-switch degradation.
* **Mechanism**: In-kernel hash table lookup (`bpf_map_lookup_elem`) returns `NULL` in $O(1)$ constant time; the hook returns `0` immediately without taking spinlocks or emitting diagnostic ringbuf allocations for benign reads.
* **Enforcement Point**: `moray_kern.bpf.c` fast-path return.
* **Verification**: Microbenchmarking latency comparing baseline syscall execution vs unflagged hooked execution.

### Invariant 3: Anti-Tamper Camouflage ($I_3$)
* **Definition**: The loaded eBPF programs, maps, and pinned VFS paths (`/sys/fs/bpf/moray/`) cannot be enumerated, detached, or overwritten by unprivileged or quarantined user-space processes.
* **Mechanism**: `moray_kern.bpf.c` attaches to `lsm/bpf`. If the calling PID is quarantined or lacks `CAP_SYS_ADMIN`, attempts to issue `BPF_PROG_DETACH` or unload pinned descriptors are blocked with `-EPERM`.
* **Enforcement Point**: `lsm/bpf` hook and `BPF_F_RDONLY_PROG` flags.
* **Verification**: Adversarial unpin/detach test harness.

### Invariant 4: Bounded Ring 0 Memory & Static Allocation ($I_4$)
* **Definition**: Kernel Ring 0 memory footprint must remain strictly bounded and deterministic. Zero dynamic memory allocation can occur inside the eBPF VM.
* **Mechanism**:
  - `moray_quarantine_map` is clamped to a fixed static capacity (`max_entries = 1024`).
  - Ring buffer telemetry uses fixed-size structs (`struct moray_event`) bounded to 128 bytes.
  - User-space daemon `morayd` memory footprint must remain under 15 MB of RSS.
* **Enforcement Point**: Compile-time BPF map sizing in `moray.h` and verifier boundaries.
* **Verification**: Verifier output inspection and static struct size validation in `tests/test_struct_layout.c`.

### Invariant 5: Binary Type & Alignment Contract ($I_5$)
* **Definition**: Shared memory schemas between kernel C bytecode, user-space daemon C code, and Python bridge scripts must be byte-for-byte identical across architectures (explicit padding, fixed integer widths, endianness).
* **Mechanism**:
  - All integers use standard fixed-width types (`__u32`, `__u64`, `__u8`, `__s32`).
  - Structs are aligned to 8-byte boundaries without compiler-dependent tail padding.
  - Python bridge defines matching `ctypes.Structure` specifications with explicit `_fields_`.
* **Enforcement Point**: `src/moray.h` compile-time assertions and `bridge/lobster_hook.py`.
* **Verification**: `tests/test_struct_layout.c` checking `sizeof()` and offset assertions.

### Invariant 6: Provenance & Chronology Invariant ($I_6$)
* **Definition**: All historical claims, release versions, author attributions, and benchmarks must be grounded in immutable Git metadata or empirical system traces.
* **Mechanism**: No synthetic claims or inferences from filesystem `mtime`.
* **Enforcement Point**: Workspace Rules & Operational Guardrails: Rule 3.
* **Verification**: Verifiable Git commits via `git log --format='%ad %h'`.

### Invariant 7: Containment Self-Defense & Anti-Tamper Protection ($I_7$)
* **Definition**: Quarantined processes cannot invoke `bpf()` syscall or tamper with loaded Moray probes or maps.
* **Mechanism**: `moray_bpf_strike` intercepts `lsm/bpf` and returns `-EPERM` for any quarantined PID.
* **Enforcement Point**: `moray_kern.bpf.c` and `bridge/lobster_hook.py` (`report_tamper`).
* **Verification**: `tests/test_anti_tamper.py` and `tests/run_live_kernel_test.sh` (Step 7).

### Invariant 8: Granular Egress & Semantic Network Isolation ($I_8$)
* **Definition**: When `MORAY_ACT_BLOCK_SOCKET` is active, outbound network socket creation is denied with `-EPERM`. If `MORAY_ACT_ALLOW_LOOPBACK` (`0x10`) is explicitly granted, local IPC (`AF_UNIX`) and localhost destinations (`127.0.0.0/8`, `::1`) are permitted while strictly severing external WAN egress attempts.
* **Mechanism**: `moray_socket_strike` inspects destination sockaddr via `bpf_probe_read_kernel`, discriminating loopback and UNIX families from external WAN addresses.
* **Enforcement Point**: `moray_kern.bpf.c` (`SEC("lsm/socket_connect")`) and `bridge/lobster_hook.py`.
* **Verification**: `tests/test_network_policy.py` and `tests/run_live_kernel_test.sh` (Steps 10, 11, 12).

---

## 📊 Invariant Verification Matrix

| Invariant | Target Subsystem | Automated Verification Test | Pass Criteria |
| :--- | :--- | :--- | :--- |
| **$I_1$** | `moray_kern.bpf.c`, `lobster_hook.py` | `tests/test_lobster_hook.py` | Syscall blocked (`-EPERM`), bridge returns `-4` on fault. |
| **$I_2$** | `moray_kern.bpf.c` | Microbenchmark harness | Delta syscall overhead < 1% for benign PID. |
| **$I_3$** | `lsm/bpf` | `tests/test_anti_tamper.py` | EPERM returned on unauthorized BPF map manipulation. |
| **$I_4$** | `src/moray.h` | `tests/test_struct_layout.c` | Static assertion `sizeof(struct moray_event) == 128`. |
| **$I_7$** | `lsm/bpf` | `tests/test_anti_tamper.py` | Quarantined PID calling `sys_bpf` receives `-EPERM`. |
| **$I_8$** | `lsm/socket_connect` | `tests/test_network_policy.py` | WAN blocked with `-EPERM`; loopback allowed when flag asserted. |
| **$I_5$** | `src/moray.h`, `lobster_hook.py` | `tests/test_struct_layout.c` | Struct offsets match Python `ctypes.sizeof()`. |
| **$I_6$** | Repository Git history | Differential CI check | Zero synthetic commit hashes or ungrounded claims. |
| **$I_7$** | `bridge/lobster_hook.py` | `tests/test_adversarial.py` | 64KB heap ceiling clamp, `fcntl.flock` serialization, and strict PID validation. |
| **$I_8$** | `src/moray_kern.bpf.c` | `tests/test_adversarial.py` | SMP atomic counters (`__sync_fetch_and_add`) and XDP EtherType wire validation. |
