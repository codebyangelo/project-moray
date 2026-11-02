# Project Moray: Kernel Compatibility & Hardware Matrix

**Canonical Specification:** [`/root/home/projects/project-moray/docs/COMPATIBILITY.md`](file:///root/home/projects/project-moray/docs/COMPATIBILITY.md)  
**Author:** Angelo Hershall Heith Ayton (`codebyangelo`)

---

## 1. Supported Linux Kernel Releases

Project Moray relies on the modern Linux BPF-LSM infrastructure.

| Kernel Version | BPF-LSM Support | XDP Driver Support | Operational Status |
| :--- | :--- | :--- | :--- |
| **< 5.7** | Unsupported | Basic (`XDP_DROP` only) | **Unsupported** (BPF-LSM infrastructure missing from mainline kernel) |
| **5.7 – 5.10** | Experimental | Standard | **Tier 2 (Supported with manual boot params)** |
| **5.15 LTS** | Fully Supported | Standard | **Tier 1 (Production Baseline LTS)** |
| **6.1 – 6.6 LTS** | Fully Supported | Advanced Multi-Buffer | **Tier 1 (Recommended Production LTS)** |
| **6.7+** | Fully Supported | Full BPF LSM Multi-Prog | **Tier 1 (Production)** |

---

## 2. Mandatory Kernel Configuration Flags (`.config`)

To load and attach Moray's in-kernel eBPF programs, the host Linux kernel must be compiled with the following flags enabled:

```ini
# Core eBPF Infrastructure
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y

# Linux Security Module (LSM) BPF Instrumentation
CONFIG_BPF_LSM=y
CONFIG_SECURITY=y
CONFIG_SECURITY_NETWORK=y

# BPF Type Format (BTF) Metadata
CONFIG_DEBUG_INFO_BTF=y

# Ring Buffer & Telemetry Channel
CONFIG_BPF_EVENTS=y

# eXpress Data Path (XDP) Wire Filtering
CONFIG_NET_CLS_ACT=y
CONFIG_XDP_SOCKETS=y
```

### Kernel Boot Parameter Configuration
Even when compiled with `CONFIG_BPF_LSM=y`, modern Linux distributions require BPF to be listed in the active LSM ordering in `/etc/default/grub`:
```text
GRUB_CMDLINE_LINUX="... lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
```
Verification on a live running host:
```bash
cat /sys/kernel/security/lsm
# Must output: ...bpf
```

---

## 3. Supported CPU Architectures

| Architecture | Target ABI | Status | Clang Compilation Target |
| :--- | :--- | :--- | :--- |
| **x86_64 / AMD64** | System V AMD64 | **Tier 1 (Validated in CI)** | `-target bpf` |
| **aarch64 / ARM64** | ARM 64-bit EABI | **Tier 1 (Validated in Local Harness)** | `-target bpf` |
| **armv7l / 32-bit** | ARM EABI | Unsupported | Untested |
| **riscv64** | RISC-V 64-bit | Experimental | Community testing |

---

## 4. Execution Mode Matrix

| Mode | Kernel LSM Required | Root Required | Intended Environment |
| :--- | :--- | :--- | :--- |
| **Live Kernel Ring 0** | **YES** (`CONFIG_BPF_LSM=y`) | **YES** (`CAP_SYS_ADMIN` / `CAP_BPF`) | Production hosts, bare-metal agents, hardened KVM hypervisors |
| **Mock Mode (`--mock`)** | **NO** | **NO** (Unprivileged user) | CI runners, unprivileged Docker containers, developer test harnesses |
