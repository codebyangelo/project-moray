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
Even when compiled with `CONFIG_BPF_LSM=y`, modern Linux distributions require BPF to be explicitly listed in the active LSM ordering. Because the default configuration on most distributions omits `bpf`, operators must arm the kernel boot parameters prior to starting `morayd`.

---

## 3. Arming BPF-LSM Across Linux Distributions

To arm the host so that `morayd --preflight` succeeds, execute the following steps before launching containment:

### Step 1: Verify Host Kernel Compilation Support
Verify that your kernel was compiled with BPF-LSM and BTF support:

```bash
# Check running kernel configuration
if [ -f /proc/config.gz ]; then
    zcat /proc/config.gz | grep -E "CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF"
elif [ -f "/boot/config-$(uname -r)" ]; then
    grep -E "CONFIG_BPF_LSM|CONFIG_DEBUG_INFO_BTF" "/boot/config-$(uname -r)"
else
    echo "[!] Warning: Kernel config not found in /boot or /proc; checking /sys"
fi
```
**Required output:**
```text
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y
```

### Step 2: Inspect Active LSM Stack
Query the current active LSM modules on your live system:

```bash
cat /sys/kernel/security/lsm
```
*Typical default output (Ubuntu/Debian):* `lockdown,capability,landlock,yama,apparmor`  
*Typical default output (Fedora/RHEL):* `lockdown,capability,selinux`

> [!CAUTION]
> **Never set `lsm=bpf` alone.** Overwriting the boot parameter without your distribution's primary security modules will disable AppArmor or SELinux, degrading host security. Always append `,bpf` to your existing active LSM stack.

### Step 3: Distribution Bootloader Configuration

#### A. Ubuntu (20.04 / 22.04 / 24.04 LTS) & Debian (11 / 12)
Ubuntu and Debian utilize standard GRUB2:

1. Query existing LSMs and append `,bpf`:
   ```bash
   CURRENT_LSM=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "lockdown,capability,landlock,yama,apparmor")
   TARGET_LSM="${CURRENT_LSM},bpf"
   echo "[*] Arming LSM parameter: lsm=${TARGET_LSM}"
   ```

2. Edit `/etc/default/grub` and update `GRUB_CMDLINE_LINUX`:
   ```bash
   sudo sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="lsm='"${TARGET_LSM}"' /' /etc/default/grub
   ```

3. Update the GRUB configuration and regenerate `/boot/grub/grub.cfg`:
   ```bash
   sudo update-grub
   ```

#### B. Fedora (36+), RHEL 9, Rocky Linux, AlmaLinux & Amazon Linux 2023
RPM-based distributions provide `grubby` to safely manage boot arguments across EFI and BIOS without editing templates manually:

1. Query existing LSMs and append `,bpf`:
   ```bash
   CURRENT_LSM=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "lockdown,capability,selinux")
   TARGET_LSM="${CURRENT_LSM},bpf"
   ```

2. Arm all installed kernels via `grubby`:
   ```bash
   sudo grubby --update-kernel=ALL --args="lsm=${TARGET_LSM}"
   ```

3. Verify the configured kernel arguments:
   ```bash
   sudo grubby --info=DEFAULT | grep args
   ```

*(Alternative without `grubby`: Edit `/etc/default/grub` and execute `sudo grub2-mkconfig -o /boot/grub2/grub.cfg`)*.

#### C. Arch Linux & Manjaro

* **If using GRUB**:
  1. Edit `/etc/default/grub` and append to `GRUB_CMDLINE_LINUX_DEFAULT`:
     ```text
     GRUB_CMDLINE_LINUX_DEFAULT="... lsm=landlock,lockdown,yama,integrity,bpf"
     ```
  2. Regenerate GRUB config:
     ```bash
     sudo grub-mkconfig -o /boot/grub/grub.cfg
     ```

* **If using `systemd-boot`**:
  1. Edit the active loader entry file in `/boot/loader/entries/*.conf`.
  2. Append `lsm=landlock,lockdown,yama,integrity,bpf` to the `options` line.

### Step 4: Configure Persistent BPF Filesystem (`bpffs`) Mount
Project Moray requires `/sys/fs/bpf` to be mounted as a BPF filesystem.

1. Mount immediately for current session:
   ```bash
   sudo mount -t bpf bpf /sys/fs/bpf
   ```

2. Add persistent mount entry to `/etc/fstab`:
   ```bash
   if ! grep -q "/sys/fs/bpf" /etc/fstab; then
       echo "bpffs /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0" | sudo tee -a /etc/fstab
   fi
   ```
   *(Or enable systemd mount: `sudo systemctl enable --now sys-fs-bpf.mount`)*.

### Step 5: Reboot Host
Apply the new kernel command line parameters:

```bash
sudo reboot
```

### Step 6: Verify Armed State Post-Reboot
Once the host reboots, execute these verification commands:

```bash
# 1. Verify kernel boot arguments
cat /proc/cmdline | grep "bpf"

# 2. Confirm BPF is active in the LSM stack
cat /sys/kernel/security/lsm | grep "bpf"

# 3. Confirm BPF filesystem mount and magic (0xcafe4a11)
stat -f -c %T /sys/fs/bpf
# Must output: bpf_fs

# 4. Run morayd live preflight check
/usr/local/bin/morayd --preflight
```
**Expected Preflight Result:**
```text
========================================================
  PROJECT MORAY: Ring 0 OS-Level Containment Daemon     
  Subsystem: BPF-LSM / XDP Pharyngeal Strike Controller 
========================================================
[*] Running Ring 0 Kernel Preflight Checks...
[+] PREFLIGHT PASSED: Root privilege confirmed, BPF-LSM active in kernel, /sys/fs/bpf verified.
```

---

## 4. Supported CPU Architectures

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
