/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Project Moray: In-Kernel Containment Daemon (morayd)
 * Manages BPF program lifecycle, pins quarantine maps, and polls telemetry.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "moray.h"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

#ifndef __NR_bpf
#if defined(__x86_64__)
#define __NR_bpf 321
#elif defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__arm__)
#define __NR_bpf 386
#endif
#endif

/* Volatile flag for clean signal termination */
static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* Print banner */
static void print_banner(void) {
    fprintf(stdout, "========================================================\n");
    fprintf(stdout, "  PROJECT MORAY: Ring 0 OS-Level Containment Daemon     \n");
    fprintf(stdout, "  Subsystem: BPF-LSM / XDP Pharyngeal Strike Controller \n");
    fprintf(stdout, "========================================================\n");
}

/*
 * Mandatory Kernel Preflight Checks (Phase 2 Contract)
 * Verifies privilege, active BPF-LSM, and /sys/fs/bpf mounting.
 */
static int run_kernel_preflight_checks(void) {
    fprintf(stdout, "[*] Running Ring 0 Kernel Preflight Checks...\n");

    /* 1. Privilege Check */
    if (geteuid() != 0) {
        fprintf(stderr, "[-] FATAL (PREFLIGHT_PRIVILEGE_INSUFFICIENT): morayd requires CAP_SYS_ADMIN / CAP_BPF (euid 0).\n");
        return -1;
    }

    /* 2. Active BPF-LSM Check */
    int lsm_fd = open("/sys/kernel/security/lsm", O_RDONLY);
    if (lsm_fd < 0) {
        fprintf(stderr, "[-] FATAL (PREFLIGHT_LSM_NOT_ACTIVE): Cannot access /sys/kernel/security/lsm: %s\n", strerror(errno));
        fprintf(stderr, "[-] Verify CONFIG_SECURITY and securityfs are mounted.\n");
        return -1;
    }

    char lsm_buf[256] = {0};
    ssize_t bytes_read = read(lsm_fd, lsm_buf, sizeof(lsm_buf) - 1);
    close(lsm_fd);

    if (bytes_read <= 0 || strstr(lsm_buf, "bpf") == NULL) {
        fprintf(stderr, "[-] FATAL (PREFLIGHT_LSM_NOT_ACTIVE): 'bpf' is not active in /sys/kernel/security/lsm (active: '%s').\n", lsm_buf);
        fprintf(stderr, "[-] Host kernel must have CONFIG_BPF_LSM=y and boot with 'lsm=...,bpf'.\n");
        return -1;
    }

    /* 3. BPF Filesystem Mount Check */
    struct statfs fs;
    if (statfs("/sys/fs/bpf", &fs) != 0 || (unsigned long)fs.f_type != (unsigned long)BPF_FS_MAGIC) {
        fprintf(stderr, "[-] FATAL (PREFLIGHT_BPFFS_NOT_MOUNTED): /sys/fs/bpf is not mounted as a bpf filesystem.\n");
        fprintf(stderr, "[-] Run: mount -t bpf bpf /sys/fs/bpf\n");
        return -1;
    }

    fprintf(stdout, "[+] PREFLIGHT PASSED: Root privilege confirmed, BPF-LSM active in kernel, /sys/fs/bpf verified.\n");
    return 0;
}

/* Ensure directory exists */
static int ensure_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }
        return -1;
    }
    if (mkdir(dir, 0755) == 0) {
        return 0;
    }
    return (errno == EEXIST) ? 0 : -1;
}

/*
 * Create and initialize the quarantine map in mock / file mode if kernel BPF is unavailable
 */
static int init_mock_quarantine(const char *path) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "[-] Failed to open mock map file '%s': %s\n", path, strerror(errno));
        return -1;
    }

    /* Pre-allocate empty map table space for MORAY_MAX_ENTRIES */
    size_t table_size = MORAY_MAX_ENTRIES * (sizeof(__u32) + sizeof(struct moray_quarantine_entry));
    if (ftruncate(fd, (off_t)table_size) != 0) {
        fprintf(stderr, "[-] Failed to preallocate mock table: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    fprintf(stdout, "[+] Mock quarantine map initialized at: %s (%zu bytes)\n", path, table_size);
    close(fd);
    return 0;
}

/*
 * Create and initialize the mock XDP drop map in mock mode
 */
static int init_mock_xdp(const char *path) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "[-] Failed to open mock xdp file '%s': %s\n", path, strerror(errno));
        return -1;
    }

    /* Pre-allocate empty map table space for MORAY_MAX_ENTRIES (key: __u32, value: __u8) */
    size_t table_size = MORAY_MAX_ENTRIES * (sizeof(__u32) + sizeof(__u8));
    if (ftruncate(fd, (off_t)table_size) != 0) {
        fprintf(stderr, "[-] Failed to preallocate mock xdp table: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    fprintf(stdout, "[+] Mock xdp_drop_map initialized at: %s (%zu bytes)\n", path, table_size);
    close(fd);
    return 0;
}

/* Live BPF Runtime Context */
struct moray_bpf_context {
    struct bpf_object *obj;
    struct bpf_link *link_bprm;
    struct bpf_link *link_socket;
    struct bpf_link *link_bpf;
    struct bpf_link *link_xdp;
    struct bpf_map *map_quarantine;
    struct bpf_map *map_events;
    struct bpf_map *map_xdp_drop;
    char iface[IF_NAMESIZE];
    int xdp_ifindex;
};

static int load_and_attach_bpf(const char *bpf_obj_path, const char *pin_dir, struct moray_bpf_context *ctx) {
    char q_pin[256];
    char e_pin[256];
    char x_pin[256];
    snprintf(q_pin, sizeof(q_pin), "%s/quarantine_map", pin_dir);
    snprintf(e_pin, sizeof(e_pin), "%s/events", pin_dir);
    snprintf(x_pin, sizeof(x_pin), "%s/xdp_drop_map", pin_dir);

    fprintf(stdout, "[*] Loading Ring 0 BPF object from: %s\n", bpf_obj_path);
    ctx->obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!ctx->obj) {
        fprintf(stderr, "[-] Failed to open BPF object '%s': %s\n", bpf_obj_path, strerror(errno));
        return -1;
    }

    int err = bpf_object__load(ctx->obj);
    if (err) {
        fprintf(stderr, "[-] In-kernel BPF verifier rejected object '%s': %s (code %d)\n", bpf_obj_path, strerror(-err), err);
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
        return -1;
    }
    fprintf(stdout, "[+] In-kernel BPF verifier passed cleanly. Bytecode loaded into Ring 0.\n");

    /* Attach LSM hooks */
    struct bpf_program *prog_bprm = bpf_object__find_program_by_name(ctx->obj, "moray_bprm_strike");
    if (prog_bprm) {
        ctx->link_bprm = bpf_program__attach_lsm(prog_bprm);
        if (!ctx->link_bprm) {
            fprintf(stderr, "[-] Warning: Failed to attach moray_bprm_strike: %s\n", strerror(errno));
        } else {
            fprintf(stdout, "[+] Attached LSM hook: bprm_check_security (moray_bprm_strike)\n");
        }
    }

    struct bpf_program *prog_socket = bpf_object__find_program_by_name(ctx->obj, "moray_socket_strike");
    if (prog_socket) {
        ctx->link_socket = bpf_program__attach_lsm(prog_socket);
        if (!ctx->link_socket) {
            fprintf(stderr, "[-] Warning: Failed to attach moray_socket_strike: %s\n", strerror(errno));
        } else {
            fprintf(stdout, "[+] Attached LSM hook: socket_connect (moray_socket_strike)\n");
        }
    }

    struct bpf_program *prog_bpf = bpf_object__find_program_by_name(ctx->obj, "moray_bpf_strike");
    if (prog_bpf) {
        ctx->link_bpf = bpf_program__attach_lsm(prog_bpf);
        if (!ctx->link_bpf) {
            fprintf(stderr, "[-] Warning: Failed to attach moray_bpf_strike: %s\n", strerror(errno));
        } else {
            fprintf(stdout, "[+] Attached LSM hook: bpf (moray_bpf_strike)\n");
        }
    }

    /* Attach XDP filter if interface was configured */
    if (ctx->xdp_ifindex > 0) {
        struct bpf_program *prog_xdp = bpf_object__find_program_by_name(ctx->obj, "moray_xdp_filter");
        if (prog_xdp) {
            ctx->link_xdp = bpf_program__attach_xdp(prog_xdp, ctx->xdp_ifindex);
            if (!ctx->link_xdp) {
                fprintf(stderr, "[-] Warning: Failed to attach moray_xdp_filter to interface '%s' (ifindex %d): %s\n",
                        ctx->iface, ctx->xdp_ifindex, strerror(errno));
            } else {
                fprintf(stdout, "[+] Attached XDP filter to interface '%s' (ifindex %d)\n", ctx->iface, ctx->xdp_ifindex);
            }
        }
    }

    /* Pin quarantine map */
    ctx->map_quarantine = bpf_object__find_map_by_name(ctx->obj, "moray_quarantine_map");
    if (ctx->map_quarantine) {
        unlink(q_pin);
        err = bpf_map__pin(ctx->map_quarantine, q_pin);
        if (err) {
            fprintf(stderr, "[-] Failed to pin quarantine map to '%s': %s\n", q_pin, strerror(-err));
            return -1;
        }
        fprintf(stdout, "[+] Pinned quarantine map to: %s\n", q_pin);
    }

    /* Pin events ringbuf */
    ctx->map_events = bpf_object__find_map_by_name(ctx->obj, "moray_events");
    if (ctx->map_events) {
        unlink(e_pin);
        err = bpf_map__pin(ctx->map_events, e_pin);
        if (err) {
            fprintf(stderr, "[-] Warning: Failed to pin events map to '%s': %s\n", e_pin, strerror(-err));
        } else {
            fprintf(stdout, "[+] Pinned events ringbuf to: %s\n", e_pin);
        }
    }

    /* Pin xdp drop map */
    ctx->map_xdp_drop = bpf_object__find_map_by_name(ctx->obj, "moray_xdp_drop_map");
    if (ctx->map_xdp_drop) {
        unlink(x_pin);
        err = bpf_map__pin(ctx->map_xdp_drop, x_pin);
        if (err) {
            fprintf(stderr, "[-] Warning: Failed to pin xdp_drop_map to '%s': %s\n", x_pin, strerror(-err));
        } else {
            fprintf(stdout, "[+] Pinned xdp_drop_map to: %s\n", x_pin);
        }
    }

    return 0;
}

static void cleanup_bpf(struct moray_bpf_context *ctx, const char *pin_dir) {
    if (!ctx) return;
    if (ctx->link_bprm) bpf_link__destroy(ctx->link_bprm);
    if (ctx->link_socket) bpf_link__destroy(ctx->link_socket);
    if (ctx->link_bpf) bpf_link__destroy(ctx->link_bpf);
    if (ctx->link_xdp) {
        bpf_link__destroy(ctx->link_xdp);
        fprintf(stdout, "[+] Detached XDP filter from interface '%s'\n", ctx->iface);
    }
    if (ctx->obj) bpf_object__close(ctx->obj);

    if (pin_dir) {
        char q_pin[256];
        char e_pin[256];
        char x_pin[256];
        snprintf(q_pin, sizeof(q_pin), "%s/quarantine_map", pin_dir);
        snprintf(e_pin, sizeof(e_pin), "%s/events", pin_dir);
        snprintf(x_pin, sizeof(x_pin), "%s/xdp_drop_map", pin_dir);
        unlink(q_pin);
        unlink(e_pin);
        unlink(x_pin);
    }
}

int main(int argc, char **argv) {
    /* Line-buffered stdout and unbuffered stderr for real-time logging */
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    bool mock_mode = false;
    const char *pin_dir = MORAY_PIN_DIR;
    const char *bpf_obj_path = "build/moray_kern.bpf.o";
    char quarantine_path[256];
    char events_path[256];
    char xdp_path[256];
    struct moray_bpf_context bpf_ctx;
    memset(&bpf_ctx, 0, sizeof(bpf_ctx));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            fprintf(stdout, "Usage: %s [options]\n", argv[0]);
            fprintf(stdout, "Options:\n");
            fprintf(stdout, "  --mock [dir]     Run in mock mode using filesystem backing (for unprivileged testing)\n");
            fprintf(stdout, "  --preflight      Execute live kernel preflight checks and exit\n");
            fprintf(stdout, "  --pin-dir <dir>  Override default BPF pin directory (default: %s)\n", MORAY_PIN_DIR);
            fprintf(stdout, "  --bpf-obj <path> Path to compiled BPF object (default: build/moray_kern.bpf.o)\n");
            fprintf(stdout, "  --iface <dev>    Attach XDP wire filter to network interface (e.g. eth0, lo)\n");
            fprintf(stdout, "  --help           Show this help message\n");
            return 0;
        } else if (strcmp(argv[i], "--preflight") == 0) {
            print_banner();
            return (run_kernel_preflight_checks() == 0) ? 0 : 1;
        } else if (strcmp(argv[i], "--mock") == 0) {
            mock_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                pin_dir = argv[++i];
            } else {
                pin_dir = "/tmp/moray_mock";
            }
        } else if (strcmp(argv[i], "--pin-dir") == 0 && i + 1 < argc) {
            pin_dir = argv[++i];
        } else if (strcmp(argv[i], "--bpf-obj") == 0 && i + 1 < argc) {
            bpf_obj_path = argv[++i];
        } else if ((strcmp(argv[i], "--iface") == 0 || strcmp(argv[i], "-i") == 0) && i + 1 < argc) {
            const char *dev = argv[++i];
            strncpy(bpf_ctx.iface, dev, sizeof(bpf_ctx.iface) - 1);
            bpf_ctx.iface[sizeof(bpf_ctx.iface) - 1] = '\0';
        }
    }

    print_banner();

    /* Resolve network interface index for XDP if configured */
    if (bpf_ctx.iface[0] != '\0') {
        bpf_ctx.xdp_ifindex = if_nametoindex(bpf_ctx.iface);
        if (bpf_ctx.xdp_ifindex == 0 && !mock_mode) {
            fprintf(stderr, "[-] FATAL (INVALID_INTERFACE): Network interface '%s' does not exist: %s\n",
                    bpf_ctx.iface, strerror(errno));
            return 1;
        }
        fprintf(stdout, "[*] Target XDP network interface: %s (ifindex: %d)\n", bpf_ctx.iface, bpf_ctx.xdp_ifindex);
    }

    /* Register signal handlers for graceful teardown */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGHUP, SIG_IGN);

    fprintf(stdout, "[*] Target pin directory: %s\n", pin_dir);

    int q_len = snprintf(quarantine_path, sizeof(quarantine_path), "%s/quarantine_map", pin_dir);
    int e_len = snprintf(events_path, sizeof(events_path), "%s/events", pin_dir);
    int x_len = snprintf(xdp_path, sizeof(xdp_path), "%s/xdp_drop_map", pin_dir);
    if (q_len < 0 || (size_t)q_len >= sizeof(quarantine_path) ||
        e_len < 0 || (size_t)e_len >= sizeof(events_path) ||
        x_len < 0 || (size_t)x_len >= sizeof(xdp_path)) {
        fprintf(stderr, "[-] Target pin directory path exceeds buffer limit (%zu bytes)\n", sizeof(quarantine_path));
        return 1;
    }

    if (ensure_dir(pin_dir) != 0) {
        fprintf(stderr, "[-] Cannot access or create pin directory '%s': %s\n", pin_dir, strerror(errno));
        if (!mock_mode) {
            fprintf(stderr, "[!] Tip: Run with --mock for unprivileged/test environments.\n");
        }
        return 1;
    }

    if (mock_mode) {
        fprintf(stdout, "[*] Running in mock containment test mode...\n");
        if (init_mock_quarantine(quarantine_path) != 0 || init_mock_xdp(xdp_path) != 0) {
            return 1;
        }
    } else {
        /* Real kernel mode: run strict preflight checks */
        if (run_kernel_preflight_checks() != 0) {
            fprintf(stderr, "[-] Preflight validation failed. morayd cannot enforce Ring 0 containment on this host.\n");
            fprintf(stderr, "[-] Use '--mock <path>' to run in simulation/testing mode.\n");
            return 1;
        }
        fprintf(stdout, "[*] Kernel BPF VFS path verified.\n");

        /* Fallback check for bpf object if not in build/ */
        if (access(bpf_obj_path, R_OK) != 0 && access("/usr/local/share/moray/moray_kern.bpf.o", R_OK) == 0) {
            bpf_obj_path = "/usr/local/share/moray/moray_kern.bpf.o";
        }

        if (load_and_attach_bpf(bpf_obj_path, pin_dir, &bpf_ctx) != 0) {
            fprintf(stderr, "[-] Failed to load and attach Ring 0 BPF program.\n");
            return 1;
        }
    }

    fprintf(stdout, "[+] morayd initialized successfully. Monitoring Ring 0 containment channels.\n");
    fprintf(stdout, "[*] Press Ctrl+C to terminate daemon.\n");

    /* Daemon polling loop */
    while (g_running) {
        usleep(100000); /* 100ms idle sleep */
    }

    fprintf(stdout, "\n[*] Signal received. Cleaning up and terminating morayd.\n");
    if (!mock_mode) {
        cleanup_bpf(&bpf_ctx, pin_dir);
    }
    return 0;
}
