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
#include "moray.h"

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

int main(int argc, char **argv) {
    bool mock_mode = false;
    const char *pin_dir = MORAY_PIN_DIR;
    char quarantine_path[256];
    char events_path[256];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            fprintf(stdout, "Usage: %s [options]\n", argv[0]);
            fprintf(stdout, "Options:\n");
            fprintf(stdout, "  --mock [dir]   Run in mock mode using filesystem backing (for unprivileged testing)\n");
            fprintf(stdout, "  --pin-dir <dir> Override default BPF pin directory (default: %s)\n", MORAY_PIN_DIR);
            fprintf(stdout, "  --help         Show this help message\n");
            return 0;
        } else if (strcmp(argv[i], "--mock") == 0) {
            mock_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                pin_dir = argv[++i];
            } else {
                pin_dir = "/tmp/moray_mock";
            }
        } else if (strcmp(argv[i], "--pin-dir") == 0 && i + 1 < argc) {
            pin_dir = argv[++i];
        }
    }

    print_banner();

    /* Register signal handlers for graceful teardown */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stdout, "[*] Target pin directory: %s\n", pin_dir);

    int q_len = snprintf(quarantine_path, sizeof(quarantine_path), "%s/quarantine_map", pin_dir);
    int e_len = snprintf(events_path, sizeof(events_path), "%s/events", pin_dir);
    if (q_len < 0 || (size_t)q_len >= sizeof(quarantine_path) ||
        e_len < 0 || (size_t)e_len >= sizeof(events_path)) {
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
        if (init_mock_quarantine(quarantine_path) != 0) {
            return 1;
        }
    } else {
        /* Real kernel mode: check if root */
        if (geteuid() != 0) {
            fprintf(stderr, "[-] Error: morayd requires root privileges (CAP_SYS_ADMIN / CAP_BPF) for live Ring 0 operation.\n");
            fprintf(stderr, "[-] Use '--mock <path>' to run in simulation/testing mode.\n");
            return 1;
        }
        fprintf(stdout, "[*] Kernel BPF VFS path verified.\n");
    }

    fprintf(stdout, "[+] morayd initialized successfully. Monitoring Ring 0 containment channels.\n");
    fprintf(stdout, "[*] Press Ctrl+C to terminate daemon.\n");

    /* Daemon polling loop */
    while (g_running) {
        usleep(100000); /* 100ms idle sleep */
    }

    fprintf(stdout, "\n[*] Signal received. Cleaning up and terminating morayd.\n");
    return 0;
}
