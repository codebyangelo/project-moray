/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Project Moray: Victim Test Worker
 * Used in live kernel verification to assert hardware-level interception of execve and bpf().
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>

#ifndef __NR_bpf
#if defined(__x86_64__)
#define __NR_bpf 321
#elif defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__arm__)
#define __NR_bpf 386
#endif
#endif

static volatile sig_atomic_t g_proceed = 0;

static void handle_usr1(int sig) {
    (void)sig;
    g_proceed = 1;
}

static void wait_for_strike(void) {
    signal(SIGUSR1, handle_usr1);
    char ready_path[64];
    snprintf(ready_path, sizeof(ready_path), "/tmp/victim_%d.ready", getpid());
    FILE *f = fopen(ready_path, "w");
    if (f) {
        fputs("ready\n", f);
        fclose(f);
    }
    while (!g_proceed) {
        pause();
    }
    unlink(ready_path);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <--baseline-exec|--wait-and-exec|--wait-and-bpf>\n", argv[0]);
        return 1;
    }

    /* Unbuffered stdout */
    setvbuf(stdout, NULL, _IONBF, 0);

    if (strcmp(argv[1], "--baseline-exec") == 0) {
        char *const args[] = {"/bin/true", NULL};
        char *const envp[] = {NULL};
        const char *bin = (access("/bin/true", X_OK) == 0) ? "/bin/true" : "/usr/bin/true";
        execve(bin, args, envp);
        return 1; /* Should never reach here if execve succeeds */
    } else if (strcmp(argv[1], "--wait-and-exec") == 0) {
        /* Wait for containment strike to be registered in kernel map */
        wait_for_strike();
        char *const args[] = {"/bin/true", NULL};
        char *const envp[] = {NULL};
        const char *bin = (access("/bin/true", X_OK) == 0) ? "/bin/true" : "/usr/bin/true";
        execve(bin, args, envp);

        int err = errno;
        fprintf(stdout, "[VICTIM] execve failed with errno=%d (%s)\n", err, strerror(err));
        if (err == EPERM || err == EACCES) {
            return 42; /* Success: Kernel blocked execve */
        }
        return 1;
    } else if (strcmp(argv[1], "--wait-and-bpf") == 0) {
        wait_for_strike();
        long ret = syscall(__NR_bpf, 0, NULL, 0);
        int err = errno;
        fprintf(stdout, "[VICTIM] sys_bpf returned %ld, errno=%d (%s)\n", ret, err, strerror(err));
        if (err == EPERM || err == EACCES) {
            return 43; /* Success: Kernel blocked bpf */
        }
        return 1;
    }

    return 2;
}
