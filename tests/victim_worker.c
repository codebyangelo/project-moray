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

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <--try-exec|--try-bpf|--loop-exec>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--try-exec") == 0) {
        char *const args[] = {"/bin/true", NULL};
        char *const envp[] = {NULL};
        execve("/bin/true", args, envp);

        /* If execve returned, it failed! */
        int err = errno;
        fprintf(stdout, "[VICTIM] execve returned errno=%d (%s)\n", err, strerror(err));
        if (err == EPERM || err == EACCES) {
            return 42; /* Expected: Ring 0 blocked execve */
        }
        return 1;
    } else if (strcmp(argv[1], "--try-bpf") == 0) {
        long ret = syscall(__NR_bpf, 0, NULL, 0);
        int err = errno;
        fprintf(stdout, "[VICTIM] sys_bpf returned %ld, errno=%d (%s)\n", ret, err, strerror(err));
        if (err == EPERM || err == EACCES) {
            return 43; /* Expected: Ring 0 blocked bpf */
        }
        return 1;
    } else if (strcmp(argv[1], "--loop-exec") == 0) {
        /* Loop calling execve to trigger Tier 3 escalation (SIGKILL) */
        char *const args[] = {"/bin/true", NULL};
        char *const envp[] = {NULL};
        for (int i = 0; i < 10; i++) {
            execve("/bin/true", args, envp);
            usleep(100000);
        }
        return 0;
    }

    return 2;
}
