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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

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
        fprintf(stderr, "Usage: %s <--baseline-exec|--wait-and-exec|--wait-and-bpf|--wait-and-connect-wan|--wait-and-connect-loopback|--wait-and-connect-unix|--wait-and-assert-loopback-blocked>\n", argv[0]);
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
    } else if (strcmp(argv[1], "--wait-and-connect-wan") == 0) {
        const char *ip = (argc > 2) ? argv[2] : "1.1.1.1";
        int port = (argc > 3) ? atoi(argv[3]) : 80;
        wait_for_strike();

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            int err = errno;
            fprintf(stdout, "[VICTIM] socket(AF_INET) failed: %d (%s)\n", err, strerror(err));
            return (err == EPERM || err == EACCES) ? 44 : 1;
        }

        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &saddr.sin_addr);

        int ret = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
        int err = errno;
        close(fd);

        fprintf(stdout, "[VICTIM] connect to %s:%d ret=%d, errno=%d (%s)\n", ip, port, ret, err, strerror(err));
        if (ret < 0 && (err == EPERM || err == EACCES)) {
            return 44; /* Success: Kernel blocked WAN connect */
        }
        return 1;
    } else if (strcmp(argv[1], "--wait-and-connect-loopback") == 0) {
        int port = (argc > 2) ? atoi(argv[2]) : 80;
        wait_for_strike();

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            int err = errno;
            fprintf(stdout, "[VICTIM] socket(AF_INET) failed: %d (%s)\n", err, strerror(err));
            return 1;
        }

        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(port);
        saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        int ret = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
        int err = errno;
        close(fd);

        fprintf(stdout, "[VICTIM] loopback connect ret=%d, errno=%d (%s)\n", ret, err, strerror(err));
        if (ret == 0 || (ret < 0 && err != EPERM && err != EACCES)) {
            return 45; /* Success: Loopback connect permitted past LSM */
        }
        return 1;
    } else if (strcmp(argv[1], "--wait-and-connect-unix") == 0) {
        const char *sock_path = (argc > 2) ? argv[2] : "/tmp/moray_test.sock";
        wait_for_strike();

        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            int err = errno;
            fprintf(stdout, "[VICTIM] socket(AF_UNIX) failed: %d (%s)\n", err, strerror(err));
            return 1;
        }

        struct sockaddr_un saddr;
        memset(&saddr, 0, sizeof(saddr));
        saddr.sun_family = AF_UNIX;
        strncpy(saddr.sun_path, sock_path, sizeof(saddr.sun_path) - 1);

        int ret = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
        int err = errno;
        close(fd);

        fprintf(stdout, "[VICTIM] unix socket connect ret=%d, errno=%d (%s)\n", ret, err, strerror(err));
        if (ret == 0 || (ret < 0 && err != EPERM && err != EACCES)) {
            return 46; /* Success: Unix domain socket permitted past LSM */
        }
        return 1;
    } else if (strcmp(argv[1], "--wait-and-assert-loopback-blocked") == 0) {
        int port = (argc > 2) ? atoi(argv[2]) : 80;
        wait_for_strike();

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            int err = errno;
            fprintf(stdout, "[VICTIM] socket(AF_INET) failed: %d (%s)\n", err, strerror(err));
            return (err == EPERM || err == EACCES) ? 48 : 1;
        }

        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(port);
        saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        int ret = connect(fd, (struct sockaddr *)&saddr, sizeof(saddr));
        int err = errno;
        close(fd);

        fprintf(stdout, "[VICTIM] loopback-blocked connect ret=%d, errno=%d (%s)\n", ret, err, strerror(err));
        if (ret < 0 && (err == EPERM || err == EACCES)) {
            return 48; /* Success: Loopback was strictly blocked with -EPERM */
        }
        return 1;
    }

    return 2;
}
