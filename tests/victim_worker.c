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
#include <sys/wait.h>
#include <fcntl.h>

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

static int join_cgroup_dir(const char *cgroup_dir) {
    char procs_path[512];
    int n = snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_dir);
    if (n < 0 || (size_t)n >= sizeof(procs_path)) {
        fprintf(stderr, "[VICTIM] Cgroup path too long: %s\n", cgroup_dir);
        return -1;
    }
    int fd = open(procs_path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "[VICTIM] Failed to open %s: %s\n", procs_path, strerror(errno));
        return -1;
    }
    char pid_buf[32];
    int len = snprintf(pid_buf, sizeof(pid_buf), "%d\n", getpid());
    ssize_t written = write(fd, pid_buf, (size_t)len);
    int err = errno;
    close(fd);
    if (written < 0) {
        fprintf(stderr, "[VICTIM] Failed to write PID %d to %s: %s\n", getpid(), procs_path, strerror(err));
        return -1;
    }
    fprintf(stdout, "[VICTIM] Successfully moved PID %d into cgroup %s\n", getpid(), cgroup_dir);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <--baseline-exec|--wait-and-exec|--wait-and-bpf|--wait-and-connect-wan|--wait-and-connect-loopback|--wait-and-connect-unix|--wait-and-assert-loopback-blocked|--fork-race|--multi-strike-loop|--burst-syscalls>\n", argv[0]);
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
    } else if (strcmp(argv[1], "--fork-race") == 0) {
        int count = (argc > 2) ? atoi(argv[2]) : 10;
        if (count <= 0) count = 10;
        if (count > 100) count = 100;

        int expect_baseline = 0;
        int do_wait = 0;
        const char *cgroup_dir = NULL;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--assert-baseline") == 0) {
                expect_baseline = 1;
            } else if (strcmp(argv[i], "--wait") == 0) {
                do_wait = 1;
            } else if (strcmp(argv[i], "--cgroup") == 0 && i + 1 < argc) {
                cgroup_dir = argv[++i];
            }
        }

        if (cgroup_dir && join_cgroup_dir(cgroup_dir) != 0) {
            return 1;
        }

        if (do_wait) {
            wait_for_strike();
        }

        pid_t *pids = calloc((size_t)count, sizeof(pid_t));
        if (!pids) {
            perror("calloc");
            return 1;
        }

        const char *bin = (access("/bin/true", X_OK) == 0) ? "/bin/true" : "/usr/bin/true";
        char *const args[] = {(char *)bin, NULL};
        char *const envp[] = {NULL};

        for (int i = 0; i < count; i++) {
            pid_t pid = fork();
            if (pid < 0) {
                perror("fork");
                free(pids);
                return 1;
            }
            if (pid == 0) {
                execve(bin, args, envp);
                int err = errno;
                if (err == EPERM || err == EACCES) {
                    _exit(42); /* Blocked by Ring 0 LSM */
                }
                _exit(1); /* Failed with unexpected errno or execve succeeded without blocking */
            }
            pids[i] = pid;
        }

        int blocked_count = 0;
        int killed_count = 0;
        int success_count = 0;
        for (int i = 0; i < count; i++) {
            int status = 0;
            waitpid(pids[i], &status, 0);
            if (WIFEXITED(status)) {
                if (WEXITSTATUS(status) == 42) {
                    blocked_count++;
                } else if (WEXITSTATUS(status) == 0) {
                    success_count++;
                }
            } else if (WIFSIGNALED(status)) {
                if (WTERMSIG(status) == SIGKILL) {
                    killed_count++;
                }
            }
        }
        free(pids);

        int total_contained = blocked_count + killed_count;
        fprintf(stdout, "[VICTIM-FORK-RACE] %d/%d children contained (-EPERM: %d, SIGKILL: %d), %d succeeded\n",
                total_contained, count, blocked_count, killed_count, success_count);

        if (expect_baseline) {
            return (success_count == count) ? 0 : 1;
        }
        return (total_contained == count) ? 50 : 1;
    } else if (strcmp(argv[1], "--multi-strike-loop") == 0) {
        int count = (argc > 2) ? atoi(argv[2]) : 5;
        if (count <= 0) count = 5;

        int no_wait = (argc > 3 && strcmp(argv[3], "--no-wait") == 0);
        if (!no_wait) {
            wait_for_strike();
        }

        int blocked_ops = 0;
        for (int i = 0; i < count; i++) {
            long ret = syscall(__NR_bpf, 0, NULL, 0);
            int err = errno;
            if (ret < 0 && (err == EPERM || err == EACCES)) {
                blocked_ops++;
            }
            usleep(10000); /* 10ms pacing between strikes */
        }

        fprintf(stdout, "[VICTIM-MULTI-STRIKE] %d/%d operations blocked with -EPERM\n", blocked_ops, count);
        return (blocked_ops == count) ? 51 : 1;
    } else if (strcmp(argv[1], "--burst-syscalls") == 0) {
        int count = (argc > 2) ? atoi(argv[2]) : 50;
        if (count <= 0) count = 50;
        if (count > 200) count = 200;

        int no_wait = 0;
        const char *cgroup_dir = NULL;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--no-wait") == 0) {
                no_wait = 1;
            } else if (strcmp(argv[i], "--cgroup") == 0 && i + 1 < argc) {
                cgroup_dir = argv[++i];
            }
        }

        if (cgroup_dir && join_cgroup_dir(cgroup_dir) != 0) {
            return 1;
        }

        if (!no_wait) {
            wait_for_strike();
        }

        pid_t *pids = calloc((size_t)count, sizeof(pid_t));
        if (!pids) {
            perror("calloc");
            return 1;
        }

        for (int i = 0; i < count; i++) {
            pid_t pid = fork();
            if (pid < 0) {
                perror("fork");
                free(pids);
                return 1;
            }
            if (pid == 0) {
                long ret = syscall(__NR_bpf, 0, NULL, 0);
                int err = errno;
                if (ret < 0 && (err == EPERM || err == EACCES)) {
                    _exit(42);
                }
                _exit(1);
            }
            pids[i] = pid;
        }

        int blocked_count = 0;
        int killed_count = 0;
        for (int i = 0; i < count; i++) {
            int status = 0;
            waitpid(pids[i], &status, 0);
            if (WIFEXITED(status)) {
                if (WEXITSTATUS(status) == 42) {
                    blocked_count++;
                }
            } else if (WIFSIGNALED(status)) {
                if (WTERMSIG(status) == SIGKILL) {
                    killed_count++;
                }
            }
        }
        free(pids);

        int total_contained = blocked_count + killed_count;
        fprintf(stdout, "[VICTIM-BURST] %d/%d burst operations contained (-EPERM: %d, SIGKILL: %d)\n",
                total_contained, count, blocked_count, killed_count);
        return (total_contained == count) ? 52 : 1;
    }

    return 2;
}
