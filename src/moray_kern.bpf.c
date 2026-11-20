// SPDX-License-Identifier: GPL-2.0
/*
 * Project Moray: In-Kernel Ring 0 Containment Engine
 * LSM and XDP hooks enforcing process, socket, and network quarantine.
 */

#include "moray_bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* Pinned Quarantine Map shared with Project Lobster
 * Key: TGID / PID (__u32)
 * Value: struct moray_quarantine_entry (24 bytes)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MORAY_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct moray_quarantine_entry);
} moray_quarantine_map SEC(".maps");

/* Ring Buffer Telemetry Channel
 * Size: 256 KB bounded Ring 0 buffer
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} moray_events SEC(".maps");

/* XDP Network Quarantine Map
 * Key: IPv4 address (__u32 network byte order)
 * Value: Action flag (__u8)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MORAY_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u8);
} moray_xdp_drop_map SEC(".maps");

/* Cgroup v2 Quarantine Map shared with Project Lobster
 * Key: Cgroup ID (__u64)
 * Value: struct moray_quarantine_entry (24 bytes)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MORAY_MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct moray_quarantine_entry);
} moray_cgroup_map SEC(".maps");

/* Autonomous Boundary Map seeded by Project Octopus
 * Key: Executable Name (comm, 16 bytes)
 * Value: struct moray_boundary_entry (16 bytes)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MORAY_MAX_ENTRIES);
    __type(key, char[MORAY_COMM_LEN]);
    __type(value, struct moray_boundary_entry);
} moray_boundary_map SEC(".maps");

/* Governed Workload Map (Milestone 2 Workload Scoping)
 * Key: Cgroup ID (__u64)
 * Value: struct moray_workload_entry (24 bytes)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MORAY_MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct moray_workload_entry);
} moray_workload_map SEC(".maps");

/*
 * Invariant I_9 / Milestone 2: Look up governed workload entry for current task.
 * 1. Checks immediate leaf cgroup ID (bpf_get_current_cgroup_id).
 * 2. If not found and nested inheritance is enabled, checks ancestor cgroups (levels 1..4).
 */
static __attribute__((always_inline)) struct moray_workload_entry *lookup_workload_entry(void)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (!cgroup_id) {
        return NULL;
    }

    struct moray_workload_entry *entry = bpf_map_lookup_elem(&moray_workload_map, &cgroup_id);
    if (entry) {
        return entry;
    }

    /* Check ancestor cgroup levels (1 to 4) for nested hierarchy inheritance */
    #pragma unroll
    for (int lvl = 1; lvl <= 4; lvl++) {
        __u64 ancestor_id = bpf_get_current_ancestor_cgroup_id(lvl);
        if (ancestor_id) {
            struct moray_workload_entry *anc = bpf_map_lookup_elem(&moray_workload_map, &ancestor_id);
            if (anc && (anc->flags & MORAY_WORKLOAD_INHERIT_CHILDREN)) {
                return anc;
            }
        }
    }

    return NULL;
}

/*
 * Invariant I_1: Look up quarantine entry for current task.
 * 1. Checks process TGID.
 * 2. Checks individual thread PID.
 * 3. Checks cgroup v2 hierarchy (bpf_get_current_cgroup_id) for subtree containment.
 */
static __attribute__((always_inline)) struct moray_quarantine_entry *lookup_quarantine_entry(
    __u32 tgid,
    __u32 pid)
{
    struct moray_quarantine_entry *entry = bpf_map_lookup_elem(&moray_quarantine_map, &tgid);
    if (!entry) {
        entry = bpf_map_lookup_elem(&moray_quarantine_map, &pid);
    }
    if (!entry) {
        __u64 cgroup_id = bpf_get_current_cgroup_id();
        if (cgroup_id) {
            entry = bpf_map_lookup_elem(&moray_cgroup_map, &cgroup_id);
        }
    }
    return entry;
}

/*
 * Internal helper to record and transmit strike telemetry
 */
static __attribute__((always_inline)) void emit_strike_event(
    __u32 pid,
    __u32 tgid,
    __u32 action,
    __s32 ret_code,
    __u32 hook_point,
    __u64 drop_count)
{
    struct moray_event ev = {};
    __u64 uid_gid = bpf_get_current_uid_gid();

    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid = pid;
    ev.tgid = tgid;
    ev.uid = (__u32)uid_gid;
    ev.action_taken = action;
    ev.ret_code = ret_code;
    ev.hook_point = hook_point;
    ev.drop_count = drop_count;
    ev.reserved = 0;

    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    bpf_ringbuf_output(&moray_events, &ev, sizeof(ev), 0);
}

/*
 * Pharyngeal Strike 1: Sever Process Execution (execve)
 * Invariant I_1: Quarantined PID cannot invoke execve.
 * Invariant I_2: Non-quarantined PID returns 0 in O(1) time.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(moray_bprm_strike, struct linux_binprm *bprm)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    __u32 pid = (__u32)pid_tgid;

    struct moray_quarantine_entry *entry = lookup_quarantine_entry(tgid, pid);

    if (entry && (entry->action_flags & MORAY_ACT_BLOCK_EXEC)) {
        __u32 hits = __sync_fetch_and_add(&entry->strike_count, 1) + 1;
        bpf_printk("MORAY STRIKE: Intercepted execve from PID %d (hits: %d)\n", tgid, hits);
        emit_strike_event(pid, tgid, entry->action_flags, -1, MORAY_HOOK_BPRM, hits);

        /* Dynamic Escalation: Auto-terminate target if hits reach Tier 3 threshold (5 hits) */
        if ((entry->action_flags & MORAY_ACT_KILL) || hits >= MORAY_STRIKE_TIER3) {
            bpf_send_signal(9); /* SIGKILL */
        }
        return -1; /* -EPERM */
    }

    /* 2. Autonomous Boundary Defense: Workload-Scoped (Milestone 2) or Host-Wide Fallback */
    struct moray_workload_entry *w_entry = lookup_workload_entry();
    char sentinel_key[MORAY_COMM_LEN] = "__moray_auto__";
    struct moray_boundary_entry *sentinel = bpf_map_lookup_elem(&moray_boundary_map, sentinel_key);

    int is_governed = 0;
    if (w_entry) {
        is_governed = 1;
    } else if (sentinel && !(sentinel->reserved & MORAY_BOUNDARY_FLAG_WORKLOAD)) {
        is_governed = 1;
    }

    if (is_governed) {
        char comm[MORAY_COMM_LEN] = {};
        bpf_get_current_comm(comm, sizeof(comm));

        struct moray_boundary_entry *b_entry = bpf_map_lookup_elem(&moray_boundary_map, comm);
        if (b_entry && (b_entry->perm_flags & MORAY_PERM_EXEC)) {
            __sync_fetch_and_add(&b_entry->hit_count, 1);
            if (w_entry) {
                __sync_fetch_and_add(&w_entry->hit_count, 1);
            }
            return 0; /* Permitted executable: O(1) Fast-Path (Invariant I_2) */
        }

        /* Unlisted binary execution inside governed boundary: autonomous strike and quarantine */
        if (w_entry) {
            __sync_fetch_and_add(&w_entry->strike_count, 1);
        }
        struct moray_quarantine_entry auto_strike = {};
        auto_strike.action_flags = MORAY_ACT_BLOCK_EXEC | MORAY_ACT_BLOCK_SOCKET;
        auto_strike.reason = MORAY_REASON_EXEC_VIOLATION;
        auto_strike.timestamp_ns = bpf_ktime_get_ns();
        auto_strike.strike_count = 1;
        auto_strike.ttl_seconds = 0;

        bpf_map_update_elem(&moray_quarantine_map, &tgid, &auto_strike, BPF_ANY);
        bpf_printk("MORAY AUTO-STRIKE: Intercepted unlisted binary '%s' (PID %d)\n", comm, tgid);
        emit_strike_event(pid, tgid, auto_strike.action_flags, -1, MORAY_HOOK_BPRM, 1);
        return -1; /* -EPERM */
    }

    return 0;
}

/*
 * Helper: Verify destination/bind address is loopback (127.0.0.0/8, ::1) or AF_UNIX
 */
static inline int is_loopback_or_unix(struct sockaddr *address, int addrlen)
{
    if (!address || addrlen <= 0) {
        return 0;
    }

    sa_family_t family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family) != 0) {
        return 0;
    }

    /* Allow local Unix Domain Sockets */
    if (family == AF_UNIX) {
        return 1;
    }

    /* Check IPv4 loopback (127.0.0.0/8) */
    if (family == AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in in = {};
        if (bpf_probe_read_kernel(&in, sizeof(in), address) == 0) {
            __u32 host_ip = bpf_ntohl(in.sin_addr.s_addr);
            if ((host_ip & 0xFF000000) == 0x7F000000) {
                return 1; /* Loopback IPv4 allowed */
            }
        }
    }

    /* Check IPv6 loopback (::1) */
    if (family == AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 in6 = {};
        if (bpf_probe_read_kernel(&in6, sizeof(in6), address) == 0) {
            if (in6.sin6_addr.in6_u.u6_addr32[0] == 0 &&
                in6.sin6_addr.in6_u.u6_addr32[1] == 0 &&
                in6.sin6_addr.in6_u.u6_addr32[2] == 0 &&
                in6.sin6_addr.in6_u.u6_addr32[3] == bpf_htonl(1)) {
                return 1; /* Loopback IPv6 allowed */
            }
        }
    }

    return 0;
}

/*
 * Pharyngeal Strike 2: Sever Outbound Network Socket Initiation
 * Invariant I_1 / I_4: Quarantined PID cannot establish unauthorized network connections.
 * Invariant I_4: Granular Network Egress Filtering allows loopback/IPC if MORAY_ACT_ALLOW_LOOPBACK is set.
 */
SEC("lsm/socket_connect")
int BPF_PROG(moray_socket_strike, struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    __u32 pid = (__u32)pid_tgid;

    struct moray_quarantine_entry *entry = lookup_quarantine_entry(tgid, pid);

    if (entry && (entry->action_flags & MORAY_ACT_BLOCK_SOCKET)) {
        /* If granular loopback policy is set, permit local IPC and localhost loopback */
        if ((entry->action_flags & MORAY_ACT_ALLOW_LOOPBACK) && is_loopback_or_unix(address, addrlen)) {
            return 0;
        }

        __u32 hits = __sync_fetch_and_add(&entry->strike_count, 1) + 1;
        bpf_printk("MORAY STRIKE: Intercepted socket connect from PID %d (hits: %d)\n", tgid, hits);
        emit_strike_event(pid, tgid, entry->action_flags, -1, MORAY_HOOK_SOCKET, hits);

        /* Dynamic Escalation: Auto-terminate target if hits reach Tier 3 or kill flag is asserted */
        if ((entry->action_flags & MORAY_ACT_KILL) || hits >= MORAY_STRIKE_TIER3) {
            bpf_send_signal(9); /* SIGKILL */
        }
        return -1; /* -EPERM */
    }

    /* 2. Autonomous Network Boundary Enforcement (Workload-Scoped or Host-Wide Fallback) */
    struct moray_workload_entry *w_entry = lookup_workload_entry();
    char sentinel_key[MORAY_COMM_LEN] = "__moray_auto__";
    struct moray_boundary_entry *sentinel = bpf_map_lookup_elem(&moray_boundary_map, sentinel_key);

    __u32 effective_posture = 0;
    int is_governed = 0;

    if (w_entry) {
        effective_posture = w_entry->posture_flags;
        is_governed = 1;
    } else if (sentinel && !(sentinel->reserved & MORAY_BOUNDARY_FLAG_WORKLOAD)) {
        effective_posture = sentinel->perm_flags;
        is_governed = 1;
    }

    if (is_governed && !(effective_posture & MORAY_PERM_SOCKET) && address && addrlen > 0) {
        char comm[MORAY_COMM_LEN] = {};
        bpf_get_current_comm(comm, sizeof(comm));
        struct moray_boundary_entry *b_entry = bpf_map_lookup_elem(&moray_boundary_map, comm);

        /* Control plane daemon (e.g. morayd) retains MORAY_PERM_ALL / MORAY_PERM_SOCKET */
        if (b_entry && (b_entry->perm_flags & MORAY_PERM_SOCKET)) {
            __sync_fetch_and_add(&b_entry->hit_count, 1);
            if (w_entry) {
                __sync_fetch_and_add(&w_entry->hit_count, 1);
            }
            return 0; /* Permitted WAN/network socket for management daemon */
        }

        /* Check if network posture permits loopback/IPC (ALLOW_LOOPBACK) */
        if ((effective_posture & MORAY_PERM_LOOPBACK) && is_loopback_or_unix(address, addrlen)) {
            return 0; /* Loopback / IPC socket allowed under ALLOW_LOOPBACK */
        }

        /* Socket severed under autonomous boundary (DENY_ALL_NET or unauthorized WAN under ALLOW_LOOPBACK) */
        if (w_entry) {
            __sync_fetch_and_add(&w_entry->strike_count, 1);
        }
        bpf_printk("MORAY AUTO-STRIKE: Socket connect severed for '%s' (PID %d)\n", comm, tgid);
        emit_strike_event(pid, tgid, MORAY_ACT_BLOCK_SOCKET, -1, MORAY_HOOK_SOCKET, 1);
        return -1; /* -EPERM */
    }

    return 0;
}

/*
 * Pharyngeal Strike 5: Sever Unauthorized Inbound Socket Binding
 * Prevents rogue listener creation under DENY_ALL_NET and restricts bind()
 * strictly to 127.0.0.1/::1/AF_UNIX under ALLOW_LOOPBACK.
 */
SEC("lsm/socket_bind")
int BPF_PROG(moray_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    __u32 pid = (__u32)pid_tgid;

    struct moray_quarantine_entry *entry = lookup_quarantine_entry(tgid, pid);

    if (entry && (entry->action_flags & MORAY_ACT_BLOCK_SOCKET)) {
        if ((entry->action_flags & MORAY_ACT_ALLOW_LOOPBACK) && is_loopback_or_unix(address, addrlen)) {
            return 0; /* Loopback / IPC bind permitted */
        }

        __u32 hits = __sync_fetch_and_add(&entry->strike_count, 1) + 1;
        bpf_printk("MORAY STRIKE: Intercepted socket bind from PID %d (hits: %d)\n", tgid, hits);
        emit_strike_event(pid, tgid, entry->action_flags, -1, MORAY_HOOK_SOCKET_BIND, hits);

        if ((entry->action_flags & MORAY_ACT_KILL) || hits >= MORAY_STRIKE_TIER3) {
            bpf_send_signal(9); /* SIGKILL */
        }
        return -1; /* -EPERM */
    }

    struct moray_workload_entry *w_entry = lookup_workload_entry();
    char sentinel_key[MORAY_COMM_LEN] = "__moray_auto__";
    struct moray_boundary_entry *sentinel = bpf_map_lookup_elem(&moray_boundary_map, sentinel_key);

    __u32 effective_posture = 0;
    int is_governed = 0;

    if (w_entry) {
        effective_posture = w_entry->posture_flags;
        is_governed = 1;
    } else if (sentinel && !(sentinel->reserved & MORAY_BOUNDARY_FLAG_WORKLOAD)) {
        effective_posture = sentinel->perm_flags;
        is_governed = 1;
    }

    if (is_governed && !(effective_posture & MORAY_PERM_SOCKET) && address && addrlen > 0) {
        char comm[MORAY_COMM_LEN] = {};
        bpf_get_current_comm(comm, sizeof(comm));
        struct moray_boundary_entry *b_entry = bpf_map_lookup_elem(&moray_boundary_map, comm);

        if (b_entry && (b_entry->perm_flags & MORAY_PERM_SOCKET)) {
            __sync_fetch_and_add(&b_entry->hit_count, 1);
            if (w_entry) {
                __sync_fetch_and_add(&w_entry->hit_count, 1);
            }
            return 0; /* Permitted for control plane daemon */
        }

        if ((effective_posture & MORAY_PERM_LOOPBACK) && is_loopback_or_unix(address, addrlen)) {
            return 0; /* Loopback / IPC bind permitted under ALLOW_LOOPBACK */
        }

        if (w_entry) {
            __sync_fetch_and_add(&w_entry->strike_count, 1);
        }
        bpf_printk("MORAY AUTO-STRIKE: Socket bind severed for '%s' (PID %d)\n", comm, tgid);
        emit_strike_event(pid, tgid, MORAY_ACT_BLOCK_SOCKET, -1, MORAY_HOOK_SOCKET_BIND, 1);
        return -1; /* -EPERM */
    }

    return 0;
}

/*
 * Pharyngeal Strike 6: Sever Unauthorized Socket Allocation
 * Prevents socket creation entirely under DENY_ALL_NET, and denies raw/packet
 * socket creation under ALLOW_LOOPBACK to prevent unmediated frame crafting.
 */
SEC("lsm/socket_create")
int BPF_PROG(moray_socket_create, int family, int type, int protocol, int kern)
{
    /* Always permit internal kernel sockets */
    if (kern != 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    __u32 pid = (__u32)pid_tgid;

    struct moray_quarantine_entry *entry = lookup_quarantine_entry(tgid, pid);

    if (entry && (entry->action_flags & MORAY_ACT_BLOCK_SOCKET)) {
        int should_block = 0;
        if (!(entry->action_flags & MORAY_ACT_ALLOW_LOOPBACK)) {
            /* Total socket block: block network and IPC socket allocation */
            if (family == AF_INET || family == AF_INET6 || family == AF_UNIX || family == AF_PACKET) {
                should_block = 1;
            }
        } else {
            /* Loopback permitted: strictly block raw socket creation */
            if (family == AF_PACKET || type == SOCK_RAW) {
                should_block = 1;
            }
        }

        if (should_block) {
            __u32 hits = __sync_fetch_and_add(&entry->strike_count, 1) + 1;
            bpf_printk("MORAY STRIKE: Intercepted socket create from PID %d (hits: %d)\n", tgid, hits);
            emit_strike_event(pid, tgid, entry->action_flags, -1, MORAY_HOOK_SOCKET_CREATE, hits);

            if ((entry->action_flags & MORAY_ACT_KILL) || hits >= MORAY_STRIKE_TIER3) {
                bpf_send_signal(9); /* SIGKILL */
            }
            return -1; /* -EPERM */
        }
    }

    struct moray_workload_entry *w_entry = lookup_workload_entry();
    char sentinel_key[MORAY_COMM_LEN] = "__moray_auto__";
    struct moray_boundary_entry *sentinel = bpf_map_lookup_elem(&moray_boundary_map, sentinel_key);

    __u32 effective_posture = 0;
    int is_governed = 0;

    if (w_entry) {
        effective_posture = w_entry->posture_flags;
        is_governed = 1;
    } else if (sentinel && !(sentinel->reserved & MORAY_BOUNDARY_FLAG_WORKLOAD)) {
        effective_posture = sentinel->perm_flags;
        is_governed = 1;
    }

    if (is_governed && !(effective_posture & MORAY_PERM_SOCKET)) {
        char comm[MORAY_COMM_LEN] = {};
        bpf_get_current_comm(comm, sizeof(comm));
        struct moray_boundary_entry *b_entry = bpf_map_lookup_elem(&moray_boundary_map, comm);

        if (b_entry && (b_entry->perm_flags & MORAY_PERM_SOCKET)) {
            __sync_fetch_and_add(&b_entry->hit_count, 1);
            if (w_entry) {
                __sync_fetch_and_add(&w_entry->hit_count, 1);
            }
            return 0; /* Permitted for control plane daemon */
        }

        int should_block = 0;
        if (!(effective_posture & MORAY_PERM_LOOPBACK)) {
            /* DENY_ALL_NET: Block all network and IPC socket allocation */
            if (family == AF_INET || family == AF_INET6 || family == AF_UNIX || family == AF_PACKET) {
                should_block = 1;
            }
        } else {
            /* ALLOW_LOOPBACK: Block raw and packet sockets */
            if (family == AF_PACKET || type == SOCK_RAW) {
                should_block = 1;
            }
        }

        if (should_block) {
            if (w_entry) {
                __sync_fetch_and_add(&w_entry->strike_count, 1);
            }
            bpf_printk("MORAY AUTO-STRIKE: Socket create severed for '%s' (PID %d)\n", comm, tgid);
            emit_strike_event(pid, tgid, MORAY_ACT_BLOCK_SOCKET, -1, MORAY_HOOK_SOCKET_CREATE, 1);
            return -1; /* -EPERM */
        }
    }

    return 0;
}

/*
 * Camouflage Strike 3: Anti-Tamper Protection (The Crevice)
 * Invariant I_3 / I_7: Quarantined processes cannot interact with bpf() syscall.
 */
SEC("lsm/bpf")
int BPF_PROG(moray_bpf_strike, int cmd, union bpf_attr *attr, unsigned int size)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    __u32 pid = (__u32)pid_tgid;

    struct moray_quarantine_entry *entry = lookup_quarantine_entry(tgid, pid);

    if (entry) {
        __u32 hits = __sync_fetch_and_add(&entry->strike_count, 1) + 1;
        bpf_printk("MORAY ANTI-TAMPER: Blocked bpf() syscall from PID %d (hits: %d)\n", tgid, hits);
        emit_strike_event(pid, tgid, entry->action_flags, -1, MORAY_HOOK_BPF_TAMPER, hits);

        /* Dynamic Escalation: Auto-terminate target if hits reach Tier 3 or kill flag is asserted */
        if ((entry->action_flags & MORAY_ACT_KILL) || hits >= MORAY_STRIKE_TIER3) {
            bpf_send_signal(9); /* SIGKILL */
        }
        return -1; /* -EPERM */
    }

    return 0;
}

/*
 * Pharyngeal Wire Strike 4: Driver-Level Packet Drop (XDP)
 * Invariant I_1: Ingress/egress packets from quarantined IPs dropped at line rate.
 */
SEC("xdp")
int moray_xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header boundary (14 bytes) */
    if (data + 14 > data_end) {
        return XDP_PASS;
    }

    /* Verify EtherType is IPv4 (0x0800) in wire order */
    __u8 *eth_proto = (__u8 *)(data + 12);
    if (eth_proto[0] != 0x08 || eth_proto[1] != 0x00) {
        return XDP_PASS;
    }

    /* Verify IPv4 header minimum boundary (14 Ethernet + 20 IPv4 = 34 bytes) */
    if (data + 34 > data_end) {
        return XDP_PASS;
    }

    /* Extract IPv4 Source Address (offset 14 ethernet + 12 ip header = 26) */
    __u32 *src_ip = (__u32 *)(data + 26);
    if ((void *)(src_ip + 1) > data_end) {
        return XDP_PASS;
    }

    __u8 *drop_flag = bpf_map_lookup_elem(&moray_xdp_drop_map, src_ip);
    if (drop_flag && *drop_flag != 0) {
        return XDP_DROP;
    }

    /* Extract IPv4 Destination Address (offset 14 ethernet + 16 ip header = 30) */
    __u32 *dst_ip = (__u32 *)(data + 30);
    if ((void *)(dst_ip + 1) > data_end) {
        return XDP_PASS;
    }

    drop_flag = bpf_map_lookup_elem(&moray_xdp_drop_map, dst_ip);
    if (drop_flag && *drop_flag != 0) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
