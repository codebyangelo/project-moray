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
int moray_bprm_strike(struct linux_binprm *bprm)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    __u32 pid = (__u32)pid_tgid;

    struct moray_quarantine_entry *entry = bpf_map_lookup_elem(&moray_quarantine_map, &tgid);
    if (!entry) {
        /* Also check individual thread PID if threaded agent */
        entry = bpf_map_lookup_elem(&moray_quarantine_map, &pid);
    }

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

    return 0;
}

/*
 * Pharyngeal Strike 2: Sever Outbound Network Socket Initiation
 * Invariant I_1: Quarantined PID cannot establish network connections.
 */
SEC("lsm/socket_connect")
int moray_socket_strike(struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    __u32 pid = (__u32)pid_tgid;

    struct moray_quarantine_entry *entry = bpf_map_lookup_elem(&moray_quarantine_map, &tgid);
    if (!entry) {
        entry = bpf_map_lookup_elem(&moray_quarantine_map, &pid);
    }

    if (entry && (entry->action_flags & MORAY_ACT_BLOCK_SOCKET)) {
        __sync_fetch_and_add(&entry->strike_count, 1);
        bpf_printk("MORAY STRIKE: Intercepted socket connect from PID %d\n", tgid);
        emit_strike_event(pid, tgid, entry->action_flags, -1, MORAY_HOOK_SOCKET, entry->strike_count);

        return -1; /* -EPERM */
    }

    return 0;
}

/*
 * Camouflage Strike 3: Anti-Tamper Protection (The Crevice)
 * Invariant I_3: Quarantined processes cannot interact with bpf() syscall.
 */
SEC("lsm/bpf")
int moray_bpf_strike(int cmd, union bpf_attr *attr, unsigned int size)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    __u32 pid = (__u32)pid_tgid;

    struct moray_quarantine_entry *entry = bpf_map_lookup_elem(&moray_quarantine_map, &tgid);
    if (!entry) {
        entry = bpf_map_lookup_elem(&moray_quarantine_map, &pid);
    }

    if (entry) {
        bpf_printk("MORAY ANTI-TAMPER: Blocked bpf() syscall from PID %d\n", tgid);
        emit_strike_event(pid, tgid, entry->action_flags, -1, MORAY_HOOK_BPF_TAMPER, entry->strike_count);
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
    if (drop_flag && *drop_flag == 1) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
