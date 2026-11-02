/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Project Moray: In-Kernel BPF Helper & Primitive Definitions
 * Provides zero-dependency standalone BPF macros and helper bindings.
 */

#ifndef _MORAY_BPF_H_
#define _MORAY_BPF_H_

#include "moray.h"

#define SEC(name) __attribute__((section(name), used))

/* BTF map definition macros */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* Standard BPF Map Types */
#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif

#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

/* XDP Actions */
#ifndef XDP_DROP
#define XDP_DROP 1
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

/* Standard POSIX Error Codes in Ring 0 */
#ifndef EPERM
#define EPERM 1
#endif

#ifndef EACCES
#define EACCES 13
#endif

/* BPF Helper IDs */
#define BPF_FUNC_map_lookup_elem     1
#define BPF_FUNC_map_update_elem     2
#define BPF_FUNC_map_delete_elem     3
#define BPF_FUNC_ktime_get_ns        5
#define BPF_FUNC_trace_printk        6
#define BPF_FUNC_get_current_pid_tgid 14
#define BPF_FUNC_get_current_uid_gid 15
#define BPF_FUNC_get_current_comm    16
#define BPF_FUNC_send_signal         109
#define BPF_FUNC_ringbuf_output      130

/* Helper Function Signatures */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)BPF_FUNC_trace_printk;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)BPF_FUNC_get_current_comm;
static long (*bpf_send_signal)(__u32 sig) = (void *)BPF_FUNC_send_signal;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_output;

#define bpf_printk(fmt, ...)                                   \
({                                                             \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

/* Forward declarations for kernel pointers used in LSM prototypes */
struct linux_binprm;
struct socket;
struct sockaddr;
struct file;
union bpf_attr;

/* XDP context forward declaration */
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

#endif /* _MORAY_BPF_H_ */
