/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Project Moray: In-Kernel BPF Helper & Primitive Definitions
 * Provides zero-dependency standalone BPF macros and helper bindings.
 */

#ifndef _MORAY_BPF_H_
#define _MORAY_BPF_H_

#include "moray.h"

#define SEC(name) __attribute__((section(name), used))

/*
 * BPF_PROG Macro Definition for LSM & Tracing Programs
 * Emits canonical (unsigned long long *ctx) entry points that safely unpack
 * context arguments via memory offsets rather than uninitialized registers.
 */
#ifndef ___bpf_concat
#define ___bpf_concat(a, b) a ## b
#endif
#ifndef ___bpf_apply
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#endif
#ifndef ___bpf_nth
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, N, ...) N
#endif
#ifndef ___bpf_narg
#define ___bpf_narg(...) ___bpf_nth(_, ##__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)
#endif

#define ___bpf_ctx_cast0()            ctx
#define ___bpf_ctx_cast1(x)           ___bpf_ctx_cast0(), (void *)ctx[0]
#define ___bpf_ctx_cast2(x, args...)  ___bpf_ctx_cast1(args), (void *)ctx[1]
#define ___bpf_ctx_cast3(x, args...)  ___bpf_ctx_cast2(args), (void *)ctx[2]
#define ___bpf_ctx_cast4(x, args...)  ___bpf_ctx_cast3(args), (void *)ctx[3]
#define ___bpf_ctx_cast5(x, args...)  ___bpf_ctx_cast4(args), (void *)ctx[4]
#define ___bpf_ctx_cast6(x, args...)  ___bpf_ctx_cast5(args), (void *)ctx[5]
#define ___bpf_ctx_cast(args...)      ___bpf_apply(___bpf_ctx_cast, ___bpf_narg(args))(args)

#define BPF_PROG(name, args...) \
name(unsigned long long *ctx); \
static inline __attribute__((always_inline)) typeof(name(0)) \
____##name(unsigned long long *ctx, ##args); \
typeof(name(0)) name(unsigned long long *ctx) \
{ \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wint-conversion\"") \
    return ____##name(___bpf_ctx_cast(args)); \
    _Pragma("clang diagnostic pop") \
} \
static inline __attribute__((always_inline)) typeof(name(0)) \
____##name(unsigned long long *ctx, ##args)

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
#define BPF_FUNC_get_current_cgroup_id 80
#define BPF_FUNC_send_signal         109
#define BPF_FUNC_probe_read_kernel   113
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
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static long (*bpf_send_signal)(__u32 sig) = (void *)BPF_FUNC_send_signal;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)BPF_FUNC_probe_read_kernel;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)BPF_FUNC_ringbuf_output;

#define bpf_printk(fmt, ...)                                   \
({                                                             \
    char ____fmt[] = fmt;                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

/* Network Address Families */
#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

typedef unsigned short sa_family_t;

struct sockaddr {
    sa_family_t sa_family;
    char        sa_data[14];
};

struct in_addr {
    __be32 s_addr;
};

struct sockaddr_in {
    sa_family_t    sin_family;
    __be16         sin_port;
    struct in_addr sin_addr;
    unsigned char  sin_zero[8];
};

struct in6_addr {
    union {
        __u8   u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
};

struct sockaddr_in6 {
    sa_family_t     sin6_family;
    __be16          sin6_port;
    __be32          sin6_flowinfo;
    struct in6_addr sin6_addr;
    __u32           sin6_scope_id;
};

/* Byte-order conversion macros */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohl(x) ((__u32)( \
    (((__u32)(x) & (__u32)0x000000ffUL) << 24) | \
    (((__u32)(x) & (__u32)0x0000ff00UL) <<  8) | \
    (((__u32)(x) & (__u32)0x00ff0000UL) >>  8) | \
    (((__u32)(x) & (__u32)0xff000000UL) >> 24)))
#define bpf_htonl(x) bpf_ntohl(x)
#define bpf_ntohs(x) ((__u16)((((__u16)(x) & 0x00ffU) << 8) | (((__u16)(x) & 0xff00U) >> 8)))
#define bpf_htons(x) bpf_ntohs(x)
#else
#define bpf_ntohl(x) (x)
#define bpf_htonl(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#endif

/* Forward declarations for kernel pointers used in LSM prototypes */
struct linux_binprm;
struct socket;
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
