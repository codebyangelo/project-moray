/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Project Moray: In-Kernel Ring 0 Containment Architecture
 * Shared data structures and constants between BPF bytecode and user space.
 */

#ifndef _MORAY_H_
#define _MORAY_H_

#if defined(__bpf__)
typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed int         __s32;
typedef signed long long   __s64;
typedef __u16              __be16;
typedef __u32              __be32;
#elif defined(__linux__) || defined(__KERNEL__)
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t  __s32;
typedef int64_t  __s64;
typedef uint16_t __be16;
typedef uint32_t __be32;
#endif

/* Pinned VFS Paths */
#define MORAY_PIN_DIR           "/sys/fs/bpf/moray"
#define MORAY_QUARANTINE_PIN    "/sys/fs/bpf/moray/quarantine_map"
#define MORAY_EVENTS_PIN        "/sys/fs/bpf/moray/events"

/* Map Configuration Boundaries */
#define MORAY_MAX_ENTRIES       1024
#define MORAY_COMM_LEN          16
#define MORAY_TARGET_INFO_LEN   64

/* Action Flags (Quarantine Bitmask) */
#define MORAY_ACT_NONE          0x00U
#define MORAY_ACT_BLOCK_EXEC    0x01U  /* Sever bprm_check_security (execve) */
#define MORAY_ACT_BLOCK_SOCKET  0x02U  /* Sever socket_connect */
#define MORAY_ACT_DROP_NET      0x04U  /* XDP wire-level frame drop */
#define MORAY_ACT_KILL          0x08U  /* Signal immediate termination */
#define MORAY_ACT_ALLOW_LOOPBACK 0x10U /* Granular policy: Allow AF_UNIX and 127.0.0.1/::1 */
#define MORAY_ACT_FULL_STRIKE   0xFFU  /* Full containment shutdown */

/* Strike Reason Codes */
#define MORAY_REASON_UNKNOWN          0U
#define MORAY_REASON_LOBSTER_L7       1U  /* Triggered by Project Lobster semantic filter */
#define MORAY_REASON_EXEC_VIOLATION   2U  /* Unauthorized execution attempt */
#define MORAY_REASON_SOCKET_VIOLATION 3U  /* Unauthorized network socket attempt */
#define MORAY_REASON_TAMPER_ATTEMPT   4U  /* Tampering with eBPF programs or maps */

/* Hook Identification Codes */
#define MORAY_HOOK_BPRM         1U
#define MORAY_HOOK_SOCKET       2U
#define MORAY_HOOK_BPF_TAMPER   3U
#define MORAY_HOOK_XDP          4U

/* Policy State Codes */
#define MORAY_STATE_ACTIVE      1U  /* Actively enforced */
#define MORAY_STATE_EXPIRED     2U  /* TTL expired, pending eviction */
#define MORAY_STATE_RELEASED    3U  /* Cleared from containment */

/* Strike Escalation Tiers */
#define MORAY_STRIKE_TIER1      1U  /* 1 hit: Block execve */
#define MORAY_STRIKE_TIER2      3U  /* 3 hits: Block execve + network sockets */
#define MORAY_STRIKE_TIER3      5U  /* 5 hits: Auto-escalate to SIGKILL */

/*
 * Quarantine Map Entry Value
 * Key: __u32 (Process ID / TGID)
 * Total size: 24 bytes (8-byte aligned)
 */
struct moray_quarantine_entry {
    __u32 action_flags;  /* Bitmask of MORAY_ACT_* */
    __u32 reason;        /* Source code / trigger reason */
    __u64 timestamp_ns;  /* Epoch timestamp in nanoseconds */
    __u32 strike_count;  /* Interception hit counter maintained by BPF */
    __u32 ttl_seconds;   /* Time-to-live in seconds (0 = permanent, >0 = auto-expiry) */
};

/*
 * Ring Buffer Telemetry Event
 * Emitted by Ring 0 hooks upon strike or tamper detection.
 * Total size: 128 bytes (64-byte / cache-line aligned)
 */
struct moray_event {
    __u64 timestamp_ns;                 /* Monotonic nanoseconds from ktime_get_ns() */
    __u32 pid;                          /* Process ID (from bpf_get_current_pid_tgid) */
    __u32 tgid;                         /* Thread Group ID */
    __u32 uid;                          /* User ID (from bpf_get_current_uid_gid) */
    __u32 action_taken;                 /* Bitmask of MORAY_ACT_* enforced */
    __s32 ret_code;                     /* Return code enforced (-1 / -EPERM) */
    __u32 hook_point;                   /* MORAY_HOOK_* identifier */
    char  comm[MORAY_COMM_LEN];         /* Process executable name (16 bytes) */
    char  target_info[MORAY_TARGET_INFO_LEN]; /* Path or socket address string (64 bytes) */
    __u64 drop_count;                   /* Total drops / cumulative strikes */
    __u64 reserved;                     /* Explicit 8-byte alignment padding */
};

#if !defined(__KERNEL__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct moray_quarantine_entry) == 24, "moray_quarantine_entry must be 24 bytes");
_Static_assert(sizeof(struct moray_event) == 128, "moray_event must be 128 bytes");
#endif

#endif /* _MORAY_H_ */
