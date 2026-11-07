/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
#include <stdio.h>
#include <stddef.h>
#include <assert.h>
#include "../src/moray.h"

int main(void) {
    printf("[*] Running Moray Struct Layout and Alignment Verification...\n");

    /* Verify moray_quarantine_entry */
    printf("[-] sizeof(struct moray_quarantine_entry) = %zu\n", sizeof(struct moray_quarantine_entry));
    assert(sizeof(struct moray_quarantine_entry) == 24);
    assert(offsetof(struct moray_quarantine_entry, action_flags) == 0);
    assert(offsetof(struct moray_quarantine_entry, reason) == 4);
    assert(offsetof(struct moray_quarantine_entry, timestamp_ns) == 8);
    assert(offsetof(struct moray_quarantine_entry, strike_count) == 16);
    assert(offsetof(struct moray_quarantine_entry, ttl_seconds) == 20);

    /* Verify Action Bitmask Flags */
    assert(MORAY_ACT_BLOCK_EXEC == 0x01);
    assert(MORAY_ACT_BLOCK_SOCKET == 0x02);
    assert(MORAY_ACT_DROP_NET == 0x04);
    assert(MORAY_ACT_KILL == 0x08);
    assert(MORAY_ACT_ALLOW_LOOPBACK == 0x10);
    assert((MORAY_ACT_BLOCK_EXEC & MORAY_ACT_BLOCK_SOCKET) == 0);
    assert((MORAY_ACT_BLOCK_SOCKET & MORAY_ACT_ALLOW_LOOPBACK) == 0);

    /* Verify moray_event */
    printf("[-] sizeof(struct moray_event) = %zu\n", sizeof(struct moray_event));
    assert(sizeof(struct moray_event) == 128);
    assert(offsetof(struct moray_event, timestamp_ns) == 0);
    assert(offsetof(struct moray_event, pid) == 8);
    assert(offsetof(struct moray_event, tgid) == 12);
    assert(offsetof(struct moray_event, uid) == 16);
    assert(offsetof(struct moray_event, action_taken) == 20);
    assert(offsetof(struct moray_event, ret_code) == 24);
    assert(offsetof(struct moray_event, hook_point) == 28);
    assert(offsetof(struct moray_event, comm) == 32);
    assert(offsetof(struct moray_event, target_info) == 48);
    assert(offsetof(struct moray_event, drop_count) == 112);
    assert(offsetof(struct moray_event, reserved) == 120);

    /* Verify moray_boundary_entry */
    printf("[-] sizeof(struct moray_boundary_entry) = %zu\n", sizeof(struct moray_boundary_entry));
    assert(sizeof(struct moray_boundary_entry) == 16);
    assert(offsetof(struct moray_boundary_entry, perm_flags) == 0);
    assert(offsetof(struct moray_boundary_entry, reserved) == 4);
    assert(offsetof(struct moray_boundary_entry, hit_count) == 8);
    assert(MORAY_PERM_EXEC == 0x01);
    assert(MORAY_PERM_SOCKET == 0x02);
    assert(MORAY_PERM_ALL == 0xFF);

    printf("[+] All struct layout and alignment assertions PASSED cleanly.\n");
    return 0;
}
