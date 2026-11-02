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
    assert(offsetof(struct moray_quarantine_entry, reserved) == 20);

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

    printf("[+] All struct layout and alignment assertions PASSED cleanly.\n");
    return 0;
}
