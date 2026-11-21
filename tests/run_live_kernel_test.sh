#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Project Moray: Live Ring 0 Kernel Verification Harness (Master Orchestrator)
# Executed inside KVM microVM with active BPF-LSM.
# Supports domain-targeted execution: ./tests/run_live_kernel_test.sh [domain_id | "all"]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIVE_DIR="$SCRIPT_DIR/live"

# Source shared environment and fixtures
source "$LIVE_DIR/common.sh"

TARGET_DOMAIN="all"
if [ $# -ge 1 ]; then
    case "$1" in
        --help|-h|help)
            TARGET_DOMAIN="help"
            ;;
        --domain)
            TARGET_DOMAIN="${2:-all}"
            ;;
        --domain=*)
            TARGET_DOMAIN="${1#*=}"
            ;;
        *)
            TARGET_DOMAIN="$1"
            ;;
    esac
fi

if [ "$TARGET_DOMAIN" = "help" ]; then
    echo "Usage: $0 [domain_id | 'all']"
    echo "Supported domain_id values:"
    echo "  0   - Core LSM & Baseline Interceptions (Steps 5-15)"
    echo "  1   - Real Cgroup v2 Subtree Fork Races (Steps 16-20)"
    echo "  2   - In-Kernel Dynamic Escalation to SIGKILL (Steps 21-25)"
    echo "  3   - Multi-Threaded SMP Concurrency (Steps 26-30)"
    echo "  4   - Real Wire-Level Packet Drops via veth Pairs (Steps 31-35)"
    echo "  5   - Ringbuf Saturation Stress & Continuous Drain (Steps 36-40)"
    echo "  6   - Live SRE Disaster Recovery DR-01..DR-03 (Steps 41-46)"
    echo "  7   - Autonomous Boundary Defense: ALLOW_LOOPBACK (Steps 47-54)"
    echo "  8   - Autonomous Boundary Defense: DENY_ALL_NET (Steps 55-62)"
    echo "  9   - Autonomous Boundary Defense: REQUIRE_WAN (Steps 63-70)"
    echo "  10  - Workload-Scoped Boundary & Non-Interference (Steps 71-80)"
    echo "  11  - Extended Network Defense: socket_create & socket_bind (Steps 81-90)"
    echo "  12  - Manifest Schema Hardening & Fail-Closed Ingestion (Steps 91-100)"
    echo "  13  - Operational Confidence, Health/Readiness Probes & Crash Recovery (Steps 101-110)"
    echo "  14  - Multi-Tenant Workload Isolation & Real Autonomous Agent Proof (Steps 111-120)"
    echo "  all - Complete 120-step end-to-end regression verification (default)"
    exit 0
fi

# Source modular domain test suites
source "$LIVE_DIR/domain_00_baseline.sh"
source "$LIVE_DIR/domain_01_cgroup_races.sh"
source "$LIVE_DIR/domain_02_dynamic_escalation.sh"
source "$LIVE_DIR/domain_03_smp_concurrency.sh"
source "$LIVE_DIR/domain_04_xdp_packet_drops.sh"
source "$LIVE_DIR/domain_05_ringbuf_telemetry.sh"
source "$LIVE_DIR/domain_06_sre_recovery.sh"
source "$LIVE_DIR/domain_07_allow_loopback.sh"
source "$LIVE_DIR/domain_08_deny_all_net.sh"
source "$LIVE_DIR/domain_09_require_wan.sh"
source "$LIVE_DIR/domain_10_workload_boundary.sh"
source "$LIVE_DIR/domain_11_socket_gates.sh"
source "$LIVE_DIR/domain_12_manifest_schema.sh"
source "$LIVE_DIR/domain_13_operational_health.sh"
source "$LIVE_DIR/domain_14_agent_isolation.sh"

# =========================================================================
# Execution Dispatcher
# =========================================================================
echo "=========================================================="
echo "  PROJECT MORAY: LIVE RING 0 KERNEL VERIFICATION (KVM)    "
echo "  Target Domain: $TARGET_DOMAIN"
echo "=========================================================="

run_preflight

case "$TARGET_DOMAIN" in
    0|domain0|baseline)
        run_domain_0
        echo "=========================================================="
        echo "  [+] DOMAIN 0 (Steps 5-15) PASSED CLEANLY!               "
        echo "=========================================================="
        ;;
    1|domain1)
        run_domain_1
        echo "=========================================================="
        echo "  [+] DOMAIN 1 (Steps 16-20) PASSED CLEANLY!              "
        echo "=========================================================="
        ;;
    2|domain2)
        run_domain_2
        echo "=========================================================="
        echo "  [+] DOMAIN 2 (Steps 21-25) PASSED CLEANLY!              "
        echo "=========================================================="
        ;;
    3|domain3)
        run_domain_3
        echo "=========================================================="
        echo "  [+] DOMAIN 3 (Steps 26-30) PASSED CLEANLY!              "
        echo "=========================================================="
        ;;
    4|domain4)
        run_domain_4
        echo "=========================================================="
        echo "  [+] DOMAIN 4 (Steps 31-35) PASSED CLEANLY!              "
        echo "=========================================================="
        ;;
    5|domain5)
        run_domain_5
        echo "=========================================================="
        echo "  [+] DOMAIN 5 (Steps 36-40) PASSED CLEANLY!              "
        echo "=========================================================="
        ;;
    6|domain6)
        run_domain_6
        echo "=========================================================="
        echo "  [+] DOMAIN 6 (Steps 41-46) PASSED CLEANLY!              "
        echo "=========================================================="
        ;;
    7|domain7)
        run_domain_7
        echo "=========================================================="
        echo "  [+] DOMAIN 7 (Steps 47-54) PASSED CLEANLY!              "
        echo "=========================================================="
        ;;
    8|domain8)
        run_domain_8
        echo "=========================================================="
        echo "  [+] DOMAIN 8 (Steps 55-62) PASSED CLEANLY!              "
        echo "=========================================================="
        ;;
    9|domain9)
        run_domain_9
        echo "=========================================================="
        echo "  [+] DOMAIN 9 (Steps 63-70) PASSED CLEANLY!              "
        echo "=========================================================="
        ;;
    10|domain10)
        run_domain_10
        echo "=========================================================="
        echo "  [+] DOMAIN 10 (Steps 71-80) PASSED CLEANLY!             "
        echo "=========================================================="
        ;;
    11|domain11)
        run_domain_11
        echo "=========================================================="
        echo "  [+] DOMAIN 11 (Steps 81-90) PASSED CLEANLY!             "
        echo "=========================================================="
        ;;
    12|domain12)
        run_domain_12
        echo "=========================================================="
        echo "  [+] DOMAIN 12 (Steps 91-100) PASSED CLEANLY!            "
        echo "=========================================================="
        ;;
    13|domain13)
        run_domain_13
        echo "=========================================================="
        echo "  [+] DOMAIN 13 (Steps 101-110) PASSED CLEANLY!           "
        echo "=========================================================="
        ;;
    14|domain14)
        run_domain_14
        echo "=========================================================="
        echo "  [+] DOMAIN 14 (Steps 111-120) PASSED CLEANLY!           "
        echo "=========================================================="
        ;;
    all|ALL)
        run_domain_0
        run_domain_1
        run_domain_2
        run_domain_3
        run_domain_4
        run_domain_5
        run_domain_6
        run_domain_7
        run_domain_8
        run_domain_9
        run_domain_10
        run_domain_11
        run_domain_12
        run_domain_13
        run_domain_14
        echo "=========================================================="
        echo "  [+] ALL 120 LIVE RING 0 KERNEL TEST STEPS PASSED CLEANLY! "
        echo "=========================================================="
        ;;
    *)
        echo "[-] FATAL: Unknown domain target: '$TARGET_DOMAIN' (expected 0-14 or 'all')"
        exit 1
        ;;
esac
