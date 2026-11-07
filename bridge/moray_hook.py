# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Native Sovereign Python Bridge & Kernel Hook Controller
Provides zero-dependency userspace control over Linux BPF-LSM and XDP containment maps.
Functions 100% independently of external agent frameworks.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Import all core Moray primitives from the internal bridge implementation
from bridge.lobster_hook import (
    BPF_ANY,
    BPF_MAP_CREATE,
    BPF_MAP_DELETE_ELEM,
    BPF_MAP_GET_NEXT_KEY,
    BPF_MAP_LOOKUP_ELEM,
    BPF_MAP_UPDATE_ELEM,
    DEFAULT_CGROUP_PIN,
    DEFAULT_EVENTS_PIN,
    DEFAULT_QUARANTINE_PIN,
    DEFAULT_XDP_PIN,
    FAIL_CLOSED_EXIT_CODE,
    MORAY_ACT_ALLOW_LOOPBACK,
    MORAY_ACT_BLOCK_EXEC,
    MORAY_ACT_BLOCK_SOCKET,
    MORAY_ACT_FULL_STRIKE,
    MORAY_ACT_KILL,
    MORAY_ACT_NONE,
    MORAY_HOOK_BPF_TAMPER,
    MORAY_HOOK_BPRM,
    MORAY_HOOK_SOCKET,
    MORAY_HOOK_XDP,
    MORAY_REASON_EXEC_VIOLATION,
    MORAY_REASON_LOBSTER_L7,
    MORAY_REASON_SOCKET_VIOLATION,
    MORAY_REASON_TAMPER_ATTEMPT,
    MORAY_REASON_UNKNOWN,
    MORAY_STATE_ACTIVE,
    MORAY_STATE_EXPIRED,
    MORAY_STATE_RELEASED,
    MorayEvent,
    MorayHook,
    MorayQuarantineEntry,
    MorayQuarantineError,
    MorayTelemetryConsumer,
    is_entry_expired,
    resolve_cgroup_id,
)
from bridge.lobster_hook import (
    main as bridge_main,
)
from bridge.moray_profiler import MorayBoundaryProfiler

__all__ = [
    "BPF_ANY",
    "BPF_MAP_CREATE",
    "BPF_MAP_DELETE_ELEM",
    "BPF_MAP_GET_NEXT_KEY",
    "BPF_MAP_LOOKUP_ELEM",
    "BPF_MAP_UPDATE_ELEM",
    "DEFAULT_CGROUP_PIN",
    "DEFAULT_EVENTS_PIN",
    "DEFAULT_QUARANTINE_PIN",
    "DEFAULT_XDP_PIN",
    "FAIL_CLOSED_EXIT_CODE",
    "MORAY_ACT_ALLOW_LOOPBACK",
    "MORAY_ACT_BLOCK_EXEC",
    "MORAY_ACT_BLOCK_SOCKET",
    "MORAY_ACT_FULL_STRIKE",
    "MORAY_ACT_KILL",
    "MORAY_ACT_NONE",
    "MORAY_HOOK_BPF_TAMPER",
    "MORAY_HOOK_BPRM",
    "MORAY_HOOK_SOCKET",
    "MORAY_HOOK_XDP",
    "MORAY_REASON_EXEC_VIOLATION",
    "MORAY_REASON_LOBSTER_L7",
    "MORAY_REASON_SOCKET_VIOLATION",
    "MORAY_REASON_TAMPER_ATTEMPT",
    "MORAY_REASON_UNKNOWN",
    "MORAY_STATE_ACTIVE",
    "MORAY_STATE_EXPIRED",
    "MORAY_STATE_RELEASED",
    "MorayBoundaryProfiler",
    "MorayEvent",
    "MorayHook",
    "MorayQuarantineEntry",
    "MorayQuarantineError",
    "MorayTelemetryConsumer",
    "is_entry_expired",
    "resolve_cgroup_id",
]

if __name__ == "__main__":
    bridge_main()
