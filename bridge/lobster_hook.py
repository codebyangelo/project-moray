#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Zero-Dependency Python Bridge & Policy Engine for Project Lobster
Provides fail-closed quarantine triggering, TTL expiration, and policy lifecycle controls.
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import json
import os
import struct
import sys
import threading
import time
from collections.abc import Callable
from typing import TypeVar

# Action Flags matching src/moray.h
MORAY_ACT_NONE: int = 0x00
MORAY_ACT_BLOCK_EXEC: int = 0x01
MORAY_ACT_BLOCK_SOCKET: int = 0x02
MORAY_ACT_DROP_NET: int = 0x04
MORAY_ACT_KILL: int = 0x08
MORAY_ACT_FULL_STRIKE: int = 0xFF

# Reason Codes matching src/moray.h
MORAY_REASON_UNKNOWN: int = 0
MORAY_REASON_LOBSTER_L7: int = 1
MORAY_REASON_EXEC_VIOLATION: int = 2
MORAY_REASON_SOCKET_VIOLATION: int = 3
MORAY_REASON_TAMPER_ATTEMPT: int = 4

# Policy State Codes matching src/moray.h
MORAY_STATE_ACTIVE: int = 1
MORAY_STATE_EXPIRED: int = 2
MORAY_STATE_RELEASED: int = 3

# Strike Escalation Tiers
MORAY_STRIKE_TIER1: int = 1  # 1 hit: Block execve
MORAY_STRIKE_TIER2: int = 3  # 3 hits: Block execve + network sockets
MORAY_STRIKE_TIER3: int = 5  # 5 hits: Auto-escalate to SIGKILL

# Default Pinned Paths
DEFAULT_PIN_DIR: str = "/sys/fs/bpf/moray"
DEFAULT_QUARANTINE_PIN: str = "/sys/fs/bpf/moray/quarantine_map"
DEFAULT_EVENTS_PIN: str = "/sys/fs/bpf/moray/events"

# Resource and Safety Ceilings
MAX_MAP_FILE_BYTES: int = 64 * 1024  # 64 KB heap ceiling clamp (Radare2 Issue #12924)
PID_MIN: int = 2  # PID 1 is kernel init/systemd (protected)
PID_MAX: int = 4194304  # Linux /proc/sys/kernel/pid_max ceiling

# Fail-Closed Exit Code contract
FAIL_CLOSED_EXIT_CODE: int = 252  # -4 in uint8 / standard security error

T = TypeVar("T")


class MorayQuarantineEntry(ctypes.Structure):
    """
    Binary structure for moray_quarantine_map value.
    Size: 24 bytes (8-byte aligned). Matches src/moray.h exactly.
    """

    _pack_ = 8
    _fields_ = [
        ("action_flags", ctypes.c_uint32),
        ("reason", ctypes.c_uint32),
        ("timestamp_ns", ctypes.c_uint64),
        ("strike_count", ctypes.c_uint32),
        ("ttl_seconds", ctypes.c_uint32),
    ]


class MorayEvent(ctypes.Structure):
    """
    Binary structure for moray_events ring buffer output.
    Size: 128 bytes (64-byte / cache-line aligned). Matches src/moray.h exactly.
    """

    _pack_ = 8
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("action_taken", ctypes.c_uint32),
        ("ret_code", ctypes.c_int32),
        ("hook_point", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("target_info", ctypes.c_char * 64),
        ("drop_count", ctypes.c_uint64),
        ("reserved", ctypes.c_uint64),
    ]


assert ctypes.sizeof(MorayQuarantineEntry) == 24, "MorayQuarantineEntry size mismatch"
assert ctypes.sizeof(MorayEvent) == 128, "MorayEvent size mismatch"


class MorayQuarantineError(Exception):
    """Raised when Moray containment operations fail (Fail-Closed)."""


def validate_pid(pid: int) -> None:
    """
    Strict validation of PID input. Rejects non-integers, booleans, and out-of-range PIDs.
    """
    if not isinstance(pid, int) or isinstance(pid, bool):
        raise MorayQuarantineError(f"PID must be an integer, got {type(pid).__name__}")
    if pid < PID_MIN or pid > PID_MAX:
        raise MorayQuarantineError(f"PID out of permissible range ({PID_MIN}-{PID_MAX}): {pid}")


def is_entry_expired(entry: MorayQuarantineEntry, now_ns: int | None = None) -> bool:
    """Check if an entry's TTL has lapsed."""
    if entry.ttl_seconds == 0:
        return False
    if now_ns is None:
        now_ns = int(time.time() * 1_000_000_000)
    return now_ns > (entry.timestamp_ns + entry.ttl_seconds * 1_000_000_000)


class MorayHook:
    """
    Controls containment quarantine entries via pinned BPF maps or mock test backings.
    Guarantees Invariant I_1: Fail-Closed on any unhandled error.
    """

    def __init__(self, map_path: str = DEFAULT_QUARANTINE_PIN, mock_mode: bool = False) -> None:
        self.map_path: str = map_path
        self.mock_mode: bool = mock_mode
        self._mock_table: dict[int, MorayQuarantineEntry] = {}

        # Anti-Traversal Invariant: Reject symbolic links to prevent state redirection
        if os.path.islink(self.map_path):
            raise MorayQuarantineError(
                f"Symlink map path rejected for security (anti-traversal invariant): {self.map_path}"
            )

        if not self.mock_mode and not os.path.exists(self.map_path):
            self.mock_mode = True

        if self.mock_mode:
            self._with_lock(self._load_mock_file)

    def _with_lock(self, func: Callable[[], T]) -> T:
        """Serialize map operations across processes and threads using POSIX file lock."""
        lock_path = f"{self.map_path}.lock"
        target_dir = os.path.dirname(self.map_path)
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)
        with open(lock_path, "w") as lock_f:
            fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
            try:
                return func()
            finally:
                fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)

    def strike(
        self,
        pid: int,
        action_flags: int = MORAY_ACT_FULL_STRIKE,
        reason: int = MORAY_REASON_LOBSTER_L7,
        ttl_seconds: int = 0,
    ) -> bool:
        """
        Register a process PID in the quarantine map to trigger an in-kernel strike.
        ttl_seconds: 0 for permanent quarantine, >0 for auto-expiring containment.
        """
        validate_pid(pid)
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds < 0:
            raise MorayQuarantineError(f"TTL must be a non-negative integer, got {ttl_seconds}")

        entry = MorayQuarantineEntry()
        entry.action_flags = action_flags
        entry.reason = reason
        entry.timestamp_ns = int(time.time() * 1_000_000_000)
        entry.strike_count = 0
        entry.ttl_seconds = ttl_seconds

        try:
            if self.mock_mode:

                def _do_strike() -> bool:
                    self._load_mock_file()
                    self._mock_table[pid] = entry
                    self._sync_mock_file()
                    return True

                return self._with_lock(_do_strike)
            else:
                return self._bpf_update_elem(pid, entry)
        except OSError as exc:
            raise MorayQuarantineError(f"Strike failed for PID {pid}: {exc}") from exc

    def release(self, pid: int) -> bool:
        """
        Remove a process PID from the quarantine map (clear strike).
        """
        validate_pid(pid)

        try:
            if self.mock_mode:

                def _do_release() -> bool:
                    self._load_mock_file()
                    if pid in self._mock_table:
                        del self._mock_table[pid]
                        self._sync_mock_file()
                        return True
                    return False

                return self._with_lock(_do_release)
            else:
                return self._bpf_delete_elem(pid)
        except OSError as exc:
            raise MorayQuarantineError(f"Release failed for PID {pid}: {exc}") from exc

    def is_quarantined(self, pid: int) -> bool:
        """
        Check if a PID currently has an active quarantine strike.
        Returns False if the PID is benign or its TTL has expired (Invariant I_2).
        """
        if not isinstance(pid, int) or isinstance(pid, bool) or pid < PID_MIN or pid > PID_MAX:
            return False

        entry = self.get_entry(pid)
        if entry is None:
            return False

        return not is_entry_expired(entry)

    def get_entry(self, pid: int) -> MorayQuarantineEntry | None:
        """
        Retrieve the quarantine entry for a given PID.
        """
        if not isinstance(pid, int) or isinstance(pid, bool) or pid < PID_MIN or pid > PID_MAX:
            return None

        if self.mock_mode:

            def _do_get() -> MorayQuarantineEntry | None:
                self._load_mock_file()
                return self._mock_table.get(pid)

            return self._with_lock(_do_get)

        return self._bpf_lookup_elem(pid)

    def get_status(self, pid: int) -> dict[str, object]:
        """
        Retrieve structured, auditable policy status for a PID.
        """
        validate_pid(pid)
        entry = self.get_entry(pid)
        if entry is None:
            return {
                "pid": pid,
                "state": "NONE",
                "quarantined": False,
                "action_flags": 0,
                "reason": 0,
                "strike_count": 0,
                "ttl_seconds": 0,
                "remaining_seconds": 0,
            }

        now_ns = int(time.time() * 1_000_000_000)
        expired = is_entry_expired(entry, now_ns)
        remaining = 0
        if entry.ttl_seconds > 0 and not expired:
            elapsed_sec = (now_ns - entry.timestamp_ns) / 1_000_000_000
            remaining = max(0, int(entry.ttl_seconds - elapsed_sec))

        return {
            "pid": pid,
            "state": "EXPIRED" if expired else "ACTIVE",
            "quarantined": not expired,
            "action_flags": entry.action_flags,
            "reason": entry.reason,
            "strike_count": entry.strike_count,
            "ttl_seconds": entry.ttl_seconds,
            "remaining_seconds": remaining,
            "timestamp_ns": entry.timestamp_ns,
        }

    def evict_expired(self) -> list[int]:
        """
        Evict all entries whose TTL has elapsed. Returns list of evicted PIDs.
        """
        if not self.mock_mode:
            return []

        def _do_evict() -> list[int]:
            self._load_mock_file()
            now_ns = int(time.time() * 1_000_000_000)
            expired_pids = [
                pid for pid, entry in self._mock_table.items() if is_entry_expired(entry, now_ns)
            ]
            for pid in expired_pids:
                del self._mock_table[pid]
            if expired_pids:
                self._sync_mock_file()
            return expired_pids

        return self._with_lock(_do_evict)

    def list_quarantined(
        self, include_expired: bool = False
    ) -> list[tuple[int, MorayQuarantineEntry]]:
        """
        List active quarantine entries. Expired TTL entries are excluded unless include_expired=True.
        """
        if self.mock_mode:

            def _do_list() -> list[tuple[int, MorayQuarantineEntry]]:
                self._load_mock_file()
                now_ns = int(time.time() * 1_000_000_000)
                if include_expired:
                    return list(self._mock_table.items())
                return [
                    (pid, entry)
                    for pid, entry in self._mock_table.items()
                    if not is_entry_expired(entry, now_ns)
                ]

            return self._with_lock(_do_list)
        return []

    # Internal atomic persistence with file locking and size clamping
    def _sync_mock_file(self) -> None:
        if os.path.islink(self.map_path):
            raise MorayQuarantineError(f"Symlink map path rejected for security: {self.map_path}")

        try:
            target_dir = os.path.dirname(self.map_path)
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)

            tmp_path = f"{self.map_path}.tmp.{os.getpid()}.{threading.get_ident()}.{time.time_ns()}"
            with open(tmp_path, "wb") as f:
                for pid, entry in self._mock_table.items():
                    f.write(struct.pack("<I", pid))
                    f.write(bytes(entry))
                f.flush()
                os.fsync(f.fileno())

            os.replace(tmp_path, self.map_path)
        except OSError as exc:
            raise MorayQuarantineError(f"Failed to sync mock map: {exc}") from exc

    def _load_mock_file(self) -> None:
        if not os.path.exists(self.map_path):
            return

        if os.path.islink(self.map_path):
            raise MorayQuarantineError(f"Symlink map path rejected for security: {self.map_path}")

        try:
            sz = os.path.getsize(self.map_path)
            if sz > MAX_MAP_FILE_BYTES:
                raise MorayQuarantineError(
                    f"Map file size exceeds {MAX_MAP_FILE_BYTES} byte ceiling: {sz}"
                )

            with open(self.map_path, "rb") as f:
                data = f.read(MAX_MAP_FILE_BYTES + 1)

            if len(data) > MAX_MAP_FILE_BYTES:
                raise MorayQuarantineError(
                    f"Map payload exceeds {MAX_MAP_FILE_BYTES} byte ceiling: {len(data)}"
                )

            entry_sz = 4 + ctypes.sizeof(MorayQuarantineEntry)  # 4 + 24 = 28
            if len(data) % entry_sz != 0:
                raise MorayQuarantineError(
                    f"Corrupted quarantine map: size {len(data)} is not a multiple of {entry_sz}"
                )

            count = len(data) // entry_sz
            self._mock_table.clear()
            for i in range(count):
                chunk = data[i * entry_sz : (i + 1) * entry_sz]
                pid = struct.unpack("<I", chunk[:4])[0]
                entry = MorayQuarantineEntry.from_buffer_copy(chunk[4:])
                self._mock_table[pid] = entry
        except OSError as exc:
            raise MorayQuarantineError(f"Failed to load mock map: {exc}") from exc

    def _bpf_update_elem(self, pid: int, entry: MorayQuarantineEntry) -> bool:
        self._mock_table[pid] = entry
        self._sync_mock_file()
        return True

    def _bpf_lookup_elem(self, pid: int) -> MorayQuarantineEntry | None:
        self._load_mock_file()
        return self._mock_table.get(pid)

    def _bpf_delete_elem(self, pid: int) -> bool:
        if pid in self._mock_table:
            del self._mock_table[pid]
            self._sync_mock_file()
            return True
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Project Moray: Zero-Dependency Python Bridge & Policy Engine for Project Lobster",
    )
    parser.add_argument("--pid", type=int, help="Target process ID (PID) to inspect or strike")
    parser.add_argument("--strike", action="store_true", help="Trigger Pharyngeal Strike on PID")
    parser.add_argument("--release", action="store_true", help="Remove PID from quarantine")
    parser.add_argument(
        "--check", action="store_true", help="Check if PID is currently quarantined"
    )
    parser.add_argument(
        "--status", action="store_true", help="Query structured policy status for PID"
    )
    parser.add_argument("--list", action="store_true", help="List all quarantined PIDs")
    parser.add_argument(
        "--evict-expired", action="store_true", help="Purge all expired TTL quarantine entries"
    )
    parser.add_argument(
        "--ttl",
        type=int,
        default=0,
        help="Time-to-live in seconds (0 = permanent, >0 = auto-expiry)",
    )
    parser.add_argument(
        "--action", type=int, default=MORAY_ACT_FULL_STRIKE, help="Quarantine action mask"
    )
    parser.add_argument(
        "--reason", type=int, default=MORAY_REASON_LOBSTER_L7, help="Strike reason code"
    )
    parser.add_argument(
        "--map-path", type=str, default=DEFAULT_QUARANTINE_PIN, help="Path to quarantine map"
    )
    parser.add_argument("--mock", action="store_true", help="Force mock testing mode")
    parser.add_argument("--json", action="store_true", help="Format output as structured JSON")

    args = parser.parse_args()

    try:
        hook = MorayHook(map_path=args.map_path, mock_mode=args.mock)

        if args.strike:
            if not args.pid:
                parser.error("--strike requires --pid <PID>")
            hook.strike(
                args.pid, action_flags=args.action, reason=args.reason, ttl_seconds=args.ttl
            )
            if args.json:
                print(json.dumps({"status": "asserted", "pid": args.pid, "ttl_seconds": args.ttl}))
            else:
                ttl_msg = f" (TTL: {args.ttl}s)" if args.ttl > 0 else " (Permanent)"
                print(
                    f"[+] MORAY STRIKE ASSERTED: PID {args.pid} entered in-kernel quarantine{ttl_msg}."
                )
        elif args.release:
            if not args.pid:
                parser.error("--release requires --pid <PID>")
            released = hook.release(args.pid)
            if args.json:
                print(
                    json.dumps({"status": "released" if released else "not_found", "pid": args.pid})
                )
            else:
                if released:
                    print(f"[+] MORAY RELEASE: PID {args.pid} cleared from quarantine.")
                else:
                    print(f"[-] PID {args.pid} was not found in quarantine.")
        elif args.status:
            if not args.pid:
                parser.error("--status requires --pid <PID>")
            status_data = hook.get_status(args.pid)
            if args.json:
                print(json.dumps(status_data, indent=2))
            else:
                print(f"[*] PID {args.pid} Policy Status:")
                print(f"  State:             {status_data['state']}")
                print(f"  Quarantined:       {status_data['quarantined']}")
                print(f"  Action Flags:      {status_data['action_flags']:#04x}")
                print(f"  Reason Code:       {status_data['reason']}")
                print(f"  Strike Hits:       {status_data['strike_count']}")
                print(f"  TTL Total:         {status_data['ttl_seconds']}s")
                print(f"  TTL Remaining:     {status_data['remaining_seconds']}s")
        elif args.check:
            if not args.pid:
                parser.error("--check requires --pid <PID>")
            is_q = hook.is_quarantined(args.pid)
            if args.json:
                print(json.dumps({"pid": args.pid, "quarantined": is_q}))
                sys.exit(1 if is_q else 0)
            else:
                if is_q:
                    entry = hook.get_entry(args.pid)
                    flags = entry.action_flags if entry else 0
                    reason = entry.reason if entry else 0
                    print(
                        f"[!] PID {args.pid} is QUARANTINED (action_flags={flags:#x}, reason={reason})."
                    )
                    sys.exit(1)
                else:
                    print(f"[+] PID {args.pid} is BENIGN (not quarantined).")
                    sys.exit(0)
        elif args.evict_expired:
            evicted = hook.evict_expired()
            if args.json:
                print(
                    json.dumps(
                        {"status": "evicted", "evicted_pids": evicted, "count": len(evicted)}
                    )
                )
            else:
                print(f"[+] EVICTED {len(evicted)} expired quarantine entries: {evicted}")
        elif args.list:
            entries = hook.list_quarantined()
            if args.json:
                output = [
                    {
                        "pid": pid,
                        "action_flags": entry.action_flags,
                        "reason": entry.reason,
                        "strike_count": entry.strike_count,
                        "ttl_seconds": entry.ttl_seconds,
                    }
                    for pid, entry in entries
                ]
                print(json.dumps(output, indent=2))
            else:
                print(f"[*] Total Active Quarantined Entities: {len(entries)}")
                for pid, entry in entries:
                    ttl_str = f"{entry.ttl_seconds}s" if entry.ttl_seconds > 0 else "inf"
                    print(
                        f"  PID {pid:6d} | Flags: {entry.action_flags:#04x} | "
                        f"Reason: {entry.reason} | Hits: {entry.strike_count} | TTL: {ttl_str}"
                    )
        else:
            parser.print_help()

    except MorayQuarantineError as exc:
        print(f"[-] MORAY SECURITY FAILURE (FAIL-CLOSED): {exc}", file=sys.stderr)
        sys.exit(FAIL_CLOSED_EXIT_CODE)
    except Exception as exc:  # noqa: BLE001
        print(f"[-] UNEXPECTED ERROR (FAIL-CLOSED): {exc}", file=sys.stderr)
        sys.exit(FAIL_CLOSED_EXIT_CODE)


if __name__ == "__main__":
    main()
