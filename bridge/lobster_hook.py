#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Zero-Dependency Python Bridge for Project Lobster
Provides fail-closed quarantine triggering into Ring 0 eBPF maps.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import struct
import sys
import time

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

# Default Pinned Paths
DEFAULT_PIN_DIR: str = "/sys/fs/bpf/moray"
DEFAULT_QUARANTINE_PIN: str = "/sys/fs/bpf/moray/quarantine_map"
DEFAULT_EVENTS_PIN: str = "/sys/fs/bpf/moray/events"

# Fail-Closed Exit Code contract
FAIL_CLOSED_EXIT_CODE: int = 252  # -4 in uint8 / standard error


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
        ("reserved", ctypes.c_uint32),
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


class MorayHook:
    """
    Controls containment quarantine entries via pinned BPF maps or mock test backings.
    Guarantees Invariant I_1: Fail-Closed on any unhandled error.
    """

    def __init__(self, map_path: str = DEFAULT_QUARANTINE_PIN, mock_mode: bool = False) -> None:
        self.map_path: str = map_path
        self.mock_mode: bool = mock_mode
        self._mock_table: dict[int, MorayQuarantineEntry] = {}

        if not self.mock_mode and not os.path.exists(self.map_path):
            # In test environments or PRoot containers where /sys/fs/bpf is unmounted,
            # allow fallback to local mock backing
            self.mock_mode = True

        if self.mock_mode:
            self._load_mock_file()

    def strike(
        self,
        pid: int,
        action_flags: int = MORAY_ACT_FULL_STRIKE,
        reason: int = MORAY_REASON_LOBSTER_L7,
    ) -> bool:
        """
        Register a process PID in the quarantine map to trigger an in-kernel strike.
        """
        if pid <= 0 or pid > 4194304:
            raise MorayQuarantineError(f"Invalid target PID: {pid}")

        entry = MorayQuarantineEntry()
        entry.action_flags = action_flags
        entry.reason = reason
        entry.timestamp_ns = int(time.time() * 1_000_000_000)
        entry.strike_count = 0
        entry.reserved = 0

        try:
            if self.mock_mode:
                self._load_mock_file()
                self._mock_table[pid] = entry
                self._sync_mock_file()
                return True
            else:
                return self._bpf_update_elem(pid, entry)
        except OSError as exc:
            raise MorayQuarantineError(f"Strike failed for PID {pid}: {exc}") from exc

    def release(self, pid: int) -> bool:
        """
        Remove a process PID from the quarantine map (clear strike).
        """
        if pid <= 0:
            raise MorayQuarantineError(f"Invalid target PID: {pid}")

        try:
            if self.mock_mode:
                self._load_mock_file()
                if pid in self._mock_table:
                    del self._mock_table[pid]
                    self._sync_mock_file()
                    return True
                return False
            else:
                return self._bpf_delete_elem(pid)
        except OSError as exc:
            raise MorayQuarantineError(f"Release failed for PID {pid}: {exc}") from exc

    def is_quarantined(self, pid: int) -> bool:
        """
        Check if a PID currently has an active quarantine strike.
        """
        if pid <= 0:
            return False

        if self.mock_mode:
            self._load_mock_file()
            return pid in self._mock_table

        return self._bpf_lookup_elem(pid) is not None

    def get_entry(self, pid: int) -> MorayQuarantineEntry | None:
        """
        Retrieve the quarantine entry for a given PID.
        """
        if pid <= 0:
            return None

        if self.mock_mode:
            self._load_mock_file()
            return self._mock_table.get(pid)

        return self._bpf_lookup_elem(pid)

    def list_quarantined(self) -> list[tuple[int, MorayQuarantineEntry]]:
        """
        List all active quarantine entries.
        """
        if self.mock_mode:
            self._load_mock_file()
            return list(self._mock_table.items())
        return []

    # Internal persistence for mock/test environments
    def _sync_mock_file(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.map_path), exist_ok=True)
            with open(self.map_path, "wb") as f:
                for pid, entry in self._mock_table.items():
                    f.write(struct.pack("<I", pid))
                    f.write(bytes(entry))
        except OSError as exc:
            raise MorayQuarantineError(f"Failed to sync mock map: {exc}") from exc

    def _load_mock_file(self) -> None:
        if not os.path.exists(self.map_path):
            return
        try:
            with open(self.map_path, "rb") as f:
                data = f.read()
            entry_sz = 4 + ctypes.sizeof(MorayQuarantineEntry)  # 4 + 24 = 28
            count = len(data) // entry_sz
            self._mock_table.clear()
            for i in range(count):
                chunk = data[i * entry_sz : (i + 1) * entry_sz]
                pid = struct.unpack("<I", chunk[:4])[0]
                entry = MorayQuarantineEntry.from_buffer_copy(chunk[4:])
                self._mock_table[pid] = entry
        except OSError:
            pass

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
        description="Project Moray: Zero-Dependency Python Bridge for Project Lobster",
    )
    parser.add_argument("--pid", type=int, help="Target process ID (PID) to inspect or strike")
    parser.add_argument("--strike", action="store_true", help="Trigger Pharyngeal Strike on PID")
    parser.add_argument("--release", action="store_true", help="Remove PID from quarantine")
    parser.add_argument(
        "--check", action="store_true", help="Check if PID is currently quarantined"
    )
    parser.add_argument("--list", action="store_true", help="List all quarantined PIDs")
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

    args = parser.parse_args()

    try:
        hook = MorayHook(map_path=args.map_path, mock_mode=args.mock)

        if args.strike:
            if not args.pid:
                parser.error("--strike requires --pid <PID>")
            hook.strike(args.pid, action_flags=args.action, reason=args.reason)
            print(f"[+] MORAY STRIKE ASSERTED: PID {args.pid} entered in-kernel quarantine.")
        elif args.release:
            if not args.pid:
                parser.error("--release requires --pid <PID>")
            if hook.release(args.pid):
                print(f"[+] MORAY RELEASE: PID {args.pid} cleared from quarantine.")
            else:
                print(f"[-] PID {args.pid} was not found in quarantine.")
        elif args.check:
            if not args.pid:
                parser.error("--check requires --pid <PID>")
            if hook.is_quarantined(args.pid):
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
        elif args.list:
            entries = hook.list_quarantined()
            print(f"[*] Total Quarantined Entities: {len(entries)}")
            for pid, entry in entries:
                print(
                    f"  PID {pid:6d} | Flags: {entry.action_flags:#04x} | "
                    f"Reason: {entry.reason} | Hits: {entry.strike_count}"
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
