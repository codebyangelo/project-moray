#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Zero-Dependency Python Bridge & Policy Engine for Project Lobster
Provides fail-closed quarantine triggering, TTL expiration, and policy lifecycle controls.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import fcntl
import json
import os
import socket
import stat
import struct
import sys
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any, TypeVar

# Action Flags matching src/moray.h
MORAY_ACT_NONE: int = 0x00
MORAY_ACT_BLOCK_EXEC: int = 0x01
MORAY_ACT_BLOCK_SOCKET: int = 0x02
MORAY_ACT_DROP_NET: int = 0x04
MORAY_ACT_KILL: int = 0x08
MORAY_ACT_ALLOW_LOOPBACK: int = 0x10  # Granular policy: Allow AF_UNIX and 127.0.0.1/::1
MORAY_ACT_FULL_STRIKE: int = 0xFF

# Reason Codes matching src/moray.h
MORAY_REASON_UNKNOWN: int = 0
MORAY_REASON_LOBSTER_L7: int = 1
MORAY_REASON_EXEC_VIOLATION: int = 2
MORAY_REASON_SOCKET_VIOLATION: int = 3
MORAY_REASON_TAMPER_ATTEMPT: int = 4

# Hook Point Identifiers matching src/moray.h
MORAY_HOOK_NONE: int = 0
MORAY_HOOK_BPRM: int = 1
MORAY_HOOK_SOCKET: int = 2
MORAY_HOOK_BPF_TAMPER: int = 3
MORAY_HOOK_XDP: int = 4

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
DEFAULT_XDP_PIN: str = "/sys/fs/bpf/moray/xdp_drop_map"
DEFAULT_CGROUP_PIN: str = "/sys/fs/bpf/moray/cgroup_map"
DEFAULT_MOCK_QUARANTINE_FILE: str = "/tmp/moray_quarantine_mock.bin"
DEFAULT_MOCK_XDP_FILE: str = "/tmp/moray_xdp_mock.bin"
DEFAULT_MOCK_EVENTS_FILE: str = "/tmp/moray_events_mock.jsonl"
DEFAULT_MOCK_CGROUP_FILE: str = "/tmp/moray_cgroup_mock.bin"

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

    def to_dict(self) -> dict[str, Any]:
        """Convert binary event to structured dictionary."""
        hook_names = {
            MORAY_HOOK_NONE: "NONE",
            MORAY_HOOK_BPRM: "BPRM_CHECK_SECURITY",
            MORAY_HOOK_SOCKET: "SOCKET_CONNECT",
            MORAY_HOOK_BPF_TAMPER: "BPF_ANTI_TAMPER",
            MORAY_HOOK_XDP: "XDP_FILTER",
        }
        comm_str = self.comm.decode("utf-8", errors="replace").rstrip("\x00")
        target_str = self.target_info.decode("utf-8", errors="replace").rstrip("\x00")
        return {
            "timestamp_ns": int(self.timestamp_ns),
            "pid": int(self.pid),
            "tgid": int(self.tgid),
            "uid": int(self.uid),
            "action_taken": int(self.action_taken),
            "ret_code": int(self.ret_code),
            "hook_point": int(self.hook_point),
            "hook_name": hook_names.get(int(self.hook_point), f"HOOK_UNKNOWN_{self.hook_point}"),
            "drop_count": int(self.drop_count),
            "comm": comm_str,
            "target_info": target_str,
        }

    def to_json(self) -> str:
        """Format as JSON string."""
        return json.dumps(self.to_dict())

    def format_log(self) -> str:
        """Format as human-readable audit log line."""
        d = self.to_dict()
        ts_s = d["timestamp_ns"] / 1_000_000_000
        time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts_s))
        millis = int((ts_s % 1) * 1000)
        return (
            f"[{time_str}.{millis:03d}] PID {d['pid']} (tgid: {d['tgid']}, comm: '{d['comm']}') "
            f"INTERCEPTED at {d['hook_name']} (action: 0x{d['action_taken']:02x}, "
            f"ret: {d['ret_code']}, strikes: {d['drop_count']})"
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MorayEvent:
        """Instantiate MorayEvent from dictionary values."""
        ev = cls()
        ev.timestamp_ns = int(data.get("timestamp_ns", 0))
        ev.pid = int(data.get("pid", 0))
        ev.tgid = int(data.get("tgid", 0))
        ev.uid = int(data.get("uid", 0))
        ev.action_taken = int(data.get("action_taken", 0))
        ev.ret_code = int(data.get("ret_code", 0))
        ev.hook_point = int(data.get("hook_point", 0))
        ev.drop_count = int(data.get("drop_count", 0))
        ev.reserved = 0
        comm_b = str(data.get("comm", "")).encode("utf-8")[:15]
        ev.comm = comm_b + b"\x00" * (16 - len(comm_b))
        target_b = str(data.get("target_info", "")).encode("utf-8")[:63]
        ev.target_info = target_b + b"\x00" * (64 - len(target_b))
        return ev


assert ctypes.sizeof(MorayQuarantineEntry) == 24, "MorayQuarantineEntry size mismatch"
assert ctypes.sizeof(MorayEvent) == 128, "MorayEvent size mismatch"

# BPF Syscall Command Codes & Flags
BPF_MAP_CREATE: int = 0
BPF_MAP_LOOKUP_ELEM: int = 1
BPF_MAP_UPDATE_ELEM: int = 2
BPF_MAP_DELETE_ELEM: int = 3
BPF_MAP_GET_NEXT_KEY: int = 4
BPF_OBJ_PIN: int = 6
BPF_OBJ_GET: int = 7
BPF_ANY: int = 0


class BpfAttrObjGet(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]


class BpfAttrMapElem(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("pad0", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


def get_bpf_syscall_nr() -> int:
    """Return platform-specific __NR_bpf syscall number."""
    arch = os.uname().machine
    if arch in ("x86_64", "amd64"):
        return 321
    if arch in ("aarch64", "arm64"):
        return 280
    if arch.startswith("arm"):
        return 386
    return 321


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


def validate_ipv4(ip_str: object) -> None:
    """
    Strict validation of IPv4 address.
    Rejects non-strings, booleans, non-dotted, out-of-range octets, or malformed addresses fail-closed.
    """
    if not isinstance(ip_str, str) or isinstance(ip_str, bool):
        raise MorayQuarantineError(f"IP address must be a string, got {type(ip_str).__name__}")
    parts = ip_str.strip().split(".")
    if len(parts) != 4:
        raise MorayQuarantineError(f"Invalid IPv4 format (expected 4 dotted octets): '{ip_str}'")
    for part in parts:
        if not part.isdigit():
            raise MorayQuarantineError(f"Invalid non-numeric octet in IP: '{ip_str}'")
        val = int(part)
        if val < 0 or val > 255:
            raise MorayQuarantineError(
                f"Octet value {val} out of permissible range (0-255): '{ip_str}'"
            )


def ip_to_wire_bytes(ip_str: str) -> bytes:
    """Convert dotted IPv4 string to 4 bytes in network wire order (big-endian)."""
    validate_ipv4(ip_str)
    try:
        return socket.inet_aton(ip_str.strip())
    except OSError as exc:
        raise MorayQuarantineError(f"Failed to parse IPv4 address '{ip_str}': {exc}") from exc


def wire_bytes_to_ip(raw: bytes) -> str:
    """Convert 4-byte network wire buffer back to dotted IPv4 string."""
    if len(raw) != 4:
        raise MorayQuarantineError(f"Expected 4 bytes for IPv4 address, got {len(raw)}")
    return socket.inet_ntoa(raw)


def resolve_cgroup_id(target: object) -> int:
    """
    Resolve a cgroup path, decimal integer, or hex string to a 64-bit unsigned cgroup ID.
    Rejects negative numbers, booleans, zero, out-of-range IDs (> 2^64-1), and symlinks.
    """
    if isinstance(target, bool) or target is None:
        raise MorayQuarantineError(
            f"Cgroup identifier must be an integer or path string, got {type(target).__name__}"
        )

    if isinstance(target, int):
        if target <= 0 or target > 0xFFFFFFFFFFFFFFFF:
            raise MorayQuarantineError(
                f"Cgroup ID out of 64-bit unsigned range (1 to 2^64-1): {target}"
            )
        return target

    if not isinstance(target, str):
        raise MorayQuarantineError(
            f"Cgroup identifier must be an integer or path string, got {type(target).__name__}"
        )

    s = target.strip()
    if not s:
        raise MorayQuarantineError("Cgroup target cannot be empty")

    # Direct numeric parsing (e.g. "12345" or "0xabcd")
    if s.isdigit() or (s.startswith("0x") and len(s) > 2):
        try:
            val = int(s, 0)
            if val <= 0 or val > 0xFFFFFFFFFFFFFFFF:
                raise MorayQuarantineError(f"Cgroup ID out of 64-bit unsigned range: {val}")
            return val
        except ValueError:
            pass

    # Path resolution: check anti-traversal symlink invariant
    if os.path.islink(s):
        raise MorayQuarantineError(
            f"Symlink cgroup path rejected for security (anti-traversal invariant): {s}"
        )

    if not os.path.exists(s):
        raise MorayQuarantineError(f"Cgroup path does not exist: {s}")

    st = os.stat(s)
    if not stat.S_ISDIR(st.st_mode):
        raise MorayQuarantineError(f"Cgroup target path must be a directory: {s}")

    cgroup_id = int(st.st_ino)
    if cgroup_id <= 0 or cgroup_id > 0xFFFFFFFFFFFFFFFF:
        raise MorayQuarantineError(f"Extracted cgroup inode {cgroup_id} out of 64-bit range")
    return cgroup_id


def is_entry_expired(entry: MorayQuarantineEntry, now_ns: int | None = None) -> bool:
    """Check if an entry's TTL has lapsed."""
    if entry.ttl_seconds == 0:
        return False
    if now_ns is None:
        now_ns = int(time.time() * 1_000_000_000)
    return now_ns > (entry.timestamp_ns + entry.ttl_seconds * 1_000_000_000)


class MorayTelemetryConsumer:
    """
    Consumes binary MorayEvent records from the Linux BPF ring buffer (/sys/fs/bpf/moray/events)
    or a mock file backing under Invariant I_6 (Hermetic Telemetry & Ringbuf Non-Blocking Dispatch).
    """

    def __init__(
        self,
        events_path: str = DEFAULT_EVENTS_PIN,
        mock_mode: bool = False,
    ) -> None:
        self.events_path: str = events_path
        self.mock_mode: bool = mock_mode
        self._events_fd: int = -1
        self._libbpf: ctypes.CDLL | None = None
        self._rb: ctypes.c_void_p | None = None
        self._c_cb: Any = None
        self._buffered_events: list[MorayEvent] = []
        self._mock_offset: int = 0
        self._lock = threading.Lock()

        # Anti-Traversal Invariant: Reject symbolic links to prevent redirection
        if os.path.islink(self.events_path):
            raise MorayQuarantineError(
                f"Symlink events path rejected for security (anti-traversal invariant): {self.events_path}"
            )

        if not self.mock_mode and not os.path.exists(self.events_path):
            self.mock_mode = True

        if self.mock_mode and self.events_path == DEFAULT_EVENTS_PIN:
            self.events_path = DEFAULT_MOCK_EVENTS_FILE

        if not self.mock_mode:
            self._init_live_ringbuf()

    def _init_live_ringbuf(self) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        b_path = self.events_path.encode("utf-8")
        path_buf = ctypes.create_string_buffer(b_path)
        attr = BpfAttrObjGet(
            pathname=ctypes.cast(path_buf, ctypes.c_void_p).value or 0,
            bpf_fd=0,
            file_flags=0,
        )
        nr = get_bpf_syscall_nr()
        fd = libc.syscall(nr, BPF_OBJ_GET, ctypes.byref(attr), ctypes.sizeof(attr))
        if fd < 0:
            err = ctypes.get_errno()
            raise MorayQuarantineError(
                f"Failed to access pinned events ringbuf at '{self.events_path}': {os.strerror(err)} (code {err})"
            )
        self._events_fd = fd

        lib_name = ctypes.util.find_library("bpf") or "libbpf.so.1"
        try:
            self._libbpf = ctypes.CDLL(lib_name, use_errno=True)
        except OSError as exc:
            os.close(self._events_fd)
            self._events_fd = -1
            raise MorayQuarantineError(f"Failed to load libbpf shared library: {exc}") from exc

        RINGBUF_CB = ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
        )

        def _raw_cb(ctx: ctypes.c_void_p, data: ctypes.c_void_p, size: int) -> int:
            if size >= ctypes.sizeof(MorayEvent):
                raw = ctypes.string_at(data, ctypes.sizeof(MorayEvent))
                ev = MorayEvent.from_buffer_copy(raw)
                with self._lock:
                    self._buffered_events.append(ev)
            return 0

        self._c_cb = RINGBUF_CB(_raw_cb)
        self._libbpf.ring_buffer__new.argtypes = [
            ctypes.c_int,
            RINGBUF_CB,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self._libbpf.ring_buffer__new.restype = ctypes.c_void_p
        self._libbpf.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self._libbpf.ring_buffer__poll.restype = ctypes.c_int
        self._libbpf.ring_buffer__consume.argtypes = [ctypes.c_void_p]
        self._libbpf.ring_buffer__consume.restype = ctypes.c_int
        self._libbpf.ring_buffer__free.argtypes = [ctypes.c_void_p]
        self._libbpf.ring_buffer__free.restype = None

        self._rb = self._libbpf.ring_buffer__new(self._events_fd, self._c_cb, None, None)
        if not self._rb:
            err = ctypes.get_errno()
            os.close(self._events_fd)
            self._events_fd = -1
            raise MorayQuarantineError(f"ring_buffer__new failed (errno={err})")

    def emit_mock_event(self, event: MorayEvent | dict[str, Any]) -> None:
        """Append an event to the mock events file backing."""
        if not isinstance(event, MorayEvent):
            event = MorayEvent.from_dict(event)

        lock_path = f"{self.events_path}.lock"
        try:
            with open(lock_path, "a+") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    with open(self.events_path, "a", encoding="utf-8") as f:
                        f.write(event.to_json() + "\n")
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise MorayQuarantineError(f"Failed to emit mock event: {exc}") from exc

    def poll(self, timeout_ms: int = 100) -> list[MorayEvent]:
        """Poll the ring buffer (or mock backing) for new events."""
        if self.mock_mode:
            new_events: list[MorayEvent] = []
            if os.path.exists(self.events_path):
                lock_path = f"{self.events_path}.lock"
                try:
                    with open(lock_path, "a+") as lock_file:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
                        try:
                            with open(self.events_path, "r", encoding="utf-8") as f:
                                f.seek(self._mock_offset)
                                for line in f:
                                    line = line.strip()
                                    if line:
                                        try:
                                            d = json.loads(line)
                                            new_events.append(MorayEvent.from_dict(d))
                                        except (json.JSONDecodeError, ValueError):
                                            continue
                                self._mock_offset = f.tell()
                        finally:
                            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            return new_events
        else:
            if not self._rb or not self._libbpf:
                return []
            self._libbpf.ring_buffer__poll(self._rb, timeout_ms)
            with self._lock:
                ret = list(self._buffered_events)
                self._buffered_events.clear()
            return ret

    def read_all_mock(self) -> list[MorayEvent]:
        """Read all events from mock file from beginning without advancing stream offset."""
        events: list[MorayEvent] = []
        if self.mock_mode and os.path.exists(self.events_path):
            lock_path = f"{self.events_path}.lock"
            try:
                with open(lock_path, "a+") as lock_file:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
                    try:
                        with open(self.events_path, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        d = json.loads(line)
                                        events.append(MorayEvent.from_dict(d))
                                    except (json.JSONDecodeError, ValueError):
                                        continue
                    finally:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        return events

    def close(self) -> None:
        if self._rb and self._libbpf:
            self._libbpf.ring_buffer__free(self._rb)
            self._rb = None
        if self._events_fd >= 0:
            os.close(self._events_fd)
            self._events_fd = -1


class MorayHook:
    """
    Controls containment quarantine entries via pinned BPF maps or mock test backings.
    Guarantees Invariant I_1: Fail-Closed on any unhandled error.
    """

    def __init__(
        self,
        map_path: str = DEFAULT_QUARANTINE_PIN,
        events_path: str = DEFAULT_EVENTS_PIN,
        xdp_map_path: str = DEFAULT_XDP_PIN,
        cgroup_map_path: str = DEFAULT_CGROUP_PIN,
        mock_mode: bool = False,
    ) -> None:
        self.map_path: str = map_path
        self.events_path: str = events_path
        self.xdp_map_path: str = xdp_map_path
        self.cgroup_map_path: str = cgroup_map_path
        self.mock_mode: bool = mock_mode
        self._mock_table: dict[int, MorayQuarantineEntry] = {}
        self._mock_xdp_table: dict[bytes, int] = {}
        self._mock_cgroup_table: dict[int, MorayQuarantineEntry] = {}
        self._bpf_map_fd: int = -1
        self._bpf_xdp_fd: int = -1
        self._bpf_cgroup_fd: int = -1
        self._consumer: MorayTelemetryConsumer | None = None

        # Anti-Traversal Invariant: Reject symbolic links to prevent state redirection
        if os.path.islink(self.map_path):
            raise MorayQuarantineError(
                f"Symlink map path rejected for security (anti-traversal invariant): {self.map_path}"
            )
        if os.path.islink(self.events_path):
            raise MorayQuarantineError(
                f"Symlink events path rejected for security (anti-traversal invariant): {self.events_path}"
            )
        if os.path.islink(self.xdp_map_path):
            raise MorayQuarantineError(
                f"Symlink xdp map path rejected for security (anti-traversal invariant): {self.xdp_map_path}"
            )
        if os.path.islink(self.cgroup_map_path):
            raise MorayQuarantineError(
                f"Symlink cgroup map path rejected for security (anti-traversal invariant): {self.cgroup_map_path}"
            )

        if not self.mock_mode and not os.path.exists(self.map_path):
            self.mock_mode = True

        if self.mock_mode:
            if self.map_path == DEFAULT_QUARANTINE_PIN:
                self.map_path = DEFAULT_MOCK_QUARANTINE_FILE
            if self.xdp_map_path == DEFAULT_XDP_PIN:
                self.xdp_map_path = DEFAULT_MOCK_XDP_FILE
            if self.events_path == DEFAULT_EVENTS_PIN:
                self.events_path = DEFAULT_MOCK_EVENTS_FILE
            if self.cgroup_map_path == DEFAULT_CGROUP_PIN:
                self.cgroup_map_path = DEFAULT_MOCK_CGROUP_FILE
            self._with_lock(self._load_mock_file)
            self._with_xdp_lock(self._load_mock_xdp_file)
            self._with_cgroup_lock(self._load_mock_cgroup_file)
        else:
            self._open_bpf_map()
            if os.path.exists(self.xdp_map_path):
                self._open_bpf_xdp_map()
            if os.path.exists(self.cgroup_map_path):
                self._open_bpf_cgroup_map()

    def get_consumer(self) -> MorayTelemetryConsumer:
        """Get or initialize the telemetry consumer."""
        if self._consumer is None:
            self._consumer = MorayTelemetryConsumer(
                events_path=self.events_path,
                mock_mode=self.mock_mode,
            )
        return self._consumer

    def emit_event(self, event: MorayEvent | dict[str, Any]) -> None:
        """Emit a telemetry event (writes to mock store in mock mode)."""
        consumer = self.get_consumer()
        if consumer.mock_mode:
            consumer.emit_mock_event(event)

    def tail_events(
        self,
        count: int = 10,
        follow: bool = False,
        timeout_seconds: float | None = None,
    ) -> Iterator[dict[str, Any]]:
        """
        Tail or follow Ring 0 telemetry events.
        Yields event dictionaries.
        """
        consumer = self.get_consumer()
        start_time = time.time()
        yielded = 0

        # When not following in mock mode, read historical events
        if not follow and consumer.mock_mode:
            all_events = consumer.read_all_mock()
            slice_events = all_events[-count:] if count > 0 else all_events
            for ev in slice_events:
                yield ev.to_dict()
            return

        while True:
            if timeout_seconds is not None and (time.time() - start_time) >= timeout_seconds:
                break
            batch = consumer.poll(timeout_ms=100)
            for ev in batch:
                yield ev.to_dict()
                yielded += 1
                if not follow and count > 0 and yielded >= count:
                    return

            if not follow:
                break

            if not batch:
                time.sleep(0.05)

    def _open_bpf_map(self) -> None:
        """Open pinned BPF map via sys_bpf(BPF_OBJ_GET)."""
        libc = ctypes.CDLL(None, use_errno=True)
        b_path = self.map_path.encode("utf-8")
        path_buf = ctypes.create_string_buffer(b_path)
        attr = BpfAttrObjGet(
            pathname=ctypes.cast(path_buf, ctypes.c_void_p).value or 0,
            bpf_fd=0,
            file_flags=0,
        )
        nr = get_bpf_syscall_nr()
        fd = libc.syscall(nr, BPF_OBJ_GET, ctypes.byref(attr), ctypes.sizeof(attr))
        if fd < 0:
            err = ctypes.get_errno()
            raise MorayQuarantineError(
                f"Failed to access pinned BPF map at '{self.map_path}': {os.strerror(err)} (code {err})"
            )
        self._bpf_map_fd = fd

    def _open_bpf_xdp_map(self) -> None:
        """Open pinned XDP drop map via sys_bpf(BPF_OBJ_GET)."""
        libc = ctypes.CDLL(None, use_errno=True)
        b_path = self.xdp_map_path.encode("utf-8")
        path_buf = ctypes.create_string_buffer(b_path)
        attr = BpfAttrObjGet(
            pathname=ctypes.cast(path_buf, ctypes.c_void_p).value or 0,
            bpf_fd=0,
            file_flags=0,
        )
        nr = get_bpf_syscall_nr()
        fd = libc.syscall(nr, BPF_OBJ_GET, ctypes.byref(attr), ctypes.sizeof(attr))
        if fd < 0:
            err = ctypes.get_errno()
            raise MorayQuarantineError(
                f"Failed to access pinned XDP map at '{self.xdp_map_path}': {os.strerror(err)} (code {err})"
            )
        self._bpf_xdp_fd = fd

    def _open_bpf_cgroup_map(self) -> None:
        """Open pinned cgroup map via sys_bpf(BPF_OBJ_GET)."""
        libc = ctypes.CDLL(None, use_errno=True)
        b_path = self.cgroup_map_path.encode("utf-8")
        path_buf = ctypes.create_string_buffer(b_path)
        attr = BpfAttrObjGet(
            pathname=ctypes.cast(path_buf, ctypes.c_void_p).value or 0,
            bpf_fd=0,
            file_flags=0,
        )
        nr = get_bpf_syscall_nr()
        fd = libc.syscall(nr, BPF_OBJ_GET, ctypes.byref(attr), ctypes.sizeof(attr))
        if fd < 0:
            err = ctypes.get_errno()
            raise MorayQuarantineError(
                f"Failed to access pinned cgroup map at '{self.cgroup_map_path}': {os.strerror(err)} (code {err})"
            )
        self._bpf_cgroup_fd = fd

    def close(self) -> None:
        if self._consumer:
            self._consumer.close()
            self._consumer = None
        if self._bpf_map_fd >= 0:
            os.close(self._bpf_map_fd)
            self._bpf_map_fd = -1
        if self._bpf_xdp_fd >= 0:
            os.close(self._bpf_xdp_fd)
            self._bpf_xdp_fd = -1
        if self._bpf_cgroup_fd >= 0:
            os.close(self._bpf_cgroup_fd)
            self._bpf_cgroup_fd = -1

    def _with_lock(self, func: Callable[[], T]) -> T:
        """Serialize map operations across processes and threads using POSIX file lock."""
        if not self.mock_mode or self.map_path.startswith("/sys/fs/bpf"):
            return func()
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

    def _with_xdp_lock(self, func: Callable[[], T]) -> T:
        """Serialize XDP map operations across processes and threads using POSIX file lock."""
        if not self.mock_mode or self.xdp_map_path.startswith("/sys/fs/bpf"):
            return func()
        lock_path = f"{self.xdp_map_path}.lock"
        target_dir = os.path.dirname(self.xdp_map_path)
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)
        with open(lock_path, "w") as lock_f:
            fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
            try:
                return func()
            finally:
                fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)

    def _with_cgroup_lock(self, func: Callable[[], T]) -> T:
        """Serialize cgroup map operations across processes and threads using POSIX file lock."""
        if not self.mock_mode or self.cgroup_map_path.startswith("/sys/fs/bpf"):
            return func()
        lock_path = f"{self.cgroup_map_path}.lock"
        target_dir = os.path.dirname(self.cgroup_map_path)
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
        allow_loopback: bool = False,
    ) -> bool:
        """
        Register a process PID in the quarantine map to trigger an in-kernel strike.
        ttl_seconds: 0 for permanent quarantine, >0 for auto-expiring containment.
        allow_loopback: If True, set MORAY_ACT_ALLOW_LOOPBACK to permit loopback & AF_UNIX.
        """
        validate_pid(pid)
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds < 0:
            raise MorayQuarantineError(f"TTL must be a non-negative integer, got {ttl_seconds}")

        if allow_loopback:
            action_flags |= MORAY_ACT_ALLOW_LOOPBACK

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

    def report_tamper(self, pid: int, auto_escalate: bool = True) -> bool:
        """
        Assert immediate high-severity quarantine against a PID attempting containment tampering.
        Enforces Invariant I_7 (Anti-Tampering & Containment Self-Defense).
        """
        flags = (
            MORAY_ACT_FULL_STRIKE
            if auto_escalate
            else (MORAY_ACT_BLOCK_EXEC | MORAY_ACT_BLOCK_SOCKET | MORAY_ACT_DROP_NET)
        )
        return self.strike(pid, action_flags=flags, reason=MORAY_REASON_TAMPER_ATTEMPT)

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
                "allow_loopback": False,
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
            "allow_loopback": bool(entry.action_flags & MORAY_ACT_ALLOW_LOOPBACK),
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
            if self._bpf_map_fd < 0 and os.path.exists(self.map_path):
                self._open_bpf_map()
            if self._bpf_map_fd >= 0:
                evicted = []
                now_ns = int(time.time() * 1_000_000_000)
                for pid in self._bpf_list_all_keys():
                    entry = self._bpf_lookup_elem(pid)
                    if entry and is_entry_expired(entry, now_ns) and self._bpf_delete_elem(pid):
                        evicted.append(pid)
                return evicted
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
        if not self.mock_mode:
            if self._bpf_map_fd < 0 and os.path.exists(self.map_path):
                self._open_bpf_map()
            if self._bpf_map_fd >= 0:
                entries = []
                now_ns = int(time.time() * 1_000_000_000)
                for pid in self._bpf_list_all_keys():
                    entry = self._bpf_lookup_elem(pid)
                    if entry and (include_expired or not is_entry_expired(entry, now_ns)):
                        entries.append((pid, entry))
                return entries
            return []

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

    def flush_all(self, force: bool = False) -> int:
        """
        Emergency break-glass procedure: purge all entries from quarantine map.
        Requires force=True to confirm intent. Returns count of purged entries.
        """
        if not force:
            raise MorayQuarantineError(
                "Emergency flush requires explicit confirmation (force=True / --force)."
            )

        if not self.mock_mode:
            if self._bpf_map_fd < 0 and os.path.exists(self.map_path):
                self._open_bpf_map()
            if self._bpf_map_fd >= 0:
                count = 0
                for pid in self._bpf_list_all_keys():
                    if self._bpf_delete_elem(pid):
                        count += 1
                return count
            return 0

        if self.mock_mode:

            def _do_flush() -> int:
                self._load_mock_file()
                count = len(self._mock_table)
                self._mock_table.clear()
                self._sync_mock_file()
                return count

            return self._with_lock(_do_flush)

        return 0

    def healthcheck(self) -> dict[str, object]:
        """
        Comprehensive operational liveness and readiness probe.
        Evaluates bpffs mount, quarantine map presence, and LSM status.
        """
        warnings: list[str] = []
        status: str = "healthy"
        map_accessible = False
        xdp_accessible = False
        cgroup_accessible = False
        bpffs_mounted = False
        bpf_lsm_active = False

        if self.mock_mode:
            map_accessible = True
            xdp_accessible = True
            cgroup_accessible = True
            bpffs_mounted = True
            bpf_lsm_active = True
        else:
            if os.path.exists(self.map_path):
                map_accessible = True
            else:
                warnings.append(f"Quarantine map pin not found: {self.map_path}")
                status = "degraded"

            if os.path.exists(self.xdp_map_path):
                xdp_accessible = True

            if os.path.exists(self.cgroup_map_path):
                cgroup_accessible = True

            if os.path.exists("/sys/fs/bpf"):
                bpffs_mounted = True
            else:
                warnings.append("/sys/fs/bpf filesystem path does not exist")
                status = "unhealthy"

            lsm_path = "/sys/kernel/security/lsm"
            if os.path.exists(lsm_path):
                try:
                    with open(lsm_path, encoding="utf-8") as f:
                        content = f.read()
                        if "bpf" in content:
                            bpf_lsm_active = True
                        else:
                            warnings.append(
                                f"BPF-LSM not active in {lsm_path} (active: '{content.strip()}')"
                            )
                            status = "degraded"
                except OSError as exc:
                    warnings.append(f"Cannot read {lsm_path}: {exc}")
                    status = "degraded"
            else:
                warnings.append(f"{lsm_path} not found (securityfs not mounted)")
                status = "degraded"

        return {
            "status": status,
            "mock_mode": self.mock_mode,
            "map_path": self.map_path,
            "map_accessible": map_accessible,
            "xdp_map_path": self.xdp_map_path,
            "xdp_accessible": xdp_accessible,
            "cgroup_map_path": self.cgroup_map_path,
            "cgroup_accessible": cgroup_accessible,
            "bpffs_mounted": bpffs_mounted,
            "bpf_lsm_active": bpf_lsm_active,
            "quarantined_count": len(self.list_quarantined()),
            "xdp_dropped_count": len(self.xdp_list_dropped()),
            "cgroup_quarantined_count": len(self.list_quarantined_cgroups()),
            "warnings": warnings,
        }

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
        if self.mock_mode or self._bpf_map_fd < 0:
            self._mock_table[pid] = entry
            self._sync_mock_file()
            return True

        libc = ctypes.CDLL(None, use_errno=True)
        k = ctypes.c_uint32(pid)
        attr = BpfAttrMapElem(
            map_fd=self._bpf_map_fd,
            pad0=0,
            key=ctypes.addressof(k),
            value=ctypes.addressof(entry),
            flags=BPF_ANY,
        )
        nr = get_bpf_syscall_nr()
        ret = libc.syscall(nr, BPF_MAP_UPDATE_ELEM, ctypes.byref(attr), ctypes.sizeof(attr))
        if ret != 0:
            err = ctypes.get_errno()
            raise MorayQuarantineError(f"bpf(BPF_MAP_UPDATE_ELEM) failed: {os.strerror(err)}")
        return True

    def _bpf_lookup_elem(self, pid: int) -> MorayQuarantineEntry | None:
        if self.mock_mode or self._bpf_map_fd < 0:
            self._load_mock_file()
            return self._mock_table.get(pid)

        libc = ctypes.CDLL(None, use_errno=True)
        k = ctypes.c_uint32(pid)
        entry = MorayQuarantineEntry()
        attr = BpfAttrMapElem(
            map_fd=self._bpf_map_fd,
            pad0=0,
            key=ctypes.addressof(k),
            value=ctypes.addressof(entry),
            flags=0,
        )
        nr = get_bpf_syscall_nr()
        ret = libc.syscall(nr, BPF_MAP_LOOKUP_ELEM, ctypes.byref(attr), ctypes.sizeof(attr))
        if ret != 0:
            err = ctypes.get_errno()
            if err == 2:  # ENOENT (entry not present in map)
                return None
            raise MorayQuarantineError(f"bpf(BPF_MAP_LOOKUP_ELEM) failed: {os.strerror(err)}")
        return entry

    def _bpf_delete_elem(self, pid: int) -> bool:
        if self.mock_mode or self._bpf_map_fd < 0:
            if pid in self._mock_table:
                del self._mock_table[pid]
                self._sync_mock_file()
                return True
            return False

        libc = ctypes.CDLL(None, use_errno=True)
        k = ctypes.c_uint32(pid)
        attr = BpfAttrMapElem(
            map_fd=self._bpf_map_fd,
            pad0=0,
            key=ctypes.addressof(k),
            value=0,
            flags=0,
        )
        nr = get_bpf_syscall_nr()
        ret = libc.syscall(nr, BPF_MAP_DELETE_ELEM, ctypes.byref(attr), ctypes.sizeof(attr))
        if ret != 0:
            err = ctypes.get_errno()
            if err == 2:  # ENOENT
                return False
            raise MorayQuarantineError(f"bpf(BPF_MAP_DELETE_ELEM) failed: {os.strerror(err)}")
        return True

    def _bpf_get_next_key(self, current_key: int | None) -> int | None:
        if self.mock_mode or self._bpf_map_fd < 0:
            return None

        libc = ctypes.CDLL(None, use_errno=True)
        next_k = ctypes.c_uint32(0)
        curr_k = ctypes.c_uint32(current_key) if current_key is not None else None

        attr = BpfAttrMapElem(
            map_fd=self._bpf_map_fd,
            pad0=0,
            key=ctypes.addressof(curr_k) if curr_k is not None else 0,
            value=ctypes.addressof(next_k),
            flags=0,
        )
        nr = get_bpf_syscall_nr()
        ret = libc.syscall(nr, BPF_MAP_GET_NEXT_KEY, ctypes.byref(attr), ctypes.sizeof(attr))
        if ret != 0:
            err = ctypes.get_errno()
            if err == 2:  # ENOENT
                return None
            raise MorayQuarantineError(f"bpf(BPF_MAP_GET_NEXT_KEY) failed: {os.strerror(err)}")
        return int(next_k.value)

    def _bpf_list_all_keys(self) -> list[int]:
        keys: list[int] = []
        curr = self._bpf_get_next_key(None)
        while curr is not None:
            keys.append(curr)
            curr = self._bpf_get_next_key(curr)
        return keys

    # -------------------------------------------------------------------------
    # Phase 6.4: Wire-Level XDP Drop Map Lifecycle & Persistence
    # -------------------------------------------------------------------------

    def _sync_mock_xdp_file(self) -> None:
        if os.path.islink(self.xdp_map_path):
            raise MorayQuarantineError(
                f"Symlink xdp map path rejected for security: {self.xdp_map_path}"
            )

        try:
            target_dir = os.path.dirname(self.xdp_map_path)
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)

            tmp_path = (
                f"{self.xdp_map_path}.tmp.{os.getpid()}.{threading.get_ident()}.{time.time_ns()}"
            )
            with open(tmp_path, "wb") as f:
                for raw_ip, flag in self._mock_xdp_table.items():
                    f.write(raw_ip)  # 4 bytes in network wire order
                    f.write(struct.pack("B", flag))  # 1 byte flag
                f.flush()
                os.fsync(f.fileno())

            os.replace(tmp_path, self.xdp_map_path)
        except OSError as exc:
            raise MorayQuarantineError(f"Failed to sync mock xdp map: {exc}") from exc

    def _load_mock_xdp_file(self) -> None:
        if not os.path.exists(self.xdp_map_path):
            return

        if os.path.islink(self.xdp_map_path):
            raise MorayQuarantineError(
                f"Symlink xdp map path rejected for security: {self.xdp_map_path}"
            )

        try:
            sz = os.path.getsize(self.xdp_map_path)
            if sz > MAX_MAP_FILE_BYTES:
                raise MorayQuarantineError(
                    f"XDP map file size exceeds {MAX_MAP_FILE_BYTES} byte ceiling: {sz}"
                )

            with open(self.xdp_map_path, "rb") as f:
                data = f.read(MAX_MAP_FILE_BYTES + 1)

            if len(data) > MAX_MAP_FILE_BYTES:
                raise MorayQuarantineError(
                    f"XDP map payload exceeds {MAX_MAP_FILE_BYTES} byte ceiling: {len(data)}"
                )

            entry_sz = 5  # 4 bytes IPv4 + 1 byte flag
            if len(data) % entry_sz != 0:
                raise MorayQuarantineError(
                    f"Corrupted XDP map: size {len(data)} is not a multiple of {entry_sz}"
                )

            count = len(data) // entry_sz
            self._mock_xdp_table.clear()
            for i in range(count):
                chunk = data[i * entry_sz : (i + 1) * entry_sz]
                raw_ip = chunk[:4]
                flag = chunk[4]
                self._mock_xdp_table[raw_ip] = flag
        except OSError as exc:
            raise MorayQuarantineError(f"Failed to load mock xdp map: {exc}") from exc

    def _bpf_xdp_update_elem(self, raw_ip: bytes, flag: int) -> bool:
        if self.mock_mode or self._bpf_xdp_fd < 0:
            self._mock_xdp_table[raw_ip] = flag
            self._sync_mock_xdp_file()
            return True

        libc = ctypes.CDLL(None, use_errno=True)
        k_buf = ctypes.create_string_buffer(raw_ip, 4)
        v = ctypes.c_uint8(flag)
        attr = BpfAttrMapElem(
            map_fd=self._bpf_xdp_fd,
            pad0=0,
            key=ctypes.cast(k_buf, ctypes.c_void_p).value or 0,
            value=ctypes.addressof(v),
            flags=BPF_ANY,
        )
        nr = get_bpf_syscall_nr()
        ret = libc.syscall(nr, BPF_MAP_UPDATE_ELEM, ctypes.byref(attr), ctypes.sizeof(attr))
        if ret != 0:
            err = ctypes.get_errno()
            raise MorayQuarantineError(f"bpf(BPF_MAP_UPDATE_ELEM xdp) failed: {os.strerror(err)}")
        return True

    def _bpf_xdp_lookup_elem(self, raw_ip: bytes) -> int | None:
        if self.mock_mode or self._bpf_xdp_fd < 0:
            self._load_mock_xdp_file()
            return self._mock_xdp_table.get(raw_ip)

        libc = ctypes.CDLL(None, use_errno=True)
        k_buf = ctypes.create_string_buffer(raw_ip, 4)
        v = ctypes.c_uint8()
        attr = BpfAttrMapElem(
            map_fd=self._bpf_xdp_fd,
            pad0=0,
            key=ctypes.cast(k_buf, ctypes.c_void_p).value or 0,
            value=ctypes.addressof(v),
            flags=0,
        )
        nr = get_bpf_syscall_nr()
        ret = libc.syscall(nr, BPF_MAP_LOOKUP_ELEM, ctypes.byref(attr), ctypes.sizeof(attr))
        if ret != 0:
            err = ctypes.get_errno()
            if err == 2:  # ENOENT
                return None
            raise MorayQuarantineError(f"bpf(BPF_MAP_LOOKUP_ELEM xdp) failed: {os.strerror(err)}")
        return int(v.value)

    def _bpf_xdp_delete_elem(self, raw_ip: bytes) -> bool:
        if self.mock_mode or self._bpf_xdp_fd < 0:
            self._load_mock_xdp_file()
            if raw_ip in self._mock_xdp_table:
                del self._mock_xdp_table[raw_ip]
                self._sync_mock_xdp_file()
                return True
            return False

        libc = ctypes.CDLL(None, use_errno=True)
        k_buf = ctypes.create_string_buffer(raw_ip, 4)
        attr = BpfAttrMapElem(
            map_fd=self._bpf_xdp_fd,
            pad0=0,
            key=ctypes.cast(k_buf, ctypes.c_void_p).value or 0,
            value=0,
            flags=0,
        )
        nr = get_bpf_syscall_nr()
        ret = libc.syscall(nr, BPF_MAP_DELETE_ELEM, ctypes.byref(attr), ctypes.sizeof(attr))
        if ret != 0:
            err = ctypes.get_errno()
            if err == 2:  # ENOENT
                return False
            raise MorayQuarantineError(f"bpf(BPF_MAP_DELETE_ELEM xdp) failed: {os.strerror(err)}")
        return True

    def xdp_drop_ip(self, ip_str: str, flag: int = 1) -> bool:
        """
        Add an IPv4 address to the wire-level XDP drop map (moray_xdp_drop_map).
        Packets with matching source or destination IP will be discarded with XDP_DROP at line rate.
        """
        raw_ip = ip_to_wire_bytes(ip_str)
        if not (1 <= flag <= 255):
            raise MorayQuarantineError(f"XDP action flag must be between 1 and 255, got {flag}")

        if self.mock_mode:

            def _do_drop() -> bool:
                self._load_mock_xdp_file()
                self._mock_xdp_table[raw_ip] = flag
                self._sync_mock_xdp_file()
                return True

            return self._with_xdp_lock(_do_drop)

        if self._bpf_xdp_fd < 0 and os.path.exists(self.xdp_map_path):
            self._open_bpf_xdp_map()
        return self._bpf_xdp_update_elem(raw_ip, flag)

    def xdp_remove_ip(self, ip_str: str) -> bool:
        """
        Remove an IPv4 address from the wire-level XDP drop map.
        """
        raw_ip = ip_to_wire_bytes(ip_str)
        if self.mock_mode:

            def _do_remove() -> bool:
                self._load_mock_xdp_file()
                if raw_ip in self._mock_xdp_table:
                    del self._mock_xdp_table[raw_ip]
                    self._sync_mock_xdp_file()
                    return True
                return False

            return self._with_xdp_lock(_do_remove)

        if self._bpf_xdp_fd < 0 and os.path.exists(self.xdp_map_path):
            self._open_bpf_xdp_map()
        return self._bpf_xdp_delete_elem(raw_ip)

    def xdp_is_dropped(self, ip_str: str) -> bool:
        """
        Check if an IPv4 address is registered in the wire-level XDP drop map.
        """
        try:
            raw_ip = ip_to_wire_bytes(ip_str)
        except MorayQuarantineError:
            return False

        if self.mock_mode:

            def _do_check() -> bool:
                self._load_mock_xdp_file()
                return raw_ip in self._mock_xdp_table

            return self._with_xdp_lock(_do_check)

        if self._bpf_xdp_fd < 0 and os.path.exists(self.xdp_map_path):
            self._open_bpf_xdp_map()
        val = self._bpf_xdp_lookup_elem(raw_ip)
        return val is not None and val != 0

    def xdp_list_dropped(self) -> list[str]:
        """
        List all dropped IPv4 addresses currently programmed in the XDP drop map.
        """
        if self.mock_mode:

            def _do_list() -> list[str]:
                self._load_mock_xdp_file()
                return [wire_bytes_to_ip(raw) for raw in self._mock_xdp_table]

            return self._with_xdp_lock(_do_list)
        return []

    def xdp_flush(self, force: bool = False) -> int:
        """
        Flush all entries from the XDP drop map. Requires force=True.
        """
        if not force:
            raise MorayQuarantineError(
                "XDP flush requires explicit confirmation (force=True / --force)."
            )

        if self.mock_mode:

            def _do_flush() -> int:
                self._load_mock_xdp_file()
                count = len(self._mock_xdp_table)
                self._mock_xdp_table.clear()
                self._sync_mock_xdp_file()
                return count

            return self._with_xdp_lock(_do_flush)
        return 0

    # -------------------------------------------------------------------------
    # Phase 6.5: Cgroup v2 Containment Scoping & Map Lifecycle
    # -------------------------------------------------------------------------

    def _sync_mock_cgroup_file(self) -> None:
        if os.path.islink(self.cgroup_map_path):
            raise MorayQuarantineError(
                f"Symlink cgroup map path rejected for security: {self.cgroup_map_path}"
            )

        try:
            target_dir = os.path.dirname(self.cgroup_map_path)
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)

            tmp_path = (
                f"{self.cgroup_map_path}.tmp.{os.getpid()}.{threading.get_ident()}.{time.time_ns()}"
            )
            with open(tmp_path, "wb") as f:
                for cgroup_id, entry in self._mock_cgroup_table.items():
                    f.write(struct.pack("<Q", cgroup_id))  # 8 bytes unsigned 64-bit int
                    f.write(bytes(entry))  # 24 bytes MorayQuarantineEntry
                f.flush()
                os.fsync(f.fileno())

            os.replace(tmp_path, self.cgroup_map_path)
        except OSError as exc:
            raise MorayQuarantineError(f"Failed to sync mock cgroup map: {exc}") from exc

    def _load_mock_cgroup_file(self) -> None:
        if not os.path.exists(self.cgroup_map_path):
            return

        if os.path.islink(self.cgroup_map_path):
            raise MorayQuarantineError(
                f"Symlink cgroup map path rejected for security: {self.cgroup_map_path}"
            )

        try:
            sz = os.path.getsize(self.cgroup_map_path)
            if sz > MAX_MAP_FILE_BYTES:
                raise MorayQuarantineError(
                    f"Cgroup map file size exceeds {MAX_MAP_FILE_BYTES} byte ceiling: {sz}"
                )

            with open(self.cgroup_map_path, "rb") as f:
                data = f.read(MAX_MAP_FILE_BYTES + 1)

            if len(data) > MAX_MAP_FILE_BYTES:
                raise MorayQuarantineError(
                    f"Cgroup map payload exceeds {MAX_MAP_FILE_BYTES} byte ceiling: {len(data)}"
                )

            entry_sz = 32  # 8 bytes cgroup_id + 24 bytes MorayQuarantineEntry
            if len(data) % entry_sz != 0:
                raise MorayQuarantineError(
                    f"Corrupted cgroup map: size {len(data)} is not a multiple of {entry_sz}"
                )

            count = len(data) // entry_sz
            self._mock_cgroup_table.clear()
            for i in range(count):
                chunk = data[i * entry_sz : (i + 1) * entry_sz]
                cgroup_id = struct.unpack("<Q", chunk[:8])[0]
                entry = MorayQuarantineEntry.from_buffer_copy(chunk[8:])
                self._mock_cgroup_table[cgroup_id] = entry
        except OSError as exc:
            raise MorayQuarantineError(f"Failed to load mock cgroup map: {exc}") from exc

    def _bpf_cgroup_update_elem(self, cgroup_id: int, entry: MorayQuarantineEntry) -> bool:
        if self.mock_mode or self._bpf_cgroup_fd < 0:
            self._mock_cgroup_table[cgroup_id] = entry
            self._sync_mock_cgroup_file()
            return True

        libc = ctypes.CDLL(None, use_errno=True)
        k = ctypes.c_uint64(cgroup_id)
        attr = BpfAttrMapElem(
            map_fd=self._bpf_cgroup_fd,
            pad0=0,
            key=ctypes.addressof(k),
            value=ctypes.addressof(entry),
            flags=BPF_ANY,
        )
        nr = get_bpf_syscall_nr()
        ret = libc.syscall(nr, BPF_MAP_UPDATE_ELEM, ctypes.byref(attr), ctypes.sizeof(attr))
        if ret != 0:
            err = ctypes.get_errno()
            raise MorayQuarantineError(
                f"bpf(BPF_MAP_UPDATE_ELEM) failed for cgroup: {os.strerror(err)}"
            )
        return True

    def _bpf_cgroup_lookup_elem(self, cgroup_id: int) -> MorayQuarantineEntry | None:
        if self.mock_mode or self._bpf_cgroup_fd < 0:
            self._load_mock_cgroup_file()
            return self._mock_cgroup_table.get(cgroup_id)

        libc = ctypes.CDLL(None, use_errno=True)
        k = ctypes.c_uint64(cgroup_id)
        entry = MorayQuarantineEntry()
        attr = BpfAttrMapElem(
            map_fd=self._bpf_cgroup_fd,
            pad0=0,
            key=ctypes.addressof(k),
            value=ctypes.addressof(entry),
            flags=0,
        )
        nr = get_bpf_syscall_nr()
        ret = libc.syscall(nr, BPF_MAP_LOOKUP_ELEM, ctypes.byref(attr), ctypes.sizeof(attr))
        if ret != 0:
            err = ctypes.get_errno()
            if err == 2:  # ENOENT
                return None
            raise MorayQuarantineError(
                f"bpf(BPF_MAP_LOOKUP_ELEM) failed for cgroup: {os.strerror(err)}"
            )
        return entry

    def _bpf_cgroup_delete_elem(self, cgroup_id: int) -> bool:
        if self.mock_mode or self._bpf_cgroup_fd < 0:
            if cgroup_id in self._mock_cgroup_table:
                del self._mock_cgroup_table[cgroup_id]
                self._sync_mock_cgroup_file()
                return True
            return False

        libc = ctypes.CDLL(None, use_errno=True)
        k = ctypes.c_uint64(cgroup_id)
        attr = BpfAttrMapElem(
            map_fd=self._bpf_cgroup_fd,
            pad0=0,
            key=ctypes.addressof(k),
            value=0,
            flags=0,
        )
        nr = get_bpf_syscall_nr()
        ret = libc.syscall(nr, BPF_MAP_DELETE_ELEM, ctypes.byref(attr), ctypes.sizeof(attr))
        if ret != 0:
            err = ctypes.get_errno()
            if err == 2:  # ENOENT
                return False
            raise MorayQuarantineError(
                f"bpf(BPF_MAP_DELETE_ELEM) failed for cgroup: {os.strerror(err)}"
            )
        return True

    def quarantine_cgroup(
        self,
        target: str | int,
        action_flags: int = MORAY_ACT_BLOCK_EXEC,
        reason: int = MORAY_REASON_LOBSTER_L7,
        ttl_seconds: int = 0,
    ) -> bool:
        """Assert quarantine containment on a cgroup v2 hierarchy."""
        cgroup_id = resolve_cgroup_id(target)
        if ttl_seconds < 0:
            raise MorayQuarantineError(f"TTL must be >= 0 seconds, got {ttl_seconds}")

        entry = MorayQuarantineEntry(
            action_flags=action_flags,
            reason=reason,
            timestamp_ns=time.time_ns(),
            strike_count=1,
            ttl_seconds=ttl_seconds,
        )

        if self.mock_mode:

            def _do_quarantine() -> bool:
                return self._bpf_cgroup_update_elem(cgroup_id, entry)

            return self._with_cgroup_lock(_do_quarantine)

        if self._bpf_cgroup_fd < 0 and os.path.exists(self.cgroup_map_path):
            self._open_bpf_cgroup_map()
        return self._bpf_cgroup_update_elem(cgroup_id, entry)

    def release_cgroup(self, target: str | int) -> bool:
        """Release a cgroup v2 hierarchy from quarantine."""
        cgroup_id = resolve_cgroup_id(target)

        if self.mock_mode:

            def _do_release() -> bool:
                return self._bpf_cgroup_delete_elem(cgroup_id)

            return self._with_cgroup_lock(_do_release)

        if self._bpf_cgroup_fd < 0 and os.path.exists(self.cgroup_map_path):
            self._open_bpf_cgroup_map()
        return self._bpf_cgroup_delete_elem(cgroup_id)

    def is_cgroup_quarantined(self, target: str | int) -> bool:
        """Check if a cgroup v2 hierarchy is actively quarantined."""
        cgroup_id = resolve_cgroup_id(target)

        if self.mock_mode:

            def _do_check() -> bool:
                entry = self._bpf_cgroup_lookup_elem(cgroup_id)
                if entry is None:
                    return False
                return not is_entry_expired(entry)

            return self._with_cgroup_lock(_do_check)

        if self._bpf_cgroup_fd < 0 and os.path.exists(self.cgroup_map_path):
            self._open_bpf_cgroup_map()
        entry = self._bpf_cgroup_lookup_elem(cgroup_id)
        if entry is None:
            return False
        return not is_entry_expired(entry)

    def get_cgroup_entry(self, target: str | int) -> MorayQuarantineEntry | None:
        """Retrieve raw quarantine entry for a cgroup."""
        cgroup_id = resolve_cgroup_id(target)

        if self.mock_mode:

            def _do_get() -> MorayQuarantineEntry | None:
                return self._bpf_cgroup_lookup_elem(cgroup_id)

            return self._with_cgroup_lock(_do_get)

        if self._bpf_cgroup_fd < 0 and os.path.exists(self.cgroup_map_path):
            self._open_bpf_cgroup_map()
        return self._bpf_cgroup_lookup_elem(cgroup_id)

    def get_cgroup_status(self, target: str | int) -> dict[str, object]:
        """Query structured quarantine status for a cgroup."""
        cgroup_id = resolve_cgroup_id(target)
        entry = self.get_cgroup_entry(cgroup_id)
        if entry is None:
            return {
                "cgroup_id": cgroup_id,
                "state": "RELEASED",
                "state_code": MORAY_STATE_RELEASED,
                "quarantined": False,
                "action_flags": 0,
                "allow_loopback": False,
                "strike_count": 0,
                "ttl_seconds": 0,
                "remaining_seconds": 0,
                "reason": MORAY_REASON_UNKNOWN,
            }

        now_ns = time.time_ns()
        expired = is_entry_expired(entry, now_ns)
        rem_ttl = 0
        if entry.ttl_seconds > 0:
            elapsed_ns = now_ns - entry.timestamp_ns
            total_ttl_ns = entry.ttl_seconds * 1_000_000_000
            rem_ttl = max(0, int((total_ttl_ns - elapsed_ns) / 1_000_000_000))

        state_code = MORAY_STATE_EXPIRED if expired else MORAY_STATE_ACTIVE
        state_str = "EXPIRED" if expired else "ACTIVE"

        return {
            "cgroup_id": cgroup_id,
            "state": state_str,
            "state_code": state_code,
            "quarantined": not expired,
            "action_flags": entry.action_flags,
            "allow_loopback": bool(entry.action_flags & MORAY_ACT_ALLOW_LOOPBACK),
            "strike_count": entry.strike_count,
            "ttl_seconds": entry.ttl_seconds,
            "remaining_seconds": rem_ttl,
            "reason": entry.reason,
            "timestamp_ns": entry.timestamp_ns,
        }

    def list_quarantined_cgroups(
        self, include_expired: bool = False
    ) -> list[tuple[int, MorayQuarantineEntry]]:
        """List all quarantined cgroup entries."""
        if not self.mock_mode:
            return []

        def _do_list() -> list[tuple[int, MorayQuarantineEntry]]:
            self._load_mock_cgroup_file()
            if include_expired:
                return list(self._mock_cgroup_table.items())
            now_ns = time.time_ns()
            return [
                (cid, entry)
                for cid, entry in self._mock_cgroup_table.items()
                if not is_entry_expired(entry, now_ns)
            ]

        return self._with_cgroup_lock(_do_list)

    def flush_cgroups(self, force: bool = False) -> int:
        """Purge all entries from the cgroup containment map."""
        if not force:
            raise MorayQuarantineError(
                "Cgroup flush requires explicit confirmation (force=True / --force)."
            )

        if not self.mock_mode:
            return 0

        def _do_flush() -> int:
            self._load_mock_cgroup_file()
            count = len(self._mock_cgroup_table)
            self._mock_cgroup_table.clear()
            self._sync_mock_cgroup_file()
            return count

        return self._with_cgroup_lock(_do_flush)


# Backward compatibility alias
MorayQuarantineHook = MorayHook


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Project Moray: Zero-Dependency Python Bridge & Policy Engine for Project Lobster",
    )
    parser.add_argument("--pid", type=int, help="Target process ID (PID) to inspect or strike")
    parser.add_argument("--strike", action="store_true", help="Trigger Pharyngeal Strike on PID")
    parser.add_argument(
        "--report-tamper",
        action="store_true",
        help="Assert immediate anti-tamper quarantine on target PID (reason=TAMPER_ATTEMPT)",
    )
    parser.add_argument(
        "--block-exec",
        action="store_true",
        help="Strike target PID or cgroup with execution block (MORAY_ACT_BLOCK_EXEC)",
    )
    parser.add_argument(
        "--block-wan",
        action="store_true",
        help="Strike target PID with granular WAN egress block (permitting loopback/IPC)",
    )
    parser.add_argument(
        "--deny-all-net",
        action="store_true",
        help="Strike target PID with total network block (severing all sockets and wire traffic)",
    )
    parser.add_argument(
        "--allow-loopback",
        action="store_true",
        help="Permit loopback (127.0.0.1, ::1) and AF_UNIX IPC when blocking sockets",
    )
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
        "--flush-all",
        action="store_true",
        help="Emergency purge of all quarantine entries (requires --force)",
    )
    parser.add_argument(
        "--healthcheck", action="store_true", help="Run operational healthcheck and liveness probe"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Confirm intent for destructive emergency operations like --flush-all",
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
    parser.add_argument(
        "--events-path",
        type=str,
        default=DEFAULT_EVENTS_PIN,
        help="Path to pinned events ring buffer map or mock file",
    )
    parser.add_argument(
        "--tail-events",
        action="store_true",
        help="Tail recent Ring 0 telemetry events from the ring buffer",
    )
    parser.add_argument(
        "--stream-events",
        action="store_true",
        help="Continuously stream live Ring 0 telemetry events (like tail -f)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of events to retrieve when tailing (default: 10)",
    )
    parser.add_argument(
        "--emit-mock-event",
        action="store_true",
        help="Emit a synthesized test event to the mock events log (requires --mock)",
    )
    parser.add_argument(
        "--xdp-drop-ip",
        type=str,
        help="Add an IPv4 address to the wire-level XDP drop map (XDP_DROP)",
    )
    parser.add_argument(
        "--xdp-remove-ip",
        type=str,
        help="Remove an IPv4 address from the wire-level XDP drop map",
    )
    parser.add_argument(
        "--xdp-check-ip",
        type=str,
        help="Check if an IPv4 address is in the wire-level XDP drop map",
    )
    parser.add_argument(
        "--xdp-list",
        action="store_true",
        help="List all IPv4 addresses in the wire-level XDP drop map",
    )
    parser.add_argument(
        "--xdp-flush",
        action="store_true",
        help="Purge all entries from the wire-level XDP drop map (requires --force)",
    )
    parser.add_argument(
        "--xdp-map-path",
        type=str,
        default=DEFAULT_XDP_PIN,
        help="Path to pinned XDP drop map or mock file",
    )
    parser.add_argument(
        "--quarantine-cgroup",
        type=str,
        help="Target cgroup v2 hierarchy (path or 64-bit ID) to quarantine",
    )
    parser.add_argument(
        "--release-cgroup",
        type=str,
        help="Release cgroup v2 hierarchy (path or 64-bit ID) from quarantine",
    )
    parser.add_argument(
        "--cgroup-status",
        type=str,
        help="Query structured quarantine status for cgroup v2 hierarchy",
    )
    parser.add_argument(
        "--list-cgroups",
        action="store_true",
        help="List all quarantined cgroup v2 hierarchies",
    )
    parser.add_argument(
        "--flush-cgroups",
        action="store_true",
        help="Purge all cgroup v2 quarantine entries (requires --force)",
    )
    parser.add_argument(
        "--cgroup-map-path",
        type=str,
        default=DEFAULT_CGROUP_PIN,
        help="Path to pinned cgroup map or mock file",
    )
    parser.add_argument("--mock", action="store_true", help="Force mock testing mode")
    parser.add_argument("--json", action="store_true", help="Format output as structured JSON")

    args = parser.parse_args()

    try:
        hook = MorayHook(
            map_path=args.map_path,
            events_path=args.events_path,
            xdp_map_path=args.xdp_map_path,
            cgroup_map_path=args.cgroup_map_path,
            mock_mode=args.mock,
        )

        if args.strike:
            if not args.pid:
                parser.error("--strike requires --pid <PID>")
            action = args.action
            if args.allow_loopback:
                action |= MORAY_ACT_ALLOW_LOOPBACK
            hook.strike(args.pid, action_flags=action, reason=args.reason, ttl_seconds=args.ttl)
            if args.json:
                print(
                    json.dumps(
                        {
                            "status": "asserted",
                            "pid": args.pid,
                            "action_flags": action,
                            "ttl_seconds": args.ttl,
                            "allow_loopback": bool(action & MORAY_ACT_ALLOW_LOOPBACK),
                        }
                    )
                )
            else:
                ttl_msg = f" (TTL: {args.ttl}s)" if args.ttl > 0 else " (Permanent)"
                loop_msg = (
                    " [Granular Loopback Allowed]" if (action & MORAY_ACT_ALLOW_LOOPBACK) else ""
                )
                print(
                    f"[+] MORAY STRIKE ASSERTED: PID {args.pid} entered in-kernel quarantine{ttl_msg}{loop_msg}."
                )
        elif args.quarantine_cgroup:
            action = args.action
            if args.block_exec:
                action = MORAY_ACT_BLOCK_EXEC
            elif args.block_wan:
                action = MORAY_ACT_BLOCK_SOCKET | MORAY_ACT_ALLOW_LOOPBACK
            elif args.deny_all_net:
                action = MORAY_ACT_BLOCK_SOCKET | MORAY_ACT_DROP_NET
            elif args.allow_loopback:
                action |= MORAY_ACT_ALLOW_LOOPBACK

            hook.quarantine_cgroup(
                args.quarantine_cgroup,
                action_flags=action,
                reason=args.reason,
                ttl_seconds=args.ttl,
            )
            cid = resolve_cgroup_id(args.quarantine_cgroup)
            if args.json:
                print(
                    json.dumps(
                        {
                            "status": "asserted",
                            "cgroup": args.quarantine_cgroup,
                            "cgroup_id": cid,
                            "action_flags": action,
                            "ttl_seconds": args.ttl,
                            "allow_loopback": bool(action & MORAY_ACT_ALLOW_LOOPBACK),
                        }
                    )
                )
            else:
                ttl_msg = f" (TTL: {args.ttl}s)" if args.ttl > 0 else " (Permanent)"
                loop_msg = (
                    " [Granular Loopback Allowed]" if (action & MORAY_ACT_ALLOW_LOOPBACK) else ""
                )
                print(
                    f"[+] MORAY CGROUP QUARANTINE ASSERTED: Cgroup '{args.quarantine_cgroup}' (ID {cid}) entered in-kernel quarantine{ttl_msg}{loop_msg}."
                )
        elif args.release_cgroup:
            released = hook.release_cgroup(args.release_cgroup)
            cid = resolve_cgroup_id(args.release_cgroup)
            if args.json:
                print(
                    json.dumps(
                        {
                            "status": "released" if released else "not_found",
                            "cgroup": args.release_cgroup,
                            "cgroup_id": cid,
                        }
                    )
                )
            else:
                if released:
                    print(
                        f"[+] MORAY CGROUP RELEASE: Cgroup '{args.release_cgroup}' (ID {cid}) released from quarantine."
                    )
                else:
                    print(f"[-] Cgroup '{args.release_cgroup}' was not actively quarantined.")
        elif args.cgroup_status:
            stat_res = hook.get_cgroup_status(args.cgroup_status)
            if args.json:
                print(json.dumps(stat_res, indent=2))
            else:
                print("[*] Moray Cgroup Quarantine Status:")
                print(f"  Target:            {args.cgroup_status}")
                print(f"  Cgroup ID:         {stat_res['cgroup_id']}")
                print(f"  State:             {stat_res['state']} ({stat_res['state_code']})")
                print(f"  Quarantined:       {stat_res['quarantined']}")
                print(f"  Action Flags:      {stat_res['action_flags']:#04x}")
                print(f"  Allow Loopback:    {stat_res['allow_loopback']}")
                print(f"  Strike Count:      {stat_res['strike_count']}")
                print(f"  Remaining TTL:     {stat_res['remaining_seconds']}s")
        elif args.list_cgroups:
            cgroups = hook.list_quarantined_cgroups()
            if args.json:
                out = [
                    {
                        "cgroup_id": cid,
                        "action_flags": entry.action_flags,
                        "reason": entry.reason,
                        "strike_count": entry.strike_count,
                        "ttl_seconds": entry.ttl_seconds,
                    }
                    for cid, entry in cgroups
                ]
                print(json.dumps(out, indent=2))
            else:
                print(f"[*] Quarantined Cgroups: {len(cgroups)}")
                for cid, entry in cgroups:
                    print(
                        f"  Cgroup ID {cid} | Flags: {entry.action_flags:#04x} | Hits: {entry.strike_count}"
                    )
        elif args.flush_cgroups:
            flushed = hook.flush_cgroups(force=args.force)
            if args.json:
                print(json.dumps({"status": "cgroups_flushed", "count": flushed}))
            else:
                print(f"[!] BREAK-GLASS CGROUP FLUSH: Purged {flushed} quarantined cgroups.")
        elif args.block_exec:
            if not args.pid:
                parser.error("--block-exec requires --pid <PID>")
            action = MORAY_ACT_BLOCK_EXEC
            hook.strike(args.pid, action_flags=action, reason=args.reason, ttl_seconds=args.ttl)
            if args.json:
                print(
                    json.dumps(
                        {
                            "status": "asserted",
                            "policy": "block-exec",
                            "pid": args.pid,
                            "action_flags": action,
                            "ttl_seconds": args.ttl,
                        }
                    )
                )
            else:
                ttl_msg = f" (TTL: {args.ttl}s)" if args.ttl > 0 else " (Permanent)"
                print(
                    f"[+] MORAY EXECUTION POLICY ASSERTED: PID {args.pid} blocked from execve{ttl_msg}."
                )
        elif args.block_wan:
            if not args.pid:
                parser.error("--block-wan requires --pid <PID>")
            action = MORAY_ACT_BLOCK_SOCKET | MORAY_ACT_ALLOW_LOOPBACK
            hook.strike(args.pid, action_flags=action, reason=args.reason, ttl_seconds=args.ttl)
            if args.json:
                print(
                    json.dumps(
                        {
                            "status": "asserted",
                            "policy": "block-wan",
                            "pid": args.pid,
                            "action_flags": action,
                            "ttl_seconds": args.ttl,
                            "allow_loopback": True,
                        }
                    )
                )
            else:
                ttl_msg = f" (TTL: {args.ttl}s)" if args.ttl > 0 else " (Permanent)"
                print(
                    f"[+] MORAY GRANULAR EGRESS POLICY ASSERTED: PID {args.pid} blocked from WAN egress (loopback permitted){ttl_msg}."
                )
        elif args.deny_all_net:
            if not args.pid:
                parser.error("--deny-all-net requires --pid <PID>")
            action = MORAY_ACT_BLOCK_SOCKET | MORAY_ACT_DROP_NET
            hook.strike(args.pid, action_flags=action, reason=args.reason, ttl_seconds=args.ttl)
            if args.json:
                print(
                    json.dumps(
                        {
                            "status": "asserted",
                            "policy": "deny-all-net",
                            "pid": args.pid,
                            "action_flags": action,
                            "ttl_seconds": args.ttl,
                            "allow_loopback": False,
                        }
                    )
                )
            else:
                ttl_msg = f" (TTL: {args.ttl}s)" if args.ttl > 0 else " (Permanent)"
                print(
                    f"[+] MORAY TOTAL NETWORK BLOCK ASSERTED: PID {args.pid} severed from all network activity{ttl_msg}."
                )
        elif args.report_tamper:
            if not args.pid:
                parser.error("--report-tamper requires --pid <PID>")
            hook.report_tamper(args.pid)
            if args.json:
                print(
                    json.dumps(
                        {
                            "status": "asserted_tamper",
                            "pid": args.pid,
                            "reason": MORAY_REASON_TAMPER_ATTEMPT,
                        }
                    )
                )
            else:
                print(
                    f"[!] MORAY ANTI-TAMPER ASSERTED: PID {args.pid} entered in-kernel quarantine (Tamper Attempt)."
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
        elif args.flush_all:
            flushed = hook.flush_all(force=args.force)
            if args.json:
                print(json.dumps({"status": "flushed", "count": flushed}))
            else:
                print(f"[!] BREAK-GLASS FLUSH: Purged {flushed} quarantine entries.")
        elif args.healthcheck:
            health = hook.healthcheck()
            if args.json:
                print(json.dumps(health, indent=2))
            else:
                print(f"[*] Moray Containment Health: {health['status'].upper()}")
                print(f"  Mock Mode:        {health['mock_mode']}")
                print(f"  Map Path:         {health['map_path']}")
                print(f"  Map Accessible:   {health['map_accessible']}")
                print(f"  BPFFS Mounted:    {health['bpffs_mounted']}")
                print(f"  BPF-LSM Active:   {health['bpf_lsm_active']}")
                print(f"  Quarantined PIDs: {health['quarantined_count']}")
                warnings_list = health.get("warnings", [])
                if warnings_list and isinstance(warnings_list, list):
                    print("  Warnings:")
                    for w in warnings_list:
                        print(f"    - {w}")
            sys.exit(0 if health["status"] == "healthy" else 1)
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
        elif args.tail_events or args.stream_events:
            follow = args.stream_events
            count = args.count if not follow else 0
            try:
                for ev_dict in hook.tail_events(count=count, follow=follow):
                    if args.json:
                        print(json.dumps(ev_dict))
                    else:
                        ev_obj = MorayEvent.from_dict(ev_dict)
                        print(ev_obj.format_log())
            except KeyboardInterrupt:
                pass
        elif args.emit_mock_event:
            pid = args.pid or os.getpid()
            ev = MorayEvent()
            ev.timestamp_ns = int(time.time() * 1_000_000_000)
            ev.pid = pid
            ev.tgid = pid
            ev.uid = os.getuid()
            ev.action_taken = args.action
            ev.ret_code = -1
            ev.hook_point = MORAY_HOOK_BPRM
            ev.drop_count = 1
            comm = b"test_agent\x00"
            ev.comm = comm + b"\x00" * (16 - len(comm))
            target = b"/bin/unauthorized\x00"
            ev.target_info = target + b"\x00" * (64 - len(target))
            hook.emit_event(ev)
            if args.json:
                print(json.dumps({"status": "emitted", "event": ev.to_dict()}))
            else:
                print(f"[+] EMITTED MOCK EVENT: PID {pid} blocked at BPRM_CHECK_SECURITY")
        elif args.xdp_drop_ip:
            hook.xdp_drop_ip(args.xdp_drop_ip)
            if args.json:
                print(
                    json.dumps(
                        {"status": "xdp_dropped", "ip": args.xdp_drop_ip, "action": "XDP_DROP"}
                    )
                )
            else:
                print(
                    f"[+] MORAY XDP WIRE DROP ASSERTED: IP {args.xdp_drop_ip} registered in moray_xdp_drop_map."
                )
        elif args.xdp_remove_ip:
            removed = hook.xdp_remove_ip(args.xdp_remove_ip)
            if args.json:
                print(
                    json.dumps(
                        {
                            "status": "removed" if removed else "not_found",
                            "ip": args.xdp_remove_ip,
                        }
                    )
                )
            else:
                if removed:
                    print(
                        f"[+] MORAY XDP WIRE RELEASE: IP {args.xdp_remove_ip} removed from drop map."
                    )
                else:
                    print(f"[-] IP {args.xdp_remove_ip} was not found in XDP drop map.")
        elif args.xdp_check_ip:
            is_dropped = hook.xdp_is_dropped(args.xdp_check_ip)
            if args.json:
                print(json.dumps({"ip": args.xdp_check_ip, "xdp_dropped": is_dropped}))
                sys.exit(1 if is_dropped else 0)
            else:
                if is_dropped:
                    print(f"[!] IP {args.xdp_check_ip} is DROPPED at wire level (XDP_DROP).")
                    sys.exit(1)
                else:
                    print(f"[+] IP {args.xdp_check_ip} is NOT dropped by XDP.")
                    sys.exit(0)
        elif args.xdp_list:
            dropped_ips = hook.xdp_list_dropped()
            if args.json:
                print(json.dumps({"dropped_ips": dropped_ips, "count": len(dropped_ips)}, indent=2))
            else:
                print(f"[*] Total Wire-Dropped IPs: {len(dropped_ips)}")
                for ip in dropped_ips:
                    print(f"  {ip} -> XDP_DROP")
        elif args.xdp_flush:
            flushed = hook.xdp_flush(force=args.force)
            if args.json:
                print(json.dumps({"status": "xdp_flushed", "count": flushed}))
            else:
                print(f"[!] BREAK-GLASS XDP FLUSH: Purged {flushed} XDP drop entries.")
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
