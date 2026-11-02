# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Telemetry Streamer & Ringbuf Consumer Verification Suite
Enforces Invariant I_6 (Hermetic Telemetry & Ringbuf Non-Blocking Dispatch).
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from bridge.lobster_hook import (
    FAIL_CLOSED_EXIT_CODE,
    MORAY_ACT_BLOCK_EXEC,
    MORAY_ACT_KILL,
    MORAY_HOOK_BPF_TAMPER,
    MORAY_HOOK_BPRM,
    MORAY_HOOK_SOCKET,
    MorayEvent,
    MorayHook,
    MorayQuarantineError,
    MorayTelemetryConsumer,
)


class TestMorayEventBinaryContract:
    """Verifies binary layout and serialization contracts of MorayEvent struct."""

    def test_struct_size_and_alignment(self) -> None:
        assert ctypes.sizeof(MorayEvent) == 128
        assert MorayEvent.timestamp_ns.offset == 0
        assert MorayEvent.pid.offset == 8
        assert MorayEvent.tgid.offset == 12
        assert MorayEvent.uid.offset == 16
        assert MorayEvent.action_taken.offset == 20
        assert MorayEvent.ret_code.offset == 24
        assert MorayEvent.hook_point.offset == 28
        assert MorayEvent.comm.offset == 32
        assert MorayEvent.target_info.offset == 48
        assert MorayEvent.drop_count.offset == 112
        assert MorayEvent.reserved.offset == 120

    def test_binary_roundtrip(self) -> None:
        ev = MorayEvent()
        ev.timestamp_ns = 1730569800123456789
        ev.pid = 4321
        ev.tgid = 4321
        ev.uid = 1000
        ev.action_taken = MORAY_ACT_BLOCK_EXEC | MORAY_ACT_KILL
        ev.ret_code = -1
        ev.hook_point = MORAY_HOOK_BPRM
        ev.drop_count = 5
        ev.reserved = 0
        ev.comm = b"test_worker\x00"
        ev.target_info = b"/usr/bin/python3\x00"

        raw_bytes = bytes(ev)
        assert len(raw_bytes) == 128

        ev_restored = MorayEvent.from_buffer_copy(raw_bytes)
        assert ev_restored.timestamp_ns == 1730569800123456789
        assert ev_restored.pid == 4321
        assert ev_restored.tgid == 4321
        assert ev_restored.uid == 1000
        assert ev_restored.action_taken == (MORAY_ACT_BLOCK_EXEC | MORAY_ACT_KILL)
        assert ev_restored.ret_code == -1
        assert ev_restored.hook_point == MORAY_HOOK_BPRM
        assert ev_restored.drop_count == 5
        assert ev_restored.comm.decode("utf-8").rstrip("\x00") == "test_worker"
        assert ev_restored.target_info.decode("utf-8").rstrip("\x00") == "/usr/bin/python3"

    def test_to_dict_and_json(self) -> None:
        ev = MorayEvent()
        ev.timestamp_ns = 1700000000000000000
        ev.pid = 999
        ev.tgid = 999
        ev.uid = 0
        ev.action_taken = MORAY_ACT_BLOCK_EXEC
        ev.ret_code = -1
        ev.hook_point = MORAY_HOOK_BPRM
        ev.drop_count = 1
        ev.comm = b"sh\x00"
        ev.target_info = b"/bin/bash\x00"

        d = ev.to_dict()
        assert d["pid"] == 999
        assert d["hook_name"] == "BPRM_CHECK_SECURITY"
        assert d["comm"] == "sh"
        assert d["target_info"] == "/bin/bash"

        json_str = ev.to_json()
        parsed = json.loads(json_str)
        assert parsed["pid"] == 999
        assert parsed["hook_name"] == "BPRM_CHECK_SECURITY"

    def test_from_dict_factory(self) -> None:
        data = {
            "timestamp_ns": 1234567890,
            "pid": 5001,
            "tgid": 5001,
            "uid": 1001,
            "action_taken": 3,
            "ret_code": -1,
            "hook_point": MORAY_HOOK_SOCKET,
            "drop_count": 2,
            "comm": "curl",
            "target_info": "1.1.1.1:443",
        }
        ev = MorayEvent.from_dict(data)
        assert ev.pid == 5001
        assert ev.hook_point == MORAY_HOOK_SOCKET
        assert ev.comm.decode("utf-8").rstrip("\x00") == "curl"
        assert ev.target_info.decode("utf-8").rstrip("\x00") == "1.1.1.1:443"

    def test_format_log(self) -> None:
        ev = MorayEvent()
        ev.timestamp_ns = 1730569800000000000
        ev.pid = 123
        ev.tgid = 123
        ev.action_taken = MORAY_ACT_BLOCK_EXEC
        ev.ret_code = -1
        ev.hook_point = MORAY_HOOK_BPF_TAMPER
        ev.drop_count = 3
        ev.comm = b"tamper_bot\x00"
        log_line = ev.format_log()
        assert "PID 123" in log_line
        assert "tamper_bot" in log_line
        assert "BPF_ANTI_TAMPER" in log_line
        assert "strikes: 3" in log_line


class TestMockTelemetryStreamer:
    """Verifies event consumer, mock emission, tailing, and FIFO ordering."""

    def test_mock_consumer_poll_and_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            events_path = os.path.join(tmpdir, "events.mock")
            consumer = MorayTelemetryConsumer(events_path=events_path, mock_mode=True)

            # Initial poll on empty file
            assert consumer.poll() == []

            # Emit 3 events
            for i in range(1, 4):
                consumer.emit_mock_event(
                    {
                        "timestamp_ns": int(time.time() * 1_000_000_000),
                        "pid": 1000 + i,
                        "tgid": 1000 + i,
                        "uid": 0,
                        "action_taken": 1,
                        "ret_code": -1,
                        "hook_point": MORAY_HOOK_BPRM,
                        "drop_count": i,
                        "comm": f"agent_{i}",
                        "target_info": "/bin/true",
                    }
                )

            # Poll should retrieve all 3 in order
            events = consumer.poll()
            assert len(events) == 3
            assert events[0].pid == 1001
            assert events[1].pid == 1002
            assert events[2].pid == 1003

            # Subsequent poll should yield 0 (offset advanced)
            assert consumer.poll() == []

            # Emit another event
            consumer.emit_mock_event(
                {
                    "timestamp_ns": int(time.time() * 1_000_000_000),
                    "pid": 1004,
                    "tgid": 1004,
                    "uid": 0,
                    "action_taken": 1,
                    "ret_code": -1,
                    "hook_point": MORAY_HOOK_BPRM,
                    "drop_count": 4,
                    "comm": "agent_4",
                    "target_info": "/bin/true",
                }
            )
            new_events = consumer.poll()
            assert len(new_events) == 1
            assert new_events[0].pid == 1004

            consumer.close()

    def test_hook_tail_events_count_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            map_path = os.path.join(tmpdir, "quarantine.mock")
            events_path = os.path.join(tmpdir, "events.mock")
            hook = MorayHook(map_path=map_path, events_path=events_path, mock_mode=True)

            for i in range(10):
                hook.emit_event(
                    {
                        "timestamp_ns": int(time.time() * 1_000_000_000),
                        "pid": 2000 + i,
                        "tgid": 2000 + i,
                        "uid": 0,
                        "action_taken": 1,
                        "ret_code": -1,
                        "hook_point": MORAY_HOOK_BPRM,
                        "drop_count": 1,
                        "comm": f"worker_{i}",
                        "target_info": "/bin/true",
                    }
                )

            # Tail last 3 events
            tailed = list(hook.tail_events(count=3, follow=False))
            assert len(tailed) == 3
            assert tailed[0]["pid"] == 2007
            assert tailed[1]["pid"] == 2008
            assert tailed[2]["pid"] == 2009

            hook.close()

    def test_symlink_rejection_security_contract(self) -> None:
        """Enforces anti-traversal invariant: symlinks pointing to event sinks must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            real_file = os.path.join(tmpdir, "real_events")
            Path(real_file).touch()
            symlink_file = os.path.join(tmpdir, "symlink_events")
            os.symlink(real_file, symlink_file)

            with pytest.raises(MorayQuarantineError, match="anti-traversal"):
                MorayTelemetryConsumer(events_path=symlink_file, mock_mode=True)


class TestCLIStreamerIntegration:
    """Verifies command line execution of telemetry tail and stream commands."""

    def test_cli_emit_and_tail_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            map_path = os.path.join(tmpdir, "quarantine.mock")
            events_path = os.path.join(tmpdir, "events.mock")

            # 1. Emit mock event via CLI
            emit_cmd = [
                sys.executable,
                str(REPO_ROOT / "bridge" / "lobster_hook.py"),
                "--emit-mock-event",
                "--pid",
                "7777",
                "--map-path",
                map_path,
                "--events-path",
                events_path,
                "--mock",
                "--json",
            ]
            res = subprocess.run(emit_cmd, capture_output=True, text=True, check=True)
            out = json.loads(res.stdout)
            assert out["status"] == "emitted"
            assert out["event"]["pid"] == 7777

            # 2. Tail events via CLI
            tail_cmd = [
                sys.executable,
                str(REPO_ROOT / "bridge" / "lobster_hook.py"),
                "--tail-events",
                "--count",
                "1",
                "--map-path",
                map_path,
                "--events-path",
                events_path,
                "--mock",
                "--json",
            ]
            res_tail = subprocess.run(tail_cmd, capture_output=True, text=True, check=True)
            lines = res_tail.stdout.strip().splitlines()
            assert len(lines) == 1
            event_obj = json.loads(lines[0])
            assert event_obj["pid"] == 7777
            assert event_obj["hook_name"] == "BPRM_CHECK_SECURITY"

    def test_cli_tail_human_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            map_path = os.path.join(tmpdir, "quarantine.mock")
            events_path = os.path.join(tmpdir, "events.mock")

            hook = MorayHook(map_path=map_path, events_path=events_path, mock_mode=True)
            hook.emit_event(
                {
                    "timestamp_ns": int(time.time() * 1_000_000_000),
                    "pid": 8888,
                    "tgid": 8888,
                    "uid": 1000,
                    "action_taken": 1,
                    "ret_code": -1,
                    "hook_point": MORAY_HOOK_BPRM,
                    "drop_count": 1,
                    "comm": "python3",
                    "target_info": "/etc/shadow",
                }
            )
            hook.close()

            tail_cmd = [
                sys.executable,
                str(REPO_ROOT / "bridge" / "lobster_hook.py"),
                "--tail-events",
                "--count",
                "1",
                "--map-path",
                map_path,
                "--events-path",
                events_path,
                "--mock",
            ]
            res = subprocess.run(tail_cmd, capture_output=True, text=True, check=True)
            assert "PID 8888" in res.stdout
            assert "python3" in res.stdout
            assert "BPRM_CHECK_SECURITY" in res.stdout

    def test_cli_symlink_rejection_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            real_file = os.path.join(tmpdir, "real_events")
            Path(real_file).touch()
            symlink_file = os.path.join(tmpdir, "symlink_events")
            os.symlink(real_file, symlink_file)

            cmd = [
                sys.executable,
                str(REPO_ROOT / "bridge" / "lobster_hook.py"),
                "--tail-events",
                "--events-path",
                symlink_file,
                "--mock",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            assert res.returncode == FAIL_CLOSED_EXIT_CODE
            assert "anti-traversal invariant" in res.stderr
