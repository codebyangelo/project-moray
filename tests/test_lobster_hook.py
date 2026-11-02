# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Test Suite for Lobster Hook and Invariant Verification
Enforces Invariants I_1 (Fail-Closed), I_2 (Benign Fast-Path), and I_5 (Binary Layout).
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
from pathlib import Path

import pytest

# Ensure bridge is on path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from bridge.lobster_hook import (
    FAIL_CLOSED_EXIT_CODE,
    MORAY_ACT_BLOCK_EXEC,
    MORAY_ACT_BLOCK_SOCKET,
    MORAY_REASON_LOBSTER_L7,
    MorayEvent,
    MorayHook,
    MorayQuarantineEntry,
    MorayQuarantineError,
)


class TestBinaryContracts:
    """Invariant I_5: Binary Type & Alignment Contract Verification."""

    def test_quarantine_entry_size(self) -> None:
        assert ctypes.sizeof(MorayQuarantineEntry) == 24, (
            "MorayQuarantineEntry must be exactly 24 bytes"
        )

    def test_event_struct_size(self) -> None:
        assert ctypes.sizeof(MorayEvent) == 128, "MorayEvent must be exactly 128 bytes"

    def test_entry_member_offsets(self) -> None:
        assert MorayQuarantineEntry.action_flags.offset == 0
        assert MorayQuarantineEntry.reason.offset == 4
        assert MorayQuarantineEntry.timestamp_ns.offset == 8
        assert MorayQuarantineEntry.strike_count.offset == 16
        assert MorayQuarantineEntry.ttl_seconds.offset == 20

    def test_event_member_offsets(self) -> None:
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


class TestMorayHookLifecycle:
    """Lifecycle and Invariant I_1 / I_2 Verification."""

    @pytest.fixture
    def temp_hook(self, tmp_path: Path) -> MorayHook:
        map_file = str(tmp_path / "test_quarantine.map")
        return MorayHook(map_path=map_file, mock_mode=True)

    def test_benign_fast_path(self, temp_hook: MorayHook) -> None:
        """Invariant I_2: Benign process lookup returns non-quarantined cleanly."""
        assert not temp_hook.is_quarantined(99999)
        assert temp_hook.get_entry(99999) is None

    def test_strike_and_lookup(self, temp_hook: MorayHook) -> None:
        """Invariant I_1: Asserting strike sets quarantine state."""
        target_pid = 4321
        success = temp_hook.strike(
            target_pid,
            action_flags=(MORAY_ACT_BLOCK_EXEC | MORAY_ACT_BLOCK_SOCKET),
            reason=MORAY_REASON_LOBSTER_L7,
        )
        assert success is True
        assert temp_hook.is_quarantined(target_pid) is True

        entry = temp_hook.get_entry(target_pid)
        assert entry is not None
        assert entry.action_flags == (MORAY_ACT_BLOCK_EXEC | MORAY_ACT_BLOCK_SOCKET)
        assert entry.reason == MORAY_REASON_LOBSTER_L7
        assert entry.strike_count == 0

    def test_release_quarantine(self, temp_hook: MorayHook) -> None:
        """Releasing clears strike state."""
        target_pid = 7788
        temp_hook.strike(target_pid)
        assert temp_hook.is_quarantined(target_pid) is True

        assert temp_hook.release(target_pid) is True
        assert temp_hook.is_quarantined(target_pid) is False
        assert temp_hook.release(target_pid) is False  # Idempotent release

    def test_fail_closed_on_invalid_pid(self, temp_hook: MorayHook) -> None:
        """Invariant I_1: Invalid PIDs fail closed with MorayQuarantineError."""
        with pytest.raises(MorayQuarantineError):
            temp_hook.strike(0)

        with pytest.raises(MorayQuarantineError):
            temp_hook.strike(-1)

        with pytest.raises(MorayQuarantineError):
            temp_hook.strike(99999999)

        with pytest.raises(MorayQuarantineError):
            temp_hook.release(0)

    def test_list_quarantined(self, temp_hook: MorayHook) -> None:
        """Listing all active quarantined entities."""
        temp_hook.strike(101, action_flags=MORAY_ACT_BLOCK_EXEC)
        temp_hook.strike(102, action_flags=MORAY_ACT_BLOCK_SOCKET)

        entries = temp_hook.list_quarantined()
        pids = [p for p, _ in entries]
        assert 101 in pids
        assert 102 in pids
        assert len(entries) == 2


class TestCLIExecution:
    """CLI execution and exit code verification."""

    def test_cli_strike_and_check(self, tmp_path: Path) -> None:
        script = str(REPO_ROOT / "bridge" / "lobster_hook.py")
        map_path = str(tmp_path / "cli_quarantine.map")

        # 1. Check benign PID -> exit code 0
        res = subprocess.run(
            [sys.executable, script, "--pid", "5555", "--check", "--map-path", map_path, "--mock"],
            capture_output=True,
            check=False,
            text=True,
        )
        assert res.returncode == 0
        assert "BENIGN" in res.stdout

        # 2. Strike PID -> exit code 0
        res = subprocess.run(
            [sys.executable, script, "--pid", "5555", "--strike", "--map-path", map_path, "--mock"],
            capture_output=True,
            check=False,
            text=True,
        )
        assert res.returncode == 0
        assert "MORAY STRIKE ASSERTED" in res.stdout

        # 3. Check quarantined PID -> exit code 1
        res = subprocess.run(
            [sys.executable, script, "--pid", "5555", "--check", "--map-path", map_path, "--mock"],
            capture_output=True,
            check=False,
            text=True,
        )
        assert res.returncode == 1
        assert "QUARANTINED" in res.stdout

        # 4. Release PID -> exit code 0
        res = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                "5555",
                "--release",
                "--map-path",
                map_path,
                "--mock",
            ],
            capture_output=True,
            check=False,
            text=True,
        )
        assert res.returncode == 0
        assert "MORAY RELEASE" in res.stdout

        # 5. Check released PID -> exit code 0
        res = subprocess.run(
            [sys.executable, script, "--pid", "5555", "--check", "--map-path", map_path, "--mock"],
            capture_output=True,
            check=False,
            text=True,
        )
        assert res.returncode == 0
        assert "BENIGN" in res.stdout

    def test_cli_invalid_pid_fail_closed(self, tmp_path: Path) -> None:
        """Invariant I_1: CLI exits with FAIL_CLOSED_EXIT_CODE (252) on invalid PID."""
        script = str(REPO_ROOT / "bridge" / "lobster_hook.py")
        map_path = str(tmp_path / "cli_quarantine.map")

        res = subprocess.run(
            [sys.executable, script, "--pid", "-1", "--strike", "--map-path", map_path, "--mock"],
            capture_output=True,
            check=False,
            text=True,
        )
        assert res.returncode == FAIL_CLOSED_EXIT_CODE
        assert "FAIL-CLOSED" in res.stderr
