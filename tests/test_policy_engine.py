# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Phase 3 Policy Engine & Lifecycle Unit Tests
Validates TTL auto-expiration, eviction lifecycle, strike escalation constants,
structured status telemetry, and CLI verbs under fail-closed invariants.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from bridge.lobster_hook import (
    MORAY_ACT_BLOCK_EXEC,
    MORAY_ACT_FULL_STRIKE,
    MORAY_ACT_KILL,
    MORAY_REASON_EXEC_VIOLATION,
    MORAY_REASON_LOBSTER_L7,
    MORAY_STATE_ACTIVE,
    MORAY_STATE_EXPIRED,
    MORAY_STATE_RELEASED,
    MORAY_STRIKE_TIER1,
    MORAY_STRIKE_TIER2,
    MORAY_STRIKE_TIER3,
    MorayHook,
    MorayQuarantineEntry,
    MorayQuarantineError,
    is_entry_expired,
)


class TestPolicyConstants:
    """Verifies Phase 3 policy constants and alignment."""

    def test_tier_escalation_hierarchy(self) -> None:
        assert MORAY_STRIKE_TIER1 == 1
        assert MORAY_STRIKE_TIER2 == 3
        assert MORAY_STRIKE_TIER3 == 5
        assert MORAY_STRIKE_TIER1 < MORAY_STRIKE_TIER2 < MORAY_STRIKE_TIER3

    def test_state_codes(self) -> None:
        assert MORAY_STATE_ACTIVE == 1
        assert MORAY_STATE_EXPIRED == 2
        assert MORAY_STATE_RELEASED == 3


class TestTTLExpirationLifecycle:
    """Tests TTL expiration semantics and Invariant I_2 (Fast-Path bypass)."""

    def test_entry_expiration_calculation(self) -> None:
        entry = MorayQuarantineEntry()
        entry.action_flags = MORAY_ACT_FULL_STRIKE
        entry.reason = MORAY_REASON_LOBSTER_L7
        entry.strike_count = 0
        entry.ttl_seconds = 0
        entry.timestamp_ns = 1_000_000_000_000

        # Permanent entry (ttl_seconds == 0) never expires
        assert not is_entry_expired(entry, now_ns=entry.timestamp_ns + 100_000_000_000)

        # Temporary entry with TTL = 10 seconds
        entry.ttl_seconds = 10
        base_time = entry.timestamp_ns
        assert not is_entry_expired(entry, now_ns=base_time + 5_000_000_000)
        assert not is_entry_expired(entry, now_ns=base_time + 10_000_000_000)
        assert is_entry_expired(entry, now_ns=base_time + 10_000_000_001)

    def test_strike_with_ttl_and_auto_expiry(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "quarantine.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)

        target_pid = 2048
        # Strike with 1-second TTL
        hook.strike(target_pid, ttl_seconds=1)

        # Immediate check: Must be quarantined
        assert hook.is_quarantined(target_pid) is True
        status = hook.get_status(target_pid)
        assert status["state"] == "ACTIVE"
        assert status["quarantined"] is True
        assert status["remaining_seconds"] is not None
        assert status["remaining_seconds"] >= 0

        # Wait for TTL lapse
        time.sleep(1.1)

        # Fast-path check: is_quarantined returns False automatically
        assert hook.is_quarantined(target_pid) is False

        # Status check reflects EXPIRED
        expired_status = hook.get_status(target_pid)
        assert expired_status["state"] == "EXPIRED"
        assert expired_status["quarantined"] is False
        assert expired_status["remaining_seconds"] == 0

    def test_evict_expired_lifecycle(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "quarantine.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)

        pid_perm = 1001
        pid_temp1 = 1002
        pid_temp2 = 1003

        hook.strike(pid_perm, ttl_seconds=0)  # Permanent
        hook.strike(pid_temp1, ttl_seconds=1)  # 1 second
        hook.strike(pid_temp2, ttl_seconds=60)  # 60 seconds

        assert len(hook.list_quarantined()) == 3

        # Wait for temp1 to lapse
        time.sleep(1.1)

        # Without eviction, list_quarantined default filters out expired entries
        active_list = hook.list_quarantined(include_expired=False)
        active_pids = [p for p, _ in active_list]
        assert pid_perm in active_pids
        assert pid_temp2 in active_pids
        assert pid_temp1 not in active_pids

        # Run eviction
        evicted = hook.evict_expired()
        assert evicted == [pid_temp1]

        # Verify raw table no longer holds pid_temp1
        all_entries = hook.list_quarantined(include_expired=True)
        all_pids = [p for p, _ in all_entries]
        assert pid_temp1 not in all_pids
        assert pid_perm in all_pids
        assert pid_temp2 in all_pids

    def test_invalid_ttl_validation(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "quarantine.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)

        with pytest.raises(MorayQuarantineError, match="TTL must be a non-negative integer"):
            hook.strike(101, ttl_seconds=-5)

        with pytest.raises(MorayQuarantineError, match="TTL must be a non-negative integer"):
            hook.strike(101, ttl_seconds=True)  # type: ignore[arg-type]

        with pytest.raises(MorayQuarantineError, match="TTL must be a non-negative integer"):
            hook.strike(101, ttl_seconds="30")  # type: ignore[arg-type]


class TestStructuredStatusAPI:
    """Verifies get_status dictionary contracts for integration with agents."""

    def test_status_unquarantined_pid(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "quarantine.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)

        status = hook.get_status(9999)
        assert status == {
            "pid": 9999,
            "state": "NONE",
            "quarantined": False,
            "action_flags": 0,
            "reason": 0,
            "strike_count": 0,
            "ttl_seconds": 0,
            "remaining_seconds": 0,
        }

    def test_status_active_pid(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "quarantine.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)

        hook.strike(
            4242,
            action_flags=MORAY_ACT_BLOCK_EXEC | MORAY_ACT_KILL,
            reason=MORAY_REASON_EXEC_VIOLATION,
            ttl_seconds=300,
        )
        status = hook.get_status(4242)

        assert status["pid"] == 4242
        assert status["state"] == "ACTIVE"
        assert status["quarantined"] is True
        assert status["action_flags"] == (MORAY_ACT_BLOCK_EXEC | MORAY_ACT_KILL)
        assert status["reason"] == MORAY_REASON_EXEC_VIOLATION
        assert status["strike_count"] == 0
        assert status["ttl_seconds"] == 300
        assert isinstance(status["remaining_seconds"], int)
        assert 295 <= status["remaining_seconds"] <= 300


class TestCLIPolicyVerbs:
    """Verifies command line interface with Phase 3 arguments."""

    def test_cli_strike_with_ttl_and_status_json(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "cli_quarantine.bin")
        script = str(Path(__file__).resolve().parent.parent / "bridge" / "lobster_hook.py")

        # 1. Strike PID 5555 with TTL 10s
        res_strike = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                "5555",
                "--strike",
                "--ttl",
                "10",
                "--mock",
                "--map-path",
                mock_file,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_strike.returncode == 0
        assert "STRIKE" in res_strike.stdout
        assert "TTL: 10s" in res_strike.stdout

        # 2. Query status as JSON
        res_status = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                "5555",
                "--status",
                "--json",
                "--mock",
                "--map-path",
                mock_file,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_status.returncode == 0
        status_data = json.loads(res_status.stdout)
        assert status_data["pid"] == 5555
        assert status_data["state"] == "ACTIVE"
        assert status_data["ttl_seconds"] == 10
        assert status_data["quarantined"] is True

        # 3. List entries as JSON
        res_list = subprocess.run(
            [sys.executable, script, "--list", "--json", "--mock", "--map-path", mock_file],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_list.returncode == 0
        list_data = json.loads(res_list.stdout)
        assert len(list_data) == 1
        assert list_data[0]["pid"] == 5555
        assert list_data[0]["ttl_seconds"] == 10

    def test_cli_evict_expired(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "cli_evict.bin")
        script = str(Path(__file__).resolve().parent.parent / "bridge" / "lobster_hook.py")

        # Strike PID 7777 with TTL 1s
        res_s = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                "7777",
                "--strike",
                "--ttl",
                "1",
                "--mock",
                "--map-path",
                mock_file,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_s.returncode == 0

        time.sleep(1.1)

        # Evict expired via CLI
        res_evict = subprocess.run(
            [sys.executable, script, "--evict-expired", "--mock", "--map-path", mock_file],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_evict.returncode == 0
        assert "EVICTED 1 expired quarantine entries" in res_evict.stdout

        # Verify status is now NONE
        res_status = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                "7777",
                "--status",
                "--json",
                "--mock",
                "--map-path",
                mock_file,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_status.returncode == 0
        status_data = json.loads(res_status.stdout)
        assert status_data["state"] == "NONE"
