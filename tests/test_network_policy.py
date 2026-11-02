# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Granular Network Egress Filtering & Socket Policy Test Suite
Enforces Invariant I_1 & I_4: Quarantined processes cannot establish unauthorized
outbound connections, while allowing local loopback/IPC when explicitly permitted.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from bridge.lobster_hook import (
    FAIL_CLOSED_EXIT_CODE,
    MORAY_ACT_ALLOW_LOOPBACK,
    MORAY_ACT_BLOCK_EXEC,
    MORAY_ACT_BLOCK_SOCKET,
    MORAY_ACT_DROP_NET,
    MORAY_ACT_FULL_STRIKE,
    MORAY_ACT_KILL,
    MORAY_ACT_NONE,
    MORAY_REASON_LOBSTER_L7,
    MorayHook,
)


class TestNetworkPolicyConstants:
    """Verifies bitmask definitions and isolation for network egress control."""

    def test_allow_loopback_flag_definition(self) -> None:
        assert MORAY_ACT_ALLOW_LOOPBACK == 0x10
        assert (MORAY_ACT_ALLOW_LOOPBACK & MORAY_ACT_BLOCK_EXEC) == 0
        assert (MORAY_ACT_ALLOW_LOOPBACK & MORAY_ACT_BLOCK_SOCKET) == 0
        assert (MORAY_ACT_ALLOW_LOOPBACK & MORAY_ACT_DROP_NET) == 0
        assert (MORAY_ACT_ALLOW_LOOPBACK & MORAY_ACT_KILL) == 0

    def test_full_strike_mask_encompasses_loopback_bit(self) -> None:
        # Full strike mask is 0xFF, which includes 0x10
        assert (MORAY_ACT_FULL_STRIKE & MORAY_ACT_ALLOW_LOOPBACK) == MORAY_ACT_ALLOW_LOOPBACK


class TestNetworkPolicyEngine:
    """Verifies MorayHook API handling of granular network egress flags."""

    def test_strike_with_allow_loopback_flag(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "quarantine.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)
        pid = 3131

        assert (
            hook.strike(
                pid,
                action_flags=MORAY_ACT_BLOCK_SOCKET,
                allow_loopback=True,
                reason=MORAY_REASON_LOBSTER_L7,
            )
            is True
        )

        entry = hook.get_entry(pid)
        assert entry is not None
        assert entry.action_flags == (MORAY_ACT_BLOCK_SOCKET | MORAY_ACT_ALLOW_LOOPBACK)

        status = hook.get_status(pid)
        assert status["state"] == "ACTIVE"
        assert status["quarantined"] is True
        assert status["allow_loopback"] is True
        assert status["action_flags"] == (MORAY_ACT_BLOCK_SOCKET | MORAY_ACT_ALLOW_LOOPBACK)

    def test_strike_without_allow_loopback_flag(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "quarantine.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)
        pid = 3132

        assert (
            hook.strike(
                pid,
                action_flags=MORAY_ACT_BLOCK_SOCKET,
                allow_loopback=False,
            )
            is True
        )

        entry = hook.get_entry(pid)
        assert entry is not None
        assert entry.action_flags == MORAY_ACT_BLOCK_SOCKET

        status = hook.get_status(pid)
        assert status["allow_loopback"] is False
        assert status["action_flags"] == MORAY_ACT_BLOCK_SOCKET

    def test_policy_status_unquarantined_pid(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "quarantine.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)
        status = hook.get_status(9999)
        assert status["allow_loopback"] is False
        assert status["action_flags"] == MORAY_ACT_NONE


class TestNetworkPolicyCLI:
    """Verifies CLI verbs for granular network policies (--block-wan, --deny-all-net, --allow-loopback)."""

    @pytest.fixture
    def hook_cli(self, tmp_path: Path) -> tuple[str, str]:
        mock_file = str(tmp_path / "cli_net_quarantine.bin")
        script = str(Path(__file__).resolve().parent.parent / "bridge" / "lobster_hook.py")
        return script, mock_file

    def test_cli_block_wan(self, hook_cli: tuple[str, str]) -> None:
        script, mock_file = hook_cli
        pid = 4001

        res = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                str(pid),
                "--block-wan",
                "--json",
                "--mock",
                "--map-path",
                mock_file,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data["status"] == "asserted"
        assert data["policy"] == "block-wan"
        assert data["pid"] == pid
        assert data["allow_loopback"] is True
        assert data["action_flags"] == (MORAY_ACT_BLOCK_SOCKET | MORAY_ACT_ALLOW_LOOPBACK)

        # Query status to verify persistence
        res_status = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                str(pid),
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
        assert status_data["quarantined"] is True
        assert status_data["allow_loopback"] is True

    def test_cli_deny_all_net(self, hook_cli: tuple[str, str]) -> None:
        script, mock_file = hook_cli
        pid = 4002

        res = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                str(pid),
                "--deny-all-net",
                "--json",
                "--mock",
                "--map-path",
                mock_file,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data["status"] == "asserted"
        assert data["policy"] == "deny-all-net"
        assert data["pid"] == pid
        assert data["allow_loopback"] is False
        assert data["action_flags"] == (MORAY_ACT_BLOCK_SOCKET | MORAY_ACT_DROP_NET)

        # Query status
        res_status = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                str(pid),
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
        assert status_data["quarantined"] is True
        assert status_data["allow_loopback"] is False

    def test_cli_strike_with_allow_loopback(self, hook_cli: tuple[str, str]) -> None:
        script, mock_file = hook_cli
        pid = 4003

        res = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                str(pid),
                "--strike",
                "--action",
                str(MORAY_ACT_BLOCK_SOCKET),
                "--allow-loopback",
                "--mock",
                "--map-path",
                mock_file,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert "STRIKE" in res.stdout
        assert "Granular Loopback Allowed" in res.stdout

    def test_cli_invalid_pid_fails_closed(self, hook_cli: tuple[str, str]) -> None:
        script, mock_file = hook_cli
        for flag in ["--block-wan", "--deny-all-net"]:
            res = subprocess.run(
                [
                    sys.executable,
                    script,
                    "--pid",
                    "-1",
                    flag,
                    "--mock",
                    "--map-path",
                    mock_file,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            assert res.returncode == FAIL_CLOSED_EXIT_CODE
            assert "FAIL-CLOSED" in res.stderr

    def test_cli_missing_pid_returns_parser_error(self, hook_cli: tuple[str, str]) -> None:
        script, mock_file = hook_cli
        for flag in ["--block-wan", "--deny-all-net"]:
            res = subprocess.run(
                [
                    sys.executable,
                    script,
                    flag,
                    "--mock",
                    "--map-path",
                    mock_file,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            assert res.returncode == 2
            assert "requires --pid" in res.stderr
