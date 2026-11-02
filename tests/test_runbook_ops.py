# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Phase 5 Operational & Runbook Unit Tests
Validates systemd unit hardening directives, healthcheck probes,
emergency break-glass procedures, and disaster recovery lifecycle.
"""

from __future__ import annotations

import configparser
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from bridge.lobster_hook import (
    MorayHook,
    MorayQuarantineError,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestSystemdUnitContract:
    """Verifies production hardening contracts in packaging/systemd/morayd.service."""

    def test_systemd_unit_file_exists(self) -> None:
        service_path = REPO_ROOT / "packaging" / "systemd" / "morayd.service"
        assert service_path.exists(), f"Missing systemd service unit: {service_path}"

    def test_systemd_unit_hardening_directives(self) -> None:
        service_path = REPO_ROOT / "packaging" / "systemd" / "morayd.service"
        content = service_path.read_text(encoding="utf-8")

        # Parse with configparser using interpolation disabled
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(content)

        assert parser.has_section("Unit")
        assert parser.has_section("Service")
        assert parser.has_section("Install")

        service = dict(parser.items("Service"))

        # Verify fail-closed preflight is executed prior to daemon start
        assert "--preflight" in service.get("execstartpre", "")

        # Verify mandatory kernel security sandboxing
        assert service.get("nonewprivileges") == "true"
        assert service.get("protectsystem") == "strict"
        assert service.get("protecthome") == "true"
        assert service.get("privatetmp") == "true"
        assert service.get("memorydenywriteexecute") == "true"
        assert service.get("restrictrealtime") == "true"
        assert service.get("limitmemlock") == "infinity"
        assert service.get("restart") == "on-failure"

        # Verify bounding capabilities
        caps = service.get("capabilityboundingset", "")
        assert "CAP_BPF" in caps
        assert "CAP_SYS_ADMIN" in caps
        assert "CAP_KILL" in caps


class TestHealthcheckProbe:
    """Verifies operational liveness/readiness probe API and CLI."""

    def test_healthcheck_mock_mode(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "health_quarantine.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)

        health = hook.healthcheck()
        assert health["status"] == "healthy"
        assert health["mock_mode"] is True
        assert health["map_accessible"] is True
        assert health["bpffs_mounted"] is True
        assert health["quarantined_count"] == 0

        # Assert strike increments quarantined count
        hook.strike(3001)
        health_updated = hook.healthcheck()
        assert health_updated["quarantined_count"] == 1

    def test_cli_healthcheck_json(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "health_cli.bin")
        script = str(REPO_ROOT / "bridge" / "lobster_hook.py")

        res = subprocess.run(
            [sys.executable, script, "--healthcheck", "--mock", "--map-path", mock_file, "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data["status"] == "healthy"
        assert data["mock_mode"] is True
        assert data["quarantined_count"] == 0


class TestEmergencyBreakGlassFlush:
    """Verifies disaster recovery break-glass procedures."""

    def test_flush_all_requires_force(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "flush_test.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)
        hook.strike(4001)

        with pytest.raises(
            MorayQuarantineError, match="Emergency flush requires explicit confirmation"
        ):
            hook.flush_all(force=False)

        assert hook.is_quarantined(4001) is True

    def test_flush_all_clears_all_entries(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "flush_test.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)
        hook.strike(4001, ttl_seconds=0)
        hook.strike(4002, ttl_seconds=60)
        hook.strike(4003, ttl_seconds=120)

        assert len(hook.list_quarantined()) == 3

        flushed = hook.flush_all(force=True)
        assert flushed == 3
        assert len(hook.list_quarantined()) == 0
        assert hook.is_quarantined(4001) is False
        assert hook.is_quarantined(4002) is False
        assert hook.is_quarantined(4003) is False

    def test_cli_flush_all_lifecycle(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "flush_cli.bin")
        script = str(REPO_ROOT / "bridge" / "lobster_hook.py")

        # 1. Strike PID 8888
        subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                "8888",
                "--strike",
                "--mock",
                "--map-path",
                mock_file,
            ],
            check=True,
        )

        # 2. Try flush without --force -> must fail closed
        res_fail = subprocess.run(
            [sys.executable, script, "--flush-all", "--mock", "--map-path", mock_file],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_fail.returncode == 252  # Fail-closed exit code
        assert "FAIL-CLOSED" in res_fail.stderr

        # 3. Flush with --force -> success
        res_ok = subprocess.run(
            [
                sys.executable,
                script,
                "--flush-all",
                "--force",
                "--mock",
                "--map-path",
                mock_file,
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_ok.returncode == 0
        data = json.loads(res_ok.stdout)
        assert data["status"] == "flushed"
        assert data["count"] == 1


class TestDisasterRecoveryMapRecreation:
    """Verifies that deleting or unlinking corrupted state recovers safely."""

    def test_recovery_from_deleted_map(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "corrupted_map.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)
        hook.strike(9001)
        assert hook.is_quarantined(9001) is True

        # Simulate emergency unpinning / rm -f /sys/fs/bpf/moray/*
        os.unlink(mock_file)
        assert not os.path.exists(mock_file)

        # Re-initialize hook (post-recovery daemon start)
        new_hook = MorayHook(map_path=mock_file, mock_mode=True)
        assert new_hook.is_quarantined(9001) is False
        assert len(new_hook.list_quarantined()) == 0

        # Verify normal operation resumes
        new_hook.strike(9002)
        assert new_hook.is_quarantined(9002) is True
