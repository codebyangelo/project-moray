# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Operational Confidence, Health/Readiness Probes & Recovery Tests
Verifies daemon health probes (--health, --readiness, --json), emergency pin cleanup,
stale pin recovery resilience, and cross-language bridge readiness reporting.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from bridge.lobster_hook import MorayHook, MorayQuarantineError

REPO_ROOT = Path(__file__).resolve().parent.parent
MORAYD_BIN = REPO_ROOT / "bin" / "morayd"
LOBSTER_HOOK = REPO_ROOT / "bridge" / "lobster_hook.py"


@pytest.fixture
def mock_pin_dir():
    """Create a temporary directory seeded with all 6 mock map files."""
    with tempfile.TemporaryDirectory(prefix="moray_health_test_") as tmpdir:
        for name in [
            "quarantine_map",
            "events",
            "xdp_drop_map",
            "cgroup_map",
            "boundary_map",
            "workload_map",
        ]:
            file_path = os.path.join(tmpdir, name)
            with open(file_path, "wb") as f:
                f.write(b"\x00" * 64)
        yield tmpdir


class TestOperationalHealthAndRecovery:
    def test_morayd_health_mock_success(self, mock_pin_dir):
        """Verify morayd --health returns exit code 0 and reports HEALTHY in mock mode."""
        res = subprocess.run(
            [str(MORAYD_BIN), "--mock", mock_pin_dir, "--health"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0, f"morayd --health failed: {res.stderr}"
        assert "Overall Status: HEALTHY" in res.stdout
        assert "Ready: YES" in res.stdout
        assert "6/6 accessible" in res.stdout

    def test_morayd_health_mock_json_schema(self, mock_pin_dir):
        """Verify morayd --health --json emits valid JSON matching operational schema."""
        res = subprocess.run(
            [str(MORAYD_BIN), "--mock", mock_pin_dir, "--health", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0, f"morayd --health --json failed: {res.stderr}"
        data = json.loads(res.stdout)
        assert data["status"] == "HEALTHY"
        assert data["ready"] is True
        assert data["mock_mode"] is True
        assert data["maps_accessible"] == 6
        assert data["maps"]["quarantine_map"] is True
        assert data["maps"]["events"] is True
        assert data["maps"]["xdp_drop_map"] is True
        assert data["maps"]["cgroup_map"] is True
        assert data["maps"]["boundary_map"] is True
        assert data["maps"]["workload_map"] is True
        assert data["warnings"] == []

    def test_morayd_readiness_mock_success(self, mock_pin_dir):
        """Verify morayd --readiness exits 0 when all maps are present."""
        res = subprocess.run(
            [str(MORAYD_BIN), "--mock", mock_pin_dir, "--readiness", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data["ready"] is True

    def test_morayd_health_degraded_when_map_missing(self, mock_pin_dir):
        """Verify morayd --health returns exit code 1 and reports DEGRADED when a map is missing."""
        # Delete boundary_map to induce degraded state
        os.unlink(os.path.join(mock_pin_dir, "boundary_map"))
        res = subprocess.run(
            [str(MORAYD_BIN), "--mock", mock_pin_dir, "--health", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 1, "Should exit 1 on degraded health"
        data = json.loads(res.stdout)
        assert data["status"] == "DEGRADED"
        assert data["ready"] is False
        assert data["maps_accessible"] == 5
        assert data["maps"]["boundary_map"] is False
        assert len(data["warnings"]) >= 1

    def test_morayd_clean_pins_removes_files(self, mock_pin_dir):
        """Verify morayd --clean-pins unlinks all pinned files and exits 0."""
        res = subprocess.run(
            [str(MORAYD_BIN), "--clean-pins", "--pin-dir", mock_pin_dir],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert "Emergency pin cleanup complete. Unlinked 6 pins." in res.stdout
        # Verify files no longer exist
        for name in [
            "quarantine_map",
            "events",
            "xdp_drop_map",
            "cgroup_map",
            "boundary_map",
            "workload_map",
        ]:
            assert not os.path.exists(os.path.join(mock_pin_dir, name))

    def test_lobster_hook_healthcheck_mock_data(self):
        """Verify Python bridge healthcheck returns comprehensive readiness report."""
        hook = MorayHook(mock_mode=True)
        health = hook.healthcheck()
        assert health["status"] == "healthy"
        assert health["ready"] is True
        assert health["mock_mode"] is True
        assert health["map_accessible"] is True
        assert health["xdp_accessible"] is True
        assert health["cgroup_accessible"] is True
        assert health["boundary_accessible"] is True
        assert health["workload_accessible"] is True
        assert health["events_accessible"] is True
        assert health["bpffs_mounted"] is True
        assert health["bpf_lsm_active"] is True
        assert "boundary_count" in health
        assert "workload_count" in health

    def test_lobster_hook_healthcheck_cli_json(self):
        """Verify lobster_hook.py --mock --healthcheck --json runs and emits structured JSON."""
        res = subprocess.run(
            ["python3", str(LOBSTER_HOOK), "--mock", "--healthcheck", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data["status"] == "healthy"
        assert data["ready"] is True
        assert data["boundary_accessible"] is True
        assert data["workload_accessible"] is True

    def test_lobster_hook_readiness_cli(self):
        """Verify lobster_hook.py --mock --readiness exits 0."""
        res = subprocess.run(
            ["python3", str(LOBSTER_HOOK), "--mock", "--readiness"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert "Ready:            True" in res.stdout

    def test_lobster_hook_non_bpf_path_fails_closed(self):
        """Verify lobster_hook in non-mock mode against non-bpffs paths raises MorayQuarantineError."""
        with tempfile.TemporaryDirectory() as empty_dir:
            quarantine_path = os.path.join(empty_dir, "quarantine_map")
            with open(quarantine_path, "wb") as f:
                f.write(b"")
            with pytest.raises(MorayQuarantineError):
                MorayHook(
                    map_path=quarantine_path,
                    events_path=os.path.join(empty_dir, "events"),
                    xdp_map_path=os.path.join(empty_dir, "xdp_drop_map"),
                    cgroup_map_path=os.path.join(empty_dir, "cgroup_map"),
                    boundary_map_path=os.path.join(empty_dir, "boundary_map"),
                    workload_map_path=os.path.join(empty_dir, "workload_map"),
                    mock_mode=False,
                )

    def test_systemd_service_file_directives(self):
        """Verify packaging/systemd/morayd.service contains required hardening & readiness directives."""
        service_file = REPO_ROOT / "packaging" / "systemd" / "morayd.service"
        assert service_file.exists()
        content = service_file.read_text(encoding="utf-8")
        assert "ExecStartPre=/usr/local/bin/morayd --preflight" in content
        assert "ExecStart=/usr/local/bin/morayd --pin-dir /sys/fs/bpf/moray" in content
        assert (
            "ExecStartPost=/usr/local/bin/morayd --readiness --pin-dir /sys/fs/bpf/moray" in content
        )
        assert "LimitMEMLOCK=infinity" in content
        assert "CapabilityBoundingSet=" in content
        assert "ProtectSystem=strict" in content
