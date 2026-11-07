# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Daemon Lifecycle Smoke Tests
Verifies daemon initialization, mock VFS mounting, signal handling (SIGTERM), and clean shutdown.
"""

from __future__ import annotations

import signal
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestDaemonSmokeLifecycle:
    """Smoke testing for the morayd user-space daemon."""

    @pytest.fixture
    def daemon_bin(self) -> Path:
        bin_path = REPO_ROOT / "bin" / "morayd"
        if not bin_path.exists():
            # Build daemon if not present
            subprocess.run(["make", "daemon"], cwd=str(REPO_ROOT), check=True)
        return bin_path

    def test_daemon_help_flag(self, daemon_bin: Path) -> None:
        """Daemon prints usage and exits 0 on --help."""
        res = subprocess.run(
            [str(daemon_bin), "--help"],
            capture_output=True,
            check=False,
            text=True,
        )
        assert res.returncode == 0
        assert "Usage:" in res.stdout
        assert "--mock" in res.stdout
        assert "--iface" in res.stdout

    def test_daemon_mock_lifecycle_and_sigterm(self, daemon_bin: Path, tmp_path: Path) -> None:
        """Daemon starts in mock mode, pins mock maps (quarantine and xdp), and terminates cleanly."""
        mock_pin_dir = tmp_path / "moray_smoke_pin"
        proc = subprocess.Popen(
            [str(daemon_bin), "--mock", str(mock_pin_dir), "--iface", "lo"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # Allow daemon 300ms to initialize and print banner
            time.sleep(0.3)
            assert proc.poll() is None, "Daemon exited prematurely"

            # Verify mock map files were created
            quarantine_map = mock_pin_dir / "quarantine_map"
            assert quarantine_map.exists(), "quarantine_map was not pinned"
            assert quarantine_map.stat().st_size > 0, "quarantine_map was not preallocated"

            xdp_map = mock_pin_dir / "xdp_drop_map"
            assert xdp_map.exists(), "xdp_drop_map was not pinned"
            assert xdp_map.stat().st_size > 0, "xdp_drop_map was not preallocated"

            cgroup_map = mock_pin_dir / "cgroup_map"
            assert cgroup_map.exists(), "cgroup_map was not pinned"
            assert cgroup_map.stat().st_size > 0, "cgroup_map was not preallocated"

            boundary_map = mock_pin_dir / "boundary_map"
            assert boundary_map.exists(), "boundary_map was not pinned"
            assert boundary_map.stat().st_size > 0, "boundary_map was not preallocated"

            # Deliver SIGTERM for graceful shutdown
            proc.send_signal(signal.SIGTERM)
            stdout, _ = proc.communicate(timeout=3)

            assert proc.returncode == 0, f"Daemon exited with non-zero code: {proc.returncode}"
            assert "Signal received" in stdout or "PROJECT MORAY" in stdout

        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_daemon_invalid_path_fail_closed(self, daemon_bin: Path, tmp_path: Path) -> None:
        """Daemon exits non-zero if pin directory cannot be created (e.g. parent is a regular file)."""
        blocking_file = tmp_path / "not_a_dir"
        blocking_file.write_text("blocker")

        target_dir = blocking_file / "impossible_sub"
        res = subprocess.run(
            [str(daemon_bin), "--mock", str(target_dir)],
            capture_output=True,
            check=False,
            timeout=5,
            text=True,
        )
        assert res.returncode != 0
        assert "Cannot access or create pin directory" in res.stderr

    def test_daemon_auto_harden_flag(self, daemon_bin: Path, tmp_path: Path) -> None:
        """Daemon accepts --auto-harden and initializes boundary defense."""
        manifest = tmp_path / "moray_boundary.json"
        manifest.write_text(
            '{"boundary_policy": {"allowed_comms": ["python3", "morayd"], "network_posture": "ALLOW_LOOPBACK"}}'
        )

        mock_pin_dir = tmp_path / "moray_auto_pin"
        proc = subprocess.Popen(
            [str(daemon_bin), "--mock", str(mock_pin_dir), "--auto-harden", str(manifest)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            time.sleep(0.3)
            assert proc.poll() is None, "Daemon exited prematurely"

            boundary_map = mock_pin_dir / "boundary_map"
            assert boundary_map.exists(), "boundary_map was not pinned"

            proc.send_signal(signal.SIGTERM)
            stdout, _ = proc.communicate(timeout=3)
            assert proc.returncode == 0
            assert "PROJECT MORAY" in stdout
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
