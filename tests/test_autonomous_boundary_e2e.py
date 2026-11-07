# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: End-to-End Autonomous Boundary Defense Verification Suite
Validates the sovereign Moray pipeline:
Workspace -> Native Profiler -> Boundary Generator -> Moray Daemon Auto-Harden ->
Adversarial Injection Matrix -> Live Telemetry Streaming (NDJSON) -> Optional Octopus SARIF Audit.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bridge.moray_hook import (
    FAIL_CLOSED_EXIT_CODE,
    MORAY_ACT_BLOCK_EXEC,
    MORAY_ACT_BLOCK_SOCKET,
    MORAY_ACT_KILL,
    MORAY_REASON_EXEC_VIOLATION,
    MORAY_REASON_TAMPER_ATTEMPT,
    MorayBoundaryProfiler,
    MorayEvent,
    MorayHook,
    MorayTelemetryConsumer,
)


def _find_octopus_verifier() -> Path | None:
    """Safely locate Project Octopus verifier without triggering permission errors in CI."""
    candidates: list[Path] = []
    env_path = os.getenv("OCTOPUS_VERIFIER_PATH")
    if env_path:
        candidates.append(Path(env_path))

    # Sibling directory check (portable relative to repo root)
    candidates.append(REPO_ROOT.parent / "project-octopus" / "v2.0.0" / "octopus_verifier.py")

    # Local development fallback
    candidates.append(Path("/root/home/projects/project-octopus/v2.0.0/octopus_verifier.py"))

    for cand in candidates:
        try:
            if cand.is_file() and os.access(cand, os.R_OK):
                return cand
        except (PermissionError, OSError):
            continue
    return None


OCTOPUS_VERIFIER = _find_octopus_verifier()
OCTOPUS_AVAILABLE = OCTOPUS_VERIFIER is not None


class TestAutonomousBoundaryE2E:
    """End-to-End integration testing for zero-configuration autonomous boundary defense."""

    def test_e2e_sovereign_profiler_and_boundary_generation(self, tmp_path: Path) -> None:
        """Native Moray profiler inspects workspace and emits compliant boundary manifest with zero external dependencies."""
        profiler = MorayBoundaryProfiler(REPO_ROOT)
        manifest = profiler.generate_manifest()

        assert manifest["version"] == "1.0.0"
        assert manifest["target_name"] == "project-moray"
        policy = manifest["boundary_policy"]
        assert policy["default_action"] == "AUTONOMOUS_STRIKE"
        assert policy["network_posture"] in ("ALLOW_LOOPBACK", "REQUIRE_WAN")
        assert "morayd" in policy["allowed_comms"]
        assert "python3" in policy["allowed_comms"]
        assert "make" in policy["allowed_comms"]

        out_file = tmp_path / "moray_boundary.json"
        profiler.write_manifest(out_file)
        assert out_file.exists()

        with open(out_file, encoding="utf-8") as f:
            data = json.load(f)
        assert data["boundary_policy"]["default_action"] == "AUTONOMOUS_STRIKE"

    def test_e2e_morayd_auto_harden_startup(self, tmp_path: Path) -> None:
        """morayd consumes boundary manifest and seeds autonomous boundary map on boot."""
        daemon_bin = REPO_ROOT / "bin" / "morayd"
        if not daemon_bin.exists():
            subprocess.run(["make", "daemon"], cwd=str(REPO_ROOT), check=True)

        manifest = tmp_path / "moray_boundary.json"
        manifest_data = {
            "version": "1.0.0",
            "target_name": "test-agent",
            "boundary_policy": {
                "default_action": "AUTONOMOUS_STRIKE",
                "allowed_comms": ["morayd", "victim_worker", "python3"],
                "allowed_paths": ["/bin/morayd", "/tmp/victim_worker"],
                "network_posture": "ALLOW_LOOPBACK",
            },
        }
        manifest.write_text(json.dumps(manifest_data))

        mock_pin_dir = tmp_path / "moray_e2e_pin"
        proc = subprocess.Popen(
            [str(daemon_bin), "--mock", str(mock_pin_dir), "--auto-harden", str(manifest)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            time.sleep(0.3)
            assert proc.poll() is None, "morayd failed to launch in auto-harden mode"

            boundary_map = mock_pin_dir / "boundary_map"
            assert boundary_map.exists()
            assert boundary_map.stat().st_size == 32768  # 1024 entries * 32 bytes

            proc.send_signal(signal.SIGTERM)
            stdout, _ = proc.communicate(timeout=3)
            assert proc.returncode == 0
            assert (
                "Autonomous Ring 0 Boundary Defense ACTIVE" in stdout or "PROJECT MORAY" in stdout
            )
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_e2e_adversarial_payload_containment_matrix(self) -> None:
        """Simulated adversarial injections verify autonomous interception across all vectors."""
        hook = MorayHook()  # Mock mode
        test_pid = 77001

        # Vector 1: Prompt injection attempting unauthorized binary execution
        hook.strike(
            test_pid,
            action_flags=MORAY_ACT_BLOCK_EXEC | MORAY_ACT_BLOCK_SOCKET,
            reason=MORAY_REASON_EXEC_VIOLATION,
        )
        assert hook.is_quarantined(test_pid) is True
        status = hook.get_status(test_pid)
        assert status is not None
        assert int(status["action_flags"]) & MORAY_ACT_BLOCK_EXEC

        # Vector 2: Tamper attempt (calling sys_bpf on protected maps)
        hook.strike(
            test_pid,
            action_flags=MORAY_ACT_KILL,
            reason=MORAY_REASON_TAMPER_ATTEMPT,
        )
        status_after_tamper = hook.get_status(test_pid)
        assert status_after_tamper is not None
        assert int(status_after_tamper["action_flags"]) & MORAY_ACT_KILL
        assert status_after_tamper["reason"] == MORAY_REASON_TAMPER_ATTEMPT

        # Clean release
        assert hook.release(test_pid) is True
        assert hook.is_quarantined(test_pid) is False

        # Fail-closed invariant validation
        assert FAIL_CLOSED_EXIT_CODE == 252

    def test_e2e_telemetry_stream_drain(self, tmp_path: Path) -> None:
        """Moray telemetry consumer drains events and streams valid NDJSON."""
        mock_events_file = tmp_path / "mock_events.ndjson"

        consumer = MorayTelemetryConsumer(events_path=str(mock_events_file), mock_mode=True)

        ev1 = MorayEvent()
        ev1.timestamp_ns = 1234567890
        ev1.pid = 9901
        ev1.tgid = 9901
        ev1.uid = 0
        ev1.action_taken = MORAY_ACT_BLOCK_EXEC
        ev1.ret_code = -1
        ev1.hook_point = 1
        ev1.drop_count = 1
        ev1.comm = b"unauthorized_sh"

        consumer.emit_mock_event(ev1)

        events = consumer.poll(timeout_ms=50)
        assert len(events) == 1
        rec = events[0]
        assert rec.pid == 9901
        d = rec.to_dict()
        assert d["comm"] == "unauthorized_sh"
        assert d["hook_name"] == "BPRM_CHECK_SECURITY"

        # Verify NDJSON serialization
        raw_json = rec.to_json()
        data = json.loads(raw_json)
        assert data["pid"] == 9901
        assert data["hook_name"] == "BPRM_CHECK_SECURITY"

    @pytest.mark.skipif(
        not OCTOPUS_AVAILABLE or OCTOPUS_VERIFIER is None,
        reason="Project Octopus verifier not available in runner environment",
    )
    def test_e2e_octopus_ecosystem_compliance_audit(self, tmp_path: Path) -> None:
        """Optional cross-repo compliance audit using Project Octopus if present in environment."""
        assert OCTOPUS_VERIFIER is not None
        report_dir = tmp_path / "reports"
        verifier_cmd = [
            sys.executable,
            str(OCTOPUS_VERIFIER),
            "--target",
            str(REPO_ROOT),
            "--pack",
            "marine_ecosystem",
            "--output-dir",
            str(report_dir),
        ]
        res = subprocess.run(verifier_cmd, capture_output=True, text=True, check=False)
        assert res.returncode == 0
        assert "VERIFICATION SUMMARY: 6/6 boundary tests passed (100.0%)" in res.stdout

        sarif_files = list(report_dir.glob("*.sarif"))
        assert len(sarif_files) == 1
        with open(sarif_files[0], encoding="utf-8") as f:
            sarif = json.load(f)
        assert sarif["version"] == "2.1.0"
