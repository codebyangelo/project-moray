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

    def test_e2e_boundary_manifest_verification(self, tmp_path: Path) -> None:
        """MorayHook verifies boundary manifest against boundary table."""
        from bridge.moray_hook import (
            MORAY_PERM_ALL,
            MORAY_PERM_EXEC,
            MORAY_PERM_LOOPBACK,
            MorayBoundaryEntry,
            MorayQuarantineError,
        )

        hook = MorayHook(mock_mode=True)

        # Seed mock boundary entries for ALLOW_LOOPBACK
        sentinel = MorayBoundaryEntry()
        sentinel.perm_flags = MORAY_PERM_EXEC | MORAY_PERM_LOOPBACK
        hook._mock_boundary_table["__moray_auto__"] = sentinel

        vw = MorayBoundaryEntry()
        vw.perm_flags = MORAY_PERM_EXEC
        hook._mock_boundary_table["victim_worker"] = vw

        daemon = MorayBoundaryEntry()
        daemon.perm_flags = MORAY_PERM_ALL
        hook._mock_boundary_table["morayd"] = daemon

        manifest_file = tmp_path / "test_manifest.json"
        manifest_data = {
            "version": "1.0.0",
            "target_name": "test-agent",
            "boundary_policy": {
                "default_action": "AUTONOMOUS_STRIKE",
                "allowed_comms": ["morayd", "victim_worker"],
                "network_posture": "ALLOW_LOOPBACK",
            },
        }
        manifest_file.write_text(json.dumps(manifest_data))

        res = hook.verify_boundary_manifest(str(manifest_file))
        assert res["status"] == "verified"
        assert res["network_posture"] == "ALLOW_LOOPBACK"

        boundary_list = hook.list_boundary()
        assert "__moray_auto__" in boundary_list
        assert boundary_list["victim_worker"]["can_exec"] is True
        assert boundary_list["victim_worker"]["can_socket"] is False
        assert boundary_list["victim_worker"]["can_loopback"] is False
        assert boundary_list["morayd"]["can_exec"] is True
        assert boundary_list["morayd"]["can_socket"] is True
        assert boundary_list["__moray_auto__"]["can_exec"] is True
        assert boundary_list["__moray_auto__"]["can_loopback"] is True
        assert boundary_list["__moray_auto__"]["can_socket"] is False

        # Verify DENY_ALL_NET posture
        sentinel_deny = MorayBoundaryEntry()
        sentinel_deny.perm_flags = MORAY_PERM_EXEC  # No loopback, no socket
        hook._mock_boundary_table["__moray_auto__"] = sentinel_deny

        manifest_deny_file = tmp_path / "test_manifest_deny.json"
        manifest_deny_data = {
            "version": "1.0.0",
            "target_name": "test-agent-isolated",
            "boundary_policy": {
                "default_action": "AUTONOMOUS_STRIKE",
                "allowed_comms": ["morayd", "victim_worker"],
                "network_posture": "DENY_ALL_NET",
            },
        }
        manifest_deny_file.write_text(json.dumps(manifest_deny_data))

        res_deny = hook.verify_boundary_manifest(str(manifest_deny_file))
        assert res_deny["status"] == "verified"
        assert res_deny["network_posture"] == "DENY_ALL_NET"
        assert hook.list_boundary()["__moray_auto__"]["can_loopback"] is False

        # Negative check: sentinel improperly has MORAY_PERM_LOOPBACK under DENY_ALL_NET
        sentinel_deny.perm_flags = MORAY_PERM_EXEC | MORAY_PERM_LOOPBACK
        with pytest.raises(
            MorayQuarantineError, match="improperly has MORAY_PERM_LOOPBACK under DENY_ALL_NET"
        ):
            hook.verify_boundary_manifest(str(manifest_deny_file))

        # Reset sentinel for DENY_ALL_NET
        sentinel_deny.perm_flags = MORAY_PERM_EXEC

        # Negative check: worker comm improperly granted MORAY_PERM_SOCKET under DENY_ALL_NET
        vw.perm_flags = MORAY_PERM_ALL
        with pytest.raises(
            MorayQuarantineError, match="improperly granted MORAY_PERM_SOCKET under DENY_ALL_NET"
        ):
            hook.verify_boundary_manifest(str(manifest_deny_file))

        # Verify REQUIRE_WAN posture
        sentinel_wan = MorayBoundaryEntry()
        sentinel_wan.perm_flags = MORAY_PERM_ALL
        hook._mock_boundary_table["__moray_auto__"] = sentinel_wan

        vw_wan = MorayBoundaryEntry()
        vw_wan.perm_flags = MORAY_PERM_ALL
        hook._mock_boundary_table["victim_worker"] = vw_wan

        manifest_wan_file = tmp_path / "test_manifest_wan.json"
        manifest_wan_data = {
            "version": "1.0.0",
            "target_name": "test-agent-wan",
            "boundary_policy": {
                "default_action": "AUTONOMOUS_STRIKE",
                "allowed_comms": ["morayd", "victim_worker"],
                "network_posture": "REQUIRE_WAN",
            },
        }
        manifest_wan_file.write_text(json.dumps(manifest_wan_data))

        res_wan = hook.verify_boundary_manifest(str(manifest_wan_file))
        assert res_wan["status"] == "verified"
        assert res_wan["network_posture"] == "REQUIRE_WAN"
        assert hook.list_boundary()["__moray_auto__"]["can_socket"] is True
        assert hook.list_boundary()["victim_worker"]["can_socket"] is True

        # Negative check: sentinel missing MORAY_PERM_SOCKET under REQUIRE_WAN
        sentinel_wan.perm_flags = MORAY_PERM_EXEC
        with pytest.raises(
            MorayQuarantineError, match="missing MORAY_PERM_SOCKET under REQUIRE_WAN"
        ):
            hook.verify_boundary_manifest(str(manifest_wan_file))
        sentinel_wan.perm_flags = MORAY_PERM_ALL

        # Negative check: worker comm missing MORAY_PERM_SOCKET under REQUIRE_WAN
        vw_wan.perm_flags = MORAY_PERM_EXEC
        with pytest.raises(
            MorayQuarantineError, match="missing MORAY_PERM_SOCKET under REQUIRE_WAN"
        ):
            hook.verify_boundary_manifest(str(manifest_wan_file))
        vw_wan.perm_flags = MORAY_PERM_ALL

        # Restore victim_worker and sentinel for ALLOW_LOOPBACK
        vw.perm_flags = MORAY_PERM_EXEC
        sentinel.perm_flags = MORAY_PERM_EXEC | MORAY_PERM_LOOPBACK
        hook._mock_boundary_table["__moray_auto__"] = sentinel

        # Negative check 1: manifest with missing comm fails closed
        bad_manifest = tmp_path / "bad_manifest.json"
        bad_data = {
            "version": "1.0.0",
            "target_name": "bad-agent",
            "boundary_policy": {
                "default_action": "AUTONOMOUS_STRIKE",
                "allowed_comms": ["unlisted_worker"],
                "network_posture": "ALLOW_LOOPBACK",
            },
        }
        bad_manifest.write_text(json.dumps(bad_data))
        with pytest.raises(MorayQuarantineError, match="missing from kernel"):
            hook.verify_boundary_manifest(str(bad_manifest))

        # Negative check 2: worker comm improperly granted MORAY_PERM_SOCKET under ALLOW_LOOPBACK fails closed
        vw_leaky = MorayBoundaryEntry()
        vw_leaky.perm_flags = MORAY_PERM_ALL
        hook._mock_boundary_table["victim_worker"] = vw_leaky
        with pytest.raises(
            MorayQuarantineError, match="improperly granted MORAY_PERM_SOCKET under ALLOW_LOOPBACK"
        ):
            hook.verify_boundary_manifest(str(manifest_file))

        # Restore victim_worker to valid state
        vw.perm_flags = MORAY_PERM_EXEC
        hook._mock_boundary_table["victim_worker"] = vw

        # Negative check 3: sentinel missing MORAY_PERM_LOOPBACK under ALLOW_LOOPBACK fails closed
        sentinel.perm_flags = MORAY_PERM_EXEC
        with pytest.raises(
            MorayQuarantineError, match="missing MORAY_PERM_LOOPBACK under ALLOW_LOOPBACK"
        ):
            hook.verify_boundary_manifest(str(manifest_file))
        sentinel.perm_flags = MORAY_PERM_EXEC | MORAY_PERM_LOOPBACK

        # Negative check 4: missing morayd daemon self-entry fails closed
        del hook._mock_boundary_table["morayd"]
        with pytest.raises(MorayQuarantineError, match="missing from kernel"):
            hook.verify_boundary_manifest(str(manifest_file))

        # Check when morayd is not in allowed_comms, Section 3 catches missing morayd
        manifest_no_daemon = tmp_path / "test_no_daemon.json"
        manifest_no_daemon.write_text(
            json.dumps(
                {
                    "version": "1.0.0",
                    "boundary_policy": {
                        "default_action": "AUTONOMOUS_STRIKE",
                        "allowed_comms": ["victim_worker"],
                        "network_posture": "ALLOW_LOOPBACK",
                    },
                }
            )
        )
        with pytest.raises(MorayQuarantineError, match="Daemon entry 'morayd' missing"):
            hook.verify_boundary_manifest(str(manifest_no_daemon))

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
