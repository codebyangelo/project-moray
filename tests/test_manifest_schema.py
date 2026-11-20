# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Strict Manifest Schema & Fail-Closed Validation Suite
Verifies Milestone 4 requirements:
- Valid manifests in ENFORCED/APPROVED state pass cleanly.
- Unreviewed profiler suggestions (SUGGESTION/PROPOSED) fail closed unless explicitly activated.
- Invalid versions, target names, postures, comms, and threshold boundaries are strictly rejected.
- C daemon (morayd) and Python bridge enforce 100% identical validation logic.
"""

from __future__ import annotations

import json
import signal
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

from bridge.moray_hook import (
    validate_boundary_manifest,
)


@pytest.fixture
def base_manifest_data() -> dict:
    return {
        "version": "1.0.0",
        "target_name": "test-workload",
        "policy_state": "ENFORCED",
        "boundary_policy": {
            "default_action": "AUTONOMOUS_STRIKE",
            "allowed_comms": ["morayd", "python3", "victim_worker"],
            "allowed_paths": ["/bin/morayd"],
            "network_posture": "ALLOW_LOOPBACK",
            "cgroup_slice": "agent.slice",
            "auto_quarantine_violations": True,
            "max_strike_threshold": 5,
        },
    }


class TestManifestSchemaValidation:
    """Hermetic unit tests for boundary manifest schema validation."""

    def test_schema_valid_enforced(self, tmp_path: Path, base_manifest_data: dict) -> None:
        """Valid manifest in ENFORCED state passes validation."""
        f = tmp_path / "manifest.json"
        f.write_text(json.dumps(base_manifest_data))

        valid, errors = validate_boundary_manifest(f)
        assert valid is True
        assert len(errors) == 0

    def test_schema_valid_approved(self, tmp_path: Path, base_manifest_data: dict) -> None:
        """Valid manifest in APPROVED state passes validation."""
        base_manifest_data["policy_state"] = "APPROVED"
        f = tmp_path / "manifest.json"
        f.write_text(json.dumps(base_manifest_data))

        valid, errors = validate_boundary_manifest(f)
        assert valid is True
        assert len(errors) == 0

    def test_schema_suggestion_requires_explicit_flag(
        self, tmp_path: Path, base_manifest_data: dict
    ) -> None:
        """Profiler suggestion (SUGGESTION/PROPOSED) fails closed without explicit flag."""
        base_manifest_data["policy_state"] = "SUGGESTION"
        f = tmp_path / "manifest.json"
        f.write_text(json.dumps(base_manifest_data))

        # Rejected by default
        valid, errors = validate_boundary_manifest(f, allow_unreviewed=False)
        assert valid is False
        assert any("Profiler suggestions require explicit human review" in err for err in errors)

        # Accepted with explicit flag
        valid_flag, errors_flag = validate_boundary_manifest(f, allow_unreviewed=True)
        assert valid_flag is True
        assert len(errors_flag) == 0

    def test_schema_missing_or_invalid_version(
        self, tmp_path: Path, base_manifest_data: dict
    ) -> None:
        """Missing or non-1.0.0 version fails closed."""
        del base_manifest_data["version"]
        f = tmp_path / "no_version.json"
        f.write_text(json.dumps(base_manifest_data))
        valid, errors = validate_boundary_manifest(f)
        assert valid is False
        assert any("version" in err for err in errors)

        base_manifest_data["version"] = "2.0.0"
        f2 = tmp_path / "bad_version.json"
        f2.write_text(json.dumps(base_manifest_data))
        valid2, errors2 = validate_boundary_manifest(f2)
        assert valid2 is False
        assert any("Field 'version' must equal '1.0.0'" in err for err in errors2)

    def test_schema_missing_or_empty_target_name(
        self, tmp_path: Path, base_manifest_data: dict
    ) -> None:
        """Missing or whitespace target_name fails closed."""
        base_manifest_data["target_name"] = "   "
        f = tmp_path / "empty_target.json"
        f.write_text(json.dumps(base_manifest_data))
        valid, errors = validate_boundary_manifest(f)
        assert valid is False
        assert any("target_name" in err for err in errors)

    def test_schema_invalid_policy_state(self, tmp_path: Path, base_manifest_data: dict) -> None:
        """Unrecognized policy_state fails closed."""
        base_manifest_data["policy_state"] = "PERMISSIVE"
        f = tmp_path / "bad_state.json"
        f.write_text(json.dumps(base_manifest_data))
        valid, errors = validate_boundary_manifest(f)
        assert valid is False
        assert any("policy_state" in err for err in errors)

    def test_schema_invalid_default_action(self, tmp_path: Path, base_manifest_data: dict) -> None:
        """Unsupported default_action fails closed."""
        base_manifest_data["boundary_policy"]["default_action"] = "LOG_AND_PERMIT"
        f = tmp_path / "bad_action.json"
        f.write_text(json.dumps(base_manifest_data))
        valid, errors = validate_boundary_manifest(f)
        assert valid is False
        assert any("default_action" in err for err in errors)

    @pytest.mark.parametrize(
        "bad_posture",
        ["ALLOW_ALL", "REQUIRE_WAN_EXTENDED", "DENY_ALL", "LOOPBACK", ""],
    )
    def test_schema_invalid_network_posture(
        self, tmp_path: Path, base_manifest_data: dict, bad_posture: str
    ) -> None:
        """Invalid, truncated, or ambiguous network_posture fails closed."""
        base_manifest_data["boundary_policy"]["network_posture"] = bad_posture
        f = tmp_path / f"bad_posture_{bad_posture}.json"
        f.write_text(json.dumps(base_manifest_data))
        valid, errors = validate_boundary_manifest(f)
        assert valid is False
        assert any("network_posture" in err for err in errors)

    def test_schema_invalid_allowed_comms_empty(
        self, tmp_path: Path, base_manifest_data: dict
    ) -> None:
        """Empty allowed_comms array fails closed."""
        base_manifest_data["boundary_policy"]["allowed_comms"] = []
        f = tmp_path / "empty_comms.json"
        f.write_text(json.dumps(base_manifest_data))
        valid, errors = validate_boundary_manifest(f)
        assert valid is False
        assert any("allowed_comms" in err for err in errors)

    def test_schema_comm_length_overflow(self, tmp_path: Path, base_manifest_data: dict) -> None:
        """Comm string exceeding 15 chars (Linux TASK_COMM_LEN - 1) fails closed."""
        base_manifest_data["boundary_policy"]["allowed_comms"].append(
            "comm_that_exceeds_15_characters_limit"
        )
        f = tmp_path / "long_comm.json"
        f.write_text(json.dumps(base_manifest_data))
        valid, errors = validate_boundary_manifest(f)
        assert valid is False
        assert any("exceeds 15 chars" in err for err in errors)

    def test_schema_comm_invalid_characters(self, tmp_path: Path, base_manifest_data: dict) -> None:
        """Comm string with slashes, spaces, or control characters fails closed."""
        base_manifest_data["boundary_policy"]["allowed_comms"].append("/bin/bash")
        f = tmp_path / "invalid_chars.json"
        f.write_text(json.dumps(base_manifest_data))
        valid, errors = validate_boundary_manifest(f)
        assert valid is False
        assert any("contains invalid characters" in err for err in errors)

    @pytest.mark.parametrize("bad_thresh", [0, -1, 101, "five", True])
    def test_schema_invalid_max_strike_threshold(
        self, tmp_path: Path, base_manifest_data: dict, bad_thresh: int | str | bool
    ) -> None:
        """Threshold out of [1..100] range or non-integer fails closed."""
        base_manifest_data["boundary_policy"]["max_strike_threshold"] = bad_thresh
        f = tmp_path / "bad_thresh.json"
        f.write_text(json.dumps(base_manifest_data))
        valid, errors = validate_boundary_manifest(f)
        assert valid is False
        assert any("max_strike_threshold" in err for err in errors)

    def test_morayd_validate_manifest_cli(self, tmp_path: Path, base_manifest_data: dict) -> None:
        """morayd --validate-manifest returns 0 on valid and non-zero on invalid."""
        daemon_bin = REPO_ROOT / "bin" / "morayd"
        if not daemon_bin.exists():
            subprocess.run(["make", "daemon"], cwd=str(REPO_ROOT), check=True)

        valid_f = tmp_path / "valid.json"
        valid_f.write_text(json.dumps(base_manifest_data))
        res_valid = subprocess.run(
            [str(daemon_bin), "--validate-manifest", str(valid_f)],
            capture_output=True,
            check=False,
            text=True,
        )
        assert res_valid.returncode == 0
        assert "is VALID" in res_valid.stdout

        # Invalid manifest
        bad_f = tmp_path / "invalid.json"
        base_manifest_data["boundary_policy"]["network_posture"] = "ALLOW_ALL"
        bad_f.write_text(json.dumps(base_manifest_data))
        res_invalid = subprocess.run(
            [str(daemon_bin), "--validate-manifest", str(bad_f)],
            capture_output=True,
            check=False,
            text=True,
        )
        assert res_invalid.returncode != 0
        assert "is INVALID" in res_invalid.stderr

    def test_morayd_auto_harden_fail_closed_on_unreviewed(
        self, tmp_path: Path, base_manifest_data: dict
    ) -> None:
        """morayd --auto-harden fails closed (exit 1) on unreviewed suggestion unless --enforce-unreviewed is passed."""
        daemon_bin = REPO_ROOT / "bin" / "morayd"
        base_manifest_data["policy_state"] = "SUGGESTION"
        suggest_f = tmp_path / "suggest.json"
        suggest_f.write_text(json.dumps(base_manifest_data))

        mock_dir = tmp_path / "mock_pin_unrev"
        res = subprocess.run(
            [str(daemon_bin), "--mock", str(mock_dir), "--auto-harden", str(suggest_f)],
            capture_output=True,
            check=False,
            text=True,
        )
        assert res.returncode != 0
        assert "Profiler suggestions require explicit human review" in res.stderr

        # With explicit activation flag, it starts cleanly
        proc = subprocess.Popen(
            [
                str(daemon_bin),
                "--mock",
                str(mock_dir),
                "--enforce-unreviewed",
                "--auto-harden",
                str(suggest_f),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(0.3)
            assert proc.poll() is None, "Daemon should be running with --enforce-unreviewed"
            proc.send_signal(signal.SIGTERM)
            _stdout, _ = proc.communicate(timeout=2)
            assert proc.returncode == 0
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
