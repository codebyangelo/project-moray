# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Adversarial Test Suite ("adtest")
Hermetic verification of failure modes, boundary fuzzing, concurrency, and fail-closed contracts.
"""

from __future__ import annotations

import concurrent.futures
import subprocess
import sys
from pathlib import Path

import pytest

# Ensure bridge is on path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from bridge.lobster_hook import (
    MAX_MAP_FILE_BYTES,
    PID_MAX,
    MorayHook,
    MorayQuarantineError,
    validate_pid,
)


class TestAdversarialPIDFuzzing:
    """Adversarial type confusion and integer boundary attacks."""

    @pytest.mark.parametrize(
        "malformed_pid",
        [
            True,  # Boolean subtype confusion (True == 1)
            False,  # Boolean subtype confusion (False == 0)
            "1234",  # String injection
            None,  # Null object
            3.14159,  # Float truncation attempt
            [],  # Array
            {},  # Dict
        ],
    )
    def test_type_confusion_rejection(self, malformed_pid: object) -> None:
        """Verify strict integer validation blocks type confusion."""
        with pytest.raises(MorayQuarantineError, match="PID must be an integer"):
            validate_pid(malformed_pid)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "out_of_bounds_pid",
        [
            0,
            1,  # PID 1 is kernel init/systemd (protected invariant)
            -1,
            -999999,
            PID_MAX + 1,
            PID_MAX + 1000000,
            2**32,
            2**64,
        ],
    )
    def test_pid_range_boundary_clamping(self, out_of_bounds_pid: int) -> None:
        """Verify PID values outside 2-4194304 are rejected fail-closed."""
        with pytest.raises(MorayQuarantineError, match="PID out of permissible range"):
            validate_pid(out_of_bounds_pid)


class TestCorruptedFormatAndResourceCeilings:
    """Adversarial filesystem inputs, corrupted entries, and resource exhaustion."""

    @pytest.fixture
    def test_dir(self, tmp_path: Path) -> Path:
        return tmp_path

    def test_truncated_entry_fail_closed(self, test_dir: Path) -> None:
        """Map file with truncated entry must fail closed upon initialization."""
        map_file = test_dir / "truncated.map"
        # 1 entry is 28 bytes. Write 17 bytes (corrupted/truncated)
        map_file.write_bytes(b"\x00" * 17)

        with pytest.raises(MorayQuarantineError, match="Corrupted quarantine map"):
            MorayHook(map_path=str(map_file), mock_mode=True)

    def test_trailing_garbage_fail_closed(self, test_dir: Path) -> None:
        """Map file with valid 28-byte entry plus 3 trailing garbage bytes must fail closed."""
        map_file = test_dir / "trailing.map"
        # 28 bytes valid + 3 bytes garbage = 31 bytes
        map_file.write_bytes(b"\x01" * 31)

        with pytest.raises(MorayQuarantineError, match="Corrupted quarantine map"):
            MorayHook(map_path=str(map_file), mock_mode=True)

    def test_resource_exhaustion_ceiling_clamp(self, test_dir: Path) -> None:
        """Map file exceeding 64KB safety ceiling must be rejected to prevent OOM attacks."""
        map_file = test_dir / "bomb.map"
        # Write 65,537 bytes (> 64KB)
        map_file.write_bytes(b"\x00" * (MAX_MAP_FILE_BYTES + 1))

        with pytest.raises(MorayQuarantineError, match="exceeds 65536 byte ceiling"):
            MorayHook(map_path=str(map_file), mock_mode=True)


class TestConcurrencyAndSMPThreadSafety:
    """Concurrent multi-agent strike/release under POSIX file locking."""

    def test_concurrent_agent_strikes(self, tmp_path: Path) -> None:
        """Verify 20 concurrent threads executing strikes produce zero race corruption."""
        map_path = str(tmp_path / "concurrent.map")
        pids = [1000 + i for i in range(20)]

        def worker_strike(target_pid: int) -> bool:
            hook = MorayHook(map_path=map_path, mock_mode=True)
            return hook.strike(target_pid)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(worker_strike, pids))

        assert all(results)

        # Verify all 20 PIDs were recorded without corrupted records
        final_hook = MorayHook(map_path=map_path, mock_mode=True)
        active_entries = final_hook.list_quarantined()
        assert len(active_entries) == 20
        active_pids = {p for p, _ in active_entries}
        assert active_pids == set(pids)

    def test_concurrent_interleaved_strike_and_release(self, tmp_path: Path) -> None:
        """Verify concurrent interleaved strikes and releases maintain integrity."""
        map_path = str(tmp_path / "interleaved.map")

        def worker_cycle(pid: int) -> None:
            hook = MorayHook(map_path=map_path, mock_mode=True)
            hook.strike(pid)
            assert hook.is_quarantined(pid) is True
            hook.release(pid)
            assert hook.is_quarantined(pid) is False

        pids = [3000 + i for i in range(15)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            list(executor.map(worker_cycle, pids))

        final_hook = MorayHook(map_path=map_path, mock_mode=True)
        assert len(final_hook.list_quarantined()) == 0


class TestDaemonPathBoundary:
    """User-space daemon boundary verification."""

    def test_daemon_path_overflow_rejection(self) -> None:
        """Daemon must reject pin directories exceeding path buffer boundaries without crash."""
        daemon_bin = REPO_ROOT / "bin" / "morayd"
        if not daemon_bin.exists():
            pytest.skip("morayd binary not yet built")

        oversized_dir = "/tmp/" + ("A" * 300)
        res = subprocess.run(
            [str(daemon_bin), "--mock", oversized_dir],
            capture_output=True,
            check=False,
            text=True,
        )
        assert res.returncode != 0
        assert (
            "exceeds buffer limit" in res.stderr
            or "File name too long" in res.stderr
            or "Cannot access" in res.stderr
        )


class TestSymlinkAndPathTraversalAttacks:
    """Adversarial symlink manipulation and path traversal defenses."""

    def test_symlink_map_path_rejected_on_init(self, tmp_path: Path) -> None:
        """Hook must reject symlinked map paths at initialization to prevent file tampering."""
        sensitive_target = tmp_path / "sensitive_file.txt"
        sensitive_target.write_text("CONFIDENTIAL_SYSTEM_DATA")

        malicious_symlink = tmp_path / "fake_map.symlink"
        malicious_symlink.symlink_to(sensitive_target)

        with pytest.raises(MorayQuarantineError, match="Symlink map path rejected"):
            MorayHook(map_path=str(malicious_symlink), mock_mode=True)

        # Confirm sensitive target was never overwritten
        assert sensitive_target.read_text() == "CONFIDENTIAL_SYSTEM_DATA"

    def test_symlink_substitution_rejected_during_strike(self, tmp_path: Path) -> None:
        """Hook must reject symlink if substituted before strike."""
        map_path = tmp_path / "normal_map.map"
        hook = MorayHook(map_path=str(map_path), mock_mode=True)

        # Adversary removes map file and substitutes a symlink
        sensitive_target = tmp_path / "sensitive_target.txt"
        sensitive_target.write_text("ORIGINAL_DATA")

        if map_path.exists():
            map_path.unlink()
        map_path.symlink_to(sensitive_target)

        with pytest.raises(MorayQuarantineError, match="Symlink map path rejected"):
            hook.strike(4444)

        assert sensitive_target.read_text() == "ORIGINAL_DATA"
