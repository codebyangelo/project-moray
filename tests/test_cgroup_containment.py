# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Phase 6.5 Cgroup v2 Containment Scoping Tests
Hermetic unit and integration tests verifying cgroup v2 resolution, quarantine lifecycle,
mock map serialization, 64KB heap ceiling clamping, symlink attack defenses, and ELF section layouts.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from bridge.lobster_hook import (
    FAIL_CLOSED_EXIT_CODE,
    MAX_MAP_FILE_BYTES,
    MORAY_ACT_BLOCK_EXEC,
    MORAY_ACT_BLOCK_SOCKET,
    MORAY_REASON_LOBSTER_L7,
    MORAY_STATE_ACTIVE,
    MORAY_STATE_EXPIRED,
    MORAY_STATE_RELEASED,
    MorayHook,
    MorayQuarantineError,
    resolve_cgroup_id,
)


class TestCgroupIdResolution:
    """Verifies resolve_cgroup_id input parsing and security bounds."""

    def test_valid_integer_ids(self) -> None:
        assert resolve_cgroup_id(1) == 1
        assert resolve_cgroup_id(1000) == 1000
        assert resolve_cgroup_id(0xFFFFFFFFFFFFFFFF) == 0xFFFFFFFFFFFFFFFF

    def test_valid_numeric_strings(self) -> None:
        assert resolve_cgroup_id("42") == 42
        assert resolve_cgroup_id("0x2a") == 42
        assert resolve_cgroup_id("0xdeadbeef") == 0xDEADBEEF

    def test_invalid_types(self) -> None:
        with pytest.raises(MorayQuarantineError, match="integer or path string"):
            resolve_cgroup_id(True)
        with pytest.raises(MorayQuarantineError, match="integer or path string"):
            resolve_cgroup_id(False)
        with pytest.raises(MorayQuarantineError, match="integer or path string"):
            resolve_cgroup_id(None)
        with pytest.raises(MorayQuarantineError, match="integer or path string"):
            resolve_cgroup_id([1234])

    def test_out_of_range_integers(self) -> None:
        with pytest.raises(MorayQuarantineError, match="out of 64-bit unsigned range"):
            resolve_cgroup_id(0)
        with pytest.raises(MorayQuarantineError, match="out of 64-bit unsigned range"):
            resolve_cgroup_id(-1)
        with pytest.raises(MorayQuarantineError, match="out of 64-bit unsigned range"):
            resolve_cgroup_id(0xFFFFFFFFFFFFFFFF + 1)

    def test_valid_directory_resolution(self, tmp_path: Path) -> None:
        cgroup_dir = tmp_path / "mock_cgroup_slice"
        cgroup_dir.mkdir()
        cgroup_id = resolve_cgroup_id(str(cgroup_dir))
        assert cgroup_id == cgroup_dir.stat().st_ino

    def test_nonexistent_directory(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "does_not_exist"
        with pytest.raises(MorayQuarantineError, match="does not exist"):
            resolve_cgroup_id(str(nonexistent))

    def test_file_instead_of_directory(self, tmp_path: Path) -> None:
        reg_file = tmp_path / "regular_file.txt"
        reg_file.write_text("hello")
        with pytest.raises(MorayQuarantineError, match="must be a directory"):
            resolve_cgroup_id(str(reg_file))

    def test_symlink_rejection_anti_traversal(self, tmp_path: Path) -> None:
        real_dir = tmp_path / "real_cgroup"
        real_dir.mkdir()
        symlink_dir = tmp_path / "symlink_cgroup"
        os.symlink(real_dir, symlink_dir)

        with pytest.raises(MorayQuarantineError, match="Symlink cgroup path rejected"):
            resolve_cgroup_id(str(symlink_dir))


class TestCgroupQuarantineLifecycle:
    """Verifies cgroup quarantine asserting, lookup, release, and status."""

    @pytest.fixture
    def hook(self, tmp_path: Path) -> MorayHook:
        mock_cgroup_map = tmp_path / "moray_cgroup_test.bin"
        return MorayHook(
            cgroup_map_path=str(mock_cgroup_map),
            mock_mode=True,
        )

    def test_quarantine_and_release(self, hook: MorayHook) -> None:
        cid = 10001
        assert not hook.is_cgroup_quarantined(cid)

        # Assert quarantine
        ok = hook.quarantine_cgroup(
            cid,
            action_flags=MORAY_ACT_BLOCK_EXEC,
            reason=MORAY_REASON_LOBSTER_L7,
            ttl_seconds=0,
        )
        assert ok is True
        assert hook.is_cgroup_quarantined(cid)

        entry = hook.get_cgroup_entry(cid)
        assert entry is not None
        assert entry.action_flags == MORAY_ACT_BLOCK_EXEC
        assert entry.strike_count == 1
        assert entry.ttl_seconds == 0

        # Release
        rel = hook.release_cgroup(cid)
        assert rel is True
        assert not hook.is_cgroup_quarantined(cid)
        assert hook.get_cgroup_entry(cid) is None

    def test_quarantine_by_directory_path(self, hook: MorayHook, tmp_path: Path) -> None:
        cgroup_dir = tmp_path / "agent_subgroup"
        cgroup_dir.mkdir()
        cid = cgroup_dir.stat().st_ino

        ok = hook.quarantine_cgroup(str(cgroup_dir), action_flags=MORAY_ACT_BLOCK_SOCKET)
        assert ok is True
        assert hook.is_cgroup_quarantined(str(cgroup_dir))
        assert hook.is_cgroup_quarantined(cid)

        stat_res = hook.get_cgroup_status(str(cgroup_dir))
        assert stat_res["cgroup_id"] == cid
        assert stat_res["state"] == "ACTIVE"
        assert stat_res["state_code"] == MORAY_STATE_ACTIVE
        assert stat_res["action_flags"] == MORAY_ACT_BLOCK_SOCKET

        hook.release_cgroup(str(cgroup_dir))
        assert not hook.is_cgroup_quarantined(cid)

    def test_status_released(self, hook: MorayHook) -> None:
        stat_res = hook.get_cgroup_status(99999)
        assert stat_res["cgroup_id"] == 99999
        assert stat_res["state"] == "RELEASED"
        assert stat_res["state_code"] == MORAY_STATE_RELEASED
        assert stat_res["quarantined"] is False

    def test_cgroup_ttl_expiration(self, hook: MorayHook) -> None:
        cid = 54321
        # Set 1 second TTL
        hook.quarantine_cgroup(cid, ttl_seconds=1)
        assert hook.is_cgroup_quarantined(cid)

        entry = hook.get_cgroup_entry(cid)
        assert entry is not None
        # Back-date timestamp by 5 seconds
        entry.timestamp_ns -= 5 * 1_000_000_000
        hook._mock_cgroup_table[cid] = entry
        hook._sync_mock_cgroup_file()

        assert not hook.is_cgroup_quarantined(cid)
        stat_res = hook.get_cgroup_status(cid)
        assert stat_res["state"] == "EXPIRED"
        assert stat_res["state_code"] == MORAY_STATE_EXPIRED

    def test_list_and_flush_cgroups(self, hook: MorayHook) -> None:
        hook.quarantine_cgroup(101)
        hook.quarantine_cgroup(102)
        hook.quarantine_cgroup(103)

        cgroups = hook.list_quarantined_cgroups()
        assert len(cgroups) == 3
        ids = {cid for cid, _ in cgroups}
        assert ids == {101, 102, 103}

        # Flush without force must fail
        with pytest.raises(MorayQuarantineError, match="requires explicit confirmation"):
            hook.flush_cgroups(force=False)

        # Flush with force
        count = hook.flush_cgroups(force=True)
        assert count == 3
        assert len(hook.list_quarantined_cgroups()) == 0


class TestCgroupAdversarialAndBoundaries:
    """Verifies defenses against corrupt states, heap overflow clamps, and symlink attacks."""

    def test_corrupt_mock_file_length_rejected(self, tmp_path: Path) -> None:
        mock_file = tmp_path / "corrupt_cgroup.bin"
        # Write 25 bytes (not a multiple of 32 bytes)
        mock_file.write_bytes(b"\x00" * 25)

        with pytest.raises(MorayQuarantineError, match="not a multiple of 32"):
            MorayHook(cgroup_map_path=str(mock_file), mock_mode=True)

    def test_heap_ceiling_clamp(self, tmp_path: Path) -> None:
        mock_file = tmp_path / "oversized_cgroup.bin"
        # Write 65 KB (exceeding MAX_MAP_FILE_BYTES 64 KB ceiling)
        mock_file.write_bytes(b"\x00" * (MAX_MAP_FILE_BYTES + 32))

        with pytest.raises(MorayQuarantineError, match="exceeds 65536 byte ceiling"):
            MorayHook(cgroup_map_path=str(mock_file), mock_mode=True)

    def test_symlink_cgroup_map_path_rejected(self, tmp_path: Path) -> None:
        real_file = tmp_path / "real_cgroup.bin"
        real_file.write_bytes(b"")
        symlink_map = tmp_path / "symlink_cgroup.bin"
        os.symlink(real_file, symlink_map)

        with pytest.raises(MorayQuarantineError, match="Symlink cgroup map path rejected"):
            MorayHook(cgroup_map_path=str(symlink_map), mock_mode=True)

    def test_healthcheck_includes_cgroup_info(self, tmp_path: Path) -> None:
        mock_cgroup = tmp_path / "health_cgroup.bin"
        hook = MorayHook(cgroup_map_path=str(mock_cgroup), mock_mode=True)
        hook.quarantine_cgroup(777)

        health = hook.healthcheck()
        assert health["cgroup_accessible"] is True
        assert health["cgroup_map_path"] == str(mock_cgroup)
        assert health["cgroup_quarantined_count"] == 1

    def test_cgroup_lock_skipped_on_bpffs_path(self, tmp_path: Path) -> None:
        """Verify that _with_cgroup_lock skips file locking on bpffs or in live mode."""
        mock_cgroup = tmp_path / "test_cgroup.bin"
        hook = MorayHook(cgroup_map_path=str(mock_cgroup), mock_mode=True)
        hook._with_cgroup_lock(lambda: 1)
        assert os.path.exists(f"{mock_cgroup}.lock")

        # Set path to bpffs path; should bypass file lock without EPERM
        hook.cgroup_map_path = "/sys/fs/bpf/moray/cgroup_map"
        res = hook._with_cgroup_lock(lambda: 42)
        assert res == 42
        assert not os.path.exists("/sys/fs/bpf/moray/cgroup_map.lock")

        # Set mock_mode=False; should bypass file lock completely
        hook.cgroup_map_path = str(tmp_path / "never_locked.bin")
        hook.mock_mode = False
        res2 = hook._with_cgroup_lock(lambda: 99)
        assert res2 == 99
        assert not os.path.exists(f"{tmp_path}/never_locked.bin.lock")


class TestCgroupCliVerbs:
    """Verifies userspace bridge CLI commands for cgroup management."""

    def test_cli_quarantine_and_status_json(self, tmp_path: Path) -> None:
        mock_map = tmp_path / "cli_cgroup.bin"

        # Assert quarantine
        res_q = subprocess.run(
            [
                sys.executable,
                "bridge/lobster_hook.py",
                "--quarantine-cgroup",
                "8888",
                "--cgroup-map-path",
                str(mock_map),
                "--block-wan",
                "--mock",
                "--json",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=True,
            text=True,
        )
        data_q = json.loads(res_q.stdout)
        assert data_q["status"] == "asserted"
        assert data_q["cgroup_id"] == 8888
        assert data_q["allow_loopback"] is True

        # Query status
        res_s = subprocess.run(
            [
                sys.executable,
                "bridge/lobster_hook.py",
                "--cgroup-status",
                "8888",
                "--cgroup-map-path",
                str(mock_map),
                "--mock",
                "--json",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=True,
            text=True,
        )
        data_s = json.loads(res_s.stdout)
        assert data_s["cgroup_id"] == 8888
        assert data_s["state"] == "ACTIVE"
        assert data_s["quarantined"] is True

        # Release cgroup
        res_r = subprocess.run(
            [
                sys.executable,
                "bridge/lobster_hook.py",
                "--release-cgroup",
                "8888",
                "--cgroup-map-path",
                str(mock_map),
                "--mock",
                "--json",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=True,
            text=True,
        )
        data_r = json.loads(res_r.stdout)
        assert data_r["status"] == "released"

    def test_cli_quarantine_block_exec(self, tmp_path: Path) -> None:
        mock_map = tmp_path / "cli_block_exec_cgroup.bin"

        res = subprocess.run(
            [
                sys.executable,
                "bridge/lobster_hook.py",
                "--quarantine-cgroup",
                "7777",
                "--cgroup-map-path",
                str(mock_map),
                "--block-exec",
                "--mock",
                "--json",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=True,
            text=True,
        )
        data = json.loads(res.stdout)
        assert data["status"] == "asserted"
        assert data["cgroup_id"] == 7777
        assert data["action_flags"] == MORAY_ACT_BLOCK_EXEC

    def test_cli_flush_without_force_fails(self, tmp_path: Path) -> None:
        mock_map = tmp_path / "cli_flush.bin"

        res = subprocess.run(
            [
                sys.executable,
                "bridge/lobster_hook.py",
                "--flush-cgroups",
                "--cgroup-map-path",
                str(mock_map),
                "--mock",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=False,
            text=True,
        )
        assert res.returncode == FAIL_CLOSED_EXIT_CODE
        assert "requires explicit confirmation" in res.stderr


class TestBpfElfCgroupMapStructure:
    """Verifies the compiled BPF ELF object contains moray_cgroup_map with expected structure."""

    def test_bpf_elf_cgroup_map_symbol(self) -> None:
        bpf_obj = REPO_ROOT / "build" / "moray_kern.bpf.o"
        assert bpf_obj.exists(), "moray_kern.bpf.o must exist before running test"

        # Check symbol using llvm-objdump
        res = subprocess.run(
            ["llvm-objdump", "-t", str(bpf_obj)],
            capture_output=True,
            check=True,
            text=True,
        )
        assert "moray_cgroup_map" in res.stdout
        assert ".maps" in res.stdout
