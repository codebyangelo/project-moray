# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Phase 6.4 Wire-Level XDP Frame Dropping & Interface Attachment Unit Tests
Validates Invariant I_1 (Fail-Closed Quarantine at line rate), IPv4 address parsing,
XDP drop map lifecycle, mock backing boundaries, and CLI verbs.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from bridge.lobster_hook import (
    MAX_MAP_FILE_BYTES,
    MorayHook,
    MorayQuarantineError,
    ip_to_wire_bytes,
    validate_ipv4,
    wire_bytes_to_ip,
)


class TestIPv4ValidationAndWireEncoding:
    """Strict IPv4 validation and network wire order byte encoding."""

    @pytest.mark.parametrize(
        "valid_ip",
        [
            "1.1.1.1",
            "127.0.0.1",
            "192.168.1.100",
            "10.0.0.1",
            "198.51.100.42",
            "203.0.113.1",
            "0.0.0.0",
            "255.255.255.255",
        ],
    )
    def test_valid_ipv4_addresses(self, valid_ip: str) -> None:
        """Valid dotted IPv4 addresses parse cleanly and round-trip via wire bytes."""
        validate_ipv4(valid_ip)
        wire_bytes = ip_to_wire_bytes(valid_ip)
        assert len(wire_bytes) == 4
        assert wire_bytes_to_ip(wire_bytes) == valid_ip

    @pytest.mark.parametrize(
        "malformed_ip",
        [
            "",
            "1.2.3",  # 3 octets
            "1.2.3.4.5",  # 5 octets
            "256.1.1.1",  # Octet > 255
            "-1.1.1.1",  # Negative octet
            "1.1.1.abc",  # Alphabetic octet
            "localhost",  # Hostname
            "::1",  # IPv6 loopback
            "fe80::1",  # IPv6 link-local
            None,  # Null type
            12345,  # Integer type confusion
            True,  # Boolean type confusion
            False,  # Boolean type confusion
            ["1.1.1.1"],  # Array
            {"ip": "1.1.1.1"},  # Dict
        ],
    )
    def test_invalid_ipv4_rejection_fail_closed(self, malformed_ip: object) -> None:
        """Invalid inputs must be rejected fail-closed with MorayQuarantineError."""
        with pytest.raises(MorayQuarantineError):
            validate_ipv4(malformed_ip)

        if isinstance(malformed_ip, str):
            with pytest.raises(MorayQuarantineError):
                ip_to_wire_bytes(malformed_ip)


class TestXDPDropMapLifecycle:
    """Hermetic verification of XDP drop map add, lookup, remove, and flush operations."""

    def test_xdp_drop_and_lookup_single_ip(self, tmp_path: Path) -> None:
        xdp_file = str(tmp_path / "xdp_drop_map")
        hook = MorayHook(xdp_map_path=xdp_file, mock_mode=True)

        target_ip = "198.51.100.1"
        assert hook.xdp_is_dropped(target_ip) is False

        # Assert wire drop
        assert hook.xdp_drop_ip(target_ip) is True
        assert hook.xdp_is_dropped(target_ip) is True

        # Ensure adjacent IP is unflagged
        assert hook.xdp_is_dropped("198.51.100.2") is False

        # Remove wire drop
        assert hook.xdp_remove_ip(target_ip) is True
        assert hook.xdp_is_dropped(target_ip) is False

    def test_xdp_drop_multiple_ips_and_listing(self, tmp_path: Path) -> None:
        xdp_file = str(tmp_path / "xdp_multi_map")
        hook = MorayHook(xdp_map_path=xdp_file, mock_mode=True)

        targets = ["198.51.100.10", "198.51.100.20", "203.0.113.50"]
        for ip in targets:
            assert hook.xdp_drop_ip(ip) is True

        dropped_list = hook.xdp_list_dropped()
        assert len(dropped_list) == 3
        assert set(dropped_list) == set(targets)

        # Remove one IP
        assert hook.xdp_remove_ip("198.51.100.20") is True
        remaining = hook.xdp_list_dropped()
        assert len(remaining) == 2
        assert "198.51.100.20" not in remaining

    def test_xdp_emergency_flush(self, tmp_path: Path) -> None:
        xdp_file = str(tmp_path / "xdp_flush_map")
        hook = MorayHook(xdp_map_path=xdp_file, mock_mode=True)

        hook.xdp_drop_ip("10.10.10.1")
        hook.xdp_drop_ip("10.10.10.2")
        assert len(hook.xdp_list_dropped()) == 2

        # Flush without force must fail closed
        with pytest.raises(MorayQuarantineError, match="explicit confirmation"):
            hook.xdp_flush(force=False)

        # Flush with force
        count = hook.xdp_flush(force=True)
        assert count == 2
        assert len(hook.xdp_list_dropped()) == 0


class TestXDPFormatAndBoundaryHardening:
    """Adversarial boundary tests for XDP map file corruptions and symlinks."""

    def test_corrupted_entry_size_fail_closed(self, tmp_path: Path) -> None:
        """File whose size is not a multiple of 5 bytes (4 IP + 1 flag) must fail closed."""
        xdp_file = tmp_path / "corrupted_xdp.map"
        # 5 bytes is 1 valid entry. Write 7 bytes (corrupted)
        xdp_file.write_bytes(b"\x00" * 7)

        with pytest.raises(MorayQuarantineError, match="Corrupted XDP map"):
            MorayHook(xdp_map_path=str(xdp_file), mock_mode=True)

    def test_resource_exhaustion_ceiling_clamp(self, tmp_path: Path) -> None:
        """XDP map file exceeding 64KB ceiling must be rejected fail-closed."""
        xdp_file = tmp_path / "oversized_xdp.map"
        xdp_file.write_bytes(b"\x00" * (MAX_MAP_FILE_BYTES + 5))

        with pytest.raises(MorayQuarantineError, match="exceeds 65536 byte ceiling"):
            MorayHook(xdp_map_path=str(xdp_file), mock_mode=True)

    def test_symlink_rejection_fail_closed(self, tmp_path: Path) -> None:
        """Symlink XDP map path must be rejected under anti-traversal invariant."""
        sensitive_target = tmp_path / "sensitive_network.conf"
        sensitive_target.write_text("RESTRICTED_CONFIG")

        fake_symlink = tmp_path / "fake_xdp_symlink"
        fake_symlink.symlink_to(sensitive_target)

        with pytest.raises(MorayQuarantineError, match="Symlink xdp map path rejected"):
            MorayHook(xdp_map_path=str(fake_symlink), mock_mode=True)

        assert sensitive_target.read_text() == "RESTRICTED_CONFIG"


class TestXDPCLIInterface:
    """Verifies userspace CLI invocations for XDP commands."""

    def test_cli_xdp_drop_check_remove_cycle(self, tmp_path: Path) -> None:
        xdp_file = str(tmp_path / "cli_xdp.map")
        script = str(REPO_ROOT / "bridge" / "lobster_hook.py")
        target_ip = "198.51.100.99"

        # 1. Assert drop via CLI
        res_drop = subprocess.run(
            [
                sys.executable,
                script,
                "--xdp-drop-ip",
                target_ip,
                "--xdp-map-path",
                xdp_file,
                "--mock",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_drop.returncode == 0
        data_drop = json.loads(res_drop.stdout)
        assert data_drop["status"] == "xdp_dropped"
        assert data_drop["ip"] == target_ip

        # 2. Check dropped IP (exits 1 because dropped)
        res_check = subprocess.run(
            [
                sys.executable,
                script,
                "--xdp-check-ip",
                target_ip,
                "--xdp-map-path",
                xdp_file,
                "--mock",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_check.returncode == 1
        data_check = json.loads(res_check.stdout)
        assert data_check["xdp_dropped"] is True

        # 3. Check unflagged IP (exits 0 because benign)
        res_unflagged = subprocess.run(
            [
                sys.executable,
                script,
                "--xdp-check-ip",
                "198.51.100.100",
                "--xdp-map-path",
                xdp_file,
                "--mock",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_unflagged.returncode == 0
        data_unflagged = json.loads(res_unflagged.stdout)
        assert data_unflagged["xdp_dropped"] is False

        # 4. List dropped IPs
        res_list = subprocess.run(
            [
                sys.executable,
                script,
                "--xdp-list",
                "--xdp-map-path",
                xdp_file,
                "--mock",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_list.returncode == 0
        data_list = json.loads(res_list.stdout)
        assert target_ip in data_list["dropped_ips"]

        # 5. Remove dropped IP
        res_rm = subprocess.run(
            [
                sys.executable,
                script,
                "--xdp-remove-ip",
                target_ip,
                "--xdp-map-path",
                xdp_file,
                "--mock",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_rm.returncode == 0
        data_rm = json.loads(res_rm.stdout)
        assert data_rm["status"] == "removed"

        # 6. Verify unflagged after removal (exits 0)
        res_post_check = subprocess.run(
            [
                sys.executable,
                script,
                "--xdp-check-ip",
                target_ip,
                "--xdp-map-path",
                xdp_file,
                "--mock",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_post_check.returncode == 0


class TestKernelBPFXDPSymbols:
    """Verifies that compiled BPF object exports the required XDP section and symbols."""

    def test_xdp_section_and_symbol_present(self) -> None:
        bpf_obj = REPO_ROOT / "build" / "moray_kern.bpf.o"
        assert bpf_obj.exists(), f"BPF object not built: {bpf_obj}"

        res = subprocess.run(
            ["readelf", "-S", str(bpf_obj)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert "xdp" in res.stdout

        res_sym = subprocess.run(
            ["readelf", "-s", str(bpf_obj)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_sym.returncode == 0
        assert "moray_xdp_filter" in res_sym.stdout
        assert "moray_xdp_drop_map" in res_sym.stdout
