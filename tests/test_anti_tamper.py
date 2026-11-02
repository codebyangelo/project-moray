# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Phase 6.1 Anti-Tamper & Self-Defense Unit Tests
Validates Invariant I_7 (Containment Self-Defense), Ring 0 LSM(bpf) hook symbols,
tamper quarantine assertions, and dynamic strike escalation.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from bridge.lobster_hook import (
    MORAY_ACT_BLOCK_EXEC,
    MORAY_ACT_BLOCK_SOCKET,
    MORAY_ACT_DROP_NET,
    MORAY_ACT_FULL_STRIKE,
    MORAY_ACT_KILL,
    MORAY_HOOK_BPF_TAMPER,
    MORAY_REASON_TAMPER_ATTEMPT,
    MorayHook,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestAntiTamperConstants:
    """Verifies Phase 6.1 anti-tamper identifiers and semantic mapping."""

    def test_hook_and_reason_constants(self) -> None:
        assert MORAY_HOOK_BPF_TAMPER == 3
        assert MORAY_REASON_TAMPER_ATTEMPT == 4


class TestKernelBPFBytecodeSymbols:
    """Inspects compiled BPF ELF bytecode to verify Ring 0 LSM(bpf) hook presence."""

    def test_lsm_bpf_section_present(self) -> None:
        bpf_obj = REPO_ROOT / "build" / "moray_kern.bpf.o"
        assert bpf_obj.exists(), f"BPF object not built: {bpf_obj}"

        # Inspect ELF sections using readelf
        res = subprocess.run(
            ["readelf", "-S", str(bpf_obj)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert "lsm/bpf" in res.stdout

    def test_moray_bpf_strike_symbol_present(self) -> None:
        bpf_obj = REPO_ROOT / "build" / "moray_kern.bpf.o"
        assert bpf_obj.exists(), f"BPF object not built: {bpf_obj}"

        res = subprocess.run(
            ["readelf", "-s", str(bpf_obj)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        assert "moray_bpf_strike" in res.stdout


class TestAntiTamperHookLifecycle:
    """Verifies userspace anti-tamper reporting and policy assertions."""

    def test_report_tamper_default_escalation(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "tamper_quarantine.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)

        target_pid = 7777
        assert hook.is_quarantined(target_pid) is False

        # Assert tamper attempt
        assert hook.report_tamper(target_pid) is True
        assert hook.is_quarantined(target_pid) is True

        entry = hook.get_entry(target_pid)
        assert entry is not None
        assert entry.reason == MORAY_REASON_TAMPER_ATTEMPT
        # Auto-escalation asserts FULL_STRIKE which includes KILL flag
        assert entry.action_flags == MORAY_ACT_FULL_STRIKE
        assert (entry.action_flags & MORAY_ACT_KILL) != 0

        status = hook.get_status(target_pid)
        assert status["state"] == "ACTIVE"
        assert status["reason"] == MORAY_REASON_TAMPER_ATTEMPT

    def test_report_tamper_without_auto_escalate(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "tamper_no_kill.bin")
        hook = MorayHook(map_path=mock_file, mock_mode=True)

        target_pid = 8888
        assert hook.report_tamper(target_pid, auto_escalate=False) is True

        entry = hook.get_entry(target_pid)
        assert entry is not None
        assert entry.reason == MORAY_REASON_TAMPER_ATTEMPT
        assert entry.action_flags == (
            MORAY_ACT_BLOCK_EXEC | MORAY_ACT_BLOCK_SOCKET | MORAY_ACT_DROP_NET
        )
        assert (entry.action_flags & MORAY_ACT_KILL) == 0


class TestAntiTamperCLI:
    """Verifies CLI execution for --report-tamper verb."""

    def test_cli_report_tamper_and_status(self, tmp_path: Path) -> None:
        mock_file = str(tmp_path / "tamper_cli.bin")
        script = str(REPO_ROOT / "bridge" / "lobster_hook.py")

        # 1. Trigger anti-tamper assertion via CLI
        res = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                "6666",
                "--report-tamper",
                "--mock",
                "--map-path",
                mock_file,
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0
        data = json.loads(res.stdout)
        assert data["status"] == "asserted_tamper"
        assert data["pid"] == 6666
        assert data["reason"] == MORAY_REASON_TAMPER_ATTEMPT

        # 2. Query status as JSON
        res_status = subprocess.run(
            [
                sys.executable,
                script,
                "--pid",
                "6666",
                "--status",
                "--mock",
                "--map-path",
                mock_file,
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res_status.returncode == 0
        status_data = json.loads(res_status.stdout)
        assert status_data["pid"] == 6666
        assert status_data["state"] == "ACTIVE"
        assert status_data["reason"] == MORAY_REASON_TAMPER_ATTEMPT
        assert (status_data["action_flags"] & MORAY_ACT_KILL) != 0
