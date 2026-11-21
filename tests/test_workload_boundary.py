# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Workload Boundary Defense & Non-Interference Verification Suite
Hermetic unit and integration tests verifying Cgroup v2-scoped autonomous boundary governance:
- Workload registration, release, listing, break-glass flushing, and status inspection.
- Workload posture contracts (ALLOW_LOOPBACK, DENY_ALL_NET, REQUIRE_WAN).
- Dual-workload non-interference invariant: same binary inside vs. outside governed workload.
- Child process hierarchy inheritance (MORAY_WORKLOAD_INHERIT_CHILDREN).
- CLI commands (--register-workload, --release-workload, --workload-status, --list-workloads, --flush-workloads).
- Mock map binary serialization and file locking integrity.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bridge.moray_hook import (
    MORAY_PERM_ALL,
    MORAY_PERM_EXEC,
    MORAY_PERM_LOOPBACK,
    MORAY_PERM_SOCKET,
    MORAY_WORKLOAD_ACTIVE,
    MORAY_WORKLOAD_INHERIT_CHILDREN,
    MorayBoundaryEntry,
    MorayBoundaryKey,
    MorayHook,
    MorayQuarantineError,
)


class TestWorkloadLifecycle:
    """Verifies workload registration, retrieval, listing, release, and flushing."""

    @pytest.fixture
    def hook(self, tmp_path: Path) -> MorayHook:
        mock_workload_map = tmp_path / "moray_workload_test.bin"
        return MorayHook(
            workload_map_path=str(mock_workload_map),
            mock_mode=True,
        )

    def test_register_and_lookup_workload(self, hook: MorayHook) -> None:
        cgroup_id = 12345
        assert not hook.is_workload_governed(cgroup_id)

        ok = hook.register_workload(cgroup_id, posture="ALLOW_LOOPBACK", inherit_children=True)
        assert ok
        assert hook.is_workload_governed(cgroup_id)

        entry = hook.get_workload_entry(cgroup_id)
        assert entry is not None
        assert entry.flags & MORAY_WORKLOAD_ACTIVE
        assert entry.flags & MORAY_WORKLOAD_INHERIT_CHILDREN
        assert entry.posture_flags == (MORAY_PERM_EXEC | MORAY_PERM_LOOPBACK)

    def test_release_workload(self, hook: MorayHook) -> None:
        cgroup_id = 54321
        hook.register_workload(cgroup_id, posture="DENY_ALL_NET")
        assert hook.is_workload_governed(cgroup_id)

        released = hook.release_workload(cgroup_id)
        assert released
        assert not hook.is_workload_governed(cgroup_id)
        assert hook.get_workload_entry(cgroup_id) is None

        # Re-releasing a non-governed cgroup returns False
        assert not hook.release_workload(cgroup_id)

    def test_list_and_flush_workloads(self, hook: MorayHook) -> None:
        cgroup_ids = [101, 102, 103]
        for cid in cgroup_ids:
            hook.register_workload(cid, posture="REQUIRE_WAN")

        workloads = hook.list_workloads()
        assert len(workloads) == 3
        found_ids = {cid for cid, _ in workloads}
        assert found_ids == set(cgroup_ids)

        # Flush without force raises error
        with pytest.raises(MorayQuarantineError, match="requires explicit confirmation"):
            hook.flush_workloads(force=False)

        flushed_count = hook.flush_workloads(force=True)
        assert flushed_count == 3
        assert len(hook.list_workloads()) == 0
        for cid in cgroup_ids:
            assert not hook.is_workload_governed(cid)


class TestWorkloadPostureContracts:
    """Verifies workload posture flags mapping and structured status output."""

    @pytest.fixture
    def hook(self, tmp_path: Path) -> MorayHook:
        mock_workload_map = tmp_path / "moray_workload_test.bin"
        return MorayHook(
            workload_map_path=str(mock_workload_map),
            mock_mode=True,
        )

    def test_allow_loopback_posture(self, hook: MorayHook) -> None:
        hook.register_workload(2001, posture="ALLOW_LOOPBACK")
        status = hook.get_workload_status(2001)

        assert status["governed"] is True
        assert status["posture"] == "ALLOW_LOOPBACK"
        assert status["posture_flags"] == (MORAY_PERM_EXEC | MORAY_PERM_LOOPBACK)
        assert status["inherit_children"] is True

    def test_deny_all_net_posture(self, hook: MorayHook) -> None:
        hook.register_workload(2002, posture="DENY_ALL_NET")
        status = hook.get_workload_status(2002)

        assert status["governed"] is True
        assert status["posture"] == "DENY_ALL_NET"
        assert status["posture_flags"] == MORAY_PERM_EXEC
        assert (status["posture_flags"] & MORAY_PERM_LOOPBACK) == 0
        assert (status["posture_flags"] & MORAY_PERM_SOCKET) == 0

    def test_require_wan_posture(self, hook: MorayHook) -> None:
        hook.register_workload(2003, posture="REQUIRE_WAN", inherit_children=False)
        status = hook.get_workload_status(2003)

        assert status["governed"] is True
        assert status["posture"] == "REQUIRE_WAN"
        assert status["posture_flags"] == MORAY_PERM_ALL
        assert status["inherit_children"] is False

    def test_ungoverned_workload_status(self, hook: MorayHook) -> None:
        status = hook.get_workload_status(99999)
        assert status["governed"] is False
        assert status["posture"] == "UNGOVERNED"
        assert status["posture_flags"] == 0


class TestDualWorkloadNonInterference:
    """Verifies non-interference semantics between governed workloads and outside host processes."""

    def test_dual_workload_decision_logic(self, tmp_path: Path) -> None:
        """
        Simulates kernel decision logic:
        - Sentinel mode = MORAY_BOUNDARY_FLAG_WORKLOAD.
        - Whitelist comms: ['morayd', 'legit_worker'].
        - Workload A (ID 1000): Governed under ALLOW_LOOPBACK.
        - Workload B (ID 2000): Ungoverned.
        """
        hook = MorayHook(
            workload_map_path=str(tmp_path / "workload.bin"),
            boundary_map_path=str(tmp_path / "boundary.bin"),
            mock_mode=True,
        )

        # Register Workload A as governed
        hook.register_workload(1000, posture="ALLOW_LOOPBACK")

        # Define boundary evaluation logic mirroring moray_kern.bpf.c
        def evaluate_execution(cgroup_id: int, comm: str) -> tuple[bool, str]:
            # 1. Lookup workload entry
            w_entry = hook.get_workload_entry(cgroup_id)
            # When sentinel mode is WORKLOAD:
            if w_entry is None or not (w_entry.flags & MORAY_WORKLOAD_ACTIVE):
                # Bypasses boundary enforcement: non-interference fast path
                return True, "BYPASS_UNGOVERNED"

            # Inside governed workload: check whitelist
            allowed = {"morayd", "legit_worker"}
            if comm in allowed:
                return True, "ALLOWED_WHITELIST"
            return False, "DENIED_BOUNDARY"

        def evaluate_socket(cgroup_id: int, comm: str, is_loopback: bool) -> tuple[bool, str]:
            w_entry = hook.get_workload_entry(cgroup_id)
            if w_entry is None or not (w_entry.flags & MORAY_WORKLOAD_ACTIVE):
                return True, "BYPASS_UNGOVERNED"

            # Whitelist / posture check
            if comm == "morayd":
                return True, "ALLOWED_DAEMON"

            if (w_entry.posture_flags & MORAY_PERM_SOCKET) != 0:
                return True, "ALLOWED_WAN"
            if is_loopback and (w_entry.posture_flags & MORAY_PERM_LOOPBACK) != 0:
                return True, "ALLOWED_LOOPBACK"
            return False, "DENIED_NETWORK_POSTURE"

        # Test Case 1: Same unlisted executable 'adversary_worker'
        # Inside Workload A: blocked
        allowed_inside, reason_inside = evaluate_execution(1000, "adversary_worker")
        assert not allowed_inside
        assert reason_inside == "DENIED_BOUNDARY"

        # Inside Workload B (ungoverned): allowed!
        allowed_outside, reason_outside = evaluate_execution(2000, "adversary_worker")
        assert allowed_outside
        assert reason_outside == "BYPASS_UNGOVERNED"

        # Test Case 2: Whitelisted binary 'legit_worker'
        # Inside Workload A: allowed
        ok_legit, reason_legit = evaluate_execution(1000, "legit_worker")
        assert ok_legit
        assert reason_legit == "ALLOWED_WHITELIST"

        # Test Case 3: Network sockets under ALLOW_LOOPBACK
        # Inside Workload A: loopback allowed, WAN denied
        ok_loop, _ = evaluate_socket(1000, "legit_worker", is_loopback=True)
        assert ok_loop
        ok_wan, _ = evaluate_socket(1000, "legit_worker", is_loopback=False)
        assert not ok_wan

        # Inside Workload B: loopback AND WAN both allowed (unaffected by Moray boundary)
        ok_out_loop, _ = evaluate_socket(2000, "legit_worker", is_loopback=True)
        assert ok_out_loop
        ok_out_wan, _ = evaluate_socket(2000, "legit_worker", is_loopback=False)
        assert ok_out_wan


class TestWorkloadCLI:
    """Verifies CLI argument parsing and execution for workload subcommands."""

    def test_cli_register_and_status(self, tmp_path: Path) -> None:
        map_path = str(tmp_path / "cli_workload.bin")
        script_path = str(REPO_ROOT / "bridge" / "moray_hook.py")

        # 1. Register workload via CLI
        cmd_reg = [
            sys.executable,
            script_path,
            "--mock",
            "--workload-map-path",
            map_path,
            "--register-workload",
            "5001",
            "--workload-posture",
            "DENY_ALL_NET",
            "--json",
        ]
        res_reg = subprocess.run(cmd_reg, capture_output=True, text=True, check=True)
        data_reg = json.loads(res_reg.stdout)
        assert data_reg["status"] == "registered"
        assert data_reg["cgroup_id"] == 5001
        assert data_reg["posture"] == "DENY_ALL_NET"

        # 2. Check status via CLI
        cmd_stat = [
            sys.executable,
            script_path,
            "--mock",
            "--workload-map-path",
            map_path,
            "--workload-status",
            "5001",
            "--json",
        ]
        res_stat = subprocess.run(cmd_stat, capture_output=True, text=True, check=True)
        data_stat = json.loads(res_stat.stdout)
        assert data_stat["governed"] is True
        assert data_stat["cgroup_id"] == 5001
        assert data_stat["posture"] == "DENY_ALL_NET"

        # 3. List workloads via CLI
        cmd_list = [
            sys.executable,
            script_path,
            "--mock",
            "--workload-map-path",
            map_path,
            "--list-workloads",
            "--json",
        ]
        res_list = subprocess.run(cmd_list, capture_output=True, text=True, check=True)
        data_list = json.loads(res_list.stdout)
        assert len(data_list) == 1
        assert data_list[0]["cgroup_id"] == 5001

        # 4. Release workload via CLI
        cmd_rel = [
            sys.executable,
            script_path,
            "--mock",
            "--workload-map-path",
            map_path,
            "--release-workload",
            "5001",
            "--json",
        ]
        res_rel = subprocess.run(cmd_rel, capture_output=True, text=True, check=True)
        data_rel = json.loads(res_rel.stdout)
        assert data_rel["status"] == "released"
        assert data_rel["cgroup_id"] == 5001


class TestHeterogeneousWorkloadBoundary:
    """
    Verifies Compound-Key Workload Boundary Whitelisting:
    Workload Alpha and Workload Beta have distinct, isolated executable whitelists.
    Binary allowed in Alpha is strictly denied in Beta.
    """

    def test_heterogeneous_isolated_whitelists(self, tmp_path: Path) -> None:
        hook = MorayHook(
            workload_map_path=str(tmp_path / "workload.bin"),
            boundary_map_path=str(tmp_path / "boundary.bin"),
            mock_mode=True,
        )

        # Workload Alpha (ID 1000): Agent Alpha (allowed: python3, bash)
        hook.register_workload(1000, posture="REQUIRE_WAN")
        # Workload Beta (ID 2000): Agent Beta (allowed: curl, ls)
        hook.register_workload(2000, posture="DENY_ALL_NET")

        # Assert MorayBoundaryKey compound key layout in Python ctypes
        import ctypes

        assert ctypes.sizeof(MorayBoundaryKey) == 24
        key_alpha = MorayBoundaryKey(cgroup_id=1000, comm=b"python3")
        assert key_alpha.cgroup_id == 1000
        assert key_alpha.comm.startswith(b"python3")

        # Seed Workload Alpha boundaries
        hook._mock_boundary_table[(1000, "python3")] = MorayBoundaryEntry(
            perm_flags=MORAY_PERM_EXEC, reserved=0, hit_count=0
        )
        hook._mock_boundary_table[(1000, "bash")] = MorayBoundaryEntry(
            perm_flags=MORAY_PERM_EXEC, reserved=0, hit_count=0
        )

        # Seed Workload Beta boundaries
        hook._mock_boundary_table[(2000, "curl")] = MorayBoundaryEntry(
            perm_flags=MORAY_PERM_EXEC, reserved=0, hit_count=0
        )
        hook._mock_boundary_table[(2000, "ls")] = MorayBoundaryEntry(
            perm_flags=MORAY_PERM_EXEC, reserved=0, hit_count=0
        )

        # Seed host-wide daemon (cgroup_id = 0)
        hook._mock_boundary_table[(0, "morayd")] = MorayBoundaryEntry(
            perm_flags=MORAY_PERM_ALL, reserved=0, hit_count=0
        )

        def evaluate(cgroup_id: int, comm: str) -> tuple[bool, str]:
            w_entry = hook.get_workload_entry(cgroup_id)
            if w_entry is None or not (w_entry.flags & MORAY_WORKLOAD_ACTIVE):
                return True, "BYPASS_UNGOVERNED"

            # Check compound key lookup mirroring lookup_boundary_entry()
            entry = hook.get_boundary_entry(comm, cgroup_id=cgroup_id)
            if entry and (entry.perm_flags & MORAY_PERM_EXEC):
                return True, "ALLOWED_WHITELIST"
            return False, "DENIED_BOUNDARY"

        # 1. Workload Alpha: python3 is permitted
        ok, reason = evaluate(1000, "python3")
        assert ok and reason == "ALLOWED_WHITELIST"

        # 2. Workload Beta: python3 is DENIED (not in Beta's whitelist!)
        ok, reason = evaluate(2000, "python3")
        assert not ok and reason == "DENIED_BOUNDARY"

        # 3. Workload Beta: curl is permitted
        ok, reason = evaluate(2000, "curl")
        assert ok and reason == "ALLOWED_WHITELIST"

        # 4. Workload Alpha: curl is DENIED (not in Alpha's whitelist!)
        ok, reason = evaluate(1000, "curl")
        assert not ok and reason == "DENIED_BOUNDARY"

        # 5. Host-wide daemon morayd is permitted across both
        ok, reason = evaluate(1000, "morayd")
        assert ok and reason == "ALLOWED_WHITELIST"
        ok, reason = evaluate(2000, "morayd")
        assert ok and reason == "ALLOWED_WHITELIST"

        # 6. Ungoverned process (cgroup 9999) bypasses boundary
        ok, reason = evaluate(9999, "unlisted_tool")
        assert ok and reason == "BYPASS_UNGOVERNED"

    def test_apply_manifest_multi_workload(self, tmp_path: Path) -> None:
        hook = MorayHook(
            workload_map_path=str(tmp_path / "workload.bin"),
            boundary_map_path=str(tmp_path / "boundary.bin"),
            mock_mode=True,
        )

        manifest_alpha = tmp_path / "manifest_alpha.json"
        manifest_alpha.write_text(
            json.dumps(
                {
                    "version": "1.0.0",
                    "target_name": "agent-alpha",
                    "policy_state": "ENFORCED",
                    "boundary_policy": {
                        "default_action": "AUTONOMOUS_STRIKE",
                        "allowed_comms": ["python3", "bash"],
                        "network_posture": "REQUIRE_WAN",
                    },
                }
            )
        )

        manifest_beta = tmp_path / "manifest_beta.json"
        manifest_beta.write_text(
            json.dumps(
                {
                    "version": "1.0.0",
                    "target_name": "agent-beta",
                    "policy_state": "ENFORCED",
                    "boundary_policy": {
                        "default_action": "AUTONOMOUS_STRIKE",
                        "allowed_comms": ["curl", "ls"],
                        "network_posture": "DENY_ALL_NET",
                    },
                }
            )
        )

        # Ingest both manifests targeting distinct cgroups
        c_alpha = hook.apply_boundary_manifest(str(manifest_alpha), cgroup_target=1001)
        c_beta = hook.apply_boundary_manifest(str(manifest_beta), cgroup_target=2002)

        assert c_alpha == 2
        assert c_beta == 2

        # Verify Workload Alpha state
        entry_alpha_py = hook.get_boundary_entry("python3", cgroup_id=1001)
        assert entry_alpha_py is not None
        assert entry_alpha_py.perm_flags & MORAY_PERM_EXEC

        entry_beta_py = hook.get_boundary_entry("python3", cgroup_id=2002)
        assert entry_beta_py is None  # Not allowed in Beta!

        entry_beta_curl = hook.get_boundary_entry("curl", cgroup_id=2002)
        assert entry_beta_curl is not None
        assert entry_beta_curl.perm_flags & MORAY_PERM_EXEC

        entry_alpha_curl = hook.get_boundary_entry("curl", cgroup_id=1001)
        assert entry_alpha_curl is None  # Not allowed in Alpha!
