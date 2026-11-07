# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Standalone Zero-Dependency Boundary Profiler
Inspects target workspaces to infer runtime executable boundaries and network postures,
emitting canonical moray_boundary.json manifests for autonomous Ring 0 kernel containment.
Functions 100% independently of external frameworks.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Standard foundational utilities permitted in containment domains
BASE_SYSTEM_COMMS: set[str] = {
    "bash",
    "sh",
    "python",
    "python3",
    "true",
    "cat",
    "ls",
    "rm",
    "mkdir",
    "victim_worker",
}


class MorayBoundaryProfiler:
    """
    Zero-dependency workspace inspector and boundary policy synthesizer for Project Moray.
    Inspects build files, binary trees, test suites, and source code to determine the
    minimal defensible execution boundary.
    """

    def __init__(self, workspace_path: str | Path) -> None:
        self.workspace_path: Path = Path(workspace_path).resolve()
        if not self.workspace_path.exists():
            raise FileNotFoundError(f"Target workspace does not exist: {self.workspace_path}")

    def profile_comms(self) -> set[str]:
        """Discover permitted executable command names (comm, max 15 chars)."""
        comms: set[str] = set(BASE_SYSTEM_COMMS)

        # 1. Inspect existing compiled binaries in bin/ and build/
        for sub in ("bin", "build"):
            sub_dir = self.workspace_path / sub
            if sub_dir.is_dir():
                for item in sub_dir.iterdir():
                    if item.is_file() and os.access(item, os.X_OK):
                        comms.add(item.name[:15])

        # 2. Inspect build systems for toolchains
        makefile = self.workspace_path / "Makefile"
        if makefile.exists():
            comms.update({"make", "gcc", "clang", "tcc", "as", "ld"})
            try:
                content = makefile.read_text(encoding="utf-8", errors="ignore")
                if "pytest" in content:
                    comms.add("pytest")
                if "ruff" in content:
                    comms.add("ruff")
            except OSError:
                pass

        cmakelists = self.workspace_path / "CMakeLists.txt"
        if cmakelists.exists():
            comms.update({"cmake", "ninja", "make", "gcc", "clang"})

        # 3. Inspect Python environment / test harness
        pyproject = self.workspace_path / "pyproject.toml"
        setup_py = self.workspace_path / "setup.py"
        tests_dir = self.workspace_path / "tests"
        if pyproject.exists() or setup_py.exists() or tests_dir.is_dir():
            comms.update({"python", "python3", "pytest"})

        return comms

    def profile_paths(self) -> list[str]:
        """Discover permitted binary absolute or workspace-relative paths."""
        paths: set[str] = set()

        for sub in ("bin", "build"):
            sub_dir = self.workspace_path / sub
            if sub_dir.is_dir():
                for item in sub_dir.iterdir():
                    if item.is_file() and os.access(item, os.X_OK):
                        paths.add(str(item.resolve()))

        # Standard canonical system entrypoints
        for candidate in ("/usr/bin/make", "/usr/bin/python3", "/bin/sh", "/bin/bash"):
            if os.path.exists(candidate):
                paths.add(candidate)

        return sorted(paths)

    def profile_network_posture(self) -> str:
        """
        Inspect source code to infer required network posture:
        - ALLOW_LOOPBACK: Workload only uses local IPC / loopback (default safe posture)
        - REQUIRE_WAN: Workload connects to remote WAN IP endpoints
        - DENY_ALL_NET: Workload has zero network operations
        """
        has_network = False
        has_wan = False

        wan_pattern = re.compile(
            r"""(?:https?://|connect\s*\([^)]*(?:AF_INET|AF_INET6)|\b[1-9]\d{0,2}\.[0-9]\d{0,2}\.[0-9]\d{0,2}\.[0-9]\d{0,2})"""
        )
        loopback_pattern = re.compile(r"""(?:127\.0\.0\.1|localhost|AF_UNIX|::1)""")

        for root, _, files in os.walk(self.workspace_path):
            for file in files:
                if file.endswith((".c", ".h", ".py", ".rs", ".go")):
                    p = Path(root) / file
                    try:
                        text = p.read_text(encoding="utf-8", errors="ignore")
                        if "socket" in text or "connect" in text or "http" in text:
                            has_network = True
                            # Check if non-loopback WAN pattern is present
                            matches = wan_pattern.findall(text)
                            for m in matches:
                                if not loopback_pattern.search(m) and "0.0.0.0" not in m:
                                    has_wan = True
                                    break
                    except OSError:
                        continue

        if not has_network:
            return "ALLOW_LOOPBACK"
        if has_wan:
            return "REQUIRE_WAN"
        return "ALLOW_LOOPBACK"

    def generate_manifest(self) -> dict[str, Any]:
        """Synthesize the complete canonical moray_boundary.json manifest."""
        allowed_comms = sorted(self.profile_comms())
        allowed_paths = self.profile_paths()
        network_posture = self.profile_network_posture()

        return {
            "version": "1.0.0",
            "target_name": self.workspace_path.name,
            "target_path": str(self.workspace_path),
            "generated_by": "Project Moray Native Profiler (moray_profiler.py)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "boundary_policy": {
                "default_action": "AUTONOMOUS_STRIKE",
                "allowed_comms": allowed_comms,
                "allowed_paths": allowed_paths,
                "network_posture": network_posture,
                "cgroup_slice": "agent.slice",
                "auto_quarantine_violations": True,
                "max_strike_threshold": 5,
            },
        }

    def write_manifest(self, output_path: str | Path) -> Path:
        """Write the generated manifest to a JSON file."""
        manifest = self.generate_manifest()
        out = Path(output_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        return out


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Project Moray: Standalone Zero-Dependency Boundary Profiler"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target workspace or directory to profile (default: current directory)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="moray_boundary.json",
        help="Output path for the boundary manifest (default: moray_boundary.json)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print manifest JSON to stdout",
    )
    args = parser.parse_args()

    profiler = MorayBoundaryProfiler(args.target)
    manifest = profiler.generate_manifest()

    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        out = profiler.write_manifest(args.output)
        policy = manifest["boundary_policy"]
        print(f"[+] Successfully generated Moray boundary manifest at: {out}")
        print(f"    - Target: {manifest['target_name']}")
        print(f"    - Permitted executables: {len(policy['allowed_comms'])} comms")
        print(f"    - Network Posture: {policy['network_posture']}")
        print(f"    - Default Action: {policy['default_action']}")


if __name__ == "__main__":
    main()
