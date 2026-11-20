#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
"""
Project Moray: Real Autonomous Python Agent Workload Fixture
Simulates authentic autonomous agent behaviors under kernel containment:
- Full Python 3 runtime initialization & dynamic imports
- Subprocess tool execution (allowed vs forbidden tools)
- Network socket operations (WAN, loopback, IPC, raw sockets)
- Cgroup assignment and introspection

Exit codes:
    0:  Success (operation allowed and completed cleanly)
    42: Success-Under-Containment (intercepted with -EPERM / PermissionError as expected)
    43: Network permitted past LSM (connect succeeded or failed with L3/L4 error rather than EPERM)
    1:  Unexpected failure / unhandled error
"""

from __future__ import annotations

import argparse
import errno
import os
import socket
import subprocess
import sys


def get_current_cgroup_id() -> int:
    """Read current cgroup v2 inode from /proc/self/cgroup."""
    try:
        with open("/proc/self/cgroup", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[1] == "":
                    cg_path = "/sys/fs/cgroup" + parts[2]
                    return os.stat(cg_path).st_ino
    except (FileNotFoundError, PermissionError, OSError):
        return 0
    return 0


def join_cgroup(cgroup_dir: str) -> None:
    """Move current process into specified cgroup directory."""
    procs_path = os.path.join(cgroup_dir, "cgroup.procs")
    pid = os.getpid()
    with open(procs_path, "w", encoding="utf-8") as f:
        f.write(f"{pid}\n")
    print(f"[AGENT] Moved PID {pid} into cgroup {cgroup_dir}")


def cmd_self_check() -> int:
    """Validate that Python runtime, standard library, and process state initialize cleanly."""
    cg_id = get_current_cgroup_id()
    print(f"[AGENT] Self-check OK: PID={os.getpid()}, TGID={os.getpid()}, Cgroup_ID={cg_id}")
    return 0


def cmd_spawn_subprocess(binary: str, args: list[str]) -> int:
    """Attempt to spawn a subprocess tool. Catch Ring 0 EPERM interception."""
    cmd = [binary] + args
    print(f"[AGENT] Spawning subprocess: {cmd}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        print(f"[AGENT] Subprocess completed with exit code: {proc.returncode}")
        if proc.returncode == 0:
            return 0
        # Shell / system convention: 126 or 127 often indicate permission denied on execve
        return proc.returncode
    except (PermissionError, OSError) as e:
        if getattr(e, "errno", None) in (errno.EPERM, errno.EACCES) or isinstance(
            e, PermissionError
        ):
            print(f"[AGENT] Subprocess execution BLOCKED by kernel with -EPERM: {e}")
            return 42
        print(f"[AGENT] Subprocess failed with unexpected error: {e}")
        return 1


def cmd_connect_wan(ip: str, port: int) -> int:
    """Attempt outbound WAN socket connect."""
    print(f"[AGENT] Attempting WAN connect to {ip}:{port}")
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((ip, port))
        print("[AGENT] WAN connect succeeded")
        return 43
    except PermissionError:
        print("[AGENT] WAN connect BLOCKED by kernel with PermissionError (-EPERM)")
        return 42
    except OSError as e:
        if e.errno in (errno.EPERM, errno.EACCES):
            print(f"[AGENT] WAN connect BLOCKED by kernel with errno={e.errno} (-EPERM)")
            return 42
        # Network unreachable, connection refused, or timeout means LSM didn't block it
        print(f"[AGENT] WAN connect failed with network-layer error (LSM permitted): {e}")
        return 43
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def cmd_connect_loopback(port: int) -> int:
    """Attempt loopback TCP connect."""
    print(f"[AGENT] Attempting loopback connect to 127.0.0.1:{port}")
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(("127.0.0.1", port))
        print("[AGENT] Loopback connect succeeded")
        return 0
    except (PermissionError, OSError) as e:
        if getattr(e, "errno", None) in (errno.EPERM, errno.EACCES) or isinstance(
            e, PermissionError
        ):
            print(f"[AGENT] Loopback connect BLOCKED by kernel with -EPERM: {e}")
            return 42
        # Connection refused means LSM permitted it to reach loopback stack
        if getattr(e, "errno", None) == errno.ECONNREFUSED:
            print("[AGENT] Loopback connect reached loopback stack (ECONNREFUSED, LSM permitted)")
            return 0
        print(f"[AGENT] Loopback connect error: {e}")
        return 1
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def cmd_create_socket(family_name: str, type_name: str) -> int:
    """Attempt socket allocation via socket(). Catch Ring 0 socket_create interception."""
    family = getattr(socket, family_name, socket.AF_INET)
    stype = getattr(socket, type_name, socket.SOCK_STREAM)
    print(f"[AGENT] Attempting socket allocation ({family_name}, {type_name})")
    s = None
    try:
        s = socket.socket(family, stype)
        print("[AGENT] Socket allocation succeeded")
        return 0
    except (PermissionError, OSError) as e:
        if getattr(e, "errno", None) in (errno.EPERM, errno.EACCES) or isinstance(
            e, PermissionError
        ):
            print(f"[AGENT] Socket allocation BLOCKED by kernel with -EPERM: {e}")
            return 42
        print(f"[AGENT] Socket allocation failed with unexpected error: {e}")
        return 1
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Project Moray: Autonomous Python Agent Fixture")
    parser.add_argument(
        "--cgroup", type=str, default="", help="Cgroup directory to join before executing"
    )
    parser.add_argument("--self-check", action="store_true", help="Perform runtime self-check")
    parser.add_argument(
        "--spawn-subprocess", type=str, default="", help="Binary to spawn as subprocess"
    )
    parser.add_argument("--args", nargs="*", default=[], help="Arguments for subprocess")
    parser.add_argument("--connect-wan", type=str, default="", help="IP to connect via WAN")
    parser.add_argument("--port", type=int, default=80, help="Port for network connects")
    parser.add_argument("--connect-loopback", action="store_true", help="Connect to 127.0.0.1:port")
    parser.add_argument("--create-socket", action="store_true", help="Attempt socket creation")
    parser.add_argument("--family", type=str, default="AF_INET", help="Socket family")
    parser.add_argument("--type", type=str, default="SOCK_STREAM", help="Socket type")

    args = parser.parse_args()

    if args.cgroup:
        join_cgroup(args.cgroup)

    if args.self_check:
        return cmd_self_check()
    if args.spawn_subprocess:
        return cmd_spawn_subprocess(args.spawn_subprocess, args.args)
    if args.connect_wan:
        return cmd_connect_wan(args.connect_wan, args.port)
    if args.connect_loopback:
        return cmd_connect_loopback(args.port)
    if args.create_socket:
        return cmd_create_socket(args.family, args.type)

    print("[-] No valid command action specified.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
