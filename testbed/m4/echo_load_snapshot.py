#!/usr/bin/env python3
"""Runs in one benchmark container and saves its process and network readbacks."""

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

CGROUP = Path("/sys/fs/cgroup")
SYSCOLS = ("net/ipv4/ip_local_port_range", "net/ipv4/ip_local_reserved_ports",
           "net/ipv4/tcp_max_syn_backlog", "net/core/somaxconn")


def read(path):
    return Path(path).read_text().strip()


def pairs(lines):
    return {key: int(value) for key, value in (line.split() for line in lines.splitlines())}


def tcp_rows(role, ip, port):
    """Count unique TCP_ESTABLISHED tuples and queue bytes from this netns."""
    sockets = set()
    tx_bytes = rx_bytes = 0
    address = f"{int.from_bytes(socket.inet_aton(ip), 'little'):08X}:{port:04X}"
    column = 1 if role == "server" else 2
    with open("/proc/net/tcp", encoding="ascii") as stream:
        next(stream)
        for line in stream:
            fields = line.split()
            if fields[column] != address or fields[3] != "01":
                continue
            endpoints = (fields[1], fields[2])
            sockets.add(endpoints if role == "client" else endpoints[::-1])
            tx, rx = (int(q, 16) for q in fields[4].split(":"))
            tx_bytes += tx
            rx_bytes += rx
    tuples = "\n".join(f"{local} {remote}" for local, remote in sorted(sockets))
    return {"established": len(sockets),
            "tuple_sha256": hashlib.sha256(tuples.encode("ascii")).hexdigest(),
            "tx_queue_payload_bytes": tx_bytes, "rx_queue_payload_bytes": rx_bytes}


def snapshot(directory, phase, role, ip, port, check_sockets):
    started_ns = time.monotonic_ns()
    pid = int(read(directory / "pid"))
    proc = Path(f"/proc/{pid}")
    smaps = read(proc / "smaps_rollup")
    status = read(proc / "status")
    memory_stat = read(CGROUP / "memory.stat")
    info = {"started_ns": started_ns, "pid": pid, "phase": phase, "role": role,
            "smaps_rollup": smaps,
            "rss_bytes": int(re.search(r"^Rss:\s+(\d+) kB", smaps, re.M)[1]) * 1024,
            "rss_hwm_bytes": int(re.search(r"^VmHWM:\s+(\d+) kB", status, re.M)[1]) * 1024,
            "pss_bytes": int(re.search(r"^Pss:\s+(\d+) kB", smaps, re.M)[1]) * 1024,
            "memory_stat": pairs(memory_stat),
            "memory_current_bytes": int(read(CGROUP / "memory.current")),
            "memory_max": read(CGROUP / "memory.max"),
            "sockstat": read("/proc/net/sockstat"),
            "sockstat6": read("/proc/net/sockstat6"),
            "page_bytes": os.sysconf("SC_PAGE_SIZE"),
            "netns": os.readlink(proc / "ns/net")}
    slab = Path("/proc/slabinfo")
    try:
        lines = slab.read_text().splitlines()
        info["host_slabinfo_tcp"] = [line for line in lines if line.startswith("#") or
                                    line.split()[0] in ("TCP", "TCPv6", "tw_sock_TCP",
                                                        "tw_sock_TCPv6", "request_sock_TCP",
                                                        "request_sock_TCPv6")]
    except OSError as error:
        info["host_slabinfo_error"] = str(error)
    if check_sockets:
        info["target_tcp"] = tcp_rows(role, ip, port)
        info["fd_count"] = len(list((proc / "fd").iterdir()))
    if phase == "baseline":
        info["limits"] = read(proc / "limits")
        info["cgroup"] = read(proc / "cgroup")
        info["affinity"] = sorted(os.sched_getaffinity(pid))
        info["nice"] = os.getpriority(os.PRIO_PROCESS, pid)
        info["sysctl"] = {key: read(f"/proc/sys/{key}") for key in SYSCOLS}
        info["tcp_listeners"] = subprocess.check_output(
            ["ss", "-H", "-4", "-ltn", f"sport = :{port}"], text=True).splitlines()
    info["ended_ns"] = time.monotonic_ns()
    (directory / f"{phase}.json").write_text(json.dumps(info, indent=2) + "\n")


if __name__ == "__main__":
    directory, phase, role, ip, port, check_sockets = sys.argv[1:]
    snapshot(Path(directory), phase, role, ip, int(port), check_sockets == "tcp")
