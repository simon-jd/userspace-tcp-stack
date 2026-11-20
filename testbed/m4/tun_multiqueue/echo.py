#!/usr/bin/env python3
"""Compare TUN queue counts with simultaneous, byte-verified echo flows."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

BASELINE_SOURCE = "1427bbe64848c1c158488a2e8776aad2cb0f47c3"
FLOWS = 16
PACING = "--set=test_fixed_pacing_rate=1Gbit"


def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--baseline-runner", required=True, type=Path)
    parser.add_argument("--echo", required=True, type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--image", default="utcp-testbed:dev")
    parser.add_argument("--subnet", default=232, type=int)
    parser.add_argument("--repeats", default=5, type=int)
    parser.add_argument("--functional", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch("[a-z0-9][a-z0-9-]{0,34}", args.run_id):
        parser.error("invalid run identifier")
    if not re.fullmatch("[a-f0-9]{40}", args.source):
        parser.error("expected a full runtime source commit")
    if not 0 < args.repeats <= 10 or not 1 <= args.subnet <= 253:
        parser.error("invalid repetitions or subnet")
    if not os.access(args.echo, os.X_OK) or not args.echo.is_file():
        parser.error("expected a local echo executable")
    args.controller_cpus = sorted(os.sched_getaffinity(0))
    if not set(args.controller_cpus) <= {28, 29, 30, 31}:
        parser.error("pin the controller to CPUs 28–31, e.g. taskset -c 28-31 nice -n 10")
    args.functional_cpus = (28, 30)
    if args.functional and not set(args.functional_cpus) <= set(args.controller_cpus):
        parser.error("functional mode uses CPUs 28 and 30")
    args.size, args.count, args.rate = (32768, 24, 240) if args.functional else (65536, 512, 1000)
    args.bytes = FLOWS * args.size * args.count
    args.timeout = 45
    args.ethernet_aggregation = True
    return args


def main():
    args = parse()
    runner = args.baseline_runner.resolve()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(runner.parent))
    from run import Campaign, Mode, info, output, sha, STACK_IP, MTU, VOLUME

    if Path(sys.modules["run"].__file__) != runner:
        raise RuntimeError("did not import the supplied baseline runner")
    repo = runner.parents[3]
    if output("git", "-C", str(repo), "rev-parse", "HEAD") != BASELINE_SOURCE or output(
            "git", "-C", str(repo), "status", "--porcelain", "--", str(runner.parent)):
        raise RuntimeError("expected the clean reference runner at " + BASELINE_SOURCE)
    echo = str(args.echo.resolve())
    modes = tuple(Mode(f"mq{q}", echo, args.source, (f"--tun-queues={q}",), True, True)
                  for q in (1, 2))
    order = [(rep, q) for rep in range(1, args.repeats + 1)
             for q in ((1, 2) if rep % 2 else (2, 1))]

    with Campaign(args, *modes, None) as campaign:
        campaign.directory = f"/data/m4/performance/{args.run_id}"
        data = campaign.directory
        campaign.run_container(campaign.store, "--network", "none", "--cpuset-cpus",
                               ",".join(map(str, args.controller_cpus)),
                               "-v", f"{VOLUME}:/data", "-v", f"{echo}:/input-echo:ro")
        campaign.docker_exec("data", "mkdir", "-p", "/data/m4/performance")
        campaign.docker_exec("data", "mkdir", data)
        campaign.docker_exec("data", "mkdir", f"{data}/runner")
        campaign.docker_exec("data", "cp", "/input-echo", f"{data}/echo")
        digest = campaign.docker_exec("data", "sha256sum", f"{data}/echo").stdout.decode().split()[0]
        if digest != sha(echo):
            raise RuntimeError("echo binary changed while freezing")
        for name in ("run.py", "endpoint.py", "state.sh", "model.py"):
            campaign.put(f"runner/{name}", (runner.parent / name).read_bytes())
        campaign.put("runner/echo.py", Path(__file__).read_bytes())
        campaign.put_json("echo-plan.json", {
            "echo_source": args.source, "echo_sha256": digest, "runner_source": BASELINE_SOURCE,
            "image": campaign.image, "kernel": output("uname", "-a"), "argv": sys.argv,
            "flows": FLOWS, "size": args.size, "count": args.count, "offered_rps": args.rate,
            "echo_bytes": args.bytes, "pacing": PACING, "order": order, "offload": "tcpv4",
            "control_cpus": args.controller_cpus, "control_nice": os.nice(0),
            "endpoint_cpus": campaign.cpus, "host_before": info()})
        campaign.setup()
        rows = []
        for index, (rep, q) in enumerate(order, 1):
            arm = f"{index:02d}-r{rep}-mq{q}"
            port = str(21500 + index)
            campaign.docker_exec("data", "mkdir", f"{data}/{arm}")
            row = {"arm": arm, "repeat": rep, "queues": q, "valid": False}
            try:
                row["tun_flags"] = campaign.tun(modes[q - 1])
                campaign.state(arm, "before")
                row.update(transfer(campaign, arm, port, q, STACK_IP, MTU))
                row["valid"] = True
            except (ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired) as error:
                row["error"] = str(error)
            finally:
                campaign.state(arm, "after")
            rows.append(row)
            campaign.put_json(f"{arm}/result.json", row)
            print(row, flush=True)
        campaign.put_json("echo-results.json", rows)
        campaign.put_json("host-after.json", info())
        campaign.docker_exec("data", "bash", "-euo", "pipefail", "-c",
                             'cd "$1"; find . -type f ! -name SHA256SUMS -print0 | '
                             'sort -z | xargs -0 sha256sum > SHA256SUMS', "bash", data, timeout=60)
        print(campaign.docker_exec("data", "sha256sum", f"{data}/SHA256SUMS").stdout.decode().strip())
    return 0 if all(row["valid"] for row in rows) else 1


def transfer(campaign, arm, port, q, stack_ip, mtu):
    args = campaign.args
    data = campaign.directory
    path = f"{data}/{arm}"
    app = f"{data}/echo"
    wrap = ["python3", f"{data}/runner/endpoint.py", path]
    server_args = [*wrap, "recv", str(args.timeout), "utcp", port, app, "--backend", "utcp",
                   "--listen", f"{stack_ip}:{port}", "--addr", stack_ip, "--mtu", str(mtu),
                   "--seed", "1", "--cc", "cubic", "--tun-offload=tcpv4", f"--tun-queues={q}",
                   "--stats", f"{path}/server.stats", PACING]
    client_args = [*wrap, "send", str(args.timeout), app, "--backend", "kernel",
                   "--connect", f"{stack_ip}:{port}", "--cc", "cubic",
                   "--connections", str(FLOWS), "--concurrency", str(FLOWS),
                   "--size", str(args.size), "--count", str(args.count), "--rate", str(args.rate)]
    server_cmd = ["docker", "exec", campaign.containers["dut"], *server_args]
    client_cmd = ["docker", "exec", campaign.containers["peer"], *client_args]
    campaign.put_json(f"{arm}/commands.json", {"server": server_cmd, "client": client_cmd})
    status = {}
    server_pid = None
    with subprocess.Popen(server_cmd, stdin=subprocess.DEVNULL) as server:
        try:
            campaign.wait_listener(server, arm)
            server_pid = campaign.get(f"{arm}/listener.ready").decode().split()[0]
            campaign.record_active_tun(arm)
            fds = campaign.docker_exec("dut", "bash", "-c",
                                       'grep -H "^iff:" /proc/"$1"/fdinfo/*', "bash", server_pid).stdout
            campaign.put(f"{arm}/dut.tun-fds.txt", fds)
            if fds.count(b"iff:\tutcp0\n") != q:
                raise ValueError("active TUN descriptors did not match the requested count")
            with subprocess.Popen(client_cmd, stdin=subprocess.DEVNULL) as client:
                for _ in range(20):
                    overlap = campaign.docker_exec(
                        "peer", "ss", "-Htn", "state", "established", "dport", "=", f":{port}").stdout
                    if len(overlap.splitlines()) == FLOWS or client.poll() is not None:
                        break
                    time.sleep(.05)
                campaign.put(f"{arm}/peer.overlap.txt", overlap)
                status["client"] = client.wait(args.timeout + 2)
                if len(overlap.splitlines()) != FLOWS:
                    raise ValueError("did not observe every connection established simultaneously")
        finally:
            if server_pid is not None:
                campaign.docker_exec("dut", "kill", "-TERM", server_pid)
            status["server"] = server.wait(args.timeout + 2)
            campaign.put_json(f"{arm}/status.json", status)

    client, server, stats = (json.loads(campaign.get(f"{arm}/{name}")) for name in
                             ("send.stdout", "recv.stdout", "server.stats"))
    dut_usage = json.loads(campaign.get(f"{arm}/recv.usage.json"))
    peer_usage = json.loads(campaign.get(f"{arm}/send.usage.json"))
    if (status != {"server": 0, "client": 0} or not client["ok"] or
            client["requests_ok"] != FLOWS * args.count or client["mismatches"] or client["errors"] or
            client["connections_ok"] != FLOWS or server["accepted"] != FLOWS or server["errors"] or
            client["bytes"] != args.bytes or server["bytes"] != args.bytes or
            dut_usage["affinity"] != [campaign.cpus["dut"]] or
            peer_usage["affinity"] != [campaign.cpus["peer"]] or
            stats["dev_tun_offload"] != "tcpv4" or stats["dev_vnet_hdr_size"] != 10 or
            not stats["dev_tun_multi_queue"] or stats["dev_tun_queues"] != q or
            any(stats[key] for key in ("dev_device_failed", "dev_rx_errors", "dev_tx_errors",
                                       "dev_rx_vnet_drops", "TcpInCsumErrors"))):
        raise ValueError("process, byte integrity, or TUN validation failed")
    fd_traffic = {direction: [stats[f"dev_{direction}_queue_{i}_datagrams"] for i in range(q)]
                  for direction in ("rx", "tx")}
    if any(not all(traffic) or sum(traffic) != stats[f"dev_{direction}_datagrams"]
           for direction, traffic in fd_traffic.items()):
        raise ValueError(f"every configured queue must carry RX and TX traffic: {fd_traffic}")
    gb = args.bytes / 1e9
    seconds = client["duration_us"] / 1e6
    return {"established": FLOWS, "verified_echo_bytes": args.bytes,
            "client_seconds": seconds, "echo_gbps": 8 * gb / seconds,
            "dut_cpu_s_per_gb": (dut_usage["user_s"] + dut_usage["sys_s"]) / gb,
            "peer_cpu_s_per_gb": (peer_usage["user_s"] + peer_usage["sys_s"]) / gb,
            "dev_rx_read_calls": stats["dev_rx_read_calls"],
            "dev_tx_write_calls": stats["dev_tx_write_calls"], "fd_traffic": fd_traffic}


if __name__ == "__main__":
    sys.exit(main())
