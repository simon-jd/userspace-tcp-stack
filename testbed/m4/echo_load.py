#!/usr/bin/env python3
"""Run one gated single-queue echo arm on an isolated Linux Docker testbed."""

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
STACK_IP = "198.18.0.2"
PORT = 7000
MTU = 1500
NOFILE = 32768
ROLES = ("server", "client")


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=45, **kwargs).stdout.strip()


def readback(*args):
    try:
        return {"output": run(*args)}
    except subprocess.CalledProcessError as error:
        return {"status": error.returncode, "output": error.stdout}


def require(condition, why):
    if not condition:
        raise RuntimeError(why)


class Trial:
    def __init__(self, args, result_dir="m4-echo-load"):
        self.args = args
        self.binary_paths = {"server": (ROOT / args.binary).resolve(),
                             "client": (ROOT / (args.client_binary or args.binary)).resolve()}
        self.binaries = {role: "/utcp/" + path.relative_to(ROOT).as_posix()
                         for role, path in self.binary_paths.items()}
        self.allocation_counter = None
        self.allocation_counter_sha = None
        if args.allocation_counter:
            library = (ROOT / args.allocation_counter).resolve()
            if not library.is_file():
                raise ValueError(f"allocation counter library is missing: {library}")
            self.allocation_counter = "/utcp/" + library.relative_to(ROOT).as_posix()
            with library.open("rb") as stream:
                self.allocation_counter_sha = hashlib.file_digest(stream, "sha256").hexdigest()
        self.tag = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
        self.name = f"utcp-{result_dir.removesuffix('-load')}-{self.tag.lower()}"
        self.net = self.name + "-net"
        self.out = f"/data/{result_dir}/{self.tag}"
        addresses = ipaddress.ip_network(f"198.19.{args.net_base}.0/24")
        self.subnet = str(addresses)
        self.ips = {"server": str(addresses[2]), "client": str(addresses[3])}
        self.created = []
        self.net_created = False
        self.artifacts_created = False
        self.processes = {}
        self.affinity = dict(zip(("server", "client", "collector"), args.cpus, strict=True))
        self.nice = 10 if args.purpose == "functional" else 0

    def container(self, role):
        return self.name + "-" + role

    def docker(self, role, *args, **kwargs):
        return run("docker", "exec", self.container(role), *args, **kwargs)

    def capture_json(self, role, file, obj):
        self.docker(role, "sh", "-c", 'printf "%s\\n" "$2" > "$1"', "sh",
                    f"{self.out}/{file}", json.dumps(obj, indent=2))

    def save_manifest(self):
        a = self.args
        self.runner_source = run("git", "-C", str(ROOT), "rev-parse", "HEAD")
        self.source = a.binary_source or self.runner_source
        self.sources = {"server": self.source, "client": a.client_source or self.source}
        for source in set(self.sources.values()):
            observed = run("git", "-C", str(ROOT), "rev-parse", "--verify", f"{source}^{{commit}}")
            require(observed == source, f"binary source must name a full commit SHA: {source}")
        self.dirty = run("git", "-C", str(ROOT), "status", "--porcelain")
        require(a.purpose != "timing" or not self.dirty, "timing requires a clean source tree")
        self.binary_shas = {}
        for role, path in self.binary_paths.items():
            with path.open("rb") as binary:
                self.binary_shas[role] = hashlib.file_digest(binary, "sha256").hexdigest()
        self.image = run("docker", "image", "inspect", a.image, "--format", "{{.Id}}")
        run("docker", "volume", "inspect", "utcp-data", "--format", "{{.Name}}")
        self.manifest = {"run_id": self.tag, "source": self.source, "git_status": self.dirty,
                         "binary_sha256": self.binary_shas["server"], "arguments": vars(a),
                         "binary_sha256_by_role": self.binary_shas,
                         "binary_source_by_role": self.sources, "runner_source": self.runner_source,
                         "allocation_counter_sha256": self.allocation_counter_sha,
                         "docker_image_id": self.image, "net": self.subnet, "ips": self.ips,
                         "transport_address": STACK_IP, "port": PORT, "mtu": MTU,
                         "nofile_requested": NOFILE, "uname": run("uname", "-a"),
                         "cpu_thread_siblings": {
                             cpu: Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
                             .read_text().strip() for cpu in a.cpus},
                         "before_cpu": self.cpu_readback()}

    @staticmethod
    def cpu_readback():
        return {"utc": time.strftime("%FT%TZ", time.gmtime()), "uptime": run("uptime"),
                "process_placement": run("sh", "-c",
                    "ps -eo pid,psr,ni,pcpu,comm --sort=-pcpu | head -41"),
                "proc_stat": "\n".join(line for line in Path("/proc/stat").read_text().splitlines()
                                       if line.startswith("cpu"))}

    def setup(self):
        self.save_manifest()
        run("docker", "network", "create", "--internal", "--subnet", self.subnet, self.net)
        self.net_created = True
        for role in ROLES:
            tun = ["--device", "/dev/net/tun"] if role == "server" and self.args.backend == "utcp" else []
            forward = ["--sysctl", "net.ipv4.ip_forward=1"] if role == "server" else []
            run("docker", "create", "--name", self.container(role), "--network", self.net,
                "--ip", self.ips[role], "--cap-add", "NET_ADMIN",
                "--cpuset-cpus", ",".join(str(n) for n in self.args.cpus),
                "--ulimit", f"nofile={NOFILE}:{NOFILE}", "--sysctl", "net.ipv4.tcp_no_metrics_save=1",
                "--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
                "--sysctl", "net.ipv6.conf.default.disable_ipv6=1", *forward, *tun,
                "-v", f"{ROOT}:/utcp:ro", "-v", "utcp-data:/data", self.image, "sleep", "infinity")
            self.created.append(role)
            run("docker", "start", self.container(role))
            if role == "server":
                self.docker(role, "mkdir", "-p", str(Path(self.out).parent))
                self.docker(role, "mkdir", self.out)
                self.artifacts_created = True
                self.capture_json("server", "run.json", self.manifest)
            self.docker(role, "mkdir", f"{self.out}/{role}")
        self.docker("client", "mkdir", f"{self.out}/control")
        self.docker("client", "ip", "route", "add", "198.18.0.0/24", "via", self.ips["server"])
        # Match the peer-facing path and the destination address. On Linux
        # the destination is local; for utcp the DUT forwards through TUN.
        if self.args.backend == "utcp":
            vnet = ["vnet_hdr"] if self.args.offload != "legacy" else []
            self.docker("server", "ip", "tuntap", "add", "dev", "utcp0", "mode", "tun", *vnet)
            self.docker("server", "ip", "addr", "add", "198.18.0.1/24", "dev", "utcp0")
            self.docker("server", "ip", "link", "set", "dev", "utcp0",
                        "mtu", str(MTU), "txqueuelen", "10000", "up")
            self.docker("server", "tc", "qdisc", "replace", "dev", "utcp0",
                        "root", "pfifo", "limit", "10000")
        else:
            self.docker("server", "ip", "addr", "add", STACK_IP + "/32", "dev", "lo")
        self.docker("server", "ethtool", "-K", "eth0", "gro", "off")
        self.docker("client", "ethtool", "-K", "eth0", "tso", "off", "gso", "off", "gro", "off")

    def launch(self, role, *args):
        prefix = self.out + "/" + role
        cmd = (self.binaries[role], *args)
        self.capture_json(role, role + "/argv.json", cmd)
        pinned = ("taskset", "-c", str(self.affinity[role]), "nice", "-n", str(self.nice))
        if role == "server" and self.allocation_counter:
            pinned += ("env", f"LD_PRELOAD={self.allocation_counter}",
                       f"UTCP_NEW_COUNTER={prefix}/cpp-new-count")
        self.processes[role] = subprocess.Popen(
            ("docker", "exec", self.container(role), "sh", "-c",
             'p=$1; shift; printf "%s\\n" "$$" > "$p/pid"; exec "$@" >"$p/events.jsonl" 2>"$p/stderr"',
             "sh", prefix, *pinned, *cmd))

    def latest(self, role):
        try:
            raw = self.docker(role, "tail", "-1", f"{self.out}/{role}/events.jsonl")
            return json.loads(raw) if raw else {}
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return {}

    def wait(self, role, condition, description, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            event = self.latest(role)
            if event and condition(event):
                return event
            rc = self.processes[role].poll()
            if rc is not None:
                # The final line may have been flushed between tail and poll.
                event = self.latest(role)
                if rc == 0 and event and condition(event):
                    return event
                err = self.docker(role, "cat", f"{self.out}/{role}/stderr")
                raise RuntimeError(f"{role} exited {rc} waiting for {description}: {event}; {err}")
            if event.get("errors", 0):
                raise RuntimeError(f"{role} reported an error waiting for {description}: {event}")
            time.sleep(0.1)
        raise RuntimeError(f"timed out waiting for {role} {description}, last event: {self.latest(role)}")

    def gate(self, phase):
        self.docker("client", "touch", f"{self.out}/control/{phase}")

    def snapshot(self, phase, sockets=True):
        def one(role):
            # Each collector is pinned away from either measured application.
            path = f"{self.out}/{role}"
            self.docker(role, "taskset", "-c", str(self.affinity["collector"]),
                        "nice", "-n", str(self.nice), "python3",
                        "/utcp/testbed/m4/echo_load_snapshot.py", path, phase,
                        role, STACK_IP, str(PORT), "tcp" if sockets else "memory")
            return json.loads(self.docker(role, "cat", f"{path}/{phase}.json"))

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            return dict(zip(ROLES, workers.map(one, ROLES), strict=True))

    def network_readback(self):
        summary = {}
        for role in ROLES:
            raw = self.docker(role, "ip", "-j", "link")
            links = {d["ifname"]: d for d in json.loads(raw)}
            require(links["eth0"]["mtu"] == MTU, f"{role} eth0 MTU differs")
            summary[role] = {"links": links, "eth0_features": self.docker(role, "ethtool", "-k", "eth0"),
                             "route": self.docker(role, "ip", "route", "get",
                                 STACK_IP if role == "client" else self.ips["client"]),
                             "sysctl": self.docker(role, "sysctl", "net.ipv4.ip_forward",
                                                   "net.ipv4.tcp_no_metrics_save",
                                                   "net.ipv4.tcp_congestion_control")}
            observed_sha = self.docker(role, "sh", "-c", 'sha256sum "/proc/$(cat "$1")/exe"',
                                       "sh", f"{self.out}/{role}/pid").split()[0]
            require(observed_sha == self.binary_shas[role], f"{role} running binary hash differs")
            summary[role]["running_sha256"] = observed_sha
            if role == "server" and self.args.backend == "utcp":
                require(links["utcp0"]["mtu"] == MTU, "TUN MTU differs")
                queues = self.docker(role, "ls", "-1", "/sys/class/net/utcp0/queues").splitlines()
                require(queues == ["rx-0", "tx-0"], f"expected one TUN queue pair, observed {queues}")
                summary[role].update(
                    tun_queues=queues,
                    tun_features=self.docker(role, "ethtool", "-k", "utcp0"),
                    tun_flags=self.docker(role, "cat", "/sys/class/net/utcp0/tun_flags"),
                    tun_qdisc=self.docker(role, "tc", "qdisc", "show", "dev", "utcp0"))
        self.capture_json("server", "runtime.json", summary)
        return summary

    def check_limits(self, base):
        """Use the observed limits of the running processes and network namespaces."""
        a = self.args
        for role, snap in base.items():
            # Exclude only this run's already open fds and leave headroom for
            # the event loop, listener and incidental instrumentation.
            limit = re.search(r"^Max open files\s+(\d+)\s+(\d+)", snap["limits"], re.M)
            require(limit and int(limit[1]) >= snap["fd_count"] + a.connections + 32,
                    f"{role} nofile below requested concurrency plus headroom: {snap['limits']}")
            require(snap["nice"] == self.nice and snap["affinity"] == [self.affinity[role]],
                    f"{role} affinity or nice mismatch")
        client = base["client"]["sysctl"]
        low, high = map(int, client["net/ipv4/ip_local_port_range"].split())
        available = high - low + 1
        for reserved in filter(None, client["net/ipv4/ip_local_reserved_ports"].split(",")):
            start, _, end = reserved.partition("-")
            available -= max(0, min(high, int(end or start)) - max(low, int(start)) + 1)
        require(available >= a.connections + 32, f"only {available} available client ephemeral ports")
        if a.backend == "kernel":
            server = base["server"]
            require(len(server["tcp_listeners"]) == 1, f"expected exactly one target listener: {server}")
            accept_limit = int(server["tcp_listeners"][0].split()[2])  # ss LISTEN Send-Q
            syn_limit = int(server["sysctl"]["net/ipv4/tcp_max_syn_backlog"])
            require(min(accept_limit, syn_limit) >= a.open_batch,
                    f"Linux accept/SYN backlog below open batch: {accept_limit}/{syn_limit}")
        require(a.backlog >= a.open_batch, "requested backlog below open batch")

    def check_held(self, snaps, client, server, *, idle):
        n = self.args.connections
        require(client.get("open") == n and client.get("established") == n and
                client.get("errors") == 0, f"client did not hold {n} sockets: {client}")
        require(server.get("open") == n and server.get("accepted") == n and
                server.get("closed") == 0 and server.get("errors") == 0,
                f"server did not hold {n} sockets: {server}")
        client_kernel = snaps["client"]["target_tcp"]
        require(client_kernel["established"] == n,
                f"client kernel did not have {n} ESTABLISHED tuples: {client_kernel}")
        if self.args.backend == "kernel":
            kernel = snaps["server"]["target_tcp"]
            require(kernel["established"] == n and kernel["tuple_sha256"] == client_kernel["tuple_sha256"],
                    f"kernel server flavor did not have the same {n} ESTABLISHED tuples: {kernel}")
        else:
            require(server.get("tcp_slots") == n + 1 and server.get("time_wait_entries") == 0,
                    f"userspace server needed {n + 1} live slots and no TIME_WAIT: {server}")
        if idle:
            require(client["requests_started"] == 0 and client["bytes"] == 0 and server["bytes"] == 0,
                    f"workload reached the server before the active gate: {client}; {server}")

    def trial(self):
        a = self.args
        server_extra = []
        if a.backend == "utcp":
            help_text = self.docker("server", self.binaries["server"], "--help")
            server_extra = ["--tun", "utcp0", "--addr", STACK_IP, "--mtu", str(MTU),
                            "--profile", "linux", "--seed", "1",
                            "--stats", f"{self.out}/server/stack-stats.jsonl"]
            if "--tun-offload" in help_text:
                server_extra += ["--tun-offload", a.offload]
            else:
                require(a.offload == "legacy", "binary has no --tun-offload option")
        common = ["--load-report", "--cc", "cubic", "--nodelay"]
        self.launch("server", "--backend", a.backend, "--listen", f"{STACK_IP}:{PORT}",
                    "--backlog", str(a.backlog), *common, *server_extra)
        self.wait("server", lambda e: e.get("open") == 0, "listen")
        self.launch("client", "--backend", "kernel", "--connect", f"{STACK_IP}:{PORT}",
                    "--connections", str(a.connections), "--concurrency", str(a.connections),
                    "--count", str(a.count), "--size", str(a.size), "--rate", str(a.rate),
                    "--open-batch", str(a.open_batch), "--pattern-seed", "1",
                    "--load-control", self.out + "/control", *common)
        self.wait("client", lambda e: e.get("phase") == "baseline", "baseline gate")
        runtime = self.network_readback()
        base = self.snapshot("baseline")
        self.check_limits(base)
        require(all(s["target_tcp"]["established"] == 0 for s in base.values()),
                "baseline already has established target sockets")

        self.gate("open")
        self.wait("client", lambda e: e.get("phase") == "idle", "full client population")
        self.wait("server", lambda e: e.get("open") == a.connections, "full server population")
        first_idle = self.snapshot("idle-start")
        first_client, first_server = self.latest("client"), self.latest("server")
        self.check_held(first_idle, first_client, first_server, idle=True)
        time.sleep(a.hold_s)
        idle = self.snapshot("idle-end")
        idle_client, idle_server = self.latest("client"), self.latest("server")
        self.check_held(idle, idle_client, idle_server, idle=True)
        require(idle["client"]["target_tcp"]["tuple_sha256"] ==
                first_idle["client"]["target_tcp"]["tuple_sha256"], "tuples changed during idle hold")
        held_ns = min(s["started_ns"] for s in idle.values()) - max(
            s["ended_ns"] for s in first_idle.values())
        require(held_ns >= a.hold_s * 1e9, "snapshot timestamps do not span the required idle hold")

        self.gate("active")
        active = self.wait("client", lambda e: e.get("phase") == "active", "active workload")
        offered_seconds = a.connections * a.count / a.rate
        active_samples = []
        for number, fraction in enumerate((0.40, 0.55, 0.70), 1):
            sample_at = active["workload_start_ns"] + int(offered_seconds * fraction * 1e9)
            time.sleep(max(0, (sample_at - time.monotonic_ns()) / 1e9))
            sample = self.snapshot(f"active-{number}", sockets=False)
            client, server = self.latest("client"), self.latest("server")
            require(client.get("phase") == "active" and client.get("established") == a.connections and
                    server.get("open") == a.connections and not server["errors"] and
                    not client["errors"] and client["requests_ok"] > 0,
                    f"active snapshot sampled outside verified traffic: {client}; {server}")
            active_samples.append({"memory": sample, "client_app": client, "server_app": server})
        work_timeout = max(120, int(2 * offered_seconds + 30))
        drained_client = self.wait("client", lambda e: e.get("phase") == "drained",
                                   "all echo requests verified", timeout=work_timeout)
        want_requests = a.connections * a.count
        want_bytes = want_requests * a.size
        drained_server = self.wait("server", lambda e: e.get("bytes") == want_bytes,
                                   "server accounted for all echoed bytes")
        drained = self.snapshot("drained")
        self.check_held(drained, drained_client, drained_server, idle=False)
        require(drained["client"]["target_tcp"]["tuple_sha256"] ==
                idle["client"]["target_tcp"]["tuple_sha256"], "tuples changed during active workload")
        require(drained_client["requests_ok"] == want_requests and drained_client["bytes"] == want_bytes and
                drained_server["bytes"] == want_bytes, f"drained byte/request mismatch: {drained_client}; {drained_server}")
        self.gate("close")
        client = self.wait("client", lambda e: e.get("ev") == "summary", "client summary")
        require(self.processes["client"].wait(timeout=15) == 0, "client exit was nonzero")
        self.wait("server", lambda e: e.get("open") == 0, "all sockets released", timeout=45)
        self.docker("server", "sh", "-c", 'kill -TERM "$(cat "$1")"', "sh", f"{self.out}/server/pid")
        server = self.wait("server", lambda e: e.get("ev") == "summary", "server summary")
        require(self.processes["server"].wait(timeout=15) == 0, "server exit was nonzero")
        require(client["ok"] and client["requests_started"] == client["requests_ok"] ==
                client["latency_samples"] == want_requests and client["mismatches"] == 0 and
                client["connections_ok"] == a.connections and not client["errors"] and
                0 < client["latency_p50_ns"] <= client["latency_p99_ns"] and
                client["offered_requests_per_s"] == a.rate and server["errors"] == 0 and
                server["closed"] == server["accepted"] == a.connections and
                client["bytes"] == server["bytes"] == want_bytes, "final echo totals disagree")
        for sample in active_samples:
            for snap in sample["memory"].values():
                require(client["workload_start_ns"] <= snap["started_ns"] <= snap["ended_ns"] <
                        client["workload_end_ns"], "memory sample crossed the workload boundary")
        require(len({sample["client_app"]["requests_ok"] for sample in active_samples}) == 3,
                "client byte verification did not advance between active samples")
        stack_stats = (json.loads(self.docker("server", "cat", f"{self.out}/server/stack-stats.jsonl"))
                       if a.backend == "utcp" else None)
        if stack_stats and "dev_tun_offload" in stack_stats:
            require(stack_stats["dev_tun_offload"] == a.offload, "negotiated offload mode differs")
        elif a.offload != "legacy":
            raise RuntimeError("requested offload has no runtime counter readback")
        allocation = None
        if self.allocation_counter:
            first, last = (s["memory"]["server"]["cpp_new"] for s in (active_samples[0], active_samples[-1]))
            require(last["calls"] >= first["calls"], "C++ allocation counter went backwards")
            allocation = {"scope": "server_process_replaced_cpp_new",
                          "start": first, "end": last, "calls": last["calls"] - first["calls"]}
        return {"ok": True, "purpose": a.purpose, "source": self.source, "backend": a.backend,
                "held_ns": held_ns, "connections": a.connections, "offload": a.offload,
                "client_summary": client, "server_summary": server,
                "stack_stats": stack_stats, "steady": {"client_app": idle_client, "server_app": idle_server},
                "active_process_cpu": active_process_cpu(active_samples),
                "active_cpp_new": allocation,
                "active_app": [{k: v for k, v in sample.items() if k != "memory"}
                               for sample in active_samples],
                "memory": memory_results(a, base, idle, active_samples, drained, runtime, idle_server),
                "after_cpu": self.cpu_readback()}

    def cleanup(self):
        for role in reversed(self.created):
            try:
                run("docker", "rm", "-f", self.container(role))
            except (subprocess.SubprocessError, OSError) as error:
                print(f"cleanup {self.container(role)}: {error}", file=sys.stderr)
        if self.net_created:
            try:
                run("docker", "network", "rm", self.net)
            except (subprocess.SubprocessError, OSError) as error:
                print(f"cleanup {self.net}: {error}", file=sys.stderr)
        for proc in self.processes.values():
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)


def active_process_cpu(active):
    """CPU between the first and last in-workload /proc samples, in scheduler ticks."""
    result = {}
    for role in ROLES:
        first = active[0]["memory"][role]["process_cpu"]
        last = active[-1]["memory"][role]["process_cpu"]
        hz = first["ticks_per_second"]
        ns = last["sample_ns"] - first["sample_ns"]
        user = last["user_ticks"] - first["user_ticks"]
        system = last["system_ticks"] - first["system_ticks"]
        require(ns > 0 and hz == last["ticks_per_second"] and min(user, system) >= 0,
                f"{role} process CPU counters changed unexpectedly")
        result[role] = {"start_ns": first["sample_ns"], "end_ns": last["sample_ns"],
                        "user_ticks": user, "system_ticks": system, "ticks_per_second": hz,
                        "cpu_seconds": (user + system) / hz,
                        "cpu_fraction_of_one_core": (user + system) * 1e9 / (hz * ns)}
    return result


def memory_results(args, base, idle, active, drained, runtime, idle_server):
    result = {}
    for role in ROLES:
        result[role] = {}
        for label, snapshot in (("idle", idle[role]), *((f"active-{n}", s["memory"][role])
                                         for n, s in enumerate(active, 1))):
            b = base[role]
            entry = {field: snapshot[field] for field in ("rss_bytes", "pss_bytes", "memory_current_bytes")}
            for field in tuple(entry):
                entry[field + "_delta"] = entry[field] - b[field]
                entry[field + "_delta_per_connection"] = entry[field + "_delta"] / args.connections
            entry["cgroup_memory_stat_bytes_delta"] = {
                key: snapshot["memory_stat"][key] - b["memory_stat"][key]
                for key in ("anon", "kernel", "sock", "slab", "slab_unreclaimable")
                if key in b["memory_stat"] and key in snapshot["memory_stat"]}
            result[role][label] = entry
    if args.backend == "utcp":
        server = result["server"]
        peak_active_rss = max(server[f"active-{i}"]["rss_bytes"] for i in (1, 2, 3))
        peak_active_delta = max(server[f"active-{i}"]["rss_bytes_delta_per_connection"] for i in (1, 2, 3))
        result["utcp_server_targets"] = {
            "tcb_bytes": idle_server["tcb_bytes"], "tcb_bytes_at_most_1_kib": idle_server["tcb_bytes"] <= 1024,
            "idle_rss_delta_per_connection_at_most_2_kib": server["idle"]["rss_bytes_delta_per_connection"] <= 2048,
            "active_rss_delta_per_connection_at_most_12_kib": peak_active_delta <= 12288,
            "sampled_active_rss_at_most_128_mib": peak_active_rss <= 128 * 1024 * 1024,
            "peak_rss_through_workload_bytes": drained["server"]["rss_hwm_bytes"],
            "peak_rss_through_workload_at_most_128_mib":
                drained["server"]["rss_hwm_bytes"] <= 128 * 1024 * 1024,
            "measured_at_target_concurrency": args.connections == 10000,
            "verified_tun_rx_tx_queue_pair": runtime["server"]["tun_queues"]}
    return result


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--purpose", choices=("functional", "timing"), required=True)
    parser.add_argument("--backend", choices=("utcp", "kernel"), required=True)
    parser.add_argument("--offload", choices=("legacy", "checksum", "tcpv4"), default="legacy")
    parser.add_argument("--image", default=os.environ.get("UTCP_IMAGE", "utcp-testbed:dev"))
    parser.add_argument("--binary", default="build/gcc-release/apps/utcp-echo/utcp-echo")
    parser.add_argument("--binary-source", help="full source SHA for a separately built server")
    parser.add_argument("--client-binary", help="optional separate kernel client, under this checkout")
    parser.add_argument("--client-source", help="full source SHA for the separate kernel client")
    parser.add_argument("--allocation-counter", help="functional server only, path to the preload library")
    parser.add_argument("--connections", type=int, default=10000)
    parser.add_argument("--open-batch", type=int, default=32)
    parser.add_argument("--backlog", type=int, default=4096)
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--size", type=int, default=64)
    parser.add_argument("--rate", type=int, default=5000)
    parser.add_argument("--hold-s", type=float, default=5.0)
    parser.add_argument("--net-base", type=int, default=85)
    parser.add_argument("--cpus", default="24,25,26", help="server,client,collector CPU IDs")
    args = parser.parse_args()
    try:
        args.cpus = tuple(int(cpu) for cpu in args.cpus.split(","))
    except ValueError:
        parser.error("--cpus must be three comma-separated CPU IDs")
    allowed = range(24, 28) if args.purpose == "functional" else range(8, 16)
    if len(set(args.cpus)) != 3 or len(args.cpus) != 3 or any(cpu not in allowed for cpu in args.cpus):
        parser.error(f"--cpus needs three distinct CPU IDs in {allowed.start}–{allowed.stop - 1}")
    if not (1 <= args.connections <= NOFILE - 128 and 1 <= args.open_batch <= min(args.backlog, 1024)
            and args.backlog <= 2**31 - 1 and 1 <= args.net_base <= 254
            and 1 <= args.rate <= 10**9 and args.count > 0 and 1 <= args.size <= 1460
            and args.connections * args.count * args.size <= 2**64 - 1
            and args.connections * args.count / args.rate >= 4 and 1 <= args.hold_s <= 300):
        parser.error("invalid concurrency, backlog, subnet, workload or hold; allow at least four seconds of active work")
    if args.purpose == "timing" and (args.connections != 10000 or args.hold_s < 5):
        parser.error("timing requires 10,000 sockets and a hold of at least five seconds")
    if bool(args.client_binary) != bool(args.client_source):
        parser.error("--client-binary requires --client-source and vice versa")
    if args.allocation_counter and (args.purpose != "functional" or args.backend != "utcp"):
        parser.error("--allocation-counter requires a functional userspace server")
    if args.backend == "kernel" and args.offload != "legacy":
        parser.error("--offload requires the utcp server")
    return args


def main():
    args = arguments()
    try:
        trial = Trial(args)
    except ValueError as error:
        print(f"invalid benchmark binary or allocation counter: {error}", file=sys.stderr)
        return 1
    try:
        trial.setup()
        result = trial.trial()
        trial.capture_json("server", "result.json", result)
        print(json.dumps({"ok": True, "volume": "utcp-data:" + trial.out.removeprefix("/data"),
                          "client": result["client_summary"], "memory": result["memory"]}))
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        detail = {"ok": False, "run_id": trial.tag, "error": str(error)}
        if isinstance(error, subprocess.CalledProcessError):
            detail["output"] = error.stdout
        if trial.artifacts_created:
            try:
                trial.capture_json("server", "failure.json", detail)
            except (OSError, subprocess.SubprocessError) as save_error:
                detail["artifact_error"] = str(save_error)
        print(json.dumps(detail), file=sys.stderr)
        return 1
    finally:
        trial.cleanup()


if __name__ == "__main__":
    sys.exit(main())
