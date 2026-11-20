#!/usr/bin/env python3
"""Serial same-host bulk comparisons. All campaign receipts stay in utcp-data."""

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from model import measure, schedule, summarize

SCRIPTS = Path(__file__).resolve().parent
REPO = SCRIPTS.parents[2]
VOLUME = "utcp-data"
HELPER_CPUS = "28-31"
MTU = 1500
STACK_IP = "198.18.0.2"
TUN_GATEWAY = "198.18.0.1"
APP_OPTIONS = ("--cc", "cubic", "--chunk", "256Ki", "--sample-ms", "0", "--pattern-seed", "1")
FIXED_OPTIONS = {"--backend", "--listen", "--connect", "--send", "--recv", "--bytes",
                 "--duration", "--pcap", "--stats", "--jsonl", "--tun", "--addr", "--mtu",
                 "--profile", "--seed", *APP_OPTIONS[::2]}


def invoke(*argv, check=True, stdin=None, timeout=30):
    result = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    if check and result.returncode:
        diagnostic = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"{argv!r} returned {result.returncode}: {diagnostic}")
    return result


def output(*argv):
    return invoke(*argv).stdout.decode().strip()


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def info():
    return {"utc": datetime.now(timezone.utc).isoformat(), "uptime": output("uptime"),
            "top_cpu": output("ps", "-e", "-o", "pid,psr,pcpu,comm", "--sort=-pcpu").splitlines()[:21],
            "slot_threads": [line for line in output(
                "ps", "-eLo", "pid,lwp,psr,pcpu,cputimes,comm", "--sort=-pcpu").splitlines()[1:]
                if line.split()[2] in {"8", "9", "10", "11"}],
            **{name: Path(f"/proc/{name}").read_text()
               for name in ("stat", "softirqs", "net/softnet_stat")}}


def load_cgroup(state):
    rows = state.split("== cgroup cpu.stat\n", 1)[1].split("== affinity\n", 1)[0]
    return {key: int(value) for key, value in (line.split() for line in rows.splitlines())}


def ethernet_settings(aggregation):
    segmentation = "on" if aggregation else "off"
    return {"tso": segmentation, "gso": segmentation, "gro": "off"}


def tun_features(flags):
    return [name for bit, name in ((0x4000, "vnet_hdr"), (0x0100, "multi_queue")) if flags & bit]


def expected_hash(nbytes):
    with tempfile.TemporaryDirectory(prefix="utcp-m4-oracle-") as temp:
        binary = str(Path(temp) / "oracle")
        invoke("gcc", "-std=c17", "-Wall", "-Wextra", "-Werror", "-O2",
               str(SCRIPTS / "oracle.c"), "-o", binary)
        with subprocess.Popen([binary, str(nbytes)], stdout=subprocess.PIPE) as oracle:
            with oracle.stdout as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            if oracle.wait():
                raise RuntimeError("independent byte oracle did not complete")
        return digest


@dataclass(frozen=True)
class Mode:
    name: str
    binary: str
    source: str
    args: tuple = ()
    vnet: bool = False
    multi_queue: bool = False


class Campaign:
    def __init__(self, args, kernel, candidate, reference):
        self.args = args
        self.modes = {mode.name: mode for mode in (kernel, reference, candidate) if mode}
        self.order = schedule(args.repeats, candidate.name, reference.name if reference else None)
        self.prefix = f"utcp-m4-{args.run_id}"
        self.directory = f"/data/m4/performance/{args.run_id}"
        self.network = f"{self.prefix}-net"
        self.store = f"{self.prefix}-data"
        self.containers = {role: f"{self.prefix}-{role}" for role in ("dut", "peer")}
        self.cpus = dict(zip(self.containers, (28, 30) if args.functional else (8, 10), strict=True))
        self.addresses = {role: f"198.19.{args.subnet}.{index}"
                          for index, role in enumerate(self.containers, 2)}
        self.created = []
        self.have_network = False
        self.image = output("docker", "image", "inspect", "--format", "{{.Id}}", args.image)
        self.digest = expected_hash(args.bytes)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        for name in reversed(self.created):
            result = invoke("docker", "rm", "-f", name, check=False)
            if result.returncode:
                print(result.stderr.decode(errors="replace"), file=sys.stderr)
        if self.have_network:
            invoke("docker", "network", "rm", self.network)

    def docker_exec(self, role, *argv, **kwargs):
        name = self.store if role == "data" else self.containers[role]
        return invoke("docker", "exec", "-i", name, *argv, **kwargs)

    def put(self, path, data):
        self.docker_exec("data", "tee", f"{self.directory}/{path}", stdin=data)

    def put_json(self, path, data):
        self.put(path, json_bytes(data))

    def get(self, path):
        return self.docker_exec("data", "cat", f"{self.directory}/{path}").stdout

    def run_container(self, name, *options):
        invoke("docker", "run", "-d", "--init", "--name", name, *options, self.image,
               "sleep", "infinity", timeout=60)
        self.created.append(name)

    def freeze(self):
        output("docker", "volume", "inspect", VOLUME)
        mounts = [option for name, mode in self.modes.items()
                  for option in ("-v", f"{mode.binary}:/input-{name}:ro")]
        data_mount = ("-v", f"{VOLUME}:/data")
        self.run_container(self.store, "--network", "none", "--cpuset-cpus", HELPER_CPUS,
                           *data_mount, *mounts)
        self.docker_exec("data", "mkdir", "-p", "/data/m4/performance")
        self.docker_exec("data", "mkdir", self.directory)
        self.docker_exec("data", "mkdir", f"{self.directory}/bin", f"{self.directory}/runner")
        inputs = {}
        for name, mode in self.modes.items():
            archived = f"{self.directory}/bin/{name}"
            self.docker_exec("data", "cp", f"/input-{name}", archived)
            digest = self.docker_exec("data", "sha256sum", archived).stdout.decode().split()[0]
            if digest != sha(mode.binary):
                raise RuntimeError(f"{name} binary changed while freezing")
            inputs[name] = {**asdict(mode), "sha256": digest}
        sources = {}
        for name in ("run.py", "state.sh", "endpoint.py", "model.py", "oracle.c", "test_performance.py"):
            data = (SCRIPTS / name).read_bytes()
            self.put(f"runner/{name}", data)
            sources[name] = hashlib.sha256(data).hexdigest()
        self.put("image.json", invoke("docker", "image", "inspect", self.image).stdout)
        self.put_json("plan.json", {
            "schema": 1, "run_id": self.args.run_id, "argv": sys.argv,
            "runner_source": output("git", "-C", str(REPO), "rev-parse", "HEAD"),
            "image": self.image, "kernel": output("uname", "-a"), "modes": inputs,
            "runner_sha256": sources, "order": self.order, "bytes": self.args.bytes,
            "sha256": self.digest, "cpus": self.cpus, "addresses": self.addresses,
            "stack_ip": STACK_IP, "mtu": MTU, "app_options": APP_OPTIONS,
            "ethernet_aggregation": self.args.ethernet_aggregation,
            "functional": self.args.functional, "volume": VOLUME, "host_pre": info()})
        if self.args.probe_perf:
            command = ("perf", "stat", "-e", "task-clock,cycles,instructions", "--", "/usr/bin/true")
            attempt = invoke(*command, check=False)
            self.put_json("perf.json", {"argv": command, "exit": attempt.returncode,
                                       "stdout": attempt.stdout.decode(errors="replace"),
                                       "stderr": attempt.stderr.decode(errors="replace"),
                                       "version": output("perf", "--version"),
                                       "paranoid": Path("/proc/sys/kernel/perf_event_paranoid").read_text().strip(),
                                       "cap_eff": next(row for row in Path("/proc/self/status").read_text().splitlines()
                                                       if row.startswith("CapEff:"))})

    def setup(self):
        invoke("docker", "network", "create", "--driver", "bridge",
               "--subnet", f"198.19.{self.args.subnet}.0/24",
               "--opt", f"com.docker.network.driver.mtu={MTU}", self.network)
        self.have_network = True
        self.put("network.json", invoke("docker", "network", "inspect", self.network).stdout)
        for role, name in self.containers.items():
            forwarding = ("--device", "/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1") if role == "dut" else ()
            self.run_container(name, "--network", self.network, "--ip", self.addresses[role],
                               "--cap-add", "NET_ADMIN", "--cpuset-cpus", str(self.cpus[role]),
                               "--sysctl", "net.ipv4.tcp_no_metrics_save=1",
                               "--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
                               "--sysctl", "net.ipv6.conf.default.disable_ipv6=1",
                               "-v", f"{VOLUME}:/data", *forwarding)
            self.put(f"{role}.container.json", invoke("docker", "container", "inspect", name).stdout)
            self.docker_exec(role, "ip", "route", "del", "default")
            feature_states = ethernet_settings(self.args.ethernet_aggregation)
            feature_args = [item for pair in feature_states.items() for item in pair]
            self.docker_exec(role, "ethtool", "-K", "eth0", *feature_args)
            links = json.loads(self.docker_exec(role, "ip", "-j", "link", "show", "dev", "eth0").stdout)
            if links[0]["mtu"] != MTU:
                raise RuntimeError(f"{role} ethernet MTU differs from {MTU}")
            offloads = self.docker_exec(role, "ethtool", "-k", "eth0").stdout.decode()
            names = {"tso": "tcp-segmentation-offload", "gso": "generic-segmentation-offload",
                     "gro": "generic-receive-offload"}
            for short, value in feature_states.items():
                feature = names[short]
                if not re.search(rf"(?m)^{feature}: {value}(?: |$)", offloads):
                    raise RuntimeError(f"{role} ethernet feature {feature} did not read back {value}")
        self.docker_exec("peer", "ip", "route", "add", f"{STACK_IP}/32", "via", self.addresses["dut"])
        for role, other in (("dut", "peer"), ("peer", "dut")):
            mac = self.docker_exec(other, "cat", "/sys/class/net/eth0/address").stdout.decode().strip()
            self.docker_exec(role, "ip", "neigh", "replace", self.addresses[other],
                             "lladdr", mac, "dev", "eth0", "nud", "permanent")

    def tun(self, mode):
        flag_path = "/sys/class/net/utcp0/tun_flags"
        previous = self.docker_exec("dut", "cat", flag_path, check=False)
        if previous.returncode == 0:
            # Deleting a persistent TUN attaches a temporary fd and must use
            # the same IFF_VNET_HDR and IFF_MULTI_QUEUE as the existing device.
            self.docker_exec("dut", "ip", "tuntap", "del", "dev", "utcp0", "mode", "tun",
                             *tun_features(int(previous.stdout, 16)))
        features = tun_features((0x4000 if mode.vnet else 0) | (0x0100 if mode.multi_queue else 0))
        self.docker_exec("dut", "ip", "tuntap", "add", "dev", "utcp0", "mode", "tun", *features)
        self.docker_exec("dut", "ip", "addr", "add", f"{TUN_GATEWAY}/24", "dev", "utcp0")
        self.docker_exec("dut", "ip", "link", "set", "dev", "utcp0", "mtu", str(MTU),
                         "txqueuelen", "10000", "up")
        self.docker_exec("dut", "tc", "qdisc", "replace", "dev", "utcp0", "root",
                         "pfifo", "limit", "10000")
        flags = int(self.docker_exec("dut", "cat", flag_path).stdout, 16)
        if (bool(flags & 0x4000) != mode.vnet or bool(flags & 0x0100) != mode.multi_queue):
            raise RuntimeError(f"TUN VNET_HDR or MULTI_QUEUE did not match {mode.name}: 0x{flags:x}")
        return f"0x{flags:x}"

    def state(self, arm, phase):
        states = {}
        for role in self.containers:
            state = self.docker_exec(role, "bash", f"{self.directory}/runner/state.sh").stdout
            self.put(f"{arm}/{role}.{phase}.txt", state)
            states[role] = load_cgroup(state.decode())
        self.put_json(f"{arm}/host.{phase}.json", info())
        return states

    def endpoint(self, arm, side, role, peer_address, port, backend, mode):
        app = [f"{self.directory}/bin/{mode.name}", "--backend", backend,
               "--bytes", str(self.args.bytes), *APP_OPTIONS, "--jsonl",
               f"{self.directory}/{arm}/{role}.jsonl"]
        address = STACK_IP if backend == "utcp" else self.addresses[side]
        if backend == "utcp":
            app += ["--profile", "linux", "--tun", "utcp0", "--addr", address,
                    "--mtu", str(MTU), "--seed", "1", "--stats",
                    f"{self.directory}/{arm}/{role}.stats.json", *mode.args]
        app += ["--recv", "--listen", f"{address}:{port}"] if role == "recv" else [
            "--send", "--connect", f"{peer_address}:{port}"]
        wrapper = ["docker", "exec", self.containers[side], "python3",
                   f"{self.directory}/runner/endpoint.py", f"{self.directory}/{arm}",
                   role, str(self.args.timeout)]
        return wrapper + ([backend, str(port)] if role == "recv" else []) + app

    def wait_listener(self, receiver, arm):
        path = f"{self.directory}/{arm}/listener.ready"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            ready = self.docker_exec("data", "test", "-s", path, check=False)
            if ready.returncode == 0:
                return
            if receiver.poll() is not None:
                break
            time.sleep(0.025)
        raise RuntimeError("receiver listener readiness was not observed")

    def record_active_tun(self, arm):
        result = self.docker_exec("dut", "ethtool", "-k", "utcp0", check=False)
        self.put_json(f"{arm}/tun.active.json", {
            "status": result.returncode, "stdout": result.stdout.decode(), "stderr": result.stderr.decode(),
            "note": "Sampled near start. Use app negotiation/stats for features that require an open FD."})

    def transfer(self, arm, send, recv, dut_role, capture_tun):
        commands = {"send": send, "recv": recv}
        children = {}
        diagnostics = {}
        try:
            children["recv"] = subprocess.Popen(recv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.wait_listener(children["recv"], arm)
            if capture_tun and dut_role == "recv":
                self.record_active_tun(arm)
            children["send"] = subprocess.Popen(send, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if capture_tun and dut_role == "send":
                time.sleep(0.1)
                self.record_active_tun(arm)
        finally:
            for role, child in children.items():
                stdout, stderr = child.communicate(timeout=self.args.timeout + 15)
                diagnostics[role] = {"status": child.returncode, "argv": commands[role],
                                     "stdout": stdout.decode(), "stderr": stderr.decode()}
            self.put_json(f"{arm}/exec.json", diagnostics)
        return diagnostics

    def evidence(self, arm, role):
        summary = json.loads(self.get(f"{arm}/{role}.stdout"))
        records = [json.loads(line) for line in self.get(f"{arm}/{role}.jsonl").splitlines()]
        if [row for row in records if row["ev"] == "summary"] != [summary]:
            raise ValueError("stdout summary differs from application JSONL")
        return {"summary": summary, "usage": json.loads(self.get(f"{arm}/{role}.usage.json"))}

    def arm(self, index, rep, direction, name):
        arm = f"{index:02d}-r{rep}-{direction}-{name}"
        self.docker_exec("data", "mkdir", f"{self.directory}/{arm}")
        row = {"arm": arm, "repeat": rep, "direction": direction, "mode": name, "valid": False}
        try:
            mode = self.modes[name]
            row["tun_flags"] = self.tun(mode)
            sender, receiver = ("dut", "peer") if direction == "dut-to-peer" else ("peer", "dut")
            backends = {side: "utcp" if side == "dut" and name != "kernel" else "kernel"
                        for side in self.containers}
            recv_ip = STACK_IP if backends[receiver] == "utcp" else self.addresses[receiver]
            port = 20000 + index
            commands = {
                role: self.endpoint(arm, side, role, recv_ip, port, backends[side],
                                    mode if backends[side] == "utcp" else self.modes["kernel"])
                for role, side in (("send", sender), ("recv", receiver))}
            self.put_json(f"{arm}/commands.json", commands)
            before = self.state(arm, "before")
            try:
                diagnostics = self.transfer(arm, commands["send"], commands["recv"],
                                            "send" if sender == "dut" else "recv", mode.vnet)
            finally:
                after = self.state(arm, "after")
                row["cgroup_usec_delta"] = {
                    role: {key: after[role][key] - before[role][key]
                           for key in ("usage_usec", "user_usec", "system_usec")}
                    for role in self.containers}
            if any(diag["status"] != 0 for diag in diagnostics.values()):
                raise ValueError("one or more endpoint attempts exited unsuccessfully")
            evidence = [self.evidence(arm, role) for role in ("send", "recv")]
            row.update(measure(*evidence, self.args.bytes, self.digest, (backends[sender], backends[receiver]),
                               (self.cpus[sender], self.cpus[receiver])))
            if name != "kernel":
                role = "send" if sender == "dut" else "recv"
                row["stack_stats"] = json.loads(self.get(f"{arm}/{role}.stats.json"))
                if row["stack_stats"].get("dev_device_failed") is not False:
                    raise ValueError("stack device failure, or missing device status")
            row["valid"] = True
        except (ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired) as error:
            row["error"] = str(error)
        self.put_json(f"{arm}/result.json", row)
        print(f"{arm}: {row.get('receiver_gbps', row.get('error'))}", flush=True)
        return row

    def archive(self, rows):
        compact = {"rows": rows, "groups": summarize(rows, tuple(self.modes))}
        self.put_json("compact.json", compact)
        self.put_json("host-after.json", info())
        self.docker_exec("data", "bash", "-euo", "pipefail", "-c",
                         'cd "$1"; find . -type f ! -name SHA256SUMS -print0 | '
                         'sort -z | xargs -0 sha256sum > SHA256SUMS', "bash", self.directory, timeout=60)
        print(self.docker_exec("data", "sha256sum", f"{self.directory}/SHA256SUMS").stdout.decode().strip())


def parse():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-id", required=True, help="new campaign name within the private volume")
    p.add_argument("--bulk", required=True, type=Path, help="fixed Linux control bulk binary")
    p.add_argument("--bulk-source", required=True, help="full commit of the Linux control binary")
    p.add_argument("--mode", default="stack", help="name of the candidate mode")
    p.add_argument("--reference-mode", help="optional third arm paired against the candidate")
    p.add_argument("--image", default="utcp-testbed:dev")
    p.add_argument("--bytes", type=int, default=1_000_000_000)
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--timeout", type=float, default=120)
    p.add_argument("--subnet", type=int, default=220, help="third octet for a dedicated 198.19.X.0/24 bridge")
    p.add_argument("--functional", action="store_true", help="use CPUs 28 and 30 for untimed testing")
    p.add_argument("--probe-perf", action="store_true", help="retain an ordinary process-scoped perf attempt")
    p.add_argument("--ethernet-aggregation", action="store_true",
                   help="enable ethernet TSO/GSO in every arm so aggregates can reach TUN")
    for option in ("candidate", "reference"):
        p.add_argument(f"--{option}-bulk", type=Path)
        p.add_argument(f"--{option}-source")
    for prefix in ("", "reference-"):
        p.add_argument(f"--{prefix}stack-arg", action="append", default=[])
        p.add_argument(f"--{prefix}tun-vnet", action="store_true")
        p.add_argument(f"--{prefix}tun-multi-queue", action="store_true")
    args = p.parse_args()
    names = [args.run_id, "kernel", args.mode]
    if args.reference_mode:
        names.append(args.reference_mode)
    if any(not re.fullmatch("[a-z0-9][a-z0-9-]{0,39}", name) for name in names):
        p.error("run and mode names must be lower-case alphanumeric or hyphen, up to 40 characters")
    if len(set(names[1:])) != len(names[1:]):
        p.error("mode names must be distinct and cannot replace kernel")
    if (not 0 < args.bytes <= 10_000_000_000 or not 0 < args.repeats <= 100
            or not 10 <= args.timeout <= 600 or not 1 <= args.subnet <= 253):
        p.error("invalid bytes, repeats, timeout or subnet")
    if args.candidate_bulk and not args.candidate_source:
        p.error("--candidate-bulk requires --candidate-source")
    if args.reference_bulk and not args.reference_source:
        p.error("--reference-bulk requires --reference-source")
    for setting in args.stack_arg + args.reference_stack_arg:
        if setting.split("=", 1)[0] in FIXED_OPTIONS:
            p.error(f"{setting} overrides a fixed workload or recording option")
    input_files = [args.bulk, args.candidate_bulk, args.reference_bulk]
    if any(not path.is_file() or not os.access(path, os.X_OK) or ":" in str(path.resolve())
           for path in input_files if path):
        p.error("all bulk binaries must be local executable files with mountable paths")
    commits = [args.bulk_source, args.candidate_source, args.reference_source]
    if any(not re.fullmatch("[0-9a-f]{40}", commit) for commit in commits if commit):
        p.error("all binary sources must be full commit hashes")
    if not os.sched_getaffinity(0) <= set(range(28, 32)):
        p.error("start the controller with taskset -c 28-31 nice -n 10")
    return args


def main():
    args = parse()
    if output("git", "-C", str(REPO), "status", "--porcelain", "--", str(SCRIPTS)):
        raise RuntimeError("commit the runner before freezing a campaign")
    kernel = Mode("kernel", str(args.bulk.resolve()), args.bulk_source)
    candidate = Mode(args.mode, str((args.candidate_bulk or args.bulk).resolve()),
                     args.candidate_source or args.bulk_source, tuple(args.stack_arg),
                     args.tun_vnet, args.tun_multi_queue)
    reference = None
    if args.reference_mode:
        reference = Mode(args.reference_mode,
                         str(args.reference_bulk.resolve()) if args.reference_bulk else candidate.binary,
                         args.reference_source or candidate.source, tuple(args.reference_stack_arg),
                         args.reference_tun_vnet, args.reference_tun_multi_queue)
    with Campaign(args, kernel, candidate, reference) as campaign:
        campaign.freeze()
        rows = []
        try:
            campaign.setup()
            for index, (rep, direction, mode) in enumerate(campaign.order, 1):
                rows.append(campaign.arm(index, rep, direction, mode))
        finally:
            campaign.archive(rows)
    return 0 if len(rows) == len(campaign.order) and all(row["valid"] for row in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
