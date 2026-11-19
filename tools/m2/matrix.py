#!/usr/bin/env python3
"""Runner of the M2 comparison testbed (DESIGN §14; M2 design §5.4, §5.6, §5.13).

Runs on the server host (it calls docker); writes everything into the volume
utcp-data under /m2/<campaign>/<run>/ through the testbed containers, and runs
the analysis in a helper container on CPUs 16-31.

  matrix.py up --slot N [--nontiming]       testbed/m2/up.sh
  matrix.py down --slot N                   testbed/m2/down.sh
  matrix.py one --slot N --campaign C --run R --bw MBIT --rtt MS --queue-bdp X
                [--loss P] [--seed S] [--impl linux|utcp] [--cc CC] [--duration S]
                [--extra-capture]          one run, analysed (summary.json)
  matrix.py calibrate --slot N --campaign C [--pairs 10x20,...] [--skip-stack]
                                            the calibration gate (§5.4), gate.json
                                            and gate.md in the campaign directory
  matrix.py analyze --campaign C            summary.json of every run again
  matrix.py tables --campaign C --out DIR   runs.csv and cells.csv (DIR in the volume)
  matrix.py cat PATH                        prints a file from the volume
  matrix.py run PLAN.toml --slot N (--gate CAMPAIGN ... | --no-gate)
                [--nontiming] [--rekey] [--no-rerun] [--parallel --slot M]
                                            a run plan (load_plan has the format;
                                            run_plan the checks); resumable: runs
                                            with a summary.json are skipped, a partial
                                            run is moved to aside/; an invalid group
                                            is rerun as a whole
  matrix.py expand PLAN.toml [--slots K]    the run list of a plan, no runs
  matrix.py plot --campaign C [--out DIR]   overlay plots (tools/m2/plot.py)
  matrix.py proof --campaign C [--phase serial|parallel|report|all] [--reps 5] [--stack-cc newreno|cubic | --cubic-only]
                                            the parallel-mode proof (§6) and the trace
                                            overhead (§5.6): proof.json, proof.md

A partial calibration, or a proof with fewer than five reps or a subset of
pairs, reports diagnostic measurements. For a live proof use a separate
campaign per configuration. --cubic-only runs the five serial CUBIC transfers
and five pairs assigned to m2-integrate, with the stack criteria of §6. Historical reports predate proof-config.json,
identified ping records, sender CC observations, metadata digests and boot
IDs for comparing measured CLOCK_MONOTONIC windows across the two slots.

Environment: UTCP_M2_PREFIX (testbed names, default utcp-m2), UTCP_M2_JOB
(names of the helper containers, default utcp-m2-runner), UTCP_IMAGE,
UTCP_DATA_VOLUME, UTCP_BUILD (build directory below the repository, default
build/tb-gcc-release), UTCP_COMMIT (else the .utcp-commit file, else git).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import itertools
import json
import math
import os
import random
import re
import shlex
import subprocess
import sys
import threading
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze as A  # noqa: E402

IMAGE = os.environ.get("UTCP_IMAGE", "utcp-testbed:dev")
VOLUME = os.environ.get("UTCP_DATA_VOLUME", "utcp-data")
PREFIX = os.environ.get("UTCP_M2_PREFIX", "utcp-m2")
JOB = os.environ.get("UTCP_M2_JOB", "utcp-m2-runner")
BUILD = os.environ.get("UTCP_BUILD", "build/tb-gcc-release")
BULK = f"/utcp/{BUILD}/apps/utcp-bulk/utcp-bulk"
PORT = 5201

# Calibration (§5.4).
PAIRS = ((10, 20), (10, 100), (100, 20), (100, 100))
QUEUES = (2.0, 0.5)
LOSSES = (0.1, 1.0)
RATE_FRACTION = 0.98 * 1448 / 1514

# The stack's buffers (§5.3); gso_max_size is added per slot from the
# sender's measured gso_ipv4_max_size (stack_sets).
STACK_SETS = ("snd_buf_max=64Mi", "rcv_buf_max=32Mi")
# Linux sk_setup_caps: sk_gso_max_size = the device's gso_ipv4_max_size -
# (MAX_TCP_HEADER + 1); MAX_TCP_HEADER = 320 as in TcpConfig's default.
MAX_TCP_HEADER = 320


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def sh(cmd, check=True, capture=True, input=None, timeout=None):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), check=False, text=True, input=input,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {cmd}\n{r.stdout}")
    return r.stdout if capture else ""


def dexec(c, script, check=True, timeout=300, input=None):
    cmd = ["docker", "exec"] + (["-i"] if input is not None else []) + [c, "bash", "-c", script]
    return sh(cmd, check=check, timeout=timeout, input=input)


def dexec_bg(c, script):
    sh(["docker", "exec", "-d", c, "bash", "-c", script])


def publish_script(path):
    target = shlex.quote(path)
    return f"set -e; tmp=$(mktemp {target}.tmp.XXXXXXXX); cat > \"$tmp\"; mv -f \"$tmp\" {target}"


def vol_write(c, path, text):
    sh(["docker", "exec", "-i", c, "bash", "-c", publish_script(path)], input=text)


def prepare_trial(slot, campaign, run):
    """Keep every interrupted or replaced attempt, including its partial raw files."""
    base = shlex.quote(f"/data/m2/{campaign}")
    rd = shlex.quote(f"/data/m2/{campaign}/{run}")
    prefix = shlex.quote(f"/data/m2/{campaign}/aside/{run}.XXXXXXXX")
    dexec(slot.snd, f"set -e; if [ -e {rd} ]; then mkdir -p {base}/aside; "
                    f"saved=$(mktemp -d {prefix}); mv {rd} \"$saved/raw\"; fi; mkdir -p {rd}")


def timing_cpu_names(slot):
    first = 8 + 4 * slot
    return (",".join(str(c) for c in range(first, first + 4)), f"{first}-{first + 3}")


def timing_placement(slot, cpusets):
    if slot not in (0, 1) or not isinstance(cpusets, dict) or len(cpusets) != 4:
        return False
    first = 8 + 4 * slot
    expected = {"snd": [first, first + 1], "rcv": [first + 2], "r1": [first + 3], "r2": [first + 3]}
    try:
        return {name.rsplit("-", 1)[-1]: sorted(A.cpu_list(cpus)) for name, cpus in cpusets.items()} == expected
    except (ValueError, AttributeError):
        return False


class Slot:
    def __init__(self, n):
        self.n = n
        b = f"{PREFIX}-s{n}"
        self.snd, self.r1, self.r2, self.rcv = (f"{b}-snd", f"{b}-r1", f"{b}-r2", f"{b}-rcv")
        x = 10 + 4 * n if n < 2 else 40 + 4 * (n - 2)
        self.snd_ip = f"198.19.{x}.2"
        self.rcv_ip = f"198.19.{x + 2}.5"
        self.ip = {"r1_a": f"198.19.{x}.3", "r1_b": f"198.19.{x + 1}.3", "r2_b": f"198.19.{x + 1}.4",
                   "r2_c": f"198.19.{x + 2}.4"}
        self.stack_ip = f"198.18.{8 * n}.2"
        self.cpus = {c: sh(["docker", "container", "inspect", "-f", "{{.HostConfig.CpusetCpus}}", c]).strip()
                     for c in (self.snd, self.r1, self.r2, self.rcv)}
        self.ifs = {}
        for key, c in (("r1_a", self.r1), ("r1_b", self.r1), ("r2_b", self.r2), ("r2_c", self.r2)):
            self.ifs[key] = self.ifname(c, self.ip[key])
        self.ifs["snd"] = self.ifname(self.snd, self.snd_ip)
        self.ifs["rcv"] = self.ifname(self.rcv, self.rcv_ip)

    @staticmethod
    def ifname(c, addr):
        out = sh(["docker", "exec", c, "ip", "-o", "-4", "addr", "show"])
        for line in out.splitlines():
            f = line.split()
            if f[3].split("/")[0] == addr:
                return f[1]
        raise RuntimeError(f"no interface with {addr} in {c}")

    def containers(self):
        return {"snd": self.snd, "r1": self.r1, "r2": self.r2, "rcv": self.rcv}

    def gso_ipv4_max_size(self):
        """The sender interface's gso_ipv4_max_size (ip -d link), the
        device value Linux derives sk_gso_max_size from."""
        out = sh(["docker", "exec", self.snd, "ip", "-d", "link", "show", "dev", self.ifs["snd"]])
        m = re.search(r"gso_ipv4_max_size (\d+)", out)
        return int(m.group(1)) if m else None

    def cleanup(self):
        """Stops what an interrupted run may have left: senders, receivers,
        pings, captures, the tbf sampler."""
        for c in (self.snd, self.rcv):
            dexec(c, "pkill -x utcp-bulk; pkill -x ping; true", check=False)
        dexec(self.r2, "[ -e /run/utcp-tbf-sampler.pid ] && kill $(cat /run/utcp-tbf-sampler.pid); "
                       "rm -f /run/utcp-tbf-sampler.pid; true", check=False)
        for c in (self.r1, self.r2):
            dexec(c, "pkill -INT -x tcpdump; true", check=False)
        for c in (self.snd, self.rcv, self.r1, self.r2):
            try:
                wait_for(c, "! ps -eo stat=,comm= | awk '($2 == \"utcp-bulk\" || $2 == \"tcpdump\" || "
                            "$2 == \"ping\") && $1 !~ /^Z/' | grep -q .", "leftover processes", timeout=10)
            except RuntimeError:
                dexec(c, "pkill -KILL -x utcp-bulk; pkill -KILL -x tcpdump; pkill -KILL -x ping; true",
                      check=False)

    def slot_cpus(self):
        cpus = []
        for c in self.cpus.values():
            cpus += A.cpu_list(c)
        return ",".join(str(x) for x in sorted(set(cpus)))

    @property
    def timing(self):
        return timing_placement(self.n, self.cpus)


def stack_sets(gso_ipv4_max_size):
    """--set arguments of every stack run (§5.3, M2-TASKS m2d-testbed test 9)."""
    sets = list(STACK_SETS)
    if gso_ipv4_max_size:
        sets.append(f"gso_max_size={gso_ipv4_max_size - MAX_TCP_HEADER - 1}")
    return sets


def tb(script, *args):
    return sh([str(REPO / "testbed" / "m2" / script), *map(str, args)])


def sha256_file(p):
    try:
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except FileNotFoundError:
        return None


def tree_hash(*dirs):
    h = hashlib.sha256()
    for d in dirs:
        for p in sorted(Path(d).rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                h.update(p.relative_to(REPO).as_posix().encode() + b"\0" + p.read_bytes())
    return h.hexdigest()


def commit():
    if os.environ.get("UTCP_COMMIT"):
        return os.environ["UTCP_COMMIT"]
    f = REPO / ".utcp-commit"
    if f.exists():
        return f.read_text().strip()
    try:
        return sh(["git", "-C", str(REPO), "describe", "--always", "--dirty", "--abbrev=40"]).strip()
    except Exception:
        return "unknown"


def static_meta():
    bulk = REPO / BUILD / "apps" / "utcp-bulk" / "utcp-bulk"
    core = REPO / BUILD / "src" / "core" / "libutcp_core.a"
    return {
        "uname_r": sh(["uname", "-r"]).strip(),
        "image": IMAGE,
        "image_id": sh(["docker", "image", "inspect", "-f", "{{.Id}}", IMAGE]).strip(),
        "commit": commit(),
        "build": BUILD,
        "bulk_sha256": sha256_file(bulk),
        "core_sha256": sha256_file(core),
        "scripts_sha256": tree_hash(REPO / "testbed" / "m2", REPO / "tools" / "m2"),
    }


def reuse_key(meta, sysctl_dump):
    """§5.13: binaries, preset, kernel, image, scripts, sysctls and module parameters."""
    h = hashlib.sha256()
    for k in ("bulk_sha256", "core_sha256", "build", "uname_r", "image_id", "scripts_sha256"):
        h.update(f"{k}={meta.get(k)}\n".encode())
    h.update(sysctl_dump.encode())
    return h.hexdigest()


def sysctl_dump(record_text):
    rec = A.parse_record(record_text)
    out = []
    for (where, what), lines in sorted(rec.items()):
        if what == "sysctl" or what == "module parameters":
            # The container name carries the slot; the key must not.
            role = where.rsplit("-", 1)[-1]
            out += [f"{role}: {l}" for l in lines]
    return "\n".join(out) + "\n"


_helper_seq = itertools.count()  # unique helper container names across threads


def run_analysis(args, timeout=900):
    """analyze.py in a helper container on CPUs 16-31 with the volume mounted."""
    name = f"{JOB}-ana-{os.getpid()}-{next(_helper_seq)}"
    return sh(["docker", "run", "--rm", "--name", name, "--cpuset-cpus", "16-31",
               "-v", f"{VOLUME}:/data", "-v", f"{REPO}:/utcp:ro", IMAGE,
               "nice", "-n", "10", "python3", "-I", "/utcp/tools/m2/analyze.py", *args], timeout=timeout)


def wait_for(c, script, what, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            # A docker exec that hangs (seen once on a busy host) must not
            # stall the run: each check gets 20 s.
            if subprocess.run(["docker", "exec", c, "bash", "-c", script], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=20).returncode == 0:
                return
        except subprocess.TimeoutExpired:
            log(f"docker exec in {c} took more than 20 s ({what})")
        time.sleep(0.05)
    raise RuntimeError(f"timeout waiting for {what} in {c}")


def one_run(slot, campaign, run, spec, smeta=None, sender_barrier=None):
    """One run (§5.6): fresh shaping, pre record, captures, tbf sampler,
    receiver, pings (3 s idle first), sender, post record, analysis.
    spec: bw, rtt, queue_bdp, loss, seed, impl, cc, duration, profile,
    extra_capture (also r1-out), plus anything copied into meta.json."""
    smeta = smeta or static_meta()
    base = f"/data/m2/{campaign}"
    rd = f"{base}/{run}"
    S = float(spec["duration"])
    slot.cleanup()
    prepare_trial(slot, campaign, run)
    dexec(slot.snd, f"mkdir -p {rd}/pre {rd}/post")
    shape = tb("shape.sh", "--slot", slot.n, "--bw", spec["bw"], "--rtt", spec["rtt"],
               "--queue-bdp", spec["queue_bdp"], *(["--loss", spec["loss"]] if spec.get("loss") else []),
               *(["--seed", spec["seed"]] if spec.get("seed") is not None else []))
    sl = [l for l in shape.splitlines() if l.startswith("shape: slot")][0].split()
    shp = dict(zip(sl[3::2], sl[4::2]))
    for c in (slot.snd, slot.rcv):
        dexec(c, "ip tcp_metrics flush")
    meta = dict(spec)
    meta.setdefault("timing", slot.timing)
    meta.update(smeta)
    meta.update({
        "campaign": campaign, "run": run, "slot": slot.n, "duration_s": S,
        "start_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "containers": slot.containers(), "cpusets": slot.cpus, "slot_cpus": slot.slot_cpus(),
        "ifaces": slot.ifs, "rcv_ip": slot.rcv_ip, "snd_ip": slot.snd_ip,
        "queue_bytes": int(shp["queue_bytes"]), "burst_bytes": int(shp["burst_bytes"]),
        "bdp_bytes": int(shp["bdp_bytes"]),
        "bw_mbit": float(spec["bw"]), "rtt_ms": float(spec["rtt"]), "loss_pct": float(spec.get("loss") or 0),
        "netem": [l for l in shape.splitlines() if " netem " in l and l.startswith("shape:")][0].split(" root ")[1],
        "tbf": [l for l in shape.splitlines() if " tbf " in l and l.startswith("shape:")][0].split(" root ")[1],
        "iproute2": sh(["docker", "exec", slot.r1, "tc", "-V"]).strip(),
    })
    impl = spec.get("impl", "linux")
    if impl == "utcp":
        gso = slot.gso_ipv4_max_size()
        meta["gso_ipv4_max_size"] = gso
        meta["stack_set"] = stack_sets(gso) + list(spec.get("stack_set", []))
        meta["trace"] = bool(spec.get("trace", True))
    vol_write(slot.snd, f"{rd}/meta.json", json.dumps(meta, indent=1, sort_keys=True) + "\n")
    vol_write(slot.snd, f"{rd}/shape.txt", shape)
    pre = tb("record.sh", "--slot", slot.n, "pre")
    vol_write(slot.snd, f"{rd}/pre/record.txt", pre)
    # §5.13 and §6: the host's load at the start (the full lists are in
    # pre/record.txt).
    rec = A.parse_record(pre)
    meta["uptime"] = " ".join(rec.get(("host", "uptime"), [])).strip()
    meta["top_cpu"] = rec.get(("host", "top"), [])[1:8]
    meta["threads_on_8_15"] = rec.get(("host", "threads on 8-15"))
    meta["module_parameters"] = rec.get(("host", "module parameters"), [])
    vol_write(slot.snd, f"{rd}/meta.json", json.dumps(meta, indent=1, sort_keys=True) + "\n")

    caps = [("r1-in", slot.r1, slot.ifs["r1_a"]), ("r2-out", slot.r2, slot.ifs["r2_c"])]
    if spec.get("extra_capture"):
        caps.append(("r1-out", slot.r1, slot.ifs["r1_b"]))
    # Ethernet multicast is left out: the host sends SSDP from every bridge's
    # gateway address, which is not the run's traffic and, arriving in the last
    # ring block, made captures look incomplete.
    for name, c, dev in caps:
        dexec_bg(c, f"exec tcpdump -i {dev} -s 128 -B 16384 -n --time-stamp-precision nano "
                    f"-w {rd}/{name}.pcap 'not ether multicast' 2> {rd}/{name}.tcpdump.txt")
    for name, c, dev in caps:
        wait_for(c, f"grep -q 'listening on' {rd}/{name}.tcpdump.txt", f"tcpdump {name}")
    dexec_bg(slot.r2, f"echo $$ > /run/utcp-tbf-sampler.pid; exec > {rd}/tbf.txt;"
                      f" while :; do printf '@ %s\\n' \"$EPOCHREALTIME\";"
                      f" tc -s qdisc show dev {slot.ifs['r2_c']}; sleep 0.01; done")
    # Scripted drops (§4.2): drop.sh argument lists, armed before the connection.
    for args in spec.get("drops", []):
        log(tb("drop.sh", "--slot", slot.n, *args).strip())
    dexec_bg(slot.rcv, f"exec {BULK} --backend kernel --listen {PORT} --recv --sample-ms 10 "
                       f"--jsonl {rd}/rcv.jsonl > {rd}/rcv.out 2>&1")
    wait_for(slot.rcv, f"ss -Hltn sport = :{PORT} | grep -q LISTEN", "receiver listening")
    dexec_bg(slot.snd, f"exec ping -D -O -i 0.05 -s 56 {slot.rcv_ip} > {rd}/ping.txt 2>&1")
    time.sleep(3.0)

    cc = spec.get("cc", "cubic")
    amount = f"--bytes {spec['bytes']}" if spec.get("bytes") else f"--duration {S:g}"
    if impl == "linux":
        snd_cmd = (f"{BULK} --backend kernel --connect {slot.rcv_ip}:{PORT} --send {amount} "
                   f"--cc {cc} --sample-ms 10 --jsonl {rd}/snd.jsonl")
    else:
        sets = " ".join(f"--set {shlex.quote(x)}" for x in meta["stack_set"])
        trace = f"--trace {rd}/trace.jsonl" if meta["trace"] else ""
        snd_cmd = (f"{BULK} --backend utcp --tun utcp0 --addr {slot.stack_ip} "
                   f"--profile {spec.get('profile', 'linux')} --connect {slot.rcv_ip}:{PORT} --send "
                   f"{amount} --cc {cc} --sample-ms 10 --jsonl {rd}/snd.jsonl "
                   f"--stats {rd}/stats.json {sets} {trace} {spec.get('stack_args', '')}")
    if sender_barrier is not None:
        sender_barrier.wait(timeout=180)
    rc = subprocess.run(["docker", "exec", slot.snd, "bash", "-c", f"{snd_cmd} > {rd}/snd.out 2>&1"],
                        timeout=S + 120).returncode
    try:
        wait_for(slot.rcv, "! ps -eo stat=,comm= | awk '$2 == \"utcp-bulk\" && $1 !~ /^Z/' | grep -q .",
                 "receiver exit", timeout=60)
    except RuntimeError:
        dexec(slot.rcv, "pkill -x utcp-bulk", check=False)
    # The close (FIN, its retransmissions after a loss) can outlast the
    # processes; captures stop only after both ends left every state but
    # TIME-WAIT (the stack's end is not in snd's socket table).
    for c in (slot.snd, slot.rcv):
        try:
            wait_for(c, f"! ss -Htn state connected exclude time-wait '( dport = :{PORT} or sport = :{PORT} )'"
                        " | grep -q .", "connection closed", timeout=30)
        except RuntimeError as e:
            log(f"{run}: {e}")
    time.sleep(0.5)
    dexec(slot.snd, "pkill -INT -x ping", check=False)
    dexec(slot.r2, "kill $(cat /run/utcp-tbf-sampler.pid)", check=False)
    # tcpdump reads the kernel's ring in blocks retired after at most 1 s
    # (its 1000 ms timeout); packets of an unretired block are lost on SIGINT.
    time.sleep(1.5)
    for c in {slot.r1, slot.r2}:
        dexec(c, "pkill -INT -x tcpdump", check=False)
    for name, c, dev in caps:
        wait_for(c, "! ps -eo stat=,comm= | awk '$2 == \"tcpdump\" && $1 !~ /^Z/' | grep -q .",
                 "tcpdump exit", timeout=30)
    for args in spec.get("drops", []):
        router = args[args.index("--router") + 1] if "--router" in args else "r1"
        vol_write(slot.snd, f"{rd}/drop-{router}.txt", tb("drop.sh", "--slot", slot.n, "show", "--router", router))
        tb("drop.sh", "--slot", slot.n, "clear", "--router", router)
    post = tb("record.sh", "--slot", slot.n, "post")
    vol_write(slot.snd, f"{rd}/post/record.txt", post)
    meta["sender_exit"] = rc
    meta["reuse_key"] = reuse_key(meta, sysctl_dump(post))
    vol_write(slot.snd, f"{rd}/meta.json", json.dumps(meta, indent=1, sort_keys=True) + "\n")
    run_analysis(["captures", rd])
    summ = json.loads(run_analysis(["run", rd]).strip().splitlines()[-1])
    log(f"{run}: captures " + ", ".join(
        f"{k} {v.get('bytes')} B, {v.get('captured')} packets, {v.get('kernel_dropped')} dropped by kernel"
        for k, v in sorted((summ.get("capture") or {}).items()) if isinstance(v, dict)))
    return meta, summ


def capture_start(c, dev, path, filt):
    """tcpdump in container c (DESIGN §14.2 options), log next to the file."""
    dexec_bg(c, f"exec tcpdump -i {dev} -s 128 -B 16384 -n --time-stamp-precision nano "
                f"-w {path} {shlex.quote(filt)} 2> {path}.tcpdump.txt")
    wait_for(c, f"grep -q 'listening on' {path}.tcpdump.txt", f"tcpdump {path}")


def capture_stop(c):
    """Stops c's tcpdump after its 1 s ring-block timeout (DESIGN §14.2)."""
    time.sleep(1.5)
    dexec(c, "pkill -INT -x tcpdump", check=False)
    wait_for(c, "! ps -eo stat=,comm= | awk '$2 == \"tcpdump\" && $1 !~ /^Z/' | grep -q .", "tcpdump exit",
             timeout=30)


def ping_only(slot, campaign, run, spec, src="snd", target=None, count=200, sender_barrier=None, prepared=False):
    """Gate item 1 (and 6's ping): `count` pings at 50 ms with no load. The
    RTTs come from a capture next to the pinging end, where each request
    enters the path and its reply leaves it (ns timestamps): r1's sender side
    for pings from the sender, r2's receiver side for pings from the receiver
    (netem sits between the two, on r1's b side, so the capture must have it
    between request and reply). iputils prints RTTs of 100 ms and more as
    whole milliseconds. The statistics of ping's own output are kept as
    "text"."""
    base = f"/data/m2/{campaign}"
    rd = f"{base}/{run}"
    if not prepared:
        prepare_trial(slot, campaign, run)
    if spec:
        tb("shape.sh", "--slot", slot.n, "--bw", spec["bw"], "--rtt", spec["rtt"], "--queue-bdp", spec["queue_bdp"])
    c = slot.snd if src == "snd" else slot.rcv
    src_ip = slot.snd_ip if src == "snd" else slot.rcv_ip
    target = target or slot.rcv_ip
    router, dev, where = ((slot.r1, slot.ifs["r1_a"], "r1, sender side") if src == "snd"
                          else (slot.r2, slot.ifs["r2_c"], "r2, receiver side"))
    capture_start(router, dev, f"{rd}/ping.pcap", "icmp")
    try:
        if sender_barrier is not None:
            sender_barrier.wait(timeout=180)
        # tcpdump timestamps are realtime on this host. Relate the actual
        # observed request interval to the transfers' CLOCK_MONOTONIC epoch.
        offset = time.monotonic_ns() - time.time_ns()
        out = dexec(c, f"ping -D -i 0.05 -s 56 -c {count} {target} | tee {rd}/ping.txt")
    finally:
        capture_stop(router)
    st = json.loads(run_analysis(["pings", f"{rd}/ping.pcap", src_ip, target, str(count)]).strip().splitlines()[-1])
    if "first_request_rt_ns" in st and "last_request_rt_ns" in st:
        st["ping_start_ns"] = st["first_request_rt_ns"] + offset
        st["ping_end_ns"] = st["last_request_rt_ns"] + offset
    st["source"] = f"capture {where}"
    st["text"] = A.ping_stats(A.parse_ping(out), count)
    return st


# --------------------------------------------------------------------------
# Calibration gate (§5.4, DESIGN §14.4): the pass decisions are the pure
# functions gate_item1 .. gate_item6_run, unit-tested at their bounds.


def ping_sample(p, minimum):
    n, lost = p.get("n"), p.get("lost")
    return (p.get("requests_seen") == 200 and type(n) is int and type(lost) is int
            and minimum <= n <= 200 and n + lost == 200
            and finite(p.get("median_ms")) and finite(p.get("p99_ms")) and 0 < p["median_ms"] <= p["p99_ms"])


def gate_item1(p, rtt):
    """Idle ping: at least 190 of 200 replies, median in [RTT, RTT + 1 ms], p99 <= RTT + 2 ms."""
    return ping_sample(p, 190) and rtt <= p["median_ms"] <= rtt + 1 and p["p99_ms"] <= rtt + 2


def gate_item2(goodput_bps, bw, queue_bdp):
    """At 0.5xBDP the measured goodput is reported without a rate threshold."""
    thr = RATE_FRACTION * bw * 1e6
    gated = float(queue_bdp) == 2.0
    measured = finite(goodput_bps) and goodput_bps >= 0
    return {"ok": measured and (not gated or goodput_bps >= thr), "gated": gated,
            "goodput_bps": goodput_bps, "threshold_bps": thr,
            "fraction_of_bw": goodput_bps / (bw * 1e6) if measured else None}


def loss_alpha(n_tests):
    """Item 3's level: 99 % Bonferroni-corrected over the gate's loss tests."""
    return 0.01 / max(1, n_tests)


def capture_complete(c):
    """A capture with tcpdump's counts, nothing dropped by the kernel and every
    packet the filter received written."""
    return isinstance(c, dict) and c.get("kernel_dropped") == 0 and type(c.get("captured")) is int and c["captured"] > 0 \
        and c.get("received_by_filter") == c.get("captured")


def gate_item3(cap, tbf_dropped, loss_pct, alpha, ack_path, local_drops):
    """Loss: data segments lost on the netem hop (r1-in minus r1-out, both
    captures complete) inside the binomial interval of the offered count at
    level alpha; no ACK-path qdisc drops and no local drops."""
    n_in = (cap.get("r1-in") or {}).get("data_segs")
    n_out1 = (cap.get("r1-out") or {}).get("data_segs")
    n_out2 = (cap.get("r2-out") or {}).get("data_segs")
    if not all(type(n) is int and n >= 0 for n in (n_in, n_out1, n_out2, tbf_dropped)) or not n_in:
        return {"ok": False, "error": "missing captures or tbf counters"}
    complete = {n: capture_complete(cap.get(n)) for n in ("r1-in", "r1-out")}
    lost = n_in - n_out1
    lo, hi = A.binom_interval(n_in, loss_pct / 100, alpha)
    ack_ok = ack_path_clear(ack_path)
    return {"ok": bool(lo <= lost <= hi and ack_ok and local_drops == {} and all(complete.values())),
            "offered": n_in, "lost": lost, "measured_pct": 100 * lost / n_in, "interval": [lo, hi],
            "alpha": alpha, "captures_complete": complete, "lost_by_design_formula": n_in - n_out2 - tbf_dropped,
            "ack_path_ok": ack_ok}


def ping_target_ms(q_bytes, bw):
    """The largest backlog a ping (98-byte frame) can find is the whole
    1514-byte frames that fit with it, plus its own transmission; §5.4 says
    Q*8/BW, 3 % above what is attainable for Q = 12 500 B (DESIGN §14.4)."""
    return ((q_bytes - 98) // A.FRAME * A.FRAME + 98) * 8 / (bw * 1e6) * 1e3


def gate_item4(qc, q_bytes, bw, ping_max_ms, ping_base_ms):
    """Queue: the sampled backlog reaches [0.9, 1]·Q, no testable drop interval
    below the tail-drop bound (queue_check; intervals the 10 ms sampler
    cannot test are reported, not passed as tested), and ping max - base
    within 10 % of ping_target_ms."""
    qc = qc or {}
    target = ping_target_ms(q_bytes, bw) if finite(q_bytes) and q_bytes > 0 else None
    dmax = ping_max_ms - ping_base_ms if finite(ping_max_ms) and finite(ping_base_ms) else None
    backlog = qc.get("backlog_max")
    ok = (target is not None and finite(backlog) and 0.9 * q_bytes <= backlog <= q_bytes
          and qc.get("reaches") is True and qc.get("drop_intervals_low") == 0
          and dmax is not None and abs(dmax - target) <= 0.1 * target)
    return {"ok": ok, "queue_bytes": q_bytes, "backlog_max": qc.get("backlog_max"),
            "backlog_frac": backlog / q_bytes if target is not None and finite(backlog) else None, "drop_intervals": qc.get("drop_intervals"),
            "drop_intervals_low": qc.get("drop_intervals_low"),
            "drop_intervals_untestable": qc.get("drop_intervals_untestable"), "drop_check": qc.get("drop_check"),
            "drop_intervals_below_frac": qc.get("drop_intervals_below_frac"), "min_level": qc.get("min_level"),
            "ping_max_minus_base_ms": dmax, "target_ms": target}


def ack_path_clear(ack):
    return isinstance(ack, dict) and all(isinstance(ack.get(k), dict) and ack[k].get("dropped") == 0
                                         for k in ("r1_a", "r2_b"))


def gate_item5(s, loss=False):
    """No local drops (§5.2), no time_squeeze, no capture drop by the kernel,
    in a run of items 2-3 (RESULTS.md "Calibration" item 5)."""
    caps = {k: v for k, v in (s.get("capture") or {}).items() if isinstance(v, dict)}
    required = {"r1-in", "r2-out"} | ({"r1-out"} if loss else set())
    cap_ok = required <= caps.keys() and all(v.get("kernel_dropped") == 0 for v in caps.values())
    ok = (s.get("local_drops") == {} and s.get("time_squeeze") == 0
          and ack_path_clear(s.get("ack_path")) and cap_ok)
    return {"ok": bool(ok), "local_drops": s.get("local_drops"), "time_squeeze": s.get("time_squeeze"),
            "captures": {k: v.get("kernel_dropped") for k, v in caps.items()}}


def gate_item6_ping(p_stack, p_kernel):
    """Stack path: the idle ping median to the stack within 0.2 ms of the kernel's."""
    a, b = p_stack.get("median_ms"), p_kernel.get("median_ms")
    d = a - b if finite(a) and finite(b) else None
    return {"ok": ping_sample(p_stack, 1) and ping_sample(p_kernel, 1) and abs(d) <= 0.2, "diff_ms": d}


def gate_item6_run(s):
    """Stack path: one stack NewReno run at 100 Mbit/s, 20 ms, 0 %, 2xBDP at
    item 2's threshold, valid, no local drops, no device errors."""
    thr = RATE_FRACTION * 100e6
    g = s.get("goodput_bps")
    return {"ok": bool(finite(g) and g >= thr and s.get("local_drops") == {} and s.get("stack_device") == {}
                       and s.get("stack_local_drops") == {} and s.get("valid") is True),
            "goodput_bps": g, "threshold_bps": thr}


def calibration_transfer(slot, campaign, run, spec, smeta, expected_key, sources):
    meta, summary = one_run(slot, campaign, run, spec, smeta)
    for leaf, data in (("meta", meta), ("summary", summary)):
        sources[f"{run}/{leaf}.json"] = A.proof_meta_digest(data)
    expected = dict(spec, campaign=campaign, run=run, slot=slot.n, reuse_key=expected_key,
                    timing=True, cpusets=slot.cpus, duration_s=spec["duration"], sender_exit=0)
    errors = [f"wrong {k}" for k, v in expected.items()
              if meta.get(k) != v or isinstance(v, bool) != isinstance(meta.get(k), bool)]
    if (not timing_placement(slot.n, meta.get("cpusets")) or
            meta.get("slot_cpus") not in timing_cpu_names(slot.n)):
        errors.append("wrong timing placement")
    if summary.get("run") != run or summary.get("proof_meta_sha256") != A.proof_meta_digest(meta):
        errors.append("summary does not match run metadata")
    if measured_transfer_window(summary, spec["duration"]) is None:
        errors.append("missing or inconsistent endpoint measurement window")
    if summary.get("sender_ccs") != [spec["cc"]]:
        errors.append(f"sender reported {summary.get('sender_ccs')}, expected {spec['cc']}")
    if summary.get("valid") is not True or summary.get("invalid") != []:
        errors.append(f"invalid transfer: {summary.get('invalid')}")
    return meta, summary, errors


def calibrate(slot, campaign, pairs, skip_stack=False, seed=1):
    smeta = static_meta()
    directory = shlex.quote(f"/data/m2/{campaign}")
    if dexec(slot.snd, f"test ! -d {directory} || ls -A {directory}").strip():
        raise RuntimeError("calibration directory contains evidence; use a new campaign for the whole gate")
    rng = random.Random(seed)
    results = {"campaign": campaign, "slot": slot.n, "cpusets": slot.cpus, "seed": seed,
               "static": smeta, "items": [], "sources": {}, "schema": 2}
    loss_tests = [(bw, rtt, q, p) for bw, rtt in pairs for q in QUEUES for p in LOSSES]
    alpha = loss_alpha(len(loss_tests))
    expected_key = current_key(slot, smeta)
    keys = set()

    def add(item, ok, **kw):
        kw.update(item=item, ok=ok and not kw.get("source_errors"), slot=slot.n)
        kw.setdefault("reuse_key", expected_key)
        results["items"].append(kw)
        log(f"item {item}: {'pass' if kw['ok'] else 'FAIL'} {json.dumps(kw, sort_keys=True)}")

    def observe_ping(run, spec, **kwargs):
        data = ping_only(slot, campaign, run, spec, **kwargs)
        data.update(campaign=campaign, run=run, slot=slot.n, reuse_key=expected_key, cpusets=slot.cpus)
        path = f"{run}/ping.json"
        vol_write(slot.snd, f"/data/m2/{campaign}/{path}", json.dumps(data, sort_keys=True))
        results["sources"][path] = A.proof_meta_digest(data)
        return data

    def transfer(run, spec):
        return calibration_transfer(slot, campaign, run, spec, smeta, expected_key, results["sources"])

    for bw, rtt in pairs:
        dur = 30 if rtt == 20 else 60
        for q in QUEUES:
            spec = {"bw": bw, "rtt": rtt, "queue_bdp": q}
            p = observe_ping(f"ping-{bw}-{rtt}-{q:g}", spec)
            add(1, gate_item1(p, rtt), **spec, **p)
            run = f"rate-{bw}-{rtt}-{q:g}"
            rate_spec = dict(spec, loss=0, seed=rng.randrange(1, 2**31), impl="linux", cc="cubic",
                             duration=dur, cell=f"{bw}-{rtt}-0-{q:g}", rep=0, order=0, gate="rate")
            meta, s, errors = transfer(run, rate_spec)
            keys.add(meta.get("reuse_key"))
            source = dict(bw=bw, rtt=rtt, queue_bdp=q, run=run, reuse_key=meta.get("reuse_key"), source_errors=errors)
            r2 = gate_item2(s.get("goodput_bps"), bw, q)
            add(2, r2.pop("ok"), **source, **r2)
            r4 = gate_item4(s.get("queue"), meta.get("queue_bytes"), bw, s.get("ping_max_ms"), s.get("ping_base_ms"))
            add(4, r4.pop("ok"), **source, ping_source=s.get("ping_source"), **r4)
            r5 = gate_item5(s)
            add(5, r5.pop("ok"), **source, **r5)
            for p_loss in LOSSES:
                run = f"loss-{bw}-{rtt}-{q:g}-{p_loss:g}"
                loss_spec = dict(rate_spec, loss=p_loss, seed=rng.randrange(1, 2**31),
                                 cell=f"{bw}-{rtt}-{p_loss:g}-{q:g}", gate="loss", extra_capture=True)
                meta, s, errors = transfer(run, loss_spec)
                keys.add(meta.get("reuse_key"))
                # Lost in netem = data segments into r1 minus those leaving r1's
                # b side (r1-out is captured after the netem qdisc). §5.4's
                # r1-in - r2-out - tbf drops is reported too; it counts tbf drops
                # of ping packets as data (DESIGN §14.4).
                r3 = gate_item3(s.get("capture") or {}, (s.get("tbf") or {}).get("dropped"), p_loss, alpha,
                                s.get("ack_path"), s.get("local_drops"))
                loss_source = dict(source, run=run, loss_pct=p_loss, reuse_key=meta.get("reuse_key"), source_errors=errors)
                add(3, r3.pop("ok"), **loss_source,
                    netem_dropped_counter=(s.get("netem") or {}).get("dropped"),
                    tbf_dropped=(s.get("tbf") or {}).get("dropped"), ack_path=s.get("ack_path"),
                    local_drops=s.get("local_drops"), **r3)
                r5 = gate_item5(s, loss=True)
                add(5, r5.pop("ok"), **loss_source, **r5)
    if not skip_stack:
        keys |= stack_item(slot, campaign, rng, add, observe_ping, transfer)
    results["passed"] = all(i["ok"] for i in results["items"])
    results["passed_linux_items_1_5"] = (sorted(pairs) == sorted(PAIRS)
                                           and all(i["ok"] for i in results["items"] if i["item"] <= 5))
    # The runs' reuse key (§5.13); `run` accepts this gate only for runs with
    # the same key.
    results["reuse_keys"] = sorted(keys, key=str)
    results["reject_reason"] = gate_rejects(results, slot.n, expected_key)
    results["passed"] = results["reject_reason"] is None
    text = json.dumps(results, indent=1, sort_keys=True) + "\n"
    vol_write(slot.snd, f"/data/m2/{campaign}/gate.json", text)
    vol_write(slot.snd, f"/data/m2/{campaign}/gate.md", gate_markdown(results))
    log(f"gate {'PASSED' if results['passed'] else 'FAILED'}; /data/m2/{campaign}/gate.json")
    return results


def stack_item(slot, campaign, rng, add, observe_ping, transfer):
    """Gate item 6: ping the stack from the receiver (stack idle, listening)
    against item 1's median; one stack NewReno run at 100 Mbit/s, 20 ms, 0 %,
    2xBDP against item 2's threshold, no utcp* or DeviceStats drops. Returns
    the runs' reuse keys."""
    rd = f"/data/m2/{campaign}/stack-ping"
    spec = {"bw": 100, "rtt": 20, "queue_bdp": 2}
    tb("shape.sh", "--slot", slot.n, "--bw", 100, "--rtt", 20, "--queue-bdp", 2)
    prepare_trial(slot, campaign, "stack-ping")
    dexec_bg(slot.snd, f"exec {BULK} --backend utcp --tun utcp0 --addr {slot.stack_ip} --listen {PORT} "
                       f"--recv --sample-ms 0 > {rd}/stack.out 2>&1")
    time.sleep(1.0)
    try:
        p_stack = observe_ping("stack-ping", None, src="rcv", target=slot.stack_ip, prepared=True)
    finally:
        dexec(slot.snd, "pkill -x utcp-bulk", check=False)
    p_kernel = observe_ping("stack-ping-kernel", spec)
    r = gate_item6_ping(p_stack, p_kernel)
    add(6, r["ok"], part="ping", stack=p_stack, kernel=p_kernel, diff_ms=r["diff_ms"])
    keys = set()
    # "run": §5.4's run. "path": the same with the stack's send buffer at
    # 400 000 B (1.6 x BDP, below BDP + queue = 750 000 B), so the window never
    # overflows the queue and the result shows what the TUN path carries
    # without loss recovery in play.
    for part, extra in (("run", ""), ("path", "--snd-buf 400000")):
        run = f"stack-100-20-2-{part}"
        run_spec = dict(spec, loss=0, seed=rng.randrange(1, 2**31), impl="utcp", profile="linux", cc="newreno",
                        duration=30, cell="100-20-0-2", rep=0, order=0, gate="stack", stack_args=extra)
        meta, s, errors = transfer(run, run_spec)
        keys.add(meta.get("reuse_key"))
        r = gate_item6_run(s)
        add(6, r["ok"], part=part, run=run, reuse_key=meta.get("reuse_key"), source_errors=errors, stack_args=extra,
            goodput_bps=r["goodput_bps"], threshold_bps=r["threshold_bps"], local_drops=s.get("local_drops"), stack_device=s.get("stack_device"),
            invalid=s.get("invalid"), flags=s.get("flags"), retrans_pct=s.get("retrans_pct"),
            tbf_dropped=(s.get("tbf") or {}).get("dropped"), sndbuf_limited_frac=s.get("sndbuf_limited_frac"),
            rwnd_limited_frac=s.get("rwnd_limited_frac"), lateness_p99_ns=s.get("sender_lateness_p99_ns"),
            lateness_max_ns=s.get("sender_lateness_max_ns"))
    return keys


def gate_markdown(r):
    lines = [f"Calibration gate, campaign {r['campaign']}, slot {r['slot']}, cpusets "
             + ", ".join(f"{k.rsplit('-', 1)[-1]} {v}" for k, v in r["cpusets"].items())
             + f", kernel {r['static']['uname_r']}, commit {r['static']['commit']}: "
             + ("PASSED" if r["passed"] else "FAILED")
             + f" (items 1-5, Linux to Linux: {'passed' if r.get('passed_linux_items_1_5') else 'FAILED'})", ""]
    if r.get("reject_reason"):
        lines += [r["reject_reason"], ""]
    lines += ["| Item | Cell | Result | Pass |", "|---|---|---|---|"]
    for i in r["items"]:
        it = i["item"]
        cell = f"{i.get('bw', 100)} Mbit/s, {i.get('rtt', 20)} ms" + (
            f", {i['queue_bdp']:g}xBDP" if "queue_bdp" in i else "") + (
            f", {i['loss_pct']:g} %" if "loss_pct" in i else "")
        if it == 1:
            res = f"median {_f(i.get('median_ms'), nd=3)} ms, p99 {_f(i.get('p99_ms'), nd=3)} ms, n {i.get('n')}"
        elif it == 2:
            res = (f"goodput {_f(i['goodput_bps'], 1e6, 3)} Mbit/s = {_f(i['fraction_of_bw'], 0.01)} % of BW"
                   f" (threshold {i['threshold_bps'] / 1e6:.3f}){'' if i['gated'] else ', not gated'}")
        elif it == 3:
            if "error" in i:
                res = i["error"]
            else:
                res = (f"lost {i['lost']} of {i['offered']} = {i['measured_pct']:.4f} %, interval "
                       f"[{i['interval'][0]}, {i['interval'][1]}]; r1-in - r2-out - tbf drops {i['lost_by_design_formula']}, "
                       f"netem counter {i['netem_dropped_counter']}, tbf drops {i['tbf_dropped']}; captures complete "
                       f"{i.get('captures_complete')}")
        elif it == 4:
            res = (f"backlog max {i['backlog_max']} B = {_f(i['backlog_frac'], 0.01, 1)} % of Q {i['queue_bytes']};"
                   f" drop intervals {i['drop_intervals']}, below the tail-drop bound"
                   f" (lowest {i['min_level'] if not finite(i['min_level']) else round(i['min_level'])} B):"
                   f" {i['drop_intervals_low']} (below 0.9Q: {i['drop_intervals_below_frac']};"
                   f" {i.get('drop_check', 'tested')}, {i.get('drop_intervals_untestable', 0)} not testable);"
                   f" ping max - base {i['ping_max_minus_base_ms'] if i['ping_max_minus_base_ms'] is None else round(i['ping_max_minus_base_ms'], 2)}"
                   f" ms vs {_f(i['target_ms'])} ms")
        elif it == 5:
            res = f"local drops {i['local_drops'] or 'none'}, time_squeeze {i['time_squeeze']}, capture drops {i['captures']}"
        else:
            if i.get("part") == "ping":
                res = (f"stack ping median {i['stack'].get('median_ms')} ms vs kernel {i['kernel'].get('median_ms')}"
                       f" ms, diff {i['diff_ms'] if i['diff_ms'] is None else round(i['diff_ms'], 3)} ms")
                cell = "100 Mbit/s, 20 ms (idle)"
            else:
                cell = f"100 Mbit/s, 20 ms, 2xBDP, stack {i['part']}" + (f" ({i['stack_args']})" if i["stack_args"] else "")
                res = (f"stack NewReno goodput {_f(i['goodput_bps'], 1e6, 3)} Mbit/s (threshold "
                       f"{i['threshold_bps'] / 1e6:.3f}); drops {i['local_drops'] or 'none'}, device "
                       f"{i['stack_device'] or 'none'}; lateness p99 {i['lateness_p99_ns']} ns max "
                       f"{i['lateness_max_ns']} ns; retransmitted {i['retrans_pct']} %, tbf drops "
                       f"{i['tbf_dropped']}; sndbuf-limited {i['sndbuf_limited_frac']}, rwnd-limited "
                       f"{i['rwnd_limited_frac']}")
        if i.get("source_errors"):
            res += "; " + ", ".join(i["source_errors"])
        lines.append(f"| {it} | {cell} | {res} | {'yes' if i['ok'] else 'NO'} |")
    return "\n".join(lines) + "\n"


def gate_table(gates):
    """The compact calibration table of RESULTS.md "Calibration": one row per
    slot and (bandwidth, RTT, queue) with items 1-5, then item 6 per slot."""
    out = ["| Slot | BW, RTT, queue | 1: ping median / p99 (ms) | 2: goodput, % of BW | "
           "4: backlog max, % of Q; ping max - base / target (ms) | 3: loss % at 0.1 / 1 (lost segments in the accepted interval) "
           "| 5: drops, squeeze | Pass |", "|---|---|---|---|---|---|---|---|"]
    for g in gates:
        cells = {}
        for i in g["items"]:
            if i["item"] in (1, 2, 3, 4, 5):
                cells.setdefault((i["bw"], i["rtt"], i["queue_bdp"]), []).append(i)
        for (bw, rtt, q), items in cells.items():
            by = {}
            for i in items:
                by.setdefault(i["item"], []).append(i)
            i1, i2, i4 = by[1][0], by[2][0], by[4][0]
            l3 = " / ".join(f"{i['measured_pct']:.3f} ({i['lost']} in [{i['interval'][0]}, {i['interval'][1]}])"
                            if "measured_pct" in i else i.get("error", "?")
                            for i in sorted(by.get(3, []), key=lambda i: i["loss_pct"]))
            bad5 = [i for i in by.get(5, []) if not i["ok"]]
            ok = all(i["ok"] for i in items)
            dmax = i4["ping_max_minus_base_ms"]
            out.append(
                f"| {g['slot']} | {bw} Mbit/s, {rtt} ms, {q:g}xBDP | {_f(i1.get('median_ms'))} / {_f(i1.get('p99_ms'))} "
                f"| {_f(i2['fraction_of_bw'], 0.01)}{'' if i2['gated'] else ' (not gated)'} "
                f"| {_f(i4['backlog_frac'], 0.01, 1)}; {'-' if dmax is None else f'{dmax:.1f}'} / {_f(i4['target_ms'], nd=1)} "
                f"| {l3} | {len(bad5)} of {len(by.get(5, []))} runs "
                f"| {'yes' if ok else 'NO'} |")
    out += ["", "| Slot | Item 6 part | Result | Pass |", "|---|---|---|---|"]
    for g in gates:
        for i in g["items"]:
            if i["item"] != 6:
                continue
            if i.get("part") == "ping":
                res = (f"idle ping median rcv to stack {i['stack'].get('median_ms')} ms, snd kernel to rcv "
                       f"{i['kernel'].get('median_ms')} ms")
            else:
                res = (f"stack NewReno 100 Mbit/s, 20 ms, 0 %, 2xBDP{', ' + i['stack_args'] if i['stack_args'] else ''}: "
                       f"{_f(i['goodput_bps'], 1e6)} Mbit/s (threshold {i['threshold_bps'] / 1e6:.2f}); "
                       f"retransmitted {_f(i['retrans_pct'])} %; rwnd-limited {_f(i['rwnd_limited_frac'], 0.01, 1)} %, "
                       f"sndbuf-limited {_f(i['sndbuf_limited_frac'], 0.01, 1)} %; loop lateness p99 bucket "
                       f"<= {i['lateness_p99_ns']} ns; drops {i['local_drops'] or 'none'}")
            out.append(f"| {g['slot']} | {i.get('part')} | {res} | {'yes' if i['ok'] else 'NO'} |")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Plans (§5.6, §5.13): `run PLAN.toml`


def default_duration(rtt):
    return 30 if float(rtt) <= 20 else 60


def cell_name(c):
    return f"{c['bw']:g}-{c['rtt']:g}-{float(c.get('loss', 0)):g}-{float(c['queue_bdp']):g}"


_LABEL = re.compile(r"^[A-Za-z0-9_.+]+(-[A-Za-z0-9_.+]+)*$")


def algo_label(a):
    """An algorithm's label: its `name`, else cc, plus "-PROFILE" for a stack
    profile other than linux, plus "-" and 8 hex digits of the sha256 of its
    stack_set. It names the runs ("<cell>-<label>-r<rep>-<impl>") and groups
    them in cells.csv and the plots."""
    if a.get("name"):
        return str(a["name"])
    label = str(a["cc"])
    if a.get("profile", "linux") != "linux":
        label += f"-{a['profile']}"
    if a.get("stack_set"):
        label += "-" + hashlib.sha256(";".join(map(str, a["stack_set"])).encode()).hexdigest()[:8]
    return label


def load_plan(path):
    """A run plan (TOML):

        campaign = "m2d-testbed/mini"
        seed = 20261115            # the one recorded seed
        reps = 2
        trace = true               # stack runs: --trace (default true)
        duration = 30              # optional; default 30 s at RTT <= 20 ms, else 60 s
        [[cell]]                   # one table per cell
        bw = 10                    # Mbit/s
        rtt = 20                   # ms
        loss = 0                   # percent
        queue_bdp = 2
        [[algo]]                   # one table per algorithm
        cc = "newreno"
        impls = ["utcp", "linux"]  # default both: a pair
        profile = "linux"          # the stack's profile (default linux)
        stack_set = []             # extra --set FIELD=VALUE for the stack
        name = "..."               # optional label (default algo_label)

    Algorithms are told apart by their label: two with one label must not
    share an implementation (their runs would have the same names)."""
    with open(path, "rb") as f:
        plan = tomllib.load(f)
    for k in ("campaign", "seed", "reps", "cell", "algo"):
        if k not in plan:
            raise ValueError(f"plan {path}: '{k}' missing")
    for c in plan["cell"]:
        for k in ("bw", "rtt", "queue_bdp"):
            if k not in c:
                raise ValueError(f"plan {path}: cell without '{k}'")
    seen = {}
    for a in plan["algo"]:
        if "cc" not in a:
            raise ValueError(f"plan {path}: algo without 'cc'")
        impls = set(a.get("impls", ("utcp", "linux")))
        if not impls <= {"utcp", "linux"}:
            raise ValueError(f"plan {path}: impls are utcp and linux")
        label = algo_label(a)
        if not _LABEL.match(label):
            raise ValueError(f"plan {path}: algo label '{label}' (letters, digits, _ . + and single -)")
        if seen.get(label, set()) & impls:
            raise ValueError(f"plan {path}: two algos with label '{label}' and implementation "
                             f"{sorted(seen[label] & impls)}; give one a 'name'")
        seen.setdefault(label, set()).update(impls)
    return plan


def expand_plan(plan, nslots=1):
    """The run list of a plan: one group per (cell, algorithm, repetition),
    its runs back to back in one slot (a pair when the algorithm has both
    implementations). From the plan's seed, in this order: the shuffle of the
    groups, then per group (in shuffled order) the netem seed and the order
    inside the group. Repetition r runs on slot r mod nslots, so every cell
    and algorithm is spread evenly over the slots. Returns the runs in
    execution order per slot: [{run, group, slot, order, spec...}]."""
    rng = random.Random(plan["seed"])
    groups = [(ci, ai, rep) for ci in range(len(plan["cell"])) for ai in range(len(plan["algo"]))
              for rep in range(int(plan["reps"]))]
    rng.shuffle(groups)
    runs = []
    for gi, (ci, ai, rep) in enumerate(groups):
        c, a = plan["cell"][ci], plan["algo"][ai]
        impls = list(a.get("impls", ("utcp", "linux")))
        netem_seed = rng.randrange(1, 2 ** 31)
        rng.shuffle(impls)
        cell = cell_name(c)
        label = algo_label(a)
        for k, impl in enumerate(impls):
            spec = {"bw": c["bw"], "rtt": c["rtt"], "loss": float(c.get("loss", 0)),
                    "queue_bdp": float(c["queue_bdp"]), "seed": netem_seed, "impl": impl, "cc": a["cc"],
                    "algo": label, "profile": a.get("profile", "linux") if impl == "utcp" else "",
                    "duration": float(plan.get("duration", default_duration(c["rtt"]))),
                    "cell": cell, "rep": rep, "group": gi, "in_group": k, "plan_seed": plan["seed"],
                    "trace": bool(plan.get("trace", True))}
            if impl == "utcp" and a.get("stack_set"):
                spec["stack_set"] = list(a["stack_set"])
            spec["run"] = f"{cell}-{label}-r{rep}-{impl}"
            spec["slot_index"] = rep % nslots
            runs.append(spec)
    for i, r in enumerate(runs):
        r["order"] = i
    return runs


def read_volume(slot, path):
    r = subprocess.run(["docker", "exec", slot.snd, "cat", path], stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, text=True)
    return r.stdout if r.returncode == 0 else None


def parse_json_object(text):
    try:
        value = json.loads(text) if text else None
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        return None


def run_done(slot, campaign, run):
    """A run is done when its summary.json exists (analysis finished)."""
    t = read_volume(slot, f"/data/m2/{campaign}/{run}/summary.json")
    if not t:
        return None
    try:
        s = json.loads(t)
    except json.JSONDecodeError:
        return None
    return s if "valid" in s else None


def current_key(slot, smeta):
    """The reuse key (§5.13) runs on this slot get now: static_meta and the
    containers' sysctls and module parameters from a fresh record."""
    return reuse_key(smeta, sysctl_dump(tb("record.sh", "--slot", slot.n, "key")))


def campaign_keys(slot, campaign):
    """{run directory: reuse_key or None} of every run directory with a
    meta.json in the campaign, from one docker exec."""
    out = dexec(slot.snd, f"cd /data/m2/{campaign} 2>/dev/null || exit 0; for d in */; do d=${{d%/}};"
                          " [ -e \"$d/meta.json\" ] || continue;"
                          " echo \"$d $(sed -n 's/.*\"reuse_key\": \"\\([0-9a-f]*\\)\".*/\\1/p' \"$d/meta.json\")\";"
                          " done", check=False)
    keys = {}
    for line in out.splitlines():
        f = line.split()
        if f:
            keys[f[0]] = f[1] if len(f) > 1 else None
    return keys


def group_dirs(group, existing):
    """The run directories of a group that exist: its runs and their reruns."""
    out = []
    for r in group:
        for d in existing:
            if d == r["run"] or re.fullmatch(re.escape(r["run"]) + r"-rerun\d+", d):
                out.append(d)
    return out


def gate_cells():
    """Each logical item in the published calibration and its source run."""
    expected = {}
    for bw, rtt in PAIRS:
        for q in QUEUES:
            rate = f"rate-{bw}-{rtt}-{q:g}"
            for item in (1, 2, 4, 5):
                expected[item, bw, rtt, q, 0, None] = f"ping-{bw}-{rtt}-{q:g}" if item == 1 else rate
            for loss in LOSSES:
                for item in (3, 5):
                    expected[item, bw, rtt, q, loss, None] = f"loss-{bw}-{rtt}-{q:g}-{loss:g}"
    for part in ("ping", "run", "path"):
        expected[6, 100, 20, 2, 0, part] = None if part == "ping" else f"stack-100-20-2-{part}"
    return expected


def gate_rejects(gate, slot_n, key):
    """First reason a gate cannot cover runs on this slot and reuse key."""
    if not isinstance(gate, dict):
        return "no gate.json"
    if type(gate.get("slot")) is not int or gate["slot"] != slot_n:
        return f"wrong gate slot {gate.get('slot')}, expected {slot_n}"
    if not isinstance(key, str) or not key or gate.get("reuse_keys") != [key]:
        return f"gate reuse keys {gate.get('reuse_keys')} do not match {key}"
    if gate.get("schema") != 2 or not timing_placement(slot_n, gate.get("cpusets")):
        return "missing verified timing calibration sources or wrong role CPU placement"
    rows = gate.get("items")
    if not isinstance(rows, list) or not rows:
        return "missing calibration items"
    remaining = gate_cells()
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            return "malformed calibration item"
        item = row.get("item")
        # Archived item 6 identified the fixed stack cell solely by its part.
        cell = (item, row.get("bw", 100 if item == 6 else None), row.get("rtt", 20 if item == 6 else None),
                row.get("queue_bdp", 2 if item == 6 else None), row.get("loss_pct", 0), row.get("part"))
        if any(not isinstance(v, (type(None), int, float, str)) or isinstance(v, bool) for v in cell):
            return f"malformed calibration item {cell}"
        if cell in seen:
            return f"duplicate calibration item {cell}"
        if cell not in remaining:
            return f"unexpected calibration item {cell}"
        if row.get("run") != remaining.pop(cell):
            return f"wrong source run {row.get('run')} for calibration item {cell}"
        if type(row.get("slot")) is not int or row.get("slot") != slot_n or row.get("reuse_key") != key:
            return f"wrong slot or reuse key in calibration item {cell}"
        if row.get("ok") is not True or row.get("source_errors"):
            return f"failed calibration item {cell}"
        seen.add(cell)
    if remaining:
        return f"missing {len(remaining)} calibration items, first {next(iter(remaining))}"
    expected_paths = {"stack-ping/ping.json", "stack-ping-kernel/ping.json"}
    for cell, name in gate_cells().items():
        if name is not None:
            leaves = ("ping.json",) if cell[0] == 1 else ("meta.json", "summary.json")
            expected_paths.update(f"{name}/{leaf}" for leaf in leaves)
    sources = gate.get("sources")
    if not isinstance(sources, dict) or sources.keys() != expected_paths:
        return "missing calibration source inventory"
    if gate.get("passed") is not True:
        return "gate marked not passed"
    return None


def stale_groups(groups, existing, want):
    """{group: its run directories} of the groups with a run directory whose
    reuse key is set and differs from want(group). groups: {group: [runs]};
    existing: campaign_keys()."""
    out = {}
    for g, rs in groups.items():
        dirs = group_dirs(rs, existing)
        if any(existing[d] and existing[d] != want(g) for d in dirs):
            out[g] = dirs
    return out


def check_gate(slot, gates, key):
    """M2-TASKS: no matrix run before the slot's calibration gate passed with
    the final runner. A gate campaign is accepted for the slot when
    gate_rejects finds nothing. Returns the accepted campaign; raises
    otherwise."""
    why = []
    for g in gates:
        t = read_volume(slot, f"/data/m2/{g}/gate.json")
        gate = parse_json_object(t)
        reason = gate_rejects(gate, slot.n, key)
        if reason is None and (gate.get("campaign") != g or not timing_placement(slot.n, slot.cpus)):
            reason = "wrong campaign or current CPU placement"
        if reason is None:
            durations = {f"{r['run']}/summary.json": default_duration(r.get("rtt", 20))
                         for r in gate["items"] if r.get("run") and r["item"] != 1}
            for path, digest in gate["sources"].items():
                source = parse_json_object(read_volume(slot, f"/data/m2/{g}/{path}"))
                if source is None or A.proof_meta_digest(source) != digest:
                    reason = f"missing or changed calibration source {path}"
                    break
                if path in durations and measured_transfer_window(source, durations[path]) is None:
                    reason = f"missing or inconsistent endpoint measurement window in {path}"
                    break
        if reason is None:
            return g
        why.append(f"{g}: {reason}")
    raise RuntimeError(f"slot {slot.n}: no passing calibration gate with reuse key {key[:12]} "
                       f"({'; '.join(why) or 'no --gate given'}); --no-gate only outside timing campaigns")


def run_plan(plan_path, slots, rerun_invalid=True, parallel=False, nontiming=False, gates=(), no_gate=False,
             rekey=False):
    """Runs a plan, resumable (DESIGN §14.7). Refuses: more than one slot
    without `parallel` (RESULTS.md "Timing hygiene": timing runs are serial); a
    non-timing slot (CPUs outside 8-15) without `nontiming`, which marks the
    runs timing=false; a slot without a passing gate of the same reuse key
    unless `no_gate`; a campaign holding runs of this plan with another reuse
    key, unless `rekey`, which moves those groups aside and reruns them.
    Every group (the runs of one cell, algorithm and repetition) runs back to
    back; an invalid group is rerun as a whole right after it (names
    <run>-rerunK, the same netem seed and order), at most A.RERUN_CAP times
    per cell and algorithm."""
    plan = load_plan(plan_path)
    campaign = plan["campaign"]
    if len(slots) > 1 and not parallel:
        raise RuntimeError("timing runs are serial (RESULTS.md Timing hygiene): give one --slot "
                           "(--parallel only if that decision changes)")
    for s in slots:
        if not s.timing and not nontiming:
            raise RuntimeError(f"slot {s.n} is not a timing slot (CPUs {s.slot_cpus()}); --nontiming marks "
                               "the runs as not timed")
    runs = expand_plan(plan, len(slots))
    smeta = static_meta()
    keys = {s.n: current_key(s, smeta) for s in slots}
    gate_of = {}
    for s in slots:
        if no_gate:
            gate_of[s.n] = None
            log(f"slot {s.n}: --no-gate, the runs are not covered by a calibration gate")
        else:
            gate_of[s.n] = check_gate(s, gates, keys[s.n])
    expanded = json.dumps({"plan": plan, "runs": runs}, indent=1, sort_keys=True) + "\n"
    old = read_volume(slots[0], f"/data/m2/{campaign}/plan.json")
    if old is not None and json.loads(old)["runs"] != runs:
        raise RuntimeError(f"/data/m2/{campaign}/plan.json holds a different plan; use a new campaign")
    dexec(slots[0].snd, f"mkdir -p /data/m2/{campaign}")
    if old is None:
        vol_write(slots[0].snd, f"/data/m2/{campaign}/plan.json", expanded)
    groups = {}
    for r in runs:
        groups.setdefault(r["group"], []).append(r)
    # §5.13: runs done with another reuse key are not mixed with new ones.
    existing = campaign_keys(slots[0], campaign)
    stale = stale_groups(groups, existing, lambda g: keys[slots[groups[g][0]["slot_index"]].n])
    if stale:
        names = sorted(d for ds in stale.values() for d in ds)
        if not rekey:
            raise RuntimeError(f"{len(names)} run directories of {len(stale)} groups have another reuse key "
                               f"({', '.join(names[:6])}{' ...' if len(names) > 6 else ''}); --rekey moves "
                               "those groups aside and reruns them")
        stamp = int(time.time())
        dexec(slots[0].snd, f"cd /data/m2/{campaign} && mkdir -p aside && " + " && ".join(
            f"mv {shlex.quote(d)} aside/{shlex.quote(d)}-rekey-{stamp}" for d in names))
        log(f"rekey: moved {len(names)} run directories of {len(stale)} groups aside")
    log(f"plan {plan_path}: campaign {campaign}, seed {plan['seed']}, {len(runs)} runs on slots "
        + ",".join(str(s.n) for s in slots) + ", reuse key " + ",".join(sorted({k[:12] for k in keys.values()})))
    errors = []
    lock = threading.Lock()
    invalid_groups = {}

    def run_group(slot, rs, extra):
        cellalgo = (rs[0]["cell"], rs[0]["algo"])
        k = 0
        while True:
            summs = []
            for r in rs:
                name = r["run"] if k == 0 else f"{r['run']}-rerun{k}"
                s = run_done(slot, campaign, name)
                if s is not None:
                    log(f"{name}: done before, skipped")
                else:
                    spec = {kk: v for kk, v in r.items() if kk not in ("run", "slot_index")}
                    spec.update(extra, rerun=k)
                    if k:
                        spec["rerun_of"] = r["run"]
                    try:
                        log(f"slot {slot.n}: {name} (order {r['order']}, group {r['group']}, netem seed {r['seed']})")
                        _, s = one_run(slot, campaign, name, spec, smeta)
                        log(f"{name}: valid {s.get('valid')} goodput {s.get('goodput_bps')} "
                            f"{s.get('invalid')} {s.get('flags')}")
                    except Exception as e:  # noqa: BLE001 - one failed run must not stop the slot
                        with lock:
                            errors.append((name, str(e)))
                        log(f"{name}: ERROR {e}")
                        s = None
                summs.append(s)
            if all(s is not None and s.get("valid") for s in summs):
                return
            with lock:
                invalid_groups[cellalgo] = invalid_groups.get(cellalgo, 0) + 1
                again = rerun_invalid and invalid_groups[cellalgo] <= A.RERUN_CAP
            if not again:
                log(f"group {rs[0]['group']} ({cellalgo}): invalid, no rerun left")
                return
            k += 1
            log(f"group {rs[0]['group']} ({cellalgo}): invalid, rerun {k} of the whole group")

    def worker(si):
        slot = slots[si]
        extra = {"timing": slot.timing and not nontiming, "gate": gate_of[slot.n]}
        for g in sorted(groups, key=lambda g: groups[g][0]["order"]):
            if groups[g][0]["slot_index"] == si:
                run_group(slot, groups[g], extra)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(len(slots))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log(f"plan {campaign}: finished, {len(errors)} errors")
    return errors


# --------------------------------------------------------------------------
# Parallel-mode proof (§6) and the trace overhead (§5.6)

PROOF_PAIRS = ((10, 20), (10, 100), (100, 20), (100, 100))


def proof_list(reps, pairs, with_trace_off, stack_cc="newreno"):
    """Per repetition: item 1 (idle ping) and items 2 and 4 (Linux CUBIC,
    0 % loss, 2xBDP) for each pair, then the selected stack CC at 100 Mbit/s, 20 ms,
    0 %, 2xBDP with the trace, and (serial only) without it."""
    out = []
    for rep in range(reps):
        for bw, rtt in pairs:
            spec = {"bw": bw, "rtt": rtt, "queue_bdp": 2.0, "loss": 0.0, "rep": rep}
            out.append(("ping", f"ping-{bw}-{rtt}-2-r{rep}", spec))
            out.append(("run", f"rate-{bw}-{rtt}-2-r{rep}",
                        dict(spec, impl="linux", cc="cubic", duration=default_duration(rtt),
                             cell=f"{bw}-{rtt}-0-2", gate="proof-rate", order=rep)))
        stack = {"bw": 100, "rtt": 20, "queue_bdp": 2.0, "loss": 0.0, "rep": rep, "impl": "utcp",
                 "cc": stack_cc, "profile": "linux", "duration": 30, "cell": "100-20-0-2", "order": rep}
        out.append(("run", f"stack-trace-r{rep}", dict(stack, trace=True, gate="proof-stack")))
        if with_trace_off and pairs:
            out.append(("run", f"stack-notrace-r{rep}", dict(stack, trace=False, gate="proof-notrace")))
    return out


def proof_config(reps, pairs, stack_cc):
    return {"schema": 2, "scope": "full" if pairs else "cubic-only", "reps": reps,
            "pairs": [list(p) for p in pairs], "stack_cc": stack_cc}


def proof_phase(campaign, phase, slots, reps, pairs, stack_cc="newreno"):
    smeta = static_meta()
    # Both testbed slots share this Linux host and its CLOCK_MONOTONIC epoch.
    smeta["boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    keys = {current_key(s, smeta) for s in slots}
    if len(keys) != 1 or not all(s.timing for s in slots):
        raise RuntimeError("proof requires timing slots with the same reuse key")
    key = keys.pop()
    config = dict(proof_config(reps, pairs, stack_cc), reuse_key=key)
    rd = f"/data/m2/{campaign}"
    path = f"{rd}/proof-config.json"
    old = read_volume(slots[0], path)
    if old is None:
        # Keep historical NewReno reports and interrupted older campaigns intact.
        if dexec(slots[0].snd, f"test ! -d {shlex.quote(rd)} || ls -A {shlex.quote(rd)}").strip():
            raise RuntimeError("proof directory already has evidence without a configuration; use a new campaign")
        dexec(slots[0].snd, f"mkdir -p {shlex.quote(rd)}")
        vol_write(slots[0].snd, path, json.dumps(config, sort_keys=True) + "\n")
    elif parse_json_object(old) != config:
        raise RuntimeError("proof configuration or reuse key differs; use a new campaign")

    jobs = proof_list(reps, pairs, with_trace_off=(phase == "serial"), stack_cc=stack_cc)
    pending = []
    barriers = {}
    for kind, name, spec in jobs:
        trials = []
        for slot in slots:
            sub = f"{campaign}/{phase}-s{slot.n}"
            rd = f"/data/m2/{sub}/{name}"
            leaf = "ping.json" if kind == "ping" else "summary.json"
            row = parse_json_object(read_volume(slot, f"{rd}/{leaf}"))
            meta = row if kind == "ping" else parse_json_object(read_volume(slot, f"{rd}/meta.json"))
            expected = dict(spec, campaign=sub, run=name, slot=slot.n, reuse_key=key)
            if proof_row_error(row, meta, expected, kind) is None:
                trials.append((meta["boot_id"], measured_window(row, spec)))
        if len(trials) == len(slots) and (phase == "serial" or overlap_info(trials)["ok"]):
            continue
        pending.append((kind, name, spec))
        if phase == "parallel":
            barriers[name] = threading.Barrier(len(slots))

    stopped = threading.Event()

    def worker(slot):
        sub = f"{campaign}/{phase}-s{slot.n}"
        try:
            for kind, name, spec in pending:
                if stopped.is_set():
                    return
                barrier = barriers.get(name)
                if barrier is not None:
                    barrier.wait(timeout=180)
                if kind == "ping":
                    slot.cleanup()
                    ping = ping_only(slot, sub, name, spec, sender_barrier=barrier)
                    ping.update(spec, campaign=sub, run=name, slot=slot.n, reuse_key=key, timing=slot.timing,
                                cpusets=slot.cpus, slot_cpus=slot.slot_cpus(), boot_id=smeta["boot_id"])
                    vol_write(slot.snd, f"/data/m2/{sub}/{name}/ping.json", json.dumps(ping, sort_keys=True) + "\n")
                    log(f"{phase} slot {slot.n} {name}: median {ping.get('median_ms')} p99 {ping.get('p99_ms')}")
                else:
                    _, summary = one_run(slot, sub, name, spec, smeta, sender_barrier=barrier)
                    log(f"{phase} slot {slot.n} {name}: goodput {summary.get('goodput_bps')} valid {summary.get('valid')}")
        except BaseException:
            stopped.set()
            for barrier in barriers.values():
                barrier.abort()
            try:
                slot.cleanup()
            except Exception as cleanup_error:
                log(f"{sub} cleanup: {cleanup_error}")
            raise

    with ThreadPoolExecutor(max_workers=len(slots)) as pool:
        futures = [pool.submit(worker, slot) for slot in slots]
        errors = [exc for f in futures if (exc := f.exception()) is not None]
    if errors:
        raise next((e for e in errors if not isinstance(e, threading.BrokenBarrierError)), errors[0])


def hist_merge(hists):
    out = {}
    for h in hists:
        for k, v in (h or {}).items():
            out[int(k)] = out.get(int(k), 0) + v
    return out


def hist_percentile(h, q, max_ns=None):
    """LatenessHistogram::percentile (src/backend/event_loop.cpp): the
    inclusive upper edge of the bucket holding the sample of rank ceil(q *
    count) (0 for bucket 0, 2^i - 1 ns), with the same correction for a
    product just above an integer (0.07 * 100) and clamped to the maximum
    when it is given."""
    n = sum(h.values())
    if n == 0:
        return None
    q = min(max(q, 0.0), 1.0)
    x = q * n
    rank = math.ceil(x)
    if rank > 1 and rank - 1 >= x - x * 1e-12:
        rank -= 1
    rank = min(max(rank, 1), n)
    acc = 0
    for i in sorted(h):
        acc += h[i]
        if acc >= rank:
            upper = 0 if i == 0 else (1 << i) - 1
            return upper if max_ns is None else min(upper, max_ns)
    return max_ns


def lateness_bucket(ns):
    """The log2 bucket of the event loop's histogram that holds ns: 0 for 0,
    i for [2^(i-1), 2^i)."""
    return 0 if not ns or ns <= 0 else int(ns).bit_length()


def lateness_p99_ok(serial_ns, parallel_ns):
    """§6 asks parallel p99 <= 2 x serial. The pooled histograms resolve p99
    only to a log2 bucket, a factor of 2: a parallel p99 one bucket above the
    serial one may be anywhere from just above to almost 4 x the serial value,
    so "<= 2x" is read as "at most one bucket higher"."""
    if serial_ns is None or parallel_ns is None:
        return False
    return lateness_bucket(parallel_ns) <= lateness_bucket(serial_ns) + 1


def lateness_max_ok(serial_ns, parallel_ns):
    """§6: parallel max <= 2 x serial max (both exact nanoseconds)."""
    return serial_ns is not None and parallel_ns is not None and parallel_ns <= 2 * serial_ns


def proof_compare(serial, parallel, rel=None, abs_=None):
    """serial/parallel: lists of per-run values. Pass when all values are present, the parallel
    median is within rel (fraction) or abs_ of the serial median and the
    ranges overlap."""
    s, p = serial, parallel
    if not s or len(s) != len(p) or any(not finite(x) for x in (*s, *p)):
        return {"ok": False, "why": "missing or invalid metric", "serial": s, "parallel": p}
    ms, mp = A.median(s), A.median(p)
    diff = mp - ms
    within = abs(diff) <= (rel * abs(ms) if rel is not None else abs_)
    overlap = A.ranges_overlap(min(s), max(s), min(p), max(p))
    return {"ok": bool(within and overlap), "serial_median": ms, "parallel_median": mp, "diff": diff,
            "serial_range": [min(s), max(s)], "parallel_range": [min(p), max(p)], "within": within,
            "overlap": overlap, "n_serial": len(s), "n_parallel": len(p)}


def proof_files(campaign):
    """{relative path: JSON} of the configuration and each ping, metadata and summary in a proof
    campaign, read through a helper container."""
    dump = sh(["docker", "run", "--rm", "--name", f"{JOB}-rd-{os.getpid()}-{next(_helper_seq)}",
               "-v", f"{VOLUME}:/data:ro", IMAGE, "bash", "-c",
               f"cd /data/m2/{campaign} && for f in proof-config.json */*/ping.json */*/meta.json */*/summary.json; do "
               f"[ -e \"$f\" ] && {{ echo \"### $f\"; tr -d '\\n' < \"$f\"; echo; }}; done; true"])
    files = {}
    lines = dump.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("### ") and i + 1 < len(lines):
            files[line[4:]] = parse_json_object(lines[i + 1])
    return files


PROOF_LIMITS = {"ping_median_abs_ms": 0.2, "goodput_rel": 0.01, "backlog_rel": 0.02, "stack_goodput_rel": 0.02}


def finite(x):
    return type(x) is int or type(x) is float and math.isfinite(x)


def proof_row_error(summary, meta, expected, kind):
    if not isinstance(summary, dict) or not isinstance(meta, dict):
        return "missing evidence"
    for k, want in expected.items():
        actual = meta.get(k)
        if actual != want or isinstance(actual, bool) != isinstance(want, bool):
            return f"{k}={meta.get(k)!r}, expected {want!r}"
    start_cpu = 8 + 4 * expected["slot"]
    cpus = [str(c) for c in range(start_cpu, start_cpu + 4)]
    if (meta.get("timing") is not True or not timing_placement(expected["slot"], meta.get("cpusets"))
            or meta.get("slot_cpus") not in timing_cpu_names(expected["slot"])):
        return "wrong timing slot CPUs"
    if not isinstance(meta.get("boot_id"), str) or not meta["boot_id"] or not measured_window(summary, expected):
        return "missing boot ID or inconsistent measured window"
    if kind == "ping":
        return None if ping_sample(summary, 190) else "incomplete idle ping"
    if summary.get("proof_meta_sha256") != A.proof_meta_digest(meta):
        return "summary does not match this run metadata"
    if summary.get("run") != expected["run"] or summary.get("valid") is not True or summary.get("invalid") != []:
        return f"invalid or mismatched summary ({summary.get('invalid')})"
    if type(meta.get("sender_exit")) is not int or meta["sender_exit"] != 0 or meta.get("duration_s") != expected["duration"]:
        return "sender failure or wrong measured duration"
    if summary.get("sender_ccs") != [expected["cc"]]:
        return f"sender samples report {summary.get('sender_ccs')}, expected {expected['cc']}"
    for k in ("goodput_bps", "rwnd_limited_frac", "sndbuf_limited_frac"):
        if not finite(summary.get(k)) or summary[k] < 0:
            return f"missing or invalid {k}"
    if summary["goodput_bps"] == 0:
        return "no transfer in measurement window"
    if expected["impl"] == "linux":
        q = summary.get("queue")
        if not isinstance(q, dict) or not finite(q.get("backlog_max")) or q["backlog_max"] < 0:
            return "missing backlog maximum"
        return None
    cpu = summary.get("cpu") or {}
    softirqs = summary.get("softirqs") or {}
    if not (isinstance(cpu, dict) and all(isinstance(cpu.get(c), dict) and all(finite(cpu[c].get(k)) for k in
                                          ("busy", "total", "softirq", "irq")) for c in cpus)
            and isinstance(softirqs, dict) and all(finite(softirqs.get(k)) for k in A.SOFTIRQ_KINDS)
            and finite(summary.get("foreign_cpu_frac")) and meta.get("uptime") and meta.get("top_cpu")
            and isinstance(meta.get("threads_on_8_15"), list)):
        return "incomplete stack CPU or external load evidence"
    for k in ("sender_lateness_p99_ns", "sender_lateness_max_ns"):
        if type(summary.get(k)) is not int or summary[k] < 0:
            return f"missing or invalid {k}"
    if not finite(summary.get("qdelay_p99_ms")):
        return "missing stack ping p99"
    if summary["sender_lateness_p99_ns"] > summary["sender_lateness_max_ns"]:
        return "lateness p99 exceeds maximum"
    if "stack_lateness_max_ns" in summary and (type(summary["stack_lateness_max_ns"]) is not int
                                                or summary["stack_lateness_max_ns"] < 0):
        return "invalid stack lateness maximum"
    hist = summary.get("stack_lateness_hist")
    if not isinstance(hist, dict) or not hist or not all(
            str(i) in HIST_BUCKETS and type(n) is int and n >= 0 for i, n in hist.items()) or not any(hist.values()):
        return "missing or invalid lateness histogram"
    events = summary.get("trace_events")
    if (expected["trace"] and (type(events) is not int or events < 0)) or (not expected["trace"] and events is not None):
        return "missing or mismatched trace evidence"
    return None


HIST_BUCKETS = {str(i) for i in range(64)}


def measured_transfer_window(s, duration):
    bounds = A.endpoint_window(s.get("t0_ns"), s.get("sender_start_ns"), duration)
    end = s.get("window_end_ns")
    return bounds if bounds and type(end) is int and end == bounds[1] else None


def measured_window(s, spec):
    """Measured monotonic window, bounded by both endpoint starts (run_window)."""
    if "impl" not in spec:
        lo, hi = s.get("ping_start_ns"), s.get("ping_end_ns")
        return (lo, hi) if type(lo) is int and type(hi) is int and lo < hi else None
    return measured_transfer_window(s, spec["duration"])


def overlap_info(trials):
    windows = [window for _, window in trials]
    overlap = fraction = None
    if len(trials) == 2 and trials[0][0] == trials[1][0] and all(windows):
        overlap = max(0, min(hi for lo, hi in windows) - max(lo for lo, hi in windows))
        fraction = overlap / max(hi - lo for lo, hi in windows)
    return {"windows_mono_ns": windows, "overlap_ns": overlap, "fraction_of_longer_window": fraction,
            "ok": bool(overlap)}


def proof_evaluate(files, campaign, reps, pairs, stack_cc="newreno"):
    """Decide the §6 proof from the individual runs and their observed evidence."""
    phases = {"serial": ["serial-s0"], "parallel": ["parallel-s0", "parallel-s1"]}
    result = {"campaign": campaign, "reps": reps, "idle_ping": {}, "stack_cc": stack_cc, "items": [], "notes": [],
              "limits": PROOF_LIMITS, "valid_runs": {}, "evidence_errors": {}, "stack_overlap": [],
              "control_overlap": [], "stack_load": {}, "scope": "full" if pairs else "cubic-only"}
    if reps != A.RUNS_PER_SIDE:
        result["notes"].append("proof requires five repetitions")
    if (pairs and sorted(pairs) != sorted(PROOF_PAIRS)) or (not pairs and stack_cc != "cubic"):
        result["notes"].append("full proof requires all four bandwidth/RTT pairs; the stack-only proof requires CUBIC")
    data, trials, keys = {}, {}, set()
    slot_windows = {}
    for ph, subs in phases.items():
        for sub in subs:
            for kind, name, spec in proof_list(reps, pairs, with_trace_off=(ph == "serial"), stack_cc=stack_cc):
                path = f"{sub}/{name}"
                f = "ping.json" if kind == "ping" else "summary.json"
                row = files.get(f"{path}/{f}")
                meta = row if kind == "ping" else files.get(f"{path}/meta.json")
                expected = dict(spec, campaign=f"{campaign}/{sub}", run=name, slot=int(sub[-1]))
                why = proof_row_error(row, meta, expected, kind)
                if kind == "ping" and isinstance(row, dict):
                    result["idle_ping"][path] = {k: row.get(k) for k in ("requests_seen", "n", "lost", "median_ms", "p99_ms")}
                for leaf in ([f] if kind == "ping" else [f, "meta.json"]):
                    filename = f"{path}/{leaf}"
                    if filename in files and files[filename] is None:
                        why = f"unreadable JSON in {filename}"
                if not why:
                    key = meta.get("reuse_key")
                    if isinstance(key, str) and key:
                        keys.add(key)
                    else:
                        why = "missing reuse key"
                if kind != "ping":
                    result["valid_runs"][path] = (row or {}).get("valid") if isinstance(row, dict) else None
                if not why:
                    window = measured_window(row, spec)
                    trials[sub, name] = (meta["boot_id"], window)
                    slot_windows.setdefault((meta["slot"], meta["boot_id"]), []).append((*window, path))
                if not why and spec.get("impl") == "utcp":
                    result["stack_load"][path] = {k: row.get(k) for k in ("cpu", "softirqs", "foreign_cpu_frac")}
                    result["stack_load"][path].update({k: meta.get(k) for k in ("uptime", "top_cpu", "threads_on_8_15")})
                if why:
                    result["evidence_errors"][path] = why
                data[sub, name] = None if why else row

    for intervals in slot_windows.values():
        intervals.sort()
        for (_, hi, old_path), (lo, _, path) in zip(intervals, intervals[1:]):
            if lo < hi:
                result["evidence_errors"][path] = f"measured window overlaps {old_path} on the same slot"
    config = files.get("proof-config.json") or {}
    if any(config.get(k) != v for k, v in proof_config(reps, pairs, stack_cc).items()):
        result["notes"].append("proof configuration differs from request")
    if len(keys) != 1 or (config and config.get("reuse_key") not in keys):
        result["notes"].append("missing or mixed proof reuse keys")
    for _, name, spec in proof_list(reps, pairs, False, stack_cc):
        pair = [trials.get((sub, name), (None, None)) for sub in phases["parallel"]]
        overlap = dict(overlap_info(pair), rep=spec["rep"], run=name)
        group = "stack_overlap" if spec.get("impl") == "utcp" else "control_overlap"
        result[group].append(overlap)

    def vals(sub, prefix, key, sub_key=None):
        out = []
        for rep in range(reps):
            v = data.get((sub, f"{prefix}-r{rep}"))
            if v is None:
                out.append(None)
                continue
            x = v.get(key)
            if sub_key is not None and isinstance(x, dict):
                x = x.get(sub_key)
            out.append(x)
        return out

    for bw, rtt in pairs:
        for item, prefix, key, sub_key, crit in (
                (1, f"ping-{bw}-{rtt}-2", "median_ms", None, {"abs_": PROOF_LIMITS["ping_median_abs_ms"]}),
                (2, f"rate-{bw}-{rtt}-2", "goodput_bps", None, {"rel": PROOF_LIMITS["goodput_rel"]}),
                (4, f"rate-{bw}-{rtt}-2", "queue", "backlog_max", {"rel": PROOF_LIMITS["backlog_rel"]})):
            ser = vals("serial-s0", prefix, key, sub_key)
            for sub in phases["parallel"]:
                c = proof_compare(ser, vals(sub, prefix, key, sub_key), **crit)
                c.update(item=item, cell=f"{bw} Mbit/s, {rtt} ms, 2xBDP", metric=key if not sub_key else sub_key,
                         parallel_slot=int(sub[-1]))
                result["items"].append(c)
    # The configured stack algorithm.
    ser_g = vals("serial-s0", "stack-trace", "goodput_bps")
    ser_h = [data.get(("serial-s0", f"stack-trace-r{r}")) for r in range(reps)]

    def pooled(runs):
        if not runs or not all(runs):
            return None
        hist = hist_merge([x["stack_lateness_hist"] for x in runs])
        mx = max(x.get("stack_lateness_max_ns", x["sender_lateness_max_ns"]) for x in runs)
        return hist_percentile(hist, 0.99, mx)

    for sub in phases["parallel"]:
        c = proof_compare(ser_g, vals(sub, "stack-trace", "goodput_bps"), rel=PROOF_LIMITS["stack_goodput_rel"])
        c.update(item="stack", cell="100 Mbit/s, 20 ms, 0 %, 2xBDP", metric="goodput_bps",
                 parallel_slot=int(sub[-1]))
        result["items"].append(c)
        par_h = [data.get((sub, f"stack-trace-r{r}")) for r in range(reps)]
        for label in ("p99", "max"):
            if label == "max":
                s_v = max(x["sender_lateness_max_ns"] for x in ser_h) if ser_h and all(ser_h) else None
                p_v = max(x["sender_lateness_max_ns"] for x in par_h) if par_h and all(par_h) else None
                ok = lateness_max_ok(s_v, p_v)
            else:
                s_v, p_v = pooled(ser_h), pooled(par_h)
                ok = lateness_p99_ok(s_v, p_v)
            result["items"].append({"item": "stack", "metric": f"lateness_{label}_ns", "parallel_slot": int(sub[-1]),
                                    "serial": s_v, "parallel": p_v, "ok": bool(ok),
                                    "serial_per_run": vals("serial-s0", "stack-trace", f"sender_lateness_{label}_ns"),
                                    "parallel_per_run": vals(sub, "stack-trace", f"sender_lateness_{label}_ns")})
        # Reported, not a criterion (§6): "ok" after the comparison's own.
        result["items"].append({**proof_compare(vals("serial-s0", "stack-trace", "qdelay_p99_ms"),
                                                vals(sub, "stack-trace", "qdelay_p99_ms"), abs_=1e9),
                                "item": "stack", "metric": "ping_p99_ms", "parallel_slot": int(sub[-1]),
                                "ok": True, "informational": True})
    # sndbuf-limited time on both senders (§5.3).
    lim = {}
    for sub in ["serial-s0"] + phases["parallel"]:
        lim[sub] = {"stack": vals(sub, "stack-trace", "sndbuf_limited_frac"),
                    "stack_rwnd": vals(sub, "stack-trace", "rwnd_limited_frac")}
        if pairs:
            lim[sub].update(linux_100_20=vals(sub, "rate-100-20-2", "sndbuf_limited_frac"),
                            linux_100_20_rwnd=vals(sub, "rate-100-20-2", "rwnd_limited_frac"))
    result["sndbuf_limited"] = lim
    if pairs:
        # Trace overhead (§5.6): serial, trace on vs off.
        on = [data.get(("serial-s0", f"stack-trace-r{r}")) for r in range(reps)]
        off = [data.get(("serial-s0", f"stack-notrace-r{r}")) for r in range(reps)]
        result["trace_overhead"] = {
            "goodput_on": [(x or {}).get("goodput_bps") for x in on],
            "goodput_off": [(x or {}).get("goodput_bps") for x in off],
            "lateness_p99_on": [(x or {}).get("sender_lateness_p99_ns") for x in on],
            "lateness_p99_off": [(x or {}).get("sender_lateness_p99_ns") for x in off],
            "lateness_max_on": [(x or {}).get("sender_lateness_max_ns") for x in on],
            "lateness_max_off": [(x or {}).get("sender_lateness_max_ns") for x in off],
            "trace_events": [(x or {}).get("trace_events") for x in on],
            "hist_p99_on": pooled(on),
            "hist_p99_off": pooled(off),
        }
    result["passed"] = (not result["notes"] and not result["evidence_errors"]
                        and all(i["ok"] for i in result["stack_overlap"] + result["control_overlap"]) and all(i["ok"] for i in result["items"]))
    return result


def proof_report(campaign, reps, pairs, stack_cc="newreno"):
    """Write the verdict only into the campaign that collected this configuration."""
    files = proof_files(campaign)
    config = files.get("proof-config.json") or {}
    if any(config.get(k) != v for k, v in proof_config(reps, pairs, stack_cc).items()):
        raise RuntimeError("missing or mismatched proof configuration; preserve archived reports and use a new campaign")
    result = proof_evaluate(files, campaign, reps, pairs, stack_cc)
    text = json.dumps(result, indent=1, sort_keys=True) + "\n"
    helper = f"{JOB}-wr-{os.getpid()}"
    sh(["docker", "run", "--rm", "-i", "--name", helper, "-v", f"{VOLUME}:/data", IMAGE, "bash", "-c",
        publish_script(f"/data/m2/{campaign}/proof.json")], input=text)
    md = proof_markdown(result)
    sh(["docker", "run", "--rm", "-i", "--name", helper, "-v", f"{VOLUME}:/data", IMAGE, "bash", "-c",
        publish_script(f"/data/m2/{campaign}/proof.md")], input=md)
    return result, md


def _f(x, scale=1.0, nd=2):
    return f"{x / scale:.{nd}f}" if finite(x) else "-"


def proof_markdown(r):
    cc_label = {"newreno": "NewReno", "cubic": "CUBIC"}[r.get("stack_cc", "newreno")]
    lines = [f"Parallel-mode proof, stack {cc_label}, campaign {r['campaign']}, {r['reps']} repetitions: "
             + ("PASSED" if r["passed"] else "FAILED"), "",
             "| Item | Cell | Metric | Parallel slot | Serial median [range] | Parallel median [range] | Pass |",
             "|---|---|---|---|---|---|---|"]
    for i in r["items"]:
        m = i["metric"]
        if "serial_median" in i:
            sc = 1e6 if m == "goodput_bps" else 1.0
            nd = 3
            s = f"{_f(i['serial_median'], sc, nd)} [{_f(i['serial_range'][0], sc, nd)}, {_f(i['serial_range'][1], sc, nd)}]"
            p = f"{_f(i['parallel_median'], sc, nd)} [{_f(i['parallel_range'][0], sc, nd)}, {_f(i['parallel_range'][1], sc, nd)}]"
        else:
            s, p = str(i.get("serial")), str(i.get("parallel"))
        unit = {"goodput_bps": "goodput (Mbit/s)", "median_ms": "ping median (ms)", "backlog_max": "backlog max (B)"}.get(m, m)
        ok = "info" if i.get("informational") else ("yes" if i["ok"] else "NO")
        lines.append(f"| {i['item']} | {i.get('cell', '100 Mbit/s, 20 ms, 0 %, 2xBDP')} | {unit} | {i['parallel_slot']} | {s} | {p} | {ok} |")
    if "trace_overhead" in r:
        t = r["trace_overhead"]
        lines += ["", f"Trace overhead (stack {cc_label}, 100 Mbit/s, 20 ms, 0 %, 2xBDP, serial):",
                  f"- goodput on (Mbit/s): {[_f(x, 1e6) for x in t['goodput_on']]}",
                  f"- goodput off (Mbit/s): {[_f(x, 1e6) for x in t['goodput_off']]}",
                  f"- lateness p99 on/off (ns, per run): {t['lateness_p99_on']} / {t['lateness_p99_off']}",
                  f"- lateness max on/off (ns, per run): {t['lateness_max_on']} / {t['lateness_max_off']}",
                  f"- pooled lateness p99 on/off (ns): {t['hist_p99_on']} / {t['hist_p99_off']}",
                  f"- trace events per run: {t['trace_events']}"]
    lines += ["", "sndbuf-limited and rwnd-limited fractions of the window:"]
    for sub, v in r["sndbuf_limited"].items():
        lines.append(f"- {sub}: {json.dumps(v)}")
    bad = [k for k, v in r["valid_runs"].items() if v is not True]
    lines += ["", f"Runs not valid: {bad if bad else 'none'}"]
    if "stack_overlap" not in r:
        lines.append("Historical report: paired windows and sampled sender identity were not recorded.")
    for row in r.get("stack_overlap", []):
        lines.append(f"- Parallel stack r{row['rep']}: measured overlap {row['overlap_ns']} ns "
                     f"(fraction of the longer window {row['fraction_of_longer_window']})")
    for row in r.get("control_overlap", []):
        lines.append(f"- Parallel {row['run']}: measured overlap {row['overlap_ns']} ns")
    lines.extend(r["notes"])
    lines.extend(f"- {path}: {reason}" for path, reason in r.get("evidence_errors", {}).items())
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Plots (§5.12)


def run_plot(campaign, out=None):
    out = out or f"/data/m2/{campaign}/plots"
    name = f"{JOB}-plot-{os.getpid()}"
    return sh(["docker", "run", "--rm", "--name", name, "--cpuset-cpus", "16-31", "-e", "MPLCONFIGDIR=/tmp/mpl",
               "-v", f"{VOLUME}:/data", "-v", f"{REPO}:/utcp:ro", IMAGE,
               "nice", "-n", "10", "python3", "-I", "/utcp/tools/m2/plot.py", f"/data/m2/{campaign}", out],
              timeout=1800)


# --------------------------------------------------------------------------


def main(argv):
    ap = argparse.ArgumentParser(prog="matrix.py", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("up")
    p.add_argument("--slot", type=int, required=True)
    p.add_argument("--nontiming", action="store_true")
    p = sub.add_parser("down")
    p.add_argument("--slot", type=int, required=True)
    p = sub.add_parser("one")
    p.add_argument("--slot", type=int, required=True)
    p.add_argument("--campaign", required=True)
    p.add_argument("--run", required=True)
    p.add_argument("--bw", type=int, required=True)
    p.add_argument("--rtt", type=int, required=True)
    p.add_argument("--queue-bdp", type=float, required=True)
    p.add_argument("--loss", type=float, default=0)
    p.add_argument("--seed", type=int)
    p.add_argument("--impl", default="linux", choices=("linux", "utcp"))
    p.add_argument("--profile", default="linux")
    p.add_argument("--cc", default="cubic")
    p.add_argument("--duration", type=float, default=30)
    p.add_argument("--extra-capture", action="store_true")
    p.add_argument("--bytes", help="send this many bytes instead of --duration")
    p.add_argument("--drop", action="append", default=[],
                   help="drop.sh arguments after --slot N, e.g. 'arm --offsets 1448000 --copies 1'")
    p = sub.add_parser("calibrate")
    p.add_argument("--slot", type=int, required=True)
    p.add_argument("--campaign", required=True)
    p.add_argument("--pairs", default=",".join(f"{b}x{r}" for b, r in PAIRS))
    p.add_argument("--skip-stack", action="store_true")
    p.add_argument("--seed", type=int, default=1)
    p = sub.add_parser("analyze")
    p.add_argument("--campaign", required=True)
    p = sub.add_parser("tables")
    p.add_argument("--campaign", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("gate-table")
    p.add_argument("--campaign", action="append", required=True, help="a calibration campaign (repeatable)")
    p = sub.add_parser("cat")
    p.add_argument("path")
    p = sub.add_parser("run", help="a run plan (TOML), resumable")
    p.add_argument("plan")
    p.add_argument("--slot", type=int, action="append", required=True,
                   help="the slot; a second one only with --parallel")
    p.add_argument("--no-rerun", action="store_true", help="do not rerun invalid groups")
    p.add_argument("--parallel", action="store_true",
                   help="allow two slots at once (RESULTS.md Timing hygiene decided serial)")
    p.add_argument("--nontiming", action="store_true",
                   help="allow a non-timing slot and mark the runs timing=false")
    p.add_argument("--gate", action="append", default=[],
                   help="a calibration campaign whose gate.json passed on the slot with the same reuse key "
                        "(repeatable)")
    p.add_argument("--no-gate", action="store_true", help="run without a gate (not for timing campaigns)")
    p.add_argument("--rekey", action="store_true",
                   help="move groups with runs of another reuse key aside and rerun them")
    p = sub.add_parser("expand", help="print the run list of a plan (no runs)")
    p.add_argument("plan")
    p.add_argument("--slots", type=int, default=1)
    p = sub.add_parser("plot", help="overlay plots of a campaign (tools/m2/plot.py)")
    p.add_argument("--campaign", required=True)
    p.add_argument("--out", help="directory in the volume (default /data/m2/CAMPAIGN/plots)")
    p = sub.add_parser("proof", help="the parallel-mode proof and the trace overhead (§6, §5.6)")
    p.add_argument("--campaign", required=True)
    p.add_argument("--phase", choices=("serial", "parallel", "report", "all"), default="all")
    p.add_argument("--reps", type=int, default=5)
    cc = p.add_mutually_exclusive_group()
    cc.add_argument("--cubic-only", action="store_true", help="only the 15 trace-on m2-integrate CUBIC transfers")
    cc.add_argument("--stack-cc", choices=("newreno", "cubic"), default="newreno",
                   help="stack sender congestion control (use a separate campaign per configuration)")
    p.add_argument("--pairs", help="full-proof control cells (default: all four)")
    a = ap.parse_args(argv[1:])
    if a.cmd == "up":
        print(tb("up.sh", "--slot", a.slot, *(["--nontiming"] if a.nontiming else [])), end="")
    elif a.cmd == "down":
        print(tb("down.sh", "--slot", a.slot), end="")
    elif a.cmd == "one":
        spec = {"bw": a.bw, "rtt": a.rtt, "queue_bdp": a.queue_bdp, "loss": a.loss, "seed": a.seed,
                "impl": a.impl, "profile": a.profile, "cc": a.cc, "duration": a.duration,
                "extra_capture": a.extra_capture, "cell": f"{a.bw}-{a.rtt}-{a.loss:g}-{a.queue_bdp:g}",
                "rep": 0, "order": 0, "bytes": a.bytes, "drops": [shlex.split(d) for d in a.drop]}
        meta, s = one_run(Slot(a.slot), a.campaign, a.run, spec)
        print(json.dumps(s, indent=1, sort_keys=True))
    elif a.cmd == "calibrate":
        pairs = [tuple(int(x) for x in p.split("x")) for p in a.pairs.split(",")]
        r = calibrate(Slot(a.slot), a.campaign, pairs, a.skip_stack, a.seed)
        print(gate_markdown(r), end="")
        return 0 if r["passed"] else 1
    elif a.cmd == "analyze":
        # Run directories only: those with a meta.json (not plots/, tables/, aside/).
        out = sh(["docker", "run", "--rm", "--name", f"{JOB}-ls-{os.getpid()}", "-v", f"{VOLUME}:/data", IMAGE,
                  "bash", "-c", f"ls -d /data/m2/{a.campaign}/*/meta.json 2>/dev/null; true"])
        for f in out.split():
            run_analysis(["run", f.rsplit("/", 1)[0]])
    elif a.cmd == "tables":
        run_analysis(["tables", a.out, "--campaign", f"/data/m2/{a.campaign}"])
    elif a.cmd == "gate-table":
        gates = [json.loads(sh(["docker", "run", "--rm", "--name", f"{JOB}-cat-{os.getpid()}", "-v",
                                f"{VOLUME}:/data:ro", IMAGE, "cat", f"/data/m2/{c}/gate.json"])) for c in a.campaign]
        print(gate_table(gates), end="")
    elif a.cmd == "run":
        if not a.gate and not a.no_gate:
            ap.error("run needs --gate CAMPAIGN (a passing calibration gate) or --no-gate")
        if len(a.slot) > 1 and not a.parallel:
            ap.error("timing runs are serial (RESULTS.md Timing hygiene): one --slot, or --parallel")
        errors = run_plan(a.plan, [Slot(n) for n in a.slot], rerun_invalid=not a.no_rerun, parallel=a.parallel,
                          nontiming=a.nontiming, gates=a.gate, no_gate=a.no_gate, rekey=a.rekey)
        return 1 if errors else 0
    elif a.cmd == "expand":
        for r in expand_plan(load_plan(a.plan), a.slots):
            print(json.dumps(r, sort_keys=True))
    elif a.cmd == "plot":
        print(run_plot(a.campaign, a.out), end="")
    elif a.cmd == "proof":
        if a.cubic_only and a.pairs:
            ap.error("--pairs selects full-proof controls and cannot be combined with --cubic-only")
        pairs = [tuple(map(int, p.split("x"))) for p in a.pairs.split(",")] if a.pairs else PROOF_PAIRS
        if a.cubic_only:
            pairs, a.stack_cc = (), "cubic"
        if a.reps <= 0:
            ap.error("proof --reps must be positive")
        if a.phase in ("serial", "all"):
            proof_phase(a.campaign, "serial", [Slot(0)], a.reps, pairs, a.stack_cc)
        if a.phase in ("parallel", "all"):
            proof_phase(a.campaign, "parallel", [Slot(0), Slot(1)], a.reps, pairs, a.stack_cc)
        if a.phase in ("report", "all"):
            r, md = proof_report(a.campaign, a.reps, pairs, a.stack_cc)
            print(md, end="")
            return 0 if r["passed"] else 1
    elif a.cmd == "cat":
        print(sh(["docker", "run", "--rm", "--name", f"{JOB}-cat-{os.getpid()}", "-v", f"{VOLUME}:/data:ro",
                  IMAGE, "cat", a.path]), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
