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
  matrix.py run PLAN.toml --slot N [--slot M]
                                            a run plan (load_plan has the format);
                                            resumable: runs with a summary.json are
                                            skipped, a partial run is moved to aside/
  matrix.py expand PLAN.toml [--slots K]    the run list of a plan, no runs
  matrix.py plot --campaign C [--out DIR]   overlay plots (tools/m2/plot.py)
  matrix.py proof --campaign C [--phase serial|parallel|report|all] [--reps 5]
                                            the parallel-mode proof (§6) and the trace
                                            overhead (§5.6): proof.json, proof.md

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


def dexec(c, script, check=True, timeout=None, input=None):
    cmd = ["docker", "exec"] + (["-i"] if input is not None else []) + [c, "bash", "-c", script]
    return sh(cmd, check=check, timeout=timeout, input=input)


def dexec_bg(c, script):
    sh(["docker", "exec", "-d", c, "bash", "-c", script])


def vol_write(c, path, text):
    sh(["docker", "exec", "-i", c, "bash", "-c", f"cat > {shlex.quote(path)}"], input=text)


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
        if subprocess.run(["docker", "exec", c, "bash", "-c", script], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0:
            return
        time.sleep(0.05)
    raise RuntimeError(f"timeout waiting for {what} in {c}")


def one_run(slot, campaign, run, spec, smeta=None):
    """One run (§5.6): fresh shaping, pre record, captures, tbf sampler,
    receiver, pings (3 s idle first), sender, post record, analysis.
    spec: bw, rtt, queue_bdp, loss, seed, impl, cc, duration, profile,
    extra_capture (also r1-out), plus anything copied into meta.json."""
    smeta = smeta or static_meta()
    base = f"/data/m2/{campaign}"
    rd = f"{base}/{run}"
    S = float(spec["duration"])
    slot.cleanup()
    dexec(slot.snd, f"if [ -e {rd} ]; then mkdir -p {base}/aside && mv {rd} {base}/aside/{run}-$(date +%s); fi;"
                    f" mkdir -p {rd}/pre {rd}/post")
    shape = tb("shape.sh", "--slot", slot.n, "--bw", spec["bw"], "--rtt", spec["rtt"],
               "--queue-bdp", spec["queue_bdp"], *(["--loss", spec["loss"]] if spec.get("loss") else []),
               *(["--seed", spec["seed"]] if spec.get("seed") is not None else []))
    sl = [l for l in shape.splitlines() if l.startswith("shape: slot")][0].split()
    shp = dict(zip(sl[3::2], sl[4::2]))
    for c in (slot.snd, slot.rcv):
        dexec(c, "ip tcp_metrics flush")
    meta = dict(spec)
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


def ping_only(slot, campaign, run, spec, src="snd", target=None, count=200):
    """Gate item 1 (and 6's ping): `count` pings at 50 ms with no load."""
    base = f"/data/m2/{campaign}"
    rd = f"{base}/{run}"
    dexec(slot.snd, f"mkdir -p {rd}")
    if spec:
        tb("shape.sh", "--slot", slot.n, "--bw", spec["bw"], "--rtt", spec["rtt"], "--queue-bdp", spec["queue_bdp"])
    c = slot.snd if src == "snd" else slot.rcv
    target = target or slot.rcv_ip
    out = dexec(c, f"ping -D -i 0.05 -s 56 -c {count} {target} | tee {rd}/ping.txt")
    pings = A.parse_ping(out)
    rtts = [p.rtt_ms for p in pings if p.rtt_ms is not None]
    return {"n": len(rtts), "lost": count - len(rtts), "median_ms": A.median(rtts),
            "p99_ms": A.percentile(rtts, 0.99), "max_ms": max(rtts) if rtts else None}


# --------------------------------------------------------------------------
# Calibration gate


def calibrate(slot, campaign, pairs, skip_stack=False, seed=1):
    smeta = static_meta()
    rng = random.Random(seed)
    results = {"campaign": campaign, "slot": slot.n, "cpusets": slot.cpus, "seed": seed,
               "static": smeta, "items": []}
    loss_tests = [(bw, rtt, q, p) for bw, rtt in pairs for q in QUEUES for p in LOSSES]
    alpha = 0.01 / max(1, len(loss_tests))

    def add(item, ok, **kw):
        kw.update(item=item, ok=ok)
        results["items"].append(kw)
        log(f"item {item}: {'pass' if ok else 'FAIL'} {json.dumps(kw, sort_keys=True)}")

    for bw, rtt in pairs:
        dur = 30 if rtt == 20 else 60
        for q in QUEUES:
            spec = {"bw": bw, "rtt": rtt, "queue_bdp": q}
            p = ping_only(slot, campaign, f"ping-{bw}-{rtt}-{q:g}", spec)
            ok = p["n"] >= 190 and rtt <= p["median_ms"] <= rtt + 1 and p["p99_ms"] <= rtt + 2
            add(1, ok, bw=bw, rtt=rtt, queue_bdp=q, **p)
            run = f"rate-{bw}-{rtt}-{q:g}"
            meta, s = one_run(slot, campaign, run, dict(spec, loss=0, seed=rng.randrange(1, 2**31),
                                                         impl="linux", cc="cubic", duration=dur,
                                                         cell=f"{bw}-{rtt}-0-{q:g}", rep=0, order=0,
                                                         gate="rate"), smeta)
            g = s.get("goodput_bps") or 0
            thr = RATE_FRACTION * bw * 1e6
            add(2, (g >= thr) if q == 2.0 else True, gated=q == 2.0, bw=bw, rtt=rtt, queue_bdp=q, run=run,
                goodput_bps=g, threshold_bps=thr, fraction_of_bw=g / (bw * 1e6))
            qc = s.get("queue") or {}
            Q = meta["queue_bytes"]
            # The largest backlog a ping (98-byte frame) can find is the whole
            # 1514-byte frames that fit with it; plus its own transmission.
            # §5.4 says Q*8/BW; for Q = 12 500 B (8 frames) that is 3 % above
            # what is attainable (DESIGN §14).
            target_ms = ((Q - 98) // A.FRAME * A.FRAME + 98) * 8 / (bw * 1e6) * 1e3
            pmax = s.get("ping_max_ms")
            base = s.get("ping_base_ms")
            dmax = (pmax - base) if pmax is not None and base is not None else None
            ok4 = bool(qc.get("reaches")) and qc.get("drop_intervals_low", 1) == 0 and dmax is not None \
                and abs(dmax - target_ms) <= 0.1 * target_ms
            add(4, ok4, bw=bw, rtt=rtt, queue_bdp=q, run=run, queue_bytes=Q, backlog_max=qc.get("backlog_max"),
                backlog_frac=(qc.get("backlog_max") or 0) / Q, drop_intervals=qc.get("drop_intervals"),
                drop_intervals_low=qc.get("drop_intervals_low"),
                drop_intervals_below_frac=qc.get("drop_intervals_below_frac"), min_level=qc.get("min_level"),
                ping_max_minus_base_ms=dmax, target_ms=target_ms)
            add(5, not s.get("local_drops") and "ACK-path qdisc drops" not in s.get("invalid", []), run=run,
                bw=bw, rtt=rtt, queue_bdp=q,
                local_drops=s.get("local_drops"), time_squeeze=s.get("time_squeeze"),
                captures={k: v.get("kernel_dropped") for k, v in (s.get("capture") or {}).items()})
            for p_loss in LOSSES:
                run = f"loss-{bw}-{rtt}-{q:g}-{p_loss:g}"
                meta, s = one_run(slot, campaign, run, dict(spec, loss=p_loss, seed=rng.randrange(1, 2**31),
                                                             impl="linux", cc="cubic", duration=dur,
                                                             cell=f"{bw}-{rtt}-{p_loss:g}-{q:g}", rep=0,
                                                             order=0, gate="loss", extra_capture=True), smeta)
                cap = s.get("capture") or {}
                n_in = cap.get("r1-in", {}).get("data_segs")
                n_out2 = cap.get("r2-out", {}).get("data_segs")
                n_out1 = cap.get("r1-out", {}).get("data_segs")
                tbf_drop = (s.get("tbf") or {}).get("dropped")
                if None in (n_in, n_out1, n_out2, tbf_drop):
                    add(3, False, run=run, error="missing captures or tbf counters")
                    continue
                # Lost in netem = data segments into r1 minus those leaving r1's
                # b side (r1-out is captured after the netem qdisc). §5.4's
                # r1-in - r2-out - tbf drops is reported too; it counts tbf drops
                # of ping packets as data (DESIGN §14).
                lost = n_in - n_out1
                lo, hi = A.binom_interval(n_in, p_loss / 100, alpha)
                ack = s.get("ack_path") or {}
                ack_ok = all((v or {}).get("dropped", 0) == 0 for v in ack.values())
                add(3, lo <= lost <= hi and ack_ok and not s.get("local_drops"), run=run, bw=bw, rtt=rtt,
                    queue_bdp=q, loss_pct=p_loss, offered=n_in, lost=lost, measured_pct=100 * lost / n_in,
                    interval=[lo, hi], alpha=alpha, lost_by_design_formula=n_in - n_out2 - tbf_drop,
                    netem_dropped_counter=(s.get("netem") or {}).get("dropped"), tbf_dropped=tbf_drop,
                    ack_path=ack, local_drops=s.get("local_drops"))
                add(5, not s.get("local_drops"), run=run, bw=bw, rtt=rtt, queue_bdp=q, loss_pct=p_loss,
                    local_drops=s.get("local_drops"),
                    time_squeeze=s.get("time_squeeze"),
                    captures={k: v.get("kernel_dropped") for k, v in cap.items()})
    if not skip_stack:
        stack_item(slot, campaign, results, smeta, rng, add)
    results["passed"] = all(i["ok"] for i in results["items"])
    results["passed_linux_items_1_5"] = all(i["ok"] for i in results["items"] if i["item"] <= 5)
    text = json.dumps(results, indent=1, sort_keys=True) + "\n"
    vol_write(slot.snd, f"/data/m2/{campaign}/gate.json", text)
    vol_write(slot.snd, f"/data/m2/{campaign}/gate.md", gate_markdown(results))
    log(f"gate {'PASSED' if results['passed'] else 'FAILED'}; /data/m2/{campaign}/gate.json")
    return results


def stack_item(slot, campaign, results, smeta, rng, add):
    """Gate item 6: ping the stack from the receiver (stack idle, listening)
    against item 1's median; one stack NewReno run at 100 Mbit/s, 20 ms, 0 %,
    2xBDP against item 2's threshold, no utcp* or DeviceStats drops."""
    rd = f"/data/m2/{campaign}/stack-ping"
    spec = {"bw": 100, "rtt": 20, "queue_bdp": 2}
    tb("shape.sh", "--slot", slot.n, "--bw", 100, "--rtt", 20, "--queue-bdp", 2)
    dexec(slot.snd, f"mkdir -p {rd}")
    dexec_bg(slot.snd, f"exec {BULK} --backend utcp --tun utcp0 --addr {slot.stack_ip} --listen {PORT} "
                       f"--recv --sample-ms 0 > {rd}/stack.out 2>&1")
    time.sleep(1.0)
    p_stack = ping_only(slot, campaign, "stack-ping", None, src="rcv", target=slot.stack_ip)
    dexec(slot.snd, "pkill -x utcp-bulk", check=False)
    p_kernel = ping_only(slot, campaign, "stack-ping-kernel", spec)
    d = None if p_stack["median_ms"] is None else p_stack["median_ms"] - p_kernel["median_ms"]
    add(6, d is not None and abs(d) <= 0.2, part="ping", stack=p_stack, kernel=p_kernel, diff_ms=d)
    thr = RATE_FRACTION * 100e6
    # "run": §5.4's run. "path": the same with the stack's send buffer at
    # 400 000 B (1.6 x BDP, below BDP + queue = 750 000 B), so the window never
    # overflows the queue and the result shows what the TUN path carries
    # without loss recovery in play.
    for part, extra in (("run", ""), ("path", "--snd-buf 400000")):
        run = f"stack-100-20-2-{part}"
        meta, s = one_run(slot, campaign, run, dict(spec, loss=0, seed=rng.randrange(1, 2**31), impl="utcp",
                                                     profile="linux", cc="newreno", duration=30,
                                                     cell="100-20-0-2", rep=0, order=0, gate="stack",
                                                     stack_args=extra), smeta)
        g = s.get("goodput_bps") or 0
        add(6, g >= thr and not s.get("local_drops") and not s.get("stack_device") and s.get("valid"),
            part=part, run=run, stack_args=extra, goodput_bps=g, threshold_bps=thr,
            local_drops=s.get("local_drops"), stack_device=s.get("stack_device"), invalid=s.get("invalid"),
            flags=s.get("flags"), retrans_pct=s.get("retrans_pct"), tbf_dropped=(s.get("tbf") or {}).get("dropped"),
            sndbuf_limited_frac=s.get("sndbuf_limited_frac"), rwnd_limited_frac=s.get("rwnd_limited_frac"),
            lateness_p99_ns=s.get("sender_lateness_p99_ns"), lateness_max_ns=s.get("sender_lateness_max_ns"))


def gate_markdown(r):
    lines = [f"Calibration gate, campaign {r['campaign']}, slot {r['slot']}, cpusets "
             + ", ".join(f"{k.rsplit('-', 1)[-1]} {v}" for k, v in r["cpusets"].items())
             + f", kernel {r['static']['uname_r']}, commit {r['static']['commit']}: "
             + ("PASSED" if r["passed"] else "FAILED")
             + f" (items 1-5, Linux to Linux: {'passed' if r.get('passed_linux_items_1_5') else 'FAILED'})", ""]
    lines += ["| Item | Cell | Result | Pass |", "|---|---|---|---|"]
    for i in r["items"]:
        it = i["item"]
        cell = f"{i.get('bw', 100)} Mbit/s, {i.get('rtt', 20)} ms" + (
            f", {i['queue_bdp']:g}xBDP" if "queue_bdp" in i else "") + (
            f", {i['loss_pct']:g} %" if "loss_pct" in i else "")
        if it == 1:
            res = f"median {i['median_ms']:.3f} ms, p99 {i['p99_ms']:.3f} ms, n {i['n']}"
        elif it == 2:
            res = (f"goodput {i['goodput_bps'] / 1e6:.3f} Mbit/s = {100 * i['fraction_of_bw']:.2f} % of BW"
                   f" (threshold {i['threshold_bps'] / 1e6:.3f}){'' if i['gated'] else ', not gated'}")
        elif it == 3:
            if "error" in i:
                res = i["error"]
            else:
                res = (f"lost {i['lost']} of {i['offered']} = {i['measured_pct']:.4f} %, interval "
                       f"[{i['interval'][0]}, {i['interval'][1]}]; r1-in - r2-out - tbf drops {i['lost_by_design_formula']}, "
                       f"netem counter {i['netem_dropped_counter']}, tbf drops {i['tbf_dropped']}")
        elif it == 4:
            res = (f"backlog max {i['backlog_max']} B = {100 * i['backlog_frac']:.1f} % of Q {i['queue_bytes']};"
                   f" drop intervals {i['drop_intervals']}, below the tail-drop bound"
                   f" (lowest {i['min_level'] if i['min_level'] is None else round(i['min_level'])} B):"
                   f" {i['drop_intervals_low']} (below 0.9Q: {i['drop_intervals_below_frac']});"
                   f" ping max - base {i['ping_max_minus_base_ms'] if i['ping_max_minus_base_ms'] is None else round(i['ping_max_minus_base_ms'], 2)}"
                   f" ms vs {i['target_ms']:.2f} ms")
        elif it == 5:
            res = f"local drops {i['local_drops'] or 'none'}, time_squeeze {i['time_squeeze']}, capture drops {i['captures']}"
        else:
            if i.get("part") == "ping":
                res = (f"stack ping median {i['stack']['median_ms']} ms vs kernel {i['kernel']['median_ms']}"
                       f" ms, diff {i['diff_ms'] if i['diff_ms'] is None else round(i['diff_ms'], 3)} ms")
                cell = "100 Mbit/s, 20 ms (idle)"
            else:
                cell = f"100 Mbit/s, 20 ms, 2xBDP, stack {i['part']}" + (f" ({i['stack_args']})" if i["stack_args"] else "")
                res = (f"stack NewReno goodput {i['goodput_bps'] / 1e6:.3f} Mbit/s (threshold "
                       f"{i['threshold_bps'] / 1e6:.3f}); drops {i['local_drops'] or 'none'}, device "
                       f"{i['stack_device'] or 'none'}; lateness p99 {i['lateness_p99_ns']} ns max "
                       f"{i['lateness_max_ns']} ns; retransmitted {i['retrans_pct']} %, tbf drops "
                       f"{i['tbf_dropped']}; sndbuf-limited {i['sndbuf_limited_frac']}, rwnd-limited "
                       f"{i['rwnd_limited_frac']}")
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
            bad5 = [i for i in by.get(5, []) if i["local_drops"] or i["time_squeeze"]
                    or any(v for v in (i["captures"] or {}).values())]
            ok = all(i["ok"] for i in items)
            dmax = i4["ping_max_minus_base_ms"]
            out.append(
                f"| {g['slot']} | {bw} Mbit/s, {rtt} ms, {q:g}xBDP | {i1['median_ms']:.2f} / {i1['p99_ms']:.2f} "
                f"| {100 * i2['fraction_of_bw']:.2f}{'' if i2['gated'] else ' (not gated)'} "
                f"| {100 * i4['backlog_frac']:.1f}; {'-' if dmax is None else f'{dmax:.1f}'} / {i4['target_ms']:.1f} "
                f"| {l3} | {len(bad5)} of {len(by.get(5, []))} runs "
                f"| {'yes' if ok else 'NO'} |")
    out += ["", "| Slot | Item 6 part | Result | Pass |", "|---|---|---|---|"]
    for g in gates:
        for i in g["items"]:
            if i["item"] != 6:
                continue
            if i.get("part") == "ping":
                res = (f"idle ping median rcv to stack {i['stack']['median_ms']} ms, snd kernel to rcv "
                       f"{i['kernel']['median_ms']} ms")
            else:
                res = (f"stack NewReno 100 Mbit/s, 20 ms, 0 %, 2xBDP{', ' + i['stack_args'] if i['stack_args'] else ''}: "
                       f"{i['goodput_bps'] / 1e6:.2f} Mbit/s (threshold {i['threshold_bps'] / 1e6:.2f}); "
                       f"retransmitted {i['retrans_pct']:.2f} %; rwnd-limited {100 * (i['rwnd_limited_frac'] or 0):.1f} %, "
                       f"sndbuf-limited {100 * (i['sndbuf_limited_frac'] or 0):.1f} %; loop lateness p99 bucket "
                       f"<= {i['lateness_p99_ns']} ns; drops {i['local_drops'] or 'none'}")
            out.append(f"| {g['slot']} | {i.get('part')} | {res} | {'yes' if i['ok'] else 'NO'} |")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Plans (§5.6, §5.13): `run PLAN.toml`


def default_duration(rtt):
    return 30 if float(rtt) <= 20 else 60


def cell_name(c):
    return f"{c['bw']:g}-{c['rtt']:g}-{float(c.get('loss', 0)):g}-{float(c['queue_bdp']):g}"


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
    """
    with open(path, "rb") as f:
        plan = tomllib.load(f)
    for k in ("campaign", "seed", "reps", "cell", "algo"):
        if k not in plan:
            raise ValueError(f"plan {path}: '{k}' missing")
    for c in plan["cell"]:
        for k in ("bw", "rtt", "queue_bdp"):
            if k not in c:
                raise ValueError(f"plan {path}: cell without '{k}'")
    for a in plan["algo"]:
        if "cc" not in a:
            raise ValueError(f"plan {path}: algo without 'cc'")
        if not set(a.get("impls", ("utcp", "linux"))) <= {"utcp", "linux"}:
            raise ValueError(f"plan {path}: impls are utcp and linux")
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
        for k, impl in enumerate(impls):
            spec = {"bw": c["bw"], "rtt": c["rtt"], "loss": float(c.get("loss", 0)),
                    "queue_bdp": float(c["queue_bdp"]), "seed": netem_seed, "impl": impl, "cc": a["cc"],
                    "profile": a.get("profile", "linux"),
                    "duration": float(plan.get("duration", default_duration(c["rtt"]))),
                    "cell": cell, "rep": rep, "group": gi, "in_group": k, "plan_seed": plan["seed"],
                    "trace": bool(plan.get("trace", True))}
            if impl == "utcp" and a.get("stack_set"):
                spec["stack_set"] = list(a["stack_set"])
            spec["run"] = f"{cell}-{a['cc']}-r{rep}-{impl}"
            spec["slot_index"] = rep % nslots
            runs.append(spec)
    for i, r in enumerate(runs):
        r["order"] = i
    return runs


def read_volume(slot, path):
    r = subprocess.run(["docker", "exec", slot.snd, "cat", path], stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, text=True)
    return r.stdout if r.returncode == 0 else None


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


def run_plan(plan_path, slots, rerun_invalid=True):
    plan = load_plan(plan_path)
    campaign = plan["campaign"]
    runs = expand_plan(plan, len(slots))
    smeta = static_meta()
    expanded = json.dumps({"plan": plan, "runs": runs}, indent=1, sort_keys=True) + "\n"
    old = read_volume(slots[0], f"/data/m2/{campaign}/plan.json")
    if old is not None and json.loads(old)["runs"] != runs:
        raise RuntimeError(f"/data/m2/{campaign}/plan.json holds a different plan; use a new campaign")
    dexec(slots[0].snd, f"mkdir -p /data/m2/{campaign}")
    if old is None:
        vol_write(slots[0].snd, f"/data/m2/{campaign}/plan.json", expanded)
    log(f"plan {plan_path}: campaign {campaign}, seed {plan['seed']}, {len(runs)} runs on slots "
        + ",".join(str(s.n) for s in slots))
    errors = []

    def worker(si):
        slot = slots[si]
        mine = [r for r in runs if r["slot_index"] == si]
        for r in mine:
            if run_done(slot, campaign, r["run"]) is not None:
                log(f"{r['run']}: done before, skipped")
                continue
            spec = {k: v for k, v in r.items() if k not in ("run", "slot_index")}
            try:
                log(f"slot {slot.n}: {r['run']} (order {r['order']}, group {r['group']}, netem seed {r['seed']})")
                _, summ = one_run(slot, campaign, r["run"], spec, smeta)
                log(f"{r['run']}: valid {summ.get('valid')} goodput {summ.get('goodput_bps')} "
                    f"{summ.get('invalid')} {summ.get('flags')}")
            except Exception as e:  # noqa: BLE001 - one failed run must not stop the slot
                errors.append((r["run"], str(e)))
                log(f"{r['run']}: ERROR {e}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(len(slots))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if rerun_invalid:
        rerun_invalid_runs(plan, runs, slots, smeta)
    log(f"plan {campaign}: finished, {len(errors)} errors")
    return errors


def rerun_invalid_runs(plan, runs, slots, smeta):
    """RESULTS.md "Which runs count": an invalid run is rerun (the invalid
    one is kept, marked); at most A.RERUN_CAP reruns per cell and algorithm."""
    campaign = plan["campaign"]
    by_cell = {}
    for r in runs:
        by_cell.setdefault((r["cell"], r["cc"]), []).append(r)
    for (cell, cc), rs in sorted(by_cell.items()):
        slot = slots[rs[0]["slot_index"]]
        reruns = 0
        order = len(runs) + 1000 * (1 + sorted(by_cell).index((cell, cc)))
        for r in rs:
            s = run_done(slot, campaign, r["run"])
            k = 0
            while (s is None or not s.get("valid")) and reruns < A.RERUN_CAP:
                k += 1
                reruns += 1
                name = f"{r['run']}-rerun{k}"
                spec = {kk: v for kk, v in r.items() if kk not in ("run", "slot_index")}
                spec.update(order=order, rerun_of=r["run"])
                order += 1
                log(f"{r['run']}: invalid or missing, rerun as {name}")
                if run_done(slot, campaign, name) is None:
                    try:
                        one_run(slot, campaign, name, spec, smeta)
                    except Exception as e:  # noqa: BLE001
                        log(f"{name}: ERROR {e}")
                s = run_done(slot, campaign, name)


# --------------------------------------------------------------------------
# Parallel-mode proof (§6) and the trace overhead (§5.6)

PROOF_PAIRS = ((10, 20), (10, 100), (100, 20), (100, 100))


def proof_list(reps, pairs, with_trace_off):
    """Per repetition: item 1 (idle ping) and items 2 and 4 (Linux CUBIC,
    0 % loss, 2xBDP) for each pair, then stack NewReno at 100 Mbit/s, 20 ms,
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
                 "cc": "newreno", "profile": "linux", "duration": 30, "cell": "100-20-0-2", "order": rep}
        out.append(("run", f"stack-trace-r{rep}", dict(stack, trace=True, gate="proof-stack")))
        if with_trace_off:
            out.append(("run", f"stack-notrace-r{rep}", dict(stack, trace=False, gate="proof-notrace")))
    return out


def proof_phase(campaign, phase, slots, reps, pairs):
    smeta = static_meta()

    def worker(slot):
        sub = f"{campaign}/{phase}-s{slot.n}"
        for kind, name, spec in proof_list(reps, pairs, with_trace_off=(phase == "serial")):
            if kind == "ping":
                rd = f"/data/m2/{sub}/{name}"
                if read_volume(slot, f"{rd}/ping.json"):
                    continue
                slot.cleanup()
                p = ping_only(slot, sub, name, spec)
                vol_write(slot.snd, f"{rd}/ping.json", json.dumps(p, sort_keys=True) + "\n")
                log(f"{phase} slot {slot.n} {name}: median {p['median_ms']} p99 {p['p99_ms']}")
            else:
                if run_done(slot, sub, name) is not None:
                    continue
                try:
                    _, s = one_run(slot, sub, name, spec, smeta)
                    log(f"{phase} slot {slot.n} {name}: goodput {s.get('goodput_bps')} valid {s.get('valid')} "
                        f"lateness p99 {s.get('sender_lateness_p99_ns')} max {s.get('sender_lateness_max_ns')}")
                except Exception as e:  # noqa: BLE001
                    log(f"{phase} slot {slot.n} {name}: ERROR {e}")

    threads = [threading.Thread(target=worker, args=(s,)) for s in slots]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def hist_merge(hists):
    out = {}
    for h in hists:
        for k, v in (h or {}).items():
            out[int(k)] = out.get(int(k), 0) + v
    return out


def hist_percentile(h, q):
    """LatenessHistogram::percentile: the inclusive upper edge of the bucket
    holding the sample of rank ceil(q * count) (0 for bucket 0, 2^i - 1 ns)."""
    n = sum(h.values())
    if n == 0:
        return None
    rank = math.ceil(q * n)
    acc = 0
    for i in sorted(h):
        acc += h[i]
        if acc >= rank:
            return 0 if i == 0 else (1 << i) - 1
    return None


def proof_compare(serial, parallel, rel=None, abs_=None):
    """serial/parallel: lists of per-run values. Pass when the parallel
    median is within rel (fraction) or abs_ of the serial median and the
    ranges overlap."""
    s = [x for x in serial if x is not None]
    p = [x for x in parallel if x is not None]
    if not s or not p:
        return {"ok": False, "why": "no data", "serial": s, "parallel": p}
    ms, mp = A.median(s), A.median(p)
    diff = mp - ms
    within = abs(diff) <= (rel * abs(ms) if rel is not None else abs_)
    overlap = A.ranges_overlap(min(s), max(s), min(p), max(p))
    return {"ok": bool(within and overlap), "serial_median": ms, "parallel_median": mp, "diff": diff,
            "serial_range": [min(s), max(s)], "parallel_range": [min(p), max(p)], "within": within,
            "overlap": overlap, "n_serial": len(s), "n_parallel": len(p)}


def proof_report(campaign, reps, pairs):
    """proof.json and proof.md from the serial (slot 0) and parallel (slots
    0 and 1) phases; read through a helper container."""
    dump = sh(["docker", "run", "--rm", "--name", f"{JOB}-rd-{os.getpid()}-{next(_helper_seq)}",
               "-v", f"{VOLUME}:/data:ro", IMAGE, "bash", "-c",
               f"cd /data/m2/{campaign} && for f in */*/ping.json */*/summary.json; do "
               f"[ -e \"$f\" ] && {{ echo \"### $f\"; tr -d '\\n' < \"$f\"; echo; }}; done; true"])
    files = {}
    lines = dump.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("### ") and i + 1 < len(lines):
            files[line[4:]] = json.loads(lines[i + 1])

    phases = {"serial": ["serial-s0"], "parallel": ["parallel-s0", "parallel-s1"]}
    data = {}
    for ph, subs in phases.items():
        for sub in subs:
            for kind, name, spec in proof_list(reps, pairs, with_trace_off=(ph == "serial")):
                data[(sub, name)] = files.get(f"{sub}/{name}/{'ping.json' if kind == 'ping' else 'summary.json'}")
    result = {"campaign": campaign, "reps": reps, "items": [], "notes": []}

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
                (1, f"ping-{bw}-{rtt}-2", "median_ms", None, {"abs_": 0.2}),
                (2, f"rate-{bw}-{rtt}-2", "goodput_bps", None, {"rel": 0.01}),
                (4, f"rate-{bw}-{rtt}-2", "queue", "backlog_max", {"rel": 0.02})):
            ser = vals("serial-s0", prefix, key, sub_key)
            for sub in phases["parallel"]:
                c = proof_compare(ser, vals(sub, prefix, key, sub_key), **crit)
                c.update(item=item, cell=f"{bw} Mbit/s, {rtt} ms, 2xBDP", metric=key if not sub_key else sub_key,
                         parallel_slot=int(sub[-1]))
                result["items"].append(c)
    # Stack NewReno.
    ser_g = vals("serial-s0", "stack-trace", "goodput_bps")
    ser_h = [data.get(("serial-s0", f"stack-trace-r{r}")) for r in range(reps)]
    ser_hist = hist_merge([(x or {}).get("stack_lateness_hist") for x in ser_h])
    for sub in phases["parallel"]:
        c = proof_compare(ser_g, vals(sub, "stack-trace", "goodput_bps"), rel=0.02)
        c.update(item="stack", cell="100 Mbit/s, 20 ms, 0 %, 2xBDP", metric="goodput_bps",
                 parallel_slot=int(sub[-1]))
        result["items"].append(c)
        par_h = [data.get((sub, f"stack-trace-r{r}")) for r in range(reps)]
        par_hist = hist_merge([(x or {}).get("stack_lateness_hist") for x in par_h])
        for q, label in ((0.99, "p99"), (None, "max")):
            if q is None:
                s_v = max([x.get("sender_lateness_max_ns") or 0 for x in ser_h if x] or [0])
                p_v = max([x.get("sender_lateness_max_ns") or 0 for x in par_h if x] or [0])
            else:
                s_v, p_v = hist_percentile(ser_hist, q), hist_percentile(par_hist, q)
            ok = s_v is not None and p_v is not None and p_v <= 2 * max(s_v, 1)
            result["items"].append({"item": "stack", "metric": f"lateness_{label}_ns", "parallel_slot": int(sub[-1]),
                                    "serial": s_v, "parallel": p_v, "ok": ok,
                                    "serial_per_run": vals("serial-s0", "stack-trace", f"sender_lateness_{label}_ns"),
                                    "parallel_per_run": vals(sub, "stack-trace", f"sender_lateness_{label}_ns")})
        result["items"].append({"item": "stack", "metric": "ping_p99_ms", "parallel_slot": int(sub[-1]),
                                "ok": True, "informational": True,
                                **proof_compare(vals("serial-s0", "stack-trace", "qdelay_p99_ms"),
                                                vals(sub, "stack-trace", "qdelay_p99_ms"), abs_=1e9)})
    # sndbuf-limited time on both senders (§5.3).
    lim = {}
    for sub in ["serial-s0"] + phases["parallel"]:
        lim[sub] = {"stack": vals(sub, "stack-trace", "sndbuf_limited_frac"),
                    "linux_100_20": vals(sub, "rate-100-20-2", "sndbuf_limited_frac"),
                    "stack_rwnd": vals(sub, "stack-trace", "rwnd_limited_frac"),
                    "linux_100_20_rwnd": vals(sub, "rate-100-20-2", "rwnd_limited_frac")}
    result["sndbuf_limited"] = lim
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
        "hist_p99_on": hist_percentile(hist_merge([(x or {}).get("stack_lateness_hist") for x in on]), 0.99),
        "hist_p99_off": hist_percentile(hist_merge([(x or {}).get("stack_lateness_hist") for x in off]), 0.99),
    }
    result["valid_runs"] = {f"{sub}/{name}": (v or {}).get("valid") for (sub, name), v in data.items()
                            if not name.startswith("ping")}
    result["passed"] = all(i["ok"] for i in result["items"])
    text = json.dumps(result, indent=1, sort_keys=True) + "\n"
    helper = f"{JOB}-wr-{os.getpid()}"
    sh(["docker", "run", "--rm", "-i", "--name", helper, "-v", f"{VOLUME}:/data", IMAGE, "bash", "-c",
        f"cat > /data/m2/{campaign}/proof.json"], input=text)
    md = proof_markdown(result)
    sh(["docker", "run", "--rm", "-i", "--name", helper, "-v", f"{VOLUME}:/data", IMAGE, "bash", "-c",
        f"cat > /data/m2/{campaign}/proof.md"], input=md)
    return result, md


def _f(x, scale=1.0, nd=2):
    return "-" if x is None else f"{x / scale:.{nd}f}"


def proof_markdown(r):
    lines = [f"Parallel-mode proof, campaign {r['campaign']}, {r['reps']} repetitions: "
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
    t = r["trace_overhead"]
    lines += ["", "Trace overhead (stack NewReno, 100 Mbit/s, 20 ms, 0 %, 2xBDP, serial):",
              f"- goodput on (Mbit/s): {[_f(x, 1e6) for x in t['goodput_on']]}",
              f"- goodput off (Mbit/s): {[_f(x, 1e6) for x in t['goodput_off']]}",
              f"- lateness p99 on/off (ns, per run): {t['lateness_p99_on']} / {t['lateness_p99_off']}",
              f"- lateness max on/off (ns, per run): {t['lateness_max_on']} / {t['lateness_max_off']}",
              f"- pooled lateness p99 on/off (ns): {t['hist_p99_on']} / {t['hist_p99_off']}",
              f"- trace events per run: {t['trace_events']}", "",
              "sndbuf-limited and rwnd-limited fractions of the window:"]
    for sub, v in r["sndbuf_limited"].items():
        lines.append(f"- {sub}: {json.dumps(v)}")
    bad = [k for k, v in r["valid_runs"].items() if v is not True]
    lines += ["", f"Runs not valid: {bad if bad else 'none'}"]
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
    p.add_argument("--slot", type=int, action="append", required=True, help="repeatable: slots to use")
    p.add_argument("--no-rerun", action="store_true", help="do not rerun invalid runs")
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
    p.add_argument("--pairs", default=",".join(f"{b}x{r}" for b, r in PROOF_PAIRS))
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
        out = sh(["docker", "run", "--rm", "--name", f"{JOB}-ls-{os.getpid()}", "-v", f"{VOLUME}:/data", IMAGE,
                  "bash", "-c", f"ls -d /data/m2/{a.campaign}/*/ 2>/dev/null"])
        for d in out.split():
            if "/aside/" not in d:
                run_analysis(["run", d.rstrip("/")])
    elif a.cmd == "tables":
        run_analysis(["tables", a.out, "--campaign", f"/data/m2/{a.campaign}"])
    elif a.cmd == "gate-table":
        gates = [json.loads(sh(["docker", "run", "--rm", "--name", f"{JOB}-cat-{os.getpid()}", "-v",
                                f"{VOLUME}:/data:ro", IMAGE, "cat", f"/data/m2/{c}/gate.json"])) for c in a.campaign]
        print(gate_table(gates), end="")
    elif a.cmd == "run":
        errors = run_plan(a.plan, [Slot(n) for n in a.slot], rerun_invalid=not a.no_rerun)
        return 1 if errors else 0
    elif a.cmd == "expand":
        for r in expand_plan(load_plan(a.plan), a.slots):
            print(json.dumps(r, sort_keys=True))
    elif a.cmd == "plot":
        print(run_plot(a.campaign, a.out), end="")
    elif a.cmd == "proof":
        pairs = [tuple(int(x) for x in p.split("x")) for p in a.pairs.split(",")]
        if a.phase in ("serial", "all"):
            proof_phase(a.campaign, "serial", [Slot(0)], a.reps, pairs)
        if a.phase in ("parallel", "all"):
            proof_phase(a.campaign, "parallel", [Slot(0), Slot(1)], a.reps, pairs)
        if a.phase in ("report", "all"):
            r, md = proof_report(a.campaign, a.reps, pairs)
            print(md, end="")
            return 0 if r["passed"] else 1
    elif a.cmd == "cat":
        print(sh(["docker", "run", "--rm", "--name", f"{JOB}-cat-{os.getpid()}", "-v", f"{VOLUME}:/data:ro",
                  IMAGE, "cat", a.path]), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
