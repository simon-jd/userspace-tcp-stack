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

Environment: UTCP_M2_PREFIX (testbed names, default utcp-m2), UTCP_M2_JOB
(names of the helper containers, default utcp-m2-runner), UTCP_IMAGE,
UTCP_DATA_VOLUME, UTCP_BUILD (build directory below the repository, default
build/tb-gcc-release), UTCP_COMMIT (else the .utcp-commit file, else git).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import random
import shlex
import subprocess
import sys
import time
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

    def slot_cpus(self):
        cpus = []
        for c in self.cpus.values():
            cpus += A.cpu_list(c)
        return ",".join(str(x) for x in sorted(set(cpus)))


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


def run_analysis(args, timeout=900):
    """analyze.py in a helper container on CPUs 16-31 with the volume mounted."""
    name = f"{JOB}-ana-{os.getpid()}-{int(time.time() * 1000) % 100000}"
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
    vol_write(slot.snd, f"{rd}/meta.json", json.dumps(meta, indent=1, sort_keys=True) + "\n")
    vol_write(slot.snd, f"{rd}/shape.txt", shape)
    pre = tb("record.sh", "--slot", slot.n, "pre")
    vol_write(slot.snd, f"{rd}/pre/record.txt", pre)

    caps = [("r1-in", slot.r1, slot.ifs["r1_a"]), ("r2-out", slot.r2, slot.ifs["r2_c"])]
    if spec.get("extra_capture"):
        caps.append(("r1-out", slot.r1, slot.ifs["r1_b"]))
    for name, c, dev in caps:
        dexec_bg(c, f"exec tcpdump -i {dev} -s 128 -B 16384 -n --time-stamp-precision nano "
                    f"-w {rd}/{name}.pcap 2> {rd}/{name}.tcpdump.txt")
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

    impl = spec.get("impl", "linux")
    cc = spec.get("cc", "cubic")
    amount = f"--bytes {spec['bytes']}" if spec.get("bytes") else f"--duration {S:g}"
    if impl == "linux":
        snd_cmd = (f"{BULK} --backend kernel --connect {slot.rcv_ip}:{PORT} --send {amount} "
                   f"--cc {cc} --sample-ms 10 --jsonl {rd}/snd.jsonl")
    else:
        snd_cmd = (f"{BULK} --backend utcp --tun utcp0 --addr {slot.stack_ip} "
                   f"--profile {spec.get('profile', 'linux')} --connect {slot.rcv_ip}:{PORT} --send "
                   f"{amount} --cc {cc} --sample-ms 10 --jsonl {rd}/snd.jsonl "
                   f"--stats {rd}/stats.json {spec.get('stack_args', '')}")
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
           "4: backlog max, % of Q; ping max - base / target (ms) | 3: loss % at 0.1 / 1 (expected count interval) "
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
    elif a.cmd == "cat":
        print(sh(["docker", "run", "--rm", "--name", f"{JOB}-cat-{os.getpid()}", "-v", f"{VOLUME}:/data:ro",
                  IMAGE, "cat", a.path]), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
