#!/usr/bin/env python3
"""Run the registered multi-flow competition on an isolated M2 testbed."""

import argparse
import csv
import datetime
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import matrix as m

SCHEDULE = m.REPO / "docs/results/m2-multiflow/schedule.csv"
SCHEDULE_SHA = "2578224d2af0326873288b34c8d1b102c2f52ebda0edd8b830df0debf3ddf327"
STUDY_ROOT = "/data/m2/m2d-multiflow"
SELF = "/utcp/tools/m2/multiflow.py"


def dump(path, value):
    path = Path(path)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=1, sort_keys=True) + "\n")
    temp.replace(path)


def schedule():
    if m.sha256_file(SCHEDULE) != SCHEDULE_SHA:
        raise ValueError("changed multi-flow schedule")
    with SCHEDULE.open() as stream:
        return list(csv.DictReader(stream))


def specification(row, side, slot):
    duration = int(row["wall_duration_s"])
    flows = []
    roles = row[f"flow_roles_{side}_by_id"].split()
    for k, (role, join, port) in enumerate(
        zip(
            roles,
            row["flow_join_offsets_s"].split(),
            row["listener_ports"].split(),
            strict=True,
        )
    ):
        backend, cc = role.split("/")
        stack = backend == "stack"
        flows.append(
            {
                "id": f"f{k}",
                "backend": backend,
                "cc": cc,
                "port": int(port),
                "join_s": int(join),
                "duration_s": duration - int(join),
                "tun": f"utcp{k}" if stack else None,
                "source_ip": f"198.18.{8 * slot.n + k}.2" if stack else slot.snd_ip,
                "profile": "linux" if stack else None,
            }
        )
    return {
        "pair_order": int(row["pair_order"]),
        "scenario": int(row["scenario"]),
        "rep": int(row["rep"]),
        "side": side,
        "pair_seed": int(row["pair_seed"]),
        "duration_s": duration,
        "flows": flows,
        "bw_mbit": int(row["mbit_s"]),
        "rtt_ms": int(row["rtt_ms"]),
        "loss_pct": float(row["loss_pct"]),
        "queue_bdp": float(row["queue_bdp"]),
        "side_first": row["side_first"],
    }


def write_meta(slot, path, value):
    m.vol_write(slot.snd, str(path), json.dumps(value, indent=1, sort_keys=True) + "\n")


def endpoint_argv(meta, flow, role, path):
    if role == "rcv":
        return [
            m.BULK,
            "--backend",
            "kernel",
            "--listen",
            str(flow["port"]),
            "--recv",
            "--sample-ms",
            "10",
            "--jsonl",
            str(path / "rcv.jsonl"),
        ]
    stack = flow["backend"] == "stack"
    args = [m.BULK, "--backend", "utcp" if stack else "kernel"]
    if stack:
        args += [
            "--tun",
            flow["tun"],
            "--addr",
            flow["source_ip"],
            "--profile",
            flow["profile"],
            "--stats",
            str(path / "stats.json"),
            "--trace",
            str(path / "trace.jsonl"),
        ]
        for value in meta["stack_set"]:
            args += ["--set", value]
    return args + [
        "--connect",
        f"{meta['rcv_ip']}:{flow['port']}",
        "--send",
        "--duration",
        str(flow["duration_s"]),
        "--cc",
        flow["cc"],
        "--sample-ms",
        "10",
        "--jsonl",
        str(path / "snd.jsonl"),
    ]


def endpoint_group(rd, role):
    """This single in-namespace launcher releases peers without Docker exec jitter."""
    rd = Path(rd)
    meta = json.loads((rd / "meta.json").read_text())
    planned = []
    children = []
    for flow in meta["flows"]:
        path = rd / "flows" / flow["id"]
        path.mkdir(parents=True, exist_ok=True)
        args = endpoint_argv(meta, flow, role, path)
        dump(path / f"{role}.argv.json", args)
        planned.append((flow["join_s"] if role == "snd" else 0, args, path))
    release_ns = time.monotonic_ns() + 100_000_000 if role == "snd" else None
    dump(
        rd / f"{role}.release.json",
        {"release_ns": release_ns, "clock": "CLOCK_MONOTONIC"},
    )
    try:
        for offset, args, path in planned:
            target = release_ns + offset * 10**9 if release_ns is not None else None
            if target is not None:
                time.sleep(max(0, (target - time.monotonic_ns()) / 1e9))
            with (path / f"{role}.out").open("w") as output:
                before = time.monotonic_ns()
                proc = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT)
                after = time.monotonic_ns()
            children.append((path, proc))
            dump(
                path / f"{role}.launch.json",
                {
                    "target_ns": target,
                    "before_popen_ns": before,
                    "after_popen_ns": after,
                    "pid": proc.pid,
                },
            )
        limit = time.monotonic() + meta["duration_s"] + 140
        for path, proc in children:
            rc = proc.wait(timeout=max(0, limit - time.monotonic()))
            (path / f"{role}.exit").write_text(f"{rc}\n")
    finally:
        for path, proc in children:
            if proc.poll() is None:
                proc.kill()
            rc = proc.wait()
            (path / f"{role}.exit").write_text(f"{rc}\n")
    (rd / f"{role}.done").write_text("done\n")


def stop_capture(slot):
    m.dexec(slot.snd, "pkill -INT -x ping", check=False)
    m.dexec(
        slot.r2,
        'if test -s /run/utcp-tbf-sampler.pid; then kill "$(cat /run/utcp-tbf-sampler.pid)"; fi',
        check=False,
    )
    time.sleep(1.5)
    for container in (slot.r1, slot.r2):
        m.dexec(container, "pkill -INT -x tcpdump", check=False)
    for container in (slot.r1, slot.r2):
        m.wait_for(
            container,
            "! ps -eo stat=,comm= | awk '$2 == \"tcpdump\" && $1 !~ /^Z/' | grep -q .",
            "capture completion",
            timeout=30,
        )


def acquire(slot, row, side, stage, attempt, static, expected):
    meta = specification(row, side, slot)
    run = f"p{meta['pair_order']:03}-a{attempt:02}-{side}"
    rd = f"{STUDY_ROOT}/{stage}/{run}"
    # A terminated host may leave an in-container parent awaiting the late
    # join. Stop only previous endpoint launchers before clearing their children.
    cleanup_script = """import os, pathlib, signal, sys
for entry in pathlib.Path('/proc').glob('[0-9]*'):
    try:
        argv=(entry/'cmdline').read_bytes().split(b'\\0')
        if sys.argv[1].encode() in argv and b'endpoints' in argv and int(entry.name)!=os.getpid():
            os.kill(int(entry.name),signal.SIGTERM)
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        continue
"""
    for container in (slot.snd, slot.rcv):
        m.sh(["docker", "exec", container, "python3", "-Ic", cleanup_script, SELF])
    slot.cleanup()
    m.dexec(
        slot.snd,
        f"set -e; mkdir -p {STUDY_ROOT}/{stage}; mkdir {rd}; mkdir -p {rd}/pre {rd}/post",
    )
    meta.update(
        static,
        stage=stage,
        attempt=attempt,
        run=run,
        slot=slot.n,
        timing=slot.timing,
        campaign=f"m2d-multiflow/{stage}",
        schedule_sha256=SCHEDULE_SHA,
        start_utc=datetime.datetime.now(datetime.UTC).isoformat(),
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        rcv_ip=slot.rcv_ip,
        snd_ip=slot.snd_ip,
        containers=slot.containers(),
        ifaces=slot.ifs,
        cpusets=slot.cpus,
        slot_cpus=slot.slot_cpus(),
        stack_set=m.stack_sets(slot.gso_ipv4_max_size()),
    )
    write_meta(slot, f"{rd}/meta.json", meta)
    shape = m.tb(
        "shape.sh",
        "--slot",
        slot.n,
        "--bw",
        meta["bw_mbit"],
        "--rtt",
        meta["rtt_ms"],
        "--queue-bdp",
        meta["queue_bdp"],
        "--seed",
        meta["pair_seed"],
    )
    m.vol_write(slot.snd, f"{rd}/shape.txt", shape)
    fields = next(
        line.split() for line in shape.splitlines() if line.startswith("shape: slot")
    )
    shape_values = dict(zip(fields[3::2], fields[4::2]))
    meta.update(
        {k: int(shape_values[k]) for k in ("queue_bytes", "burst_bytes", "bdp_bytes")}
    )
    for container in (slot.snd, slot.rcv):
        m.dexec(container, "ip tcp_metrics flush")
    pre = m.tb("record.sh", "--slot", slot.n, "pre")
    m.vol_write(slot.snd, f"{rd}/pre/record.txt", pre)
    rec = m.A.parse_record(pre)
    meta.update(
        reuse_key=m.reuse_key(static, m.sysctl_dump(pre)),
        uptime=rec.get(("host", "uptime"), []),
        top_cpu=rec.get(("host", "top"), []),
        threads_on_8_15=rec.get(("host", "threads on 8-15")),
        iproute2=m.sh(["docker", "exec", slot.r1, "tc", "-V"]).strip(),
    )
    write_meta(slot, f"{rd}/meta.json", meta)
    if expected and expected != meta["reuse_key"]:
        raise RuntimeError("runtime fingerprint changed before release")
    try:
        for name, container, iface in (
            ("r1-in", slot.r1, slot.ifs["r1_a"]),
            ("r2-out", slot.r2, slot.ifs["r2_c"]),
        ):
            m.dexec_bg(
                container,
                f"exec tcpdump -i {iface} -s 128 -B 16384 -n --time-stamp-precision nano "
                f"-w {rd}/{name}.pcap 'not ether multicast' 2> {rd}/{name}.tcpdump.txt",
            )
            m.wait_for(
                container, f"grep -q 'listening on' {rd}/{name}.tcpdump.txt", name
            )
        m.dexec_bg(
            slot.r2,
            f"echo $$ > /run/utcp-tbf-sampler.pid; exec > {rd}/tbf.txt; "
            f'while :; do printf "@ %s\\n" "$EPOCHREALTIME"; tc -s qdisc show dev {slot.ifs["r2_c"]}; sleep 0.01; done',
        )
        for role in ("rcv", "snd"):
            if role == "snd":
                m.dexec_bg(
                    slot.snd,
                    f"exec ping -D -O -i 0.05 -s 56 {slot.rcv_ip} > {rd}/ping.txt 2>&1",
                )
                time.sleep(3.1)
            container = slot.snd if role == "snd" else slot.rcv
            # Full command is retained by the parent, including early launch errors.
            cmd = f"python3 -IB {SELF} endpoints {rd} {role} >{rd}/{role}.supervisor.log 2>&1"
            if role == "snd":
                m.dexec(container, cmd, timeout=meta["duration_s"] + 160)
            else:
                m.dexec_bg(container, cmd)
            if role == "rcv":
                ports = " ".join(str(f["port"]) for f in meta["flows"])
                m.wait_for(
                    slot.rcv,
                    f"for p in {ports}; do ss -Hltn sport = :$p | grep -q LISTEN || exit 1; done",
                    "all distinct listeners",
                    timeout=20,
                )
        for role, container in (("snd", slot.snd), ("rcv", slot.rcv)):
            m.wait_for(
                container,
                f"test -f {rd}/{role}.done",
                f"{role} completion",
                timeout=meta["duration_s"] + 150,
            )
        tests = " or ".join(
            f"dport = :{f['port']} or sport = :{f['port']}" for f in meta["flows"]
        )
        for role, container in (("snd", slot.snd), ("rcv", slot.rcv)):
            output = m.dexec(
                container, f"ss -Htn state connected exclude time-wait '( {tests} )'"
            )
            if output.strip():
                m.wait_for(
                    container,
                    f"! ss -Htn state connected exclude time-wait '( {tests} )' | grep -q .",
                    f"{role} socket close",
                    timeout=30,
                )
            m.vol_write(
                container,
                f"{rd}/{role}.closed",
                "socket tables contain no connected non-TIME_WAIT sockets\n",
            )
    finally:
        stop_capture(slot)
        post = m.tb("record.sh", "--slot", slot.n, "post")
        m.vol_write(slot.snd, f"{rd}/post/record.txt", post)
        meta["post_reuse_key"] = m.reuse_key(static, m.sysctl_dump(post))
        meta["end_utc"] = datetime.datetime.now(datetime.UTC).isoformat()
        write_meta(slot, f"{rd}/meta.json", meta)
    if meta["post_reuse_key"] != meta["reuse_key"]:
        raise RuntimeError("runtime fingerprint changed during scenario")
    return rd


def attempt_status(attempts):
    """Only a fully closed, adjudicated pair may advance its schedule row."""
    if not attempts:
        return 1, False
    ordinals = sorted(attempts)
    if ordinals != list(range(1, ordinals[-1] + 1)):
        raise ValueError("gap in attempt ordinals")
    for ordinal in ordinals:
        if attempts[ordinal] == {"test": True, "baseline": True}:
            if ordinal != ordinals[-1]:
                raise ValueError("retry follows a valid complete pair")
            return ordinal, True
    return ordinals[-1] + 1, False


def inventory(slot, stage, key):
    base = Path(STUDY_ROOT) / stage
    # Re-read evidence at every program start. Directory creation records an
    # attempt even if a supervisor interruption preceded its first metadata.
    code = """import hashlib, json, pathlib, sys
p=pathlib.Path(sys.argv[1])
for d in sorted(p.glob('p*-a*-*')):
    def read(f):
        return json.loads((d/f).read_text()) if (d/f).is_file() else {}
    q=read('qualification.json')
    if q:
        data=(d/'summary.json').read_bytes()
        if hashlib.sha256(data).hexdigest()!=q.get('summary_sha256') or json.loads(data).get('valid') is not q.get('valid'):
            raise ValueError('changed physical attempt summary: '+d.name)
    print(json.dumps([d.name,read('meta.json').get('reuse_key'),q]))
"""
    out = m.sh(["docker", "exec", slot.snd, "python3", "-Ic", code, str(base)])
    groups = {}
    for line in out.splitlines():
        name, observed, qualification = json.loads(line)
        match = re.fullmatch(r"p(\d{3})-a(\d{2})-(test|baseline)", name)
        if not match:
            raise ValueError(f"invalid physical attempt name {name}")
        pair, attempt, side = match.groups()
        if observed and observed != key:
            raise ValueError(f"changed runtime for attempt {name}")
        valid = qualification.get("valid") is True
        if qualification and (
            qualification.get("name") != name or qualification.get("reuse_key") != key
        ):
            raise ValueError(f"mismatched qualification for {name}")
        groups.setdefault(int(pair), {}).setdefault(int(attempt), {})[side] = valid
    return groups


def adjudicate(slot, rd, gate, key):
    code = "/utcp/docs/results/m2-multiflow/study.py"
    prefix = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cpuset-cpus",
        "16-31",
        "--name",
        f"{m.JOB}-judge-{os.getpid()}",
        "-v",
        f"{m.VOLUME}:/data",
        "-v",
        f"{m.REPO}:/utcp:ro",
        m.IMAGE,
        "nice",
        "-n",
        "10",
        "python3",
        "-IB",
        code,
    ]
    m.sh(prefix + ["capture", rd], timeout=900)
    check = subprocess.run(
        prefix
        + [
            "run",
            rd,
            "--schedule",
            "/utcp/docs/results/m2-multiflow/schedule.csv",
            "--gate",
            f"/data/m2/{gate}",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if check.returncode not in (0, 1):
        raise RuntimeError(f"analysis process failed: {check.stderr[-2000:]}")
    result = json.loads(check.stdout)
    if not isinstance(result.get("valid"), bool) or result["valid"] != (
        check.returncode == 0
    ):
        raise ValueError("inconsistent study verdict")
    write_meta(slot, f"{rd}/summary.json", result)
    write_meta(
        slot,
        f"{rd}/qualification.json",
        {
            "name": Path(rd).name,
            "valid": result["valid"],
            "reuse_key": key,
            "summary_sha256": m.dexec(slot.snd, f"sha256sum {rd}/summary.json").split()[
                0
            ],
        },
    )
    return result["valid"]


def production(gate, proof):
    slot = m.Slot(0)
    if not slot.timing:
        raise RuntimeError("production requires the assigned slot 0 timing placement")
    other = m.sh(["docker", "ps", "--format", "{{.Names}}"]).splitlines()
    if any(name.startswith(f"{m.PREFIX}-s1-") for name in other):
        raise RuntimeError("slot 1 must be down for serial production")
    static = m.static_meta()
    if not static["bulk_sha256"] or not static["core_sha256"]:
        raise RuntimeError("missing frozen binaries")
    key = m.current_key(slot, static)
    m.check_gate(slot, [gate], key)
    files = m.proof_files(proof)
    finding = m.proof_evaluate(files, proof, 5, (), "cubic")
    if (
        finding["notes"]
        or finding["evidence_errors"]
        or len(finding["valid_runs"]) != 15
        or not all(finding["valid_runs"].values())
        or files["proof-config.json"]["reuse_key"] != key
    ):
        raise RuntimeError("missing source-bound same-key fifteen-transfer proof")
    rows = schedule()
    groups = inventory(slot, "production", key)
    if any(pair < 1 or pair > len(rows) for pair in groups):
        raise RuntimeError("unknown registered pair")
    used_retries = {}
    # In row order, every failed attempt (partial or invalid on either side)
    # consumes one retry from the shared scenario budget.
    for row in rows:
        pair, scenario = int(row["pair_order"]), int(row["scenario"])
        attempts = groups.get(pair, {})
        ordinal, complete = attempt_status(attempts)
        invalid_count = sum(
            sides != {"test": True, "baseline": True} for sides in attempts.values()
        )
        used_retries[scenario] = used_retries.get(scenario, 0) + invalid_count
        if complete:
            continue
        while used_retries[scenario] <= m.A.RERUN_CAP:
            side1 = row["side_first"]
            sides = (side1, "baseline" if side1 == "test" else "test")
            validity = []
            for side in sides:
                m.log(f"pair {pair}/50, attempt {ordinal}, {side}, key {key[:12]}")
                rd = acquire(slot, row, side, "production", ordinal, static, key)
                validity.append(adjudicate(slot, rd, gate, key))
            if all(validity):
                break
            ordinal += 1
            used_retries[scenario] += 1
        else:
            m.log(f"scenario {scenario} exhausted its preregistered cap")
    final = inventory(slot, "production", key)
    counts = {pair: attempt_status(attempts)[1] for pair, attempts in final.items()}
    receipt = {
        "reuse_key": key,
        "gate": gate,
        "proof": proof,
        "schedule_sha256": SCHEDULE_SHA,
        "valid_pairs": sum(counts.values()),
        "planned_pairs": len(rows),
        "invalid_attempts": used_retries,
    }
    write_meta(slot, f"{STUDY_ROOT}/production-status.json", receipt)
    return receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    ep = sub.add_parser("endpoints")
    ep.add_argument("directory")
    ep.add_argument("role", choices=("snd", "rcv"))
    one = sub.add_parser("rehearse")
    one.add_argument("--pair", type=int, required=True, choices=range(1, 51))
    one.add_argument("--side", choices=("test", "baseline"), required=True)
    one.add_argument("--attempt", type=int, required=True, choices=range(1, 100))
    prod = sub.add_parser("produce")
    prod.add_argument("--gate", required=True)
    prod.add_argument("--proof", required=True)
    args = p.parse_args()
    if args.command == "produce":
        import fcntl

        lockdir = m.REPO / ".logs"
        lockdir.mkdir(exist_ok=True)
        with (lockdir / "multiflow-acquisition.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(production(args.gate, args.proof)), flush=True)
        return
    if args.command == "endpoints":
        endpoint_group(args.directory, args.role)
        return
    slot = m.Slot(2)
    if slot.timing or set(slot.cpus.values()) != {"16-31"}:
        raise RuntimeError("rehearsal requires the non-timing placement")
    print(
        acquire(
            slot,
            schedule()[args.pair - 1],
            args.side,
            "rehearsal",
            args.attempt,
            m.static_meta(),
            None,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
