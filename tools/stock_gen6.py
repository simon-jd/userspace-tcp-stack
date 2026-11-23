#!/usr/bin/env python3
"""Run or verify the original stock Gen6 Stack sweep and serialized replays."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

PROFILE = "gen6-stock-v1"
GENERATED = ("--gen-version", "6", "--nodes", "stack", "--strict-fast-rexmit")
SERIALIZED = ("--strict-fast-rexmit",)
WORLD_VERDICTS = {
    "ok", "stream", "termination", "inflight", "progress", "leak",
    "stuck", "livelock", "workload", "pacing",
}
CAPTURES = tuple(f"{node}.{direction}.pcap" for node in "ab" for direction in ("ingress", "egress"))
ARTIFACTS = ("result.jsonl", "scenario.txt", "trace.jsonl", *CAPTURES)
WORKTREE = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encode_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def stamp(path):
    return {"sha256": digest(path), "bytes": path.stat().st_size}


def replace_text(path, data):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as temp:
        temp.write(data)
        temp.flush()
        os.fsync(temp.fileno())
        temporary = Path(temp.name)
    temporary.replace(path)


@contextmanager
def staged(final):
    """Publish result and receipt together, leaving a killed run's staging outside coverage."""
    require(not final.exists(), f"already published: {final}")
    temporary = Path(tempfile.mkdtemp(prefix=f".{final.name}-", dir=final.parent))
    try:
        yield temporary
        for path in temporary.iterdir():
            with path.open("rb") as handle:
                os.fsync(handle.fileno())
        sync_dir(temporary)
        temporary.rename(final)
        sync_dir(final.parent)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def sync_dir(path):
    fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load(path):
    return json.loads(path.read_text())


def git(*args):
    return subprocess.check_output(("git", "-C", WORKTREE, *args), text=True).strip()


def replay_seeds(plan):
    lo, hi = plan["seed_range"]
    return range((lo + 499) // 500 * 500, hi, 500)


def chunks(plan):
    lo, hi = plan["seed_range"]
    size = plan["shard_size"]
    return [(start, min(start + size, hi)) for start in range(lo, hi, size)]


def run_plan(args):
    require(not git("status", "--porcelain", "--untracked-files=no"), "commit tracked changes before running")
    require(os.getpriority(os.PRIO_PROCESS, 0) == 10, "launch runner with nice -n 10")
    require(set(args.cpus) <= os.sched_getaffinity(0), "requested CPU outside process affinity")
    plan = {
        "schema": 1,
        "profile": PROFILE,
        "source_commit": git("rev-parse", "HEAD"),
        "source_tree": git("rev-parse", "HEAD^{tree}"),
        "binary": stamp(args.sim),
        "runner_sha256": digest(Path(__file__)),
        "generated_arguments": list(GENERATED),
        "serialized_arguments": list(SERIALIZED),
        "seed_range": list(args.seeds),
        "shard_size": args.shard_size,
        "timeout_s": args.timeout,
        "cpu_ids": args.cpus,
        "nice": 10,
        "replay_modulus": 500,
    }
    path = args.out / "replay-seeds.txt"
    expected_seeds = "".join(f"{seed}\n" for seed in replay_seeds(plan))
    if not path.exists():
        replace_text(path, expected_seeds)
    require(path.read_text() == expected_seeds, f"registered seed list differs: {path}")
    plan["replay_seeds_sha256"] = digest(path)
    path = args.out / "plan.json"
    if path.exists():
        require(load(path) == plan, f"existing plan differs: {path}")
    else:
        replace_text(path, encode_json(plan))
    print(f"{PROFILE} commit={plan['source_commit']} binary_sha256={plan['binary']['sha256']}")
    return plan, digest(path)


def read_plan(out):
    path = out / "plan.json"
    plan = load(path)
    require(plan["schema"] == 1 and plan["profile"] == PROFILE and
            plan["generated_arguments"] == list(GENERATED) and
            plan["serialized_arguments"] == list(SERIALIZED),
            "unsupported sweep plan")
    require(plan["replay_modulus"] == 500, "unexpected replay modulus")
    seed_list = out / "replay-seeds.txt"
    require(seed_list.read_text() == "".join(f"{seed}\n" for seed in replay_seeds(plan)) and
            digest(seed_list) == plan["replay_seeds_sha256"], "invalid registered replay seed list")
    return plan, digest(path)


def strict_row(row, seed):
    require(type(row.get("seed")) is int and row["seed"] == seed, f"expected seed {seed}")
    verdict = row.get("verdict")
    if verdict in ("timeout", "crash"):
        require(row.get("kind") == "process" and isinstance(row.get("stderr"), str),
                f"seed {seed}: missing process diagnosis")
        return
    require(verdict in WORLD_VERDICTS and row.get("strict_fast_rexmit") is True and
            row.get("gen_version") == 6 and row.get("nodes") == "stack",
            f"seed {seed}: unexpected simulator result")
    require(re.fullmatch(r"[0-9a-f]{16}", row.get("digest", "")),
            f"seed {seed}: missing run digest")


def command(sim, cpu, *args, serialized=False):
    profile = SERIALIZED if serialized else GENERATED
    return ("taskset", "-c", str(cpu), str(sim), *profile, *args)


def simulate_range(sim, cpu, lo, hi, timeout):
    """A simulator child may stop at one seed. Keep that terminal outcome, then advance."""
    seed = lo
    while seed < hi:
        with tempfile.TemporaryFile() as stderr:
            cmd = command(sim, cpu, "--seed-range", f"{seed}:{hi}")
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr) as proc:
                timed_out = False
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(proc.stdout, selectors.EVENT_READ)
                        deadline = time.monotonic() + timeout
                        pending = b""
                        while True:
                            remaining = max(deadline - time.monotonic(), 0)
                            if not selector.select(remaining):
                                timed_out = True
                                proc.kill()
                                break
                            data = os.read(proc.stdout.fileno(), 65536)
                            if not data:
                                require(not pending or seed < hi, f"trailing output after seed {seed - 1}")
                                break
                            lines = (pending + data).split(b"\n")
                            pending = lines.pop()
                            for line in lines:
                                require(seed < hi, f"extra result after seed {seed - 1}")
                                row = json.loads(line)
                                strict_row(row, seed)
                                require(row["verdict"] in WORLD_VERDICTS, "unexpected process row")
                                yield row
                                seed += 1
                                deadline = time.monotonic() + timeout
                    rc = proc.wait(timeout=timeout)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
            stderr.seek(0)
            diagnostic = stderr.read().decode(errors="replace")
        if seed == hi:
            require(not timed_out and rc in (0, 1) and not diagnostic,
                    f"simulator exited after final seed {seed - 1}: {rc} {diagnostic}")
            continue
        require(timed_out or rc < 0 or rc >= 128,
                f"unexpected exit {rc} before seed {seed} completed: {diagnostic}")
        row = {"seed": seed, "kind": "process",
               "verdict": "timeout" if timed_out else "crash", "exit": rc, "stderr": diagnostic}
        reported = re.search(r"utcp-sim: (?:abort|crash) (\{.*\})", diagnostic)
        if reported:
            report = json.loads(reported[1])
            require(report["seed"] == seed, f"process failure reported a different seed: {report['seed']}")
            row["process_report"] = report
        yield row
        seed += 1


def shard_dir(out, lo, hi):
    return out / "primary" / f"{lo:07d}-{hi:07d}"


def primary_receipt(lo, hi, plan_hash, counts, data):
    return {"kind": "primary", "range": [lo, hi], "plan_sha256": plan_hash,
            "verdict_counts": dict(counts), "results": stamp(data)}


def delivery(row):
    if row["verdict"] != "ok":
        return "failed"
    if row["a_received"] == row["b_requested"] and row["b_received"] == row["a_requested"]:
        return "complete"
    if row["a_received"] or row["b_received"]:
        return "partial"
    return "no_payload"


def verify_shard(out, lo, hi, plan_hash, selected, failures=None):
    root = shard_dir(out, lo, hi)
    data = root / "results.jsonl.gz"
    require({item.name for item in root.iterdir()} == {"results.jsonl.gz", "receipt.json"},
            f"{root}: unexpected shard files")
    counts, deliveries = Counter(), Counter()
    with gzip.open(data, "rt") as handle:
        for seed in range(lo, hi):
            line = handle.readline()
            require(line, f"{root}: missing seed {seed}")
            row = json.loads(line)
            strict_row(row, seed)
            counts[row["verdict"]] += 1
            deliveries[delivery(row)] += 1
            if seed % 500 == 0:
                selected[seed] = row
            if failures is not None and row["verdict"] != "ok":
                failures[seed] = row
        require(not handle.readline(), f"{root}: too many results")
    require(load(root / "receipt.json") == primary_receipt(lo, hi, plan_hash, counts, data),
            f"{root}: primary receipt differs")
    return counts, deliveries


def run_shard(args, plan_hash, cpu, lo, hi):
    final = shard_dir(args.out, lo, hi)
    if final.exists():
        verify_shard(args.out, lo, hi, plan_hash, {})
        return
    counts = Counter()
    with staged(final) as target:
        data = target / "results.jsonl.gz"
        with data.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as zipped:
            for row in simulate_range(args.sim, cpu, lo, hi, args.timeout):
                zipped.write(encode_json(row).encode())
                counts[row["verdict"]] += 1
        require(sum(counts.values()) == hi - lo, "incomplete shard")
        (target / "receipt.json").write_text(encode_json(primary_receipt(lo, hi, plan_hash, counts, data)))


def deterministic(row):
    return {key: value for key, value in row.items() if key != "wall_ms"}


def result_difference(first, second):
    first, second = deterministic(first), deterministic(second)
    return {key: [first.get(key), second.get(key)] for key in sorted(first.keys() | second.keys())
            if key not in first or key not in second or first[key] != second[key]}


def verify_artifacts(root, seed, primary):
    row = json.loads((root / "result.jsonl").read_text())
    strict_row(row, seed)
    require(not result_difference(primary, row), f"seed {seed}: result fields differ")
    files = {name: stamp(root / name) for name in ARTIFACTS}
    scenario = (root / "scenario.txt").read_text()
    require(f"gen_version=6\nseed={seed}\nnodes=stack\n" in scenario,
            f"seed {seed}: serialized scenario identity differs")
    require("node.0.test_isn=" in scenario and "node.1.test_isn=" in scenario and
            "node.0.renege_ppm=" in scenario and "node.1.renege_ppm=" in scenario,
            f"seed {seed}: original node fields missing")
    require(files["trace.jsonl"]["bytes"] > 0, f"seed {seed}: empty trace")
    for name in CAPTURES:
        require(files[name]["bytes"] > 24, f"seed {seed}: empty capture {name}")
    if primary["verdict"] != "ok":
        repeat = json.loads((root / "repeat.jsonl").read_text())
        strict_row(repeat, seed)
        require(not result_difference(primary, repeat), f"seed {seed}: second replay differs")
        files["repeat.jsonl"] = stamp(root / "repeat.jsonl")
    return files


def replay_dir(out, seed):
    return out / "replay" / f"seed-{seed}"


def replay_start(seed, plan_hash, primary):
    return {"kind": "replay", "seed": seed, "plan_sha256": plan_hash,
            "primary_sha256": hashlib.sha256(encode_json(primary).encode()).hexdigest()}


def verify_replay(out, seed, plan_hash, primary):
    root = replay_dir(out, seed)
    receipt = load(root / "receipt.json")
    expected = replay_start(seed, plan_hash, primary)
    if receipt.get("status") == "matched":
        expected.update(status="matched", files=verify_artifacts(root, seed, primary))
        expected_names = {"receipt.json", *ARTIFACTS}
        if primary["verdict"] != "ok":
            expected_names.add("repeat.jsonl")
        require({item.name for item in root.iterdir()} == expected_names,
                f"seed {seed}: unexpected capture files")
    else:
        require(receipt.get("status") == "failed" and isinstance(receipt.get("detail"), dict),
                f"seed {seed}: invalid replay outcome")
        expected.update(status="failed", detail=receipt["detail"])
        require({item.name for item in root.iterdir()} == {"receipt.json"},
                f"seed {seed}: failed replay retained unexpected files")
    require(receipt == expected, f"seed {seed}: replay receipt differs")
    return receipt["status"]


def capture_replay(args, cpu, target, seed, primary):
    # A rejected replay can retain a diagnosis in its receipt. Its raw staging
    # is ephemeral and does not become part of the capture collection.
    with tempfile.TemporaryDirectory(prefix=".capture-", dir=args.out) as temp:
        work = Path(temp)
        files = work / f"seed-{seed}"
        files.mkdir()
        generated = subprocess.run(command(args.sim, cpu, "--seed", str(seed), "--dump-scenario"),
                                   capture_output=True, timeout=args.timeout, check=False)
        if generated.returncode != 0 or generated.stderr or not generated.stdout:
            return {"status": "failed", "detail": {"stage": "generate", "exit": generated.returncode,
                    "stderr": generated.stderr.decode(errors="replace")}}
        (files / "scenario.txt").write_bytes(generated.stdout)
        cmd = command(args.sim, cpu, "--scenario", str(files / "scenario.txt"), "--pcap", str(work),
                      "--trace", str(files / "trace.jsonl"), serialized=True)
        try:
            process = subprocess.run(cmd, capture_output=True, timeout=args.timeout, check=False)
        except subprocess.TimeoutExpired as error:
            return {"status": "failed", "detail": {"timeout": args.timeout,
                    "stderr": (error.stderr or b"").decode(errors="replace")}}
        if process.returncode != (0 if primary["verdict"] == "ok" else 1) or process.stderr:
            return {"status": "failed", "detail": {"exit": process.returncode,
                    "stdout": process.stdout.decode(errors="replace"),
                    "stderr": process.stderr.decode(errors="replace")}}
        if (files / "scenario.txt").read_bytes() != generated.stdout:
            return {"status": "failed", "detail": {"stage": "scenario", "error": "capture changed scenario"}}
        (files / "result.jsonl").write_bytes(process.stdout)
        if primary["verdict"] != "ok":
            repeat = subprocess.run(command(args.sim, cpu, "--scenario", str(files / "scenario.txt"),
                                            serialized=True), capture_output=True, timeout=args.timeout,
                                    check=False)
            if repeat.returncode != 1 or repeat.stderr:
                return {"status": "failed", "detail": {"stage": "repeat", "exit": repeat.returncode,
                        "stdout": repeat.stdout.decode(errors="replace"),
                        "stderr": repeat.stderr.decode(errors="replace")}}
            (files / "repeat.jsonl").write_bytes(repeat.stdout)
        try:
            hashes = verify_artifacts(files, seed, primary)
        except (OSError, ValueError) as error:
            return {"status": "failed", "detail": {"verification": str(error),
                    "stdout": process.stdout.decode(errors="replace")}}
        for name in hashes:
            (files / name).rename(target / name)
        return {"status": "matched", "files": hashes}


def run_replay(args, plan_hash, cpu, seed, primary):
    final = replay_dir(args.out, seed)
    if final.exists():
        verify_replay(args.out, seed, plan_hash, primary)
        return
    with staged(final) as target:
        receipt = replay_start(seed, plan_hash, primary)
        receipt.update(capture_replay(args, cpu, target, seed, primary))
        (target / "receipt.json").write_text(encode_json(receipt))


def parallel(cpus, jobs, action, label):
    available = queue.Queue()
    for cpu in cpus:
        available.put(cpu)

    def run(job):
        cpu = available.get()
        try:
            action(cpu, *job)
        finally:
            available.put(cpu)

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=len(cpus)) as pool:
        pending = [pool.submit(run, job) for job in jobs]
        try:
            for done, future in enumerate(as_completed(pending), 1):
                future.result()
                if done == 1 or done % 10 == 0 or done == len(pending):
                    elapsed = time.monotonic() - started
                    print(f"{label}: {done}/{len(pending)} complete ({elapsed:.1f}s)", flush=True)
        except BaseException:
            for future in pending:
                future.cancel()
            raise


def verify_primary(out, plan, plan_hash):
    selected, failures = {}, {}
    counts, deliveries = Counter(), Counter()
    expected_names = set()
    for lo, hi in chunks(plan):
        expected_names.add(shard_dir(out, lo, hi).name)
        verdict_count, delivery_count = verify_shard(out, lo, hi, plan_hash, selected, failures)
        counts.update(verdict_count)
        deliveries.update(delivery_count)
    require({path.name for path in (out / "primary").iterdir() if not path.name.startswith(".")}
            == expected_names, "unexpected primary shards")
    require(list(selected) == list(replay_seeds(plan)), "primary coverage differs from registered replay list")
    return counts, deliveries, selected, failures


def summary(out, plan, plan_hash, counts, deliveries, selected, failures):
    root = out / "replay"
    all_replays = dict(selected)
    all_replays.update(failures)
    status = Counter(verify_replay(out, seed, plan_hash, primary)
                     for seed, primary in sorted(all_replays.items()))
    require({path.name for path in root.iterdir() if not path.name.startswith(".")} ==
            {replay_dir(out, seed).name for seed in all_replays}, "unexpected replay directories")
    lo, hi = plan["seed_range"]
    return {"plan_sha256": plan_hash, "profile": PROFILE, "source_commit": plan["source_commit"],
            "seed_count": hi - lo, "verdict_counts": dict(counts), "delivery_counts": dict(deliveries),
            "registered_replay_count": len(selected), "failure_seeds": list(failures),
            "extra_failure_replay_count": len(set(failures) - set(selected)),
            "replay_counts": dict(status),
            "passed": counts["ok"] == hi - lo and status["matched"] == len(all_replays)}


def execute(args):
    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / ".run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan, plan_hash = run_plan(args)
        for directory in ("primary", "replay"):
            (args.out / directory).mkdir(exist_ok=True)
        if args.phase in ("all", "primary"):
            parallel(args.cpus, chunks(plan), lambda cpu, lo, hi: run_shard(args, plan_hash, cpu, lo, hi),
                     "primary shards")
        counts, deliveries, selected, failures = verify_primary(args.out, plan, plan_hash)
        print(encode_json({"verdict_counts": dict(counts), "delivery_counts": dict(deliveries),
                           "registered_replay_count": len(selected), "failure_count": len(failures)}), end="")
        if args.phase == "primary":
            return int(counts["ok"] != sum(counts.values()))
        all_replays = dict(selected)
        all_replays.update(failures)
        parallel(args.cpus, sorted(all_replays.items()),
                 lambda cpu, seed, row: run_replay(args, plan_hash, cpu, seed, row),
                 "registered replays")
        result = summary(args.out, plan, plan_hash, counts, deliveries, selected, failures)
        replace_text(args.out / "summary.json", encode_json(result))
        print(encode_json(result), end="")
        return int(not result["passed"])


def verify(out):
    plan, plan_hash = read_plan(out)
    counts, deliveries, selected, failures = verify_primary(out, plan, plan_hash)
    result = summary(out, plan, plan_hash, counts, deliveries, selected, failures)
    require(load(out / "summary.json") == result, "summary differs")
    print(encode_json(result), end="")
    return int(not result["passed"])


def seed_range(value):
    lo, hi = map(int, value.split(":"))
    if not 0 <= lo < hi <= 1_000_000:
        raise argparse.ArgumentTypeError("use LO:HI within 0:1000000")
    return lo, hi


def cpu_list(value):
    cpus = [int(part) for part in value.split(",")]
    allow = {16, 17, 18, 19, 20, 21, 28, 29}
    if len(cpus) > 8 or len(cpus) != len(set(cpus)) or not set(cpus) <= allow:
        raise argparse.ArgumentTypeError("use at most eight distinct assigned E core IDs, comma-separated")
    return cpus


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    run = sub.add_parser("run")
    check = sub.add_parser("verify")
    run.add_argument("--out", type=Path, required=True)
    check.add_argument("--out", type=Path, required=True)
    run.add_argument("--sim", type=lambda path: Path(path).resolve(), required=True)
    run.add_argument("--cpus", type=cpu_list, required=True)
    run.add_argument("--seeds", type=seed_range, default=(0, 1_000_000))
    run.add_argument("--phase", choices=("all", "primary", "replay"), default="all")
    run.add_argument("--shard-size", type=int, default=1_000)
    run.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if args.mode == "run" and (args.shard_size < 1 or args.timeout < 1):
        parser.error("--shard-size and --timeout must be positive")
    try:
        if args.mode == "run":
            return execute(args)
        return verify(args.out)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"stock_gen6: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
