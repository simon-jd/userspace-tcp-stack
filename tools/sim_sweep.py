#!/usr/bin/env python3
"""Run utcp-sim over a seed range in parallel (DESIGN §7.4).

    tools/sim_sweep.py --seeds A:B [--jobs 8] [--out DIR] [--sim PATH]
                       [--timeout 120] [--nodes stack|synthetic]
                       [--plant-fail LIST] [--plant-abort LIST] [--plant-hang LIST]
                       [--plant-segv LIST]

--sim defaults to the gcc-sweep preset's utcp-sim (Release with UTCP_DCHECK:
sweeps use a release build with assertions, DESIGN §7.4).

The range [A, B) is cut into chunks; up to --jobs worker processes run
`utcp-sim --seed-range a:b --jsonl -` under `taskset -c 16-31 nice -n 10`.
A seed that runs longer than --timeout seconds of wall-clock time is killed
and recorded with verdict `timeout`; a worker that dies (abort, signal) is
recorded as `crash` for its current seed, with the rolling digest and event
count from the line utcp-sim's fatal-signal handler prints, and the worker
restarts at the next seed.

Every failing seed (verdict not ok, timeout, crash) is re-run twice with pcap
and trace output to confirm the digest, and once more under --asan-sim (an
ASan/UBSan build) if given; seeds with seed % --sample-mod == 0 get pcap and
trace too. A crash without a digest (killed before the handler could print
one, e.g. SIGKILL) counts as reproduced when the re-runs crash with the same
exit status, and is listed under `crash_no_digest`. Output in --out:

    results.jsonl    one line per seed, sorted by seed
    failures.jsonl   failing seeds: verdict, digests of the three runs, files
    summary.json     counts per verdict, failing seeds, replay mismatches
    failures/seed-N/ scenario.txt, *.pcap, trace.jsonl, run*.jsonl, run*.stderr,
                     asan.jsonl, asan.stderr
    samples/seed-N/  scenario.txt, *.pcap, trace.jsonl

Exit status 0 if every seed passed and every re-run matched, 1 otherwise.
"""

import argparse
import json
import os
import queue
import re
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ABORT_RE = re.compile(r"utcp-sim: (?:abort|crash) (\{.*\})")


def parse_range(s):
    a, sep, b = s.partition(":")
    if not sep:
        raise argparse.ArgumentTypeError("expected A:B")
    a, b = int(a), int(b)
    if b < a:
        raise argparse.ArgumentTypeError("expected A <= B")
    return a, b


def parse_list(s):
    return {int(x) for x in s.split(",") if x} if s else set()


class Sweep:
    def __init__(self, args):
        self.args = args
        self.out = Path(args.out)
        self.results = {}
        self.lock = threading.Lock()
        self.done = 0
        self.total = args.seeds[1] - args.seeds[0]
        self.started = time.monotonic()

    # --- Commands.

    def prefix(self):
        if self.args.no_taskset:
            return []
        return ["taskset", "-c", self.args.cpus, "nice", "-n", "10"]

    def sim_args(self):
        a = ["--nodes", self.args.nodes]
        for name in ("plant_fail", "plant_abort", "plant_hang", "plant_segv"):
            v = getattr(self.args, name)
            if v:
                a += ["--" + name.replace("_", "-"), v]
        if self.args.plant_after is not None:
            a += ["--plant-after", str(self.args.plant_after)]
        return a

    # --- Workers.

    def record(self, line):
        with self.lock:
            self.results[line["seed"]] = line
            self.done += 1
            if self.args.progress and self.done % self.args.progress == 0:
                rate = self.done / max(time.monotonic() - self.started, 1e-9)
                print(f"sim_sweep: {self.done}/{self.total} seeds ({rate:.1f}/s)",
                      file=sys.stderr, flush=True)

    def run_chunk(self, a, b):
        """Runs seeds [a, b), restarting after a timeout or crash."""
        seed = a
        while seed < b:
            seed = self.run_worker(seed, b)

    def run_worker(self, a, b):
        """One utcp-sim process from seed a; returns the next seed to run."""
        cmd = self.prefix() + [self.args.sim, "--seed-range", f"{a}:{b}", "--jsonl", "-"] + \
            self.sim_args()
        with tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err,
                                    start_new_session=True)
            fd = proc.stdout.fileno()
            buf = b""
            seed = a
            deadline = time.monotonic() + self.args.timeout
            t_seed = time.monotonic()
            eof = False
            while seed < b and not eof:
                left = deadline - time.monotonic()
                if left <= 0:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                    self.record({"seed": seed, "verdict": "timeout",
                                 "wall_ms": int((time.monotonic() - t_seed) * 1000)})
                    return seed + 1
                r, _, _ = select.select([fd], [], [], left)
                if not r:
                    continue
                chunk = os.read(fd, 65536)
                if not chunk:
                    eof = True
                    break
                buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = json.loads(raw)
                    if line.get("seed") != seed:
                        raise RuntimeError(f"expected seed {seed}, got {raw!r}")
                    self.record(line)
                    seed += 1
                    deadline = time.monotonic() + self.args.timeout
                    t_seed = time.monotonic()
            proc.stdout.close()
            rc = proc.wait()
            if seed >= b:
                return seed
            # The worker died at `seed`.
            err.seek(0)
            info = {"seed": seed, "verdict": "crash", "exit": rc}
            m = ABORT_RE.search(err.read().decode(errors="replace"))
            if m:
                abort = json.loads(m.group(1))
                info["digest"] = abort.get("digest")
                info["events"] = abort.get("events")
            self.record(info)
            return seed + 1

    def run_all(self):
        a, b = self.args.seeds
        chunk = self.args.chunk or max(1, min(200, -(-(b - a) // (self.args.jobs * 4))))
        work = queue.Queue()
        for s in range(a, b, chunk):
            work.put((s, min(b, s + chunk)))
        errors = []

        def worker():
            while True:
                try:
                    lo, hi = work.get_nowait()
                except queue.Empty:
                    return
                try:
                    self.run_chunk(lo, hi)
                except Exception as e:  # noqa: BLE001 - reported below
                    errors.append(e)
                    return

        threads = [threading.Thread(target=worker) for _ in range(self.args.jobs)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if errors:
            raise errors[0]

    # --- Re-runs with pcap and trace.

    def rerun(self, seed, dirpath, tag, sim=None):
        """One run of `seed` into dirpath (with pcap and trace unless `sim` is
        given); returns its result."""
        dirpath.mkdir(parents=True, exist_ok=True)
        jsonl = dirpath / f"{tag}.jsonl"
        outputs = [] if sim else ["--pcap", str(dirpath.parent), "--trace",
                                  str(dirpath / "trace.jsonl")]
        cmd = self.prefix() + [sim or self.args.sim, "--seed", str(seed), "--jsonl", str(jsonl)] + \
            outputs + self.sim_args()
        t0 = time.monotonic()
        with open(dirpath / f"{tag}.stderr", "wb") as err:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=err,
                                    start_new_session=True)
            try:
                proc.wait(timeout=self.args.timeout)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                return {"seed": seed, "verdict": "timeout",
                        "wall_ms": int((time.monotonic() - t0) * 1000)}
        text = jsonl.read_text() if jsonl.exists() else ""
        if text.strip():
            return json.loads(text.splitlines()[-1])
        m = ABORT_RE.search((dirpath / f"{tag}.stderr").read_text(errors="replace"))
        info = {"seed": seed, "verdict": "crash", "exit": proc.returncode}
        if m:
            abort = json.loads(m.group(1))
            info["digest"] = abort.get("digest")
            info["events"] = abort.get("events")
        return info

    def confirm(self, seed):
        first = self.results[seed]
        d = self.out / "failures" / f"seed-{seed}"
        runs = [self.rerun(seed, d, f"run{i}") for i in (1, 2)]
        keys = [(r.get("verdict"), r.get("digest"), r.get("events")) for r in [first] + runs]
        no_digest = False
        if first["verdict"] == "timeout":
            # A hang has no digest; the re-runs must hang too.
            identical = all(r["verdict"] == "timeout" for r in runs)
        elif first["verdict"] == "crash" and all(r.get("digest") is None for r in [first] + runs):
            # No handler line (e.g. SIGKILL): the same crash, by exit status.
            no_digest = True
            identical = all(r["verdict"] == "crash" and r.get("exit") == first.get("exit")
                            for r in runs)
        else:
            identical = len(set(keys)) == 1 and first.get("digest") is not None
        out = {"seed": seed, "verdict": first["verdict"],
               "violation": first.get("violation"), "events": first.get("events"),
               "digests": [r.get("digest") for r in [first] + runs],
               "verdicts": [r.get("verdict") for r in [first] + runs],
               "identical": identical, "no_digest": no_digest, "dir": str(d)}
        if self.args.asan_sim:
            a = self.rerun(seed, d, "asan", self.args.asan_sim)
            out["asan"] = {"verdict": a.get("verdict"), "digest": a.get("digest")}
        return out

    def sample(self, seed):
        d = self.out / "samples" / f"seed-{seed}"
        r = self.rerun(seed, d, "run1")
        return r.get("digest") == self.results[seed].get("digest")


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--seeds", type=parse_range, required=True, help="A:B, seeds A..B-1")
    p.add_argument("--jobs", type=int, default=8)
    p.add_argument("--out", default="sweep-out")
    p.add_argument("--sim", default="build/gcc-sweep/apps/utcp-sim/utcp-sim",
                   help="utcp-sim to run (default: the gcc-sweep build, Release with UTCP_DCHECK)")
    p.add_argument("--asan-sim", help="utcp-sim of an ASan/UBSan build to replay failing seeds")
    p.add_argument("--timeout", type=float, default=120.0, help="wall-clock seconds per seed")
    p.add_argument("--nodes", choices=("stack", "synthetic"), default="stack")
    p.add_argument("--plant-fail", default="", help="seeds that fail (tests the tooling)")
    p.add_argument("--plant-abort", default="", help="seeds that abort")
    p.add_argument("--plant-hang", default="", help="seeds that hang")
    p.add_argument("--plant-segv", default="", help="seeds that get SIGSEGV")
    p.add_argument("--plant-after", type=int, help="events before a planted abort or hang")
    p.add_argument("--sample-mod", type=int, default=500, help="pcap+trace for seed %% N == 0")
    p.add_argument("--chunk", type=int, default=0, help="seeds per worker process")
    p.add_argument("--cpus", default="16-31", help="taskset CPU list")
    p.add_argument("--no-taskset", action="store_true", help="run without taskset and nice")
    p.add_argument("--progress", type=int, default=0, help="report every N seeds on stderr")
    args = p.parse_args()
    if not Path(args.sim).exists():
        p.error(f"{args.sim}: not found (build the gcc-sweep preset first, or pass --sim)")
    if args.asan_sim and not Path(args.asan_sim).exists():
        p.error(f"{args.asan_sim}: not found")
    for name in ("plant_fail", "plant_abort", "plant_hang", "plant_segv"):
        parse_list(getattr(args, name))  # validate

    sweep = Sweep(args)
    sweep.out.mkdir(parents=True, exist_ok=True)
    sweep.run_all()
    wall = time.monotonic() - sweep.started

    a, b = args.seeds
    missing = [s for s in range(a, b) if s not in sweep.results]
    with open(sweep.out / "results.jsonl", "w") as f:
        for s in sorted(sweep.results):
            f.write(json.dumps(sweep.results[s], separators=(",", ":")) + "\n")

    failing = sorted(s for s, r in sweep.results.items() if r["verdict"] != "ok")
    confirmed = [sweep.confirm(s) for s in failing]
    with open(sweep.out / "failures.jsonl", "w") as f:
        for c in confirmed:
            f.write(json.dumps(c, separators=(",", ":")) + "\n")
    sampled = [s for s in range(a, b) if args.sample_mod > 0 and s % args.sample_mod == 0 and
               s in sweep.results and sweep.results[s]["verdict"] == "ok"]
    sample_mismatch = [s for s in sampled if not sweep.sample(s)]

    verdicts = {}
    for r in sweep.results.values():
        verdicts[r["verdict"]] = verdicts.get(r["verdict"], 0) + 1
    summary = {
        "seeds": [a, b],
        "runs": len(sweep.results),
        "missing": missing,
        "verdicts": verdicts,
        "failures": failing,
        "timeouts": [s for s in failing if sweep.results[s]["verdict"] == "timeout"],
        "crashes": [s for s in failing if sweep.results[s]["verdict"] == "crash"],
        "crash_no_digest": [c["seed"] for c in confirmed if c["no_digest"]],
        "replay_mismatch": [c["seed"] for c in confirmed if not c["identical"]],
        "sampled": sampled,
        "sample_mismatch": sample_mismatch,
        "wall_s": round(wall, 1),
    }
    with open(sweep.out / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    print(json.dumps({k: summary[k] for k in ("runs", "verdicts", "failures", "timeouts",
                                              "crashes", "crash_no_digest", "replay_mismatch",
                                              "sample_mismatch", "wall_s")}))
    bad = failing or missing or summary["replay_mismatch"] or sample_mismatch
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
