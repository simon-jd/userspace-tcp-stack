#!/usr/bin/env python3
"""Run registered matched ring-size blocks with the existing bulk and echo gates."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace

M4 = Path(__file__).resolve().parents[1]
ROOT = M4.parents[1]
sys.path[:0] = [str(M4), str(M4 / "performance")]
import echo_load
from performance.run import Campaign, Mode, output, sha
from model import DIRECTIONS

ORDER = ((2, 4, 8), (4, 8, 2), (8, 2, 4), (8, 4, 2), (4, 2, 8), (2, 8, 4))
SIZES = (2, 4, 8)


def binary(kib, program):
    return ROOT / f"build/ring-{kib * 1024}/apps/{program}/{program}"


def store(image, *argv, data=None):
    command = ["docker", "run", "--rm", "--network", "none", "--cpuset-cpus", "28-31",
               "-v", "utcp-data:/data", "-v", f"{ROOT}:/source:ro"]
    if data is not None:
        command.append("-i")
    return subprocess.run([*command, image, *argv], input=data, stdout=subprocess.PIPE,
                          check=True).stdout


def store_json(image, path, value):
    store(image, "tee", path, data=(json.dumps(value, indent=2) + "\n").encode())


def freeze(root, image, source, args, blocks):
    store(image, "mkdir", root)
    store(image, "mkdir", f"{root}/build")
    manifest = {"source": source, "image": image, "argv": sys.argv,
                "order": {b: ORDER[b - 1] for b in blocks}, "builds": {},
                "scope": args.workload, "host": output("uname", "-a"),
                "compiler": output("g++-15", "--version").splitlines()[0]}
    files = [M4 / "ring_size/run.py", M4 / "ring_size/analyze.py", M4 / "echo_load.py", M4 / "echo_load_snapshot.py",
             ROOT / "docs/results/m4-ring-size/PROTOCOL.md"]
    for path in files:
        store(image, "cp", f"/source/{path.relative_to(ROOT)}", f"{root}/{path.name}")
    for kib in SIZES:
        build = binary(kib, "utcp-echo").parents[2]
        cache = (build / "CMakeCache.txt").read_text().splitlines()
        checks = ("CMAKE_BUILD_TYPE:STRING=Release", f"UTCP_RING_CHUNK_BYTES:STRING={1024 * kib}",
                  "UTCP_SANITIZE:BOOL=OFF")
        if not all(row in cache for row in checks):
            raise ValueError(f"{build} has unexpected settings")
        records = {}
        dest = f"{root}/build/{kib}"
        store(image, "mkdir", dest)
        for file in (build / "CMakeCache.txt", build / "compile_commands.json",
                     binary(kib, "utcp-echo"), binary(kib, "utcp-bulk")):
            store(image, "cp", f"/source/{file.relative_to(ROOT)}", f"{dest}/{file.name}")
            records[file.name] = sha(file)
            if store(image, "sha256sum", f"{dest}/{file.name}").decode().split()[0] != records[file.name]:
                raise ValueError(f"archived hash differs for {file}")
        manifest["builds"][kib] = records
    store_json(image, f"{root}/plan.json", manifest)


def bulk(root, image, source, run_id, blocks):
    kernel = Mode("kernel", str(binary(4, "utcp-bulk")), source)
    modes = {k: Mode(f"ring-{k}", str(binary(k, "utcp-bulk")), source) for k in SIZES}
    opts = SimpleNamespace(run_id=run_id, image=image, repeats=1, subnet=177, bytes=1_000_000_000,
                           functional=False, ethernet_aggregation=False, probe_perf=False,
                           timeout=180, controller_cpus=sorted(os.sched_getaffinity(0)))
    with Campaign(opts, kernel, modes[2], modes[4]) as campaign:
        campaign.directory = root + "/bulk"
        campaign.modes[modes[8].name] = modes[8]
        campaign.order = [(b, direction, modes[k].name) for b in blocks
                          for direction in (DIRECTIONS if b % 2 else DIRECTIONS[::-1])
                          for k in ORDER[b - 1]]
        campaign.freeze()
        rows = []
        try:
            campaign.setup()
            for i, arm in enumerate(campaign.order, 1):
                rows.append(campaign.arm(i, *arm))
        finally:
            campaign.archive(rows)
    return all(row["valid"] for row in rows) and len(rows) == len(campaign.order)


def echo(root, image, source, blocks):
    rows = []
    for block in blocks:
        for kib in ORDER[block - 1]:
            opts = SimpleNamespace(purpose="timing", backend="utcp", offload="legacy", image=image,
                                   binary=str(binary(kib, "utcp-echo").relative_to(ROOT)),
                                   binary_source=source, direct_echo=False,
                                   client_binary=str(binary(4, "utcp-echo").relative_to(ROOT)),
                                   client_source=source, allocation_counter=None, connections=10000,
                                   open_batch=32, backlog=4096, count=5, size=64, rate=5000,
                                   hold_s=5, net_base=178, cpus=(8, 10, 12))
            trial = echo_load.Trial(opts, root.removeprefix("/data/"))
            row = {"block": block, "kib": kib, "dir": trial.tag, "valid": False}
            try:
                trial.setup()
                result = trial.trial()
                trial.capture_json("server", "result.json", result)
                lines = trial.docker("server", "cat", f"{trial.out}/server/events.jsonl").splitlines()
                chunks = [event for line in lines if "chunks" in (event := json.loads(line))]
                if not chunks or any(x["chunk_bytes"] != kib * 1024 for x in chunks):
                    raise ValueError("echo did not report the configured pool geometry")
                counts = [s["chunks"] for s in chunks]
                if counts != sorted(counts) or counts[-1] >= (1 << 32) // (kib * 1024):
                    raise ValueError("pool exhausted or allocation high-water count went backwards")
                row.update(valid=True, allocated_chunks=counts[-1],
                           allocated_chunk_bytes=counts[-1] * kib * 1024)
            except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
                row["error"] = str(error)
                if trial.artifacts_created:
                    trial.capture_json("server", "failure.json", row)
            finally:
                trial.cleanup()
            rows.append(row)
            store_json(image, f"{root}/echo-index.json", rows)
            print(json.dumps(row), flush=True)
    return all(row["valid"] for row in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--blocks", default="1,2,3,4,5,6")
    parser.add_argument("--workload", choices=("both", "bulk", "echo"), default="both")
    parser.add_argument("--image", default="utcp-testbed:dev")
    args = parser.parse_args()
    blocks = [int(b) for b in args.blocks.split(",")]
    if (not re.fullmatch("[a-z0-9][a-z0-9-]{0,26}", args.run_id) or not blocks
            or sorted(set(blocks)) != blocks or not set(blocks) <= set(range(1, 7))):
        parser.error("provide a unique lowercase run ID and ascending registered block numbers 1-6")
    if not os.sched_getaffinity(0) <= set(range(28, 32)) or os.nice(0) != 10:
        parser.error("run with taskset -c 28-31 nice -n 10")
    if output("git", "-C", str(ROOT), "status", "--porcelain"):
        parser.error("commit the exact source before measuring")
    source = output("git", "-C", str(ROOT), "rev-parse", "HEAD")
    image = output("docker", "image", "inspect", "--format", "{{.Id}}", args.image)
    root = f"/data/m4-ring-size-{args.run_id}"
    freeze(root, image, source, args, blocks)
    ok = []
    try:
        if args.workload in ("bulk", "both"):
            ok.append(bulk(root, image, source, args.run_id, blocks))
        if args.workload in ("echo", "both"):
            ok.append(echo(root, image, source, blocks))
    finally:
        shell = 'cd "$1" && find . -type f ! -name ROOT-SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > ROOT-SHA256SUMS'
        store(image, "bash", "-euo", "pipefail", "-c", shell, "bash", root)
        print(store(image, "sha256sum", f"{root}/ROOT-SHA256SUMS").decode().strip(), flush=True)
    return 0 if all(ok) else 1


if __name__ == "__main__":
    sys.exit(main())
