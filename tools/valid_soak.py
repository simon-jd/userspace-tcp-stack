#!/usr/bin/env python3
"""Run one valid-input soak lane, or verify a saved lane receipt."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ASAN = ("abort_on_error=1:detect_leaks=1:detect_stack_use_after_return=1:"
        "strict_string_checks=1:check_initialization_order=1")
UBSAN = "print_stacktrace=1:halt_on_error=1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with open(path, "rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def save(path, data):
    with path.open("x") as file:
        json.dump(data, file, indent=2, sort_keys=True)
        file.write("\n")


def read(path):
    return json.loads(path.read_text())


def manifest(args):
    build = args.build.resolve()
    binary = build / "tests/unit/utcp_unit_tests"
    database = build / "compile_commands.json"
    test_source = ROOT / "tests/unit/valid_wire_stream_test.cpp"
    entries = [entry for entry in read(database) if Path(entry["file"]) == test_source]
    require(len(entries) == 1, "build must belong to this checkout")
    argv = shlex.split(entries[0]["command"])
    compiler = Path(argv[0]).resolve(strict=True)
    version = command(compiler, "--version")
    require("clang version" in version.lower(), "expected Clang")
    require({"-fsanitize=address,undefined", "-fno-sanitize-recover=all"} <= set(argv),
            "expected aborting ASan+UBSan compile flags")
    require(not command("git", "status", "--porcelain", "--untracked-files=all"),
            "use a clean committed source checkout and keep results outside it")
    build_commands = command("ninja", "-C", str(build), "-t", "commands", "utcp_unit_tests")
    link_command = build_commands.splitlines()[-1]
    require("-fsanitize=address,undefined" in shlex.split(link_command),
            "expected ASan+UBSan link flags")
    tracked_snapshot = subprocess.check_output(["git", "archive", "--format=tar", "HEAD"], cwd=ROOT)
    sources = [test_source, ROOT / "tests/support/naive_reassembler.hpp",
               ROOT / "tests/support/packet_builder.cpp", ROOT / "src/core/tcp/recv_buffer.cpp",
               *sorted((ROOT / "src/core/wire").glob("*.cpp")), Path(__file__).resolve()]
    return {
        "lane": args.lane, "run": args.run, "scale": args.scale,
        "seconds": args.seconds, "first_batch": args.first_batch,
        "git_commit": command("git", "rev-parse", "HEAD"),
        "git_tree": command("git", "rev-parse", "HEAD^{tree}"),
        "git_archive_sha256": hashlib.sha256(tracked_snapshot).hexdigest(),
        "source_sha256": {str(path.relative_to(ROOT)): sha(path) for path in sources},
        "binary": str(binary), "binary_sha256": sha(binary),
        "compiler": str(compiler), "compiler_sha256": sha(compiler), "compiler_version": version,
        "link_command": link_command, "test_compile_command": entries[0]["command"], "compile_database_sha256": sha(database),
        "asan_options": ASAN, "ubsan_options": UBSAN, "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "nice": os.getpriority(os.PRIO_PROCESS, 0),
    }


def verify_counts(lane, scale, counts):
    if lane == "wire":
        n = 128 * scale
        fixed = {"ipv4_datagrams": 3*n, "tcp_segments": n, "tcp_syn": n//4,
                 "tcp_syn_ack": n//4, "udp_datagrams": n, "udp_without_checksum": n//4,
                 "icmp_messages": n, "icmp_echo_request": n//4, "icmp_echo_reply": n//2,
                 "icmp_port_unreachable": n//4}
        require(counts == fixed, "wire counts differ from completed profiles")
    else:
        n = 16 * scale
        fixed = {"streams": n, "ordered_windows": n, "reordered_windows": n,
                 "fin_reached": n, "delivery_windows": 2*n, "drained_windows": 2*n,
                 "repeat_inserts": n}
        require(all(counts.get(key) == value for key, value in fixed.items()),
                "stream counts differ from completed profiles")
        require(counts.keys() == fixed.keys() | {"inserts", "reordered_inserts", "hole_fills",
                                                  "reads", "bytes_read"}, "unexpected stream fields")
        require(counts["inserts"] > counts["reordered_inserts"] >= n and
                counts["hole_fills"] >= n and counts["reads"] >= 2*n and
                2*n*4096 < counts["bytes_read"] <= 2*n*8191,
                "stream operation counts outside profile")


def verify(output, expected_batches=None):
    spec = read(output / "start.json")
    exit_info = read(output / "exit.json")
    require(exit_info["returncode"] == 0, "test process failed")
    require(exit_info["binary_sha256_after"] == spec["binary_sha256"], "executable changed")
    suite = ET.parse(output / "test.xml").getroot()
    cases = suite.findall("./testsuite/testcase")
    require(len(cases) == 1 and cases[0].get("classname") == "ValidWireStreamSoak"
            and cases[0].get("name") == "DISABLED_" + spec["lane"].title()
            and cases[0].get("status") == "run" and cases[0].get("result") == "completed"
            and suite.get("failures") == "0" and suite.get("errors") == "0",
            "expected one passing lane in GoogleTest XML")
    totals = Counter()
    batches = active = 0
    last_end = spec["monotonic_ns"]
    prefix = (1 << 63) | (spec["run"] << 32) | (int(spec["lane"] == "stream") << 31)
    with (output / "test.log").open() as log:
        for line in log:
            if not line.startswith("UTCP_VALID_BATCH "):
                continue
            _, idx, begin, end, *fields = line.split()
            idx, begin, end = int(idx), int(begin), int(end)
            require(idx == spec["first_batch"] + batches and idx < 2**31, "batch sequence mismatch")
            require(last_end <= begin < end <= exit_info["monotonic_ns"], "invalid batch timing")
            counts = {k: int(v) for k, v in (item.split("=") for item in fields)}
            require(len(counts) == len(fields) and counts.pop("seed") == (prefix | idx), "seed mismatch")
            verify_counts(spec["lane"], spec["scale"], counts)
            require(active < spec["seconds"] * 10**9, "unexpected batch after deadline")
            totals.update(counts)
            active += end - begin
            last_end = end
            batches += 1
    require(batches > 0 and active >= spec["seconds"] * 10**9, "insufficient verified workload time")
    properties = [(p.get("name"), p.get("value")) for p in cases[0].findall("./properties/property")]
    expected = {key: str(value) for key, value in counts.items()}
    expected["seed"] = str(prefix | idx)
    require(len(properties) == len(expected) and dict(properties) == expected,
            "XML properties differ from final batch")
    if expected_batches is not None:
        require(batches == expected_batches, "unexpected number of completed batches")
    return {"lane": spec["lane"], "run": spec["run"], "scale": spec["scale"], "batches": batches,
            "first_seed": prefix | spec["first_batch"], "last_seed": prefix | idx,
            "active_ns": active, "process_wall_ns": exit_info["monotonic_ns"] - spec["monotonic_ns"],
            "totals": dict(totals), "test_log_sha256": sha(output / "test.log"),
            "test_xml_sha256": sha(output / "test.xml")}


def run(args):
    require(1 <= args.run < 2**31 and 1 <= args.scale <= 1024 and 1 <= args.seconds <= 86400
            and 0 <= args.first_batch < 2**31, "invalid run, scale, seconds, or first batch")
    spec = manifest(args)
    output = args.output.resolve()
    output.mkdir(parents=False, exist_ok=False)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GTEST_")}
    env.update(ASAN_OPTIONS=ASAN, UBSAN_OPTIONS=UBSAN, UTCP_VALID_SOAK_RUN=str(args.run),
               UTCP_VALID_SOAK_SCALE=str(args.scale), UTCP_VALID_SOAK_SECONDS=str(args.seconds),
               UTCP_VALID_SOAK_FIRST_BATCH=str(args.first_batch))
    argv = [spec["binary"], "--gtest_also_run_disabled_tests",
            "--gtest_filter=ValidWireStreamSoak.DISABLED_" + args.lane.title(),
            "--gtest_output=xml:" + str(output / "test.xml")]
    spec.update(argv=argv, utc=datetime.now(timezone.utc).isoformat(), monotonic_ns=time.monotonic_ns())
    save(output / "start.json", spec)
    with (output / "test.log").open("x") as log:
        proc = subprocess.run(argv, env=env, stdout=log, stderr=subprocess.STDOUT)
    stop = time.monotonic_ns()
    save(output / "exit.json", {"returncode": proc.returncode, "monotonic_ns": stop,
                                "utc": datetime.now(timezone.utc).isoformat(),
                                "binary_sha256_after": sha(spec["binary"])})
    result = verify(output)
    save(output / "summary.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    launch = actions.add_parser("run")
    launch.add_argument("lane", choices=["wire", "stream"])
    launch.add_argument("--build", type=Path, default=ROOT / "build/clang-asan")
    launch.add_argument("--run", type=int, required=True)
    launch.add_argument("--scale", type=int, default=16)
    launch.add_argument("--seconds", type=int, default=7200)
    launch.add_argument("--first-batch", type=int, default=0)
    launch.add_argument("--output", type=Path, required=True)
    check = actions.add_parser("check")
    check.add_argument("output", type=Path)
    check.add_argument("--expected-batches", type=int)
    args = parser.parse_args()
    if args.action == "run":
        result = run(args)
    else:
        result = verify(args.output, args.expected_batches)
        stored = read(args.output / "summary.json")
        # Compare JSON values with their types (Python otherwise equates 1, True and 1.0).
        require(json.dumps(stored, sort_keys=True) == json.dumps(result, sort_keys=True),
                "stored summary differs from recomputed receipt")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
