#!/usr/bin/env python3
"""Verify the defensive profile without running a stock or imported scenario."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


def check(sim):
    def call(*args):
        result = subprocess.run([sim, *args], capture_output=True)
        assert result.returncode == 0, result.stderr.decode()
        return result.stdout

    profile = ("--defensive-gen6",)
    forced = {"node.0.test_isn", "node.1.test_isn", "node.0.renege_ppm", "node.1.renege_ppm"}
    changed = set()
    for seed in range(32):
        args = ("--seed", str(seed), "--dump-scenario")
        stock = dict(line.split("=", 1) for line in call(*args, "--gen-version", "6").decode().splitlines())
        normal = dict(line.split("=", 1) for line in call(*args, *profile).decode().splitlines())
        assert stock.keys() == normal.keys()
        for key in stock:
            if normal[key] != stock[key]:
                assert key in forced, (seed, key)
                changed.add(key)
        for key, value in normal.items():
            if key.endswith((".bitflip_ppm", ".garbage_ppm", ".icmp_spoof_ppm", ".renege_ppm")):
                assert value == "0", (seed, key)
            if key.endswith(".test_isn"):
                assert value == "none", (seed, key)
            if key.endswith(".test_fault"):
                assert value == "none", (seed, key)
            if key.endswith(".mode"):
                assert value == "close", (seed, key)
            if key.endswith(".mtu"):
                assert value == "1500", (seed, key)
    assert any(key.endswith(".test_isn") for key in changed), changed
    assert any(key.endswith(".renege_ppm") for key in changed), changed

    for option in (
        ("--scenario", "/does-not-exist"),
        ("--corpus", "/does-not-exist"),
        ("--seed", "0", "--nodes", "synthetic"),
        ("--seed", "0", "--gen-version", "3"),
        ("--seed", "0", "--plant-fail", "0"),
        ("--seed", "0", "--test-fault", "none"),
        ("--seed", "0", "--no-strict-fast-rexmit"),
        ("--seed", "0", "--max-events", "1"),
        ("--seed", "0", "--snaplen", "64"),
        ("--seed-range", "0:2", "--pcap", "/does-not-exist"),
    ):
        result = subprocess.run([sim, *profile, *option], capture_output=True)
        assert result.returncode == 2 and b"--defensive-gen6" in result.stderr, option

    with TemporaryDirectory() as tmp:
        args = ("--seed", "0", *profile)
        original = json.loads(call(*args))
        dest = Path(tmp)
        replay = json.loads(call(*args, "--pcap", tmp, "--trace", str(dest / "trace.jsonl")))
        for row in (original, replay):
            row.pop("wall_ms")
            assert row["sweep_profile"] == "gen6-normal-v1"
            assert row["verdict"] == "ok"
        assert original == replay
        capture = dest / "seed-0"
        scenario = (capture / "scenario.txt").read_bytes()
        assert scenario == call(*args, "--dump-scenario")
        assert original["scenario_sha256"] == hashlib.sha256(scenario).hexdigest()
        assert (dest / "trace.jsonl").stat().st_size > 0
        for node in ("a", "b"):
            for direction in ("ingress", "egress"):
                assert (capture / f"{node}.{direction}.pcap").stat().st_size > 24
    print("defensive Gen6 CLI checks passed")


if __name__ == "__main__":
    check(sys.argv[1])
