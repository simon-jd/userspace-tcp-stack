"""Check the published CLI generator vectors and replay a saved strict failure."""
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

sim, sweep = sys.argv[1:]
golden = {
    3: "0cf01e4d5eb07cb275d2052324445638f6564930408e983cc46a691a0ee3cecb",
    4: "9d33ebe468594b9446903e7dd887f2b24a7351de104ead0f74bb2e4692f7ff70",
    5: "52a0d36ca8f96aa4b832943b5ff909825874c483cfe7b55fdd840e7fd887809c",
    6: "8bf012bed98f0864873166d47afb7f6c7c1bfb68e5c987c7e24b4a581de5d8dd",
}
default = subprocess.check_output([sim, "--seed", "42", "--dump-scenario"])
assert default == subprocess.check_output([sim, "--seed", "42", "--gen-version", "6", "--dump-scenario"])
for version, expected in golden.items():
    dump = subprocess.check_output([sim, "--seed", "42", "--gen-version", str(version),
                                    "--dump-scenario"])
    assert hashlib.sha256(dump).hexdigest() == expected, version

assert subprocess.run([sim, "--seed", "42", "--strict-fast-rexmit", "--no-strict-fast-rexmit"],
                      capture_output=True).returncode == 2

with tempfile.TemporaryDirectory() as out:
    root = Path(out)
    def cli_row(*args):
        return json.loads(subprocess.check_output([sim, *args], text=True))

    trace = root / "bbr.trace"
    row = cli_row("--seed", "5", "--trace", str(trace))
    assert row["gen_version"] == 6 and row["a_cc"] == "bbr"
    events = [json.loads(line) for line in trace.read_text().splitlines()]
    acks = [e for e in events if e["node"] == "a" and e["ev"] == "ack" and "bbr_mode" in e]
    assert any(e["bbr_mode"] == "STARTUP" and e["bbr_pacing_gain_q8"] == 739
               and e["bbr_cwnd_gain_q8"] == 739 and e["bbr_min_rtt_us"] > 0
               and e["bbr_bandwidth_q24"] > 0 and e["delivery_rate"] > 0
               and isinstance(e["bbr_lt_use_bw"], bool) for e in acks)
    # The first advancing ACK covers the short first segment in the initial
    # burst. Linux reports delivered packets times MSS, using integer-us stamps.
    first_tx = next(e for e in events if e["node"] == "a" and e["ev"] == "tx"
                    and e["tx"] == "data" and e["len"] > 0)
    first_ack = next(e for e in acks if e["snd_una_off"] > first_tx["snd_una_off"])
    assert first_ack["snd_una_off"] - first_tx["snd_una_off"] == first_tx["len"]
    assert first_ack["delivered"] - first_tx["delivered"] == 1
    interval_us = first_ack["t"] // 1000 - first_tx["t"] // 1000
    expected_rate = first_tx["mss"] * 1_000_000 // interval_us
    assert first_ack["pacing_rate"] != expected_rate
    assert first_ack["delivery_rate"] == expected_rate, (first_ack["delivery_rate"], expected_rate)
    assert all("bbr_mode" not in e for e in events if e["node"] == "b")

    # Count only payload that the receiver actually read and checked. Gen5
    # permits retry exhaustion or an idle application to end a workload.
    empty = root / "empty.scenario"
    empty.write_text("\n".join("conn.count=0" if line.startswith("conn.count=") else line
                              for line in default.decode().splitlines()
                              if not line.startswith("conn.0.")) + "\n")
    rows = [cli_row("--seed", seed, "--gen-version", "5") for seed in ("4", "158", "1295")]
    rows += [cli_row("--scenario", str(empty)), cli_row("--seed", "4", "--nodes", "synthetic")]
    count_transfers = runpy.run_path(sweep)["transfer_counts"]
    assert count_transfers(rows) == dict(complete=1, partial=1, no_payload=2, synthetic=1, unreported=0)
    clean_out = root / "default"
    subprocess.run([sys.executable, sweep, "--sim", sim, "--seeds", "4:5", "--sample-mod", "1",
                    "--out", str(clean_out), "--jobs", "1", "--no-taskset"], check=True)
    summary = json.loads((clean_out / "summary.json").read_text())
    assert (summary["gen_version"], summary["strict_fast_rexmit"], summary["nodes"]) == (6, True, "stack")
    assert summary["ok_transfers"]["complete"] == 1 and summary["sample_mismatch"] == []
    assert (clean_out / "samples/seed-4/replay.jsonl").is_file()

    for strict in (False, True):
        flags = ["--strict-fast-rexmit" if strict else "--no-strict-fast-rexmit"]
        run = subprocess.run([sys.executable, sweep, "--sim", sim, "--seeds", "42:43",
                              "--gen-version", "4", "--plant-fail", "42", "--out", out,
                              "--jobs", "1", "--no-taskset", *flags], check=False)
        assert run.returncode == 1
        summary = json.loads((root / "summary.json").read_text())
        failure = json.loads((root / "failures.jsonl").read_text())
        assert summary["strict_fast_rexmit"] is strict
        assert failure["identical"]
        directory = root / "failures" / "seed-42"
        args = failure["replay_args"]
        assert args == ["--scenario", "scenario.txt", *flags]
        replay = subprocess.run([sim, *args, "--jsonl", "-"], cwd=directory,
                                capture_output=True, text=True, check=False)
        assert replay.returncode == 1, replay.stderr
        result = json.loads(replay.stdout)
        assert (result["verdict"], result["digest"], result["events"]) == (
            failure["verdict"], failure["digests"][0], failure["events"])
