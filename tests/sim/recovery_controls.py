"""Replay real loss recovery with planted PRR and TLP errors through the public CLI."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sim = sys.argv[1]


def run(scenario, fault, trace, *opts):
    process = subprocess.run([sim, "--scenario", str(scenario), "--test-fault", fault,
                              "--trace", str(trace), *opts], text=True, capture_output=True)
    row = json.loads(process.stdout)
    assert row["nodes"] == "stack" and row["gen_version"] == 5
    assert row["strict_fast_rexmit"] == ("--no-strict-fast-rexmit" not in opts)
    events = [json.loads(line) for line in trace.read_text().splitlines()]
    return process.returncode, row, events


with tempfile.TemporaryDirectory() as tmp:
    work = Path(tmp)
    for seed, fault in [(4, "prr_skip_force"), (13729, "double_tlp")]:
        scenario = work / f"{seed}.scenario"
        scenario.write_bytes(subprocess.check_output([sim, "--seed", str(seed), "--gen-version", "5", "--dump-scenario"]))
        for extra in [(), ("--strict-fast-rexmit",)]:
            rc, row, trace = run(scenario, fault, work / "on.trace", *extra)
            assert rc == 1 and row["verdict"] == "inflight", row
            sender = row["violation"].split()[1]
            tx = [e for e in trace if e["node"] == sender and e["ev"] == "tx"]
            if fault == "prr_skip_force":
                bad = next(e for e in tx if e["tx"] == "fast_rexmit")
                assert bad["len"] > 0 and bad["in_flight"] > bad["cwnd"]
                assert "packets_in_flight" in row["violation"]
            else:
                assert "second TLP in open probe episode" in row["violation"]
                bad = next(e for e in tx if e["tx"] == "tlp" and e["t"] == row["violation_t_ns"])
                probes = [e for e in tx if e["conn"] == bad["conn"] and e["tx"] == "tlp"]
                assert len(probes) >= 2 and probes[-2]["t"] < bad["t"]
            assert bad["t"] == row["violation_t_ns"]
        controls = [("none", ())]
        if fault == "prr_skip_force":
            controls.append((fault, ("--no-strict-fast-rexmit",)))
        for setting, opts in controls:
            rc, row, _ = run(scenario, setting, work / "off.trace", *opts)
            assert rc == 0 and row["verdict"] == "ok" and row["violations"] == 0, row
            for sender, peer in (("a", "b"), ("b", "a")):
                assert 0 < row[sender + "_requested"] == row[peer + "_received"]
                assert row[sender + "_cc"] in ("newreno", "cubic")
                assert row[sender + "_cc_flavor"] in ("rfc", "linux")
