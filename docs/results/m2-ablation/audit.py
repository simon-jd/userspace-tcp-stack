"""Verify the registered schedule, both endpoints, calibrated runtime, effective settings and traces.

Run with Python 3.11+ on the complete or compact restored campaign:
    python audit.py CAMPAIGN NEW_OUTPUT
The compact restore needs the exact plan.json from the full archive.
"""

import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CHECKPOINT = HERE.parent / "m2-checkpoint/verify"
sys.path[:0] = [str(REPO / "tools/m2"), str(CHECKPOINT)]
import analyze
import checkpoint_inputs
import diagnostics
import matrix
import physical_checkpoint
import verify_endpoint_cc
import verify_profile_trace

SOURCE = "35a14fb5ff9c5b243a74aa9198268c29ee250ffc"
KEY = "cd50db51c944442c8f1158f6b5e48f01ab3f913d9b96034a675af9a8aed9c1fd"
GATE = "m2-integrate/3f48c30dbf70240d50234f095eaca6de24fc0625-calib-a1-s0"
EXPANSION = "5654c1d0e2071b2f1b31e9ebfb29bfc6e85da36b8dff858c31b68a9fbfdafd1b"
BULK = "2363c1adc946b052633fa349f92196e9c27eff5045e6208fb7f6d299ba9c4a8f"
CORE = "5642df899b2915bc88e8154b61ac2a3cb9b3124a53917ac7393775c7f7961276"
SCRIPTS = "43bf359c7ba1bf5d40f3a58ef7c4c9e5ba82737038b6d25ba35aa52d55b72912"
HYSTART = [
    "TcpExtTCPHystart" + n
    for n in ("TrainDetect", "TrainCwnd", "DelayDetect", "DelayCwnd")
]
read = checkpoint_inputs.load
write_csv = checkpoint_inputs.write_csv


def schedule(camp):
    plan = matrix.load_plan(HERE / "plan.toml")
    runs = matrix.expand_plan(plan, 1)
    expanded = "".join(json.dumps(r, sort_keys=True) + "\n" for r in runs)
    assert hashlib.sha256(expanded.encode()).hexdigest() == EXPANSION
    assert read(camp / "plan.json") == {"plan": plan, "runs": runs}
    return {r["run"]: r for r in runs}


def profiles():
    rfc_path = HERE / "rfc-profile.json"
    assert (
        hashlib.sha256(rfc_path.read_bytes()).hexdigest()
        == "eead814fe8a51a3d6652d8a5e51f3fa08c767ad5ceb0da23cedbe1662b2d92b0"
    )
    rfc = read(rfc_path)
    assert (
        rfc["rto_min"],
        rfc["rtt_estimator"],
        rfc["recovery_reduction"],
        rfc["initial_cwnd"],
        rfc["hystart"],
        rfc["cc_flavor"],
        rfc["rack_tlp"],
    ) == ("1s", "rfc6298", "rfc6675", "none", "hystart_pp", "rfc", "false")
    return {"linux": read(CHECKPOINT / "linux-profile.json"), "rfc": rfc}


def settings(meta, spec, refs):
    assert meta["cc"] == spec["cc"] == "cubic" and meta["profile"] == spec["profile"]
    assert not meta.get("stack_args")
    if meta["impl"] == "linux":
        assert not meta["profile"] and not meta.get("stack_set")
        return None
    common = matrix.stack_sets(meta["gso_ipv4_max_size"])
    assert common == verify_profile_trace.BASE_SETS
    extra = spec.get("stack_set", [])
    assert meta["stack_set"] == common + extra
    base = refs[meta["profile"]]
    expected = {
        **base,
        **dict(x.split("=", 1) for x in extra),
        "set": " ".join(common + extra),
    }
    changed = {k for k in expected if k != "set" and base[k] != expected[k]}
    assert changed == {x.split("=")[0] for x in extra}
    return expected


def check_run(rd, meta, spec):
    assert (
        rd.name
        == meta["run"]
        == (spec["run"] if not meta["rerun"] else f"{spec['run']}-rerun{meta['rerun']}")
    )
    for k, v in spec.items():
        if k not in ("run", "stack_set", "slot_index"):
            assert meta[k] == v, (rd, k, meta[k], v)
    assert meta["slot"] == spec["slot_index"] == 0 and meta["timing"] is True
    assert (
        meta["commit"],
        meta["reuse_key"],
        meta["gate"],
        meta["bulk_sha256"],
        meta["core_sha256"],
        meta["scripts_sha256"],
    ) == (SOURCE, KEY, GATE, BULK, CORE, SCRIPTS)
    assert meta["campaign"] == "m2d-ablation" and meta["duration_s"] == spec["duration"]
    for phase in ("pre", "post"):
        lines = (rd / phase / "record.txt").read_text().splitlines()
        (tbf,) = [line for line in lines if line.startswith("qdisc tbf ")]
        for field, value in (
            ("rate", f"{meta['bw']}Mbit"),
            ("limit", f"{meta['queue_bytes']}b"),
        ):
            assert re.search(r"\b" + field + " " + value + r"\b", tbf), (rd, field, tbf)
    physical_checkpoint.kernel_netem(rd, meta)


def stack_trace(rd, meta, summary, expect):
    rows = [json.loads(line) for line in (rd / "snd.jsonl").read_text().splitlines()]
    assert [r for r in rows if r.get("ev") == "config"] == [expect], (
        rd,
        "effective configuration",
    )
    ids = {r["conn_id"] for r in rows if r["ev"] == "sample"}
    assert len(ids) == 1
    stats = read(rd / "stats.json")
    assert stats["trace_events"] == summary["trace_events"]
    counts, digest = verify_profile_trace.check_trace(
        rd / "trace.jsonl", meta, ids.pop(), stats["trace_events"]
    )
    data = {
        "run": meta["run"],
        "variant": meta["algo"],
        "profile": meta["profile"],
        "overrides": expect["set"],
        "effective_config": json.dumps(expect, sort_keys=True),
        "trace_sha256": digest,
        "trace_events": sum(counts.values()),
    }
    data.update(
        {"trace_" + k: counts[k] for k in sorted(verify_profile_trace.TRACE_KINDS)}
    )
    classification = Counter()
    for ev in diagnostics.rows(rd / "trace.jsonl"):
        if ev["ev"] in ("rto", "recovery", "tx"):
            classification[
                (ev["ev"], ev["tx"] if ev["ev"] == "tx" else ev["cause"], ev["ca"])
            ] += 1
    data["event_classes"] = json.dumps(
        {"|".join(k): v for k, v in sorted(classification.items())}
    )
    data.update({k: stats[k] for k in HYSTART})
    return data


def main(campaign, out):
    planned = schedule(campaign)
    refs = profiles()
    out.mkdir(parents=True, exist_ok=False)
    families = defaultdict(list)
    for mp in sorted(campaign.glob("*/meta.json")):
        rd = mp.parent
        meta, summary = read(mp), read(rd / "summary.json")
        spec = planned[meta.get("rerun_of", meta["run"])]
        check_run(rd, meta, spec)
        expected = settings(meta, spec, refs)
        families[meta["cell"], meta["algo"]].append((meta, summary, expected))
    rows, traces, statuses = [], [], {}
    for (cell, variant), members in sorted(families.items()):
        pairs, bad, status = checkpoint_inputs.independently_count(
            [(m, s) for m, s, e in members]
        )
        counted = {m["run"] for pair in pairs for m, s in pair}
        assert len(counted) == 2 * len(pairs)
        statuses[cell + "/" + variant] = {
            "status": status,
            "bad_pairs": bad,
            "counted": len(counted),
        }
        for meta, summ, expected in members:
            rd = campaign / meta["run"]
            row = checkpoint_inputs.details(
                rd, meta, summ, meta["run"] in counted, analyze, matrix
            )
            if expected and summ["valid"]:
                traces.append(stack_trace(rd, meta, summ, expected))
            if not expected:
                assert not any(
                    r.get("ev") == "config" for r in diagnostics.rows(rd / "snd.jsonl")
                )
            rows.append(row)
    assert len(families) == 14
    rows.sort(key=lambda r: (r["order"], r["rerun"]))
    write_csv(out / "evidence.csv", checkpoint_inputs.ROWS, rows)
    if traces:
        write_csv(
            out / "profile-trace.csv",
            traces[0].keys(),
            sorted(traces, key=lambda r: r["run"]),
        )
    (out / "qualification.json").write_text(
        json.dumps(statuses, sort_keys=True, indent=2) + "\n"
    )
    verify_endpoint_cc.main(campaign, out / "evidence.csv", out / "endpoint-cc.csv")
    diagnostics.main(campaign, out / "evidence.csv", out / "trace-diagnostics.csv")
    return statuses


if __name__ == "__main__":
    print(json.dumps(main(*(Path(p) for p in sys.argv[1:])), sort_keys=True))
