"""Read-only checkpoint verification and reproducible evidence for the two result tables.

Usage: python checkpoint_inputs.py REPO CAMPAIGN CELLS.CSV NEW_OUTPUT ACCEPTED_SHA KEY GATE
The endpoint reconstruction lives in endpoint_replay.py.
"""

from __future__ import annotations

import collections
import csv
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import endpoint_replay

METRICS = ("goodput_bps", "retrans_pct", "qdelay_p50_ms", "qdelay_p99_ms")
ROWS = [
    "run",
    "cell",
    "algo",
    "impl",
    "rep",
    "group",
    "rerun",
    "order",
    "netem_seed",
    "valid",
    "counted",
    "flags",
    "invalid",
    "observed_cc",
    "window_s",
    "receiver_bytes",
    "transfer_sha256",
    "slot",
    "cpusets",
    "start_utc",
    "uptime",
    "slot_cpu_ticks",
    "iproute2",
    "build",
    "kernel",
    "image",
    "bulk_sha256",
    "core_sha256",
    "scripts_sha256",
    "reuse_key",
    "commit",
    "sender_samples",
    "receiver_samples",
    "foreign_lower",
    "foreign_upper",
    "softirq_NET_RX",
    "softirq_NET_TX",
    "softirq_HRTIMER",
    "softirq_TIMER",
    "r1-in_captured",
    "r1-in_dropped",
    "r1-in_filter",
    "r2-out_captured",
    "r2-out_dropped",
    "r2-out_filter",
]


def load(path):
    return json.loads(path.read_text())


def write_csv(path, fields, rows):
    with path.open("x", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def details(rd, meta, summary, counted, A, M):
    observed = endpoint_replay.audit_run(rd, A)
    window = M.measured_transfer_window(summary, meta["duration_s"])
    assert window == (observed["lo_ns"], observed["hi_ns"])
    assert meta["slot"] == 0 and meta["timing"] is True and M.timing_placement(0, meta["cpusets"])
    assert meta["uptime"] and meta["top_cpu"] and isinstance(meta["threads_on_8_15"], list)
    assert set(summary["softirqs"]) == set(A.SOFTIRQ_KINDS)
    assert set(summary["cpu"]) == {"8", "9", "10", "11"}
    assert all(v["total"] > 0 and v["busy"] >= 0 for v in summary["cpu"].values())
    assert summary["foreign_cpu"]["upper_frac"] >= summary["foreign_cpu"]["lower_frac"] >= 0
    assert "utcp" != meta["impl"] or meta["trace"] and (rd / "trace.jsonl").stat().st_size > 0
    row = {
        k: meta[k]
        for k in (
            "run",
            "cell",
            "algo",
            "impl",
            "rep",
            "group",
            "rerun",
            "order",
            "slot",
            "reuse_key",
            "commit",
            "bulk_sha256",
            "core_sha256",
            "scripts_sha256",
        )
    }
    row.update(
        netem_seed=meta["seed"],
        counted=int(counted),
        valid=int(summary["valid"]),
        flags=";".join(summary["flags"]),
        invalid=";".join(summary["invalid"]),
        observed_cc=";".join(observed["observed_cc"]),
        window_s=summary["window_s"],
        cpusets=json.dumps(meta["cpusets"], sort_keys=True),
        start_utc=meta["start_utc"],
        uptime=meta["uptime"],
        slot_cpu_ticks=json.dumps(summary["cpu"], sort_keys=True),
        iproute2=meta["iproute2"],
        build=meta["build"],
        kernel=meta["uname_r"],
        image=meta["image_id"],
        receiver_bytes=observed["endpoints"]["receiver"]["bytes"],
        transfer_sha256=observed["sha256"],
        sender_samples=observed["endpoints"]["sender"]["samples_in_window"],
        receiver_samples=observed["endpoints"]["receiver"]["samples_in_window"],
        foreign_lower=summary["foreign_cpu"]["lower_frac"],
        foreign_upper=summary["foreign_cpu"]["upper_frac"],
    )
    for kind, value in summary["softirqs"].items():
        row["softirq_" + kind] = value
    for name in ("r1-in", "r2-out"):
        cap = summary["capture"][name]
        assert all(
            type(cap[k]) is int for k in ("captured", "received_by_filter", "kernel_dropped", "bytes")
        )
        assert cap["bytes"] > 24 and cap["captured"] > 0
        if (rd / (name + ".pcap")).exists():
            assert (rd / (name + ".pcap")).stat().st_size == cap["bytes"]
        row.update(
            {
                name + "_captured": cap["captured"],
                name + "_dropped": cap["kernel_dropped"],
                name + "_filter": cap["received_by_filter"],
            }
        )
    return row


def independently_count(members):
    by_pair = collections.defaultdict(list)
    for m, s in members:
        by_pair[(m["group"], m["rerun"])].append((m, s))
    accepted = []
    bad = []
    for pair, runs in sorted(by_pair.items()):
        if sorted(m["impl"] for m, s in runs) != ["linux", "utcp"] or not all(
            s["valid"] for m, s in runs
        ):
            bad.append(pair)
            continue
        assert len({m["seed"] for m, s in runs}) == 1 and len({m["rep"] for m, s in runs}) == 1
        if len(accepted) < 5:
            accepted.append(runs)
    status = "invalid (rerun cap)" if len(bad) > 3 else "ok" if len(accepted) == 5 else "incomplete"
    return accepted, bad, status


def main():
    repo, camp, cells, out = map(Path, sys.argv[1:5])
    sha, key, gate = sys.argv[5:8]
    sys.path.insert(0, str(repo / "tools/m2"))
    import analyze as A
    import matrix as M

    plan = load(camp / "plan.json")
    planned = {p["run"]: p for p in plan["runs"]}
    assert len(planned) == 160
    with cells.open(newline="") as fh:
        aggregates = {(r["cell"], r["algo"], r["impl"]): r for r in csv.DictReader(fh)}
    families = collections.defaultdict(list)
    for mp in sorted(camp.glob("*/meta.json")):
        rd = mp.parent
        meta = load(mp)
        summ = load(rd / "summary.json")
        base = meta.get("rerun_of", meta["run"])
        p = planned[base]
        for k in (
            "cell",
            "algo",
            "cc",
            "impl",
            "duration",
            "group",
            "order",
            "rep",
            "rtt",
            "bw",
            "loss",
            "queue_bdp",
            "seed",
        ):
            assert p[k] == meta[k], (rd, k, p[k], meta[k])
        assert rd.name == meta["run"] == summ["run"] and (
            meta["commit"],
            meta["reuse_key"],
            meta["gate"],
        ) == (sha, key, gate)
        assert meta["duration_s"] == p["duration"] and meta["campaign"] == plan["plan"]["campaign"]
        families[(meta["cell"], meta["algo"])].append((meta, summ))
    assert len(families) == 16 and len(aggregates) == 32
    out.mkdir(parents=True, exist_ok=False)
    errors = {}
    evidence = []
    selected = []
    statuses = {}
    for (cell, algo), members in sorted(families.items()):
        pairs, bad, status = independently_count(members)
        statuses[cell + "/" + algo] = {
            "status": status,
            "invalid_pairs": bad,
            "valid_paired_reps": [g[0][0]["rep"] for g in pairs],
        }
        counted = {m["run"] for runs in pairs for m, s in runs}
        for meta, summ in members:
            run = meta["run"]
            try:
                row = details(camp / run, meta, summ, run in counted, A, M)
            except Exception as e:
                if summ["valid"]:
                    errors[run] = repr(e)
                row = {
                    k: meta.get(k)
                    for k in (
                        "run",
                        "cell",
                        "algo",
                        "impl",
                        "rep",
                        "group",
                        "rerun",
                        "order",
                        "slot",
                        "commit",
                        "reuse_key",
                    )
                }
                row.update(
                    valid=int(summ["valid"]),
                    counted=int(run in counted),
                    invalid=";".join(summ["invalid"]),
                    flags=";".join(summ["flags"]),
                    netem_seed=meta["seed"],
                    observed_cc=";".join(summ.get("sender_ccs", [])),
                    window_s=summ.get("window_s"),
                )
            evidence.append(row)
        for impl in ("linux", "utcp"):
            row = aggregates[(cell, algo, impl)]
            side = [(m, s) for runs in pairs for m, s in runs if m["impl"] == impl]
            assert row["status"] == status and int(row["n_counted"]) == len(side)
            if status != "ok":
                continue
            for metric in METRICS:
                values = [s[metric] for m, s in side if s.get(metric) is not None]
                assert int(row[metric + "_n"]) == len(values)
                if values:
                    for k, v in (
                        ("min", min(values)),
                        ("max", max(values)),
                        ("median", statistics.median(values)),
                    ):
                        assert row[metric + "_" + k] == A.fmt(v), (cell, algo, impl, metric, k)
            ordered = sorted(side, key=lambda ms: (ms[1]["goodput_bps"], ms[0]["run"]))
            med_m, med_s = ordered[len(ordered) // 2]
            selected.append(
                dict(
                    cell=cell,
                    algo=algo,
                    impl=impl,
                    run=med_m["run"],
                    goodput_bps=med_s["goodput_bps"],
                    group=med_m["group"],
                    rerun=med_m["rerun"],
                )
            )
    write_csv(out / "evidence.csv", ROWS, sorted(evidence, key=lambda r: (r["order"], r["rerun"])))
    write_csv(
        out / "overlay-runs.csv",
        ("cell", "algo", "impl", "run", "goodput_bps", "group", "rerun"),
        selected,
    )
    (out / "audit.json").write_text(
        json.dumps({"status": statuses, "errors": errors}, indent=2, sort_keys=True) + "\n"
    )
    print(
        json.dumps(
            {
                "runs": len(evidence),
                "aggregate_rows": len(aggregates),
                "selected": len(selected),
                "errors": errors,
                "unqualified": {k: v for k, v in statuses.items() if v["status"] != "ok"},
            },
            sort_keys=True,
        )
    )
    return bool(errors) or any(v["status"] != "ok" for v in statuses.values())


if __name__ == "__main__":
    sys.exit(main())
