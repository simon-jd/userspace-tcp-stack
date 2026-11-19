"""Replay the serial M2 matrix using its registered schedule and independent endpoint checks."""

import argparse
import hashlib
import json
import re
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CHECKPOINT = HERE.parent / "m2-checkpoint/verify"
sys.path[:0] = [str(HERE), str(REPO / "tools/m2"), str(CHECKPOINT)]
import analyze
import attempts
import checkpoint_inputs as checkpoint
import diagnostics
import endpoint_replay
import matrix
import physical_checkpoint
import verify_endpoint_cc
import verify_profile_trace

SOURCE = "4f9c9b89e16188fd65f3961af967cc3d83370d12"
GATE = "m2c-bbr/769311e-calib-a1-s0"
PLAN_SHA = "9a418b50e2d15530ceb9fe429467498bf5c177e6b93609d81b24258af02661ba"
EXPANDED_SHA = "18be22c23775f69ad508fcaf26cd21fd87d3f19f36488842c21e2d8972a95d23"
LINUX_COUNTERS = (
    "TcpExtTCPFullUndo",
    "TcpExtTCPPartialUndo",
    "TcpExtTCPDSACKUndo",
    "TcpExtTCPLossUndo",
    "TcpExtTCPSpuriousRTOs",
    "TcpExtTCPSpuriousRtxHostQueues",
)
read = checkpoint.load
write_csv = checkpoint.write_csv


def preregistered(campaign):
    path = HERE / "plan.toml"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == PLAN_SHA
    plan = matrix.load_plan(path)
    runs = matrix.expand_plan(plan, 1)
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in runs)
    assert hashlib.sha256(text.encode()).hexdigest() == EXPANDED_SHA
    assert read(campaign / "plan.json") == {"plan": plan, "runs": runs}
    assert len(runs) == 720 and len({(r["cell"], r["algo"]) for r in runs}) == 72
    return {r["run"]: r for r in runs}


def check_spec(directory, meta, spec, freeze, valid):
    retry = meta["rerun"]
    assert (
        directory.name
        == meta["run"]
        == (spec["run"] if not retry else f"{spec['run']}-rerun{retry}")
    )
    assert (not retry and "rerun_of" not in meta) or (
        retry > 0 and meta["rerun_of"] == spec["run"]
    )
    for key in spec.keys() - {"run", "slot_index"}:
        assert meta[key] == spec[key], (directory, key, meta[key], spec[key])
    static = {**freeze["static"], "commit": SOURCE}
    assert all(meta[k] == v for k, v in static.items()), directory
    assert meta["campaign"] == "m2-matrix" and meta["gate"] == GATE
    assert (
        meta["duration_s"] == spec["duration"]
        and meta["timing"] is True
        and meta["slot"] == 0
    )
    assert matrix.timing_placement(0, meta["cpusets"])
    if valid or "reuse_key" in meta:
        assert meta.get("reuse_key") == freeze["slots"]["0"]["reuse_key"], directory
    if valid:
        assert type(meta.get("sender_exit")) is int and meta["sender_exit"] == 0
    assert not meta.get("stack_args")
    if spec["impl"] == "linux":
        assert not meta.get("stack_set") and not meta["profile"]
    else:
        assert (
            meta["stack_set"] == verify_profile_trace.BASE_SETS
            and meta["profile"] == "linux"
        )


def optional_sender_deltas(directory, meta, fields):
    """Keep available counters for an interrupted run. An absent snapshot leaves its delta unknown."""
    samples = []
    for phase in ("pre", "post"):
        path = directory / phase / "record.txt"
        rec = analyze.parse_record(path.read_text()) if path.is_file() else {}
        sender = meta.get("containers", {}).get("snd")
        samples.append(analyze.parse_nstat(rec.get((sender, "nstat -asz"), [])))
    return {
        k: samples[1][k] - samples[0][k] if all(k in x for x in samples) else None
        for k in fields
    }


def check_records(directory, meta, freeze):
    physical_checkpoint.kernel_netem(directory, meta)
    assert meta["bdp_bytes"] == int(meta["bw"] * 1e6 * meta["rtt"] / 8000)
    expected_burst = max(2 * 1514, int(meta["bw"] * 1e6 / 8000))
    assert meta["burst_bytes"] == expected_burst
    assert meta["ifaces"] == freeze["slots"]["0"]["ifaces"]
    snapshots = []
    for phase in ("pre", "post"):
        text = (directory / phase / "record.txt").read_text()
        records = analyze.parse_record(text)
        dump = matrix.sysctl_dump(text)
        assert matrix.reuse_key(meta, dump) == freeze["slots"]["0"]["reuse_key"]
        assert (
            hashlib.sha256(dump.encode()).hexdigest()
            == freeze["slots"]["0"]["sysctl_sha256"]
        )
        for container, cpuset in meta["cpusets"].items():
            assert records[container, "cpuset"] == [cpuset]
        assert records["host", "uname -r"] == [meta["uname_r"]]
        ingress_router = meta["containers"]["r1"]
        (netem,) = (
            line
            for line in records[ingress_router, "tc -s -raw qdisc"]
            if line.startswith("qdisc netem ")
        )
        assert " limit 20000 " in netem, (directory, phase, netem)
        router = meta["containers"]["r2"]
        (tbf,) = (
            line
            for line in records[router, "tc -s -raw qdisc"]
            if line.startswith("qdisc tbf ")
        )
        for field, value in (
            ("dev", meta["ifaces"]["r2_c"]),
            ("rate", f"{meta['bw']}Mbit"),
            ("limit", f"{meta['queue_bytes']}b"),
        ):
            assert re.search(r"\b" + field + " " + value + r"\b", tbf), (
                directory,
                phase,
                tbf,
            )
        # Both rates have exact byte readbacks on the recorded kernel and the approved gate.
        (burst,) = re.findall(r"\bburst (\S+)", tbf)
        assert burst == f"{expected_burst}b", (directory, phase, tbf)
        snapshots.append(
            (
                analyze.parse_nstat(records[meta["containers"]["snd"], "nstat -asz"]),
                burst,
            )
        )
    before, after = snapshots
    assert before[1] == after[1], directory
    return {name: after[0][name] - before[0][name] for name in LINUX_COUNTERS}, before[
        1
    ]


def endpoint_details(rd, meta, summary, counted):
    """Endpoint and capture checks shared with the checkpoint, with trace verification in trace_row."""
    observed = endpoint_replay.audit_run(rd, analyze)
    window = matrix.measured_transfer_window(summary, meta["duration_s"])
    assert window == (observed["lo_ns"], observed["hi_ns"])
    assert (
        meta["slot"] == 0
        and meta["timing"] is True
        and matrix.timing_placement(0, meta["cpusets"])
    )
    assert (
        meta["uptime"] and meta["top_cpu"] and isinstance(meta["threads_on_8_15"], list)
    )
    assert set(summary["softirqs"]) == set(analyze.SOFTIRQ_KINDS)
    assert set(summary["cpu"]) == {"8", "9", "10", "11"}
    assert all(v["total"] > 0 and v["busy"] >= 0 for v in summary["cpu"].values())
    assert (
        summary["foreign_cpu"]["upper_frac"]
        >= summary["foreign_cpu"]["lower_frac"]
        >= 0
    )
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
            type(cap[k]) is int
            for k in ("captured", "received_by_filter", "kernel_dropped", "bytes")
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


ELIGIBLE_COUNTERS = (
    "TcpRetransSegs",
    "TcpExtTCPTimeouts",
    "TcpExtTCPFastRetrans",
    "TcpExtTCPSlowStartRetrans",
    "TcpExtTCPLossProbes",
)


def verified_trace(path, meta, conn, stats, summary, sender_records=None):
    """A trace sink can be enabled for an entire transfer without receiving an eligible event."""
    assert meta["trace"] is True and path.is_file(), (path, "missing or disabled trace")
    n = stats.get("trace_events")
    assert (
        type(n) is int
        and n >= 0
        and type(stats.get("trace_blocks")) is int
        and stats["trace_blocks"] > 0
    )
    assert type(summary.get("trace_events")) is int and summary["trace_events"] == n
    if n:
        return verify_profile_trace.check_trace(path, meta, conn, n)
    assert path.stat().st_size == 0, (path, "bytes with zero emitted events")
    assert summary["capture"]["r1-in"]["retrans_segs"] == 0, (
        path,
        "ingress capture includes retransmissions",
    )
    for k in ELIGIBLE_COUNTERS:
        assert stats[k] == 0 and summary["sender_counters"][k] == 0, (path, k)
    records = (
        list(diagnostics.rows(path.with_name("snd.jsonl")))
        if sender_records is None
        else sender_records
    )
    samples = [r for r in records if r.get("ev") == "sample"]
    terminals = [r for r in records if r.get("ev") == "summary"]
    assert samples and len(terminals) == 1, (path, "missing lifetime socket records")
    for row in samples + terminals:
        assert row.get("role") == "sender" and row.get("total_retrans") == 0, (
            path,
            "lifetime sender total_retrans",
        )
        for key in ("bytes_retrans", "retrans"):
            if key in row:
                assert row[key] == 0, (path, "lifetime sender " + key)
    return Counter(), hashlib.sha256(b"").hexdigest()


def trace_row(directory, meta, summary, profile):
    records = list(diagnostics.rows(directory / "snd.jsonl"))
    assert [r for r in records if r.get("ev") == "config"] == [profile]
    (conn,) = {r["conn_id"] for r in records if r.get("ev") == "sample"}
    stats = read(directory / "stats.json")
    counts, digest = verified_trace(
        directory / "trace.jsonl", meta, conn, stats, summary, records
    )
    modes = Counter()
    lt = Counter()
    ranges = {}
    for event in diagnostics.rows(directory / "trace.jsonl"):
        assert ("bbr_mode" in event) == (meta["cc"] == "bbr"), (
            directory,
            "per-connection BBR trace model",
        )
        if "bbr_mode" not in event:
            continue
        assert event["bbr_mode"] in {"STARTUP", "DRAIN", "PROBE_BW", "PROBE_RTT"}
        modes[event["bbr_mode"]] += 1
        assert type(event["bbr_lt_use_bw"]) is bool
        lt[str(event["bbr_lt_use_bw"]).lower()] += 1
        for key in (
            "bbr_bandwidth_q24",
            "bbr_min_rtt_us",
            "bbr_cwnd_gain_q8",
            "bbr_pacing_gain_q8",
        ):
            value = event[key]
            assert type(value) is int and value >= 0
            low, high = ranges.get(key, (value, value))
            ranges[key] = (min(low, value), max(high, value))
    return dict(
        run=meta["run"],
        algo=meta["algo"],
        profile=meta["profile"],
        observed_default_cc=profile["cc"],
        effective_profile_fields=len(profile),
        trace_events=stats["trace_events"],
        trace_blocks=stats["trace_blocks"],
        trace_sha256=digest,
        bbr_modes=json.dumps(modes, sort_keys=True),
        bbr_lt_selection=json.dumps(lt, sort_keys=True),
        bbr_observed_ranges=json.dumps(ranges, sort_keys=True),
        **{"trace_" + k: counts[k] for k in sorted(verify_profile_trace.TRACE_KINDS)},
    )


def partial_row(directory, meta, summary):
    row = {k: meta[k] for k in checkpoint.ROWS if k in meta}
    row.update(
        valid=0,
        counted=0,
        flags=";".join(summary["flags"]),
        invalid=";".join(summary["invalid"]),
        netem_seed=meta["seed"],
        observed_cc=";".join(summary.get("sender_ccs", [])),
        window_s=summary.get("window_s"),
        kernel=meta.get("uname_r"),
        image=meta.get("image_id"),
        cpusets=json.dumps(meta["cpusets"], sort_keys=True),
    )
    for interface, cap in summary.get("capture", {}).items():
        for key, source in (
            ("captured", "captured"),
            ("filter", "received_by_filter"),
            ("dropped", "kernel_dropped"),
        ):
            row[interface + "_" + key] = cap.get(source)
    return row


def preserved_attempts(campaign, planned):
    return attempts.preserved(campaign, planned, analyze.ARCHIVE_FILES)


def main(campaign, out, live=False):
    planned = preregistered(campaign)
    frozen = read(HERE.parent / "m2-bbr/freeze.json")
    profile = read(CHECKPOINT / "linux-profile.json")
    families = defaultdict(list)
    excluded = {}
    for path in sorted(campaign.glob("*/meta.json")):
        directory = path.parent
        meta = read(path)
        saved = directory / "summary.json"
        if live and not saved.exists():
            continue
        summary = read(saved) if saved.exists() else analyze.summarize_run(directory)
        valid = summary["valid"]
        assert type(valid) is bool and summary["run"] == meta["run"]
        check_spec(
            directory, meta, planned[meta.get("rerun_of", meta["run"])], frozen, valid
        )
        if not valid:
            assert summary["invalid"] and summary == analyze.summarize_run(directory)
            excluded[meta["run"]] = dict(
                reasons=summary["invalid"],
                flags=summary["flags"],
                saved_summary=saved.is_file(),
                available_inputs=[
                    n for n in analyze.ARCHIVE_FILES if (directory / n).is_file()
                ],
                absent_metadata=[
                    k
                    for k in (
                        "reuse_key",
                        "sender_exit",
                        "uptime",
                        "top_cpu",
                        "threads_on_8_15",
                        "module_parameters",
                    )
                    if k not in meta
                ],
            )
        families[meta["cell"], meta["algo"]].append((meta, summary))
    if not live:
        assert len(families) == 72
        assert {
            m.get("rerun_of", m["run"])
            for members in families.values()
            for m, _ in members
        } == planned.keys()
    history = preserved_attempts(campaign, planned)
    chronology = attempts.timeline(campaign, families, history)
    by_condition = defaultdict(list)
    orphaned = []
    for item in history:
        if item["group"] is None:
            orphaned.append(item["path"])
        else:
            by_condition[item["cell"], item["algo"]].append(item)
    out.mkdir(parents=True, exist_ok=False)
    rows, trace, controls, medians, statuses = [], [], [], [], {}
    for cell, algo in sorted(families.keys() | by_condition.keys()):
        members = families[cell, algo]
        pairs, ledger = attempts.qualify(
            members,
            by_condition[cell, algo],
            checkpoint.independently_count,
            chronology,
        )
        if orphaned:
            pairs = []
            ledger.update(status="indeterminate (unassigned archive)", counted_pairs=0)
            ledger["association_issues"].extend(orphaned)
        status = ledger["status"]
        reps = [pair[0][0]["rep"] for pair in pairs]
        assert len(set(reps)) == len(reps)
        if status == "ok":
            assert set(reps) == set(range(5)) and len(ledger["bad_pairs"]) <= 3
        statuses[f"{cell}/{algo}"] = ledger
        counted = {m["run"] for pair in pairs for m, s in pair}
        for meta, summary in members:
            name = meta["run"]
            directory = campaign / name
            if not summary["valid"]:
                rows.append(partial_row(directory, meta, summary))
                if meta["impl"] == "linux":
                    controls.append(
                        dict(
                            run=name,
                            impl="linux",
                            seed=meta["seed"],
                            configured_burst_bytes=meta.get("burst_bytes"),
                            kernel_burst=None,
                            **optional_sender_deltas(directory, meta, LINUX_COUNTERS),
                        )
                    )
                continue
            row = endpoint_details(directory, meta, summary, name in counted)
            controls_delta, burst = check_records(directory, meta, frozen)
            if meta["impl"] == "utcp":
                trace.append(trace_row(directory, meta, summary, profile))
            else:
                assert not any(
                    r.get("ev") == "config"
                    for r in diagnostics.rows(directory / "snd.jsonl")
                )
            controls.append(
                dict(
                    run=name,
                    impl=meta["impl"],
                    seed=meta["seed"],
                    configured_burst_bytes=meta["burst_bytes"],
                    kernel_burst=burst,
                    **controls_delta,
                )
            )
            rows.append(row)
        if status == "ok":
            for side in ("utcp", "linux"):
                ranked = sorted(
                    (s["goodput_bps"], m["run"])
                    for pair in pairs
                    for m, s in pair
                    if m["impl"] == side
                )
                rate, name = ranked[len(ranked) // 2]
                medians.append(
                    dict(cell=cell, algo=algo, impl=side, run=name, goodput_bps=rate)
                )
    write_csv(
        out / "attempt-chronology.csv",
        (
            "path",
            "source",
            "group",
            "rerun",
            "in_group",
            "valid",
            "attempted",
            "first_ns",
            "last_ns",
            "position",
            "order_issue",
        ),
        sorted(
            chronology.values(),
            key=lambda r: (r.get("position", float("inf")), r["path"]),
        ),
    )
    rows.sort(key=lambda r: (r["order"], r["rerun"]))
    write_csv(out / "evidence.csv", checkpoint.ROWS, rows)
    for filename, data in (
        ("profile-trace.csv", trace),
        ("network-records.csv", controls),
        ("overlay-runs.csv", medians),
    ):
        if data:
            write_csv(
                out / filename, data[0].keys(), sorted(data, key=lambda r: r["run"])
            )
    for filename, data in (
        ("qualification.json", statuses),
        ("invalid-attempts.json", excluded),
        ("preserved-attempts.json", history),
    ):
        (out / filename).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    with tempfile.TemporaryDirectory() as scratch:
        valid_file = Path(scratch) / "valid.csv"
        write_csv(
            valid_file,
            checkpoint.ROWS,
            [dict(r, counted=1) for r in rows if r["valid"]],
        )
        verify_endpoint_cc.main(campaign, valid_file, out / "endpoint-cc.csv")
    diagnostics.main(campaign, out / "evidence.csv", out / "trace-diagnostics.csv")
    print(
        "rows",
        len(rows),
        "pairs",
        sum(s["counted_pairs"] for s in statuses.values()),
        "conditions",
        len(statuses),
    )
    if not live:
        assert all(s["status"] == "ok" for s in statuses.values()), statuses


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument(
        "--live",
        action="store_true",
        help="audit finished runs only while acquisition continues",
    )
    args = parser.parse_args()
    main(args.campaign, args.out, args.live)
