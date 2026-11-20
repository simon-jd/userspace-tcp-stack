#!/usr/bin/env python3
"""Private multi-flow study: capture, validate one measured run, or replay a campaign."""

import argparse
from bisect import bisect_left, bisect_right
import csv
import hashlib
import json
import math
import re
import statistics
import struct
import sys
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / "tools/m2"))
import analyze as A
import matrix as M
import capture_evidence as C

N = A.NS
SCHEDULE_SHA = "2578224d2af0326873288b34c8d1b102c2f52ebda0edd8b830df0debf3ddf327"
ATTEMPT = re.compile(r"p(\d{3})-a(\d{2})-(test|baseline)")
START_TOLERANCE_NS = 500_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_bytes())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@lru_cache(maxsize=2)
def schedule(path):
    require(sha(path) == SCHEDULE_SHA, "schedule SHA-256 differs from preregistration")
    with path.open() as f:
        return {int(r["pair_order"]): r for r in csv.DictReader(f)}


def specification(meta, row, side):
    values = {
        "pair_order": int(row["pair_order"]),
        "scenario": int(row["scenario"]),
        "rep": int(row["rep"]),
        "pair_seed": int(row["pair_seed"]),
        "side": side,
        "duration_s": int(row["wall_duration_s"]),
        "bw_mbit": int(row["mbit_s"]),
        "rtt_ms": int(row["rtt_ms"]),
        "loss_pct": 0,
        "queue_bdp": 2,
    }
    for k, v in values.items():
        require(meta[k] == v, f"metadata {k} differs from frozen schedule")
    roles = row[f"flow_roles_{side}_by_id"].split()
    joins = list(map(int, row["flow_join_offsets_s"].split()))
    ports = list(map(int, row["listener_ports"].split()))
    fs = meta["flows"]
    require(len(fs) == len(roles), "wrong number of participants")
    for i, (f, role, join, port) in enumerate(
        zip(fs, roles, joins, ports, strict=True)
    ):
        backend, cc = role.split("/")
        expected = dict(
            id=f"f{i}",
            backend=backend,
            cc=cc,
            port=port,
            join_s=join,
            tun=f"utcp{i}" if backend == "stack" else None,
            source_ip=f"198.18.{8 * meta['slot'] + i}.2"
            if backend == "stack"
            else meta["snd_ip"],
            duration_s=meta["duration_s"] - join,
            profile="linux" if backend == "stack" else None,
        )
        for k, v in expected.items():
            require(f[k] == v, f"flow f{i} {k} differs from frozen role")
    return fs


@lru_cache(maxsize=8)
def calibration(directory, key, slot, bw, rtt):
    gate_path = directory / "gate.json"
    gate = read(gate_path)
    error = M.gate_rejects(gate, slot, key)
    require(error is None, f"calibration gate: {error}")
    for rel, digest in gate["sources"].items():
        require(
            A.proof_meta_digest(read(directory / rel)) == digest,
            f"calibration source differs: {rel}",
        )
    rows = [
        row
        for row in gate["items"]
        if (row["item"], row.get("bw"), row.get("rtt"), row.get("queue_bdp"))
        == (2, bw, rtt, 2)
    ]
    require(len(rows) == 1, "missing or duplicate item-2 capacity")
    row = rows[0]
    source = directory / row["run"]
    meta, summary = read(source / "meta.json"), read(source / "summary.json")
    for k, v in dict(
        slot=slot,
        reuse_key=key,
        impl="linux",
        cc="cubic",
        gate="rate",
        bw=bw,
        rtt=rtt,
        queue_bdp=2,
        loss=0,
        run=row["run"],
    ).items():
        require(meta[k] == v, f"calibration source {k} mismatch")
    require(
        summary["valid"] is True
        and not summary["invalid"]
        and summary["sender_ccs"] == ["cubic"]
        and summary["proof_meta_sha256"] == A.proof_meta_digest(meta),
        "invalid calibration source run",
    )
    value = summary["goodput_bps"]
    require(
        math.isfinite(value) and value > 0 and value == row["goodput_bps"],
        "calibration C mismatch",
    )
    return dict(
        capacity_bps=value,
        calibration_gate=gate["campaign"],
        calibration_run=row["run"],
        gate_sha256=sha(gate_path),
        capacity_source_path=f"{gate['campaign']}/{row['run']}/summary.json",
        capacity_source_sha256=sha(source / "summary.json"),
    )


MAX_GAP_NS = 100_000_000


def bound_observed(ser, t):
    i = bisect_left(ser, (t,))
    if i < len(ser) and ser[i][0] == t:
        return True
    return 0 < i < len(ser) and ser[i][0] - ser[i - 1][0] <= MAX_GAP_NS


def rate(ser, lo, hi):
    require(hi > lo, "empty rate window")
    require(
        bound_observed(ser, lo) and bound_observed(ser, hi),
        "receiver samples fail to bracket required window within 100 ms",
    )
    return A.delta(ser, lo, hi) * 8 * N / (hi - lo)


def convergence_result(series, join, end, capacity):
    # A 1 s rate requires observation throughout that second. A gap touching
    # a bound only at its real observed endpoint does not hide that window.
    gaps = [
        [(a[0], b[0]) for a, b in zip(s, s[1:]) if b[0] - a[0] > MAX_GAP_NS]
        for s in series
    ]
    firsts = [s[0][0] for s in series]
    initial = sum(
        any(t < first for first in firsts)
        for t in range(join, min(end, max(firsts)) + 1, MAX_GAP_NS)
    )
    out = dict(
        unbracketed_initial_checks=initial,
        receiver_large_gap_count=sum(map(len, gaps)),
        convergence_s=None,
        earliest_possible_s=None,
        latest_observable_onset_s=None,
        unknown_rate_checks=0,
        convergence_status="unobserved-calibration",
    )
    if capacity is None:
        return out
    require(math.isfinite(capacity) and capacity > 0, "invalid calibration capacity")
    fair = capacity / len(series)
    states = []
    checks = list(range(join + N, end + 1, MAX_GAP_NS))
    require(len(checks) >= 51, "insufficient horizon for five-second hold")
    starts = [[a for a, b in g] for g in gaps]
    for t in checks:
        values = []
        for s, g, gs in zip(series, gaps, starts):
            j = bisect_left(gs, t) - 1
            if (j >= 0 and g[j][1] > t - N) or t - N < s[0][0] or t > s[-1][0]:
                values.append(None)
            else:
                values.append(abs(A.delta(s, t - N, t) * 8 - fair) <= 0.2 * fair)
        states.append(False if False in values else None if None in values else True)
    out["unknown_rate_checks"] = states.count(None)
    out["latest_observable_onset_s"] = (checks[-51] - join) / N
    first_possible = first_known = None
    for i in range(len(states) - 50):
        run = states[i : i + 51]
        if False not in run and first_possible is None:
            first_possible = (checks[i] - join) / N
        if all(x is True for x in run):
            first_known = (checks[i] - join) / N
            break
    if not any(gaps):
        canonical = A.convergence_time(series, join, end, capacity)
        require(
            canonical == first_known,
            "covered convergence disagrees with canonical estimator",
        )
    out.update(
        convergence_s=first_known,
        earliest_possible_s=first_possible,
        convergence_status=(
            "converged"
            if first_known is not None
            else "unobserved-sampling"
            if first_possible is not None
            else "right-censored"
        ),
    )
    return out


def windows(flows, duration, capacity):
    t0 = min(f["accept_ns"] for f in flows[:-1])
    join = flows[-1]["accept_ns"]
    spread = max(f["accept_ns"] for f in flows[:-1]) - t0
    require(
        spread <= START_TOLERANCE_NS and abs(join - t0 - 20 * N) <= START_TOLERANCE_NS,
        "actual accept stagger outside 500 ms tolerance",
    )
    nominal = t0 + duration * N
    active = min(nominal, *(f["connect_ns"] + f["duration_s"] * N for f in flows))
    fair = join + 20 * N
    rows = []
    for f in flows:
        ser = f["series"]
        require(
            ser and ser[0][0] <= f["accept_ns"] + 100_000_000,
            "missing initial receiver samples",
        )
        warm = f["accept_ns"] + 5 * N
        rows.append(
            dict(
                id=f["id"],
                accept_ns=f["accept_ns"],
                connect_ns=f["connect_ns"],
                release_ns=f["release_ns"],
                accept_offset_s=(f["accept_ns"] - t0) / N,
                connect_offset_s=(f["connect_ns"] - t0) / N,
                release_offset_s=(f["release_ns"] - t0) / N,
                write_end_ns=f["connect_ns"] + f["duration_s"] * N,
                warm_start_ns=warm,
                goodput_bps=rate(ser, warm, active),
                fair_nominal_bps=rate(ser, fair, nominal),
                fair_active_bps=rate(ser, fair, active),
            )
        )
    nominal_rates = [r["fair_nominal_bps"] for r in rows]
    active_rates = [r["fair_active_bps"] for r in rows]
    jn, ja = A.jain(nominal_rates), A.jain(active_rates)
    series = [f["series"] for f in flows]
    conv = convergence_result(series, join, active, capacity)
    horizon = (active - join) / N
    return dict(
        t0_ns=t0,
        join_ns=join,
        incumbent_spread_s=spread / N,
        join_error_s=(join - t0) / N - 20,
        nominal_end_ns=nominal,
        active_end_ns=active,
        fair_start_ns=fair,
        drain_s=(nominal - active) / N,
        jain_nominal=jn,
        jain_active=ja,
        aggregate_active_bps=sum(active_rates),
        observed_horizon_s=horizon,
        **conv,
    ), rows


def overlay_run(rows):
    require(
        len(rows) == 5 and len({r["rep"] for r in rows}) == 5,
        "five distinct counted reps required",
    )
    value = statistics.median(r["aggregate_active_bps"] for r in rows)
    return min(
        (r for r in rows if r["aggregate_active_bps"] == value), key=lambda r: r["rep"]
    )


def one(records, kind):
    rows = [r for r in records if r["ev"] == kind]
    require(len(rows) == 1, f"missing or repeated {kind} event")
    return rows[0]


def option(argv, name):
    require(argv.count(name) == 1, f"missing or repeated argv {name}")
    return argv[argv.index(name) + 1]


def lateness_evidence(stats, summary):
    """Read the whole-process histogram and independently recover its p99."""
    buckets = {
        int(key.removeprefix("loop_lateness_bucket_")): count
        for key, count in stats.items()
        if key.startswith("loop_lateness_bucket_")
    }
    require(
        buckets
        and all(0 <= k <= 63 and type(v) is int and v >= 0 for k, v in buckets.items()),
        "missing or malformed lateness histogram",
    )
    observed = sum(buckets.values())
    maximum = stats["loop_lateness_max_ns"]
    require(
        all(
            type(value) is int and value >= 0
            for value in (
                maximum,
                stats["loop_lateness_count"],
                summary["lateness_count"],
                summary["lateness_max_ns"],
                summary["lateness_p99_ns"],
            )
        )
        and observed > 0
        and maximum.bit_length() == max(k for k, v in buckets.items() if v),
        "maximum or observation count disagrees with occupied lateness buckets",
    )
    upper = M.hist_percentile(buckets, 0.99, maximum)
    require(
        observed > 0
        and observed == stats["loop_lateness_count"] == summary["lateness_count"]
        and maximum == summary["lateness_max_ns"]
        and upper == summary["lateness_p99_ns"],
        "event-loop histogram and sender summary disagree",
    )
    return {"lateness_histogram": buckets, "lateness_count": observed}


def endpoint(folder, meta, f):
    times, summaries, samples, launches, clocks = [], [], [], [], []
    for side, role in (("snd", "sender"), ("rcv", "receiver")):
        backend = "utcp" if side == "snd" and f["backend"] == "stack" else "kernel"
        argv = read(folder / f"{side}.argv.json")
        require(
            isinstance(argv, list)
            and option(argv, "--backend") == backend
            and option(argv, "--sample-ms") == "10",
            f"{side} backend or sampling mismatch",
        )
        suffix = f"/flows/{f['id']}/{side}.jsonl"
        require(
            option(argv, "--jsonl").endswith(suffix), f"{side} endpoint path mismatch"
        )
        require(
            (folder / f"{side}.exit").read_text().strip() == "0", f"{side} nonzero exit"
        )
        if side == "snd":
            require(
                "--send" in argv
                and option(argv, "--connect") == f"{meta['rcv_ip']}:{f['port']}"
                and option(argv, "--cc") == f["cc"]
                and float(option(argv, "--duration")) == f["duration_s"],
                "sender argv role, port, CC or duration mismatch",
            )
            if backend == "utcp":
                require(
                    option(argv, "--tun") == f["tun"]
                    and option(argv, "--addr") == f["source_ip"]
                    and option(argv, "--profile") == "linux",
                    "sender TUN/address/profile mismatch",
                )
        else:
            require(
                "--recv" in argv and int(option(argv, "--listen")) == f["port"],
                "listener port/role mismatch",
            )
        launched = read(folder / f"{side}.launch.json")
        require(
            0 < launched["before_popen_ns"] <= launched["after_popen_ns"]
            and launched["pid"] > 0,
            f"invalid {side} launch",
        )
        launches.append(launched)
        records = A.read_jsonl(folder / f"{side}.jsonl")
        clock, start, summary = (one(records, k) for k in ("clock", "start", "summary"))
        if backend == "utcp":
            reference = read(HERE.parent / "m2-checkpoint/verify/linux-profile.json")
            require(
                one(records, "config") == reference,
                "measured stack profile differs from linux_compat baseline",
            )
            for flag, filename in (
                ("--trace", "trace.jsonl"),
                ("--stats", "stats.json"),
            ):
                require(
                    option(argv, flag).endswith(f"/flows/{f['id']}/{filename}"),
                    "trace/stats argv identity mismatch",
                )
        rows = [r for r in records if r["ev"] == "sample"]
        require(
            len({r["conn_id"] for r in rows}) == 1,
            f"{side} sample connection identity changed",
        )
        require(
            start["role"] == summary["role"] == role
            and summary["backend"] == backend
            and summary["ok"] is True
            and summary["bytes"] > 0
            and re.fullmatch("[0-9a-f]{64}", summary["sha256"]),
            f"invalid {side} endpoint",
        )
        require(
            start["t"] >= launched["before_popen_ns"],
            f"{side} start precedes process release",
        )
        require(
            len(rows) >= 2
            and len(rows) == summary["samples"]
            and all(r["role"] == role for r in rows)
            and all(a["t"] < b["t"] for a, b in zip(rows, rows[1:])),
            f"{side} sample count/order/role",
        )
        require(
            start["t"] <= rows[0]["t"] and rows[-1]["t"] > start["t"],
            "invalid endpoint clock ordering",
        )
        # stdout is an independent copy of the terminal summary.
        require(
            summary
            == json.loads(
                (folder / f"{side}.out").read_text().strip().splitlines()[-1]
            ),
            f"{side} stdout summary mismatch",
        )
        times.append(start["t"])
        summaries.append(summary)
        samples.append(rows)
        clocks.append(A.Clock(clock["monotonic_ns"], clock["realtime_ns"]))
    snd, rcv = summaries
    require(
        (snd["bytes"], snd["sha256"]) == (rcv["bytes"], rcv["sha256"]),
        "endpoint payload/hash mismatch",
    )
    measured = f["cc"]  # kernel_transport normalizes TCP_CONGESTION reno to newreno.
    require(
        snd["cc"] == measured and {r["cc_name"] for r in samples[0]} == {measured},
        "measured sender CC mismatch",
    )
    require(
        {r["cc_name"] for r in samples[1]} == {rcv["cc"]} and bool(rcv["cc"]),
        "receiver CC missing/changed",
    )
    series = [(r["t"], r["bytes_received"]) for r in samples[1]]
    require(
        all(0 <= a[1] <= b[1] for a, b in zip(series, series[1:])),
        "receiver counter decreased",
    )
    require(
        launches[0]["before_popen_ns"] >= launches[0]["target_ns"],
        "sender released early",
    )
    return dict(
        **f,
        connect_ns=times[0],
        accept_ns=times[1],
        release_ns=launches[0]["before_popen_ns"],
        target_ns=launches[0]["target_ns"],
        sender_pid=launches[0]["pid"],
        receiver_pid=launches[1]["pid"],
        series=series,
        sender_samples=samples[0],
        receiver_last=samples[1][-1],
        clock=clocks[0],
        bytes=snd["bytes"],
        sha256=snd["sha256"],
        sender_cc=measured,
        receiver_cc=rcv["cc"],
        lateness_count=snd.get("lateness_count"),
        sender_clock_to_last_sample_s=(samples[0][-1]["t"] - clocks[0].monotonic_ns)
        / N,
        sender_connect_to_last_sample_s=(samples[0][-1]["t"] - times[0]) / N,
        sender_summary_duration_s=snd["duration_us"] / 1e6,
        lateness_p99_ns=snd.get("lateness_p99_ns"),
        lateness_max_ns=snd.get("lateness_max_ns"),
    )


def wire_check(evidence, fs):
    results = {f["id"]: {} for f in fs}
    for name in ("r1-in", "r2-out"):
        cap = evidence[name]
        require(
            cap["records"] > 0
            and all(type(cap[k]) is int for k in ("captured", "filtered", "dropped")),
            f"{name} lacks capture evidence",
        )
        require(len(cap["tuples"]) == len(fs), f"{name} unexpected or missing tuple")
        for f in fs:
            matches = [t for t in cap["tuples"] if t["dport"] == f["port"]]
            require(len(matches) == 1, f"{name} ambiguous or missing port {f['port']}")
            t = matches[0]
            require(
                t["src"] == f["source_ip"]
                and t["dst"] == f["destination_ip"]
                and 0 < t["sport"] < 65536
                and t["data_segments"] > 0
                and t["isn"] is not None
                and t["stream_bytes"] == f["bytes"],
                f"{f['id']} {name} wire identity or payload mismatch",
            )
            r = results[f["id"]]
            identity = (t["src"], t["sport"], t["dst"], t["dport"], t["isn"])
            require(
                r.get("identity", identity) == identity,
                f"{f['id']} tuples differ between captures",
            )
            r.update(
                identity=identity,
                **{
                    f"{name}_data_segments": t["data_segments"],
                    f"{name}_retrans_segments": t["retrans_segments"],
                },
            )
    return results


def record_check(rd, meta, fs):
    roles, cpus = meta["containers"], A.cpu_list(meta["slot_cpus"])
    snapshots = []
    tun_routes = {}
    shape = (rd / "shape.txt").read_text().splitlines()
    shape_rows = [line.split() for line in shape if line.startswith("shape: slot ")]
    require(len(shape_rows) == 1, "missing or duplicate shaping record")
    row = shape_rows[0]
    params = dict(zip(row[1::2], row[2::2], strict=True))
    for k in (
        "slot",
        "bw_mbit",
        "rtt_ms",
        "queue_bytes",
        "burst_bytes",
        "bdp_bytes",
        "loss_pct",
    ):
        require(float(params[k]) == meta[k], f"shape metadata {k} mismatch")
    require(
        int(params["seed"]) == meta["pair_seed"]
        and meta["bdp_bytes"] == int(meta["bw_mbit"] * meta["rtt_ms"] * 125)
        and meta["queue_bytes"] == 2 * meta["bdp_bytes"]
        and meta["burst_bytes"] == max(3028, int(meta["bw_mbit"] * 125)),
        "shaping seed/BDP mismatch",
    )
    for name in ("pre", "post"):
        doc = (rd / name / "record.txt").read_text()
        require(
            M.reuse_key(meta, M.sysctl_dump(doc)) == meta["reuse_key"],
            f"{name} fingerprint mismatch",
        )
        raw = A.parse_record(doc)
        snap = A.record_counters(raw, roles.values())
        line = snap["qdisc"][roles["r1"]][meta["ifaces"]["r1_b"]]["line"]
        require(
            re.findall(r"\bseed (\d+)\b", line) == [str(meta["pair_seed"])]
            and list(map(float, re.findall(r"\bdelay ([0-9.]+)ms\b", line)))
            == [meta["rtt_ms"]]
            and "loss" not in line,
            f"{name} kernel netem disagrees with registered cell",
        )
        require(
            snap["qdisc"][roles["r2"]][meta["ifaces"]["r2_c"]]["kind"] == "tbf",
            f"{name} missing forward TBF",
        )
        tbf_line = snap["qdisc"][roles["r2"]][meta["ifaces"]["r2_c"]]["line"]
        require(
            re.findall(r"\brate (\d+)Mbit\b", tbf_line) == [str(int(meta["bw_mbit"]))]
            and re.findall(r"\bburst (\d+)b\b", tbf_line) == [str(meta["burst_bytes"])]
            and re.findall(r"\blimit (\d+)b\b", tbf_line) == [str(meta["queue_bytes"])],
            f"{name} kernel TBF disagrees with registered cell",
        )
        missing = A.missing_gate_counters(snap, roles, meta["ifaces"], cpus)
        require(not missing, f"{name} missing network counters {missing}")
        for c in roles.values():
            require(
                "".join(raw[(c, "cpuset")]).strip() == meta["cpusets"][c],
                f"{name} cpuset mismatch",
            )
        for f in fs:
            if f["tun"]:
                d = f["tun"]
                require(
                    snap["qdisc"][roles["snd"]][d]["kind"] == "pfifo",
                    f"{d} missing pfifo",
                )
                network = f["source_ip"].rsplit(".", 1)[0] + ".0/24"
                routes = raw[(roles["snd"], "ip route")]
                require(
                    any(
                        line.startswith(network + " ") and f" dev {d} " in line + " "
                        for line in routes
                    ),
                    f"{d} route mismatch",
                )
        snapshots.append(snap)
    pre, post = snapshots
    bad, squeeze = A.local_drops(pre, post, roles, cpus)
    require(not bad, f"local drops {bad}")
    flags = ["time_squeeze"] if squeeze else []
    foreign = A.foreign_cpu(pre, post, cpus, list(roles.values()))
    require(foreign is not None, "missing foreign CPU observation")
    if foreign["lower_frac"] >= A.FOREIGN_CPU_FLAG_FRACTION:
        flags.append("foreign_cpu")
    for f in fs:
        if f["tun"]:
            dev = f["tun"]
            before, after = (snap["link"][roles["snd"]][dev] for snap in snapshots)
            diffs = {k: after[k] - before[k] for k in ("rx_packets", "tx_packets")}
            require(min(diffs.values()) > 0, f"{dev} not active in both directions")
            tun_routes[f["id"]] = diffs
    data = dict(
        time_squeeze=squeeze,
        foreign_cpu_frac=foreign["lower_frac"],
        cpu=A.cpu_deltas(pre, post, cpus),
        softirqs=A.softirq_deltas(pre, post, cpus),
        sender_namespace=A.nstat_deltas(pre, post, roles["snd"]),
        netem=A.qdisc_delta(pre, post, roles["r1"], meta["ifaces"]["r1_b"]),
        tbf=A.qdisc_delta(pre, post, roles["r2"], meta["ifaces"]["r2_c"]),
    )
    for role, dev in (("r1", "r1_a"), ("r2", "r2_b")):
        q = A.qdisc_delta(pre, post, roles[role], meta["ifaces"][dev])
        require(q is not None and q["dropped"] == 0, f"{role} reverse-path qdisc drop")
    return data, tun_routes, flags


def summarize(rd, sched, gatedir, pilot=False, capture_data=None):
    rn = ATTEMPT.fullmatch(rd.name)
    require(rn is not None, "physical run ID not recognized")
    pair, attempt, side = int(rn[1]), int(rn[2]), rn[3]
    meta = read(rd / "meta.json")
    row = sched[pair]
    require(
        meta["run"] == rd.name
        and meta["attempt"] == attempt
        and meta["side_first"] == row["side_first"]
        and meta["schedule_sha256"] == SCHEDULE_SHA
        and meta["boot_id"],
        "physical run metadata mismatch",
    )
    require(
        meta["stage"] == ("rehearsal" if pilot else "production"),
        "wrong acquisition stage",
    )
    if not pilot:
        require(
            meta["timing"] is True
            and meta["slot"] == 0
            and M.timing_placement(0, meta["cpusets"]),
            "production timing placement differs",
        )
    fs = specification(meta, row, side)
    require(
        {p.name for p in (rd / "flows").iterdir() if p.is_dir()}
        == {f["id"] for f in fs},
        "unexpected or missing physical flow directory",
    )
    require(meta["reuse_key"] == meta["post_reuse_key"], "runtime key changed")
    gate = (
        calibration(
            gatedir, meta["reuse_key"], meta["slot"], meta["bw_mbit"], meta["rtt_ms"]
        )
        if gatedir
        else {}
    )
    require(gate or pilot, "production requires same-key calibration")
    for who in ("snd", "rcv"):
        require(
            (rd / f"{who}.done").read_text().strip() == "done"
            and (rd / f"{who}.closed").read_text().strip()
            == "socket tables contain no connected non-TIME_WAIT sockets",
            f"{who} endpoint supervisor closure missing",
        )
    outputs = []
    for f in fs:
        try:
            outputs.append(endpoint(rd / "flows" / f["id"], meta, f))
        except (KeyError, ValueError, IndexError) as e:
            raise ValueError(f"{f['id']}: {e}") from e
    base = read(rd / "snd.release.json")["release_ns"]
    for f in outputs:
        f["destination_ip"] = meta["rcv_ip"]
        require(
            f["target_ns"] == base + f["join_s"] * N,
            "sender barrier or deadline mismatch",
        )
    for k in ("sender_pid", "receiver_pid"):
        require(len({f[k] for f in outputs}) == len(fs), f"duplicate {k}")
    capture_data = capture_data or read(rd / "capture-evidence.json")
    wires = wire_check(capture_data, outputs)
    for name in ("r1-in", "r2-out"):
        counts = C.tcpdump_counts((rd / (name + ".tcpdump.txt")).read_text())
        require(
            all(capture_data[name][k] == v for k, v in counts.items()),
            f"{name} capture receipt mismatch",
        )
    network, tuns, flags = record_check(rd, meta, fs)
    for name in ("r1-in", "r2-out"):
        cap = capture_data[name]
        if cap["dropped"]:
            flags.append(f"capture_drops:{name}")
        if not cap["records"] == cap["captured"] == cap["filtered"]:
            flags.append(f"capture_incomplete:{name}")
    metrics, rows = windows(outputs, meta["duration_s"], gate.get("capacity_bps"))
    for f, r in zip(outputs, rows):
        folder = rd / "flows" / f["id"]
        r.update(
            {
                k: f[k]
                for k in (
                    "backend",
                    "cc",
                    "sender_cc",
                    "receiver_cc",
                    "source_ip",
                    "port",
                    "tun",
                    "bytes",
                    "sha256",
                    "lateness_count",
                    "sender_clock_to_last_sample_s",
                    "sender_connect_to_last_sample_s",
                    "sender_summary_duration_s",
                    "duration_s",
                    "lateness_p99_ns",
                    "lateness_max_ns",
                    "target_ns",
                )
            }
        )
        r.update(wires[f["id"]])
        r["tun_counters"] = tuns.get(f["id"])
        for cap_key, last, field, tolerance in (
            (
                "r1-in_data_segments",
                f["sender_samples"][-1],
                "data_segs_out",
                A.CAPTURE_SEGS_TOL,
            ),
            (
                "r1-in_retrans_segments",
                f["sender_samples"][-1],
                "total_retrans",
                A.CAPTURE_RETRANS_TOL,
            ),
            (
                "r2-out_data_segments",
                f["receiver_last"],
                "data_segs_in",
                A.CAPTURE_SEGS_TOL,
            ),
        ):
            r["endpoint_total_" + field] = last[field]
            if not A.counts_agree(r[cap_key], last[field], tolerance):
                flags.append(f"{f['id']}/capture_run_mismatch:{field}")
        for field in ("rwnd_limited_us", "sndbuf_limited_us"):
            counter = A.series(f["sender_samples"], field)
            require(
                all(
                    bound_observed(counter, t)
                    for t in (r["warm_start_ns"], metrics["active_end_ns"])
                ),
                f"{f['id']} sender coverage {field}",
            )
            d = A.delta(counter, r["warm_start_ns"], metrics["active_end_ns"])
            require(d is not None and d >= 0, f"{f['id']} sender coverage {field}")
            name = field.replace("_us", "_frac")
            r[name] = d * 1000 / (metrics["active_end_ns"] - r["warm_start_ns"])
            if r[name] >= A.LIMITED_FLAG_FRACTION:
                flags.append(f"{f['id']}/{name}")
        if f["tun"]:
            st = json.loads(
                (folder / "stats.json").read_text().strip().splitlines()[-1]
            )
            require(
                type(st["dev_device_failed"]) is bool
                and not st["dev_device_failed"]
                and all(
                    type(st[k]) is int and st[k] == 0
                    for k in ("dev_rx_errors", "dev_tx_errors", *A.STACK_LOCAL_DROPS)
                ),
                f"{f['id']} stack local drop or device failure",
            )
            require(
                type(r["lateness_p99_ns"]) is int
                and type(r["lateness_max_ns"]) is int
                and 0 <= r["lateness_p99_ns"] <= r["lateness_max_ns"]
                and st["loop_lateness_max_ns"] >= 0,
                f"{f['id']} missing loop lateness",
            )
            r.update(lateness_evidence(st, r))
            src, sport, dst, dport, _ = r["identity"]
            socket_tuple = f"{src}:{sport}>{dst}:{dport}"
            trace_counts = {}
            prev = None
            with (folder / "trace.jsonl").open() as trace:
                for line in trace:
                    event = json.loads(line)
                    require(
                        event["tuple"] == socket_tuple
                        and event["conn"] == f["sender_samples"][0]["conn_id"]
                        and (prev is None or prev <= event["t"])
                        and event["ev"] in ("cwnd", "tx", "rto", "recovery"),
                        f"{f['id']} observed trace tuple/connection/time/kind mismatch",
                    )
                    prev = event["t"]
                    kind = event["tx"] if event["ev"] == "tx" else event["ev"]
                    trace_counts[kind] = trace_counts.get(kind, 0) + 1
            require(
                sum(trace_counts.values()) == st["trace_events"],
                f"{f['id']} trace count mismatch",
            )
            # A completely event-free traced connection is possible. Its identity
            # is established by both captured TCP streams and endpoint observations.
            r["trace_events"] = trace_counts
            if st["loop_pending_calls"]:
                flags.append(f"{f['id']}/stack_blocked")
    clk = outputs[0]["clock"]
    pings = [
        A.Ping(seq, t, None if delay is None else delay / 1e6)
        for _, seq, t, delay in capture_data["r1-in"]["echoes"]
    ]
    ping = A.ping_metrics(
        pings, clk, metrics["t0_ns"], metrics["t0_ns"] + 5 * N, metrics["active_end_ns"]
    )
    require(
        ping["ping_idle_n"] > 0 and ping["ping_n"] + ping["ping_lost"] > 0,
        "no idle or in-window echo evidence",
    )
    require((rd / "ping.txt").stat().st_size > 0, "missing path ping log")
    samples = A.parse_tbf_samples((rd / "tbf.txt").read_text())
    lo = metrics["t0_ns"] + 5 * N - clk.monotonic_ns + clk.realtime_ns
    hi = metrics["active_end_ns"] - clk.monotonic_ns + clk.realtime_ns
    require(
        samples and samples[0][0] <= lo < hi <= samples[-1][0],
        "no bracketing TBF sample stream",
    )
    network["queue"] = A.queue_check(
        samples, meta["queue_bytes"], meta["bw_mbit"] * 1e6, meta["burst_bytes"], lo, hi
    )
    return dict(
        **{
            k: meta[k]
            for k in (
                "run",
                "pair_order",
                "attempt",
                "side",
                "scenario",
                "rep",
                "pair_seed",
                "slot",
                "reuse_key",
                "start_utc",
                "end_utc",
                "boot_id",
                "stage",
            )
        },
        valid=True,
        flags=flags,
        **metrics,
        **gate,
        **ping,
        ping_source="r1-in paired ICMP capture",
        network=network,
        flows=rows,
    )


def verdict(rd, sched, gatedir, pilot=False):
    try:
        return summarize(rd, sched, gatedir, pilot)
    except (ValueError, KeyError, TypeError, OSError, IndexError) as e:
        missing = (
            isinstance(e, FileNotFoundError)
            or "bracket" in str(e)
            or "coverage" in str(e)
            or "missing initial receiver" in str(e)
        )
        return dict(
            run=rd.name,
            valid=False,
            status="unobserved" if missing else "invalid",
            convergence_status="unobserved" if missing else "invalid",
            reason=str(e).replace(str(rd) + "/", ""),
        )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture")
    c.add_argument("directory", type=Path)
    c.add_argument("--output", type=Path)
    for name in ("run", "tables"):
        q = sub.add_parser(name)
        q.add_argument("directory", type=Path)
        q.add_argument("--schedule", type=Path, default=HERE / "schedule.csv")
        q.add_argument("--gate", type=Path, required=name == "tables")
        if name == "run":
            q.add_argument("--pilot", action="store_true")
        else:
            q.add_argument("--out", type=Path, required=True)
            q.add_argument("--controls", type=Path, required=True)
    args = p.parse_args()
    if args.cmd == "capture":
        output = args.output or args.directory / "capture-evidence.json"
        try:
            raw = C.capture(args.directory, read(args.directory / "meta.json"))
        except (FileNotFoundError, ValueError, struct.error) as e:
            print(
                json.dumps(
                    dict(
                        valid=False,
                        status="unobserved"
                        if isinstance(e, FileNotFoundError)
                        else "invalid",
                        reason=str(e).replace(str(args.directory) + "/", ""),
                    )
                )
            )
            return 3
        text = json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n"
        temp = output.with_suffix(".tmp")
        temp.write_text(text)
        temp.replace(output)
    elif args.cmd == "run":
        r = verdict(args.directory, schedule(args.schedule), args.gate, args.pilot)
        print(json.dumps(r, sort_keys=True, allow_nan=False))
        return 0 if r["valid"] else 1
    else:
        from study_tables import tables

        return tables(
            args.directory, schedule(args.schedule), args.gate, args.controls, args.out
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
