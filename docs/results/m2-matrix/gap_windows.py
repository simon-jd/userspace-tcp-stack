"""Align captured packet bins, endpoint samples, queues and filtered events for substantive gaps."""

import csv
from collections import Counter

from audit import analyze as a, diagnostics, read, write_csv

FIELDS = (
    "algo",
    "cell",
    "run",
    "rep",
    "impl",
    "second_since_accept",
    "interval_s",
    "receiver_mbit_s",
    "sender_cwnd_p50",
    "sender_cwnd_min",
    "sender_cwnd_max",
    "delivery_mbit_s_p50",
    "pacing_mbit_s_p50",
    "ca_states",
    "tbf_backlog_p50_bytes",
    "r1_data_segments",
    "r1_retrans_segments",
    "r2_data_segments",
    "r2_retrans_segments",
    "ping_replies",
    "ping_lost",
    "ping_queue_p50_ms",
    "ping_queue_p99_ms",
    "stack_rto",
    "stack_fast_retrans",
)


def windows(directory):
    meta, summary, capture = (
        read(directory / k) for k in ("meta.json", "summary.json", "capture.json")
    )
    snd = list(diagnostics.rows(directory / "snd.jsonl"))
    rcv = a.series(list(diagnostics.rows(directory / "rcv.jsonl")), "bytes_received")
    clock = a.clock_of(snd)
    offset = clock.realtime_ns - clock.monotonic_ns
    samples = [r for r in snd if r.get("ev") == "sample"]
    lo = summary["t0_ns"] + 5 * a.NS
    hi = summary["window_end_ns"]
    pings = [
        (t - offset, None if delay is None else delay / 1e6)
        for _, t, delay in capture["r1-in"]["pings"]
    ]
    tbf = [
        (t - offset, b)
        for t, b, _ in a.parse_tbf_samples((directory / "tbf.txt").read_text())
        if b is not None
    ]
    events = []
    if meta["impl"] == "utcp":
        events = [
            (r["t"], r.get("tx") if r["ev"] == "tx" else r["ev"])
            for r in diagnostics.rows(directory / "trace.jsonl")
        ]
    # Counts within a partial edge bin use the frozen analyzer's linear interpolation.
    timed = {
        (face, kind): a.counts_series(capture[face]["bins"], kind)
        for face in ("r1-in", "r2-out")
        for kind in ("data", "retrans")
    }
    for start in range(lo, hi, a.NS):
        end = min(start + a.NS, hi)
        # [start,end) avoids double-counting samples on adjacent interior boundaries.
        measured = [r for r in samples if start <= r["t"] < end]
        cw = [r["cwnd"] for r in measured]
        delays = [v for t, v in pings if start <= t < end]
        replies = [v for v in delays if v is not None]
        queue_delays = (
            [r - summary["ping_base_ms"] for r in replies]
            if summary.get("ping_base_ms") is not None
            else []
        )
        event_counts = Counter(k for t, k in events if start <= t < end)
        row = dict(
            algo=meta["algo"],
            cell=meta["cell"],
            run=meta["run"],
            impl=meta["impl"],
            rep=meta["rep"],
            second_since_accept=(start - summary["t0_ns"]) / a.NS,
            interval_s=(end - start) / a.NS,
            receiver_mbit_s=a.delta(rcv, start, end) * 8e3 / (end - start),
            sender_cwnd_p50=a.median(cw),
            sender_cwnd_min=min(cw, default=None),
            sender_cwnd_max=max(cw, default=None),
            delivery_mbit_s_p50=a.median([r["delivery_rate"] * 8e-6 for r in measured]),
            pacing_mbit_s_p50=a.median([r["pacing_rate"] * 8e-6 for r in measured]),
            ca_states=",".join(
                f"{k}={v}"
                for k, v in sorted(
                    Counter(r.get("ca_state", "?") for r in measured).items()
                )
            ),
            tbf_backlog_p50_bytes=a.median([b for t, b in tbf if start <= t < end]),
            ping_replies=len(replies),
            ping_lost=len(delays) - len(replies),
            ping_queue_p50_ms=a.median(queue_delays),
            ping_queue_p99_ms=a.percentile(queue_delays, 0.99),
            stack_rto=event_counts["rto"] if meta["impl"] == "utcp" else None,
            stack_fast_retrans=event_counts["fast_rexmit"]
            if meta["impl"] == "utcp"
            else None,
        )
        for (face, kind), series in timed.items():
            row[f"{face[:2]}_{kind}_segments"] = a.delta(
                series, start + offset, end + offset
            )
        yield row


def write(campaign, evidence, gaps, output):
    conditions = {(g["algo"], g["cell"]) for g in gaps if g["verdict"] == "gap"}
    with evidence.open(newline="") as f:
        names = sorted(
            r["run"]
            for r in csv.DictReader(f)
            if r["counted"] == "1" and (r["algo"], r["cell"]) in conditions
        )
    write_csv(
        output, FIELDS, (row for name in names for row in windows(campaign / name))
    )
