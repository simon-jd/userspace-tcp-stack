"""Reproduce all primary verdicts, secondary ranges, and the three 24-row comparison tables."""

import argparse
import csv
import re
import statistics
import sys
from collections import defaultdict
from itertools import product
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit
import gap_windows

PRIMARY = ("goodput_bps", "retrans_pct", "qdelay_p50_ms", "qdelay_p99_ms")
LABELS = ("goodput", "retransmissions", "p50 delay", "p99 delay")
TITLES = {"newreno": "NewReno", "cubic": "CUBIC", "bbr": "BBR"}
CELLS = [
    f"{bw}-{rtt}-{loss}-{q}"
    for bw, rtt, loss, q in product((10, 100), (20, 100), (0, 0.1, 1), (0.5, 2))
]
read = audit.read


def read_rows(path):
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def verdict(metric, left, right, loss):
    if len(left) != 5 or len(right) != 5:
        return "n/a"
    if max(min(left), min(right)) <= min(max(left), max(right)):
        return "no gap"
    base = statistics.median(right)
    delta = statistics.median(left) - base
    if metric == "retrans_pct":
        return "gap" if delta > (0.2 if loss == 1 else 0.05) else "no gap"
    if abs(delta) <= 0.1 * abs(base):
        return "no gap"
    return (
        "gap (below resolution)"
        if metric.startswith("qdelay") and abs(delta) < 1
        else "gap"
    )


def per_run(summary, diagnostic, controls, impl):
    metrics = {
        k: summary.get(k)
        for k in (
            *PRIMARY,
            "spurious_retrans",
            "ping_lost",
            "sndbuf_limited_frac",
            "rwnd_limited_frac",
            "sender_lateness_p99_ns",
            "sender_lateness_max_ns",
            "foreign_cpu_frac",
            "retrans_pct_capture",
            "window_s",
            "data_segs_out",
            "retrans_segs",
        )
    }
    for k in (
        "cwnd_p50",
        "cwnd_at_warmup",
        "cwnd_at_end",
        "srtt_us_p50",
        "pacing_mbit_p50",
        "delivery_mbit_p50",
        "queue_fraction_p50",
        "positive_backlog_fraction",
    ):
        metrics[k] = float(diagnostic[k]) if diagnostic[k] else None
    for k, v in summary["sender_counters"].items():
        metrics["sender_" + k] = v
    for k in audit.UNDO:
        metrics["kernel_sender_" + k] = int(controls[k]) if impl == "linux" else None
    for interface, counts in summary["capture"].items():
        for k in ("captured", "kernel_dropped", "received_by_filter"):
            metrics[f"{interface}_{k}"] = counts[k]
    for queue in ("netem", "tbf"):
        for k, v in summary[queue].items():
            metrics[queue + "_" + k] = v
    metrics["tbf_sample_backlog_max_bytes"] = summary["queue"]["backlog_max"]
    for k, v in summary["softirqs"].items():
        metrics["softirq_" + k] = v
    for cpu, values in summary["cpu"].items():
        for key, v in values.items():
            metrics[f"cpu{cpu}_{key}_jiffies"] = v
    return metrics


def plot_check(checked, log):
    expected = {(r["cell"], r["algo"], r["impl"]): r["run"] for r in checked}
    observed = {}
    for line in log.read_text().splitlines():
        match = re.fullmatch(
            r".*/([\d.]+-[\d.]+-[\d.]+-[\d.]+)-(newreno|cubic|bbr)\.png: linux ([\w.-]+), utcp ([\w.-]+)",
            line,
        )
        if not match:
            continue
        cell, algo, linux, stack = match.groups()
        for side, name in (("linux", linux), ("utcp", stack)):
            key = cell, algo, side
            assert key not in observed
            observed[key] = name
    assert observed == expected and len(observed) == 144


def show(xs, scale):
    if not xs:
        return "n/a"
    med, low, high = [
        value / scale for value in (statistics.median(xs), min(xs), max(xs))
    ]
    return f"{med:.4g} [{low:.4g}, {high:.4g}]"


def render(campaign, native, evidence, plot_log, out):
    out.mkdir(exist_ok=False)
    endpoints = read_rows(evidence / "evidence.csv")
    native_cells = {
        (r["algo"], r["cell"], r["impl"]): r for r in read_rows(native / "cells.csv")
    }
    assert len(native_cells) == 144
    native_runs = {r["run"]: r for r in read_rows(native / "runs.csv")}
    assert set(native_runs) == {r["run"] for r in endpoints}
    diag = {r["run"]: r for r in read_rows(evidence / "trace-diagnostics.csv")}
    network = {r["run"]: r for r in read_rows(evidence / "network-records.csv")}
    medians = read_rows(evidence / "overlay-runs.csv")
    plot_check(medians, plot_log)
    samples = defaultdict(lambda: defaultdict(list))
    for row in endpoints:
        name = row["run"]
        assert (row["valid"], row["flags"], row["invalid"]) == tuple(
            native_runs[name][k] for k in ("valid", "flags", "invalid")
        )
        if row["counted"] != "1":
            continue
        s = read(campaign / name / "summary.json")
        assert bool(s["valid"]) and s["run"] == name
        bucket = samples[row["algo"], row["cell"], row["impl"]]
        for key, value in per_run(s, diag[name], network[name], row["impl"]).items():
            xs = bucket[key]
            if isinstance(value, (int, float)):
                xs.append(value)
    assert set(samples) == set(native_cells)
    all_metrics = sorted({metric for group in samples.values() for metric in group})
    wide, gaps, tables = [], [], []
    for algo, title in TITLES.items():
        tables.extend(
            [
                f"### {title}",
                "",
                "| Mbit/s · RTT ms · loss % · queue BDP | Goodput, Mbit/s | Retransmissions, % | Queue delay p50, ms | Queue delay p99, ms | Registered gaps |",
                "|---|---:|---:|---:|---:|---|",
            ]
        )
        for cell in CELLS:
            left, right = (samples[algo, cell, side] for side in ("utcp", "linux"))
            names = []
            for i, k in enumerate(PRIMARY):
                decision = verdict(k, left[k], right[k], float(cell.split("-")[2]))
                assert all(
                    native_cells[algo, cell, side]["gap_" + k] == decision
                    for side in ("utcp", "linux")
                )
                if decision != "no gap":
                    names.append(
                        LABELS[i]
                        + (
                            " (<1 ms)"
                            if decision == "gap (below resolution)"
                            else " (unavailable)"
                            if decision == "n/a"
                            else ""
                        )
                    )
                    gaps.append(
                        dict(
                            algo=algo,
                            cell=cell,
                            metric=k,
                            verdict=decision,
                            stack_median=statistics.median(left[k]) if left[k] else "",
                            linux_median=statistics.median(right[k])
                            if right[k]
                            else "",
                            overlay=f"plots/{cell}-{algo}.png",
                        )
                    )
            for side, bucket in (("utcp", left), ("linux", right)):
                canonical = native_cells[algo, cell, side]
                assert canonical["status"] == "ok" and canonical["n_counted"] == "5"
                row = dict(cell=cell, algo=algo, impl=side)
                for k in all_metrics:
                    xs = bucket.get(k, [])
                    stats = dict(
                        n=len(xs),
                        min=min(xs) if xs else None,
                        max=max(xs) if xs else None,
                        median=statistics.median(xs) if xs else None,
                    )
                    for stat, v in stats.items():
                        col = f"{k}_{stat}"
                        if k in PRIMARY:
                            assert canonical[col] == audit.analyze.fmt(v), (
                                algo,
                                cell,
                                side,
                                col,
                                v,
                                canonical[col],
                            )
                        row[col] = v
                wide.append(row)
            transient = native_cells[algo, cell, "utcp"]["transient"] == "1"
            label = " · ".join(cell.split("-"))
            name = f"[{label}](results/m2-matrix/plots/{cell}-{algo}.png)" + (
                " †" if transient else ""
            )
            measures = [
                show(left[k], 1e6 if k == "goodput_bps" else 1)
                + "<br>"
                + show(right[k], 1e6 if k == "goodput_bps" else 1)
                for k in PRIMARY
            ]
            tables.append(
                "| " + " | ".join([name, *measures, ", ".join(names) or "None"]) + " |"
            )
        tables.append("")
    audit.write_csv(out / "all-metrics.csv", wide[0].keys(), wide)
    audit.write_csv(
        out / "gap-verdicts.csv",
        (
            "algo",
            "cell",
            "metric",
            "verdict",
            "stack_median",
            "linux_median",
            "overlay",
        ),
        gaps,
    )
    gap_windows.write(
        campaign, evidence / "evidence.csv", gaps, out / "gap-windows.csv"
    )
    (out / "tables.md").write_text("\n".join(tables) + "\n")
    print(
        "Rebuilt 144 aggregate rows,",
        len(gaps),
        "non-default verdicts and 3 tables of 24 comparisons.",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("campaign", "native", "evidence", "plot_log", "out"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    render(args.campaign, args.native, args.evidence, args.plot_log, args.out)
