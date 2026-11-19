"""Print tables for docs/RESULTS.md from cells.csv and the accompanying trace explanations."""

import argparse
import csv
from itertools import product
from pathlib import Path

METRICS = ("goodput_bps", "retrans_pct", "qdelay_p50_ms", "qdelay_p99_ms")
CELLS = [f"{bw}-{rtt}-{loss}-2" for bw, rtt, loss in product((10, 100), (20, 100), (0, 1))]
ALGORITHMS = (("newreno", "NewReno"), ("cubic", "CUBIC"))


def read_csv(path):
    with path.open(newline="") as source:
        return list(csv.DictReader(source))


def metric_range(row, metric, divisor):
    fields = [row[f"{metric}_{stat}"] for stat in ("median", "min", "max")]
    if any(value == "" for value in fields):
        return "n/a"
    mid, low, high = [float(value) / divisor for value in fields]
    return f"{mid:.6g} [{low:.6g}–{high:.6g}]"


def render(directory):
    groups = {(r["algo"], r["cell"], r["impl"]): r for r in read_csv(directory / "cells.csv")}
    expected = set(product((a for a, _ in ALGORITHMS), CELLS, ("utcp", "linux")))
    if set(groups) != expected:
        raise ValueError("cells.csv must include both sides of every checkpoint condition")
    causes_path = directory / "causes.csv"
    explanations = (
        {(r["algo"], r["cell"]): r["explanation"] for r in read_csv(causes_path)}
        if causes_path.exists()
        else {}
    )
    for algo, title in ALGORITHMS:
        print(f"### {title}\n")
        print(
            "| Mbit/s · ms · loss % | Goodput (Mbit/s) | Δ goodput | Retransmissions (%) | Queue delay p50 (ms) | Queue delay p99 (ms) | Goodput gap | Retrans. gap | p50 gap | p99 gap | Explanation |"
        )
        print("|" + "---|" * 11)
        for cell in CELLS:
            stack, linux = [groups[algo, cell, side] for side in ("utcp", "linux")]
            if stack["status"] != linux["status"]:
                raise ValueError(f"inconsistent cell status for {algo} {cell}")
            label = " · ".join(cell.split("-")[:3])
            label = f"[{label}](results/m2-checkpoint/plots/{cell}-{algo}.png)" + (
                " †" if stack["transient"] == "1" else ""
            )
            ranges = []
            gaps = []
            for metric in METRICS:
                scale = 1e6 if metric == "goodput_bps" else 1
                ranges.append("<br>".join(metric_range(r, metric, scale) for r in (stack, linux)))
                verdict = stack["gap_" + metric]
                if verdict != linux["gap_" + metric]:
                    raise ValueError(f"inconsistent {metric} verdict for {algo} {cell}")
                gaps.append(
                    {"no gap": "No", "gap": "Yes", "gap (below resolution)": "Yes (<1 ms)", "n/a": "n/a"}[
                        verdict
                    ]
                )
            left, right = [r["goodput_bps_median"] for r in (stack, linux)]
            delta = (
                f"{100 * (float(left) / float(right) - 1):+.2f}%"
                if left and right and float(right)
                else "n/a"
            )
            if stack["status"] != "ok":
                delta = "n/a"
                cause = stack["status"]
            else:
                cause = explanations.get((algo, cell), "")
                if not cause and "Yes" in gaps:
                    cause = "Open"
                if "Yes (<1 ms)" in gaps and "below measurement resolution" not in cause.lower():
                    cause = (cause + ". " if cause else "") + "Below measurement resolution"
            print("| " + " | ".join([label, ranges[0], delta, *ranges[1:], *gaps, cause or "—"]) + " |")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    render(parser.parse_args().directory)
