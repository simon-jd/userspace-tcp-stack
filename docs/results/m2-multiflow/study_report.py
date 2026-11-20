"""Read the role comparisons alongside the independent fairness and convergence results."""

from pathlib import Path


def fmt(value, digits=3):
    return "—" if value is None else f"{value:.{digits}f}"


def interval(row, prefix, scale=1, digits=3):
    if not row.get(prefix + "_n"):
        return "—"
    values = [
        fmt(row[prefix + "_" + k] / scale, digits) for k in ("median", "min", "max")
    ]
    return f"{values[0]} [{values[1]}, {values[2]}]"


def report(out, summaries, roles, choices, comparison):
    lines = [
        "# Multi-flow study",
        "",
        "Brackets show the observed minimum and maximum across five matched repetitions. "
        "The reported convergence time is conditional on observing a full five-second hold. "
        "Where early sampling leaves the onset ambiguous, the first confirmed onset is an upper bound. "
        "Individual onset bounds and censoring horizons are in `runs.csv`. The common active cutoff uses "
        "each observed sender connect timestamp plus its registered write duration. The callback and "
        "last application write have no independent timestamps.",
        "",
    ]
    for r in summaries:
        s = r["scenario"]
        lines.extend([f"## Scenario {s}", ""])
        if r["status"] != "complete":
            lines.extend(
                [
                    f"{r['status'].capitalize()} with {r['counted_pairs']} counted pairs and "
                    f"{r['invalid_attempts']} invalid or interrupted pair attempts.",
                    "",
                ]
            )
            continue
        lines.extend(
            [
                "| Side | Nominal Jain | Fully active Jain | Converged / 5 | Right-censored | "
                "Sampling unobserved | First confirmed onset, s | Flagged runs |",
                "|---|---|---|---:|---:|---:|---|---:|",
            ]
        )
        for side in ("test", "baseline"):
            lines.append(
                f"| {side} | {interval(r, side + '_jain_nominal')} | {interval(r, side + '_jain_active')} | "
                f"{r[side + '_converged']}/5 | {r[side + '_right-censored']} | {r[side + '_unobserved-sampling']} | "
                f"{interval(r, side + '_conditional_convergence_s', digits=1)} | {len(r[side + '_flagged_runs'])} |"
            )
        lines.extend(
            [
                "",
                f"Test minus baseline median Jain was {fmt(r['jain_nominal_difference'])} in the nominal "
                f"window and {fmt(r['jain_active_difference'])} in the fully active window.",
                "",
                "| Physical flow | Test sender | Baseline sender | Own-window test Mbit/s | "
                "Own-window baseline Mbit/s | Gap |",
                "|---|---|---|---|---|---|",
            ]
        )
        for f in roles:
            if f["scenario"] == s:
                lines.append(
                    f"| {f['id']} · port {f['port']} | {f['test_backend']} {f['cc']} | Linux {f['cc']} | "
                    f"{interval(f, 'test_goodput_bps', 1e6)} | {interval(f, 'baseline_goodput_bps', 1e6)} | "
                    f"{f['goodput_gap']} |"
                )
        shown = ", ".join(
            f"`{x['run']}` (rep {x['rep']})" for x in choices if x["scenario"] == s
        )
        lines.extend(
            [
                "",
                f"The two real runs selected for the [per-flow plot](plots/scenario-{s:02}.png) "
                f"are {shown}.",
                "",
            ]
        )
    if comparison:
        lines.extend(
            [
                "## Eight-flow loop lateness",
                "",
                "Each row compares the five serial one-flow CUBIC controls of 30 seconds with a single "
                "physical sender role across five 60-second eight-flow CUBIC scenarios. The seven incumbents have "
                "60-second registered writes and the late f7 sender has a 40-second registered write. "
                "Both use the same slot and runtime key. Each p99 or maximum describes one process's "
                "whole-process timer lateness. The p99 is the inclusive upper bound of its logarithmic "
                "histogram bucket, capped at the exact maximum. Maxima depend on observation length "
                "and timer count. Exposure, histogram counts and sender sample spans appear in "
                "`eight-vs-one-lateness.csv`, `flows.csv` and `one-flow-controls.csv`.",
                "",
                "| Physical flow | Histogram metric | One flow, µs | Eight flows, µs | Median timer observations, one / eight |",
                "|---|---|---|---|---|",
            ]
        )
        for c in comparison:
            eight = {f"eight_{k}": c[k] for k in ("min", "max", "median", "n")}
            lines.append(
                f"| {c['id']} | {c['metric'].replace('lateness_', '').replace('_ns', '')} | "
                f"{interval(c, 'one_flow', 1000)} | {interval(eight, 'eight', 1000)} | "
                f"{c['one_flow_lateness_count_median']:.0f} / {c['eight_flow_lateness_count_median']:.0f} |"
            )
        lines.append("")
    (out / "tables.md").write_text("\n".join(lines) + "\n")
