"""Build paired study tables from physical attempts, and render two real runs per scenario."""

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import study as S


def packed(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"))
        if isinstance(value, (list, dict, tuple))
        else value
    )


def write(out, name, rows, columns=()):
    fields = list(dict.fromkeys([*columns, *(k for r in rows for k in r)]))
    with (out / name).open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows({k: packed(v) for k, v in r.items()} for r in rows)


def chronology(stage, sched, gate):
    groups = defaultdict(dict)
    physical = []
    stamps = []
    for rd in sorted(stage.iterdir()):
        if not rd.is_dir():
            continue
        m = S.ATTEMPT.fullmatch(rd.name)
        S.require(m is not None, f"unexpected attempt directory {rd.name}")
        pair, attempt, side = int(m[1]), int(m[2]), m[3]
        reg = sched[pair]
        meta = S.read(rd / "meta.json") if (rd / "meta.json").exists() else {}
        if "start_utc" in meta:
            start = datetime.fromisoformat(meta["start_utc"])
            end = (
                datetime.fromisoformat(meta["end_utc"]) if meta.get("end_utc") else None
            )
            S.require(
                end is None or end >= start, f"{rd.name} reversed acquisition interval"
            )
            stamps.append((pair, attempt, side != reg["side_first"], start, end))
        r = S.verdict(rd, sched, gate)
        qr = rd / "qualification.json"
        if qr.exists():
            q = S.read(qr)
            S.require(
                q["name"] == rd.name
                and q["summary_sha256"] == S.sha(rd / "summary.json")
                and q["valid"] is S.read(rd / "summary.json")["valid"],
                f"{rd.name} changed acquisition verdict",
            )
            if q["valid"]:
                S.require(
                    r["valid"] and q["reuse_key"] == r["reuse_key"],
                    f"{rd.name} failed replay: {r.get('reason')}",
                )
            elif r["valid"]:
                S.require(
                    False,
                    f"{rd.name} originally invalid now valid; investigate before counting",
                )
            sealed = True
        else:
            sealed = False
        r.update(
            pair_order=pair,
            attempt=attempt,
            side=side,
            rep=int(reg["rep"]),
            scenario=int(reg["scenario"]),
            counted=False,
            sealed=sealed,
        )
        physical.append(r)
        groups[(pair, attempt)][side] = r
    by_time = sorted(stamps, key=lambda x: x[3])
    S.require(
        [s[:3] for s in by_time] == sorted(s[:3] for s in stamps),
        "physical start order differs from frozen pair/side order",
    )
    S.require(
        all(a[4] is None or a[4] <= b[3] for a, b in zip(by_time, by_time[1:])),
        "physical attempt intervals overlap",
    )
    counts = Counter()
    for pair, reg in sched.items():
        tries = sorted(a for p, a in groups if p == pair)
        S.require(
            tries == list(range(1, len(tries) + 1)),
            f"missing physical attempt for pair {pair}",
        )
        for a in tries:
            sides = groups[(pair, a)]
            S.require(reg["side_first"] in sides, "missing attempt's first side")
            if set(sides) == {"test", "baseline"} and all(
                r["valid"] and r["sealed"] for r in sides.values()
            ):
                S.require(a == tries[-1], "retry after a sealed valid pair")
                x, y = sides.values()
                S.require(
                    x["pair_seed"] == y["pair_seed"]
                    and x["reuse_key"] == y["reuse_key"]
                    and x["slot"] == y["slot"]
                    and x["boot_id"] == y["boot_id"],
                    "unmatched pair",
                )
                for r in sides.values():
                    r["counted"] = True
            else:
                counts[int(reg["scenario"])] += 1
    return physical, counts


def distribution(rows, field):
    values = [r[field] for r in rows if r.get(field) is not None]
    return S.A.stats(values) or dict(min=None, max=None, median=None, n=0)


def add_stats(dest, name, st):
    dest.update({name + "_" + k: v for k, v in st.items()})


def control_rows(source, key):
    rows = []
    S.require(
        source.name == "serial-s0",
        "one-flow control directory must be the serial slot-zero proof",
    )
    campaign = source.parent.name + "/" + source.name
    for _, run, spec in S.M.proof_list(5, [], False, "cubic"):
        path = source / run
        m, s = S.read(path / "meta.json"), S.read(path / "summary.json")
        # The parent directory can be restored under any enclosing study path;
        # check its campaign suffix against the source metadata.
        S.require(
            m["campaign"].endswith(campaign) and m["reuse_key"] == key,
            "wrong control campaign/key",
        )
        expected = dict(spec, campaign=m["campaign"], run=run, slot=0)
        why = S.M.proof_row_error(s, m, expected, "run")
        S.require(not why, f"invalid one-flow control {run}: {why}")
        end = S.one(S.A.read_jsonl(path / "snd.jsonl"), "summary")
        S.require(
            end["role"] == "sender"
            and end["backend"] == "utcp"
            and end["cc"] == "cubic"
            and end["ok"] is True,
            "invalid control sender data",
        )
        S.require(
            all(
                end[k] == s["sender_" + k]
                for k in ("lateness_p99_ns", "lateness_max_ns")
            ),
            "control sender raw lateness differs",
        )
        rows.append(
            dict(
                run=run,
                campaign=m["campaign"],
                rep=m["rep"],
                slot=m["slot"],
                reuse_key=key,
                duration_s=m["duration_s"],
                lateness_p99_ns=end["lateness_p99_ns"],
                lateness_max_ns=end["lateness_max_ns"],
                summary_sha256=S.sha(path / "summary.json"),
            )
        )
    return rows


def aggregate(scenario, runs, invalid):
    sides = {
        side: sorted([r for r in runs if r["side"] == side], key=lambda r: r["rep"])
        for side in ("test", "baseline")
    }
    status = "invalid" if invalid > S.A.RERUN_CAP else "incomplete"
    if status != "invalid" and all(
        [r["rep"] for r in group] == list(range(1, 6)) for group in sides.values()
    ):
        status = (
            "complete"
            if len({r["reuse_key"] for r in runs}) == 1
            else "mixed reuse keys"
        )
    summary = dict(
        scenario=scenario,
        status=status,
        invalid_attempts=invalid,
        counted_pairs=min(map(len, sides.values())),
    )
    roles, choices = [], []
    if status != "complete":
        return summary, roles, choices
    for side, group in sides.items():
        for k in (
            "jain_nominal",
            "jain_active",
            "observed_horizon_s",
            "qdelay_p50_ms",
            "qdelay_p99_ms",
        ):
            add_stats(summary, f"{side}_{k}", distribution(group, k))
        converged = [r for r in group if r["convergence_status"] == "converged"]
        summary[side + "_converged"] = len(converged)
        for status_key in ("right-censored", "unobserved-sampling"):
            summary[side + "_" + status_key] = sum(
                r["convergence_status"] == status_key for r in group
            )
        add_stats(
            summary,
            f"{side}_conditional_convergence_s",
            distribution(converged, "convergence_s"),
        )
        summary[side + "_censored_horizons_s"] = [
            r["observed_horizon_s"]
            for r in group
            if r["convergence_status"] == "right-censored"
        ]
        summary[side + "_flagged_runs"] = [r["run"] for r in group if r["flags"]]
        selected = S.overlay_run(group)
        choices.append(
            {
                k: selected[k]
                for k in ("scenario", "rep", "side", "run", "aggregate_active_bps")
            }
        )
    for k in ("jain_nominal", "jain_active"):
        a, b = (summary[x + "_" + k + "_median"] for x in sides)
        delta = None if a is None or b is None else a - b
        summary[k + "_difference"] = delta
        summary[k + "_difference_gt_0.05"] = (
            None if delta is None else abs(delta) > 0.05
        )
    for i in range(len(sides["test"][0]["flows"])):
        f = sides["test"][0]["flows"][i]
        role = dict(
            scenario=scenario,
            id=f["id"],
            port=f["port"],
            test_backend=f["backend"],
            cc=f["cc"],
        )
        for side, group in sides.items():
            fs = [r["flows"][i] for r in group]
            S.require(
                all(
                    x["id"] == f["id"]
                    and x["port"] == f["port"]
                    and x["cc"] == f["cc"]
                    and x["backend"] == (f["backend"] if side == "test" else "linux")
                    for x in fs
                ),
                "physical role changed within matched comparison",
            )
            for k in (
                "goodput_bps",
                "fair_nominal_bps",
                "fair_active_bps",
                "lateness_p99_ns",
                "lateness_max_ns",
            ):
                add_stats(role, side + "_" + k, distribution(fs, k))
        xs = [r["flows"][i] for r in sides["test"]]
        ys = [r["flows"][i] for r in sides["baseline"]]
        role["goodput_gap"] = S.A.gap_verdict(
            "goodput_bps",
            distribution(xs, "goodput_bps"),
            distribution(ys, "goodput_bps"),
            0,
        )
        role["median_difference_bps"] = (
            role["test_goodput_bps_median"] - role["baseline_goodput_bps_median"]
        )
        role["paired_differences_bps"] = [
            x["goodput_bps"] - y["goodput_bps"] for x, y in zip(xs, ys)
        ]
        roles.append(role)
    return summary, roles, choices


def plot_pair(stage, scenario, choices, outdir):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(
        2, 1, figsize=(10, 6.5), sharex=True, sharey=True, constrained_layout=True
    )
    for ax, sel in zip(axes, choices):
        rd = stage / sel["run"]
        meta = S.read(rd / "meta.json")
        series = []
        for f in meta["flows"]:
            rec = S.A.read_jsonl(rd / "flows" / f["id"] / "rcv.jsonl")
            series.append(
                (f, S.one(rec, "start")["t"], S.A.series(rec, "bytes_received"))
            )
        t0 = min(t for _, t, _ in series[:-1])
        join = series[-1][1]
        for f, t, s in series:
            xs, ys = [], []
            for end in range(
                t + S.MAX_GAP_NS,
                min(s[-1][0], t0 + meta["duration_s"] * S.N) + 1,
                S.MAX_GAP_NS,
            ):
                begin = end - S.MAX_GAP_NS
                if S.bound_observed(s, begin) and S.bound_observed(s, end):
                    rate = S.A.delta(s, begin, end) * 8 * S.N / S.MAX_GAP_NS / 1e6
                else:
                    rate = float("nan")
                xs.append((end - t0) / S.N)
                ys.append(rate)
            ax.plot(
                xs, ys, linewidth=0.85, label=f"{f['id']} · {f['backend']} {f['cc']}"
            )
        ax.axvline((join - t0) / S.N, color="black", lw=0.8, ls="--")
        ax.set_title(
            sel["side"] + "  " + sel["run"] + f"  (rep {sel['rep']})",
            loc="left",
            fontsize=10,
        )
        ax.set_ylabel("Receiver Mbit/s")
        ax.legend(ncol=min(4, len(series)), fontsize=8, loc="upper right")
        ax.grid(alpha=0.2)
    axes[-1].set_xlabel(
        "Seconds since earliest incumbent accept  ·  dashed line = observed late accept"
    )
    fig.suptitle(
        f"Scenario {scenario}  ·  per-flow goodput in observed 100 ms intervals"
    )
    fig.savefig(outdir / f"scenario-{scenario:02}.png", dpi=140)
    plt.close(fig)


def tables(stage, sched, gate, controls, out):
    physical, retries = chronology(stage, sched, gate)
    out.mkdir(parents=True, exist_ok=True)
    counted = [r for r in physical if r["counted"]]
    flows = [
        dict(
            run=r["run"],
            scenario=r["scenario"],
            rep=r["rep"],
            side=r["side"],
            counted=r["counted"],
            **f,
        )
        for r in physical
        for f in r.get("flows", [])
    ]
    write(
        out,
        "runs.csv",
        [
            {k: v for k, v in r.items() if k not in ("flows", "network")}
            for r in physical
        ],
        ("run",),
    )
    write(out, "flows.csv", flows, ("run", "id"))
    write(
        out,
        "network.csv",
        [dict(run=r["run"], **r["network"]) for r in physical if "network" in r],
        ("run",),
    )
    keys = {r["reuse_key"] for r in counted}
    S.require(len(keys) <= 1, "multiple runtime keys in campaign")
    cs = control_rows(controls, next(iter(keys))) if keys else []
    write(out, "one-flow-controls.csv", cs, ("run",))
    (out / "plots").mkdir(exist_ok=True)
    summaries, role_rows, selections, comparisons = [], [], [], []
    for scenario in range(1, 11):
        summary, roles, choices = aggregate(
            scenario,
            [r for r in counted if r["scenario"] == scenario],
            retries[scenario],
        )
        summaries.append(summary)
        role_rows.extend(roles)
        selections.extend(choices)
        if choices:
            plot_pair(stage, scenario, choices, out / "plots")
        if scenario == 3:
            for r in roles:
                for k in ("lateness_p99_ns", "lateness_max_ns"):
                    comp = dict(
                        id=r["id"],
                        metric=k,
                        eight_flow_duration_s=60,
                        one_flow_duration_s=30,
                    )
                    add_stats(comp, "one_flow", distribution(cs, k))
                    comp.update(
                        {
                            l: r["test_" + k + "_" + l]
                            for l in ("min", "median", "max", "n")
                        }
                    )
                    comparisons.append(comp)
    write(out, "scenarios.csv", summaries)
    write(out, "roles.csv", role_rows, ("scenario", "id"))
    write(out, "overlay-runs.csv", selections, ("scenario", "side", "rep", "run"))
    write(out, "eight-vs-one-lateness.csv", comparisons, ("id", "metric"))
    print(
        json.dumps(
            dict(
                physical_runs=len(physical),
                counted_runs=len(counted),
                counted_flows=sum(len(r["flows"]) for r in counted),
                complete_scenarios=sum(r["status"] == "complete" for r in summaries),
            )
        )
    )
    return 0 if all(r["status"] == "complete" for r in summaries) else 2
