"""Calculate ablation contrasts from full-precision counted summaries and the preregistered reference.

Usage: python report.py CAMPAIGN EVIDENCE.CSV CELLS.CSV NEW_OUTPUT
"""

import csv
import itertools
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "tools/m2"))
import analyze as A

SINGLES = ("rfc-rto", "rfc-prr", "rfc-iw", "rfc-hystart")
VARIANTS = ("rfc", *SINGLES, "rfc-all", "compat")
METRICS = ("goodput_bps", "retrans_pct", "qdelay_p50_ms", "qdelay_p99_ms")
CELLS = ("100-20-1-2", "10-100-1-2")
LABEL = {
    "rfc": "RFC",
    "rfc-rto": "RFC + RTO/estimator",
    "rfc-prr": "RFC + PRR",
    "rfc-iw": "RFC + IW10",
    "rfc-hystart": "RFC + classic HyStart",
    "rfc-all": "RFC + all four",
    "compat": "Linux-compatible stack",
    "linux": "Linux CUBIC",
}
REFS = {"primary": "compat", "RFC-paired sensitivity": "rfc"}


def save(path, rows):
    with path.open("x", newline="") as f:
        writer = csv.DictWriter(f, rows[0].keys(), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def corner_range(f, *stats):
    median = f(*(x["median"] for x in stats))
    values = [
        f(*point) for point in itertools.product(*[(x["min"], x["max"]) for x in stats])
    ]
    return {"median": median, "min": min(values), "max": max(values)}


def share(r, l, x):
    return 100 * (x - r) / (l - r)


def interaction(r, l, all_four, *singles):
    return share(r, l, all_four) - sum(share(r, l, x) for x in singles)


def span(s, scale=1, decimals=3):
    if not s or s.get("median") in (None, ""):
        return "—"
    fmt = lambda field: f"{s[field] * scale:.{decimals}f}"
    return f"{fmt('median')} [{fmt('min')}, {fmt('max')}]"


def main(camp, evidence, cells_file, out):
    out.mkdir(parents=True, exist_ok=False)
    groups = defaultdict(list)
    with evidence.open() as f:
        for row in csv.DictReader(f):
            if row["counted"] == "1":
                s = json.loads((camp / row["run"] / "summary.json").read_bytes())
                groups[row["cell"], row["algo"], row["impl"]].append(s)
    with cells_file.open() as f:
        aggregates = {(r["cell"], r["algo"], r["impl"]): r for r in csv.DictReader(f)}

    def stats(cell, variant, side, metric):
        group = groups[cell, variant, side]
        row = aggregates[cell, variant, side]
        assert int(row["n_counted"]) == len(group)
        s = A.stats([v.get(metric) for v in group])
        if s:
            assert all(
                row[metric + "_" + k] == A.fmt(s[k])
                for k in ("median", "min", "max", "n")
            )
        return s if row["status"] == "ok" else None

    comparisons, effects, tables = [], [], []
    for cell in CELLS:
        tables.extend(
            [
                f"### {'A1' if cell == CELLS[0] else 'A2'} · {cell.split('-')[0]} Mbit/s, {cell.split('-')[1]} ms",
                "",
                "Medians and observed ranges across the first five valid pairs. Retransmission is a percentage of transmitted data segments. Queueing delays are in milliseconds.",
                "",
                "| Sender | Goodput (Mbit/s) | Retransmission (%) | Queue p50 (ms) | Queue p99 (ms) |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for variant in (*VARIANTS, "linux"):
            side, label = (
                ("linux", "compat") if variant == "linux" else ("utcp", variant)
            )
            vals = [
                span(
                    stats(cell, label, side, m),
                    1e-6 if m == "goodput_bps" else 1,
                    5 if m.startswith("qdelay") else 3,
                )
                for m in METRICS
            ]
            tables.append("| " + " | ".join([LABEL[variant], *vals]) + " |")
        for reference, linux_label in REFS.items():
            considered = VARIANTS if reference == "primary" else ("rfc",)
            for variant in considered:
                for metric in METRICS:
                    s = stats(cell, variant, "utcp", metric)
                    l = stats(cell, linux_label, "linux", metric)
                    verdict = A.gap_verdict(metric, s, l, 1)
                    d = s["median"] - l["median"] if verdict != "n/a" else None
                    comps = dict(
                        cell=cell,
                        reference=reference,
                        linux_partner=linux_label,
                        variant=variant,
                        metric=metric,
                        stack_median=s["median"] if s else "",
                        linux_median=l["median"] if l else "",
                        stack_minus_linux=d if d is not None else "",
                        verdict=verdict,
                        stack_worse=""
                        if d is None
                        else int(d < 0 if metric == "goodput_bps" else d > 0),
                    )
                    comparisons.append(comps)
            r = stats(cell, "rfc", "utcp", "goodput_bps")
            l = stats(cell, linux_label, "linux", "goodput_bps")
            verdict = A.gap_verdict("goodput_bps", r, l, 1)

            def emit(name, unit, estimate, message):
                effects.append(
                    dict(
                        cell=cell,
                        reference=reference,
                        linux_partner=linux_label,
                        effect=name,
                        unit=unit,
                        median=estimate["median"] if estimate else "",
                        min=estimate["min"] if estimate else "",
                        max=estimate["max"] if estimate else "",
                        status=message,
                    )
                )

            all4 = stats(cell, "rfc-all", "utcp", "goodput_bps")
            compatible = stats(cell, "compat", "utcp", "goodput_bps")
            for v in (*SINGLES, "rfc-all", "interaction"):
                x = (
                    [all4, *[stats(cell, a, "utcp", "goodput_bps") for a in SINGLES]]
                    if v == "interaction"
                    else [stats(cell, v, "utcp", "goodput_bps")]
                )
                estimate = None
                if verdict == "n/a" or any(s is None or s["n"] != 5 for s in x):
                    message = "insufficient evidence"
                elif verdict != "gap":
                    message = "no gap to attribute"
                else:
                    assert r["max"] < l["min"] or l["max"] < r["min"]
                    estimate = corner_range(
                        interaction if v == "interaction" else share, r, l, *x
                    )
                    message = "goodput gap"
                emit(v, "percent of signed gap", estimate, message)
            residual = (
                corner_range(lambda a, c: (c - a) / 1e6, all4, compatible)
                if all(s and s["n"] == 5 for s in (all4, compatible))
                else None
            )
            emit(
                "compat minus all four",
                "Mbit/s",
                residual,
                "unattributed" if residual else "insufficient evidence",
            )
        primary = [
            item
            for item in comparisons
            if item["cell"] == cell and item["reference"] == "primary"
        ]

        e = [x for x in effects if x["cell"] == cell and x["reference"] == "primary"]
        tables.extend(
            [
                "",
                "| Stack sender | Linux control | Goodput | Retransmission | Queue p50 | Queue p99 |",
                "|---|---|---|---|---|---|",
            ]
        )
        for variant, ref in (
            ("rfc", "primary"),
            ("compat", "primary"),
            ("rfc", "RFC-paired sensitivity"),
        ):
            results = [
                v["verdict"]
                for v in comparisons
                if v["cell"] == cell
                and v["variant"] == variant
                and v["reference"] == ref
            ]
            assert len(results) == len(METRICS)
            control = "Common" if ref == "primary" else "RFC-paired"
            tables.append("| " + " | ".join([LABEL[variant], control, *results]) + " |")
        tables.append("")
        if e[0]["status"] == "goodput gap":
            tables.extend(
                [
                    "| Change | Share of signed RFC-to-Linux goodput gap (%) |",
                    "|---|---:|",
                ]
            )
            tables.extend(
                f"| {LABEL.get(x['effect'], x['effect'])} | {span(x, decimals=2)} |"
                for x in e[:-1]
            )
        else:
            tables.append(
                "There is no gap to attribute."
                if e[0]["status"] == "no gap to attribute"
                else "Evidence is insufficient for goodput attribution."
            )
        tables.extend(
            [
                "",
                f"The unattributed goodput difference (Linux-compatible minus all-four) was {span(e[-1])} Mbit/s.",
                "",
            ]
        )
        worse = defaultdict(list)
        for q in primary:
            if q["stack_worse"] == 1:
                worse[q["metric"]].append(LABEL[q["variant"]])
        for m in METRICS:
            if worse[m]:
                tables.append(
                    f"- {'Lower goodput' if m == 'goodput_bps' else 'Higher ' + dict(retrans_pct='retransmission', qdelay_p50_ms='p50 delay', qdelay_p99_ms='p99 delay')[m]} than the common Linux median occurred with {', '.join(worse[m])}."
                )
        flags = Counter(
            x
            for (c, a, i), rows in groups.items()
            if c == cell
            for s in rows
            for x in s["flags"]
        )
        tables.extend(
            [
                "",
                "Counts across all physical transfers were "
                + ", ".join(f"{n} with `{flag}`" for flag, n in sorted(flags.items()))
                + "."
                if flags
                else "All counted transfers were unflagged.",
                "",
            ]
        )
    save(out / "comparisons.csv", comparisons)
    save(out / "effects.csv", effects)
    (out / "tables.md").write_text("\n".join(tables).rstrip() + "\n")


if __name__ == "__main__":
    main(*(Path(x) for x in sys.argv[1:]))
