"""Check every sampled and terminal CC against the live socket request and the recorded receiver default."""

import csv
import json
import statistics
import sys
from pathlib import Path


def kernel_default(path, container):
    current = None
    matches = []
    for line in path.read_text().splitlines():
        if line.startswith("== "):
            current = line[3:]
        elif current == container + " sysctl" and line.startswith("net.ipv4.tcp_congestion_control = "):
            matches.append(line.split(" = ", 1)[1])
    if matches != ["cubic"]:
        raise ValueError(f"receiver default requires one recorded cubic setting in {path}")
    return matches[0]


def endpoint(rows, role, backend, cc, lo, hi):
    starts = [r for r in rows if r.get("ev") == "start"]
    ends = [r for r in rows if r.get("ev") == "summary"]
    samples = [r for r in rows if r.get("ev") == "sample"]
    if len(starts) != 1 or starts[0].get("role") != role or len(ends) != 1:
        raise ValueError(f"{role} endpoint records incomplete")
    final = ends[0]
    if (final.get("role"), final.get("backend"), final.get("cc"), final.get("ok")) != (
        role,
        backend,
        cc,
        True,
    ):
        raise ValueError(f"{role} terminal role, backend, CC or completion differs")
    if len(samples) < 2 or any(r.get("role") != role or r.get("cc_name") != cc for r in samples):
        raise ValueError(f"{role} full sample stream does not match {cc}")
    ts = [r["t"] for r in samples]
    if ts != sorted(ts) or not ts[0] <= lo < hi <= ts[-1]:
        raise ValueError(f"{role} samples do not cover the measurement window")
    inside = sum(lo <= t <= hi for t in ts)
    if not inside:
        raise ValueError(f"{role} has no CC observations inside the window")
    intervals = [(b - a) / 1e6 for a, b in zip(ts, ts[1:])]
    return (len(ts), inside, statistics.median(intervals), final["cc"])


def main(campaign, evidence, output):
    with evidence.open(newline="") as source:
        counted = [r for r in csv.DictReader(source) if r["counted"] == "1"]
    fields = ["run", "impl", "requested_sender_cc", "receiver_sysctl"]
    for side in ("sender", "receiver"):
        fields.extend(
            f"{side}_{name}"
            for name in ("samples", "samples_in_window", "median_interval_ms", "terminal_cc")
        )
    with output.open("x", newline="") as out:
        writer = csv.DictWriter(out, fields, lineterminator="\n")
        writer.writeheader()
        for item in counted:
            rd = campaign / item["run"]
            m, s = [json.loads((rd / f).read_text()) for f in ("meta.json", "summary.json")]
            kernel = [
                kernel_default(rd / n / "record.txt", m["containers"]["rcv"]) for n in ("pre", "post")
            ]
            if kernel[0] != kernel[1]:
                raise ValueError("receiver default changed during transfer")
            lo, hi = s["t0_ns"] + 5 * 10**9, s["window_end_ns"]
            row = dict(
                run=item["run"], impl=m["impl"], requested_sender_cc=m["cc"], receiver_sysctl=kernel[0]
            )
            for side, file, cc, backend in (
                ("sender", "snd", m["cc"], "utcp" if m["impl"] == "utcp" else "kernel"),
                ("receiver", "rcv", kernel[0], "kernel"),
            ):
                rows = [json.loads(l) for l in (rd / (file + ".jsonl")).read_text().splitlines()]
                values = endpoint(rows, side, backend, cc, lo, hi)
                row.update(
                    zip(
                        (
                            f"{side}_{k}"
                            for k in ("samples", "samples_in_window", "median_interval_ms", "terminal_cc")
                        ),
                        values,
                    )
                )
            writer.writerow(row)
    print(
        f"Verified all sampled and terminal CC observations at both endpoints of {len(counted)} transfers."
    )


if __name__ == "__main__":
    main(*(Path(arg) for arg in sys.argv[1:]))
