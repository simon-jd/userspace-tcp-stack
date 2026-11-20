"""Replay sender sequence advances around observed Linux Loss samples after a recorded RTO.

extract writes only packet time, relative sequence and length for eligible sender flows.
report reads those compact inputs and the original endpoint clock/samples.
"""

import argparse
import bisect
import csv
import gzip
import hashlib
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit import analyze as a, diagnostics, read, write_csv, optional_sender_deltas

TWOP32 = 1 << 32
INDEX = (
    "run",
    "valid",
    "counted",
    "timeouts",
    "spurious_rtos",
    "capture_complete",
    "capture_sha256",
    "input",
    "segments",
    "status",
)
RUN = (
    "run",
    "valid",
    "counted",
    "timeouts",
    "spurious_rtos",
    "capture_complete",
    "sampled_loss_spans",
    "interior_new_segments",
    "boundary_new_segments",
    "summary",
)
EPISODE = (
    "run",
    "span",
    "first_loss_ns",
    "last_loss_ns",
    "prior_sample_ns",
    "next_sample_ns",
    "prior_state",
    "next_state",
    "first_loss_after_window_end_ms",
    "last_loss_after_window_end_ms",
    "first_phase",
    "last_phase",
    "loss_samples",
    "max_inner_sampling_ms",
    "phase",
    "position",
    "data_segments",
    "payload_bytes",
    "exact_repeat_segments",
    "advance_segments",
    "new_sequence_bytes",
    "first_advance_ns",
    "last_advance_ns",
)


def rows(path):
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def source_counter(directory):
    fields = ("TcpExtTCPTimeouts", "TcpExtTCPSpuriousRTOs")
    found = optional_sender_deltas(directory, read(directory / "meta.json"), fields)
    return tuple(found[k] for k in fields)


def extract_wire(directory, output, meta):
    initial = None
    flow = None
    n = 0
    previous_time = None
    with (
        output.open("xb") as raw,
        gzip.GzipFile(
            filename="", fileobj=raw, mode="wb", mtime=0, compresslevel=1
        ) as compact,
    ):
        for seg in a.tcp_segments(directory / "r1-in.pcap"):
            if (seg.src, seg.dst, seg.dport) != (meta["snd_ip"], meta["rcv_ip"], 5201):
                continue
            if seg.flags & 2 and not seg.flags & 16:
                if initial is None:
                    initial, flow = seg.seq, seg.sport
                else:
                    assert (initial, flow) == (seg.seq, seg.sport), (
                        directory,
                        "more than one SYN flow",
                    )
            if seg.payload <= 0:
                continue
            if initial is None or flow != seg.sport:
                raise ValueError(
                    "sender payload cannot be anchored to a unique captured SYN"
                )
            if previous_time is not None and seg.ts_ns < previous_time:
                raise ValueError("sender packet timestamps out of order")
            previous_time = seg.ts_ns
            position = (seg.seq - initial) % TWOP32
            compact.write(f"{seg.ts_ns},{position},{seg.payload}\n".encode())
            n += 1
    if not n:
        raise ValueError("no sender payload records")
    return n


def extract(campaign, evidence, out):
    out.mkdir(exist_ok=False)
    index = []
    for row in rows(evidence):
        if row["impl"] != "linux":
            continue
        directory = campaign / row["run"]
        timeouts, spurious = source_counter(directory)
        if timeouts == 0:
            continue
        entry = dict(
            run=row["run"],
            valid=row["valid"],
            counted=row["counted"],
            timeouts=timeouts,
            spurious_rtos=spurious,
        )
        index.append(entry)
        if timeouts is None:
            entry["status"] = "missing sender nstat"
            continue
        path = directory / "r1-in.pcap"
        if not path.exists() or not (directory / "capture.json").exists():
            entry["status"] = "missing ingress capture evidence"
            continue
        cap = read(directory / "capture.json").get("r1-in", {})
        entry["capture_complete"] = int(
            cap.get("kernel_dropped") == 0
            and cap.get("captured") is not None
            and cap["captured"] == cap.get("received_by_filter")
        )
        with path.open("rb") as fh:
            entry["capture_sha256"] = hashlib.file_digest(fh, "sha256").hexdigest()
        leaf = row["run"] + ".csv.gz"
        partial = out / (leaf + ".partial")
        try:
            n = extract_wire(directory, partial, read(directory / "meta.json"))
        except ValueError as err:
            entry["status"] = str(err)
            partial.unlink(missing_ok=True)
            continue
        assert n == cap["data_segs"], (directory, n, cap["data_segs"])
        partial.rename(out / leaf)
        entry.update(input=leaf, segments=n, status="captured")
    write_csv(out / "index.csv", INDEX, index)


def sample_spans(samples):
    """Maximal adjacent runs of Loss, with the nearest observed state on each edge."""
    spans = []
    i = 0
    while i < len(samples):
        if samples[i]["ca_state"].lower() != "loss":
            i += 1
            continue
        j = i + 1
        while j < len(samples) and samples[j]["ca_state"].lower() == "loss":
            j += 1
        ts = [x["t"] for x in samples[i:j]]
        spans.append(
            dict(
                span=len(spans) + 1,
                first_loss_ns=ts[0],
                last_loss_ns=ts[-1],
                prior_sample_ns=samples[i - 1]["t"] if i else None,
                next_sample_ns=samples[j]["t"] if j < len(samples) else None,
                prior_state=samples[i - 1]["ca_state"] if i else None,
                next_state=samples[j]["ca_state"] if j < len(samples) else None,
                loss_samples=len(ts),
                max_inner_sampling_ms=max(
                    ((b - a) / 1e6 for a, b in zip(ts, ts[1:])), default=None
                ),
            )
        )
        i = j
    return spans


def phase(t, lo, hi):
    if t < lo:
        return "warmup"
    return "measurement" if t < hi else "drain"


def advance(high, start, length):
    """Report new bytes above the prior highest data end. Track modular TCP offsets from SYN."""
    end = (start + length) % TWOP32
    if a.seq_leq(end, high):
        return high, 0
    return end, min(length, (end - high) % TWOP32)


def locate(spans, starts, t):
    i = bisect.bisect_right(starts, t) - 1
    if i >= 0:
        current = spans[i]
        if current["first_loss_ns"] <= t <= current["last_loss_ns"]:
            return i, "interior" if current["loss_samples"] > 1 else "isolated sample"
        if current["next_sample_ns"] is None or t < current["next_sample_ns"]:
            return i, "trailing boundary"
    if i + 1 < len(spans):
        nxt = spans[i + 1]
        if nxt["prior_sample_ns"] is None or t > nxt["prior_sample_ns"]:
            return i + 1, "leading boundary"
    return None, None


def report(campaign, inputs, out):
    out.mkdir(exist_ok=False)
    totals = []
    episodes = []
    for entry in rows(inputs / "index.csv"):
        name = entry["run"]
        result = {
            k: entry[k]
            for k in (
                "run",
                "valid",
                "counted",
                "timeouts",
                "spurious_rtos",
                "capture_complete",
            )
        }
        totals.append(result)
        if entry["status"] != "captured":
            result["summary"] = "indeterminate: " + entry["status"]
            continue
        rd = campaign / name
        if not (rd / "summary.json").exists() or not (rd / "snd.jsonl").exists():
            result["summary"] = (
                "indeterminate: incomplete sender clock or measurement window"
            )
            continue
        summ = read(rd / "summary.json")
        sender = list(diagnostics.rows(rd / "snd.jsonl"))
        clock = a.clock_of(sender)
        samp = [r for r in sender if r.get("ev") == "sample"]
        if (
            clock is None
            or not samp
            or not all(k in summ for k in ("t0_ns", "window_end_ns"))
        ):
            result["summary"] = (
                "indeterminate: incomplete sender clock or measurement window"
            )
            continue
        assert all(l["t"] <= r["t"] for l, r in zip(samp, samp[1:]))
        spans = sample_spans(samp)
        result["sampled_loss_spans"] = len(spans)
        lo, hi = summ["t0_ns"] + 5 * a.NS, summ["window_end_ns"]
        starts = [x["first_loss_ns"] for x in spans]
        groups = defaultdict(Counter)
        high = 1
        seen_segments = set()
        with gzip.open(inputs / entry["input"], "rt") as fh:
            for line in fh:
                raw, seq, size = map(int, line.split(","))
                t = clock.to_mono(raw)
                high, new = advance(high, seq, size)
                exact_repeat = (seq, size) in seen_segments
                seen_segments.add((seq, size))
                i, position = locate(spans, starts, t)
                if i is None:
                    continue
                stats = groups[i, phase(t, lo, hi), position]
                stats["data_segments"] += 1
                stats["payload_bytes"] += size
                stats["exact_repeat_segments"] += int(exact_repeat)
                if new:
                    stats["advance_segments"] += 1
                    stats["new_sequence_bytes"] += new
                    stats.setdefault("first_advance_ns", t)
                    stats["last_advance_ns"] = t
        for i, span in enumerate(spans):
            span.update(
                run=name,
                first_phase=phase(span["first_loss_ns"], lo, hi),
                last_phase=phase(span["last_loss_ns"], lo, hi),
                first_loss_after_window_end_ms=(span["first_loss_ns"] - hi) / 1e6,
                last_loss_after_window_end_ms=(span["last_loss_ns"] - hi) / 1e6,
            )
            # An empty row records actual zero packets in a sampled interval.
            periods = (
                (span["prior_sample_ns"], span["first_loss_ns"], "leading boundary"),
                (
                    span["first_loss_ns"],
                    span["last_loss_ns"],
                    "interior" if span["loss_samples"] > 1 else "isolated sample",
                ),
                (span["last_loss_ns"], span["next_sample_ns"], "trailing boundary"),
            )
            for beginning, end, position in periods:
                if beginning is None or end is None:
                    continue
                phases = {phase(beginning, lo, hi), phase(end, lo, hi)}
                if beginning < lo and end >= hi:
                    phases.add("measurement")
                for band in phases:
                    groups[i, band, position]
        for (i, band, pos), stats in sorted(groups.items()):
            episodes.append(
                dict(
                    **spans[i],
                    phase=band,
                    position=pos,
                    data_segments=stats["data_segments"],
                    payload_bytes=stats["payload_bytes"],
                    exact_repeat_segments=stats["exact_repeat_segments"],
                    advance_segments=stats["advance_segments"],
                    new_sequence_bytes=stats["new_sequence_bytes"],
                    first_advance_ns=stats.get("first_advance_ns"),
                    last_advance_ns=stats.get("last_advance_ns"),
                )
            )
        inside = sum(
            v["advance_segments"]
            for (_, _, pos), v in groups.items()
            if pos == "interior"
        )
        boundary = sum(
            v["advance_segments"]
            for (_, _, pos), v in groups.items()
            if pos != "interior"
        )
        result.update(interior_new_segments=inside, boundary_new_segments=boundary)
        if entry["capture_complete"] != "1":
            result["summary"] = "indeterminate: incomplete packet capture"
        elif inside:
            result["summary"] = "new sequence data bracketed by Loss observations"
        elif not spans:
            result["summary"] = "indeterminate: no sampled Loss interval"
        elif boundary:
            result["summary"] = "new sequence data only at uncertain Loss boundaries"
        else:
            result["summary"] = (
                "no new data observed in sampled Loss intervals; sub-sample episodes unresolved"
            )
    write_csv(out / "kernel-rto-runs.csv", RUN, totals)
    write_csv(out / "kernel-loss-spans.csv", EPISODE, episodes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action, second in (("extract", "evidence"), ("report", "inputs")):
        command = sub.add_parser(action)
        for name in ("campaign", second, "out"):
            command.add_argument(name, type=Path)
    args = parser.parse_args()
    if args.action == "extract":
        extract(args.campaign, args.evidence, args.out)
    else:
        report(args.campaign, args.inputs, args.out)
