"""Rebuild capture.json from both original pcaps and tcpdump logs, including every 10 ms bin and ping."""

import argparse
from bisect import bisect_left
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit import analyze, diagnostics, read, write_csv

KINDS = (
    "exact_repeat",
    "all_bytes_previously_seen",
    "partly_previously_seen",
    "all_bytes_first_seen",
)
FIELDS = (
    "run",
    "valid",
    "interface",
    "source_bytes",
    "sha256",
    "tcpdump_captured",
    "tcpdump_filter",
    "tcpdump_kernel_drops",
    "data_segments",
    "retransmitted_segments",
    "data_bins",
    "ping_requests",
    "canonical_observation_sha256",
    "status",
    *(phase + "_" + kind for phase in ("lifetime", "primary") for kind in KINDS),
)


class SequenceCoverage:
    """Prior sender payload coverage in wrap-unwrapped, flow-relative space."""

    def __init__(self):
        self.high = 0
        self.ranges = []
        self.exact = set()

    def add(self, relative, length):
        # Choose the sequence epoch nearest the previous highest observed end.
        start = self.high + ((relative - self.high + 2**31) % (2**32) - 2**31)
        end = start + length
        assert start >= 1 and length > 0
        at = bisect_left(self.ranges, (start,))
        if at and self.ranges[at - 1][1] >= start:
            at -= 1
        after = at
        covered = 0
        merged_start, merged_end = start, end
        while after < len(self.ranges) and self.ranges[after][0] <= merged_end:
            left, right = self.ranges[after]
            covered += max(0, min(end, right) - max(start, left))
            merged_start = min(merged_start, left)
            merged_end = max(merged_end, right)
            after += 1
        self.ranges[at:after] = [(merged_start, merged_end)]
        result = None
        if end <= self.high:
            if (start, end) in self.exact:
                result = "exact_repeat"
            elif covered == length:
                result = "all_bytes_previously_seen"
            elif covered:
                result = "partly_previously_seen"
            else:
                result = "all_bytes_first_seen"
        self.exact.add((start, end))
        self.high = max(self.high, end)
        return result


def flagged_ingress(directory, meta, summary, lifetime_count):
    """Resolve the frozen high-end classifier against all earlier captured byte ranges."""
    clock = analyze.clock_of(list(diagnostics.rows(directory / "snd.jsonl")))
    offset = clock.realtime_ns - clock.monotonic_ns
    lo = summary["t0_ns"] + 5 * analyze.NS
    hi = summary["window_end_ns"]
    origin = flow = None
    coverage = SequenceCoverage()
    counts = Counter()
    for segment in analyze.tcp_segments(directory / "r1-in.pcap"):
        if (segment.dst, segment.dport) != (meta["rcv_ip"], 5201):
            continue
        # The userspace TCP wire source can differ from the namespace interface IP.
        observed_flow = (segment.src, segment.sport, segment.dst, segment.dport)
        if segment.flags & 2 and not segment.flags & 16:
            if origin is not None:
                assert (observed_flow, segment.seq) == (flow, origin)
            flow, origin = observed_flow, segment.seq
        if segment.payload <= 0:
            continue
        assert origin is not None and observed_flow == flow
        outcome = coverage.add((segment.seq - origin) % (2**32), segment.payload)
        if outcome:
            counts["lifetime", outcome] += 1
            if lo <= segment.ts_ns - offset < hi:
                counts["primary", outcome] += 1
    assert sum(counts["lifetime", k] for k in KINDS) == lifetime_count
    return {
        phase + "_" + k: counts[phase, k]
        for phase in ("lifetime", "primary")
        for k in KINDS
    }


def run(directory):
    meta = read(directory / "meta.json")
    saved = directory / "summary.json"
    summary = read(saved) if saved.is_file() else {}
    valid = summary.get("valid", False)
    index = directory / "capture.json"
    if not index.exists():
        if valid:
            raise ValueError(f"valid run missing capture index: {directory}")
        return [
            dict(
                run=meta["run"],
                valid=0,
                status="missing capture index on excluded attempt",
            )
        ]
    expected = read(index)
    observed = analyze.captures_of_run(directory, meta)
    if valid:
        assert set(expected) == set(observed) == {"r1-in", "r2-out"}, directory
    rows = []
    for iface in sorted(set(observed) | set(expected)):
        row = dict(run=meta["run"], valid=int(valid), interface=iface)
        rows.append(row)
        matched = expected.get(iface) == observed.get(iface)
        if valid and not matched:
            changed = [
                k
                for k in set(expected[iface]) | set(observed[iface])
                if expected[iface].get(k) != observed[iface].get(k)
            ]
            raise ValueError(
                f"{directory}/{iface}: changed original capture fields {changed}"
            )
        if not matched:
            row["status"] = (
                "excluded attempt with incomplete or changed capture evidence"
            )
            continue
        data = observed[iface]
        if (
            valid
            and iface == "r1-in"
            and "capture_mismatch:total_retrans" in summary["flags"]
        ):
            row.update(flagged_ingress(directory, meta, summary, data["retrans_segs"]))
        pcap = directory / (iface + ".pcap")
        with pcap.open("rb") as src:
            sha = hashlib.file_digest(src, "sha256").hexdigest()
        row.update(
            source_bytes=pcap.stat().st_size,
            sha256=sha,
            tcpdump_captured=data.get("captured"),
            tcpdump_filter=data.get("received_by_filter"),
            tcpdump_kernel_drops=data.get("kernel_dropped"),
            data_segments=data.get("data_segs"),
            retransmitted_segments=data.get("retrans_segs"),
            data_bins=len(data.get("bins", {}).get("data", [])),
            ping_requests=len(data.get("pings", [])),
            canonical_observation_sha256=hashlib.sha256(
                json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            status="replayed from packet bytes and capture log",
        )
    return rows


def main(camp, output, jobs):
    if not 1 <= jobs <= 8:
        raise ValueError("expected 1 to 8 workers")
    dirs = sorted(p.parent for p in camp.glob("*/meta.json"))
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        table = [row for result in pool.map(run, dirs) for row in result]
    write_csv(output, FIELDS, table)
    print(len(dirs), "run directories;", len(table), "capture receipts")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    main(args.campaign, args.output, args.jobs)
