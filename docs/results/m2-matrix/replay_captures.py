"""Rebuild capture.json from both original pcaps and tcpdump logs, including every 10 ms bin and ping."""

import argparse
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit import analyze, read, write_csv

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
)


def run(directory):
    meta = read(directory / "meta.json")
    saved = directory / "summary.json"
    valid = read(saved)["valid"] if saved.is_file() else False
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
