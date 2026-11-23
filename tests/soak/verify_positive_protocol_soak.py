#!/usr/bin/env python3
"""Check exit, minute records, per-lane duration and common monotonic overlap."""

import pathlib
import re
import sys

LANES = ("ipv4", "options", "stream", "peers")
MINUTE = 60_000_000_000


def record(line):
    pieces = line.split()
    if not pieces or not pieces[0].startswith("UTCP_POSITIVE_"):
        raise ValueError(f"unexpected log line: {line!r}")
    return pieces[0], dict(piece.split("=", 1) for piece in pieces[1:])


def check(directory, threshold, seed):
    spans = []
    for lane in LANES:
        if (directory / f"{lane}.status").read_text().strip() != "0":
            raise ValueError(f"{lane}: nonzero process exit")
        records = [record(line) for line in (directory / f"{lane}.log").read_text().splitlines()]
        if len(records) < 2 or records[0][0] != "UTCP_POSITIVE_START" or records[-1][0] != "UTCP_POSITIVE_FINAL":
            raise ValueError(f"{lane}: missing start or final record")
        for kind, fields in records:
            if fields["lane"] != lane or fields["seed"] != seed:
                raise ValueError(f"{lane}: lane or seed mismatch")
            if not re.fullmatch(r"[0-9a-f]{16}", fields["digest_fnv1a64"]):
                raise ValueError(f"{lane}: invalid digest")
        for (kind_a, a), (kind_b, b) in zip(records, records[1:]):
            if kind_b not in ("UTCP_POSITIVE_PROGRESS", "UTCP_POSITIVE_FINAL"):
                raise ValueError(f"{lane}: unexpected record {kind_b}")
            if int(b["steady_ns"]) <= int(a["steady_ns"]) or int(b["elapsed_ns"]) <= int(a["elapsed_ns"]) or int(b["completed"]) <= int(a["completed"]):
                raise ValueError(f"{lane}: clock or completed count did not advance")
            if int(b["steady_ns"]) - int(a["steady_ns"]) > 65_000_000_000:
                raise ValueError(f"{lane}: progress gap exceeds 65 seconds")
        start = records[0][1]
        final = records[-1][1]
        if start["completed"] != "0" or final.get("exit") != "0":
            raise ValueError(f"{lane}: invalid start or final status")
        elapsed = int(final["elapsed_ns"])
        if elapsed < threshold * 1_000_000_000:
            raise ValueError(f"{lane}: too short ({elapsed} ns)")
        progress = sum(kind == "UTCP_POSITIVE_PROGRESS" for kind, _ in records)
        if progress < threshold // 60:
            raise ValueError(f"{lane}: missing minute progress")
        spans.append((int(start["steady_ns"]), int(final["steady_ns"])))
        print(f"{lane}: completed={final['completed']} elapsed_ns={elapsed} progress={progress} digest_fnv1a64={final['digest_fnv1a64']}")
    overlap = min(end for _, end in spans) - max(start for start, _ in spans)
    if overlap < threshold * 1_000_000_000:
        raise ValueError(f"common overlap too short ({overlap} ns)")
    print(f"common_overlap_ns={overlap} status=ok")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: verify_positive_protocol_soak.py OUTPUT_DIR MIN_COMMON_SECONDS SEED")
    check(pathlib.Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3])
