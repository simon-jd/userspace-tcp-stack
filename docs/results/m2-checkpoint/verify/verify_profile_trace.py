"""Verify the Linux-compatible TCP profile, socket CC and complete trace of every counted stack sender."""

import csv
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

BASE_SETS = ["snd_buf_max=64Mi", "rcv_buf_max=32Mi", "gso_max_size=65215"]
TRACE_KINDS = {"cwnd", "recovery", "rto", "tx"}
RETRANSMISSION_KINDS = {"fast_rexmit", "rexmit", "rto_rexmit", "pmtu_rexmit", "tlp"}


def read(path):
    return json.loads(path.read_text())


def check_profile(meta, sender, summary, reference):
    configs = [r for r in sender if r.get("ev") == "config"]
    if len(configs) != 1 or configs[0] != reference:
        raise ValueError("sender configuration differs from frozen linux_compat reference")
    if meta["profile"] != "linux" or meta["stack_set"] != BASE_SETS or meta.get("stack_args"):
        raise ValueError("non-baseline profile or arguments")
    if reference["set"].split() != BASE_SETS or reference["cc_flavor"] != "linux":
        raise ValueError("unexpected reference or testbed overrides")
    if meta["cc"] != meta["algo"] or meta["cc"] not in ("cubic", "newreno"):
        raise ValueError("socket request differs from algorithm")
    lo, hi = summary["t0_ns"] + 5 * 10**9, summary["window_end_ns"]
    samples = [r for r in sender if r.get("ev") == "sample" and lo <= r["t"] <= hi]
    if not samples or not all(r["cc_name"] == meta["cc"] and r["role"] == "sender" for r in samples):
        raise ValueError("observed socket CC differs from request")
    ids = {r["conn_id"] for r in samples}
    if len(ids) != 1:
        raise ValueError("sender CC samples do not belong to one connection")
    return ids.pop(), len(samples)


def check_trace(path, meta, conn, expected_count):
    if not (meta["trace"] is True and path.is_file() and path.stat().st_size > 0):
        raise ValueError("required stack trace is missing or empty")
    counts = Counter()
    fingerprint = hashlib.sha256()
    previous = None
    tuples = set()
    with path.open("rb") as raw:
        for line in raw:
            event = json.loads(line)
            time = event["t"]
            if (
                type(time) is not int
                or previous is not None
                and time < previous
                or event["conn"] != conn
                or event["ev"] not in TRACE_KINDS
                or type(event["cwnd"]) is not int
                or event["cwnd"] < 0
            ):
                raise ValueError("inconsistent trace timestamp, connection or event")
            if event["ev"] == "tx" and event["tx"] not in RETRANSMISSION_KINDS:
                raise ValueError("unexpected transmission kind")
            previous = time
            tuples.add(event["tuple"])
            counts[event["ev"]] += 1
            fingerprint.update(line)
    if sum(counts.values()) != expected_count or expected_count <= 0:
        raise ValueError("decoded trace count differs from stack counter")
    if len(tuples) != 1 or not re.fullmatch(
        r"198\.18\.0\.2:\d+>" + re.escape(meta["rcv_ip"]) + r":5201", tuples.pop()
    ):
        raise ValueError("unexpected connection tuple in trace")
    return counts, fingerprint.hexdigest()


def main(campaign, evidence, reference_file, output):
    reference = read(reference_file)
    fields = (
        "run",
        "algo",
        "reported_default_cc",
        "observed_socket_cc",
        "samples",
        "profile_fields",
        "reference_sha256",
        "trace_events",
        "trace_cwnd",
        "trace_recovery",
        "trace_rto",
        "trace_tx",
        "trace_sha256",
    )
    reference_digest = hashlib.sha256(reference_file.read_bytes()).hexdigest()
    with evidence.open() as f:
        rows = [r for r in csv.DictReader(f) if r["counted"] == "1" and r["impl"] == "utcp"]
    with output.open("x", newline="") as f:
        writer = csv.DictWriter(f, fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            rd = campaign / row["run"]
            meta, summary, stats = [
                read(rd / name) for name in ("meta.json", "summary.json", "stats.json")
            ]
            sender = [json.loads(line) for line in (rd / "snd.jsonl").read_text().splitlines()]
            conn, nsamples = check_profile(meta, sender, summary, reference)
            if summary["trace_events"] != stats["trace_events"]:
                raise ValueError("summary and original stats disagree about trace length")
            counts, digest = check_trace(rd / "trace.jsonl", meta, conn, stats["trace_events"])
            writer.writerow(
                dict(
                    run=meta["run"],
                    algo=meta["algo"],
                    reported_default_cc=reference["cc"],
                    observed_socket_cc=meta["cc"],
                    samples=nsamples,
                    profile_fields=len(reference) - 2,
                    reference_sha256=reference_digest,
                    trace_events=sum(counts.values()),
                    trace_sha256=digest,
                    **{"trace_" + kind: counts[kind] for kind in TRACE_KINDS},
                )
            )
    print(
        f"Verified full effective configuration, socket CC and complete trace for {len(rows)} stack runs."
    )


if __name__ == "__main__":
    main(*(Path(arg) for arg in sys.argv[1:]))
