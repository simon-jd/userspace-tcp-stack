"""Summarize the 10 ms sender samples, stack events and queues used to interpret checkpoint gaps."""

import collections
import csv
import json
import statistics
import sys
from pathlib import Path


def rows(path):
    with path.open() as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def main(campaign, evidence, output):
    with evidence.open(newline="") as f:
        counted = [r for r in csv.DictReader(f) if r["counted"] == "1"]
    fields = [
        "cell",
        "algorithm",
        "impl",
        "run",
        "goodput_bps",
        "qdelay_p50_ms",
        "qdelay_p99_ms",
        "retrans_pct",
        "capture_retrans_pct",
        "cwnd_p50",
        "cwnd_min",
        "cwnd_max",
        "ssthresh_p50",
        "srtt_us_p50",
        "cwnd_at_warmup",
        "cwnd_at_end",
        "pacing_mbit_p50",
        "delivery_mbit_p50",
        "ca_states",
        "netem_drops_run",
        "tbf_drops_run",
        "max_backlog_bytes",
        "queue_fraction_p50",
        "positive_backlog_fraction",
        "stack_events_in_window",
        "stack_tx_kinds_in_window",
        "rto_run",
        "loss_probes_run",
        "sackrecoveries_run",
        "hystart_train_run",
        "hystart_delay_run",
        "sndbuf_frac",
        "rwnd_frac",
    ]
    with output.open("x", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for item in counted:
            rd = campaign / item["run"]
            m = json.loads((rd / "meta.json").read_text())
            s = json.loads((rd / "summary.json").read_text())
            lo = s["t0_ns"] + 5 * 10**9
            hi = s["window_end_ns"]
            sender = list(rows(rd / "snd.jsonl"))
            clock = next(r for r in sender if r.get("ev") == "clock")
            samples = [r for r in sender if r.get("ev") == "sample" and lo <= r["t"] <= hi]
            events = collections.Counter()
            tx = collections.Counter()
            if m["impl"] == "utcp":
                for r in rows(rd / "trace.jsonl"):
                    if lo <= r["t"] <= hi:
                        events[r["ev"]] += 1
                        if r["ev"] == "tx":
                            tx[r.get("tx", "?")] += 1
            med = lambda k: statistics.median(r[k] for r in samples if r.get(k) is not None)
            net = s.get("netem") or {}
            tbf = s.get("tbf") or {}
            q = s.get("queue") or {}
            stats = s.get("sender_counters") or {}
            delta = clock["realtime_ns"] - clock["monotonic_ns"]
            import analyze as A

            backlog = [
                b
                for t, b, _ in A.parse_tbf_samples((rd / "tbf.txt").read_text())
                if lo + delta <= t <= hi + delta and b is not None
            ]
            states = collections.Counter(r.get("ca_state", "?") for r in samples)
            writer.writerow(
                dict(
                    cell=m["cell"],
                    algorithm=m["algo"],
                    impl=m["impl"],
                    run=m["run"],
                    goodput_bps=s["goodput_bps"],
                    qdelay_p50_ms=s["qdelay_p50_ms"],
                    qdelay_p99_ms=s["qdelay_p99_ms"],
                    retrans_pct=s["retrans_pct"],
                    capture_retrans_pct=s.get("retrans_pct_capture"),
                    cwnd_p50=med("cwnd"),
                    cwnd_min=min(r["cwnd"] for r in samples),
                    cwnd_max=max(r["cwnd"] for r in samples),
                    cwnd_at_warmup=samples[0]["cwnd"],
                    cwnd_at_end=samples[-1]["cwnd"],
                    ssthresh_p50=med("ssthresh"),
                    srtt_us_p50=med("srtt_us"),
                    pacing_mbit_p50=med("pacing_rate") * 8 / 1e6,
                    delivery_mbit_p50=med("delivery_rate") * 8 / 1e6,
                    ca_states=json.dumps(states, sort_keys=True),
                    netem_drops_run=net.get("dropped"),
                    tbf_drops_run=tbf.get("dropped"),
                    max_backlog_bytes=q.get("backlog_max"),
                    queue_fraction_p50=statistics.median(backlog) / m["queue_bytes"] if backlog else "",
                    positive_backlog_fraction=sum(b > 0 for b in backlog) / len(backlog)
                    if backlog
                    else "",
                    stack_events_in_window=json.dumps(events, sort_keys=True),
                    stack_tx_kinds_in_window=json.dumps(tx, sort_keys=True),
                    rto_run=stats.get("TcpExtTCPTimeouts"),
                    loss_probes_run=stats.get("TcpExtTCPLossProbes"),
                    sackrecoveries_run=stats.get("TcpExtTCPSackRecovery"),
                    hystart_train_run=stats.get("TcpExtTCPHystartTrainDetect"),
                    hystart_delay_run=stats.get("TcpExtTCPHystartDelayDetect"),
                    sndbuf_frac=s["sndbuf_limited_frac"],
                    rwnd_frac=s["rwnd_limited_frac"],
                )
            )


if __name__ == "__main__":
    repo, campaign, evidence, output = (Path(k) for k in sys.argv[1:])
    sys.path.insert(0, str(repo / "tools/m2"))
    main(campaign, evidence, output)
