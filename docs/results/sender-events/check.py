"""Check the dedicated events in a trace-flight capture (one ordinary sender)."""

from collections import Counter
import json
from pathlib import Path
import re
import sys


def rows(path):
    return [json.loads(row) for row in path.read_text().splitlines()]


def check(folder, controller, loss):
    events = rows(folder / "trace.jsonl")
    sample = next(e for e in rows(folder / "stack.jsonl") if e["ev"] == "sample")
    assert sample["cc_name"] == controller
    filters = (folder / "filter.txt").read_text()
    assert bool(re.search(r"2 pkt \(dropped 1,", filters)) if loss else not filters.strip()
    assert "0 packets dropped by kernel" in (folder / "tcpdump.err").read_text()

    window, state = (0, 0), "open"
    segments = {}
    counts = Counter()
    edges = []
    rx = None
    base = syn_time = None
    ack_rows = []

    for e in events:
        kind = e["ev"]
        if kind == "tx":
            if e["tx"] == "syn":
                base = (e["seq"] + 1) & 0xffffffff
                syn_time = e["t"]
            elif e["len"] or e["flags"] & 1:
                start = (e["seq"] - base) & 0xffffffff
                end = start + e["len"] + (e["flags"] & 1)
                retrans = start in segments
                segments[start] = (end, e["t"], retrans)
        if kind == "rx":
            rx = e
            ack_rows = []
        if kind in ("rtt", "recovery", "cwnd"):
            counts[kind] += 1
            if e["trigger"] in ("ack", "handshake"):
                assert (e["t"], e["seq"], e["ack"]) == (rx["t"], rx["seq"], rx["ack"])
                ack_rows.append(e)
            if e["trigger"] == "handshake":
                counts["initial_" + kind] += 1
        if kind == "cwnd":
            before = e["prior_cwnd"], e["prior_ssthresh"]
            after = e["cwnd"], e["ssthresh"]
            assert before == window and before != after, (window, before, after)
            window = after
        if kind == "recovery":
            assert e["prior_ca"] == state and state != e["ca"]
            edges.append((state, e["ca"]))
            state = e["ca"]
        if kind == "rtt":
            assert e["sample_rtt_us"] >= 0 and e["rto_us"] > 0
            if e["trigger"] == "handshake":
                assert e["sample_rtt_us"] == (rx["t"] - syn_time) // 1000
                counts["time_checked"] += 1
        if kind == "ack":
            assert window == (e["cwnd"], e["ssthresh"]) and state == e["ca"]
            # In these transfers no SACK is reneged. All rows produced by the
            # ACK pipeline see the same acknowledged bytes as the legacy ACK.
            for row in ack_rows:
                if row["trigger"] == "ack":
                    assert row["in_flight_bytes"] == e["in_flight_bytes"]
            ack_end = (e["ack"] - base) & 0xffffffff
            completed = sorted(k for k, seg in segments.items() if seg[0] <= ack_end)
            # In the unambiguous cumulative case the oldest segment supplies
            # the raw sample. Check both its value and that the row exists.
            if (completed and not rx["sacked_out"] and not e["sacked_out"]
                    and not any(segments[k][2] for k in completed)):
                rtts = [r for r in ack_rows if r["ev"] == "rtt"]
                assert len(rtts) == 1, (e, completed)
                assert rtts[0]["sample_rtt_us"] == (rx["t"] - segments[completed[0]][1]) // 1000
                counts["time_checked"] += 1
            for k in completed:
                del segments[k]
            ack_rows = []
        if kind == "state" and e["state"] == "established":
            assert window == (e["cwnd"], e["ssthresh"])
    assert counts["initial_cwnd"] == counts["initial_rtt"] == 1
    assert counts["time_checked"] > 0 and counts["cwnd"] > 1 and counts["rtt"] > 1
    assert not segments and state == "open"
    assert edges and any(new == "recovery" for _, new in edges) if loss else not edges
    return dict(controller=controller, loss=loss, events=len(events), counts=dict(counts), edges=edges)


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Run without -O so assertions execute")
    if len(sys.argv) != 4 or sys.argv[3] not in {"clean", "loss"}:
        sys.exit("usage: check.py CASE_DIR CONTROLLER clean|loss")
    print(json.dumps(check(Path(sys.argv[1]), sys.argv[2], sys.argv[3] == "loss"), sort_keys=True))
