"""Reconstruct one transfer from recorded endpoint samples, complete payload digests and monotonic bounds."""

import bisect
import json
import math
from fractions import Fraction

NS = 10**9


def read(path):
    return json.loads(path.read_text())


def at(samples, t, key):
    times = [v["t"] for v in samples]
    assert times == sorted(times) and times[0] <= t <= times[-1]
    k = bisect.bisect_right(times, t) - 1
    if times[k] == t:
        return Fraction(samples[k][key])
    a, b = samples[k : k + 2]
    return a[key] + Fraction((b[key] - a[key]) * (t - a["t"]), b["t"] - a["t"])


def audit_run(rd, A):
    meta = read(rd / "meta.json")
    summ = read(rd / "summary.json")
    assert A.summarize_run(rd) == summ, "raw-to-summary mismatch"
    endpoints = {}
    samples = {}
    for role, fname in (("sender", "snd.jsonl"), ("receiver", "rcv.jsonl")):
        records = [json.loads(l) for l in (rd / fname).read_text().splitlines() if l]
        (start,) = [r for r in records if r.get("ev") == "start"]
        (terminal,) = [r for r in records if r.get("ev") == "summary"]
        assert start["role"] == terminal["role"] == role and terminal["ok"] is True
        assert type(start["t"]) is int and type(terminal["bytes"]) is int
        assert terminal["backend"] == (
            "utcp" if role == "sender" and meta["impl"] == "utcp" else "kernel"
        )
        endpoints[role] = dict(
            start_ns=start["t"],
            bytes=terminal["bytes"],
            sha256=terminal["sha256"],
            backend=terminal["backend"],
        )
        samples[role] = [r for r in records if r.get("ev") == "sample"]
    snd, rcv = (endpoints[r] for r in ("sender", "receiver"))
    assert (
        snd["bytes"] == rcv["bytes"] > 0 and snd["sha256"] == rcv["sha256"] and len(snd["sha256"]) == 64
    )
    assert meta["duration_s"] == (30 if meta["rtt"] == 20 else 60)
    dur = int(meta["duration_s"] * NS)
    lo = rcv["start_ns"] + 5 * NS
    hi = min(snd["start_ns"], rcv["start_ns"]) + dur
    assert lo < hi
    assert (rcv["start_ns"], snd["start_ns"], hi) == (
        summ["t0_ns"],
        summ["sender_start_ns"],
        summ["window_end_ns"],
    )
    for role, rows in samples.items():
        ts = [r["t"] for r in rows]
        assert ts == sorted(ts) and ts[0] <= lo < hi <= ts[-1]
        endpoints[role]["sample_bounds_ns"] = [ts[0], ts[-1]]
        endpoints[role]["samples_in_window"] = sum(lo <= t <= hi for t in ts)
    rates = [at(samples["receiver"], t, "bytes_received") for t in (lo, hi)]
    bps = float((rates[1] - rates[0]) * 8 * NS / (hi - lo))
    assert math.isclose(bps, summ["goodput_bps"], rel_tol=2e-13)
    ccs = {r["cc_name"] for r in samples["sender"] if lo <= r["t"] <= hi}
    assert ccs == {meta["cc"]} and sorted(ccs) == summ["sender_ccs"]
    return {
        "endpoints": endpoints,
        "lo_ns": lo,
        "hi_ns": hi,
        "observed_cc": sorted(ccs),
        "sha256": snd["sha256"],
    }
