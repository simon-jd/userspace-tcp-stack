#!/usr/bin/env python3
"""Analysis of the M2 comparison testbed runs (DESIGN §14; M2 design §5.4-5.13).

Pure functions (unit-tested in test_analyze.py) plus a command line:

  analyze.py run RUNDIR            summary.json of one run (writes it, prints it)
  analyze.py captures RUNDIR       capture.json from the run's pcaps (r1-in,
                                   r1-out if present, r2-out)
  analyze.py tables OUTDIR (--campaign DIR | --archive FILE)
                                   runs.csv and cells.csv of a campaign, from
                                   its run directories or its analysis archive
  analyze.py archive CAMPAIGN_DIR FILE
                                   the analysis archive (every analysis input,
                                   no pcaps) with a sha256 manifest
  analyze.py pings PCAP SRC DST [COUNT]
                                   idle-ping statistics (gate item 1) from the
                                   echo requests SRC -> DST in a capture

Conventions
- Times: CLOCK_MONOTONIC nanoseconds (the "t" of utcp-bulk's JSONL). CLOCK_REALTIME
  times (ping -D, the tbf sampler) convert with utcp-bulk's clock line:
  mono = rt - realtime_ns + monotonic_ns.
- Window (§5.6): [t0 + 5 s, min(t0 + S, sender start + S)], t0 = the
  receiver's start line (accept time), S = the run length, sender start = the
  sender's start line, from which its writes last S (run_window); counters at
  the bounds are interpolated linearly between the 10 ms samples.
- Percentiles: linear interpolation between closest ranks (numpy's default),
  p in [0, 1].
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
import re
import statistics
import struct
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

NS = 1_000_000_000
WARMUP_S = 5.0

# --- Pre-registered rules (docs/RESULTS.md "Gap rule and thresholds" and
# "Which runs count"; M2 design §5.6, §5.10). Changing any of these after the
# first matrix run is not allowed.
GAP_REL = 0.10                     # medians differ by more than 10 % of Linux's
DELAY_RESOLUTION_MS = 1.0          # delay gaps below 1 ms: "below resolution"
RETRANS_THRESHOLD_PP = {0.0: 0.05, 0.1: 0.05, 1.0: 0.2}  # percentage points by loss %
JAIN_REPORT_DIFF = 0.05
RUNS_PER_SIDE = 5
RERUN_CAP = 3
LIMITED_FLAG_FRACTION = 0.01       # sndbuf/rwnd-limited time >= 1 % of the window flags
# Transient-dominated cells (RESULTS.md): 100 Mbit/s, 100 ms, 0 % loss, both
# queues, for the window-based algorithms.
TRANSIENT_CELLS = {(100, 100, 0.0, 0.5), (100, 100, 0.0, 2.0)}
TRANSIENT_CCS = {"newreno", "reno", "cubic"}


def transient(bw, rtt, loss, queue_bdp, cc):
    try:
        key = (int(bw), int(rtt), float(loss), float(queue_bdp))
    except (TypeError, ValueError):
        return False
    return key in TRANSIENT_CELLS and str(cc) in TRANSIENT_CCS


# --------------------------------------------------------------------------
# Basic statistics


def percentile(xs, p):
    """Linear interpolation between closest ranks; p in [0, 1]."""
    if not xs:
        return None
    s = sorted(xs)
    pos = p * (len(s) - 1)
    lo = math.floor(pos)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def median(xs):
    return percentile(xs, 0.5)


def jain(xs):
    """Jain's fairness index (sum x)^2 / (n * sum x^2)."""
    xs = list(xs)
    if not xs:
        return None
    sq = sum(x * x for x in xs)
    if sq == 0:
        return None
    return sum(xs) ** 2 / (len(xs) * sq)


def ranges_overlap(a_min, a_max, b_min, b_max):
    return a_min <= b_max and b_min <= a_max


# --------------------------------------------------------------------------
# JSONL and time series


def read_jsonl(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def find_event(lines, ev):
    for d in lines:
        if d.get("ev") == ev:
            return d
    return None


def series(lines, key):
    """[(t_ns, value)] of the sample lines, in order."""
    return [(d["t"], d[key]) for d in lines if d.get("ev") == "sample" and key in d]


def interp(ser, t):
    """Value of a sampled counter at time t, linear between the neighbours.
    None if t is outside the sampled range."""
    if not ser or t < ser[0][0] or t > ser[-1][0]:
        return None
    lo, hi = 0, len(ser) - 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if ser[mid][0] <= t:
            lo = mid
        else:
            hi = mid
    t0, v0 = ser[lo]
    t1, v1 = ser[hi]
    if t1 == t0 or t <= t0:
        return float(v0)
    if t >= t1:
        return float(v1)
    return v0 + (v1 - v0) * (t - t0) / (t1 - t0)


def delta(ser, lo, hi):
    a, b = interp(ser, lo), interp(ser, hi)
    if a is None or b is None:
        return None
    return b - a


@dataclass
class Clock:
    monotonic_ns: int
    realtime_ns: int

    def to_mono(self, rt_ns):
        return rt_ns - self.realtime_ns + self.monotonic_ns


def clock_of(lines):
    c = find_event(lines, "clock")
    return Clock(c["monotonic_ns"], c["realtime_ns"]) if c else None


def window(t0_ns, duration_s):
    return (t0_ns + int(WARMUP_S * NS), t0_ns + int(duration_s * NS))


# --------------------------------------------------------------------------
# ping -D -O output. iputils prints an RTT of 100 ms or more as whole
# milliseconds (10-100 ms with 0.1 ms), so the runs take ping RTTs from the
# r1-in capture instead (icmp_echoes) and use this text only when a run has no
# capture.

_PING_REPLY = re.compile(r"^\[(\d+)\.(\d+)\] \d+ bytes from [^:]+: icmp_seq=(\d+) .*time=([\d.]+) ms")
_PING_NOANS = re.compile(r"^\[(\d+)\.(\d+)\] no answer yet for icmp_seq=(\d+)")


def _rt_ns(sec, frac):
    return int(sec) * NS + int(frac.ljust(9, "0")[:9])


@dataclass
class Ping:
    seq: int
    send_rt_ns: int        # reply: receive time - rtt; lost: "no answer" time - interval
    rtt_ms: float | None   # None: no reply


def parse_ping(text, interval_s=0.05):
    """Replies and pings without a reply, one entry per icmp_seq, by seq."""
    replies, noans = {}, {}
    for line in text.splitlines():
        m = _PING_REPLY.match(line)
        if m:
            rtt = float(m.group(4))
            recv = _rt_ns(m.group(1), m.group(2))
            seq = int(m.group(3))
            replies.setdefault(seq, Ping(seq, recv - int(rtt * 1e6), rtt))
            continue
        m = _PING_NOANS.match(line)
        if m:
            seq = int(m.group(3))
            noans.setdefault(seq, Ping(seq, _rt_ns(m.group(1), m.group(2)) - int(interval_s * NS), None))
    out = dict(noans)
    out.update(replies)  # a late reply wins over "no answer yet"
    return [out[k] for k in sorted(out)]


def ping_stats(pings, count=None):
    """Item 1 statistics of an idle ping series: replies, lost, median, p99, max (ms)."""
    rtts = [p.rtt_ms for p in pings if p.rtt_ms is not None]
    n_sent = count if count is not None else len(pings)
    return {"n": len(rtts), "lost": n_sent - len(rtts), "median_ms": median(rtts),
            "p99_ms": percentile(rtts, 0.99), "max_ms": max(rtts) if rtts else None}


def ping_metrics(pings, clock, t0_ns, lo_ns, hi_ns):
    """Base RTT = median of replies received before t0 (the idle pings); queueing
    delay = rtt - base over replies sent in [lo, hi]; lost pings sent in the
    window counted and excluded."""
    idle = [p.rtt_ms for p in pings if p.rtt_ms is not None
            and clock.to_mono(p.send_rt_ns) + p.rtt_ms * 1e6 < t0_ns]
    base = median(idle)
    inwin = [p for p in pings if lo_ns <= clock.to_mono(p.send_rt_ns) <= hi_ns]
    rtts = [p.rtt_ms for p in inwin if p.rtt_ms is not None]
    lost = sum(1 for p in inwin if p.rtt_ms is None)
    out = {"ping_idle_n": len(idle), "ping_base_ms": base, "ping_n": len(rtts), "ping_lost": lost}
    if base is not None and rtts:
        q = [r - base for r in rtts]
        out.update(qdelay_p50_ms=percentile(q, 0.5), qdelay_p99_ms=percentile(q, 0.99),
                   ping_max_ms=max(rtts))
    else:
        out.update(qdelay_p50_ms=None, qdelay_p99_ms=None, ping_max_ms=None)
    return out


# --------------------------------------------------------------------------
# testbed/m2/record.sh output


def parse_record(text):
    """{(where, what): [lines]} of the '== where what' sections."""
    sections, key = {}, None
    for line in text.splitlines():
        if line.startswith("== "):
            parts = line[3:].split(" ", 1)
            key = (parts[0], parts[1] if len(parts) > 1 else "")
            sections[key] = []
        elif key is not None:
            sections[key].append(line)
    return sections


_QDISC = re.compile(r"^qdisc (\S+) \S+ dev (\S+) ")
_SENT = re.compile(r"Sent (\d+) bytes (\d+) pkt \(dropped (\d+), overlimits (\d+) requeues (\d+)\)")
_BACKLOG = re.compile(r"backlog (\d+)b (\d+)p")


def parse_qdiscs(lines):
    """{dev: {kind, bytes, pkts, dropped, overlimits, backlog_bytes}} of `tc -s qdisc show`."""
    out, cur = {}, None
    for line in lines:
        m = _QDISC.match(line)
        if m:
            cur = {"kind": m.group(1), "line": line.strip()}
            out[m.group(2)] = cur
            continue
        if cur is None:
            continue
        m = _SENT.search(line)
        if m:
            cur.update(bytes=int(m.group(1)), pkts=int(m.group(2)), dropped=int(m.group(3)),
                       overlimits=int(m.group(4)))
        m = _BACKLOG.search(line)
        if m and "backlog_bytes" not in cur:
            cur.update(backlog_bytes=int(m.group(1)), backlog_pkts=int(m.group(2)))
    return out


_LINK = re.compile(r"^\d+: ([^:@]+)(?:@\S+)?: ")


def parse_links(lines):
    """{dev: {rx_packets, rx_errors, rx_dropped, tx_packets, tx_errors, tx_dropped, mtu,
    gso_ipv4_max_size}} of `ip -s -d link show`."""
    out, cur, want = {}, None, None
    for line in lines:
        m = _LINK.match(line)
        if m:
            cur = {}
            out[m.group(1)] = cur
            mm = re.search(r" mtu (\d+)", line)
            if mm:
                cur["mtu"] = int(mm.group(1))
            want = None
            continue
        if cur is None:
            continue
        mm = re.search(r"gso_ipv4_max_size (\d+)", line)
        if mm:
            cur["gso_ipv4_max_size"] = int(mm.group(1))
        s = line.strip()
        if s.startswith("RX:"):
            want = "rx"
            continue
        if s.startswith("TX:"):
            want = "tx"
            continue
        if want and s and s.split()[0].isdigit():
            f = [int(x) for x in s.split()[:4]]
            cur.update({f"{want}_bytes": f[0], f"{want}_packets": f[1], f"{want}_errors": f[2],
                        f"{want}_dropped": f[3]})
            want = None
    return out


def parse_softnet(lines):
    """{cpu: (processed, dropped, time_squeeze)}; the line index is the first field."""
    out = {}
    for line in lines:
        f = line.split()
        if len(f) < 4:
            continue
        cpu = int(f[13], 16) if len(f) > 13 else int(f[0])
        out[cpu] = (int(f[1], 16), int(f[2], 16), int(f[3], 16))
    return out


def parse_proc_stat(lines):
    """{cpu: {irq, softirq, busy, total}} jiffies of the cpuN lines."""
    out = {}
    for line in lines:
        f = line.split()
        if not f or not f[0].startswith("cpu") or f[0] == "cpu":
            continue
        v = [int(x) for x in f[1:]]
        user, nice, system, idle, iowait, irq, softirq = v[:7]
        steal = v[7] if len(v) > 7 else 0
        total = sum(v[:8])
        out[int(f[0][3:])] = {"irq": irq, "softirq": softirq, "total": total,
                              "busy": total - idle - iowait}
    return out


def parse_nstat(lines):
    """{name: value} of `nstat -asz` lines ("TcpExtTCPSackRecovery  12  0.0")."""
    out = {}
    for line in lines:
        f = line.split()
        if len(f) >= 2 and not f[0].startswith("#") and f[1].isdigit():
            out[f[0]] = int(f[1])
    return out


def parse_softirqs(lines):
    """{kind: {cpu: count}} of /proc/softirqs (header "CPU0 CPU1 ...")."""
    out, cpus = {}, None
    for line in lines:
        f = line.split()
        if not f:
            continue
        if cpus is None:
            cpus = [int(c[3:]) for c in f if c.startswith("CPU")]
            continue
        if f[0].endswith(":"):
            out[f[0][:-1]] = {cpu: int(v) for cpu, v in zip(cpus, f[1:])}
    return out


# Sender counters compared between the two senders (§5.9 "Testbed counters";
# §1.10's list): Linux from the sender container's nstat, the stack from its
# --stats line, which uses the same names.
SENDER_COUNTERS = ("TcpOutSegs", "TcpRetransSegs", "TcpExtTCPSackRecovery", "TcpExtTCPRenoRecovery",
                   "TcpExtTCPLossProbes", "TcpExtTCPLossProbeRecovery", "TcpExtTCPTimeouts",
                   "TcpExtTCPFastRetrans", "TcpExtTCPSlowStartRetrans", "TcpExtTCPDSACKRecv",
                   "TcpExtTCPDSACKRecvSegs", "TcpExtTCPSACKReorder", "TcpExtTCPSpuriousRTOs",
                   "TcpExtTCPHystartTrainDetect", "TcpExtTCPHystartDelayDetect")
SOFTIRQ_KINDS = ("NET_RX", "NET_TX", "HRTIMER", "TIMER")


def cpu_list(spec):
    """'8,9' or '8-11' -> [8, 9] / [8, 9, 10, 11]."""
    out = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def parse_cgroup_usage(lines):
    """{container: usage_usec} of record.sh's "cgroup cpu.stat" section
    ("<container> usage_usec N"); None when the section is absent."""
    out = {}
    for line in lines:
        f = line.split()
        if len(f) >= 3 and f[1] == "usage_usec" and f[2].isdigit():
            out[f[0]] = int(f[2])
    return out


def record_counters(rec, containers):
    """Per container: qdiscs and links; host: softnet, /proc/stat, the
    containers' cgroup CPU usage and the clock tick."""
    out = {"qdisc": {}, "link": {}}
    for c in containers:
        out["qdisc"][c] = parse_qdiscs(rec.get((c, "tc -s -raw qdisc"), rec.get((c, "tc -s qdisc"), [])))
        out["link"][c] = parse_links(rec.get((c, "ip -s -d link"), []))
    out["softnet"] = parse_softnet(rec.get(("host", "softnet_stat"), []))
    out["stat"] = parse_proc_stat(rec.get(("host", "/proc/stat"), []))
    out["softirqs"] = parse_softirqs(rec.get(("host", "/proc/softirqs"), []))
    out["nstat"] = {c: parse_nstat(rec.get((c, "nstat -asz"), [])) for c in containers}
    out["cgroup_usage"] = parse_cgroup_usage(rec.get(("host", "cgroup cpu.stat"), []))
    tck = [l.strip() for l in rec.get(("host", "clk_tck"), []) if l.strip().isdigit()]
    out["clk_tck"] = int(tck[0]) if tck else 100
    return out


def local_drops(pre, post, roles, slot_cpus):
    """Invalidating counters (§5.2), as {name: delta} of the non-zero ones:
    rx and tx drops of every interface of the four containers (sender eth0
    TX, the routers' and receiver's RX, the ACK path's veth drops, the utcp*
    TUNs), the utcp* pfifo drops, and softnet drops on the slot's CPUs. Also
    returns the time_squeeze delta on the slot's CPUs (a flag)."""
    bad = {}

    def d(c, dev, key, kind="link"):
        a = pre[kind].get(c, {}).get(dev, {}).get(key)
        b = post[kind].get(c, {}).get(dev, {}).get(key)
        return None if a is None or b is None else b - a

    for role in ("snd", "r1", "r2", "rcv"):
        c = roles[role]
        for dev in sorted(post["link"].get(c, {})):
            if dev == "lo":
                continue
            for k in ("rx_dropped", "tx_dropped"):
                v = d(c, dev, k)
                if v:
                    bad[f"{c}/{dev}/{k}"] = v
            if dev.startswith("utcp"):
                v = d(c, dev, "dropped", "qdisc")
                if v:
                    bad[f"{c}/{dev}/qdisc_dropped"] = v
    squeeze = 0
    for cpu in slot_cpus:
        a, b = pre["softnet"].get(cpu), post["softnet"].get(cpu)
        if a and b:
            if b[1] - a[1]:
                bad[f"softnet/cpu{cpu}/dropped"] = b[1] - a[1]
            squeeze += b[2] - a[2]
    return bad, squeeze


def cpu_deltas(pre, post, cpus):
    out = {}
    for cpu in cpus:
        a, b = pre["stat"].get(cpu), post["stat"].get(cpu)
        if a and b:
            out[cpu] = {k: b[k] - a[k] for k in ("irq", "softirq", "busy", "total")}
    return out


FOREIGN_CPU_FLAG_FRACTION = 0.02   # foreign CPU time >= 2 % of the slot CPUs' time flags


def foreign_cpu(pre, post, cpus, containers):
    """CPU time on the slot's CPUs that is not the run's (RESULTS.md "Which runs
    count"), between the pre and post records, as fractions of the slot CPUs'
    time. ours = the four containers' cgroup usage (they are pinned to the
    slot CPUs; docker exec processes join the container's cgroup). The
    server's kernel has no CONFIG_IRQ_TIME_ACCOUNTING: irq and softirq time
    is sampled per tick, and a tick that hits softirq work while one of our
    tasks runs counts in both /proc/stat softirq and that task's usage. So
      lower = busy - irq - softirq - ours   (softirq counted as ours)
      upper = busy - ours                   (all softirq outside our tasks as foreign)
    bound the foreign time; the flag uses the lower bound. None when the
    records lack the cgroup section."""
    pu, qu = pre.get("cgroup_usage") or {}, post.get("cgroup_usage") or {}
    if not qu or any(c not in pu or c not in qu for c in containers):
        return None
    hz = post.get("clk_tck", 100)
    d = cpu_deltas(pre, post, cpus)
    if not d:
        return None
    us = 1e6 / hz
    total = sum(v["total"] for v in d.values()) * us
    busy = sum(v["busy"] for v in d.values()) * us
    irq = sum(v["irq"] + v["softirq"] for v in d.values()) * us
    ours = sum(qu[c] - pu[c] for c in containers)
    if total <= 0:
        return None
    return {"lower_frac": max(0.0, busy - irq - ours) / total, "upper_frac": max(0.0, busy - ours) / total,
            "ours_frac": ours / total, "busy_frac": busy / total}


def softirq_deltas(pre, post, cpus):
    """{kind: delta summed over cpus} for SOFTIRQ_KINDS."""
    out = {}
    for k in SOFTIRQ_KINDS:
        a, b = pre.get("softirqs", {}).get(k), post.get("softirqs", {}).get(k)
        if a and b:
            out[k] = sum(b.get(c, 0) - a.get(c, 0) for c in cpus)
    return out


def nstat_deltas(pre, post, c, names=SENDER_COUNTERS):
    a, b = pre.get("nstat", {}).get(c, {}), post.get("nstat", {}).get(c, {})
    if not b:
        return None
    return {n: b.get(n, 0) - a.get(n, 0) for n in names}


def qdisc_delta(pre, post, c, dev):
    a = pre["qdisc"].get(c, {}).get(dev)
    b = post["qdisc"].get(c, {}).get(dev)
    if not b:
        return None
    if not a or a.get("kind") != b.get("kind"):
        a = {}  # created during the run (shape.sh): counts from zero
    return {k: b.get(k, 0) - a.get(k, 0) for k in ("pkts", "bytes", "dropped", "overlimits")}


# --------------------------------------------------------------------------
# tbf sampler (r2: "@ <EPOCHREALTIME>" then `tc -s qdisc show dev $if`, every 10 ms)


def parse_tbf_samples(text):
    """[(rt_ns, backlog_bytes, dropped)]"""
    out, t = [], None
    backlog = dropped = None
    for line in text.splitlines():
        if line.startswith("@ "):
            if t is not None and backlog is not None:
                out.append((t, backlog, dropped))
            sec, _, frac = line[2:].strip().partition(".")
            t = _rt_ns(sec, frac or "0")
            backlog = dropped = None
            continue
        m = _SENT.search(line)
        if m:
            dropped = int(m.group(3))
        m = _BACKLOG.search(line)
        if m and backlog is None:
            backlog = int(m.group(1))
    if t is not None and backlog is not None:
        out.append((t, backlog, dropped))
    return out


FRAME = 1514  # a full-size frame as tbf counts it (skb->len with the Ethernet header)


def queue_check(samples, q_bytes, rate_bps=None, burst_bytes=0, lo_rt=None, hi_rt=None, frac=0.9):
    """Gate item 4 on the sampler: the highest backlog, whether it reaches
    [frac, 1]·Q, and the drop increments that a tail drop at the limit cannot
    explain. tbf drops a frame only when backlog + frame > Q; afterwards the
    queue drains at most at the rate R plus the bucket B, and before it, it
    filled no faster than the arrivals allow. So for a drop between samples i
    and i+1 (Δt apart), max(b_i, b_i+1) >= Q - frame - B - R·Δt; an interval
    below that level is "low". With R unknown, the level is frac·Q.
    §5.4 asks for a sample >= 0.9·Q in every drop interval; at 10 ms the queue
    drains R·10 ms between samples (12 500 B at 10 Mbit/s, 125 000 B at
    100 Mbit/s, as much as a 0.5xBDP queue holds), so that test fails on
    correct tail drops; drop_intervals_below_frac still counts it (DESIGN §14).
    Where the level is <= 0 (Q <= 1514 + B + R·Δt: the 0.5xBDP queues at
    20 ms) any backlog meets it, so such an interval is counted as
    drop_intervals_untestable and not as tested; "drop_check" is "tested",
    "not testable at 10 ms sampling" (every drop interval untestable),
    "partly testable" or "no drops"."""
    s = [x for x in samples if (lo_rt is None or x[0] >= lo_rt) and (hi_rt is None or x[0] <= hi_rt)]
    if not s:
        return {"backlog_max": None, "reaches": False, "drop_intervals": 0, "drop_intervals_low": 0,
                "drop_intervals_below_frac": 0, "drop_intervals_untestable": 0, "min_level": None,
                "drop_check": "no samples"}
    bmax = max(x[1] for x in s)
    n = low = below = untestable = 0
    min_level = None
    for a, b in zip(s, s[1:]):
        if a[2] is not None and b[2] is not None and b[2] > a[2]:
            n += 1
            top = max(a[1], b[1])
            if rate_bps:
                level = q_bytes - FRAME - burst_bytes - rate_bps / 8 * (b[0] - a[0]) / NS
            else:
                level = frac * q_bytes
            min_level = level if min_level is None else min(min_level, level)
            if level <= 0:
                untestable += 1
            else:
                low += top < level
            below += top < frac * q_bytes
    if n == 0:
        check = "no drops"
    elif untestable == n:
        check = "not testable at 10 ms sampling"
    elif untestable:
        check = "partly testable"
    else:
        check = "tested"
    return {"backlog_max": bmax, "reaches": frac * q_bytes <= bmax <= q_bytes,
            "drop_intervals": n, "drop_intervals_low": low, "drop_intervals_below_frac": below,
            "drop_intervals_untestable": untestable, "min_level": min_level, "drop_check": check}


# --------------------------------------------------------------------------
# Captures


def read_pcap(path):
    """Yields (ts_ns, ip_bytes) for every record; Ethernet (1) or raw IP (101/12)."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
        else:
            endian = ">"
            magic = struct.unpack(">I", hdr[:4])[0]
        nano = magic == 0xA1B23C4D
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        rec = struct.Struct(endian + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, frac, incl, _orig = rec.unpack(h)
            data = f.read(incl)
            ts = sec * NS + (frac if nano else frac * 1000)
            if linktype == 1:
                if len(data) < 14:
                    continue
                etype = struct.unpack(">H", data[12:14])[0]
                if etype != 0x0800:
                    continue
                data = data[14:]
            yield ts, data


@dataclass
class TcpSeg:
    ts_ns: int
    src: str
    dst: str
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    payload: int
    ipid: int = 0
    tsval: int | None = None


def _tsval(opts):
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            return None
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts):
            return None
        ln = opts[i + 1]
        if kind == 8 and ln == 10 and i + 10 <= len(opts):
            return struct.unpack(">I", opts[i + 2:i + 6])[0]
        if ln < 2:
            return None
        i += ln
    return None


def tcp_segments(path):
    for ts, ip in read_pcap(path):
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 15) * 4
        total = struct.unpack(">H", ip[2:4])[0]
        t = ip[ihl:]
        if len(t) < 14:
            continue
        sport, dport, seq, ack = struct.unpack(">HHII", t[:12])
        doff = (t[12] >> 4) * 4
        flags = t[13]
        yield TcpSeg(ts, ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20])),
                     sport, dport, seq, ack, flags, total - ihl - doff,
                     struct.unpack(">H", ip[4:6])[0], _tsval(t[20:doff]))


def icmp_echoes(path, src_ip, dst_ip):
    """Echo requests src_ip -> dst_ip in a capture paired with their replies by
    ICMP id and sequence number: [Ping(seq, request time, rtt_ms or None)] in
    request order. Both directions cross the capturing interface (r1-in sees
    the request on its way in and the reply on its way out), so the RTT is
    the capture's own time difference with nanosecond timestamps; it leaves
    out the two sender-r1 veth hops, which the run's idle base removes too."""
    req, out = {}, []
    for ts, ip in read_pcap(path):
        if len(ip) < 28 or ip[0] >> 4 != 4 or ip[9] != 1:
            continue
        ihl = (ip[0] & 15) * 4
        icmp = ip[ihl:]
        if len(icmp) < 8:
            continue
        src = ".".join(map(str, ip[12:16]))
        dst = ".".join(map(str, ip[16:20]))
        ident, seq = struct.unpack(">HH", icmp[4:8])
        if icmp[0] == 8 and src == src_ip and dst == dst_ip:
            p = Ping(seq, ts, None)
            req.setdefault((ident, seq), p)
            out.append(p)
        elif icmp[0] == 0 and src == dst_ip and dst == src_ip:
            p = req.get((ident, seq))
            if p is not None and p.rtt_ms is None:
                p.rtt_ms = (ts - p.send_rt_ns) / 1e6
    return out


def seq_leq(a, b):
    """a <= b in 32-bit sequence space."""
    d = (b - a) & 0xFFFFFFFF
    return d == 0 or d < 0x80000000


CAPTURE_BIN_NS = 10_000_000


def capture_summary(path, dst_ip, dport=None, bin_ns=None):
    """Data segments toward dst_ip (payload > 0): count and retransmissions
    (segments whose end is not above the highest end already seen, per flow).
    With bin_ns also "bins": the counts per bin of bin_ns from t0_rt_ns (the
    first data segment's bin), for the window cross-check (counts_series)."""
    n = retrans = 0
    high = {}
    t_first = None
    data_bins, rexmit_bins = [], []
    for s in tcp_segments(path):
        if s.dst != dst_ip or s.payload <= 0 or (dport is not None and s.dport != dport):
            continue
        n += 1
        key = (s.src, s.sport, s.dport)
        end = (s.seq + s.payload) & 0xFFFFFFFF
        h = high.get(key)
        is_rexmit = h is not None and seq_leq(end, h)
        if is_rexmit:
            retrans += 1
        else:
            high[key] = end
        if bin_ns:
            if t_first is None:
                t_first = s.ts_ns - s.ts_ns % bin_ns
            i = (s.ts_ns - t_first) // bin_ns
            while len(data_bins) <= i:
                data_bins.append(0)
                rexmit_bins.append(0)
            data_bins[i] += 1
            rexmit_bins[i] += is_rexmit
    out = {"data_segs": n, "retrans_segs": retrans}
    if bin_ns:
        out["bins"] = {"t0_rt_ns": t_first, "bin_ns": bin_ns, "data": data_bins, "retrans": rexmit_bins}
    return out


def counts_series(bins, key):
    """Cumulative series [(rt_ns, count up to rt_ns)] at the bin edges of a
    capture_summary "bins" object; interp() between edges, as for the 10 ms
    counter samples."""
    if not bins or bins.get("t0_rt_ns") is None:
        return []
    t, step = bins["t0_rt_ns"], bins["bin_ns"]
    out, acc = [(t, 0)], 0
    for i, c in enumerate(bins[key]):
        acc += c
        out.append((t + (i + 1) * step, acc))
    return out


def binom_interval(n, p, alpha):
    """Two-sided acceptance interval [lo, hi] for a Binomial(n, p) count at level
    alpha (each tail <= alpha/2), exact, from the log pmf."""
    if n <= 0:
        return (0, 0)
    if p <= 0:
        return (0, 0)
    lp, lq = math.log(p), math.log1p(-p)
    lg = math.lgamma(n + 1)
    mode = int((n + 1) * p)

    def pmf(k):
        return math.exp(lg - math.lgamma(k + 1) - math.lgamma(n - k + 1) + k * lp + (n - k) * lq)

    # Terms beyond 40 standard deviations are below double precision.
    reach = int(40 * math.sqrt(n * p * (1 - p))) + 10
    # Lower tail: largest lo with P(X < lo) <= alpha/2.
    acc, lo = 0.0, max(0, mode - reach)
    for k in range(max(0, mode - reach), mode + 1):
        pk = pmf(k)
        if acc + pk > alpha / 2:
            lo = k
            break
        acc += pk
    else:
        lo = mode
    acc, hi = 0.0, n
    for k in range(min(n, mode + reach), mode - 1, -1):
        pk = pmf(k)
        if acc + pk > alpha / 2:
            hi = k
            break
        acc += pk
    return (lo, hi)


# --------------------------------------------------------------------------
# Multi-flow metrics


def rate_series(ser, step_ns, avg_ns, start_ns, end_ns):
    """[(t, mean rate in bits/s over (t - avg, t])] at t = start + avg, + step, ... <= end,
    from a cumulative byte counter series."""
    out = []
    t = start_ns + avg_ns
    while t <= end_ns:
        d = delta(ser, t - avg_ns, t)
        out.append((t, None if d is None else d * 8 * NS / avg_ns))
        t += step_ns
    return out


def convergence_time(flow_series, t_join_ns, end_ns, capacity_bps, hold_ns=5 * NS,
                     step_ns=100_000_000, avg_ns=1 * NS, tol=0.20):
    """Seconds from t_join to the first time t after which every flow's 1 s
    mean goodput (sliding, 100 ms step) stays within ±tol of C/n for hold_ns;
    None when that never happens before end_ns (\"not converged\")."""
    n = len(flow_series)
    fair = capacity_bps / n
    rates = [rate_series(s, step_ns, avg_ns, t_join_ns, end_ns) for s in flow_series]
    if not rates or not rates[0]:
        return None
    times = [t for t, _ in rates[0]]
    ok = []
    for i in range(len(times)):
        good = True
        for r in rates:
            v = r[i][1]
            if v is None or abs(v - fair) > tol * fair:
                good = False
                break
        ok.append(good)
    need = hold_ns // step_ns  # number of steps after t that must hold too
    for i in range(len(times)):
        if i + need >= len(times):
            break
        if all(ok[i:i + need + 1]):
            return (times[i] - t_join_ns) / NS
    return None


# --------------------------------------------------------------------------
# One run


def read_text(p):
    try:
        return Path(p).read_text()
    except FileNotFoundError:
        return None


# Local drops inside the stack (§5.2: pool or transmit-queue problems
# invalidate): StackStats counters of datagrams the stack dropped itself.
STACK_LOCAL_DROPS = ("IpOutDiscards", "TcpExtTCPRcvQDrop", "TcpExtTCPOFODrop")
# Capture cross-check (§5.9): a sender's (receiver's) window count against the
# capture next to it, flagged when they differ by more than
# max(absolute, relative * count). Both sides are 10 ms series interpolated at
# the window bounds.
CAPTURE_SEGS_TOL = (20, 0.002)
CAPTURE_RETRANS_TOL = (5, 0.10)


def counts_agree(a, b, tol):
    return abs(a - b) <= max(tol[0], tol[1] * max(abs(a), abs(b)))


def run_window(meta, rcv, snd):
    """(t0, lo, hi, sender start) of a run (§5.6, DESIGN §14.3): t0 = the
    receiver's start line (its accept), lo = t0 + 5 s, hi = t0 + S but not
    later than the sender's start line + S, where its writes stop. All delay
    is on the data path, so the sender's start (its connect returning) is one
    RTT before t0 and t0 + S alone would put an RTT after the last write into
    the window. None without a receiver start line."""
    start = find_event(rcv, "start")
    if start is None:
        return None
    S = float(meta["duration_s"])
    t0 = start["t"]
    lo, hi = window(t0, S)
    s = find_event(snd, "start")
    snd_start = s["t"] if s else None
    if snd_start is not None:
        hi = min(hi, snd_start + int(S * NS))
    return t0, lo, hi, snd_start


def summarize_run(rundir):
    """summary.json of a run directory (§5.13): every §5.9 metric that the run
    has inputs for, the validity flags and the reasons."""
    rd = Path(rundir)
    meta = json.loads((rd / "meta.json").read_text())
    out = {"run": meta.get("run", rd.name), "valid": True, "invalid": [], "flags": []}

    def invalid(why):
        out["valid"] = False
        out["invalid"].append(why)

    lost_files = [(n, who) for n, who in (("rcv.jsonl", "receiver"), ("snd.jsonl", "sender"))
                  if not (rd / n).exists()]
    for _, who in lost_files:
        invalid(f"no {who} JSONL")
    if lost_files:
        return out
    rcv = read_jsonl(rd / "rcv.jsonl")
    snd = read_jsonl(rd / "snd.jsonl")
    w = run_window(meta, rcv, snd)
    if w is None:
        invalid("no receiver start line")
        return out
    t0, lo, hi, snd_start = w
    out["t0_ns"] = t0
    out["sender_start_ns"] = snd_start
    out["window_end_ns"] = hi
    out["window_s"] = (hi - lo) / NS
    rbytes = series(rcv, "bytes_received")
    d = delta(rbytes, lo, hi)
    if d is None:
        invalid("receiver samples do not cover the window")
        out["goodput_bps"] = None
    else:
        out["goodput_bps"] = d * 8 * NS / (hi - lo)
    rsum = find_event(rcv, "summary")
    ssum = find_event(snd, "summary")
    if not rsum or not rsum.get("ok"):
        invalid("receiver not ok")
    if not ssum or not ssum.get("ok"):
        invalid("sender not ok")
    if rsum and ssum and rsum.get("sha256") != ssum.get("sha256"):
        invalid("sha256 differs")
    # Sender counters over the window.
    dsegs = delta(series(snd, "data_segs_out"), lo, hi)
    dret = delta(series(snd, "total_retrans"), lo, hi)
    ddsack = delta(series(snd, "dsack_dups"), lo, hi)
    if dsegs is None or dret is None:
        invalid("sender samples do not cover the window")
    out["data_segs_out"] = dsegs
    out["retrans_segs"] = dret
    out["retrans_pct"] = (100.0 * dret / dsegs) if dsegs and dret is not None else None
    out["spurious_retrans"] = ddsack
    win_us = (hi - lo) / 1000
    for k, name in (("sndbuf_limited_us", "sndbuf_limited_frac"), ("rwnd_limited_us", "rwnd_limited_frac")):
        v = delta(series(snd, k), lo, hi)
        out[name] = None if v is None else v / win_us
        if v is not None and v / win_us >= LIMITED_FLAG_FRACTION:
            out["flags"].append(name)
    if ssum:
        for k in ("lateness_p50_ns", "lateness_p99_ns", "lateness_max_ns", "total_retrans"):
            if k in ssum:
                out["sender_" + k] = ssum[k]
    clock = clock_of(snd) or clock_of(rcv)
    cap_t = read_text(rd / "capture.json")
    cap = json.loads(cap_t) if cap_t else None
    # Ping: from the r1-in capture (ns timestamps) when it has the pings, else
    # from ping.txt (whole milliseconds at 100 ms RTT).
    cp = ((cap or {}).get("r1-in") or {}).get("pings")
    pings = None
    if cp:
        pings = [Ping(seq, t, None if r is None else r / 1e6) for seq, t, r in cp]
        out["ping_source"] = "capture r1-in"
    else:
        ptxt = read_text(rd / "ping.txt")
        if ptxt is not None:
            pings = parse_ping(ptxt)
            out["ping_source"] = "ping.txt"
    if pings is not None and clock is not None:
        out.update(ping_metrics(pings, clock, t0, lo, hi))
    # Records.
    roles = meta.get("containers", {})
    pre_t, post_t = read_text(rd / "pre" / "record.txt"), read_text(rd / "post" / "record.txt")
    if pre_t and post_t and roles:
        pre = record_counters(parse_record(pre_t), roles.values())
        post = record_counters(parse_record(post_t), roles.values())
        cpus = cpu_list(meta.get("slot_cpus", ""))
        bad, squeeze = local_drops(pre, post, roles, cpus)
        out["local_drops"] = bad
        out["time_squeeze"] = squeeze
        if bad:
            invalid("local drops")
        if squeeze:
            out["flags"].append("time_squeeze")
        out["cpu"] = {str(k): v for k, v in cpu_deltas(pre, post, cpus).items()}
        out["softirqs"] = softirq_deltas(pre, post, cpus)
        fc = foreign_cpu(pre, post, cpus, list(roles.values()))
        out["foreign_cpu"] = fc
        out["foreign_cpu_frac"] = None if fc is None else fc["lower_frac"]
        if fc is not None and fc["lower_frac"] >= FOREIGN_CPU_FLAG_FRACTION:
            out["flags"].append("foreign_cpu")
        if meta.get("impl") != "utcp":
            out["sender_counters"] = nstat_deltas(pre, post, roles["snd"])
        ifs = meta.get("ifaces", {})
        if ifs:
            out["netem"] = qdisc_delta(pre, post, roles["r1"], ifs["r1_b"])
            out["tbf"] = qdisc_delta(pre, post, roles["r2"], ifs["r2_c"])
            # The ACK path's interfaces are noqueue (m2_testbed.sh checks it);
            # a qdisc there that dropped would invalidate the run. Their link
            # drops are in local_drops.
            ack = {}
            for role, key in (("r2", "r2_b"), ("r1", "r1_a")):
                ack[key] = qdisc_delta(pre, post, roles[role], ifs[key])
            out["ack_path"] = ack
            if sum((q or {}).get("dropped", 0) for q in ack.values()):
                invalid("ACK-path qdisc drops")
    # tbf sampler.
    ttxt = read_text(rd / "tbf.txt")
    if ttxt is not None and clock is not None:
        samples = parse_tbf_samples(ttxt)
        q = int(meta.get("queue_bytes", 0))
        lo_rt = lo - clock.monotonic_ns + clock.realtime_ns
        hi_rt = hi - clock.monotonic_ns + clock.realtime_ns
        bw = meta.get("bw_mbit", meta.get("bw"))
        rate = float(bw) * 1e6 if bw else None
        out["queue"] = queue_check(samples, q, rate, int(meta.get("burst_bytes", 0)), lo_rt, hi_rt) if q else None
    # Captures (capture.json, made by `analyze.py captures`).
    if cap:
        out["capture"] = {k: ({kk: vv for kk, vv in v.items() if kk not in ("bins", "pings")}
                              if isinstance(v, dict) else v) for k, v in cap.items()}
        for name, v in cap.items():
            if isinstance(v, dict) and v.get("kernel_dropped"):
                out["flags"].append(f"capture_drops:{name}")
            if isinstance(v, dict) and v.get("received_by_filter") not in (None, v.get("captured")):
                out["flags"].append(f"capture_incomplete:{name}")
        r1 = cap.get("r1-in") or {}
        if r1.get("data_segs"):
            out["retrans_pct_capture_run"] = 100.0 * r1["retrans_segs"] / r1["data_segs"]
        # §5.9 cross-check over the same window: the r1-in capture against the
        # sender's counters, r2-out against the receiver's data_segs_in. A
        # difference shows a drop where no counter looks (host veth, bridge)
        # or a counter that does not count what the capture sees.
        if clock is not None:
            lo_rt = lo - clock.monotonic_ns + clock.realtime_ns
            hi_rt = hi - clock.monotonic_ns + clock.realtime_ns
            cw = {}
            for name, key, col in (("r1-in", "data", "r1in_data_segs"), ("r1-in", "retrans", "r1in_retrans_segs"),
                                   ("r2-out", "data", "r2out_data_segs")):
                cw[col] = delta(counts_series((cap.get(name) or {}).get("bins"), key), lo_rt, hi_rt)
            cw["rcv_data_segs_in"] = delta(series(rcv, "data_segs_in"), lo, hi)
            out["capture_window"] = cw
            if cw["r1in_data_segs"]:
                out["retrans_pct_capture"] = 100.0 * (cw["r1in_retrans_segs"] or 0) / cw["r1in_data_segs"]
            for a, b, tol, what in ((cw["r1in_data_segs"], dsegs, CAPTURE_SEGS_TOL, "data_segs_out"),
                                    (cw["r1in_retrans_segs"], dret, CAPTURE_RETRANS_TOL, "total_retrans"),
                                    (cw["r2out_data_segs"], cw["rcv_data_segs_in"], CAPTURE_SEGS_TOL,
                                     "data_segs_in")):
                if a is not None and b is not None and not counts_agree(a, b, tol):
                    out["flags"].append(f"capture_mismatch:{what}")
    # Stack counters (--stats): device problems and datagrams the stack dropped
    # itself invalidate (§5.2); transmit queue or pool blocking
    # (loop_pending_calls, the iterations in which a blocked connection
    # resumed) is reported and flagged (DESIGN §14.6).
    st = read_text(rd / "stats.json")
    if st:
        s = json.loads(st.strip().splitlines()[-1])
        devbad = {k: s[k] for k in ("dev_tx_errors", "dev_rx_errors") if s.get(k)}
        if s.get("dev_device_failed"):
            devbad["dev_device_failed"] = 1
        out["stack_device"] = devbad
        if devbad:
            invalid("stack device errors")
        sdrops = {k: s[k] for k in STACK_LOCAL_DROPS if s.get(k)}
        out["stack_local_drops"] = sdrops
        if sdrops:
            invalid("stack local drops")
        out["stack_blocked_resumes"] = s.get("loop_pending_calls")
        if s.get("loop_pending_calls"):
            out["flags"].append("stack_blocked")
        out["stack_tx_batch_max"] = s.get("dev_tx_batch_max")
        out["trace_events"] = s.get("trace_events")
        out["sender_counters"] = {n: s.get(n, 0) for n in SENDER_COUNTERS}
        out["stack_lateness_hist"] = {k[len("loop_lateness_bucket_"):]: v for k, v in s.items()
                                      if k.startswith("loop_lateness_bucket_")}
        if "loop_lateness_max_ns" in s:
            out["stack_lateness_max_ns"] = s["loop_lateness_max_ns"]
    return out


def captures_of_run(rundir, meta=None):
    """capture.json: per capture the data segments toward the receiver and the
    retransmissions seen, their 10 ms bins (the window cross-check), tcpdump's
    own counts (from <name>.tcpdump.txt), and for r1-in the sender's pings to
    the receiver paired with their replies ([seq, request CLOCK_REALTIME ns,
    rtt ns or null])."""
    rd = Path(rundir)
    meta = meta or json.loads((rd / "meta.json").read_text())
    rcv_ip = meta["rcv_ip"]
    out = {}
    for name in ("r1-in", "r1-out", "r2-out"):
        p = rd / f"{name}.pcap"
        if not p.exists():
            continue
        c = capture_summary(p, rcv_ip, bin_ns=CAPTURE_BIN_NS)
        if name == "r1-in" and meta.get("snd_ip"):
            c["pings"] = [[x.seq, x.send_rt_ns, None if x.rtt_ms is None else round(x.rtt_ms * 1e6)]
                          for x in icmp_echoes(p, meta["snd_ip"], rcv_ip)]
        c["bytes"] = p.stat().st_size
        log = read_text(rd / f"{name}.tcpdump.txt") or ""
        m = re.search(r"(\d+) packets? dropped by kernel", log)
        c["kernel_dropped"] = int(m.group(1)) if m else None
        m = re.search(r"(\d+) packets? captured", log)
        c["captured"] = int(m.group(1)) if m else None
        m = re.search(r"(\d+) packets? received by filter", log)
        c["received_by_filter"] = int(m.group(1)) if m else None
        out[name] = c
    return out


# --------------------------------------------------------------------------
# Cells: run counting and the gap rule


METRICS = ("goodput_bps", "retrans_pct", "qdelay_p50_ms", "qdelay_p99_ms")


def group_of(meta):
    """A run's group (M2 design §5.6, DESIGN §14.7): the runs of one (cell,
    algorithm, repetition) that ran back to back in one slot with one netem
    seed, and each rerun of them as a whole. (plan group, rerun number); runs
    without a plan group (calibration, hand-made) use their repetition."""
    g = meta.get("group")
    return (g if g is not None else f"rep{meta.get('rep')}", int(meta.get("rerun", 0)))


def select_runs(runs):
    """Run counting (RESULTS.md "Which runs count") for the runs of one (cell,
    algorithm). runs: dicts with impl, order, valid, run and group (group_of).
    A group is valid when it holds a run of every
    implementation of the cell and all its runs are valid; the statistics use
    the runs of the first RUNS_PER_SIDE valid groups in run order (order, then
    rerun number), so the counted stack and Linux runs are the same pairs.
    The cell is "invalid (rerun cap)" when more than RERUN_CAP groups were
    invalid (each is rerun as a whole), "incomplete" with fewer than
    RUNS_PER_SIDE valid groups. Returns (counted {impl: [runs]}, status)."""
    impls = sorted({r["impl"] for r in runs})
    groups = {}
    for r in runs:
        groups.setdefault(r["group"], []).append(r)

    def key(g):
        rs = groups[g]
        return (min(r["order"] for r in rs), g[1] if isinstance(g[1], int) else 0, min(r["run"] for r in rs))

    counted = {impl: [] for impl in impls}
    n_valid = n_invalid = 0
    for g in sorted(groups, key=key):
        rs = groups[g]
        ok = sorted({r["impl"] for r in rs}) == impls and all(r["valid"] for r in rs)
        if not ok:
            n_invalid += 1
            continue
        if n_valid < RUNS_PER_SIDE:
            for r in sorted(rs, key=lambda r: (r["order"], r["run"])):
                counted[r["impl"]].append(r)
        n_valid += 1
    status = "ok"
    if n_invalid > RERUN_CAP:
        status = "invalid (rerun cap)"
    elif n_valid < RUNS_PER_SIDE:
        status = "incomplete"
    return counted, status


def stats(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return {"median": median(xs), "min": min(xs), "max": max(xs), "n": len(xs)}


def gap_verdict(metric, stack, linux, loss_pct):
    """Gap rule of §5.10 between the stack's and Linux's 5-run statistics; "n/a"
    when a side has fewer than RUNS_PER_SIDE values of the metric (a counted
    run without it, e.g. no ping replies in the window)."""
    if stack is None or linux is None or min(stack.get("n", 0), linux.get("n", 0)) < RUNS_PER_SIDE:
        return "n/a"
    overlap = ranges_overlap(stack["min"], stack["max"], linux["min"], linux["max"])
    diff = stack["median"] - linux["median"]
    if metric == "retrans_pct":
        thr = RETRANS_THRESHOLD_PP.get(float(loss_pct))
        if thr is None:
            raise ValueError(f"no retransmission threshold for loss {loss_pct} %")
        return "gap" if diff > thr and not overlap else "no gap"
    if abs(diff) > GAP_REL * abs(linux["median"]) and not overlap:
        if metric.startswith("qdelay") and abs(diff) < DELAY_RESOLUTION_MS:
            return "gap (below resolution)"
        return "gap"
    return "no gap"


# --------------------------------------------------------------------------
# Tables


RUN_COLUMNS = ("campaign", "run", "cell", "bw_mbit", "rtt_ms", "loss_pct", "queue_bdp", "impl", "algo",
               "profile", "cc", "rep", "group", "rerun", "order", "slot", "timing", "commit", "reuse_key",
               "valid", "invalid", "flags",
               "goodput_bps", "retrans_pct", "spurious_retrans", "qdelay_p50_ms", "qdelay_p99_ms",
               "ping_lost", "sndbuf_limited_frac", "rwnd_limited_frac", "sender_lateness_p99_ns",
               "sender_lateness_max_ns", "backlog_max", "netem_dropped", "tbf_dropped", "foreign_cpu_frac",
               "retrans_pct_capture")

CELL_COLUMNS = ("cell", "bw_mbit", "rtt_ms", "loss_pct", "queue_bdp", "algo", "cc", "impl", "transient", "status",
                "n_counted", "n_invalid", "commits", "reuse_keys") + tuple(
    f"{m}_{s}" for m in METRICS for s in ("median", "min", "max", "n")) + tuple(f"gap_{m}" for m in METRICS)


def algo_of(meta):
    """The algorithm label of a run (matrix.algo_label; older runs: cc)."""
    return meta.get("algo") or meta.get("cc")


def fmt(v, kind="g"):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if kind == "int":
            return str(int(round(v)))
        return f"{v:.6g}"
    if isinstance(v, (list, tuple)):
        return ";".join(str(x) for x in v)
    return str(v)


def run_row(meta, summ):
    q = summ.get("queue") or {}
    netem = summ.get("netem") or {}
    tbf = summ.get("tbf") or {}
    row = {
        "campaign": meta.get("campaign"), "run": meta.get("run"), "cell": meta.get("cell"),
        "bw_mbit": meta.get("bw_mbit"), "rtt_ms": meta.get("rtt_ms"), "loss_pct": meta.get("loss_pct"),
        "queue_bdp": meta.get("queue_bdp"), "impl": meta.get("impl"), "algo": algo_of(meta),
        "profile": meta.get("profile"), "cc": meta.get("cc"), "rep": meta.get("rep"),
        "group": meta.get("group"), "rerun": meta.get("rerun", 0), "order": meta.get("order"),
        "slot": meta.get("slot"), "timing": meta.get("timing"), "commit": meta.get("commit"),
        "reuse_key": (meta.get("reuse_key") or "")[:12], "valid": summ.get("valid"),
        "invalid": summ.get("invalid"), "flags": summ.get("flags"),
        "backlog_max": q.get("backlog_max"), "netem_dropped": netem.get("dropped"),
        "tbf_dropped": tbf.get("dropped"),
    }
    for k in ("goodput_bps", "retrans_pct", "spurious_retrans", "qdelay_p50_ms", "qdelay_p99_ms",
              "ping_lost", "sndbuf_limited_frac", "rwnd_limited_frac", "sender_lateness_p99_ns",
              "sender_lateness_max_ns", "foreign_cpu_frac", "retrans_pct_capture"):
        row[k] = summ.get(k)
    return row


def write_csv(path, columns, rows):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(columns)
    for r in rows:
        w.writerow([fmt(r.get(c), "int" if c == "goodput_bps" else "g") for c in columns])
    Path(path).write_text(buf.getvalue())


def campaign_runs(campdir):
    """[(meta, summary)] of every run directory under campdir with a meta.json,
    the summary recomputed from the inputs."""
    out = []
    for meta_p in sorted(Path(campdir).glob("*/meta.json")):
        meta = json.loads(meta_p.read_text())
        meta.setdefault("run", meta_p.parent.name)
        out.append((meta, summarize_run(meta_p.parent)))
    return out


def cell_rows(pairs):
    rows = []
    groups = {}
    for meta, summ in pairs:
        if meta.get("impl") not in ("utcp", "linux"):
            continue
        groups.setdefault((meta["cell"], algo_of(meta)), []).append((meta, summ))
    for (cell, algo) in sorted(groups):
        members = groups[(cell, algo)]
        runs = [{"impl": m["impl"], "order": m.get("order", 0), "run": m["run"], "valid": s["valid"],
                 "group": group_of(m), "summary": s, "meta": m} for m, s in members]
        counted, status = select_runs(runs)
        # §5.13: the counted runs of a cell must share one reuse key.
        keys = sorted({r["meta"].get("reuse_key") or "" for rs in counted.values() for r in rs})
        if status == "ok" and len(keys) > 1:
            status = "mixed reuse keys"
        st = {impl: {m: stats([r["summary"].get(m) for r in rs]) for m in METRICS}
              for impl, rs in counted.items()}
        m0 = members[0][0]
        verdicts = {}
        for m in METRICS:
            if status != "ok" or "utcp" not in st or "linux" not in st:
                verdicts[m] = "n/a"
            else:
                verdicts[m] = gap_verdict(m, st["utcp"][m], st["linux"][m], m0["loss_pct"])
        for impl in sorted(counted):
            row = {"cell": cell, "bw_mbit": m0.get("bw_mbit"), "rtt_ms": m0.get("rtt_ms"),
                   "loss_pct": m0.get("loss_pct"), "queue_bdp": m0.get("queue_bdp"), "algo": algo,
                   "cc": ";".join(sorted({str(m.get("cc")) for m, _ in members if m["impl"] == impl})),
                   "impl": impl, "status": status, "n_counted": len(counted[impl]),
                   "transient": transient(m0.get("bw_mbit"), m0.get("rtt_ms"), m0.get("loss_pct"),
                                          m0.get("queue_bdp"), m0.get("cc")),
                   "n_invalid": sum(1 for r in runs if r["impl"] == impl and not r["valid"]),
                   "commits": sorted({r["meta"].get("commit", "") for r in counted[impl]}),
                   "reuse_keys": [k[:12] for k in keys]}
            for m in METRICS:
                s = st[impl][m]
                for k in ("median", "min", "max", "n"):
                    row[f"{m}_{k}"] = None if s is None else s[k]
                if s is None:
                    row[f"{m}_n"] = 0
                row[f"gap_{m}"] = verdicts[m]
            rows.append(row)
    return rows


def make_tables(campdir, outdir):
    pairs = campaign_runs(campdir)
    rows = [run_row(m, s) for m, s in pairs]
    rows.sort(key=lambda r: (str(r["cell"]), str(r["algo"]), str(r["impl"]), r.get("order") or 0,
                             r.get("rerun") or 0, str(r["run"])))
    Path(outdir).mkdir(parents=True, exist_ok=True)
    write_csv(Path(outdir) / "runs.csv", RUN_COLUMNS, rows)
    write_csv(Path(outdir) / "cells.csv", CELL_COLUMNS, cell_rows(pairs))


# --------------------------------------------------------------------------
# Analysis archive (§5.13): every analysis input of a campaign, no pcaps.

ARCHIVE_FILES = ("meta.json", "snd.jsonl", "rcv.jsonl", "trace.jsonl", "ping.txt", "tbf.txt",
                 "capture.json", "stats.json", "summary.json", "pre/record.txt", "post/record.txt")


def archive(campdir, out_file):
    camp = Path(campdir)
    files = []
    for meta_p in sorted(camp.glob("*/meta.json")):
        run = meta_p.parent
        for name in ARCHIVE_FILES:
            p = run / name
            if p.exists():
                files.append(p)
    manifest = "".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(camp).as_posix()}\n" for p in files)
    with tarfile.open(out_file, "w:gz") as tar:
        for p in files:
            ti = tar.gettarinfo(p, arcname=f"{camp.name}/{p.relative_to(camp).as_posix()}")
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.mtime = 0
            with open(p, "rb") as f:
                tar.addfile(ti, f)
        data = manifest.encode()
        ti = tarfile.TarInfo(f"{camp.name}/MANIFEST.sha256")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))
    return len(files)


def tables_from_archive(archive_file, outdir):
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(archive_file, "r:gz") as tar:
            tar.extractall(tmp, filter="data")
        roots = [p for p in Path(tmp).iterdir() if p.is_dir()]
        if len(roots) != 1:
            raise ValueError("archive must hold one campaign directory")
        root = roots[0]
        for line in (root / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
                raise ValueError(f"sha256 mismatch for {name}")
        make_tables(root, outdir)


# --------------------------------------------------------------------------


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="analyze.py", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run", help="summary.json of one run")
    p.add_argument("rundir")
    p = sub.add_parser("captures", help="capture.json of one run")
    p.add_argument("rundir")
    p = sub.add_parser("tables", help="runs.csv and cells.csv")
    p.add_argument("outdir")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--campaign")
    g.add_argument("--archive")
    p = sub.add_parser("archive", help="the analysis archive of a campaign")
    p.add_argument("campaign")
    p.add_argument("file")
    p = sub.add_parser("pings", help="ping statistics from a capture")
    p.add_argument("pcap")
    p.add_argument("src")
    p.add_argument("dst")
    p.add_argument("count", type=int, nargs="?")
    a = ap.parse_args(argv[1:])
    if a.cmd == "run":
        s = summarize_run(a.rundir)
        Path(a.rundir, "summary.json").write_text(json.dumps(s, indent=1, sort_keys=True) + "\n")
        print(json.dumps(s, sort_keys=True))
    elif a.cmd == "captures":
        c = captures_of_run(a.rundir)
        Path(a.rundir, "capture.json").write_text(json.dumps(c, indent=1, sort_keys=True) + "\n")
        print(json.dumps(c, sort_keys=True))
    elif a.cmd == "tables":
        if a.archive:
            tables_from_archive(a.archive, a.outdir)
        else:
            make_tables(a.campaign, a.outdir)
    elif a.cmd == "archive":
        print(f"{archive(a.campaign, a.file)} files in {a.file}")
    elif a.cmd == "pings":
        print(json.dumps(ping_stats(icmp_echoes(a.pcap, a.src, a.dst), a.count), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
