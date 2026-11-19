#!/usr/bin/env python3
"""Unit tests of tools/m2/analyze.py on synthetic inputs with known answers
(M2-TASKS m2d-testbed test 6), and of the pure parts of matrix.py (run
plans, the reuse key, the parallel-mode comparison) and plot.py (the run
selection) and dropcheck.py (the segments a scripted drop latches). Run:
python3 -I tools/m2/test_analyze.py"""

from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import shlex
import subprocess
import json
import math
import struct
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze as A  # noqa: E402
import dropcheck as D  # noqa: E402
import matrix as M  # noqa: E402
import plot as P  # noqa: E402

NS = A.NS
T0 = 1_000 * NS                # receiver accept time (CLOCK_MONOTONIC)
CLOCK = A.Clock(monotonic_ns=990 * NS, realtime_ns=1_800_000_000 * NS)


def rt(mono_ns):
    """CLOCK_REALTIME of a monotonic time under CLOCK."""
    return mono_ns - CLOCK.monotonic_ns + CLOCK.realtime_ns


def rt_str(ns):
    return f"{ns // NS}.{(ns % NS) // 1000:06d}"


def counter_samples(t_start, t_end, fn, step=10_000_000, offset=3_000_000):
    """Sample times t_start + offset + k*step up to t_end; fn(t) the counter."""
    out, t = [], t_start + offset
    while t <= t_end:
        out.append((t, fn(t)))
        t += step
    return out


def jsonl(role, samples_by_key, extra=()):
    lines = [{"ev": "clock", "monotonic_ns": CLOCK.monotonic_ns, "realtime_ns": CLOCK.realtime_ns}]
    lines.append({"t": T0 if role == "receiver" else T0 - 20_000_000, "ev": "start", "role": role})
    keys = list(samples_by_key)
    for i, (t, _) in enumerate(samples_by_key[keys[0]]):
        d = {"t": t, "ev": "sample", "role": role}
        for k in keys:
            d[k] = samples_by_key[k][i][1]
        lines.append(d)
    lines.extend(extra)
    return "".join(json.dumps(x) + "\n" for x in lines)


S = 30  # run length, seconds
RATE = 1_000_000  # bytes/s in the window (8 Mbit/s)


KINK1, KINK2 = 4.5, S + 0.5  # rate changes, away from the window bounds (interpolation is exact)


def piecewise(before, inside, after):
    """A counter growing at `before`/s until t0 + 4.5 s, `inside`/s until
    t0 + S + 0.5 s, then `after`/s: the warm-up and the drain differ from the
    window, so a window error shows."""
    def f(t):
        x = (t - T0) / NS
        if x <= KINK1:
            return before * x
        if x <= KINK2:
            return before * KINK1 + inside * (x - KINK1)
        return before * KINK1 + inside * (KINK2 - KINK1) + after * (x - KINK2)
    return f


def snd_counter(per_s_before, per_s_in, per_s_after):
    return piecewise(per_s_before, per_s_in, per_s_after)


def ping_text():
    """3 s of idle pings (rtt 20.0, 20.2, 20.4, ...), warm-up pings with a large
    delay (excluded), 100 in-window pings with queueing delay 1..100 ms over
    base, one lost in-window ping, and drain pings with 500 ms (excluded)."""
    lines, seq = [], 1
    idle = [20.0, 20.2, 20.4, 20.6, 20.8]  # median 20.4
    t = T0 - 3 * NS
    for r in idle:
        lines.append((t, seq, r))
        seq += 1
        t += 500_000_000
    for i in range(10):  # warm-up, sent in [t0 + 1 s, t0 + 2 s)
        lines.append((T0 + NS + i * 100_000_000, seq, 300.0))
        seq += 1
    for i in range(100):  # in the window, sent at t0 + 6 s + i*100 ms
        lines.append((T0 + 6 * NS + i * 100_000_000, seq, 20.4 + (i + 1)))
        seq += 1
    lost_seq = seq
    lost_send = T0 + 20 * NS
    seq += 1
    for i in range(5):  # drain, sent after t0 + S
        lines.append((T0 + (S + 1) * NS + i * 50_000_000, seq, 500.0))
        seq += 1
    out = []
    for send, sq, r in lines:
        recv = rt(send) + int(r * 1e6)
        out.append(f"[{rt_str(recv)}] 64 bytes from 198.19.12.5: icmp_seq={sq} ttl=62 time={r} ms")
    out.append(f"[{rt_str(rt(lost_send) + 50_000_000)}] no answer yet for icmp_seq={lost_seq}")
    return "\n".join(out) + "\n"


def record(label, extra_drops=0, squeeze=0, tbf_dropped=0, utcp_drop=0, link_drops=None, utcp_qdrop=0,
           softnet_drop=None, cgroup=None, stat=None, ack_qdrop=0):
    """record.sh output of slot "s". link_drops {(container, dev): (rx, tx)};
    softnet_drop {cpu: n}; cgroup {container: usage_usec}; stat {cpu: (user,
    system, idle, irq, softirq)} (default 100, 50, 1000, 5, 20); ack_qdrop:
    drops of r2's eth0 (the ACK path) qdisc."""
    link_drops = link_drops or {}
    softnet_drop = softnet_drop or {}
    stat = stat or {}

    def link(c, name, rxd=0, txd=0):
        rx, tx = link_drops.get((c, name), (0, 0))
        return [f"2: {name}@if1: <BROADCAST,UP> mtu 1500 qdisc noqueue state UP",
                "    veth gso_max_size 65536 gso_ipv4_max_size 65536",
                "    RX:  bytes packets errors dropped  missed   mcast",
                f"        1000      10      0       {rxd + rx}       0       0",
                "    TX:  bytes packets errors dropped carrier collsns",
                f"        1000      10      0       {txd + tx}       0       0"]
    lines = [f"# {label} slot 0 now"]
    lines += ["== s-snd ip -s -d link"] + link("s-snd", "eth0", txd=extra_drops) + [
        "3: utcp0: <POINTOPOINT,UP> mtu 1500 qdisc pfifo state UP",
        "    tun gso_ipv4_max_size 65536",
        "    RX:  bytes packets errors dropped  missed   mcast",
        f"        0       0      0       {utcp_drop}       0       0",
        "    TX:  bytes packets errors dropped carrier collsns",
        "        0       0      0       0       0       0"]
    lines += ["== s-snd tc -s -raw qdisc",
              "qdisc noqueue 0: dev eth0 root refcnt 2 ",
              " Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) ",
              " backlog 0b 0p requeues 0",
              "qdisc pfifo 1: dev utcp0 root refcnt 2 limit 10000p",
              f" Sent 0 bytes 0 pkt (dropped {utcp_qdrop}, overlimits 0 requeues 0) ",
              " backlog 0b 0p requeues 0"]
    for c, devs in (("s-r1", ("eth0", "eth1")), ("s-r2", ("eth0", "eth1")), ("s-rcv", ("eth0",))):
        lines.append(f"== {c} ip -s -d link")
        for d in devs:
            lines += link(c, d)
        lines.append(f"== {c} tc -s -raw qdisc")
        for d in devs:
            kind = "noqueue"
            sent = "Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)"
            if c == "s-r2" and d == "eth0" and ack_qdrop:
                kind = "pfifo"
                sent = f"Sent 100 bytes 1 pkt (dropped {ack_qdrop}, overlimits 0 requeues 0)"
            if c == "s-r1" and d == "eth1":
                kind = "netem"
                sent = "Sent 5000 bytes 50 pkt (dropped 3, overlimits 0 requeues 0)"
            if c == "s-r2" and d == "eth1":
                kind = "tbf"
                sent = f"Sent 4000 bytes 40 pkt (dropped {tbf_dropped}, overlimits 7 requeues 0)"
            lines += [f"qdisc {kind} 8001: dev {d} root refcnt 2 ", f" {sent} ", " backlog 0b 0p requeues 0"]
    lines.append("== host softnet_stat")
    for cpu in range(32):
        sq = squeeze if cpu == 8 else 0
        lines.append(f"{cpu} 00001000 {softnet_drop.get(cpu, 0):08x} {sq:08x} 0 0 0 0 0 0 0 0 0 {cpu:08x} 0 0")
    lines.append("== host /proc/stat")
    for cpu in range(32):
        user, system, idle, irq, softirq = stat.get(cpu, (100, 50, 1000, 5, 20))
        lines.append(f"cpu{cpu} {user} 0 {system} {idle} 0 {irq} {softirq} 0 0 0")
    if cgroup is not None:
        lines += ["== host clk_tck", "100", "== host cgroup cpu.stat"]
        lines += [f"{c} usage_usec {v}" for c, v in cgroup.items()]
    return "\n".join(lines) + "\n"


def make_run(root, name, meta_over=None, valid=True, goodput_scale=1.0, retrans_in=10.0, qshift=0.0):
    d = Path(root) / name
    (d / "pre").mkdir(parents=True)
    (d / "post").mkdir()
    rb = piecewise(400_000, RATE * goodput_scale, 10_000_000)
    end = T0 + (S + 1) * NS
    (d / "rcv.jsonl").write_text(jsonl("receiver", {"bytes_received": counter_samples(T0, end, rb)}, [
        {"ev": "summary", "role": "receiver", "ok": True, "sha256": "ab"}]))
    (d / "snd.jsonl").write_text(jsonl("sender", {
        "data_segs_out": counter_samples(T0, end, snd_counter(300, 1000, 50)),
        "total_retrans": counter_samples(T0, end, snd_counter(0, retrans_in, 100)),
        "dsack_dups": counter_samples(T0, end, snd_counter(0, 1, 0)),
        "sndbuf_limited_us": counter_samples(T0, end, snd_counter(0, 0, 0)),
        "rwnd_limited_us": counter_samples(T0, end, snd_counter(0, 0, 0)),
    }, [{"ev": "summary", "role": "sender", "ok": True, "sha256": "ab", "lateness_p99_ns": 1000,
         "lateness_max_ns": 5000}]))
    txt = ping_text()
    if qshift:
        txt = "\n".join(
            l.replace(f"time={l.split('time=')[1].split(' ')[0]} ms",
                      f"time={float(l.split('time=')[1].split(' ')[0]) + qshift:.1f} ms")
            if "time=" in l and "icmp_seq" in l and int(l.split("icmp_seq=")[1].split()[0]) > 15 else l
            for l in txt.splitlines()) + "\n"
    (d / "ping.txt").write_text(txt)
    (d / "pre" / "record.txt").write_text(record("pre"))
    (d / "post" / "record.txt").write_text(record("post", extra_drops=0 if valid else 2))
    meta = {"campaign": "t", "run": name, "duration_s": S, "cell": "10-20-0-2", "bw_mbit": 10, "rtt_ms": 20,
            "loss_pct": 0, "queue_bdp": 2, "impl": "linux", "profile": "", "cc": "cubic", "rep": 0,
            "order": 0, "slot": 0, "commit": "abc", "slot_cpus": "8-11",
            "containers": {"snd": "s-snd", "r1": "s-r1", "r2": "s-r2", "rcv": "s-rcv"},
            "ifaces": {"r1_a": "eth0", "r1_b": "eth1", "r2_b": "eth0", "r2_c": "eth1"},
            "queue_bytes": 50000, "rcv_ip": "198.19.12.5"}
    meta.update(meta_over or {})
    (d / "meta.json").write_text(json.dumps(meta))
    return d


class Basics(unittest.TestCase):
    def test_percentile_is_linear_between_ranks(self):
        self.assertEqual(A.percentile([1, 2, 3, 4], 0.5), 2.5)
        self.assertAlmostEqual(A.percentile(list(range(1, 101)), 0.99), 99.01)
        self.assertEqual(A.percentile([7], 0.99), 7)
        self.assertIsNone(A.percentile([], 0.5))

    def test_interp_and_delta_use_the_neighbours(self):
        ser = [(0, 0), (10, 100), (20, 100), (30, 400)]
        self.assertEqual(A.interp(ser, 5), 50)
        self.assertEqual(A.interp(ser, 25), 250)
        self.assertEqual(A.delta(ser, 5, 25), 200)
        self.assertIsNone(A.interp(ser, 31))
        self.assertIsNone(A.delta(ser, -1, 10))

    def test_jain(self):
        self.assertAlmostEqual(A.jain([10, 10, 10, 10]), 1.0)
        self.assertAlmostEqual(A.jain([10, 0]), 0.5)
        self.assertAlmostEqual(A.jain([3, 1]), 16 / 20)

    def test_transient_cells(self):
        self.assertTrue(A.transient(100, 100, 0, 2, "cubic"))
        self.assertTrue(A.transient(100, 100, 0, 0.5, "newreno"))
        self.assertFalse(A.transient(100, 100, 0, 2, "bbr"))
        self.assertFalse(A.transient(100, 100, 0.1, 2, "cubic"))
        self.assertFalse(A.transient(10, 100, 0, 2, "cubic"))

    def test_cpu_list(self):
        self.assertEqual(A.cpu_list("8,9"), [8, 9])
        self.assertEqual(A.cpu_list("8-11"), [8, 9, 10, 11])
        self.assertEqual(A.cpu_list("12,13,14-15"), [12, 13, 14, 15])

    def test_binomial_interval(self):
        lo, hi = A.binom_interval(100_000, 0.01, 0.01)
        # mean 1000, sd 31.5; the 99 % two-sided normal interval is 1000 ± 81.
        self.assertTrue(915 <= lo <= 921, lo)
        self.assertTrue(1079 <= hi <= 1085, hi)
        lo, hi = A.binom_interval(10, 0.5, 0.05)
        self.assertEqual((lo, hi), (2, 8))  # P(X<=1)=0.0107, P(X<=2)=0.0547


class Window(unittest.TestCase):
    def test_goodput_uses_the_interpolated_window_and_excludes_slow_start_and_drain(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_run(tmp, "r0")
            s = A.summarize_run(d)
            self.assertTrue(s["valid"], s["invalid"])
            # The sender started 20 ms before t0 (one RTT) and writes for S:
            # the window ends at its start + S, 20 ms before t0 + S.
            self.assertEqual(s["window_s"], 24.98)
            self.assertEqual(s["window_end_ns"], T0 - 20_000_000 + S * NS)
            # Samples are at t0 + 3 ms + k*10 ms, so both bounds are interpolated.
            self.assertAlmostEqual(s["goodput_bps"], RATE * 8, delta=1.0)

    def test_retransmission_rate_and_spurious_over_the_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = A.summarize_run(make_run(tmp, "r0"))
            # 1000 data segments/s and 10 retransmissions/s in the window; the
            # drain's 100/s and slow start's are outside it.
            self.assertAlmostEqual(s["data_segs_out"], 24_980, delta=0.01)
            self.assertAlmostEqual(s["retrans_segs"], 249.8, delta=0.01)
            self.assertAlmostEqual(s["retrans_pct"], 1.0, delta=0.0001)
            self.assertAlmostEqual(s["spurious_retrans"], 24.98, delta=0.01)

    def test_limited_time_fractions_and_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_run(tmp, "r0")
            lines = A.read_jsonl(d / "snd.jsonl")
            for x in lines:
                if x.get("ev") == "sample":
                    # sndbuf-limited 20 ms per second in the window (2 %), 1 ms/s rwnd (0.1 %).
                    sec = min(max((x["t"] - T0) / NS - 5, 0), S - 5 - 0.02)
                    x["sndbuf_limited_us"] = int(20_000 * sec)
                    x["rwnd_limited_us"] = int(1_000 * sec)
            (d / "snd.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines))
            s = A.summarize_run(d)
            self.assertAlmostEqual(s["sndbuf_limited_frac"], 0.02, places=4)
            self.assertAlmostEqual(s["rwnd_limited_frac"], 0.001, places=4)
            self.assertIn("sndbuf_limited_frac", s["flags"])
            self.assertNotIn("rwnd_limited_frac", s["flags"])
            self.assertTrue(s["valid"])  # a flag, not invalid

    def test_ping_percentiles_against_the_runs_idle_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = A.summarize_run(make_run(tmp, "r0"))
            self.assertEqual(s["ping_idle_n"], 5)
            self.assertAlmostEqual(s["ping_base_ms"], 20.4)
            # In-window delays are exactly 1..100 ms; warm-up (300 ms) and
            # drain (500 ms) pings are outside the window.
            self.assertEqual(s["ping_n"], 100)
            self.assertAlmostEqual(s["qdelay_p50_ms"], 50.5, places=6)
            self.assertAlmostEqual(s["qdelay_p99_ms"], 99.01, places=6)
            self.assertEqual(s["ping_lost"], 1)

    def test_ping_times_convert_with_the_clock_pair(self):
        # The same pings with a clock pair 1 h later on both clocks give the
        # same result; with only the realtime moved by +25 s the window holds
        # other pings.
        pings = A.parse_ping(ping_text())
        lo, hi = A.window(T0, S)
        a = A.ping_metrics(pings, CLOCK, T0, lo, hi)
        moved = A.Clock(CLOCK.monotonic_ns, CLOCK.realtime_ns + 25 * NS)
        b = A.ping_metrics(pings, moved, T0, lo, hi)
        self.assertEqual(a["ping_n"], 100)
        self.assertNotEqual(b["ping_n"], 100)

    def test_local_drops_invalidate_and_time_squeeze_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_run(tmp, "r0", valid=False)
            s = A.summarize_run(d)
            self.assertFalse(s["valid"])
            self.assertEqual(s["local_drops"], {"s-snd/eth0/tx_dropped": 2})
            d2 = make_run(tmp, "r1")
            (d2 / "post" / "record.txt").write_text(record("post", squeeze=3))
            s2 = A.summarize_run(d2)
            self.assertTrue(s2["valid"])
            self.assertIn("time_squeeze", s2["flags"])
            d3 = make_run(tmp, "r2")
            (d3 / "post" / "record.txt").write_text(record("post", utcp_drop=1))
            self.assertEqual(A.summarize_run(d3)["local_drops"], {"s-snd/utcp0/rx_dropped": 1})

    def test_netem_and_tbf_counters_from_the_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_run(tmp, "r0")
            (d / "post" / "record.txt").write_text(record("post", tbf_dropped=4))
            s = A.summarize_run(d)
            self.assertEqual(s["tbf"]["dropped"], 4)
            self.assertEqual(s["netem"]["dropped"], 0)  # same before and after


class Queue(unittest.TestCase):
    def test_tbf_sampler_and_drop_intervals(self):
        q = 12_500
        text = ""
        backlogs = [0, 6056, 12112, 12112, 10598, 12112, 4542]
        drops = [0, 0, 1, 2, 3, 3, 3]
        for i, (b, dr) in enumerate(zip(backlogs, drops)):
            text += f"@ 100.{i * 10:03d}000\nqdisc tbf 1: root refcnt 2 rate 10Mbit burst 3028b lat 1ms\n"
            text += f" Sent 1 bytes 1 pkt (dropped {dr}, overlimits 0 requeues 0)\n backlog {b}b {b // 1514}p requeues 0\n"
        s = A.parse_tbf_samples(text)
        self.assertEqual(len(s), 7)
        self.assertEqual(s[2], (100 * NS + 20_000_000, 12112, 1))
        r = A.queue_check(s, q)
        self.assertEqual(r["backlog_max"], 12112)
        self.assertTrue(r["reaches"])
        self.assertEqual(r["drop_intervals"], 3)
        # Without a rate the level is 0.9*Q = 11250: 1->2 (12112) and 2->3 are
        # fine, 3->4 has 12112 too.
        self.assertEqual(r["drop_intervals_low"], 0)
        # Samples 10 ms apart at 1 Mbit/s with B = 3028: the level is
        # 12500 - 1514 - 3028 - 1250 = 6708 B.
        lowered = list(s)
        lowered[2] = (s[2][0], 6056, 1)
        lowered[3] = (s[3][0], 6056, 2)
        lowered[4] = (s[4][0], 6000, 3)
        r = A.queue_check(lowered, q, rate_bps=1e6, burst_bytes=3028)
        self.assertAlmostEqual(r["min_level"], 6708)
        self.assertEqual((r["drop_intervals_low"], r["drop_intervals_below_frac"]), (3, 3))
        # At 10 Mbit/s the queue may drain 12 500 B in 10 ms: no level is left,
        # so none of these is low, while all are below 0.9*Q.
        r = A.queue_check(lowered, q, rate_bps=10e6, burst_bytes=3028)
        self.assertEqual((r["drop_intervals_low"], r["drop_intervals_below_frac"]), (0, 3))
        self.assertFalse(A.queue_check([x for x in lowered if x[1] < 11000], q)["reaches"])


def pcap_bytes(segs, nano=True):
    out = struct.pack("<IHHiIII", 0xA1B23C4D if nano else 0xA1B2C3D4, 2, 4, 0, 0, 128, 1)
    for i, (src, dst, seq, plen) in enumerate(segs):
        tcp = struct.pack(">HHIIBBHHH", 40000, 5201, seq, 0, 0x80, 0x10, 1000, 0, 0) + b"\0" * 12
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + plen, 0, 0, 64, 6, 0,
                         bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
        frame = b"\0" * 12 + b"\x08\x00" + ip + tcp + b"\0" * plen
        cap = frame[:128]
        out += struct.pack("<IIII", 1000 + i, 0, len(cap), len(frame)) + cap
    return out


class Captures(unittest.TestCase):
    def test_data_segments_and_retransmissions(self):
        segs = [("198.19.10.2", "198.19.12.5", 1000, 0),    # pure ACK: not data
                ("198.19.10.2", "198.19.12.5", 1001, 1448),
                ("198.19.10.2", "198.19.12.5", 2449, 1448),
                ("198.19.10.2", "198.19.12.5", 1001, 1448),  # retransmission
                ("198.19.12.5", "198.19.10.2", 1, 100),      # other direction
                ("198.19.10.2", "198.19.12.5", 0xFFFFFF00, 1448)]  # wraps: new data? no, below
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.pcap"
            p.write_bytes(pcap_bytes(segs[:5]))
            self.assertEqual(A.capture_summary(p, "198.19.12.5"), {"data_segs": 3, "retrans_segs": 1})
            p.write_bytes(pcap_bytes(segs[:5], nano=False))
            self.assertEqual(A.capture_summary(p, "198.19.12.5"), {"data_segs": 3, "retrans_segs": 1})

    def test_seq_comparison_wraps(self):
        self.assertTrue(A.seq_leq(0xFFFFFFF0, 5))
        self.assertFalse(A.seq_leq(5, 0xFFFFFFF0))
        self.assertTrue(A.seq_leq(7, 7))


def rates_series(rate_fn, t_start, t_end, step=10_000_000):
    """Cumulative bytes with rate_fn(t) bits/s, sampled every 10 ms."""
    out, b, t = [], 0.0, t_start
    while t <= t_end:
        out.append((t, b))
        b += rate_fn(t) / 8 * step / NS
        t += step
    return out


class Convergence(unittest.TestCase):
    C = 100e6

    def test_converging(self):
        join = T0 + 20 * NS
        # Flow 1 at 100 Mbit/s until the join, then both at 50 from join + 3 s.
        f1 = rates_series(lambda t: 95e6 if t < join + 3 * NS else 50e6, T0, T0 + 60 * NS)
        f2 = rates_series(lambda t: 10e6 if t < join + 3 * NS else 50e6, join, T0 + 60 * NS)
        c = A.convergence_time([f1, f2], join, T0 + 60 * NS, self.C)
        # With a fraction x of the last second at 50 Mbit/s, flow 1's mean is
        # 95 - 45x <= 60 for x >= 0.78 and flow 2's 10 + 40x >= 40 for x >= 0.75:
        # the first 100 ms point is join + 3.8 s (59 and 42).
        self.assertAlmostEqual(c, 3.8, places=6)

    def test_late_converging(self):
        join = T0 + 20 * NS
        f1 = rates_series(lambda t: 95e6 if t < join + 30 * NS else 50e6, T0, T0 + 60 * NS)
        f2 = rates_series(lambda t: 5e6 if t < join + 30 * NS else 50e6, join, T0 + 60 * NS)
        # Flow 2: 5 + 45x >= 40 for x >= 0.78, so join + 30.8 s (41 and 59);
        # it holds to join + 35.8 s, before the end at join + 40 s.
        self.assertAlmostEqual(A.convergence_time([f1, f2], join, T0 + 60 * NS, self.C), 30.8, places=6)

    def test_never_and_too_late_to_hold_5_s(self):
        join = T0 + 20 * NS
        f1 = rates_series(lambda t: 90e6, T0, T0 + 60 * NS)
        f2 = rates_series(lambda t: 10e6, join, T0 + 60 * NS)
        self.assertIsNone(A.convergence_time([f1, f2], join, T0 + 60 * NS, self.C))
        # Equal shares only for the last 3 s: not held for 5 s.
        f1 = rates_series(lambda t: 90e6 if t < T0 + 57 * NS else 50e6, T0, T0 + 60 * NS)
        f2 = rates_series(lambda t: 10e6 if t < T0 + 57 * NS else 50e6, join, T0 + 60 * NS)
        self.assertIsNone(A.convergence_time([f1, f2], join, T0 + 60 * NS, self.C))

    def test_the_hold_is_5_s(self):
        # Equal shares from end - 5.5 s: the 1 s means enter the band at
        # end - 4.7 s (x >= 0.78 as above), 4.7 s before the end, which is
        # not a 5 s hold. From end - 6 s they enter at end - 5.2 s: held.
        join, end = T0 + 20 * NS, T0 + 60 * NS
        for switch, want in ((end - 5.5 * NS, None), (end - 6 * NS, (end - 5.2 * NS - join) / NS)):
            f1 = rates_series(lambda t: 95e6 if t < switch else 50e6, T0, end)
            f2 = rates_series(lambda t: 10e6 if t < switch else 50e6, join, end)
            c = A.convergence_time([f1, f2], join, end, self.C)
            if want is None:
                self.assertIsNone(c)
            else:
                self.assertAlmostEqual(c, want, places=6)

    def test_a_dip_restarts_the_hold(self):
        join = T0 + 20 * NS
        def r1(t):
            return 50e6 if not (join + 4 * NS <= t < join + 4.5 * NS) else 20e6
        def r2(t):
            return 50e6 if not (join + 4 * NS <= t < join + 4.5 * NS) else 80e6
        f1 = rates_series(r1, T0, T0 + 60 * NS)
        f2 = rates_series(r2, join, T0 + 60 * NS)
        c = A.convergence_time([f1, f2], join, T0 + 60 * NS, self.C)
        # With a fraction x of the last second in the dip, flow 1's mean is
        # 50 - 30x, outside the band for x > 1/3: at the points join + 4.4 s
        # (x = 0.4) to join + 5.1 s (x = 0.4); 4.3 and 5.2 have x = 0.3. Every
        # start from join + 1 s (the first point) to 4.3 s meets the dip within
        # 5 s, so the answer is join + 5.2 s.
        self.assertAlmostEqual(c, 5.2, places=6)


def stat(med, lo, hi):
    return {"median": med, "min": lo, "max": hi, "n": 5}


class GapRule(unittest.TestCase):
    def test_goodput_needs_10_percent_and_disjoint_ranges(self):
        self.assertEqual(A.gap_verdict("goodput_bps", stat(80, 78, 82), stat(100, 95, 105), 0), "gap")
        # 20 % apart but the ranges overlap.
        self.assertEqual(A.gap_verdict("goodput_bps", stat(80, 70, 96), stat(100, 95, 105), 0), "no gap")
        # Disjoint but only 5 % apart.
        self.assertEqual(A.gap_verdict("goodput_bps", stat(95, 94, 95.5), stat(100, 99, 101), 0), "no gap")
        # The 10 % bound itself: 11 % apart with disjoint ranges is a gap,
        # 9 % apart is not.
        self.assertEqual(A.gap_verdict("goodput_bps", stat(89, 88.5, 89.5), stat(100, 99, 101), 0), "gap")
        self.assertEqual(A.gap_verdict("goodput_bps", stat(91, 90.5, 91.5), stat(100, 99, 101), 0), "no gap")
        # Better than Linux by more than 10 % is a gap too (the medians differ).
        self.assertEqual(A.gap_verdict("goodput_bps", stat(120, 118, 122), stat(100, 95, 105), 0), "gap")

    def test_delay_below_resolution(self):
        # 0.5 ms vs 0.8 ms p50: 37 % apart, disjoint, but < 1 ms absolute.
        self.assertEqual(A.gap_verdict("qdelay_p50_ms", stat(0.5, 0.45, 0.55), stat(0.8, 0.7, 0.9), 0),
                         "gap (below resolution)")
        self.assertEqual(A.gap_verdict("qdelay_p99_ms", stat(15, 14, 16), stat(10, 9, 11), 0), "gap")
        self.assertEqual(A.gap_verdict("qdelay_p99_ms", stat(10.5, 10.4, 10.6), stat(10, 9.8, 10.2), 0),
                         "no gap")

    def test_retransmission_thresholds_per_loss_rate(self):
        # +0.06 points at 0 % and 0.1 % loss: above 0.05.
        self.assertEqual(A.gap_verdict("retrans_pct", stat(0.16, 0.15, 0.17), stat(0.10, 0.09, 0.11), 0.1), "gap")
        self.assertEqual(A.gap_verdict("retrans_pct", stat(0.06, 0.06, 0.07), stat(0.0, 0.0, 0.0), 0), "gap")
        self.assertEqual(A.gap_verdict("retrans_pct", stat(0.04, 0.04, 0.05), stat(0.0, 0.0, 0.0), 0), "no gap")
        # +0.15 points at 1 %: below 0.2.
        self.assertEqual(A.gap_verdict("retrans_pct", stat(1.15, 1.12, 1.18), stat(1.0, 0.95, 1.05), 1), "no gap")
        self.assertEqual(A.gap_verdict("retrans_pct", stat(1.25, 1.22, 1.28), stat(1.0, 0.95, 1.05), 1), "gap")
        # Above the threshold but overlapping ranges.
        self.assertEqual(A.gap_verdict("retrans_pct", stat(1.25, 1.0, 1.3), stat(1.0, 0.95, 1.05), 1), "no gap")
        # Fewer retransmissions than Linux is never a retransmission gap.
        self.assertEqual(A.gap_verdict("retrans_pct", stat(0.5, 0.4, 0.6), stat(1.0, 0.95, 1.05), 1), "no gap")
        with self.assertRaises(ValueError):
            A.gap_verdict("retrans_pct", stat(1, 1, 1), stat(1, 1, 1), 0.5)


def run_rec(impl, order, valid, name=None, group=None, rerun=0):
    """A run of plan group `group` (default: its order); real names, which do
    not sort like the order: "...-r1-utcp-rerun1" sorts before "...-r2-utcp"."""
    g = order if group is None else group
    name = name or f"10-20-0-2-cubic-r{g}-{impl}" + (f"-rerun{rerun}" if rerun else "")
    return {"impl": impl, "order": order, "valid": valid, "run": name, "group": (g, rerun)}


def pair(g, order, utcp_ok=True, linux_ok=True, rerun=0):
    return [run_rec("utcp", order, utcp_ok, group=g, rerun=rerun),
            run_rec("linux", order + 1, linux_ok, group=g, rerun=rerun)]


class RunCounting(unittest.TestCase):
    def test_first_five_valid_groups_count_both_sides(self):
        # Group 1's stack run is invalid; the group is rerun as a whole right
        # after it (same order, rerun 1). The counted runs are the same five
        # pairs on both sides; group 5 is not counted.
        runs = pair(0, 0) + pair(1, 2, utcp_ok=False) + pair(1, 2, rerun=1)
        for g in range(2, 6):
            runs += pair(g, 2 * g)
        counted, status = A.select_runs(runs)
        self.assertEqual(status, "ok")
        for impl in ("utcp", "linux"):
            self.assertEqual([r["group"] for r in counted[impl]], [(0, 0), (1, 1), (2, 0), (3, 0), (4, 0)])

    def test_counting_follows_the_run_order_not_the_names(self):
        # Group 12 ran first (order 0) but its name sorts after group 3's; a
        # rerun's name sorts before the next group's.
        runs = pair(12, 0) + pair(3, 2, linux_ok=False) + pair(3, 2, rerun=1) + pair(4, 4) + pair(5, 6) + \
            pair(6, 8) + pair(2, 10)
        counted, _ = A.select_runs(runs)
        self.assertEqual([r["group"] for r in counted["utcp"]], [(12, 0), (3, 1), (4, 0), (5, 0), (6, 0)])

    def test_rerun_cap_counts_invalid_groups(self):
        # Three invalid groups (each rerun) are allowed ...
        runs = []
        for g in range(5):
            runs += pair(g, 10 * g)
        for g in range(5, 8):
            runs += pair(g, 10 * g, utcp_ok=False) + pair(g, 10 * g, rerun=1)
        self.assertEqual(A.select_runs(runs)[1], "ok")
        # ... a fourth makes the cell invalid, even with 5 valid groups.
        runs += pair(8, 80, linux_ok=False)
        self.assertEqual(A.select_runs(runs)[1], "invalid (rerun cap)")

    def test_a_group_without_its_partner_does_not_count(self):
        runs = [r for g in range(5) for r in pair(g, 2 * g)]
        runs = [r for r in runs if not (r["group"] == (4, 0) and r["impl"] == "linux")]
        counted, status = A.select_runs(runs)
        self.assertEqual(status, "incomplete")
        self.assertEqual(len(counted["utcp"]), 4)

    def test_incomplete(self):
        runs = [r for g in range(4) for r in pair(g, 2 * g)]
        self.assertEqual(A.select_runs(runs)[1], "incomplete")


class Tables(unittest.TestCase):
    def make_campaign(self, root):
        camp = Path(root) / "camp"
        order = 0
        for impl, scale, qs in (("utcp", 0.8, 0.0), ("linux", 1.0, 0.0)):
            for rep in range(5):
                make_run(camp, f"{impl}-{rep}", {"impl": impl, "rep": rep, "order": order,
                                                  "profile": "linux_compat" if impl == "utcp" else ""},
                         goodput_scale=scale * (1 + rep * 0.01), retrans_in=10 + rep, qshift=qs)
                order += 1
        # One invalid stack run, rerun.
        make_run(camp, "utcp-5", {"impl": "utcp", "rep": 5, "order": order}, valid=False)
        return camp

    def test_cells_and_regeneration_from_the_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            camp = self.make_campaign(tmp)
            out1 = Path(tmp) / "direct"
            A.make_tables(camp, out1)
            cells = (out1 / "cells.csv").read_text().splitlines()
            self.assertEqual(len(cells), 3)  # header + utcp + linux
            hdr = cells[0].split(",")
            row = dict(zip(hdr, cells[2].split(",")))  # utcp sorts after linux
            self.assertEqual(row["impl"], "utcp")
            self.assertEqual(row["status"], "ok")
            self.assertEqual(row["transient"], "0")
            self.assertEqual(row["n_counted"], "5")
            self.assertEqual(row["n_invalid"], "1")
            self.assertEqual(row["gap_goodput_bps"], "gap")
            self.assertEqual(row["gap_retrans_pct"], "no gap")
            self.assertEqual(row["gap_qdelay_p50_ms"], "no gap")
            runs = (out1 / "runs.csv").read_text().splitlines()
            self.assertEqual(len(runs), 12)
            arc = Path(tmp) / "camp.tar.gz"
            n = A.archive(camp, arc)
            self.assertEqual(n, 11 * 6)  # meta, snd, rcv, ping, pre, post per run
            out2 = Path(tmp) / "regen"
            A.tables_from_archive(arc, out2)
            for name in ("runs.csv", "cells.csv"):
                self.assertEqual((out1 / name).read_bytes(), (out2 / name).read_bytes(), name)

    def test_archive_manifest_is_checked(self):
        import tarfile
        with tempfile.TemporaryDirectory() as tmp:
            camp = self.make_campaign(tmp)
            arc = Path(tmp) / "camp.tar.gz"
            A.archive(camp, arc)
            # Rewrite one file in the archive.
            bad = Path(tmp) / "bad.tar.gz"
            with tarfile.open(arc) as src, tarfile.open(bad, "w:gz") as dst:
                for m in src.getmembers():
                    data = src.extractfile(m).read()
                    if m.name.endswith("utcp-0/ping.txt"):
                        data = data.replace(b"time=20.0 ms", b"time=21.0 ms")
                        m.size = len(data)
                    import io
                    dst.addfile(m, io.BytesIO(data))
            with self.assertRaises(ValueError):
                A.tables_from_archive(bad, Path(tmp) / "x")


class Records(unittest.TestCase):
    def test_parse_record_sections(self):
        rec = A.parse_record(record("pre"))
        self.assertIn(("s-snd", "ip -s -d link"), rec)
        links = A.parse_links(rec[("s-snd", "ip -s -d link")])
        self.assertEqual(links["eth0"]["mtu"], 1500)
        self.assertEqual(links["eth0"]["gso_ipv4_max_size"], 65536)
        self.assertEqual(links["utcp0"]["rx_dropped"], 0)
        q = A.parse_qdiscs(rec[("s-r2", "tc -s -raw qdisc")])
        self.assertEqual(q["eth1"]["kind"], "tbf")
        self.assertEqual(q["eth1"]["overlimits"], 7)
        sn = A.parse_softnet(rec[("host", "softnet_stat")])
        self.assertEqual(sn[8], (0x1000, 0, 0))
        st = A.parse_proc_stat(rec[("host", "/proc/stat")])
        self.assertEqual(st[3], {"irq": 5, "softirq": 20, "total": 1175, "busy": 175})


class StackCounters(unittest.TestCase):
    def test_nstat_and_softirqs(self):
        n = A.parse_nstat(["#kernel", "TcpRetransSegs                  12                 0.0",
                           "TcpExtTCPSackRecovery           3                  0.0", "garbage"])
        self.assertEqual(n, {"TcpRetransSegs": 12, "TcpExtTCPSackRecovery": 3})
        si = A.parse_softirqs(["                    CPU0       CPU8       CPU9",
                               "          HI:          0          1          2",
                               "      NET_RX:         10        100        200"])
        self.assertEqual(si["NET_RX"], {0: 10, 8: 100, 9: 200})
        pre = {"softirqs": si, "nstat": {"s-snd": n}}
        post = {"softirqs": {"NET_RX": {0: 99, 8: 150, 9: 260}},
                "nstat": {"s-snd": {"TcpRetransSegs": 20, "TcpExtTCPSackRecovery": 3}}}
        self.assertEqual(A.softirq_deltas(pre, post, [8, 9]), {"NET_RX": 110})
        d = A.nstat_deltas(pre, post, "s-snd")
        self.assertEqual(d["TcpRetransSegs"], 8)
        self.assertEqual(d["TcpExtTCPTimeouts"], 0)

    def test_stack_stats_flags_blocking_and_invalidates_device_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_run(tmp, "u", {"impl": "utcp"})
            stats = {"ev": "stack_stats", "TcpRetransSegs": 5, "dev_tx_errors": 0, "dev_rx_errors": 0,
                     "dev_device_failed": False, "dev_tx_batch_max": 44, "loop_pending_calls": 0,
                     "loop_lateness_bucket_0": 3, "loop_lateness_bucket_11": 7, "trace_events": 120}
            (d / "stats.json").write_text(json.dumps(stats) + "\n")
            s = A.summarize_run(d)
            self.assertTrue(s["valid"], s["invalid"])
            self.assertNotIn("stack_blocked", s["flags"])
            self.assertEqual(s["sender_counters"]["TcpRetransSegs"], 5)
            self.assertEqual(s["stack_lateness_hist"], {"0": 3, "11": 7})
            self.assertEqual(s["trace_events"], 120)
            self.assertEqual(s["stack_tx_batch_max"], 44)
            stats.update(loop_pending_calls=2, dev_tx_errors=1)
            (d / "stats.json").write_text(json.dumps(stats) + "\n")
            s = A.summarize_run(d)
            self.assertIn("stack_blocked", s["flags"])
            self.assertFalse(s["valid"])
            self.assertIn("stack device errors", s["invalid"])


PLAN = """
campaign = "t/mini"
seed = 7
reps = 2
[[cell]]
bw = 10
rtt = 20
loss = 0
queue_bdp = 2
[[cell]]
bw = 100
rtt = 100
loss = 1
queue_bdp = 0.5
[[algo]]
cc = "newreno"
[[algo]]
cc = "cubic"
impls = ["linux"]
"""


class Plans(unittest.TestCase):
    def plan(self, text=PLAN):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "plan.toml"
            p.write_text(text)
            return M.load_plan(p)

    def test_expansion_is_fixed_by_the_seed(self):
        plan = self.plan()
        runs = M.expand_plan(plan)
        self.assertEqual(runs, M.expand_plan(plan))
        self.assertEqual(len(runs), 2 * 2 * (2 + 1))
        self.assertEqual([r["order"] for r in runs], list(range(len(runs))))
        self.assertEqual(len({r["run"] for r in runs}), len(runs))
        other = M.expand_plan(dict(plan, seed=8))
        self.assertNotEqual([r["run"] for r in runs], [r["run"] for r in other])
        self.assertEqual(runs[0]["duration"], 30 if runs[0]["rtt"] == 20 else 60)

    def test_pairs_are_back_to_back_with_one_netem_seed(self):
        runs = M.expand_plan(self.plan())
        groups = {}
        for r in runs:
            groups.setdefault(r["group"], []).append(r)
        firsts = set()
        for g, rs in groups.items():
            orders = [r["order"] for r in rs]
            self.assertEqual(orders, list(range(orders[0], orders[0] + len(rs))))  # back to back
            self.assertEqual(len({r["seed"] for r in rs}), 1)  # one netem seed per pair
            self.assertEqual(len({(r["cell"], r["cc"], r["rep"]) for r in rs}), 1)
            if len(rs) == 2:
                self.assertEqual({r["impl"] for r in rs}, {"utcp", "linux"})
                firsts.add(rs[0]["impl"])
        for seed in range(8, 14):
            for r in M.expand_plan(dict(self.plan(), seed=seed)):
                if r["cc"] == "newreno" and r["in_group"] == 0:
                    firsts.add(r["impl"])
        self.assertEqual(firsts, {"utcp", "linux"})  # the in-pair order is drawn, not fixed
        # Repetitions of one (cell, algorithm) get different netem seeds.
        for cell in {r["cell"] for r in runs}:
            seeds = {r["seed"] for r in runs if r["cell"] == cell and r["cc"] == "newreno"}
            self.assertEqual(len(seeds), 2)

    def test_slots_split_every_cell_and_algorithm(self):
        runs = M.expand_plan(self.plan(), nslots=2)
        for key in {(r["cell"], r["cc"]) for r in runs}:
            slots = {r["slot_index"] for r in runs if (r["cell"], r["cc"]) == key}
            self.assertEqual(slots, {0, 1})
        for g in {r["group"] for r in runs}:
            self.assertEqual(len({r["slot_index"] for r in runs if r["group"] == g}), 1)

    def test_bad_plans(self):
        with self.assertRaises(ValueError):
            self.plan(PLAN.replace('campaign = "t/mini"', ""))
        with self.assertRaises(ValueError):
            self.plan(PLAN.replace('impls = ["linux"]', 'impls = ["bsd"]'))

    def test_reuse_key_changes_with_the_binary_and_a_sysctl(self):
        meta = {"bulk_sha256": "a" * 64, "core_sha256": "b" * 64, "build": "build/tb-gcc-release",
                "uname_r": "7.0.0", "image_id": "sha256:1", "scripts_sha256": "c" * 64}
        rec = ("== utcp-m2-s0-snd sysctl\nnet.ipv4.tcp_wmem = 4096 16384 67108864\n"
               "== host module parameters\ntcp_cubic.beta 717\n")
        rec_s1 = rec.replace("utcp-m2-s0-snd", "utcp-m2-s1-snd")
        k = M.reuse_key(meta, M.sysctl_dump(rec))
        self.assertEqual(k, M.reuse_key(meta, M.sysctl_dump(rec_s1)))  # the slot is not part of it
        self.assertNotEqual(k, M.reuse_key(dict(meta, bulk_sha256="d" * 64), M.sysctl_dump(rec)))
        self.assertNotEqual(k, M.reuse_key(dict(meta, core_sha256="d" * 64), M.sysctl_dump(rec)))
        self.assertNotEqual(k, M.reuse_key(meta, M.sysctl_dump(rec.replace("67108864", "4194304"))))
        self.assertNotEqual(k, M.reuse_key(meta, M.sysctl_dump(rec.replace("beta 717", "beta 700"))))

    def test_stack_sets_follow_the_measured_gso_size(self):
        self.assertEqual(M.stack_sets(65536), ["snd_buf_max=64Mi", "rcv_buf_max=32Mi", "gso_max_size=65215"])
        self.assertEqual(M.stack_sets(None), ["snd_buf_max=64Mi", "rcv_buf_max=32Mi"])


class Proof(unittest.TestCase):
    def test_compare_needs_the_bound_and_overlapping_ranges(self):
        c = M.proof_compare([100, 101, 102], [100.5, 101.5, 102.5], rel=0.01)
        self.assertTrue(c["ok"])
        c = M.proof_compare([100, 101, 102], [101, 103, 104], rel=0.01)  # median +1.98 %
        self.assertFalse(c["ok"])
        c = M.proof_compare([20.1, 20.1, 20.2], [20.25, 20.28, 20.3], abs_=0.2)  # ranges disjoint
        self.assertTrue(c["within"])
        self.assertFalse(c["overlap"])
        self.assertFalse(c["ok"])
        self.assertFalse(M.proof_compare([None], [1.0], rel=0.01)["ok"])

    def test_histogram_percentile_as_the_event_loop(self):
        h = M.hist_merge([{"0": 2, "10": 7}, {"10": 1, "20": 1}])
        self.assertEqual(h, {0: 2, 10: 8, 20: 1})
        self.assertEqual(M.hist_percentile(h, 0.18), 0)         # rank ceil(1.98) = 2: bucket 0
        self.assertEqual(M.hist_percentile(h, 0.5), 1023)       # rank 6: bucket 10, [512, 1024)
        self.assertEqual(M.hist_percentile(h, 0.99), (1 << 20) - 1)
        self.assertIsNone(M.hist_percentile({}, 0.99))


class Plot(unittest.TestCase):
    def test_median_goodput_run_per_side(self):
        runs = [({"impl": "utcp", "run": f"u{i}"}, {"valid": True, "goodput_bps": g})
                for i, g in enumerate((5, 1, 3, 4))]
        runs.append(({"impl": "utcp", "run": "bad"}, {"valid": False, "goodput_bps": 3.5}))
        runs += [({"impl": "linux", "run": f"l{i}"}, {"valid": True, "goodput_bps": g})
                 for i, g in enumerate((7, 9, 8))]
        sel = P.selection_of(runs)
        self.assertEqual(sel["utcp"][0]["run"], "u2")  # 1, 3, 4, 5: the lower middle
        self.assertEqual(sel["linux"][0]["run"], "l2")



# --------------------------------------------------------------------------
# Tests of the review fixes (2026-11-16)


def ip_packet(src, dst, proto, payload):
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                       bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))) + payload


def pcap_records(recs):
    """A nanosecond pcap (Ethernet) of [(ts_ns, ip_bytes)]."""
    out = struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 128, 1)
    for ts, ip in recs:
        frame = (b"\0" * 12 + b"\x08\x00" + ip)[:128]
        out += struct.pack("<IIII", ts // NS, ts % NS, len(frame), len(frame)) + frame
    return out


def echo(src, dst, typ, ident, seq):
    return ip_packet(src, dst, 1, struct.pack(">BBHHH", typ, 0, 0, ident, seq) + b"\0" * 56)


def tcp_data(src, dst, seq, plen):
    return ip_packet(src, dst, 6, struct.pack(">HHIIBBHHH", 40000, 5201, seq, 0, 0x50, 0x10, 1000, 0, 0)
                     + b"\0" * plen)


SND, RCV = "198.19.10.2", "198.19.12.5"


class PingFromCapture(unittest.TestCase):
    def test_echoes_pair_by_id_and_seq_with_ns_rtts(self):
        t = 5 * NS
        recs = [(t, echo(SND, RCV, 8, 7, 1)), (t + 50_000_000, echo(SND, RCV, 8, 7, 2)),
                (t + 100_123_456, echo(RCV, SND, 0, 7, 1)),        # reply to 1: 100.123456 ms
                (t + 100_000_000, echo(SND, RCV, 8, 7, 3)),        # never answered
                (t + 150_456_789, echo(RCV, SND, 0, 9, 2)),        # other id: not seq 2's reply
                (t + 150_500_000, echo(RCV, SND, 0, 7, 2)),
                (t + 160_000_000, echo("198.19.12.4", RCV, 8, 7, 4))]  # other source
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "p.pcap"
            p.write_bytes(pcap_records(recs))
            pings = A.icmp_echoes(p, SND, RCV)
        self.assertEqual([(x.seq, x.send_rt_ns) for x in pings], [(1, t), (2, t + 50_000_000), (3, t + 100_000_000)])
        self.assertAlmostEqual(pings[0].rtt_ms, 100.123456, places=9)
        self.assertAlmostEqual(pings[1].rtt_ms, 100.5, places=9)
        self.assertIsNone(pings[2].rtt_ms)
        st = A.ping_stats(pings, 3)
        self.assertEqual((st["n"], st["lost"]), (2, 1))

    def test_production_idle_ping_uses_requests_seen_on_the_wire(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "ping.pcap"
            packets = []
            for seq in range(200):
                t = (1000 + seq) * 50_000_000
                packets.extend([(t, echo(SND, RCV, 8, 7, seq)), (t + 20_000_000, echo(RCV, SND, 0, 7, seq))])
            p.write_bytes(pcap_records(packets))
            slot = SimpleNamespace(snd="snd", rcv="rcv", snd_ip=SND, rcv_ip=RCV, r1="r1", ifs={"r1_a":"eth0"})
            events = []
            def analyze(args):
                return subprocess.check_output([sys.executable, "-I", A.__file__, "pings", str(p), *args[2:]], text=True)
            def run(c, script):
                if " | tee " in script:
                    events.append("ping")
                return ""
            with ExitStack() as st:
                for name in ("capture_start", "capture_stop"):
                    st.enter_context(mock.patch.object(M, name))
                st.enter_context(mock.patch.object(M, "dexec", side_effect=run))
                st.enter_context(mock.patch.object(M, "run_analysis", side_effect=analyze))
                barrier = SimpleNamespace(wait=lambda **kwargs: events.append("ready"))
                ping = M.ping_only(slot, "t", "idle", None, sender_barrier=barrier)
            self.assertEqual(events, ["ready", "ping"])
            self.assertTrue(M.gate_item1(ping, 20))
            self.assertEqual(ping["ping_end_ns"] - ping["ping_start_ns"], 199 * 50_000_000)
            self.assertFalse(M.gate_item1(dict(ping, requests_seen=190), 20))

    def test_run_uses_the_capture_pings_with_sub_ms_resolution_at_100_ms(self):
        # ping.txt says 100 ms (iputils' whole milliseconds); the capture has
        # 100.3 ms idle and 100.3 + d in the window.
        with tempfile.TemporaryDirectory() as tmp:
            d = make_run(tmp, "r0")
            pings = [[i, rt(T0 - 3 * NS + i * 100_000_000), 100_300_000] for i in range(20)]
            pings += [[100 + i, rt(T0 + 6 * NS + i * 100_000_000), 100_300_000 + 250_000 * (i + 1)] for i in range(4)]
            (d / "capture.json").write_text(json.dumps({"r1-in": {"data_segs": 1, "retrans_segs": 0,
                                                                  "pings": pings}}))
            s = A.summarize_run(d)
            self.assertEqual(s["ping_source"], "capture r1-in")
            self.assertAlmostEqual(s["ping_base_ms"], 100.3, places=9)
            self.assertEqual(s["ping_n"], 4)
            self.assertAlmostEqual(s["qdelay_p50_ms"], 0.625, places=9)   # 0.25, 0.5, 0.75, 1.0
            (d / "capture.json").unlink()
            self.assertEqual(A.summarize_run(d)["ping_source"], "ping.txt")


class WindowEdges(unittest.TestCase):
    def test_window_bounds_from_the_receivers_accept_and_the_senders_write_stop(self):
        # A rate change at t0 + 5.05 s: a window that started at the sender's
        # start (t0 - 20 ms) or ended at t0 + S would give another goodput.
        with tempfile.TemporaryDirectory() as tmp:
            d = make_run(tmp, "r0")
            lines = A.read_jsonl(d / "rcv.jsonl")
            for x in lines:
                if x.get("ev") == "sample":
                    sec = (x["t"] - T0) / NS
                    x["bytes_received"] = 400_000 * min(sec, 5.05) + 1_000_000 * max(0.0, sec - 5.05)
            (d / "rcv.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines))
            s = A.summarize_run(d)
            hi = S - 0.02
            want = (0.05 * 400_000 + (hi - 5.05) * 1_000_000) * 8 / (hi - 5.0)
            self.assertAlmostEqual(s["goodput_bps"], want, delta=0.01)
            self.assertLessEqual(s["window_end_ns"], s["sender_start_ns"] + S * NS)
            self.assertEqual(s["t0_ns"], T0)

    def test_pings_are_windowed_by_send_time(self):
        lo, hi = T0 + 5 * NS, T0 + 25 * NS
        pings = [A.Ping(1, rt(T0 - 2 * NS), 20.0),
                 A.Ping(2, rt(lo - 50_000_000), 100.0),   # sent before lo, answered after: out
                 A.Ping(3, rt(lo + NS), 30.0),
                 A.Ping(4, rt(hi - 50_000_000), 60.0)]    # sent before hi, answered after: in
        m = A.ping_metrics(pings, CLOCK, T0, lo, hi)
        self.assertEqual(m["ping_n"], 2)
        self.assertAlmostEqual(m["qdelay_p50_ms"], 25.0)   # 10 and 40

    def test_the_base_is_the_median_of_the_idle_pings(self):
        # Idle RTTs 20.0, 20.1, 20.2, 20.3 and 25.0: median 20.2, mean 21.12.
        lo, hi = T0 + 5 * NS, T0 + 25 * NS
        pings = [A.Ping(i + 1, rt(T0 - 3 * NS + i * 500_000_000), r)
                 for i, r in enumerate([20.0, 20.1, 20.2, 20.3, 25.0])]
        pings += [A.Ping(10 + i, rt(lo + i * NS), 20.2 + d) for i, d in enumerate([1.0, 2.0, 3.0])]
        m = A.ping_metrics(pings, CLOCK, T0, lo, hi)
        self.assertEqual(m["ping_idle_n"], 5)
        self.assertAlmostEqual(m["ping_base_ms"], 20.2, places=9)
        self.assertAlmostEqual(m["qdelay_p50_ms"], 2.0, places=9)

    def test_a_lost_pings_send_time_is_one_interval_before_its_no_answer_line(self):
        lo, hi = T0 + 5 * NS, T0 + 25 * NS
        text = (f"[{rt_str(rt(T0 - NS))}] 64 bytes from {RCV}: icmp_seq=1 ttl=62 time=20.0 ms\n"
                f"[{rt_str(rt(hi + 30_000_000))}] no answer yet for icmp_seq=2\n"   # sent hi - 20 ms
                f"[{rt_str(rt(hi + 80_000_000))}] no answer yet for icmp_seq=3\n")  # sent hi + 30 ms
        m = A.ping_metrics(A.parse_ping(text), CLOCK, T0, lo, hi)
        self.assertEqual(m["ping_lost"], 1)

    def test_missing_jsonl_or_sender_samples_make_the_run_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "partial"
            d.mkdir()
            (d / "meta.json").write_text(json.dumps({"run": "partial", "duration_s": S, "impl": "linux",
                                                     "cell": "10-20-0-2", "cc": "cubic", "loss_pct": 0}))
            s = A.summarize_run(d)
            self.assertFalse(s["valid"])
            self.assertEqual(s["invalid"], ["no receiver JSONL", "no sender JSONL"])
            A.make_tables(tmp, Path(tmp) / "out")  # no exception
            d2 = make_run(tmp, "r1")
            lines = [x for x in A.read_jsonl(d2 / "snd.jsonl") if x.get("ev") != "sample"]
            (d2 / "snd.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines))
            s2 = A.summarize_run(d2)
            self.assertIn("sender samples do not cover the window", s2["invalid"])


class Validity(unittest.TestCase):
    def summ(self, tmp, name, meta_over=None, **rec):
        d = make_run(tmp, name, meta_over)
        (d / "post" / "record.txt").write_text(record("post", **rec))
        return A.summarize_run(d)

    def test_every_interface_drop_and_the_utcp_qdisc_invalidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i, (c, dev, rx, tx) in enumerate((("s-r1", "eth0", 1, 0), ("s-r1", "eth1", 0, 1),
                                                  ("s-r2", "eth0", 1, 0), ("s-r2", "eth1", 2, 0),
                                                  ("s-rcv", "eth0", 3, 0))):
                s = self.summ(tmp, f"l{i}", link_drops={(c, dev): (rx, tx)})
                self.assertFalse(s["valid"], (c, dev))
                self.assertEqual(s["local_drops"], {f"{c}/{dev}/{'rx' if rx else 'tx'}_dropped": rx or tx})
            s = self.summ(tmp, "q", utcp_qdrop=4)
            self.assertEqual(s["local_drops"], {"s-snd/utcp0/qdisc_dropped": 4})

    def test_softnet_drops_count_on_the_slot_cpus_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self.summ(tmp, "a", softnet_drop={9: 2})
            self.assertFalse(s["valid"])
            self.assertEqual(s["local_drops"], {"softnet/cpu9/dropped": 2})
            s = self.summ(tmp, "b", softnet_drop={20: 2})
            self.assertTrue(s["valid"], s["invalid"])

    def test_ack_path_qdisc_drops_invalidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self.summ(tmp, "a", ack_qdrop=1)
            self.assertIn("ACK-path qdisc drops", s["invalid"])

    def test_stack_local_drops_invalidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_run(tmp, "u", {"impl": "utcp"})
            (d / "stats.json").write_text(json.dumps({"ev": "stack_stats", "IpOutDiscards": 3,
                                                      "loop_pending_calls": 0}) + "\n")
            s = A.summarize_run(d)
            self.assertIn("stack local drops", s["invalid"])
            self.assertEqual(s["stack_local_drops"], {"IpOutDiscards": 3})

    def test_foreign_cpu_time_from_the_cgroups(self):
        # Slot CPUs 8-11: +2000 jiffies each (20 s), 750 busy of them, 50 irq
        # and softirq: 80 s total, 30 s busy, 2 s irq. The containers used
        # 26 s: lower bound (30 - 2 - 26) / 80 = 2.5 % (flagged), upper
        # (30 - 26) / 80 = 5 %.
        post_stat = {c: (700, 150, 2250, 15, 60) for c in range(8, 12)}
        pre_cg = {c: 1_000_000 for c in ("s-snd", "s-r1", "s-r2", "s-rcv")}
        with tempfile.TemporaryDirectory() as tmp:
            for ours, flagged, lower in ((26_000_000, True, 0.025), (27_600_000, False, 0.005)):
                d = make_run(tmp, f"f{ours}")
                (d / "pre" / "record.txt").write_text(record("pre", cgroup=pre_cg))
                post_cg = dict(pre_cg, **{"s-snd": 1_000_000 + ours})
                (d / "post" / "record.txt").write_text(record("post", cgroup=post_cg, stat=post_stat))
                s = A.summarize_run(d)
                self.assertAlmostEqual(s["foreign_cpu"]["lower_frac"], lower)
                self.assertAlmostEqual(s["foreign_cpu"]["upper_frac"], lower + 0.025)
                self.assertEqual("foreign_cpu" in s["flags"], flagged)
                self.assertTrue(s["valid"])
            # Without the cgroup section: not measured, no flag.
            self.assertIsNone(A.summarize_run(make_run(tmp, "none"))["foreign_cpu"])


class CaptureCrossCheck(unittest.TestCase):
    def test_bins_and_the_window_count(self):
        recs = [(10 * NS + i * 5_000_000, tcp_data(SND, RCV, 1 + 1448 * i, 1448)) for i in range(10)]
        recs.append((10 * NS + 52_000_000, tcp_data(SND, RCV, 1, 1448)))  # a retransmission
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "c.pcap"
            p.write_bytes(pcap_records(recs))
            c = A.capture_summary(p, RCV, bin_ns=A.CAPTURE_BIN_NS)
        self.assertEqual((c["data_segs"], c["retrans_segs"]), (11, 1))
        self.assertEqual(c["bins"]["data"], [2, 2, 2, 2, 2, 1])
        self.assertEqual(c["bins"]["retrans"], [0, 0, 0, 0, 0, 1])
        ser = A.counts_series(c["bins"], "data")
        self.assertEqual(A.delta(ser, 10 * NS + 10_000_000, 10 * NS + 30_000_000), 4)

    def make(self, tmp, name, extra_data=0):
        d = make_run(tmp, name)
        nb = 3100   # 31 s of 10 ms bins from t0
        data = [3 if i < 450 else 10 if i < 3050 else 0 for i in range(nb)]
        rexmit = [1 if 450 <= i < 3050 and i % 10 == 0 else 0 for i in range(nb)]
        data[1000] += extra_data
        bins = {"t0_rt_ns": rt(T0), "bin_ns": A.CAPTURE_BIN_NS, "data": data, "retrans": rexmit}
        (d / "capture.json").write_text(json.dumps({"r1-in": {"data_segs": sum(data), "retrans_segs": sum(rexmit),
                                                              "bins": bins}}))
        return A.summarize_run(d)

    def test_capture_and_sender_counters_over_the_same_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self.make(tmp, "ok")
            self.assertAlmostEqual(s["capture_window"]["r1in_data_segs"], 24_980)
            self.assertAlmostEqual(s["retrans_pct_capture"], 1.0, delta=0.01)
            self.assertFalse([f for f in s["flags"] if f.startswith("capture_mismatch")])
            s = self.make(tmp, "extra", extra_data=100)   # 100 segments the sender did not count
            self.assertIn("capture_mismatch:data_segs_out", s["flags"])
            self.assertTrue(s["valid"])

    def test_sequence_wrap(self):
        segs = [("198.19.10.2", RCV, 0xFFFFFA00, 1448),
                ("198.19.10.2", RCV, (0xFFFFFA00 + 1448) & 0xFFFFFFFF, 1448),   # crosses 2^32
                ("198.19.10.2", RCV, (0xFFFFFA00 + 2896) & 0xFFFFFFFF, 1448),   # 0x00000550: new data
                ("198.19.10.2", RCV, 0xFFFFFA00, 1448)]                         # retransmission
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "w.pcap"
            p.write_bytes(pcap_bytes(segs))
            self.assertEqual(A.capture_summary(p, RCV), {"data_segs": 4, "retrans_segs": 1})
            p.write_bytes(pcap_bytes(segs[:3]))
            self.assertEqual(A.capture_summary(p, RCV), {"data_segs": 3, "retrans_segs": 0})


class GapRuleEdges(unittest.TestCase):
    def test_below_resolution_is_strictly_below_1_ms(self):
        # 5 ms vs 4 ms p50 (25 %, disjoint): exactly 1.0 ms is a plain gap.
        self.assertEqual(A.gap_verdict("qdelay_p50_ms", stat(5.0, 4.9, 5.1), stat(4.0, 3.9, 4.1), 0), "gap")
        self.assertEqual(A.gap_verdict("qdelay_p50_ms", stat(4.99, 4.9, 5.1), stat(4.0, 3.9, 4.1), 0),
                         "gap (below resolution)")

    def test_fewer_than_five_values_give_no_verdict(self):
        short = dict(stat(80, 78, 82), n=4)
        self.assertEqual(A.gap_verdict("goodput_bps", short, stat(100, 95, 105), 0), "n/a")
        self.assertEqual(A.gap_verdict("goodput_bps", stat(80, 78, 82), short, 0), "n/a")


class QueueEdges(unittest.TestCase):
    def test_drop_intervals_the_10_ms_sampler_cannot_test(self):
        # 0.5xBDP at 10 Mbit/s, 20 ms: Q 12 500 B, B 3028 B; 10 ms drain
        # 12 500 B: the tail-drop level is negative, any backlog meets it.
        s = [(100 * NS + i * 10_000_000, b, d) for i, (b, d) in enumerate(((0, 0), (1514, 1), (0, 2)))]
        r = A.queue_check(s, 12_500, 10e6, 3028)
        self.assertEqual((r["drop_intervals"], r["drop_intervals_untestable"], r["drop_intervals_low"]), (2, 2, 0))
        self.assertEqual(r["drop_check"], "not testable at 10 ms sampling")
        r = A.queue_check(s, 250_000, 10e6, 3028)
        self.assertEqual((r["drop_intervals_untestable"], r["drop_intervals_low"], r["drop_check"]), (0, 2, "tested"))
        self.assertFalse(M.gate_item4(r, 250_000, 10, 0.2, 0.0)["ok"])


class GateItems(unittest.TestCase):
    def test_item1_bounds(self):
        ok = {"requests_seen": 200, "n": 200, "lost": 0, "median_ms": 21.0, "p99_ms": 22.0}
        self.assertTrue(M.gate_item1(ok, 20))
        self.assertFalse(M.gate_item1(dict(ok, median_ms=21.01), 20))
        self.assertFalse(M.gate_item1(dict(ok, median_ms=19.99), 20))
        self.assertFalse(M.gate_item1(dict(ok, p99_ms=22.01), 20))
        self.assertFalse(M.gate_item1(dict(ok, n=189), 20))

    def test_item2_threshold_and_the_ungated_half_bdp_queue(self):
        thr = 0.98 * 100e6 * 1448 / 1514
        self.assertTrue(M.gate_item2(thr, 100, 2)["ok"])
        self.assertFalse(M.gate_item2(thr - 1, 100, 2)["ok"])
        self.assertTrue(M.gate_item2(0, 100, 0.5)["ok"])
        self.assertFalse(M.gate_item2(0, 100, 0.5)["gated"])

    def test_item3_alpha_interval_and_complete_captures(self):
        self.assertEqual(M.loss_alpha(16), 0.01 / 16)
        alpha = M.loss_alpha(16)
        lo, hi = A.binom_interval(100_000, 0.01, alpha)
        full = {"kernel_dropped": 0, "captured": 5, "received_by_filter": 5}

        ack = {"r2_b": {"dropped": 0}, "r1_a": {"dropped": 0}}

        def cap(lost, r1out=full):
            return {"r1-in": dict(full, data_segs=100_000), "r1-out": dict(r1out, data_segs=100_000 - lost),
                    "r2-out": dict(full, data_segs=100_000 - lost - 7)}
        self.assertTrue(M.gate_item3(cap(lo), 7, 1.0, alpha, ack, {})["ok"])
        self.assertTrue(M.gate_item3(cap(hi), 7, 1.0, alpha, ack, {})["ok"])
        self.assertFalse(M.gate_item3(cap(hi + 1), 7, 1.0, alpha, ack, {})["ok"])
        self.assertFalse(M.gate_item3(cap(lo - 1), 7, 1.0, alpha, ack, {})["ok"])
        self.assertFalse(M.gate_item3(cap(lo, dict(full, received_by_filter=6)), 7, 1.0, alpha, ack, {})["ok"])
        self.assertFalse(M.gate_item3(cap(lo, dict(full, kernel_dropped=1)), 7, 1.0, alpha, ack, {})["ok"])
        self.assertFalse(M.gate_item3(cap(lo), 7, 1.0, alpha, dict(ack, r2_b={"dropped": 1}), {})["ok"])
        self.assertFalse(M.gate_item3({}, 7, 1.0, alpha, ack, {})["ok"])

    def test_item4_ping_target_within_10_percent(self):
        qc = {"reaches": True, "drop_intervals_low": 0, "backlog_max": 49_000}
        target = M.ping_target_ms(50_000, 10)   # 32 whole frames + 98 B: 38.8368 ms
        self.assertAlmostEqual(target, (32 * 1514 + 98) * 8 / 10e6 * 1e3)
        self.assertTrue(M.gate_item4(qc, 50_000, 10, 20.0 + 1.0999 * target, 20.0)["ok"])
        self.assertTrue(M.gate_item4(qc, 50_000, 10, 20.0 + 0.9001 * target, 20.0)["ok"])
        self.assertFalse(M.gate_item4(qc, 50_000, 10, 20.0 + 1.1001 * target, 20.0)["ok"])
        self.assertFalse(M.gate_item4(qc, 50_000, 10, 20.0 + 0.8999 * target, 20.0)["ok"])
        self.assertFalse(M.gate_item4(dict(qc, drop_intervals_low=1), 50_000, 10, 20 + target, 20.0)["ok"])
        self.assertFalse(M.gate_item4(dict(qc, reaches=False), 50_000, 10, 20 + target, 20.0)["ok"])

    def test_item5_counts_time_squeeze_and_capture_drops(self):
        good = {"ack_path": {"r1_a": {"dropped": 0}, "r2_b": {"dropped": 0}}, "local_drops": {}, "time_squeeze": 0, "invalid": [],
                "capture": {"r1-in": {"kernel_dropped": 0}, "r2-out": {"kernel_dropped": 0}}}
        self.assertTrue(M.gate_item5(good)["ok"])
        self.assertFalse(M.gate_item5(dict(good, time_squeeze=1))["ok"])
        self.assertFalse(M.gate_item5(dict(good, capture={"r1-in": {"kernel_dropped": 2}}))["ok"])
        self.assertFalse(M.gate_item5(dict(good, local_drops={"x": 1}))["ok"])

    def test_item6(self):
        ping = {"requests_seen": 200, "n": 200, "lost": 0, "median_ms": 20.1, "p99_ms": 21.0}
        self.assertTrue(M.gate_item6_ping(dict(ping, median_ms=20.3), ping)["ok"])
        self.assertFalse(M.gate_item6_ping(dict(ping, median_ms=20.31), ping)["ok"])
        good = {"goodput_bps": 0.98 * 100e6 * 1448 / 1514, "valid": True, "stack_device": {},
                "local_drops": {}, "stack_local_drops": {}}
        self.assertTrue(M.gate_item6_run(good)["ok"])
        self.assertFalse(M.gate_item6_run(dict(good, stack_device={"x": 1}))["ok"])



def fixture_meta_digest(meta):
    encoded = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def fixture_cpus(slot):
    first = 8 + 4 * slot
    return {f"s{slot}-snd": f"{first},{first + 1}", f"s{slot}-rcv": str(first + 2),
            f"s{slot}-r1": str(first + 3), f"s{slot}-r2": str(first + 3)}


def proof_files(par_ping=20.2, par_goodput=101.0, par_backlog=102.0, ser_p99_bucket=16, par_p99_bucket=17,
                ser_max=1_000_000, par_max=2_000_000, stack_cc="newreno"):
    """Five repetitions of the four Linux cells and the trace-on/off stack comparisons."""
    f = {"proof-config.json": dict(M.proof_config(5, M.PROOF_PAIRS, stack_cc), reuse_key="key")}
    for sub in ("serial-s0", "parallel-s0", "parallel-s1"):
        par = sub != "serial-s0"
        slot = int(sub[-1])
        for r in range(5):
            ident = {"campaign": "t/" + sub, "slot": slot, "rep": r, "queue_bdp": 2, "loss": 0}
            cpus = range(8 + slot * 4, 12 + slot * 4)
            common = {"valid": True, "invalid": [], "rwnd_limited_frac": 0, "sndbuf_limited_frac": 0}
            for bw in (10, 100):
                for rtt in (20, 100):
                    name = f"ping-{bw}-{rtt}-2-r{r}"
                    cell = dict(ident, bw=bw, rtt=rtt)
                    start = T0 + (1000 * r + 6000 * par + slot + (bw == 100) * 200 + (rtt == 100) * 100) * NS
                    f[f"{sub}/{name}/ping.json"] = dict(cell, run=name, requests_seen=200, n=200, lost=0, reuse_key="key",
                        p99_ms=22, boot_id="boot", timing=True, cpusets=fixture_cpus(slot),
                        slot_cpus=",".join(map(str, cpus)), ping_start_ns=start, ping_end_ns=start + 10 * NS,
                        median_ms=par_ping if par else (19.9, 20, 20, 20.1, 20.3)[r])
                    name = f"rate-{bw}-{rtt}-2-r{r}"
                    f[f"{sub}/{name}/meta.json"] = dict(cell, run=name, impl="linux", cc="cubic", timing=True, cpusets=fixture_cpus(slot), boot_id="boot",
                        slot_cpus=",".join(map(str, cpus)), duration_s=30 if rtt == 20 else 60,
                        cell=f"{bw}-{rtt}-0-2", order=r, gate="proof-rate", duration=30 if rtt == 20 else 60, reuse_key="key", sender_exit=0)
                    t0 = start + 20 * NS
                    f[f"{sub}/{name}/summary.json"] = dict(common, run=name, sender_ccs=["cubic"],
                        t0_ns=t0, sender_start_ns=t0, window_end_ns=t0 + (30 if rtt == 20 else 60) * NS,
                        goodput_bps=par_goodput if par else (99, 100, 100, 100, 102)[r],
                        queue={"backlog_max": par_backlog if par else (98, 100, 100, 100, 103)[r]})
            b = par_p99_bucket if par else ser_p99_bucket
            for trace in ([True] if par else [True, False]):
                name = f"stack-{'trace' if trace else 'notrace'}-r{r}"
                t0 = T0 + (1000 * r + slot + (6000 if par else 0) + (400 if trace else 440)) * NS
                f[f"{sub}/{name}/meta.json"] = dict(ident, run=name, bw=100, rtt=20, duration=30, trace=trace, cpusets=fixture_cpus(slot),
                    gate="proof-stack" if trace else "proof-notrace", impl="utcp", cc=stack_cc, profile="linux",
                    slot_cpus=",".join(map(str, cpus)), duration_s=30, uptime="up", top_cpu=["sample"], threads_on_8_15=[],
                    cell="100-20-0-2", order=r, timing=True, reuse_key="key", sender_exit=0, boot_id="boot")
                f[f"{sub}/{name}/summary.json"] = dict(common, run=name, goodput_bps=100, sender_ccs=[stack_cc],
                    cpu={str(c): {"irq": 1, "softirq": 2, "busy": 5, "total": 100} for c in cpus}, foreign_cpu_frac=0,
                    softirqs={"NET_RX": 5, "NET_TX": 0, "HRTIMER": 1, "TIMER": 2},
                    qdelay_p99_ms=3, sender_lateness_p99_ns=(1 << b) - 1, trace_events=1 if trace else None,
                    stack_lateness_hist={"3": 98, str(b): 2}, sender_lateness_max_ns=par_max if par else ser_max,
                    t0_ns=t0, sender_start_ns=t0 - 20_000_000, window_end_ns=t0 + 30 * NS - 20_000_000)
    for path, meta in list(f.items()):
        if path.endswith("/meta.json"):
            f[path.removesuffix("meta.json") + "summary.json"]["proof_meta_sha256"] = fixture_meta_digest(meta)
    return f


class ProofDecisions(unittest.TestCase):
    def items(self, **kw):
        r = M.proof_evaluate(proof_files(**kw), "t", 5, M.PROOF_PAIRS)
        return {(i["item"], i["metric"], i["parallel_slot"]): i["ok"] for i in r["items"]}, r

    def test_full_population_and_evidence(self):
        stack = "parallel-s1/stack-trace-r3/"
        for path, field, value in (
                (stack, "valid", False), (stack, "sender_ccs", ["newreno", "cubic"]),
                (stack, "stack_lateness_hist", {}), (stack, "sender_lateness_max_ns", None),
                (stack, "sender_lateness_p99_ns", None), (stack, "sender_lateness_max_ns", -10), (stack, "qdelay_p99_ms", None),
                (stack, "rwnd_limited_frac", None), (stack + "meta", "profile", "rfc"),
                (stack + "meta", "cc", "cubic"), (stack + "meta", "bw", 10),
                (stack + "meta", "rep", 0), (stack + "meta", "trace", False),
                (stack + "meta", "reuse_key", "other"), (stack + "meta", "slot", 0),
                (stack + "meta", "boot_id", "previous boot"), (stack + "meta", "slot_cpus", "8-11"),
                (stack + "meta", "duration_s", 10), (stack, "softirqs", {}), (stack, "foreign_cpu_frac", None), (stack, "t0_ns", None),
                ("serial-s0/stack-notrace-r2/", "valid", False),
                ("serial-s0/stack-notrace-r2/", "trace_events", 0),
                (stack + "meta", "cell", "10-100-0-2"),
                ("parallel-s0/rate-10-100-2-r4/", "valid", False),
                ("parallel-s0/rate-10-100-2-r4/", "sender_ccs", []),
                ("parallel-s1/ping-100-20-2-r2/ping", "median_ms", None)):
            files = proof_files()
            key = path + ("summary.json" if path.endswith("/") else ".json")
            with self.subTest(path=key, field=field):
                files[key][field] = value
                if key.endswith("meta.json"):
                    files[path.removesuffix("meta") + "summary.json"]["proof_meta_sha256"] = fixture_meta_digest(files[key])
                self.assertFalse(M.proof_evaluate(files, "t", 5, M.PROOF_PAIRS)["passed"])
        files = {p: v for p, v in proof_files().items() if "-r0/" in p}
        self.assertFalse(M.proof_evaluate(files, "t", 5, M.PROOF_PAIRS)["passed"])
        self.assertFalse(M.proof_evaluate(files, "t", 1, M.PROOF_PAIRS)["passed"])
        self.assertFalse(M.proof_evaluate(proof_files(), "t", 5, [(100, 20)])["passed"])

    def test_equal_run_names_do_not_allow_swapping_summaries_across_slots(self):
        files = proof_files()
        run = "rate-100-20-2-r0/summary.json"
        files["parallel-s1/" + run] = files["parallel-s0/" + run]
        self.assertFalse(M.proof_evaluate(files, "t", 5, M.PROOF_PAIRS)["passed"])

    def test_only_the_measured_stack_windows_count_as_parallel(self):
        files = proof_files()
        for leaf in ("t0_ns", "sender_start_ns", "window_end_ns"):
            files["parallel-s1/stack-trace-r0/summary.json"][leaf] += 24 * NS
        r = M.proof_evaluate(files, "t", 5, M.PROOF_PAIRS)
        self.assertFalse(r["passed"])  # transfers overlap in warm-up, measured windows do not
        self.assertEqual(r["stack_overlap"][0]["overlap_ns"], 0)

    def test_cubic_selection_and_label(self):
        files = proof_files(stack_cc="cubic")
        r = M.proof_evaluate(files, "t", 5, M.PROOF_PAIRS, stack_cc="cubic")
        self.assertTrue(r["passed"])
        self.assertIn("CUBIC", M.proof_markdown(r))
        self.assertFalse(M.proof_evaluate(files, "t", 5, M.PROOF_PAIRS)["passed"])
        self.assertAlmostEqual(r["stack_overlap"][0]["overlap_ns"] / NS, 23.98)
        for _, _, spec in M.proof_list(1, [(100, 20)], True, stack_cc="cubic"):
            if "impl" in spec:
                self.assertEqual(spec["cc"], "cubic")

    def test_cubic_only_cli_and_measured_controls(self):
        files = {k: v for k, v in proof_files(stack_cc="cubic").items() if "/stack-trace-" in k}
        files["proof-config.json"] = dict(M.proof_config(5, (), "cubic"), reuse_key="key")
        with mock.patch.object(M, "proof_files", return_value=files), mock.patch.object(M, "sh"), redirect_stdout(io.StringIO()):
            self.assertEqual(M.main(["matrix.py", "proof", "--campaign", "t", "--phase", "report", "--cubic-only"]), 0)
        result = M.proof_evaluate(files, "t", 5, (), "cubic")
        self.assertEqual(len(result["valid_runs"]), 15)
        self.assertEqual(len(result["stack_overlap"]), 5)
        self.assertNotIn("trace_overhead", result)
        del files["parallel-s1/stack-trace-r4/summary.json"]
        self.assertFalse(M.proof_evaluate(files, "t", 5, (), "cubic")["passed"])
        for kind in ("rate", "ping"):
            files = proof_files()
            name = f"{kind}-100-100-2-r4"
            leaf = "summary.json" if kind == "rate" else "ping.json"
            row = files[f"parallel-s1/{name}/{leaf}"]
            for k in (("t0_ns", "sender_start_ns", "window_end_ns") if kind == "rate" else ("ping_start_ns", "ping_end_ns")):
                row[k] += 50000 * NS
            result = M.proof_evaluate(files, "t", 5, M.PROOF_PAIRS)
            self.assertFalse(result["passed"])
            self.assertEqual([r["run"] for r in result["control_overlap"] if not r["ok"]], [name])
        row.update(n=1, lost=199)
        result = M.proof_evaluate(files, "t", 5, M.PROOF_PAIRS)
        self.assertIn("incomplete idle ping", result["evidence_errors"].values())

    def test_archived_endpoint_records_bind_the_actual_transfer(self):
        # m2d-testbed/proof/serial-s0/stack-trace-r0: endpoint starts/summaries
        # and the unmodified sender/receiver samples bracketing both window edges.
        rows = A.read_jsonl(Path(__file__).parent / "testdata/stack-proof-endpoints.jsonl")
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            meta = {"gate": "proof-stack", "impl": "utcp", "duration_s": 30, "run": "stack-trace-r0"}
            (d / "meta.json").write_text(json.dumps(meta))
            for role, file in (("receiver", "rcv.jsonl"), ("sender", "snd.jsonl")):
                (d / file).write_text("".join(json.dumps(r) + "\n" for r in rows if r["role"] == role))
            result = A.summarize_run(d)
            self.assertTrue(result["valid"], result["invalid"])
            self.assertEqual(result["sender_ccs"], ["newreno"])
            self.assertEqual(result["proof_meta_sha256"], fixture_meta_digest(meta))
            meta["gate"] = "stack"
            (d / "meta.json").write_text(json.dumps(meta))
            rcv = A.read_jsonl(d / "rcv.jsonl")
            del rcv[-1]["bytes"]
            (d / "rcv.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rcv))
            self.assertFalse(A.summarize_run(d)["valid"])

    def test_analyzer_reads_the_sender_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            rd = make_run(tmp, "actual", {"cc": "newreno"})
            p = rd / "snd.jsonl"
            rows = A.read_jsonl(p)
            for row in rows:
                if row.get("ev") == "sample":
                    row["cc_name"] = "cubic"
            p.write_text("".join(json.dumps(row) + "\n" for row in rows))
            self.assertEqual(A.summarize_run(rd)["sender_ccs"], ["cubic"])
            measured = [row for row in rows if row.get("ev") == "sample" and row["t"] >= T0 + 5 * NS]
            measured[0]["cc_name"] = "newreno"
            del measured[1]["cc_name"]
            rows[8]["cc_name"] = "outside-window"
            p.write_text("".join(json.dumps(row) + "\n" for row in rows))
            self.assertEqual(A.summarize_run(rd)["sender_ccs"], ["", "cubic", "newreno"])

    def test_copying_one_stack_trial_as_another_repetition(self):
        files = proof_files()
        for sub in ("parallel-s0", "parallel-s1"):
            old = files[f"{sub}/stack-trace-r0/summary.json"]
            new = files[f"{sub}/stack-trace-r1/summary.json"]
            for field in ("t0_ns", "sender_start_ns", "window_end_ns"):
                new[field] = old[field]
        self.assertFalse(M.proof_evaluate(files, "t", 5, M.PROOF_PAIRS)["passed"])

    def test_proof_transfer_needs_matching_endpoint_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            rd = make_run(tmp, "rate", {"gate": "proof-rate"})
            for fname in ("snd.jsonl", "rcv.jsonl"):
                p = rd / fname
                rows = A.read_jsonl(p)
                rows[-1].update(bytes=1024, backend="kernel")
                p.write_text("".join(json.dumps(row) + "\n" for row in rows))
            summary = A.summarize_run(rd)
            self.assertTrue(summary["valid"])
            self.assertEqual(summary["proof_meta_sha256"], fixture_meta_digest(json.loads((rd / "meta.json").read_text())))
            rows[-1]["bytes"] = 1025
            p.write_text("".join(json.dumps(row) + "\n" for row in rows))
            self.assertFalse(A.summarize_run(rd)["valid"])

    def test_limits_at_their_bounds(self):
        it, r = self.items()
        self.assertTrue(r["passed"], [k for k, v in it.items() if not v])
        self.assertFalse(self.items(par_ping=20.21)[0][(1, "median_ms", 0)])
        self.assertFalse(self.items(par_goodput=101.01)[0][(2, "goodput_bps", 1)])
        self.assertFalse(self.items(par_backlog=102.01)[0][(4, "backlog_max", 0)])

    def test_lateness(self):
        # p99: one log2 bucket higher passes (the histogram's resolution), two fail.
        self.assertTrue(self.items(par_p99_bucket=17)[0][("stack", "lateness_p99_ns", 1)])
        self.assertFalse(self.items(par_p99_bucket=18)[0][("stack", "lateness_p99_ns", 1)])
        # max: exact, <= 2x.
        self.assertTrue(self.items(par_max=2_000_000)[0][("stack", "lateness_max_ns", 0)])
        self.assertFalse(self.items(par_max=2_000_001)[0][("stack", "lateness_max_ns", 0)])

    def test_bucket_comparison(self):
        self.assertTrue(M.lateness_p99_ok(65535, 131071))
        self.assertFalse(M.lateness_p99_ok(65535, 131072))
        self.assertFalse(M.lateness_max_ok(0, 1))
        self.assertTrue(M.lateness_max_ok(0, 0))
        self.assertEqual(M.lateness_bucket(0), 0)
        self.assertEqual(M.lateness_bucket(65535), 16)
        self.assertEqual(M.lateness_bucket(65536), 17)

    def test_histogram_percentile_rank_correction_and_clamp(self):
        # 0.07 * 100 is 7.000000000000001 in binary floating point: rank 7.
        self.assertEqual(M.hist_percentile({0: 7, 5: 93}, 0.07), 0)
        self.assertEqual(M.hist_percentile({0: 7, 5: 93}, 0.08), 31)
        self.assertEqual(M.hist_percentile({3: 1}, 0.99), 7)
        self.assertEqual(M.hist_percentile({3: 1}, 0.99, max_ns=5), 5)


class PlanLabels(unittest.TestCase):
    PLAN = PLAN + """
[[algo]]
cc = "cubic"
profile = "rfc"
impls = ["utcp"]
[[algo]]
cc = "cubic"
profile = "rfc"
stack_set = ["recovery_reduction=prr"]
impls = ["utcp"]
"""

    def plan(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "plan.toml"
            p.write_text(text)
            return M.load_plan(p)

    def test_two_stack_variants_of_one_cc_are_two_algorithms(self):
        runs = M.expand_plan(self.plan(self.PLAN))
        self.assertEqual(len({r["run"] for r in runs}), len(runs))
        labels = sorted({r["algo"] for r in runs if r["cc"] == "cubic"})
        self.assertEqual(labels[:2], ["cubic", "cubic-rfc"])
        self.assertRegex(labels[2], r"^cubic-rfc-[0-9a-f]{8}$")
        prr = [r for r in runs if r["algo"] == labels[2]]
        self.assertTrue(all(r["stack_set"] == ["recovery_reduction=prr"] for r in prr))
        self.assertTrue(all(r["run"].startswith(f"{r['cell']}-{labels[2]}-r") for r in prr))

    def test_a_label_may_not_repeat_for_one_implementation(self):
        with self.assertRaises(ValueError):
            self.plan(PLAN + '[[algo]]\ncc = "cubic"\nimpls = ["linux"]\n')
        # cubic for the stack only next to cubic for Linux only is one pair.
        self.plan(PLAN.replace('impls = ["linux"]', 'impls = ["linux"]\n[[algo]]\ncc = "cubic"\nimpls = ["utcp"]'))
        with self.assertRaises(ValueError):
            self.plan(PLAN + '[[algo]]\ncc = "cubic"\nname = "a b"\n')

    def test_cells_and_plots_group_by_the_label(self):
        def pairs(algo, scale):
            return [({"impl": "utcp", "cell": "c", "algo": algo, "cc": "cubic", "run": f"{algo}-{r}", "order": r,
                      "group": r, "loss_pct": 0, "reuse_key": "k"},
                     {"valid": True, "goodput_bps": scale + r, "retrans_pct": 0.0}) for r in range(5)]
        rows = A.cell_rows(pairs("cubic-rfc", 10) + pairs("cubic-rfc-abcd1234", 20))
        self.assertEqual([(r["algo"], r["goodput_bps_median"]) for r in rows],
                         [("cubic-rfc", 12), ("cubic-rfc-abcd1234", 22)])


class ResumeKeys(unittest.TestCase):
    def test_stale_groups_and_their_reruns(self):
        groups = {0: [{"run": "c-cubic-r0-utcp"}, {"run": "c-cubic-r0-linux"}],
                  1: [{"run": "c-cubic-r1-utcp"}, {"run": "c-cubic-r1-linux"}]}
        existing = {"c-cubic-r0-utcp": "new", "c-cubic-r0-linux": "new", "c-cubic-r1-utcp": "new",
                    "c-cubic-r1-linux": "new", "c-cubic-r1-linux-rerun1": "old", "c-cubic-r10-utcp": "old",
                    "c-cubic-r0-utcp-x": None}
        self.assertEqual(M.stale_groups(groups, existing, lambda g: "new"),
                         {1: ["c-cubic-r1-utcp", "c-cubic-r1-linux", "c-cubic-r1-linux-rerun1"]})
        self.assertEqual(set(M.stale_groups(groups, existing, lambda g: "old")), {0, 1})

    def test_cells_with_two_reuse_keys_are_marked(self):
        pairs = []
        for r in range(5):
            for impl in ("utcp", "linux"):
                pairs.append(({"impl": impl, "cell": "c", "cc": "cubic", "run": f"{impl}{r}", "order": 2 * r,
                               "group": r, "loss_pct": 0, "reuse_key": "a" if r < 4 else "b"},
                              {"valid": True, "goodput_bps": 1.0}))
        rows = A.cell_rows(pairs)
        self.assertEqual({r["status"] for r in rows}, {"mixed reuse keys"})
        self.assertEqual(rows[0]["gap_goodput_bps"], "n/a")

    def test_gate_acceptance(self):
        items = []
        for bw in (10, 100):
            for rtt in (20, 100):
                for q in (0.5, 2):
                    cell = dict(bw=bw, rtt=rtt, queue_bdp=q, ok=True)
                    items.append(dict(cell, item=1, run=f"ping-{bw}-{rtt}-{q:g}"))
                    for i in (2, 4, 5):
                        items.append(dict(cell, item=i, run=f"rate-{bw}-{rtt}-{q:g}"))
                    for loss in (0.1, 1):
                        for i in (3, 5):
                            items.append(dict(cell, item=i, loss_pct=loss, run=f"loss-{bw}-{rtt}-{q:g}-{loss:g}"))
        items.append(dict(item=6, part="ping", ok=True))
        for part in ("run", "path"):
            items.append(dict(item=6, part=part, ok=True, run="stack-100-20-2-" + part))
        sources = {"stack-ping/ping.json": "x", "stack-ping-kernel/ping.json": "x"}
        for row in items:
            row.update(slot=0, reuse_key="k1")
            if "run" in row:
                for leaf in (["ping.json"] if row["item"] == 1 else ["meta.json", "summary.json"]):
                    sources[row["run"] + "/" + leaf] = "x"
        g = {"slot": 0, "schema": 2, "cpusets": fixture_cpus(0), "sources": sources,
             "passed": True, "reuse_keys": ["k1"], "items": items}
        self.assertIsNone(M.gate_rejects(g, 0, "k1"))
        for rows in ([], items[:8] + items[-3:], items[:-3], items[:-1] + [items[-2]],
                     [dict(items[0], ok=False)] + items[1:], [dict(items[0], slot=1)] + items[1:],
                     [dict(items[0], reuse_key="k2")] + items[1:],
                     [items[0], dict(items[1], run="rate-100-100-2")] + items[2:]):
            with self.subTest(rows=len(rows), first=rows[:2]):
                self.assertIsNotNone(M.gate_rejects(dict(g, items=rows), 0, "k1"))
        self.assertIsNotNone(M.gate_rejects(g, 1, "k1"))
        self.assertIsNotNone(M.gate_rejects(g, 0, "k2"))
        self.assertIsNotNone(M.gate_rejects(dict(g, passed=False), 0, "k1"))
        self.assertIsNotNone(M.gate_rejects(dict(g, reuse_keys=["k1", "k2"]), 0, "k1"))
        self.assertIsNotNone(M.gate_rejects(None, 0, "k1"))


class FakeSlot:
    def __init__(self, n, timing):
        self.n, self.timing = n, timing
        self.cpus = fixture_cpus(n)
        self.snd = f"s{n}-snd"

    def slot_cpus(self):
        return ("8-11" if self.n == 0 else "12-15") if self.timing else "16-31"


class CalibrationEvidence(unittest.TestCase):
    def test_archived_rate_requires_both_endpoint_starts(self):
        # m2d-testbed/calib-s1/rate-100-20-2: original endpoint records and
        # samples on both sides of warm-up, sender stop and receiver start + S.
        rows = A.read_jsonl(Path(__file__).parent / "testdata/calibration-rate-endpoints.jsonl")
        receiver = 577768819454879
        sender = 577768799405294
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "meta.json").write_text(json.dumps(dict(gate="rate", impl="linux", duration_s=30)))

            def write(role, records):
                file = "snd.jsonl" if role == "sender" else "rcv.jsonl"
                (d / file).write_text("".join(json.dumps(r) + "\n" for r in records))

            for role in ("sender", "receiver"):
                write(role, [r for r in rows if r["role"] == role])
            control = A.summarize_run(d)
            self.assertTrue(control["valid"], control["invalid"])
            self.assertEqual(control["window_end_ns"], sender + 30 * NS)
            self.assertAlmostEqual(control["goodput_bps"], 95625506.52316622)
            for role in ("sender", "receiver"):
                records = [r for r in rows if r["role"] == role]
                start, *rest = records
                self.assertEqual(start["ev"], "start")
                for label, starts in [
                        ("missing start", []), ("missing time", [{"ev": "start", "role": role}]),
                        ("wrong type", [dict(start, t=str(start["t"]))]), ("boolean", [dict(start, t=True)]),
                        ("wrong role", [dict(start, role="other")]), ("ambiguous", [start, start])]:
                    with self.subTest(role=role, defect=label):
                        write(role, starts + rest)
                        result = A.summarize_run(d)
                        self.assertFalse(result["valid"])
                        self.assertIsNone(result.get("goodput_bps"))
                for label, edge in (("warm-up", receiver + 5 * NS), ("stop", sender + 30 * NS)):
                    with self.subTest(role=role, missing_sample_at=label):
                        samples = [r for r in rest if r["ev"] == "sample" and
                                   (r["t"] > edge if label == "warm-up" else r["t"] < edge)]
                        write(role, [start, *samples, rest[-1]])
                        self.assertFalse(A.summarize_run(d)["valid"])
                write(role, records)
            for invalid_start in (receiver - 25 * NS, receiver + 6 * NS):
                with self.subTest(sender_start=invalid_start):
                    records = [dict(r, t=invalid_start) if r["ev"] == "start" else r
                               for r in rows if r["role"] == "sender"]
                    write("sender", records)
                    self.assertFalse(A.summarize_run(d)["valid"])

    def test_production_gate_and_source_inventory(self):
        slot = FakeSlot(0, True)
        slot.stack_ip = "stack"
        store = {}
        defect = {}

        def send(slot, campaign, run, spec, smeta):
            bw, rtt, q = (spec[k] for k in ("bw", "rtt", "queue_bdp"))
            size = int(bw * 1e6 * rtt / 1000 * q / 8)
            meta = dict(spec, reuse_key="key", run=run, campaign=campaign, slot=0, timing=True,
                        cpusets=slot.cpus, slot_cpus="8-11", queue_bytes=size, duration_s=spec["duration"], sender_exit=0)
            cap = {}
            for name in ("r1-in", "r1-out", "r2-out"):
                count = 100000 if name == "r1-in" else 100000 - round(1000 * spec["loss"])
                cap[name] = dict(data_segs=count, captured=count, received_by_filter=count, kernel_dropped=0)
            row = dict(run=run, valid=True, invalid=[], sender_ccs=[spec["cc"]], goodput_bps=bw * 0.95e6,
                       t0_ns=T0, sender_start_ns=T0 - 20_000_000,
                       window_end_ns=T0 - 20_000_000 + spec["duration"] * NS,
                       capture=cap, local_drops={}, time_squeeze=0, stack_device={}, stack_local_drops={},
                       ack_path={"r1_a": {"dropped": 0}, "r2_b": {"dropped": 0}}, tbf={"dropped": 0},
                       netem={"dropped": 0}, queue={"reaches": True, "backlog_max": size, "drop_intervals_low": 0},
                       ping_base_ms=rtt, ping_max_ms=rtt + M.ping_target_ms(size, bw))
            if run == defect.get("run"):
                row.update(defect.get("row", {}))
                meta.update(defect.get("meta", {}))
            row["proof_meta_sha256"] = fixture_meta_digest(meta)
            for leaf, data in (("meta", meta), ("summary", row)):
                store[f"/data/m2/{campaign}/{run}/{leaf}.json"] = json.dumps(data)
            return meta, row

        def ping(slot, campaign, run, spec, **kwargs):
            rtt = (spec or {"rtt": 20})["rtt"]
            return dict(requests_seen=200, n=200, lost=0, median_ms=rtt + 0.1, p99_ms=rtt + 0.2)

        with ExitStack() as st:
            for name, fn in dict(one_run=send, ping_only=ping, vol_write=lambda c,p,t: store.update({p:t}),
                                 read_volume=lambda c,p:store.get(p)).items():
                st.enter_context(mock.patch.object(M, name, side_effect=fn))
            for name, val in dict(log=None, tb="", dexec="", dexec_bg=None,
                                  static_meta={"uname_r":"test","commit":"test"}, current_key="key").items():
                st.enter_context(mock.patch.object(M, name, return_value=val))
            st.enter_context(mock.patch.object(M.time, "sleep"))
            gate = M.calibrate(slot, "t", M.PAIRS)
            self.assertTrue(gate["passed"], gate["reject_reason"])
            self.assertEqual(len(gate["items"]), 67)
            self.assertEqual(M.check_gate(slot, ["t"], "key"), "t")
            # A previous producer could attest a summary with the drain included.
            path = "rate-10-20-2/summary.json"
            old = json.loads(store[f"/data/m2/t/{path}"])
            old.update(sender_start_ns=None, window_end_ns=T0 + 30 * NS)
            store[f"/data/m2/t/{path}"] = json.dumps(old)
            prior = json.loads(store["/data/m2/t/gate.json"])
            prior["sources"][path] = fixture_meta_digest(old)
            store["/data/m2/t/gate.json"] = json.dumps(prior)
            with self.assertRaisesRegex(RuntimeError, "window"):
                M.check_gate(slot, ["t"], "key")
            store["/data/m2/t/gate.json"] = json.dumps(gate)
            del store["/data/m2/t/rate-10-20-2/summary.json"]
            with self.assertRaisesRegex(RuntimeError, "missing or changed"):
                M.check_gate(slot, ["t"], "key")
            for name, row, meta in [
                    ("rate-10-20-2", {"sender_start_ns": None}, {}),
                    ("loss-100-100-2-1", {"t0_ns": None}, {}),
                    ("stack-100-20-2-path", {"window_end_ns": None}, {}),
                    ("rate-10-20-0.5", {"window_end_ns": T0 + 30 * NS}, {}),
                    ("rate-10-20-2", {"valid": False, "invalid": ["sha256 differs"]}, {}),
                    ("rate-10-20-2", {"ack_path": {}}, {}), ("rate-10-20-2", {"local_drops": None}, {}),
                    ("rate-10-20-2", {"capture": {}}, {}), ("rate-10-20-0.5", {"goodput_bps": float("inf")}, {}),
                    ("rate-10-20-2", {}, {"slot": 1}), ("stack-100-20-2-run", {"sender_ccs": ["cubic"]}, {})]:
                with self.subTest(run=name, row=row, meta=meta):
                    defect.update(run=name, row=row, meta=meta)
                    result = M.calibrate(slot, "t", M.PAIRS)
                    self.assertFalse(result["passed"])
                    self.assertTrue(any(i.get("run") == name and not i["ok"] for i in result["items"]))
            bad_cpus = dict(slot.cpus)
            bad_cpus["s0-r1"], bad_cpus["s0-rcv"] = bad_cpus["s0-rcv"], bad_cpus["s0-r1"]
            for cpus in (bad_cpus, {k:"16-31" for k in slot.cpus}):
                self.assertIsNotNone(M.gate_rejects(dict(gate, cpusets=cpus), 0, "key"))
            for field in ("slot", "reuse_key"):
                saved = gate["items"][0].pop(field)
                self.assertIsNotNone(M.gate_rejects(gate, 0, "key"))
                gate["items"][0][field] = saved


class ProofPhase(unittest.TestCase):
    def phase(self, phase, one, cached=None, old_config=None, ping=None):
        slots = [FakeSlot(n, True) for n in ([0, 1] if phase == "parallel" else [0])]
        for slot in slots:
            slot.cleanup = mock.Mock()
        store = dict(cached or {})
        if old_config:
            store["/data/m2/t/proof-config.json"] = json.dumps(old_config)
        with ExitStack() as st:
            patch = lambda name, **kw: st.enter_context(mock.patch.object(M, name, **kw))
            patch("static_meta", return_value={})
            st.enter_context(mock.patch.object(Path, "read_text", return_value="boot"))
            patch("current_key", return_value="key")
            patch("dexec", return_value="")
            patch("read_volume", side_effect=lambda _, path: store.get(path))
            patch("vol_write", side_effect=lambda _, path, text: store.update({path: text}))
            patch("ping_only", side_effect=ping, return_value={"median_ms": 20, "p99_ms": 21})
            patch("one_run", side_effect=one)
            patch("log")
            M.proof_phase("t", phase, slots, 1, [(100, 20)], "cubic")
        return store

    def test_all_parallel_transfers_rendezvous_and_resume_together(self):
        calls = []
        def one(slot, sub, name, spec, smeta, sender_barrier):
            calls.append((slot.n, name, sender_barrier is not None))
            if sender_barrier:
                sender_barrier.wait(timeout=2)
            return {}, {"valid": True}
        store = self.phase("parallel", one)
        self.assertCountEqual(calls, [(n, name, sync) for n in (0, 1)
                             for name, sync in (("rate-100-20-2-r0", True), ("stack-trace-r0", True))])
        self.assertEqual(json.loads(store["/data/m2/t/parallel-s1/ping-100-20-2-r0/ping.json"])["slot"], 1)
        calls.clear()
        self.phase("serial", one)
        self.assertCountEqual(calls, [(0, n, False) for n in ("rate-100-20-2-r0", "stack-trace-r0", "stack-notrace-r0")])

    def test_resuming_parallel_recollects_only_the_broken_pair(self):
        full = proof_files(stack_cc="cubic")
        full.pop("proof-config.json")
        cached = {"/data/m2/t/" + path: json.dumps(value) for path, value in full.items()}
        config = dict(M.proof_config(1, [(100, 20)], "cubic"), reuse_key="key")
        for name, leaf, torn in (("ping-100-20-2-r0", "ping.json", True),
                                 ("rate-100-20-2-r0", "summary.json", False),
                                 ("stack-trace-r0", "meta.json", False)):
            with self.subTest(name=name):
                records = dict(cached)
                path = f"/data/m2/t/parallel-s1/{name}/{leaf}"
                if torn:
                    records[path] = '{"n":20'
                else:
                    del records[path]
                calls = []
                def send(slot, sub, run, spec, smeta=None, sender_barrier=None):
                    sender_barrier.wait(timeout=2)
                    calls.append((slot.n, run))
                    return ({}, {}) if smeta else {"n":200, "lost":0, "median_ms":20.1, "p99_ms":20.2}
                self.phase("parallel", send, records, config, send)
                self.assertCountEqual(calls, [(0, name), (1, name)])
        self.phase("parallel", self.fail, cached, config, self.fail)

    def test_real_sender_command_and_launch_barrier(self):
        slot = FakeSlot(0, True)
        slot.r1, slot.r2, slot.rcv = "s0-r1", "s0-r2", "s0-rcv"
        slot.containers = lambda: {k: getattr(slot, k) for k in ("snd", "r1", "r2", "rcv")}
        slot.ifs = dict(r1_a="eth0", r1_b="eth1", r2_c="eth1")
        slot.rcv_ip, slot.snd_ip, slot.stack_ip = "receiver", "sender", "stack"
        slot.cleanup, slot.gso_ipv4_max_size = lambda: None, lambda: 65536
        shape = ("shape: slot 0 queue_bytes 500000 burst_bytes 12500 bdp_bytes 250000\n"
                 "shape: r1 root netem delay 20ms\nshape: r2 root tbf rate 100mbit\n")
        for cc in ("newreno", "cubic"):
            events = []
            barrier = SimpleNamespace(wait=lambda **kwargs: events.append("ready"))
            def command(argv, **kwargs):
                args = shlex.split(argv[-1])
                self.assertEqual(args[args.index("--cc") + 1], cc)
                events.append("send")
                return SimpleNamespace(returncode=0)
            with ExitStack() as st:
                for name in ("sh", "dexec", "dexec_bg", "vol_write", "wait_for", "log"):
                    st.enter_context(mock.patch.object(M, name, return_value=""))
                st.enter_context(mock.patch.object(M, "tb", side_effect=lambda name,*args: shape if name=="shape.sh" else ""))
                st.enter_context(mock.patch.object(M, "run_analysis", return_value="{}"))
                st.enter_context(mock.patch.object(M.time, "sleep"))
                st.enter_context(mock.patch.object(M.subprocess, "run", side_effect=command))
                _, name, spec = M.proof_list(1, (), False, cc)[0]
                meta, _ = M.one_run(slot, "t", name, spec, {"boot_id":"boot"}, sender_barrier=barrier)
                self.assertEqual(meta["cc"], cc)
                self.assertEqual(events, ["ready", "send"])

    def test_ping_attempt_archival_and_atomic_markers(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            path = root / "t/ping"
            path.mkdir(parents=True)
            for name, data in (("ping.json", '{"n":20'), ("ping.pcap", "partial pcap"), ("ping.txt", "partial text")):
                (path / name).write_text(data)
            def shell(script, data=None):
                return subprocess.run(["bash", "-c", script.replace("/data/m2", t)], input=data, text=True,
                                      capture_output=True, check=True).stdout
            with mock.patch.object(M, "dexec", side_effect=lambda _,script:shell(script)):
                M.prepare_trial(FakeSlot(0, True), "t", "ping")
            backups = list((root / "t/aside").glob("*/raw"))
            self.assertEqual(len(backups), 1)
            self.assertEqual((backups[0] / "ping.pcap").read_text(), "partial pcap")
            self.assertEqual((backups[0] / "ping.json").read_text(), '{"n":20')
            self.assertEqual(list(path.iterdir()), [])
            shell(M.publish_script("/data/m2/t/ping/ping.json"), '{"n":200}')
            self.assertEqual(json.loads((path / "ping.json").read_text()), {"n":200})
            with mock.patch.object(M, "sh", return_value='### serial-s0/ping-10-20-2-r0/ping.json\n{"n":20\n'):
                files = M.proof_files("t")
            result = M.proof_evaluate(files, "t", 1, [(10,20)])
            self.assertIn("unreadable JSON", result["evidence_errors"]["serial-s0/ping-10-20-2-r0"])

    def test_sibling_setup_failure_releases_paired_sender(self):
        entered, released = threading.Event(), threading.Event()
        def one(slot, sub, name, spec, smeta, sender_barrier):
            if sender_barrier:
                if slot.n == 0:
                    entered.set()
                    try:
                        sender_barrier.wait(timeout=2)
                    except threading.BrokenBarrierError:
                        released.set()
                        raise
                else:
                    self.assertTrue(entered.wait(timeout=2))
                    raise RuntimeError("receiver failed to start")
            return {}, {}
        with self.assertRaisesRegex(RuntimeError, "receiver failed to start"):
            self.phase("parallel", one)
        self.assertTrue(released.is_set())

    def test_refuses_reusing_newreno_and_overwriting_archived_reports(self):
        with self.assertRaisesRegex(RuntimeError, "new campaign"):
            self.phase("serial", None, old_config={"stack_cc": "newreno"})
        with mock.patch.object(M, "proof_files", return_value={}), mock.patch.object(M, "sh") as write:
            with self.assertRaisesRegex(RuntimeError, "archived"):
                M.proof_report("t", 5, M.PROOF_PAIRS)
            write.assert_not_called()


class RunnerRefusals(unittest.TestCase):
    def test_two_slots_and_non_timing_slots_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "plan.toml"
            p.write_text(PLAN)
            with self.assertRaisesRegex(RuntimeError, "serial"):
                M.run_plan(p, [FakeSlot(0, True), FakeSlot(1, True)], no_gate=True)
            with self.assertRaisesRegex(RuntimeError, "not a timing slot"):
                M.run_plan(p, [FakeSlot(2, False)], no_gate=True)


class RunPlanGroups(unittest.TestCase):
    """run_plan with the docker calls replaced: group reruns, resume, the rerun
    cap and the reuse-key refusal."""
    PLAN = 'campaign = "t/p"\nseed = 3\nreps = 2\n[[cell]]\nbw = 10\nrtt = 20\nqueue_bdp = 2\n[[algo]]\ncc = "newreno"\n'

    def run_plan(self, invalid, existing=None, rekey=False):
        done, calls, cmds = self.done, [], []

        def one_run(slot, campaign, name, spec, smeta):
            calls.append((name, spec["rerun"], spec["order"], spec["group"]))
            s = {"valid": not invalid(name)}
            done[name] = s
            return {}, s
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "plan.toml"
            p.write_text(self.PLAN)
            with mock.patch.multiple(M, static_meta=lambda: {}, current_key=lambda s, m: "k", log=lambda *a: None,
                                     read_volume=lambda s, path: None, vol_write=lambda *a: None,
                                     dexec=lambda c, cmd, **kw: cmds.append(cmd) or "",
                                     campaign_keys=lambda s, c: dict(existing or {}),
                                     run_done=lambda s, c, name: done.get(name), one_run=one_run):
                errors = M.run_plan(p, [FakeSlot(0, True)], no_gate=True, rekey=rekey)
        self.assertEqual(errors, [])
        return calls, cmds

    def setUp(self):
        self.done = {}
        self.runs = M.expand_plan(M.load_plan(self._plan_path()))

    def _plan_path(self):
        d = tempfile.mkdtemp()
        p = Path(d) / "plan.toml"
        p.write_text(self.PLAN)
        return p

    def test_an_invalid_group_is_rerun_whole_and_back_to_back(self):
        first = self.runs[0]["run"]
        calls, _ = self.run_plan(lambda name: name == first)
        names = [c[0] for c in calls]
        g0 = [r["run"] for r in self.runs if r["group"] == 0]
        g1 = [r["run"] for r in self.runs if r["group"] == 1]
        self.assertEqual(names, g0 + [n + "-rerun1" for n in g0] + g1)
        self.assertEqual([c[1] for c in calls], [0, 0, 1, 1, 0, 0])
        self.assertEqual(calls[2][2], self.runs[0]["order"])   # a rerun keeps its run's order
        # Resuming runs nothing.
        calls, _ = self.run_plan(lambda name: name == first)
        self.assertEqual(calls, [])

    def test_the_rerun_cap_per_cell_and_algorithm(self):
        calls, _ = self.run_plan(lambda name: True)
        # Group 0: the run and 3 reruns (4 invalid groups > 3); group 1: no rerun left.
        self.assertEqual([c[1] for c in calls], [0, 0, 1, 1, 2, 2, 3, 3, 0, 0])

    def test_runs_with_another_reuse_key_are_refused_or_moved_aside(self):
        old = {self.runs[0]["run"]: "old", self.runs[1]["run"]: "k"}
        self.done[self.runs[0]["run"]] = {"valid": True}
        self.done[self.runs[1]["run"]] = {"valid": True}
        with self.assertRaisesRegex(RuntimeError, "another reuse key"):
            self.run_plan(lambda name: False, existing=old)
        self.done.clear()
        calls, cmds = self.run_plan(lambda name: False, existing=old, rekey=True)
        self.assertTrue(any(f"mv {self.runs[0]['run']} aside/" in c and f"mv {self.runs[1]['run']} aside/" in c
                            for c in cmds), cmds)
        self.assertEqual(len(calls), 4)

class DropTargets(unittest.TestCase):
    ISN = 0xFFFFF000  # stream offsets wrap the sequence space

    def pkts(self, offs_lens):
        return [{"seq": (self.ISN + 1 + o) % 2**32, "len": n} for o, n in offs_lens]

    def test_ranges_are_cut_at_the_next_offset(self):
        self.assertEqual(D.target_ranges("1448000"), [(1448000, 1449448, 1)])
        self.assertEqual(D.target_ranges("5000:5,1000,2000:2", 1460),
                         [(1000, 2000, 1), (2000, 4920, 2), (5000, 12300, 5)])
        with self.assertRaises(ValueError):
            D.target_ranges("1000,1000")

    def test_a_short_segment_moves_the_boundary_and_the_next_start_is_latched(self):
        # 1448-byte segments, then 512 bytes at 2896: later starts are 3408 +
        # 1448k, so offset 4344 is no boundary; the rule latches 4856.
        segs = [(0, 1448), (1448, 1448), (2896, 512), (3408, 1448), (4856, 1448), (6304, 1448)]
        self.assertEqual(D.latched(self.pkts(segs), self.ISN, D.target_ranges("4344")), [[4856]])
        # On a boundary the boundary itself.
        self.assertEqual(D.latched(self.pkts(segs), self.ISN, D.target_ranges("3408")), [[3408]])

    def test_only_the_first_start_and_its_copies_count_and_pure_acks_never(self):
        # Two starts in one range (a short segment): only the first is latched;
        # its retransmission is a copy, not a new start; a pure ACK at an
        # offset in the range is ignored.
        segs = [(0, 0), (0, 1000), (1000, 1448), (0, 1000)]
        self.assertEqual(D.latched(self.pkts(segs), self.ISN, D.target_ranges("0")), [[0]])

    def test_a_burst_latches_n_consecutive_starts(self):
        segs = [(0, 1448), (1448, 512), (1960, 1448), (3408, 1448), (4856, 1448), (6304, 1448), (7752, 1448)]
        self.assertEqual(D.latched(self.pkts(segs), self.ISN, D.target_ranges("1000:5")),
                         [[1448, 1960, 3408, 4856, 6304]])
        # A retransmission before the 5th start is not a new start.
        segs2 = segs[:3] + [(1448, 512)] + segs[3:]
        self.assertEqual(D.latched(self.pkts(segs2), self.ISN, D.target_ranges("1000:5")),
                         [[1448, 1960, 3408, 4856, 6304]])


if __name__ == "__main__":
    unittest.main(verbosity=1)
