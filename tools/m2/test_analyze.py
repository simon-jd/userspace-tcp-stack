#!/usr/bin/env python3
"""Unit tests of tools/m2/analyze.py on synthetic inputs with known answers
(M2-TASKS m2d-testbed test 6). Run: python3 -I tools/m2/test_analyze.py"""

import json
import math
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze as A  # noqa: E402

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


def record(label, extra_drops=0, squeeze=0, tbf_dropped=0, utcp_drop=0):
    def link(name, rxd=0, txd=0):
        return [f"2: {name}@if1: <BROADCAST,UP> mtu 1500 qdisc noqueue state UP",
                "    veth gso_max_size 65536 gso_ipv4_max_size 65536",
                "    RX:  bytes packets errors dropped  missed   mcast",
                f"        1000      10      0       {rxd}       0       0",
                "    TX:  bytes packets errors dropped carrier collsns",
                f"        1000      10      0       {txd}       0       0"]
    lines = [f"# {label} slot 0 now"]
    lines += ["== s-snd ip -s -d link"] + link("eth0", txd=extra_drops) + [
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
              " Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) ",
              " backlog 0b 0p requeues 0"]
    for c, devs in (("s-r1", ("eth0", "eth1")), ("s-r2", ("eth0", "eth1")), ("s-rcv", ("eth0",))):
        lines.append(f"== {c} ip -s -d link")
        for d in devs:
            lines += link(d)
        lines.append(f"== {c} tc -s -raw qdisc")
        for d in devs:
            kind = "noqueue"
            sent = "Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)"
            if c == "s-r1" and d == "eth1":
                kind = "netem"
                sent = "Sent 5000 bytes 50 pkt (dropped 3, overlimits 0 requeues 0)"
            if c == "s-r2" and d == "eth1":
                kind = "tbf"
                sent = f"Sent 4000 bytes 40 pkt (dropped {tbf_dropped}, overlimits 7 requeues 0)"
            lines += [f"qdisc {kind} 8001: dev {d} root refcnt 2 ", f" {sent} ", " backlog 0b 0p requeues 0"]
    lines.append("== host softnet_stat")
    for cpu in range(16):
        sq = squeeze if cpu == 8 else 0
        lines.append(f"{cpu} 00001000 00000000 {sq:08x} 0 0 0 0 0 0 0 0 0 {cpu:08x} 0 0")
    lines.append("== host /proc/stat")
    for cpu in range(16):
        lines.append(f"cpu{cpu} 100 0 50 1000 0 5 20 0 0 0")
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
            self.assertEqual(s["window_s"], 25.0)
            # Samples are at t0 + 3 ms + k*10 ms, so both bounds are interpolated.
            self.assertAlmostEqual(s["goodput_bps"], RATE * 8, delta=1.0)

    def test_retransmission_rate_and_spurious_over_the_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = A.summarize_run(make_run(tmp, "r0"))
            # 1000 data segments/s and 10 retransmissions/s in the window; the
            # drain's 100/s and slow start's are outside it.
            self.assertAlmostEqual(s["data_segs_out"], 25_000, delta=1)
            self.assertAlmostEqual(s["retrans_segs"], 250, delta=1)
            self.assertAlmostEqual(s["retrans_pct"], 1.0, delta=0.01)
            self.assertAlmostEqual(s["spurious_retrans"], 25, delta=1)

    def test_limited_time_fractions_and_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_run(tmp, "r0")
            lines = A.read_jsonl(d / "snd.jsonl")
            for x in lines:
                if x.get("ev") == "sample":
                    # sndbuf-limited 20 ms per second in the window (2 %), 1 ms/s rwnd (0.1 %).
                    sec = min(max((x["t"] - T0) / NS - 5, 0), S - 5)
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
        # The interval 10598 -> ... has a drop with 12112 at its end: fine.
        self.assertEqual(r["drop_intervals_low"], 0)
        s[3] = (s[3][0], 9000, 2)
        s[1] = (s[1][0], 6056, 0)
        s[2] = (s[2][0], 9000, 1)
        r = A.queue_check(s, q)
        # Each of the three drop intervals now has both bounds below 0.9*Q.
        self.assertEqual(r["drop_intervals_low"], 3)


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


def run_rec(impl, order, valid, name=None):
    return {"impl": impl, "order": order, "valid": valid, "run": name or f"{impl}-{order}"}


class RunCounting(unittest.TestCase):
    def test_first_five_valid_runs_per_side(self):
        runs = [run_rec("utcp", i, i != 2) for i in range(7)] + [run_rec("linux", i, True) for i in range(6)]
        counted, status = A.select_runs(runs)
        self.assertEqual([r["order"] for r in counted["utcp"]], [0, 1, 3, 4, 5])
        self.assertEqual([r["order"] for r in counted["linux"]], [0, 1, 2, 3, 4])
        self.assertEqual(status, "ok")

    def test_rerun_cap(self):
        # Three reruns (invalid runs) in the cell are allowed ...
        runs = [run_rec("utcp", i, i not in (0, 1)) for i in range(7)] + \
               [run_rec("linux", i, i != 3) for i in range(6)]
        self.assertEqual(A.select_runs(runs)[1], "ok")
        # ... a fourth makes the cell invalid, even with 5 valid runs per side.
        runs.append(run_rec("linux", 6, False))
        runs.append(run_rec("linux", 7, True))
        self.assertEqual(A.select_runs(runs)[1], "invalid (rerun cap)")

    def test_incomplete(self):
        runs = [run_rec("utcp", i, True) for i in range(4)] + [run_rec("linux", i, True) for i in range(5)]
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


if __name__ == "__main__":
    unittest.main(verbosity=1)
