#!/usr/bin/env python3
"""Fixture checks of m1_pcap_summary.py (ctest interop.m1_pcap_summary_check).

Runs the summary over hand-written tshark field lines and checks:
- the RST exemption of fin_ok (rst_after_close, rst_open): only an RST
  without ACK, sent after both FINs and after this sender's FIN was ACKed,
  with SEG.SEQ at the end of that FIN, is the answer to a segment after the
  close (RFC 9293 §3.10.7.1; interop case A-N3-l2s). An RST on an open
  connection, an RST|ACK, an RST with another sequence number or one sent
  before the FIN was ACKed stays rst_open;
- edge_retreats: the right window edge (SEG.ACK + window << shift) moving
  back is counted, a reordered ACK is not;
- stack_over_len_after_icmp*: segments longer than LEN after the first
  frag-needed to the stack, the new-data ones, and the time to the last.

Usage: m1_pcap_summary_check.py   (prints one line per check, exit 1 on failure)
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
STACK, PEER = "198.18.0.2", "198.19.1.3"
SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08
failures = 0


def seg(t, src, flags, seq, ack, ln=0, win=512, wscale="", mss=""):
    """One TCP_FIELDS line (field order of m1_pcap_summary.py)."""
    dst = PEER if src == STACK else STACK
    sport, dport = (5001, 40000) if src == STACK else (40000, 5001)
    sack_perm = "1" if flags & SYN else ""
    return ";".join(str(x) for x in (
        f"{t:.6f}", src, dst, sport, dport, f"0x{flags:04x}", ln, win, mss, sack_perm, "",
        wscale, "", 0, 1, seq, ack if flags & ACK else ""))


def summary(tcp_lines, icmp_lines=(), length=None):
    with tempfile.TemporaryDirectory() as d:
        paths = [os.path.join(d, n) for n in ("tcp.txt", "icmp.txt", "err.txt")]
        for p, lines in zip(paths, (tcp_lines, icmp_lines, ())):
            with open(p, "w") as f:
                f.write("".join(ln + "\n" for ln in lines))
        args = [sys.executable, "-I", os.path.join(HERE, "m1_pcap_summary.py"), STACK, *paths]
        if length is not None:
            args.append(str(length))
        return json.loads(subprocess.run(args, check=True, capture_output=True, text=True).stdout)


def expect(name, got, want):
    global failures
    ok = got == want
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} {name}: {got!r}" + ("" if ok else f" (want {want!r})"))


# Linux (PEER) sends 1000 bytes to the stack, which is the passive side.
# Linux ISS 1000, stack ISS 5000. Linux closes first; the stack ACKs and
# sends its FIN (LAST-ACK); Linux ACKs it.
def transfer():
    return [
        seg(0.000, PEER, SYN, 1000, 0, wscale=7),
        seg(0.001, STACK, SYN | ACK, 5000, 1001, wscale=10),
        seg(0.002, PEER, ACK, 1001, 5001),
        seg(0.003, PEER, ACK | PSH, 1001, 5001, ln=1000),
        seg(0.004, STACK, ACK, 5001, 2001),
    ]


def closed():
    return transfer() + [
        seg(0.005, PEER, FIN | ACK, 2001, 5001),
        seg(0.006, STACK, FIN | ACK, 5001, 2002),
        seg(0.007, PEER, ACK, 2002, 5002),
    ]


def rst_counts(lines):
    st = summary(lines)["by"]["stack"]
    return st["rst"], st["rst_after_close"], st["rst_open"]


# 1. netem duplicated Linux's last ACK; the stack had closed on the first
#    copy and answered the second with <SEQ=SEG.ACK><CTL=RST>: exempt.
expect("rst answering a duplicate last ACK",
       rst_counts(closed() + [seg(0.008, PEER, ACK, 2002, 5002), seg(0.009, STACK, RST, 5002, 0)]),
       (1, 1, 0))
# 2. An RST in the middle of the transfer.
expect("rst mid-transfer", rst_counts(transfer() + [seg(0.005, STACK, RST, 5001, 0)]), (1, 0, 1))
# 3. RST|ACK after the close.
expect("rst|ack after the close",
       rst_counts(closed() + [seg(0.008, STACK, RST | ACK, 5002, 2002)]), (1, 0, 1))
# 4. RST after the close with a sequence number other than the FIN's end.
expect("rst after the close, wrong seq",
       rst_counts(closed() + [seg(0.008, STACK, RST, 5001, 0)]), (1, 0, 1))
# 5. RST after both FINs, but the stack's FIN was never ACKed.
expect("rst before the stack's FIN was ACKed",
       rst_counts(transfer() + [seg(0.005, PEER, FIN | ACK, 2001, 5001),
                                seg(0.006, STACK, FIN | ACK, 5001, 2002),
                                seg(0.008, STACK, RST, 5002, 0)]), (1, 0, 1))
# 6. fin_acked on a clean close, no RST.
by = summary(closed())["by"]
expect("clean close fin/fin_acked/rst_open",
       (by["stack"]["fin"], by["stack"]["fin_acked"], by["remote"]["fin_acked"],
        by["stack"]["rst_open"], by["remote"]["rst_open"]), (1, True, True, 0, 0))

# Right window edge, the stack's shift 10: 5000+1 is ISS+1; edges as
# ack + win * 1024. ACK 2001 win 3 -> 5073; ACK 2401 win 2 -> 4449 (back
# 624 bytes); ACK 2201 (reordered, lower ACK) win 0 -> not counted;
# ACK 3001 win 3 -> 6073 (forward).
edge = transfer()[:4] + [
    seg(0.004, STACK, ACK, 5001, 2001, win=3),
    seg(0.005, STACK, ACK, 5001, 2401, win=2),
    seg(0.006, STACK, ACK, 5001, 2201, win=0),
    seg(0.007, STACK, ACK, 5001, 3001, win=3),
]
st = summary(edge)["by"]["stack"]
expect("edge retreats (count, largest)", (st["edge_retreats"], st["edge_retreat_max"]), (1, 624))

# PMTU: the stack sends 1448-byte segments; a frag-needed arrives at t=1.0;
# one more new 1448-byte segment follows 40 us later (sent before the stack
# read the ICMP), a retransmission of in-flight data at 1448 bytes, then
# 1348-byte segments.
pm = transfer()[:3] + [
    seg(0.500, STACK, ACK, 5001, 1001, ln=1448),
    seg(0.501, STACK, ACK, 6449, 1001, ln=1448),
    seg(1.000040, STACK, ACK, 7897, 1001, ln=1448),
    seg(1.000050, STACK, ACK, 5001, 1001, ln=1448),
    seg(1.000062, STACK, ACK, 9345, 1001, ln=1348),
]
icmp = [f"1.000000;198.18.0.1;{STACK};3;4;1400"]
s = summary(pm, icmp, 1348)
expect("over-length after the frag-needed (count, new, last dt)",
       (s["stack_over_len_after_icmp"], s["stack_over_len_after_icmp_new"],
        s["stack_over_len_after_icmp_last_dt"]), (2, 1, 5e-05))
expect("first 1348-byte segment after the frag-needed",
       (s["stack_first_len_t"] > s["icmp_frag_needed_to_stack_first_t"],
        s["stack_max_len_after_first_len"]), (True, -1))

print(f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
