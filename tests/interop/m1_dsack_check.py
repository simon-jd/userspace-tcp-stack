#!/usr/bin/env python3
"""Fixture checks of m1_dsack.py (ctest interop.m1_dsack_check).

Runs the D-SACK replay over hand-written tshark field lines and checks the
sender's retransmission count, which decides whether a D-SACK is dubious
(tcp_dsack_seen: dsack_dups > total_retrans):
- a retransmitted SYN counts (__tcp_retransmit_skb adds every retransmitted
  skb to total_retrans; interop case A-N4-l2s, verification run vrun, where
  the peer's first SYN was lost), and so does a retransmitted bare FIN;
- a zero-length segment without SYN or FIN (a window probe at SND.UNA-1)
  does not;
- a dubious D-SACK at or below SND.UNA is a predicted TCPSACKDiscard unless
  the ACK is older than an earlier one;
- on the receiver side a duplicated SYN is not a duplicated data segment.

Usage: m1_dsack_check.py   (prints one line per check, exit 1 on failure)
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
STACK, PEER = "198.18.0.2", "198.19.1.3"
SYN, ACK, FIN = 0x02, 0x10, 0x01
ISN = 1000
failures = 0


def seg(src, flags, seq, ack=0, ln=0, sack=()):
    """One line in m1_lib.sh m1_dsack's field order (raw sequence numbers)."""
    dst = PEER if src == STACK else STACK
    sport, dport = (5001, 40000) if src == STACK else (40000, 5001)
    le = ",".join(str(a) for a, _ in sack)
    re = ",".join(str(b) for _, b in sack)
    return ";".join(str(x) for x in (
        src, dst, sport, dport, f"0x{flags:04x}", seq, ln, ack if flags & ACK else 0, le, re))


def replay(sender_lines, receiver_lines=None):
    with tempfile.TemporaryDirectory() as d:
        args = [sys.executable, "-I", os.path.join(HERE, "m1_dsack.py"), PEER]
        for name, lines in (("s.txt", sender_lines), ("r.txt", receiver_lines)):
            if lines is None:
                continue
            p = os.path.join(d, name)
            with open(p, "w") as f:
                f.write("".join(ln + "\n" for ln in lines))
            args.append(p)
        return json.loads(subprocess.run(args, check=True, capture_output=True, text=True).stdout)


def expect(name, got, want):
    global failures
    ok = got == want
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} {name}: {got!r}" + ("" if ok else f" (want {want!r})"))


def data(i, flags=ACK):
    """The i-th 1000-byte data segment from the peer (i from 0)."""
    return seg(PEER, flags, ISN + 1 + 1000 * i, 5001, 1000)


def dsack_ack(ack, i):
    """A stack ACK carrying a D-SACK for data segment i, below the ACK."""
    lo = ISN + 1 + 1000 * i
    return seg(STACK, ACK, 5000, ack, sack=((lo, lo + 1000),))


def fields(r, *keys):
    return tuple(r["sender"].get(k) for k in keys)


# The peer's first SYN is lost and sent again; three data segments; the stack
# gets segments 0 and 1 twice (netem duplicates) and D-SACKs each. With the
# SYN counted, total_retrans is 1: the first D-SACK is not dubious, the second
# is (dsack_dups 2 > 1) and lies below SND.UNA, so it is a predicted discard.
handshake = [seg(PEER, SYN, ISN), seg(PEER, SYN, ISN), seg(STACK, SYN | ACK, 5000, ISN + 1)]
syn_rtx = handshake + [
    data(0), data(1), data(2),
    seg(STACK, ACK, 5001, ISN + 1001),
    dsack_ack(ISN + 1001, 0),
    seg(STACK, ACK, 5001, ISN + 2001),
    dsack_ack(ISN + 2001, 1),
    seg(STACK, ACK, 5001, ISN + 3001),
]
r = replay(syn_rtx)
expect("SYN retransmission counted (retrans, of them SYN/FIN)",
       fields(r, "retrans_segs", "retrans_syn_fin"), (1, 1))
expect("SYN retransmission: D-SACK ACKs, dubious, discard",
       fields(r, "dsack_acks", "pred_dubious", "pred_discard"), (2, 1, 1))

# Without the second SYN both D-SACKs are dubious and discarded.
r = replay([handshake[0]] + syn_rtx[2:])
expect("no SYN retransmission: retrans, dubious, discard",
       fields(r, "retrans_segs", "pred_dubious", "pred_discard"), (0, 2, 2))

# A bare FIN sent twice counts once as a retransmission; a window probe
# (zero length, ACK only, at SND.UNA-1) does not.
fin_rtx = [handshake[0], handshake[2],
           data(0), data(1),
           seg(PEER, ACK, ISN, 5001),
           seg(PEER, FIN | ACK, ISN + 2001, 5001),
           seg(PEER, FIN | ACK, ISN + 2001, 5001),
           dsack_ack(ISN + 2002, 0)]
r = replay(fin_rtx)
expect("bare FIN retransmission counted, window probe not (retrans, of them SYN/FIN)",
       fields(r, "retrans_segs", "retrans_syn_fin"), (1, 1))
expect("bare FIN retransmission: dubious, discard", fields(r, "pred_dubious", "pred_discard"), (0, 0))

# A dubious D-SACK on an ACK older than an earlier one is not a discard
# ("Don't count olds caused by ACK reordering", tcp_sacktag_write_queue).
old = [handshake[0], handshake[2], data(0), data(1), data(2),
       seg(STACK, ACK, 5001, ISN + 3001),
       dsack_ack(ISN + 2001, 0)]
r = replay(old)
expect("old ACK: D-SACK ACKs old, dubious, discard",
       fields(r, "dsack_acks_old", "pred_dubious", "pred_discard"), (1, 1, 0))

# Receiver side: the duplicated SYN is not a duplicated data segment; the
# duplicated segment 1 is, and its D-SACK is one for it.
recv = handshake + [data(0), data(1), data(1),
                    seg(STACK, ACK, 5001, ISN + 2001),
                    dsack_ack(ISN + 2001, 1)]
r = replay(recv, recv)
expect("receiver: duplicates, D-SACKs for them, other D-SACKs",
       tuple(r["receiver"][k] for k in ("dup_segs", "dsack_dup", "dsack_other")), (1, 1, 0))

print(f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
