#!/usr/bin/env python3
"""Which packets a router dropped, from the captures before and after it
(DESIGN §14, the scripted-drop check of M2-TASKS m2d-testbed test 10).

  dropcheck.py BEFORE.pcap AFTER.pcap DST_IP [DPORT] [--targets OFF[:N],... [--span B]]

Prints one JSON object: the connection's ISN (from the SYN in BEFORE), and
every packet of the connection toward DST_IP that is in BEFORE but not in
AFTER, with its index among the connection's packets in BEFORE (SYN = 1, as
conntrack counts `ct original packets`), its stream offset (seq - ISN - 1),
payload length and copy number in BEFORE (1 = the first packet with that
sequence number). Packets are matched by IP ID, TCP timestamp value, seq,
length and flags, which differ between a retransmission and the original.

With --targets (drop.sh arm's --offsets and --span, default 1448), it also
lists for each target the stream offsets of the segments drop.sh's rule
latches on the packets in BEFORE (`target_ranges`, `latched`): the expected
drops, independent of the nft rule.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze as A  # noqa: E402


def keyed(path, dst, dport):
    """The connection's packets toward dst in capture order, each with its copy
    number (data segments) and a key that identifies the transmission: IP ID,
    TSval, seq, length, flags (copies differ in IP ID and TSval)."""
    out, copies, isn = [], {}, None
    for s in A.tcp_segments(path):
        if s.dst != dst or (dport is not None and s.dport != dport):
            continue
        if s.flags & 0x02 and isn is None:
            isn = s.seq
        copy = 0  # SYN, pure ACK, FIN
        if s.payload > 0:
            copies[s.seq] = copy = copies.get(s.seq, 0) + 1
        out.append({"seq": s.seq, "len": s.payload, "flags": s.flags, "copy": copy,
                    "key": (s.ipid, s.tsval, s.seq, s.payload, s.flags)})
    return out, isn


def missing(before, after, isn):
    """Packets of `before` whose transmission key is not in `after` (copy
    numbers are those of `before`)."""
    have = {}
    for p in after:
        have[p["key"]] = have.get(p["key"], 0) + 1
    out = []
    for i, p in enumerate(before, start=1):
        if have.get(p["key"]):
            have[p["key"]] -= 1
            continue
        out.append({"index": i, "offset": None if isn is None else (p["seq"] - isn - 1) % 2**32,
                    "len": p["len"], "copy": p["copy"], "flags": p["flags"]})
    return out


def target_ranges(spec, span=1448):
    """drop.sh arm's ranges: targets "OFF[:N],..." sorted by offset, target
    i covering stream offsets [OFF, OFF + N*span) cut at the next target's
    offset. Returns [(lo, hi, n)] with hi exclusive."""
    tg = sorted((int(o), int(n or 1)) for o, _, n in (x.partition(":") for x in spec.split(",")))
    out = []
    for i, (off, n) in enumerate(tg):
        hi = off + n * span
        if i + 1 < len(tg):
            if tg[i + 1][0] <= off:
                raise ValueError(f"offset {off} is listed twice")
            hi = min(hi, tg[i + 1][0])
        out.append((off, hi, n))
    return out


def latched(pkts, isn, ranges):
    """The stream offsets drop.sh's rule latches, per range: in arrival order,
    a data packet whose first byte lies in [lo, hi) and whose sequence is not
    latched yet is latched while fewer than n are (DESIGN §14.5)."""
    out = [[] for _ in ranges]
    for p in pkts:
        if p["len"] <= 0 or isn is None:
            continue
        off = (p["seq"] - isn - 1) % 2**32
        for i, (lo, hi, n) in enumerate(ranges):
            if lo <= off < hi and off not in out[i] and len(out[i]) < n:
                out[i].append(off)
    return out


def main(argv):
    args, targets, span = [], None, 1448
    it = iter(argv[1:])
    for a in it:
        if a == "--targets":
            targets = next(it)
        elif a == "--span":
            span = int(next(it))
        else:
            args.append(a)
    if len(args) < 3:
        print(__doc__)
        return 2
    dport = int(args[3]) if len(args) > 3 else None
    before, isn = keyed(args[0], args[2], dport)
    after, _ = keyed(args[1], args[2], dport)
    out = {"isn": isn, "before": len(before), "after": len(after), "missing": missing(before, after, isn)}
    if targets:
        rg = target_ranges(targets, span)
        out["target_ranges"] = [[lo, hi, n] for lo, hi, n in rg]
        out["latched"] = latched(before, isn, rg)
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
