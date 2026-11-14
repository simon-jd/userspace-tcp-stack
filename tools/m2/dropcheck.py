#!/usr/bin/env python3
"""Which packets a router dropped, from the captures before and after it
(DESIGN §14, the scripted-drop check of M2-TASKS m2d-testbed test 10).

  dropcheck.py BEFORE.pcap AFTER.pcap DST_IP [DPORT]

Prints one JSON object: the connection's ISN (from the SYN in BEFORE), and
every packet of the connection toward DST_IP that is in BEFORE but not in
AFTER, with its index among the connection's packets in BEFORE (SYN = 1, as
conntrack counts `ct original packets`), its stream offset (seq - ISN - 1),
payload length and copy number in BEFORE (1 = the first packet with that
sequence number). Packets are matched by IP ID, TCP timestamp value, seq,
length and flags, which differ between a retransmission and the original.
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


def main(argv):
    if len(argv) < 4:
        print(__doc__)
        return 2
    dport = int(argv[4]) if len(argv) > 4 else None
    before, isn = keyed(argv[1], argv[3], dport)
    after, _ = keyed(argv[2], argv[3], dport)
    print(json.dumps({"isn": isn, "before": len(before), "after": len(after),
                      "missing": missing(before, after, isn)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
