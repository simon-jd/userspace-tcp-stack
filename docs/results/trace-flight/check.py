"""Cross-check a one-way ordinary transfer (single connection, no SACK reneging)."""

import collections
import json
import struct
import sys
from pathlib import Path

if not __debug__:
    sys.exit("Use ordinary Python so capture assertions run")
root = Path(sys.argv[1])
mask = (1 << 32) - 1
sender = bytes((198, 18, 0, 2))


def packets(path):
    dirs = {True: [], False: []}
    with path.open("rb") as f:
        header = f.read(24)
        assert header[:4] in (bytes.fromhex("d4c3b2a1"), bytes.fromhex("4d3cb2a1"))
        assert int.from_bytes(header[20:24], "little") == 101  # LINKTYPE_RAW
        while record := f.read(16):
            size = struct.unpack("<4I", record)[2]
            ip = f.read(size)
            assert len(ip) == size
            if ip[0] >> 4 != 4 or ip[9] != 6:
                continue
            tcp = ip[(ip[0] & 15) * 4 :]
            seq, ack = struct.unpack_from("!II", tcp, 4)
            hdr = (tcp[12] >> 4) * 4
            length = int.from_bytes(ip[2:4], "big") - (ip[0] & 15) * 4 - hdr
            sacks = []
            off = 20
            while off < hdr:
                kind = tcp[off]
                if kind == 0:
                    break
                if kind == 1:
                    off += 1
                    continue
                n = tcp[off + 1]
                assert n >= 2
                if kind == 5:
                    sacks.extend(struct.iter_unpack("!II", tcp[off + 2 : off + n]))
                off += n
            dirs[ip[12:16] == sender].append((seq, ack, tcp[13], length, sacks))
    return dirs


wire = packets(root / "peer.pcap")
assert wire == packets(root / "stack.pcap")
stream = {direction: iter(pkts) for direction, pkts in wire.items()}
base = (wire[True][0][0] + 1) & mask
assert wire[True][0][2] & 2
high = cum = peak = retrans = sack_blocks = 0
sacked = set()
pending = None
checks = collections.Counter()
for e in map(json.loads, (root / "trace.jsonl").read_text().splitlines()):
    kind = e["ev"]
    if kind in ("tx", "rx"):
        p = next(stream[kind == "tx"])
        assert tuple(e[k] for k in ("seq", "ack", "flags", "len")) == p[:4]
        seq, ack, flags, n, sacks = p
        if kind == "tx" and n:
            off = (seq - base) & mask
            assert off <= high
            retrans += off < high
            high = max(high, off + n)
        if kind == "rx":
            pending = p
    if kind == "ack":
        seq, ack, flags, n, sacks = pending
        assert (e["seq"], e["ack"]) == (seq, ack)
        cum = min(high, max(cum, (ack - base) & mask))  # FIN occupies no payload
        sacked = {x for x in sacked if x >= cum}
        for lo, hi in sacks:
            a, b = (lo - base) & mask, (hi - base) & mask
            if cum < a < b <= high:
                sacked.update(range(a, b))
                sack_blocks += 1
        pending = None
    if kind in ("tx", "rx", "ack", "state"):
        measured = high - cum - len(sacked)
        assert e["in_flight_bytes"] == measured, (e, measured)
        checks[kind] += 1
        peak = max(peak, measured)
assert all(next(it, None) is None for it in stream.values())
a, b = (
    json.loads((root / name).read_text().splitlines()[-1])
    for name in ("stack.jsonl", "peer.jsonl")
)
assert a["ok"] and b["ok"] and a["sha256"] == b["sha256"]
assert high == cum == a["bytes"] == b["bytes"] == 1_048_613 and not sacked
assert base + high > mask and all(checks[k] for k in ("tx", "rx", "ack", "state"))
if (root / "filter.txt").read_text().strip():
    assert retrans >= 1 and sack_blocks >= 1
else:
    assert retrans == 0 and sack_blocks == 0
print(
    json.dumps(
        {
            "checked": checks,
            "matched_packets": sum(map(len, wire.values())),
            "payload": high,
            "peak": peak,
            "sequence_wrap": base + high > mask,
            "retransmitted_segments": retrans,
            "sack_blocks": sack_blocks,
            "sha256": a["sha256"],
        },
        sort_keys=True,
    )
)
