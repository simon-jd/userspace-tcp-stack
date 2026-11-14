#!/usr/bin/env python3
"""D-SACK accounting of one bulk transfer from its captures (docs/INTEROP.md,
"TCPSACKDiscard under duplication").

Usage: m1_dsack.py SENDER_IP SENDER_SIDE.txt [RECEIVER_SIDE.txt]

Each .txt is tshark output (fields separated by ';', all occurrences joined by
','; m1_lib.sh m1_dsack) with the fields ip.src ip.dst tcp.srcport
tcp.dstport tcp.flags tcp.seq_raw tcp.len tcp.ack_raw tcp.options.sack_le
tcp.options.sack_re (raw sequence numbers). SENDER_SIDE is the capture on
the Linux data sender's interface (what it sent, and the ACKs in the order
it processed them); RECEIVER_SIDE, if given, the capture next to the data
receiver (the data after netem, the ACKs as the receiver sent them).

Only the connection that carried the most payload from SENDER_IP is used.
Sequence numbers are taken relative to the sender's ISN (a 1 GB run stays
below 2^32).

On the sender side the script replays the two Linux 7.0 rules that decide
whether a D-SACK block is counted in TcpExtTCPSACKDiscard
(net/ipv4/tcp_input.c):
  tcp_dsack_seen: dsack_dups += segments in the block; the block is dubious
    (TCPDSACKIgnoredDubious) if dsack_dups > total_retrans, i.e. the sender
    has received more D-SACKed segments than it ever retransmitted
  tcp_sacktag_write_queue: a dubious D-SACK block is then checked as an
    ordinary SACK block (tcp_is_sackblock_valid): a block above snd_una is
    valid; one at or below snd_una is counted in TCPSACKDiscard unless the
    ACK is older than snd_una ("Don't count olds caused by ACK reordering")
total_retrans is the number of data segments the sender sent at or below
its highest sequence sent so far (tso/gso are off on the sender, so one
capture record is one segment). A D-SACK block is the first block when it
lies below the ACK or inside the second block (RFC 2883 §4).

Output (JSON on stdout):
  sender:   data_segs, retrans_segs, acks, dsack_acks, dsack_acks_old,
            pred_dubious, pred_discard, dsack_never_retransmitted (D-SACK
            blocks whose range the sender sent only once),
            pred_discard_never_retransmitted, and with RECEIVER_SIDE
            pred_discard_dup (predicted TCPSACKDiscard blocks equal to a
            segment the receiver got two or more times)
  receiver: data_segs, dup_segs (data segments seen two or more times),
            dsack_acks, dsack_dup (D-SACK blocks equal to a segment the
            receiver had already seen twice), dsack_other
"""
import json
import sys

M = 1 << 32


def rows(path):
    with open(path) as f:
        for ln in f:
            p = ln.rstrip("\n").split(";")
            if len(p) < 10:
                continue
            yield p


def ints(s):
    return [int(x) for x in s.split(",") if x != ""]


def pick_flow(path, sender):
    payload = {}
    for p in rows(path):
        if p[0] == sender and p[6] and int(p[6]) > 0:
            k = (p[2], p[3])
            payload[k] = payload.get(k, 0) + int(p[6])
    if not payload:
        return None
    return max(payload, key=payload.get)


def isn_of(path, sender, flow):
    for p in rows(path):
        if p[0] == sender and (p[2], p[3]) == flow and p[5]:
            flags = int(p[4], 16)
            if flags & 0x02:
                return int(p[5])
    for p in rows(path):
        if p[0] == sender and (p[2], p[3]) == flow and p[5]:
            return int(p[5]) - 1
    return None


def dsack_block(ack, le, re):
    """The D-SACK block of an ACK (offsets), or None (RFC 2883 §4)."""
    if not le:
        return None
    if le[0] < ack:
        return (le[0], re[0])
    if len(le) > 1 and le[1] <= le[0] and re[0] <= re[1]:
        return (le[0], re[0])
    return None


def segments(path, sender, flow, isn):
    """Yields ('data', seq, len) and ('ack', ack, le, re) in capture order."""
    for p in rows(path):
        if p[0] == sender and (p[2], p[3]) == flow:
            ln = int(p[6]) if p[6] else 0
            if ln > 0:
                yield ("data", (int(p[5]) - isn) % M, ln)
        elif p[1] == sender and (p[3], p[2]) == flow and p[7]:
            flags = int(p[4], 16)
            if not flags & 0x10:
                continue
            ack = (int(p[7]) - isn) % M
            le = [(x - isn) % M for x in ints(p[8])]
            re = [(x - isn) % M for x in ints(p[9])]
            yield ("ack", ack, le, re)


def sender_side(path, sender, flow, isn, dup_ranges=None):
    out = {"data_segs": 0, "retrans_segs": 0, "acks": 0, "dsack_acks": 0,
           "dsack_acks_old": 0, "pred_dubious": 0, "pred_discard": 0,
           "dsack_never_retransmitted": 0, "pred_discard_never_retransmitted": 0}
    if dup_ranges is not None:
        out["pred_discard_dup"] = 0
    snd_max = 0
    mss = 0
    sent = {}
    max_ack = None
    dsack_dups = 0
    for s in segments(path, sender, flow, isn):
        if s[0] == "data":
            _, seq, ln = s
            out["data_segs"] += 1
            mss = max(mss, ln)
            sent[seq] = sent.get(seq, 0) + 1
            if seq + ln <= snd_max:
                out["retrans_segs"] += 1
            snd_max = max(snd_max, seq + ln)
            continue
        _, ack, le, re = s
        out["acks"] += 1
        old = max_ack is not None and ack < max_ack
        max_ack = ack if max_ack is None else max(max_ack, ack)
        d = dsack_block(ack, le, re)
        if d is None:
            continue
        out["dsack_acks"] += 1
        if old:
            out["dsack_acks_old"] += 1
        once = sent.get(d[0], 0) <= 1
        if once:
            out["dsack_never_retransmitted"] += 1
        seq_len = d[1] - d[0]
        if seq_len <= 0:
            continue
        dup_segs = -(-seq_len // mss) if mss and seq_len > mss else 1
        dsack_dups += dup_segs
        if dsack_dups > out["retrans_segs"]:
            out["pred_dubious"] += 1
            # A dubious block is then checked as an ordinary SACK block
            # (tcp_is_sackblock_valid): above snd_una (a duplicate of
            # out-of-order data) it is valid; at or below it, invalid.
            if not old and d[0] <= ack:
                out["pred_discard"] += 1
                if once:
                    out["pred_discard_never_retransmitted"] += 1
                if dup_ranges is not None and d in dup_ranges:
                    out["pred_discard_dup"] += 1
    return out


def receiver_side(path, sender, flow, isn, dup_ranges):
    out = {"data_segs": 0, "dup_segs": 0, "dsack_acks": 0, "dsack_dup": 0, "dsack_other": 0}
    seen = {}
    for s in segments(path, sender, flow, isn):
        if s[0] == "data":
            _, seq, ln = s
            out["data_segs"] += 1
            k = (seq, seq + ln)
            seen[k] = seen.get(k, 0) + 1
            if seen[k] == 2:
                out["dup_segs"] += 1
                dup_ranges.add(k)
            continue
        _, ack, le, re = s
        d = dsack_block(ack, le, re)
        if d is None:
            continue
        out["dsack_acks"] += 1
        if seen.get(d, 0) >= 2:
            out["dsack_dup"] += 1
        else:
            out["dsack_other"] += 1
    return out


def main():
    sender, spath = sys.argv[1], sys.argv[2]
    rpath = sys.argv[3] if len(sys.argv) > 3 else None
    flow = pick_flow(spath, sender)
    res = {"flow": None}
    if flow is not None:
        isn = isn_of(spath, sender, flow)
        res["flow"] = f"{sender}:{flow[0]}>{flow[1]}"
        dup_ranges = None
        if rpath:
            dup_ranges = set()
            res["receiver"] = receiver_side(rpath, sender, flow, isn, dup_ranges)
        res["sender"] = sender_side(spath, sender, flow, isn, dup_ranges)
    json.dump(res, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
