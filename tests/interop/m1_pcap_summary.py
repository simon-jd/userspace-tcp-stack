#!/usr/bin/env python3
"""Summary of one capture of an M1 interop run (tests/interop/m1_lib.sh, m1_analyze).

Usage: m1_pcap_summary.py STACK_IP TCP_FIELDS ICMP_FIELDS TSHARK_STDERR [LEN]

TCP_FIELDS has one line per TCP segment (ICMP quotes excluded), fields separated
by ';' in this order: frame.time_epoch ip.src ip.dst tcp.srcport tcp.dstport
tcp.flags tcp.len tcp.window_size_value tcp.options.mss_val
tcp.options.sack_perm tcp.options.timestamp.tsval tcp.options.wscale.shift
tcp.options.sack_le ip.dsfield.ecn ip.flags.df tcp.seq_raw tcp.ack_raw.
ICMP_FIELDS: frame.time_epoch ip.src ip.dst icmp.type icmp.code icmp.mtu
(outer header: first occurrence).

Prints one JSON object. Segments are grouped by sender: "stack" (ip.src ==
STACK_IP) and "remote" (any other source). Per sender:
  pkts, data_pkts, payload_bytes, fin, rst, max_len, len_top (5 most common
  payload lengths), syns (the SYN and SYN-ACK segments: flags, MSS, SACK
  permitted, timestamps, window scale, ECE/CWR/AE bits), zero_win (segments
  other than SYN/RST that advertise a window of 0), ecn_ip (IP ECN field not
  0), ece_cwr_after_syn, ts_after_syn (timestamp option on non-SYN segments),
  sack_segs (segments carrying SACK blocks), first_t/last_t, fin_acked (one
  of this sender's last 64 ACKs covers the other sender's last FIN),
  rst_after_close (RSTs without ACK sent after both FINs were seen and this
  sender's FIN was ACKed, with the sequence number of the end of that FIN:
  the answer to a segment that arrives after the connection is gone, e.g. a
  duplicate of the last ACK, RFC 9293 §3.10.7.1 and Linux tcp_v4_rcv ->
  tcp_v4_send_reset), rst_open (rst - rst_after_close), edge_retreats and
  edge_retreat_max (ACKs whose right window edge, SEG.ACK + window << the
  sender's shift, lies below the highest edge this sender advertised
  before, and the largest such step in bytes; RFC 9293 §3.8.6.2.2 / RFC
  7323 §2.4; ACKs below this sender's highest SEG.ACK so far, i.e.
  reordered, are skipped; meaningful only in a capture taken before any
  reordering of that sender's segments, e.g. utcp0 for the stack).
  Single-connection captures only.
"connections": distinct (src, sport, dst, dport) tuples with a SYN, as
"a:p>b:q" from the SYN's sender.
"icmp": ICMP messages by (src, dst, type, code, mtu) with count and the time
of the first; "icmp_frag_needed_to_stack_first_t": time of the first type 3
code 4 to STACK_IP.
With LEN (the PMTU case): "stack_first_len_t" is the time of the stack's first
segment with LEN bytes of payload, "stack_max_len_after_first_len" the largest
stack payload after it (-1 if there is none), "stack_lens_after_icmp" the 5
most common stack payload lengths after the first frag-needed to STACK_IP,
"stack_over_len_after_icmp" the number of stack segments longer than LEN
sent after it, "stack_over_len_after_icmp_new" those of them that carry
data beyond the highest sequence number the stack had sent before it (new
data sent at the old size, before the stack read the ICMP message), and
"stack_over_len_after_icmp_last_dt" the seconds from that frag-needed to
the last of them (None if there is none).
"""
import collections
import json
import sys

TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10
TCP_ECE, TCP_CWR, TCP_AE = 0x40, 0x80, 0x100


def num(s, base=10, default=None):
    if s == "":
        return default
    try:
        return int(s, base)
    except ValueError:
        return default


def side():
    return {
        "pkts": 0, "data_pkts": 0, "payload_bytes": 0, "fin": 0, "rst": 0, "max_len": 0,
        "len_counts": collections.Counter(), "syns": [], "zero_win": 0, "ecn_ip": 0,
        "ece_cwr_after_syn": 0, "ts_after_syn": 0, "sack_segs": 0, "first_t": None,
        "last_t": None, "fin_end": None, "last_acks": collections.deque(maxlen=64),
        "rst_after_close": 0, "fin_acked_by_peer": False,
        "ack_max": None, "edge_max": None, "edge_retreats": 0, "edge_retreat_max": 0,
    }


def main():
    stack_ip, tcp_path, icmp_path, err_path = sys.argv[1:5]
    sides = {"stack": side(), "remote": side()}
    conns = set()
    stack_lens = []  # (time, len, end) of the stack's data segments, in order;
    # end: sequence number after the segment, relative to the stack's first one
    stack_base = None
    with open(tcp_path) as f:
        for line in f:
            p = line.rstrip("\n").split(";")
            if len(p) < 17:
                continue
            t = float(p[0]) if p[0] else 0.0
            src, dst, sport, dport = p[1], p[2], p[3], p[4]
            flags = num(p[5], 16, 0)
            ln = num(p[6], 10, 0)
            win = num(p[7], 10, -1)
            s = sides["stack" if src == stack_ip else "remote"]
            o = sides["remote" if src == stack_ip else "stack"]
            s["pkts"] += 1
            s["first_t"] = t if s["first_t"] is None else s["first_t"]
            s["last_t"] = t
            if ln > 0:
                s["data_pkts"] += 1
                s["payload_bytes"] += ln
                s["max_len"] = max(s["max_len"], ln)
                s["len_counts"][ln] += 1
                if src == stack_ip:
                    seq = num(p[15], 10)
                    if seq is not None:
                        stack_base = seq if stack_base is None else stack_base
                        stack_lens.append((t, ln, (seq - stack_base) % (1 << 32) + ln))
            if flags & TCP_FIN:
                s["fin"] += 1
                seq = num(p[15], 10)
                if seq is not None:
                    s["fin_end"] = (seq + ln + 1) % (1 << 32)
            if flags & TCP_ACK and num(p[16], 10) is not None:
                ack = num(p[16], 10)
                s["last_acks"].append(ack)
                if o["fin_end"] is not None and (ack - o["fin_end"]) % (1 << 32) < (1 << 31):
                    o["fin_acked_by_peer"] = True
                in_order = s["ack_max"] is None or (ack - s["ack_max"]) % (1 << 32) < (1 << 31)
                if in_order:
                    s["ack_max"] = ack
                if (in_order and not flags & (TCP_SYN | TCP_RST) and win >= 0 and s["syns"]
                        and o["syns"]):
                    # The window is scaled only if both SYNs carried the option.
                    ws, wo = s["syns"][0]["wscale"], o["syns"][0]["wscale"]
                    edge = (ack + (win << (min(ws, 14) if ws is not None and wo is not None else 0))) \
                        % (1 << 32)
                    if s["edge_max"] is None:
                        s["edge_max"] = edge
                    else:
                        step = (edge - s["edge_max"]) % (1 << 32)
                        if 0 < step < (1 << 31):
                            s["edge_max"] = edge
                        elif step != 0:
                            s["edge_retreats"] += 1
                            s["edge_retreat_max"] = max(s["edge_retreat_max"], (1 << 32) - step)
            if flags & TCP_RST:
                s["rst"] += 1
                if (not flags & TCP_ACK and s["fin_acked_by_peer"] and o["fin"] > 0
                        and num(p[15], 10) == s["fin_end"]):
                    s["rst_after_close"] += 1
            if flags & TCP_SYN:
                conns.add(f"{src}:{sport}>{dst}:{dport}" if not flags & TCP_ACK
                          else f"{dst}:{dport}>{src}:{sport}")
                if len(s["syns"]) < 8:
                    s["syns"].append({
                        "t": t, "ack": bool(flags & TCP_ACK), "mss": num(p[8]),
                        "sack_perm": p[9] != "", "ts": p[10] != "", "wscale": num(p[11]),
                        "ece": bool(flags & TCP_ECE), "cwr": bool(flags & TCP_CWR),
                        "ae": bool(flags & TCP_AE), "ip_ecn": num(p[13], 10, 0),
                        "src": f"{src}:{sport}", "dst": f"{dst}:{dport}",
                    })
            else:
                if win == 0 and not flags & TCP_RST:
                    s["zero_win"] += 1
                if flags & (TCP_ECE | TCP_CWR | TCP_AE):
                    s["ece_cwr_after_syn"] += 1
                if p[10] != "":
                    s["ts_after_syn"] += 1
            if p[12] != "":
                s["sack_segs"] += 1
            if num(p[13], 10, 0) != 0:
                s["ecn_ip"] += 1
    icmp = collections.OrderedDict()
    frag_first = None
    with open(icmp_path) as f:
        for line in f:
            p = line.rstrip("\n").split(";")
            if len(p) < 6:
                continue
            t = float(p[0]) if p[0] else 0.0
            key = (p[1], p[2], num(p[3]), num(p[4]), num(p[5]))
            if key not in icmp:
                icmp[key] = {"src": p[1], "dst": p[2], "type": key[2], "code": key[3],
                             "mtu": key[4], "count": 0, "first_t": t}
            icmp[key]["count"] += 1
            if key[2] == 3 and key[3] == 4 and p[2] == stack_ip and frag_first is None:
                frag_first = t
    want_len = int(sys.argv[5]) if len(sys.argv) > 5 else None
    first_len_t = None
    after_len = -1
    after_icmp = collections.Counter()
    over_after_icmp = over_after_icmp_new = 0
    over_after_icmp_last_dt = None
    hi_before_icmp = max((e for t, _, e in stack_lens if frag_first is None or t <= frag_first),
                         default=0)
    for t, ln, end in stack_lens:
        if want_len is not None:
            if first_len_t is not None:
                after_len = max(after_len, ln)
            elif ln == want_len:
                first_len_t = t
        if frag_first is not None and t > frag_first:
            after_icmp[ln] += 1
            if want_len is not None and ln > want_len:
                over_after_icmp += 1
                over_after_icmp_last_dt = round(t - frag_first, 6)
                if end > hi_before_icmp:
                    over_after_icmp_new += 1
    for name, s in sides.items():
        s["len_top"] = s.pop("len_counts").most_common(5)
        other = sides["remote" if name == "stack" else "stack"]
        fe = other["fin_end"]
        s["fin_acked"] = fe is not None and any(
            (a - fe) % (1 << 32) < (1 << 31) for a in s["last_acks"])
    for s in sides.values():
        del s["last_acks"], s["fin_acked_by_peer"], s["edge_max"], s["ack_max"]
        s["rst_open"] = s["rst"] - s["rst_after_close"]
    with open(err_path) as f:
        err = f.read().strip()
    out = {
        "connections": sorted(conns),
        "by": sides,
        "icmp": list(icmp.values()),
        "icmp_frag_needed_to_stack_first_t": frag_first,
        "stack_first_len_t": first_len_t,
        "stack_max_len_after_first_len": after_len,
        "stack_lens_after_icmp": after_icmp.most_common(5),
        "stack_over_len_after_icmp": over_after_icmp,
        "stack_over_len_after_icmp_new": over_after_icmp_new,
        "stack_over_len_after_icmp_last_dt": over_after_icmp_last_dt,
        "tshark_stderr": err[-500:],
    }
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
