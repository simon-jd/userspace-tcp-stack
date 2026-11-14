#!/usr/bin/env python3
"""One row of the M1 interop matrix (tests/interop/m1_lib.sh m1_row, docs/INTEROP.md).

Usage: m1_row.py RESULTS CASE [KEY=VALUE]... [check:EXPR]...

Reads RESULTS/CASE/:
  before.rec, after.rec  testbed/m1/record.sh output: the peer's `nstat -asz`,
                         `ip -s link show utcp0` and `tc -s qdisc` of the DUT
  send.out, recv.out     JSON lines of the sender and the receiver (the line
                         with "ev":"summary" is used), if present
  stack-stats.json       the stack's --stats line, if present
  pcap-NAME.json         m1_pcap_summary.py output per capture
  extra.json             other values a script recorded (one JSON object)
and evaluates each check:EXPR as a Python expression over
  send, recv     the summaries (dicts; {} if missing)
  peer           delta of every peer nstat counter (after - before; 0 if absent)
  stack          the stack's counters (dict)
  tun            {"rx_dropped", "tx_dropped", ...} delta of utcp0
  qdisc          {"<dev> <kind>": dropped delta}
  pcap           {NAME: summary}
  extra          extra.json (time_total_s, curl's time, is the duration of
                 rows without a utcp-bulk sender)
  meta           the KEY=VALUE arguments (strings)
  sha_ok         both summaries ok, SHA-256 equal, bytes equal to meta["bytes_n"] if given
  fin_ok(NAME)   in capture NAME both sides sent a FIN, each FIN was
                 acknowledged, and nobody sent an RST
Writes RESULTS/CASE/row.json and appends it to RESULTS/rows.jsonl. Exit
status 0 if every check holds and none raised, else 1.
"""
import json
import os
import re
import sys


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def sections(text):
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith("== "):
            cur = line[3:].strip()
            out[cur] = []
        elif cur is not None:
            out[cur].append(line)
    return out


def nstat(sec):
    d = {}
    for name, lines in sec.items():
        if name.endswith("nstat -asz"):
            for ln in lines:
                p = ln.split()
                if len(p) >= 2 and not ln.startswith("#") and p[1].isdigit():
                    d[p[0]] = int(p[1])
    return d


def tun(sec):
    d = {}
    for name, lines in sec.items():
        if "ip -s link show" in name:
            for i, ln in enumerate(lines):
                s = ln.strip()
                if s.startswith("RX:") or s.startswith("TX:"):
                    keys = s.split()[1:]
                    vals = lines[i + 1].split() if i + 1 < len(lines) else []
                    pre = "rx_" if s.startswith("RX:") else "tx_"
                    for k, v in zip(keys, vals):
                        if v.isdigit():
                            d[pre + k] = int(v)
    return d


def qdisc(sec):
    d = {}
    for name, lines in sec.items():
        if name.endswith("tc -s qdisc"):
            key = None
            for ln in lines:
                m = re.match(r"qdisc (\S+) \S+ dev (\S+) (root|parent)", ln)
                if m:
                    key = f"{m.group(2)} {m.group(1)}" if m.group(3) == "root" else None
                m = re.search(r"Sent (\d+) bytes (\d+) pkt \(dropped (\d+)", ln)
                if m and key:
                    d[key] = int(m.group(3))
                    d[key + " pkts"] = int(m.group(2))
                    key = None
    return d


def summary(path):
    s = {}
    for ln in read(path).splitlines():
        if '"ev":"summary"' in ln:
            try:
                s = json.loads(ln)
            except ValueError:
                pass
    return s


def delta(a, b):
    return {k: b.get(k, 0) - a.get(k, 0) for k in set(a) | set(b)}


class Zero(dict):
    def __missing__(self, key):
        return 0


def main():
    res, case = sys.argv[1], sys.argv[2]
    d = os.path.join(res, case)
    meta, checks = {}, []
    for a in sys.argv[3:]:
        if a.startswith("check:"):
            checks.append(a[6:])
        else:
            k, _, v = a.partition("=")
            meta[k] = v
    b, a = sections(read(os.path.join(d, "before.rec"))), sections(read(os.path.join(d, "after.rec")))
    peer = Zero(delta(nstat(b), nstat(a)))
    tund = Zero(delta(tun(b), tun(a)))
    qd = Zero(delta(qdisc(b), qdisc(a)))
    send, recv = summary(os.path.join(d, "send.out")), summary(os.path.join(d, "recv.out"))
    stack = Zero()
    st = read(os.path.join(d, "stack-stats.json")).strip()
    if st:
        stack.update(json.loads(st.splitlines()[-1]))
    pcap = {}
    for f in sorted(os.listdir(d)):
        if f.startswith("pcap-") and f.endswith(".json"):
            try:
                pcap[f[5:-5]] = json.loads(read(os.path.join(d, f)))
            except ValueError:
                pcap[f[5:-5]] = {}
    ex = read(os.path.join(d, "extra.json")).strip()
    extra = Zero(json.loads(ex)) if ex else Zero()

    want = int(meta["bytes_n"]) if meta.get("bytes_n") else None
    sha_ok = bool(send.get("ok") and recv.get("ok") and send.get("sha256")
                  and send.get("sha256") == recv.get("sha256")
                  and send.get("bytes") == recv.get("bytes")
                  and (want is None or send.get("bytes") == want))

    def fin_ok(name):
        by = pcap.get(name, {}).get("by", {})
        s, r = by.get("stack", {}), by.get("remote", {})
        return s.get("fin", 0) >= 1 and r.get("fin", 0) >= 1 and s.get("rst", 0) == 0 \
            and r.get("rst", 0) == 0 and s.get("fin_acked") is True and r.get("fin_acked") is True

    env = {"send": send, "recv": recv, "peer": peer, "stack": stack, "tun": tund, "qdisc": qd,
           "pcap": pcap, "extra": extra, "meta": meta, "sha_ok": sha_ok, "fin_ok": fin_ok,
           "len": len, "max": max, "min": min, "sum": sum, "any": any, "all": all}
    results = []
    for c in checks:
        try:
            ok = bool(eval(c, {"__builtins__": {}}, env))  # expressions come from our scripts
            results.append({"check": c, "ok": ok})
        except Exception as e:  # a missing field is a failed check, with the reason
            results.append({"check": c, "ok": False, "error": f"{type(e).__name__}: {e}"})
    sender = send
    row = dict(meta)
    row.update({
        "case": case,
        "sha_ok": sha_ok,
        "sha256": send.get("sha256") or recv.get("sha256"),
        "bytes": send.get("bytes", recv.get("bytes")),
        "duration_s": round(sender.get("duration_us", 0) / 1e6, 3) if sender
        else extra.get("time_total_s") or None,
        "goodput_mbps": round(sender.get("goodput_bps", 0) / 1e6, 1) if sender else None,
        "sender_total_retrans": sender.get("total_retrans"),
        "sender_rwnd_limited_us": sender.get("rwnd_limited_us"),
        "peer_TcpRetransSegs": peer["TcpRetransSegs"],
        "stack_TcpRetransSegs": stack.get("TcpRetransSegs"),
        "tun_rx_dropped": tund["rx_dropped"],
        "tun_tx_dropped": tund["tx_dropped"],
        "qdisc_dropped": {k: v for k, v in qd.items() if not k.endswith(" pkts") and v},
        "nstat": {k: peer[k] for k in sorted(peer) if peer[k] and (
            k.startswith("TcpExtTCPSACK") or k.startswith("TcpExtTCPSack")
            or k.startswith("TcpExtTCPDSACK") or k in (
                "TcpRetransSegs", "TcpExtTCPTimeouts", "TcpExtTCPLossProbes", "TcpExtTCPFastRetrans",
                "TcpExtTCPToZeroWindowAdv", "TcpExtTCPFromZeroWindowAdv", "TcpExtTCPWinProbe",
                "TcpExtTCPZeroWindowDrop", "TcpExtTCPWantZeroWindowAdv", "TcpExtTCPRenoRecovery",
                "TcpExtTCPOFOQueue", "TcpExtTCPOFODrop", "TcpExtTCPSpuriousRTOs",
                "TcpExtTCPSpuriousRtxHostQueues", "TcpExtTCPLostRetransmit", "TcpExtTCPRcvQDrop",
                "TcpExtTCPLossUndo", "TcpExtTCPPartialUndo", "TcpExtTCPFullUndo", "TcpEstabResets",
                "TcpOutRsts", "TcpExtPAWSEstab", "TcpExtTCPChallengeACK", "TcpExtTCPAbortOnData",
                "TcpExtTCPAbortOnClose", "TcpExtTCPACKSkippedSeq", "TcpExtTCPDSACKIgnoredNoUndo",
                "TcpExtTCPDSACKIgnoredOld", "TcpExtTCPSACKReneging", "TcpExtTCPSlowStartRetrans",
                "IcmpInDestUnreachs", "IcmpOutDestUnreachs", "TcpExtTCPMTUPFail",
                "TcpExtTCPMTUPSuccess"))},
        "checks": results,
        "pass": all(r["ok"] for r in results) and bool(results),
    })
    with open(os.path.join(d, "row.json"), "w") as f:
        json.dump(row, f, indent=1)
    with open(os.path.join(res, "rows.jsonl"), "a") as f:
        f.write(json.dumps(row) + "\n")
    bad = [r for r in results if not r["ok"]]
    print(f"{case}: {'PASS' if row['pass'] else 'FAIL'} sha_ok={sha_ok} "
          f"dur={row['duration_s']}s retrans={row['sender_total_retrans']} "
          f"tun_drops={row['tun_rx_dropped']}/{row['tun_tx_dropped']}"
          + "".join(f"\n  FAILED {r['check']} {r.get('error', '')}" for r in bad))
    return 0 if row["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
