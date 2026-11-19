#!/usr/bin/env python3
"""Compare complete scripted TCP loss episodes on the sender-facing side of router 1.

Host: tests/interop/m2_drops.sh --campaign task/attempt [--case tail --cc cubic --rep 1].
Bring up non-timing slot 2 with testbed/m2/up.sh first; remove it with down.sh afterwards.
The host runs matrix.one_run and analyses the resulting volume files in the slot.
Offline: recovery_compare.py analyze RUNDIR or recovery_compare.py report CAMPAIGNDIR.
"""
import argparse
import bisect
import collections
import itertools
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze as A
import dropcheck as D

CASES = {"slow": ("18000", "1"), "avoidance": ("18000,1500000", "1"),
         "burst": ("120000:5", "1"), "lost-retrans": ("120000", "1,2"),
         "tail": ("97104:2", "1")}
CCS = ("newreno", "cubic")
IMPLS = ("utcp", "linux")
COUNTERS = ("TcpExtTCPSackRecovery", "TcpExtTCPLossProbes", "TcpExtTCPLossProbeRecovery",
            "TcpExtTCPTimeouts")
MOD = 1 << 32


def plan(campaign, cases, ccs, impls, reps):
    if not all(re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*", x) for x in campaign.split("/")):
        raise ValueError("campaign must be a relative path of named components")
    for case, cc, rep, impl in itertools.product(cases, ccs, reps, impls):
        offsets, copies = CASES[case]
        name = f"{case}-{cc}-r{rep}-{impl}"
        yield name, dict(case=case, rep=rep, impl=impl, cc=cc, bw=100, rtt=20, queue_bdp=40,
                         loss=0, duration=30, bytes=100000 if case == "tail" else 3000000,
                         profile="linux", extra_capture=True, stack_args="--trace-kinds ack,tx,rto",
                         drops=[["arm", "--router", "r1", "--offsets", offsets, "--copies", copies,
                                 "--log", f"/data/m2/{campaign}/{name}/drop-r1.log"]])


def sack_blocks(options, isn):
    pos, blocks = 0, []
    while pos < len(options):
        kind = options[pos]
        if kind == 0:
            break
        if kind == 1:
            pos += 1
            continue
        if pos + 1 >= len(options):
            raise ValueError("truncated TCP option")
        size = options[pos + 1]
        if size < 2 or pos + size > len(options):
            raise ValueError("invalid TCP option length")
        if kind == 5:
            if size < 10 or (size - 2) % 8:
                raise ValueError("invalid SACK option length")
            for left, right in struct.iter_unpack(">II", options[pos + 2:pos + size]):
                blocks.append([(v - isn - 1) % MOD for v in (left, right)])
        pos += size
    return blocks


def wire_stream(path, dst, isn):
    """In both directions, select the one 4-tuple that opened this connection."""
    peer, rows, keys = None, [], collections.Counter()
    for t, ip in A.read_pcap(path):
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = 4 * (ip[0] & 15)
        tcp = ip[ihl:]
        sport, dport, seq, ack = struct.unpack_from(">HHII", tcp)
        src, dest = ip[12:16], ip[16:20]
        flags, hdr = tcp[13], 4 * (tcp[12] >> 4)
        if dest == dst and dport == 5201 and flags & 0x12 == 2:
            if seq != isn or (peer and peer != (src, sport)):
                raise ValueError("multiple connections on the test port")
            peer = (src, sport)
        if not peer or not ((src, sport) == peer and (dest, dport) == (dst, 5201)
                            or (dest, dport) == peer and (src, sport) == (dst, 5201)):
            continue
        if len(tcp) < hdr or hdr < 20:
            raise ValueError("truncated TCP header")
        payload = struct.unpack_from(">H", ip, 2)[0] - ihl - hdr
        if src == dst:
            # Match each returning ACK (including its ordered SACKs) across captures.
            keys[(ip[4:6], tcp[:16], tcp[20:hdr], payload)] += 1
            if flags & 16 and not flags & 2:
                rows.append((t, "ack", (ack - isn - 1) % MOD, sack_blocks(tcp[20:hdr], isn)))
        elif payload:
            rows.append((t, "tx", (seq - isn - 1) % MOD, payload))
    if not peer:
        raise ValueError("missing opening SYN")
    return sorted(rows, key=lambda x: x[0]), keys


def add_interval(covered, lo, hi):
    """Maintain a sorted union and return the number of bytes sent previously."""
    i = bisect.bisect_left(covered, (lo,))
    if i and covered[i - 1][1] >= lo:
        i -= 1
    j, repeated, start, end = i, 0, lo, hi
    while j < len(covered) and covered[j][0] <= hi:
        a, b = covered[j]
        repeated += max(0, min(hi, b) - max(lo, a))
        start, end = min(start, a), max(end, b)
        j += 1
    covered[i:j] = [(start, end)]
    return repeated


def wire_episode(rows, targets, size):
    """Wire interval from first damaged original to ACK covering the pre-repair flight.

    The ACK preceding a send describes capture order; paced/timer sends can occur between ACKs.
    A repeated byte range can have a new segment boundary and therefore copy number 1.
    """
    starts, groups, coverage, originals = collections.Counter(), [], [], []
    hole = min(targets)
    drop = repair = finish = high = None
    group = {"t_ns": None, "ack": None, "sack": [], "tx": []}
    groups.append(group)
    for t, kind, off, value in rows:
        if kind == "ack":
            group = {"t_ns": t, "ack": off, "sack": value, "tx": []}
            groups.append(group)
            if repair is not None and finish is None and off >= high:
                finish = t
            continue
        old_high = coverage[-1][1] if coverage else 0
        repeat = add_interval(coverage, off, off + value)
        starts[off] += 1
        if repeat == 0:
            originals.append((off, value))
        if off == hole and starts[off] == 1:
            drop = t
        if drop is not None and repair is None and repeat and any(off <= target < off + value for target in targets):
            repair, high = t, old_high
        group["tx"].append(dict(t_ns=t, off=off, length=value, copy=starts[off], repeat_bytes=repeat))
    if None in (drop, repair, high, finish):
        raise ValueError(f"incomplete wire episode: loss={drop}, repair={repair}, high={high}, ACK={finish}")
    start_idx = max(i for i, a in enumerate(groups) if (a["t_ns"] or 0) <= drop)
    after_idx = next(i for i, a in enumerate(groups) if a["t_ns"] == finish)
    kept = groups[start_idx:after_idx + 1]
    for a in kept:
        a["tx"] = [p for p in a["tx"] if drop <= p["t_ns"] <= finish]
    return dict(drop_ns=drop, repair_ns=repair, recovery_ack_ns=finish, high_at_repair=high,
                ack_groups=kept, originals=originals, coverage=coverage,
                all_bytes_covered=coverage == [(0, size)])


def valid_targets(case, targets, originals, size):
    if case not in ("burst", "tail"):
        return len(targets) == 1
    n = 5 if case == "burst" else 2
    pairs = [(off, length) for off, length in originals if off in set(targets)]
    if len(pairs) != n or [x for x, _ in pairs] != targets:
        return False
    i = originals.index(pairs[0])
    if originals[i:i + n] != pairs or any(a + length != b for (a, length), (b, _) in zip(pairs, pairs[1:])):
        return False
    return case != "tail" or (pairs == originals[-2:] and pairs[-1][0] + pairs[-1][1] == size)


def phase(row):
    if row.get("ca_state", row.get("ca")) not in ("open", "disorder"):
        return "unresolved"
    return "slow" if row["cwnd"] < row["ssthresh"] else "avoidance"


def sample_view(row):
    if not row:
        return None
    return {k: row[k] for k in ("t", "cwnd", "ssthresh", "ca_state", "ca", "srtt_us", "srtt_ns",
                                 "snd_una_off", "snd_nxt_off", "bytes_acked", "total_retrans") if k in row}


def bracket_phase(samples, t):
    before = next((x for x in reversed(samples) if x["t"] <= t), None)
    after = next((x for x in samples if x["t"] >= t), None)
    observed = phase(before) if before and after and phase(before) == phase(after) else "unresolved"
    return dict(phase=observed, before=sample_view(before), after=sample_view(after))


def state_interval(events, drop, last, srtt_us):
    """Bound the first continuous Recovery/Loss state observed in the damaged flight.

    Times are sender monotonic nanoseconds. No active sample, or no subsequent
    exit, leaves duration unknown. A Lost-to-Recovery transition is still active.
    """
    active = ("loss", "recovery", "cwr")
    prior = drop
    opened = None
    latest = None
    states = []
    for event in events:
        t = event["t"]
        if not drop <= t <= last:
            continue
        ca = event.get("ca_state", event.get("ca"))
        if ca in active:
            if opened is None:
                opened = [prior, t]
            latest = t
            if not states or states[-1] != ca:
                states.append(ca)
        elif opened and ca in ("open", "disorder"):
            return dict(states=states, entry_bracket_ns=opened, exit_bracket_ns=[latest, t],
                        duration_rtts=[(latest - opened[1]) / (srtt_us * 1000),
                                       (t - opened[0]) / (srtt_us * 1000)] if srtt_us else None)
        prior = t
    return dict(states=states, entry_bracket_ns=opened, exit_bracket_ns=None, duration_rtts=None)


def pcap_records(path):
    with path.open("rb") as f:
        hdr = f.read(24)
        magic = hdr[:4]
        if len(hdr) != 24 or magic not in (bytes.fromhex(x) for x in
                                           ("d4c3b2a1", "4d3cb2a1", "a1b2c3d4", "a1b23c4d")):
            raise ValueError(f"bad pcap header in {path}")
        decoder = struct.Struct(("<" if magic[0] in (0xd4, 0x4d) else ">") + "IIII")
        n = 0
        while h := f.read(16):
            if len(h) != 16:
                raise ValueError(f"short pcap record in {path}")
            _, _, cap, orig = decoder.unpack(h)
            if cap > min(65535, orig) or len(f.read(cap)) != cap:
                raise ValueError(f"bad pcap record in {path}")
            n += 1
        return n


def report_counters(rd, meta):
    if meta["impl"] == "utcp":
        raw = A.read_jsonl(rd / "stats.json")[-1]
        return {k: raw[k] for k in COUNTERS}, {k: v for k, v in raw.items() if "Undo" in k or "SpuriousRTO" in k}
    sender = meta["containers"]["snd"]
    records = [A.parse_nstat(A.parse_record((rd / f"{p}/record.txt").read_text())[(sender, "nstat -asz")])
               for p in ("pre", "post")]
    a, b = records
    return ({k: b[k] - a[k] for k in COUNTERS},
            {k: b[k] - a[k] for k in b if k in a and ("Undo" in k or "SpuriousRTO" in k)})


def json_write(path, value):
    path.write_text(json.dumps(value, indent=1) + "\n")


def analyze_run(rd):
    meta = json.loads((rd / "meta.json").read_text())
    summ = json.loads((rd / "summary.json").read_text())
    case, size = meta["case"], meta["bytes"]
    checks = {}
    snd, rcv = [A.read_jsonl(rd / f"{end}.jsonl") for end in ("snd", "rcv")]
    ss, rs = (A.find_event(x, "summary") or {} for x in (snd, rcv))
    cc = meta["cc"]
    samples = [s for s in snd if s.get("ev") == "sample"]
    checks["delivery"] = (meta["sender_exit"] == 0 and ss.get("ok") and rs.get("ok") and
                          ss.get("bytes") == rs.get("bytes") == size and ss.get("sha256") == rs.get("sha256")
                          and bool(re.fullmatch("[0-9a-f]{64}", ss.get("sha256") or "")))
    checks["sender_cc"] = (ss.get("cc") == cc and bool(samples) and all(s["cc_name"] == cc for s in samples))
    checks["path"] = (ss.get("backend") == ("utcp" if meta["impl"] == "utcp" else "kernel")
                      and rs.get("backend") == "kernel" and meta["profile"] == "linux")
    checks["no_local_drops"] = (summ.get("local_drops") == {} and not summ.get("stack_local_drops")
                                and not summ.get("stack_device") and all((summ.get(k) or {}).get("dropped") == 0
                                for k in ("netem", "tbf")))
    checks["non_timing"] = (meta["slot"] == 2 and not meta["timing"] and len(meta["cpusets"]) == 4
                            and all(set(A.cpu_list(x)) == set(range(16, 32)) for x in meta["cpusets"].values()))
    drops = meta["drops"][0]
    offsets, copies_text = drops[drops.index("--offsets") + 1], drops[drops.index("--copies") + 1]
    copies = [int(k) for k in copies_text.split(",")]
    capstats = {}
    keyed, reverse, rows = [], [], None
    dst = bytes(int(x) for x in meta["rcv_ip"].split("."))
    for name in ("r1-in", "r1-out", "r2-out"):
        p = rd / f"{name}.pcap"
        before, syn = D.keyed(p, meta["rcv_ip"], 5201)
        if name == "r1-in":
            isn = syn
        if syn is None or syn != isn:
            raise ValueError(f"missing or different SYN in {name}")
        packets, seen = wire_stream(p, dst, isn)
        if rows is None:
            rows = packets
        reverse.append(seen)
        keyed.append(before)
        cap = summ["capture"][name]
        n = pcap_records(p)
        capstats[name] = {**cap, "records": n, "reverse_flow_packets": seen.total()}
        checks[f"{name}_capture"] = (n > 0 and cap["kernel_dropped"] == 0 and
                                     n == cap["captured"] == cap["received_by_filter"])
    checks["reverse_path_complete"] = reverse[0] == reverse[1] == reverse[2]
    ranges = D.target_ranges(offsets)
    latched = D.latched(keyed[0], isn, ranges)
    missing = D.missing(keyed[0], keyed[1], isn)
    expected = sorted((off, k) for tg in latched for off in tg for k in copies)
    checks["r1_drop_selection"] = ([len(tg) for tg in latched] == [n for _, _, n in ranges]
                                   and sorted((m["offset"], m["copy"]) for m in missing) == expected
                                   and not D.missing(keyed[1], keyed[0], isn))
    checks["r2_path_complete"] = not D.missing(keyed[1], keyed[2], isn) and not D.missing(keyed[2], keyed[1], isn)
    nft_hits = [int(n) for n in re.findall(r"counter packets (\d+) bytes \d+ drop", (rd / "drop-r1.txt").read_text())]
    checks["nft_hits"] = bool(nft_hits) and sum(nft_hits) == len(expected)
    armed = re.search(r"syn isn (\d+).*armed ([0-9.]+) ms after it \(nft rc 0\)", (rd / "drop-r1.log").read_text())
    armed_ms = float(armed[2]) if armed else None
    checks["watcher"] = bool(armed and int(armed[1]) == isn and armed_ms < meta["rtt"])
    targets = latched[-1]
    if not targets:
        raise ValueError("no latched comparison target")
    e = wire_episode(rows, targets, size)
    originals = e.pop("originals")
    checks["workload"] = valid_targets(case, targets, originals, size) and e["all_bytes_covered"]
    # A preceding warm-up drop puts both algorithms into avoidance. Keep it
    # visible in the whole-run counters and out of the measured wire interval.
    warmup = None
    if case == "avoidance":
        warmup = wire_episode(rows, latched[0], size)
        checks["separate_warmup"] = warmup["recovery_ack_ns"] < e["drop_ns"]
        warmup = {k: warmup[k] for k in ("drop_ns", "repair_ns", "recovery_ack_ns")}
    clock = A.clock_of(snd)
    tdrop, tend = (clock.to_mono(e[k]) for k in ("drop_ns", "recovery_ack_ns"))
    sampled_phase = bracket_phase(samples, tdrop)
    detail = sampled_phase
    state_events = samples
    post = next((s for s in samples if s["t"] >= tend and s["ca_state"] in ("open", "disorder")
                 and s["bytes_acked"] >= e["high_at_repair"] + 1), None)
    source = "10ms TCP_INFO; first subsequent sample in Open/Disorder covering the recovery ACK"
    if meta["impl"] == "utcp":
        config = A.find_event(snd, "config") or {}
        checks["linux_config"] = (config.get("quickack") == "linux" and config.get("rack_tlp") == "true"
                                  and config.get("recovery_reduction") == "prr")
        trace = A.read_jsonl(rd / "trace.jsonl")
        state_events = (v for v in trace if v["ev"] in ("ack", "tx", "rto"))
        tx = collections.defaultdict(list)
        for v in trace:
            if v["ev"] == "tx" and v["len"] > 0:
                tx[(v["seq"] - isn - 1) % MOD, v["len"]].append(v)
        loss = next(p for p in missing if p["offset"] == targets[0] and p["copy"] == 1)
        original = tx.get((targets[0], loss["len"]), [None])[0]
        detail = {"phase": phase(original) if original else "unresolved", "original_tx": sample_view(original)}
        post = next((s for s in trace if s["ev"] == "ack" and s["t"] >= tdrop
                     and s["ca"] in ("open", "disorder") and s["snd_una_off"] >= e["high_at_repair"]), None)
        source = "post-ACK stack trace in Open/Disorder covering pre-repair flight"
        # All traffic is on one flow. Number equal sequence/length sends
        # separately from the nft copy number (which is per sequence).
        occurrences = collections.Counter()
        lookup = {}
        for t, kind, off, n in rows:
            if kind == "tx":
                k = (off, n)
                index = occurrences[k]
                occurrences[k] += 1
                candidates = tx.get(k, [])
                lookup[t, off, n] = candidates[index] if index < len(candidates) else None
        for a in e["ack_groups"]:
            for p in a["tx"]:
                tr = lookup.get((p["t_ns"], p["off"], p["length"]))
                p["trace_tx"] = ({k: tr[k] for k in ("t", "tx", "ca", "cwnd", "ssthresh")} if tr else None)
        checks["trace_matches_wire"] = bool(original) and all(p["trace_tx"] for a in e["ack_groups"] for p in a["tx"])
    if case in ("slow", "avoidance"):
        checks["phase"] = detail["phase"] == case
    checks["post_cwnd"] = post is not None
    before = sampled_phase["before"]
    srtt = (before or {}).get("srtt_us")
    checks["srtt_observed"] = bool(srtt and srtt > 0)
    counters, undo = report_counters(rd, meta)
    state = state_interval(state_events, tdrop, post["t"] if post else tend, srtt)
    sample_gaps = [b["t"] - a["t"] for a, b in zip(samples, samples[1:])]

    groups = e.pop("ack_groups")
    with (rd / "recovery-acks.jsonl").open("w") as out:
        for g in groups:
            print(json.dumps(g, separators=(",", ":")), file=out)
    if meta["impl"] == "utcp":
        loss_signals = [dict(t=p["t_ns"], tx=p["trace_tx"]["tx"], off=p["off"])
                        for a in groups for p in a["tx"] if p.get("trace_tx")
                        and p["trace_tx"]["tx"] in ("rto_rexmit", "tlp")]
    else:
        loss_signals = None
    result = dict(run=rd.name, case=case, rep=meta["rep"], cc=cc, impl=meta["impl"],
                  commit=meta["commit"], bulk_sha256=meta["bulk_sha256"], checks=checks,
                  valid=all(checks.values()), delivery={k: [ss.get(k), rs.get(k)] for k in ("bytes", "sha256", "cc")},
                  isn=isn, latched=latched, dropped=missing, capture=capstats, nft_drop_hits=nft_hits,
                  armed_ms=armed_ms, phase=detail, phase_tcp_info=sampled_phase, warmup=warmup,
                  post_cwnd=sample_view(post), post_cwnd_source=source,
                  post_ms_from_wire_ack=(post["t"] - tend) / 1e6 if post else None,
                  srtt_before_drop_us=srtt, counters=counters, undo_counters=undo,
                  ack_groups=len(groups), wire=e, state_interval=state, stack_probe_rto_tx=loss_signals,
                  sample_count=len(samples), max_sample_gap_ms=max(sample_gaps, default=0) / 1e6,
                  wire_rtts={
                      k: (e["recovery_ack_ns"] - e[k]) / (srtt * 1000) if srtt else None
                      for k in ("drop_ns", "repair_ns")})
    json_write(rd / "recovery.json", result)
    return result


def decisions(rd, hole):
    """Compare at first-hole-relative offsets. Preserve ACK order, empty ACK groups and repacketization."""
    def relative(groups):
        for g in groups:
            yield dict(ack=None if g["ack"] is None else g["ack"] - hole,
                       sack=[[a - hole, b - hole] for a, b in g["sack"]],
                       tx=[[p["off"] - hole, p["length"], p["copy"], p["repeat_bytes"]] for p in g["tx"]])
    return list(relative(A.read_jsonl(rd / "recovery-acks.jsonl")))


def pair_report(base):
    pairs, missing, provenance = [], [], set()
    for case, cc, rep in itertools.product(CASES, CCS, (1, 2)):
        names = [f"{case}-{cc}-r{rep}-{impl}" for impl in IMPLS]
        if not all((base / name / "recovery.json").exists() for name in names):
            missing.extend(n for n in names if not (base / n / "recovery.json").exists())
            continue
        a, b = [json.loads((base / n / "recovery.json").read_text()) for n in names]
        if not all("latched" in x for x in (a, b)):
            pairs.append(dict(runs=names, comparable=False, reason="incomplete analysis"))
            continue
        for x in (a, b):
            provenance.add((x["commit"], x["bulk_sha256"]))
        left, right = [decisions(base / n, r["latched"][-1][0]) for n, r in zip(names, (a, b))]
        def first_difference(l, r):
            return next(({"index": i, "utcp": x, "linux": y} for i, (x, y) in
                         enumerate(itertools.zip_longest(l, r)) if x != y), None)
        first = first_difference(left, right)
        repairs = [[v for g in seq for v in g["tx"] if v[3]] for seq in (left, right)]
        comparable = (a["valid"] and b["valid"] and a["commit"] == b["commit"] and
                      a["bulk_sha256"] == b["bulk_sha256"] and
                      all((r["case"], r["cc"], r["rep"], r["impl"], r["run"]) == (case, cc, rep, impl, n)
                          for r, impl, n in zip((a, b), IMPLS, names)))
        pairs.append(dict(runs=names, comparable=comparable,
                          ack_groups=[len(left), len(right)], first_ack_difference=first,
                          repair_order=repairs, first_repair_difference=first_difference(*repairs),
                          counters=[r["counters"] for r in (a, b)], warmup=[r["warmup"] for r in (a, b)],
                          state_intervals=[r["state_interval"] for r in (a, b)],
                          stack_probe_rto_tx=a["stack_probe_rto_tx"], linux_undo=b["undo_counters"],
                          srtt_us=[r["srtt_before_drop_us"] for r in (a, b)],
                          repair_to_ack_rtts=[r["wire_rtts"]["repair_ns"] for r in (a, b)],
                          post_cwnd=[(r["post_cwnd"] or {}).get("cwnd") for r in (a, b)],
                          note=("wire decisions differ; causal attribution requires review of ACKs and samples"
                                if first else "identical ordered wire decisions for the observed ACK interval")))
    result = dict(expected_runs=40, missing=missing, pairs=pairs,
                  revisions=sorted(provenance), complete=len(pairs) == 20 and len(provenance) == 1 and all(p["comparable"] for p in pairs))
    json_write(base / "recovery-pairs.json", result)
    return result


def analyze_saved(rd):
    """Leave a failed attempt readable even when an essential input is absent."""
    try:
        return analyze_run(rd)
    except (KeyError, IndexError, ValueError, OSError, TypeError, StopIteration, struct.error) as err:
        failure = dict(run=rd.name, valid=False, analysis_error=f"{type(err).__name__}: {err}")
        json_write(rd / "recovery.json", failure)
        return failure


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = ap.add_subparsers(dest="cmd", required=True)
    run = commands.add_parser("run", description="Existing non-timing slot 2; use a fresh campaign per attempt.")
    run.add_argument("--campaign", required=True)
    for key, choices in (("case", CASES), ("cc", CCS), ("impl", IMPLS)):
        run.add_argument("--" + key, action="append", choices=list(choices))
    run.add_argument("--rep", type=int, action="append", choices=[1, 2])
    run.add_argument("--list", action="store_true", help="print the selected plan without starting containers")
    commands.add_parser("analyze", help="re-analyze one run in the mounted volume").add_argument("directory", type=Path)
    report = commands.add_parser("report", help="write the 20 paired observations and list missing runs")
    report.add_argument("directory", type=Path)
    args = ap.parse_args()
    if args.cmd == "analyze":
        result = analyze_saved(args.directory)
        print(json.dumps({k: result[k] for k in ("run", "valid", "checks", "analysis_error") if k in result}))
        return int(not result["valid"])
    if args.cmd == "report":
        result = pair_report(args.directory)
        print(json.dumps({"complete": result["complete"], "pairs": len(result["pairs"]), "missing": result["missing"]}))
        return int(not result["complete"])
    try:
        jobs = list(plan(args.campaign, args.case or CASES, args.cc or CCS, args.impl or IMPLS, args.rep or (1, 2)))
    except ValueError as err:
        ap.error(str(err))
    if len({n for n, _ in jobs}) != len(jobs):
        ap.error("duplicate selectors")
    if args.list:
        for n, s in jobs:
            print(json.dumps(dict(run=n, **s)))
        return 0
    import matrix as M
    slot = M.Slot(2)
    if not all(set(A.cpu_list(c)) == set(range(16, 32)) for c in slot.cpus.values()):
        ap.error("slot 2 containers must be pinned to CPUs 16-31")
    base = f"/data/m2/{args.campaign}"
    existing = [name for name, _ in jobs if M.dexec(slot.snd, f"if test -e {base}/{name}; then echo exists; fi").strip()]
    if existing:
        ap.error(f"existing attempts in this campaign: {', '.join(existing)}; choose a fresh campaign")
    meta = M.static_meta()
    if not meta["bulk_sha256"] or not meta["core_sha256"] or meta["commit"] == "unknown":
        ap.error("missing compiled binary, library or source revision (UTCP_COMMIT)")
    ok = True
    for name, spec in jobs:
        M.log(name)
        M.one_run(slot, args.campaign, name, spec, meta)
        cmd = f"nice -n 10 python3 -I /utcp/tools/m2/recovery_compare.py analyze {base}/{name}"
        M.log(M.dexec(slot.snd, cmd, check=False).strip())
        result = json.loads(M.dexec(slot.snd, f"cat {base}/{name}/recovery.json"))
        ok = ok and result["valid"]
    M.log(M.dexec(slot.snd, f"nice -n 10 python3 -I /utcp/tools/m2/recovery_compare.py report {base}",
                  check=False).strip())
    if len(jobs) == 40:
        ok = ok and json.loads(M.dexec(slot.snd, f"cat {base}/recovery-pairs.json"))["complete"]
    return int(not ok)


if __name__ == "__main__":
    sys.exit(main())
