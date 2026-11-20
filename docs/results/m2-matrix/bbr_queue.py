"""Aggregate only. Read the ten registered transfers inside the offline evidence container."""

import argparse
import csv
import gzip
import bisect
import collections
import hashlib
import ipaddress
import json
import math
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit import preregistered

FACES = ("r1-in", "r2-out")
ZERO_LOSS = "10-20-0-0.5"
PREFIXES = {ZERO_LOSS: "bbr-shallow", "10-20-0.1-0.5": "bbr-shallow-loss"}


def registered_names(cell):
    return tuple(
        f"{cell}-bbr-r{rep}-{impl}" for rep in range(5) for impl in ("linux", "utcp")
    )


C = collections.Counter


def digest(path):
    with path.open("rb") as src:
        return hashlib.file_digest(src, "sha256").hexdigest()


def packets(path, dest, controls=None):
    items, addresses, ports = [], set(), set()
    syn = set()
    with path.open("rb") as f:
        magic = f.read(4)
        endian, scale = {
            bytes.fromhex(k): v
            for k, v in (
                ("4d3cb2a1", ("<", 1)),
                ("a1b23c4d", (">", 1)),
                ("d4c3b2a1", ("<", 1000)),
                ("a1b2c3d4", (">", 1000)),
            )
        }[magic]
        major, minor, _, _, snap, link = struct.unpack(endian + "HHIIII", f.read(20))
        assert (major, minor, link) == (2, 4, 1)
        records = 0
        while h := f.read(16):
            sec, sub, cap, wire = struct.unpack(endian + "IIII", h)
            b = f.read(cap)
            records += 1
            if b[12:14] != b"\x08\x00" or b[30:34] != dest:
                continue
            tcp = 14 + (b[14] & 15) * 4
            timestamp = sec * 10**9 + sub * scale
            if b[23] != 6:
                if controls is not None and b[23] == 1 and b[tcp] == 8:
                    assert tcp + 8 <= len(b)
                    controls.append(
                        (timestamp, ("echo_request", b[18:20], b[tcp : tcp + 8]))
                    )
                continue
            sport, dport, seq, ack = struct.unpack_from("!HHII", b, tcp)
            if dport != 5201:
                continue
            addresses.add(str(ipaddress.IPv4Address(b[26:30])))
            ports.add(sport)
            if b[tcp + 13] & 2:
                syn.add(seq)
            hdr = (b[tcp + 12] >> 4) * 4
            length = int.from_bytes(b[16:18], "big") - (tcp - 14) - hdr
            assert length >= 0 and hdr + tcp <= len(b)
            if not length:
                if controls is not None:
                    controls.append(
                        (
                            timestamp,
                            (
                                "tcp_control",
                                b[18:20],
                                b[tcp : tcp + 16],
                                b[tcp + 18 : tcp + hdr],
                            ),
                        )
                    )
                continue
            # Transport checksum, L2 and router-dependent IPv4 fields excluded.
            key = (
                seq,
                length,
                int.from_bytes(b[18:20], "big"),
                ack,
                b[tcp + 12 : tcp + 16],
                b[tcp + 18 : tcp + hdr],
            )
            items.append((sec * 10**9 + sub * scale, key))
    assert len(syn) == len(ports) == len(addresses) == 1
    return items, dict(
        resolution_ns=scale,
        snaplen=snap,
        records=records,
        src=addresses.pop(),
        sport=ports.pop(),
        isn=syn.pop(),
    )


def distribution(values):
    s = sorted(values)
    return [s[math.ceil(len(s) * v) - 1] for v in (0.5, 0.9, 0.99, 1)]


def snapshot(p, kind):
    return int(
        re.search(
            r"^qdisc " + kind + r" [^\n]+\n Sent [^\n]*?\(dropped (\d+)",
            p.read_text(),
            re.M,
        )[1]
    )


def lerp(x, y, t):
    if not x or len(x) != len(y) or any(b <= a for a, b in zip(x, x[1:])):
        raise ValueError("sampling timestamps must be present and strictly increasing")
    if not x[0] <= t <= x[-1]:
        raise ValueError("measurement boundary is not bracketed by samples")
    i = bisect.bisect_left(x, t)
    if x[i] == t:
        return float(y[i])
    return y[i - 1] + (y[i] - y[i - 1]) * (t - x[i - 1]) / (x[i] - x[i - 1])


def check_schedule(campaign, names):
    planned = preregistered(campaign)
    for name in names:
        meta = json.loads((campaign / name / "meta.json").read_text())
        spec = planned[name]
        for key in (
            "run",
            "cell",
            "algo",
            "impl",
            "in_group",
            "group",
            "seed",
            "order",
            "rep",
            "plan_seed",
        ):
            if meta[key] != spec[key]:
                raise ValueError(f"{name} differs from the registered {key}")


def project(campaign, destination, cells=(ZERO_LOSS,)):
    """Store packet times and exact fingerprint equivalence classes without headers or payload."""
    names = [n for cell in cells for n in registered_names(cell)]
    check_schedule(campaign, names)
    destination.mkdir(exist_ok=False)
    for name in names:
        directory = campaign / name
        target = ipaddress.IPv4Address(
            json.loads((directory / "meta.json").read_text())["rcv_ip"]
        ).packed
        classes = {}
        projection = {}
        for face in FACES:
            path = directory / (face + ".pcap")
            control_rows = [] if not name.startswith(ZERO_LOSS + "-") else None
            packets_seen, header = packets(path, target, control_rows)
            rows = []
            for timestamp, fingerprint in packets_seen:
                key = classes.setdefault(fingerprint, len(classes))
                seq, length = fingerprint[:2]
                rows.append((timestamp, seq, length, key))
            projection[face] = dict(header=header, rows=rows, sha256=digest(path))
            if control_rows is not None:
                projection[face]["controls"] = [
                    (t, k[0], classes.setdefault(k, len(classes)))
                    for t, k in control_rows
                ]
        with (destination / (name + ".json.gz")).open("xb") as raw:
            with gzip.GzipFile(
                filename="", fileobj=raw, mode="wb", mtime=0, compresslevel=1
            ) as gz:
                gz.write(json.dumps(projection, separators=(",", ":")).encode())


def eligible_doublets(times, missing, lo, hi, cutoff):
    """Full-capture size-two groups whose second ingress timestamp is in [lo, hi)."""
    exposures = drops = 0
    start = 0
    for end in range(1, len(times) + 1):
        if end < len(times) and times[end] - times[end - 1] <= cutoff:
            continue
        if end - start == 2 and lo <= times[start + 1] < hi:
            exposures += 1
            drops += int(missing[start + 1])
        start = end
    return exposures, drops


def validate_forward_times(ingress, downstream, downstream_resolution_ns):
    """Require a feasible one-to-one causal match on the two router capture clocks."""
    arrivals = collections.defaultdict(list)
    departures = collections.defaultdict(list)
    for t, key in ingress:
        arrivals[key].append(t)
    for t, key in downstream:
        departures[key].append(t)
    for key, times in departures.items():
        before = sorted(arrivals[key])
        after = sorted(times)
        if len(after) > len(before):
            raise ValueError(
                "downstream fingerprint has no matching ingress occurrence"
            )
        # Pair sorted indistinguishable occurrences. If even the earliest unused
        # ingress occurs later than the latest representable downstream instant,
        # no causal assignment exists on the shared host realtime clock.
        for earlier, later in zip(before, after):
            if later + downstream_resolution_ns - 1 < earlier:
                raise ValueError(
                    "downstream packet precedes matching ingress beyond capture resolution"
                )


def validate_capture_accounting(text, physical_packets, face):
    counts = {}
    for label in ("captured", "received by filter", "dropped by kernel"):
        values = re.findall(r"^(\d+) packets? " + label + r"$", text, re.M)
        if len(values) != 1:
            raise ValueError(
                f"{face}: missing or duplicate tcpdump accounting for {label}"
            )
        counts[label] = int(values[0])
    if not (
        counts["captured"] == counts["received by filter"] == physical_packets
        and counts["dropped by kernel"] == 0
    ):
        raise ValueError(
            f"{face}: incomplete packet capture cannot locate missing transmissions"
        )


def control_accounting(upstream, downstream, precision, lo, hi):
    result = {}
    for kind in ("echo_request", "tcp_control"):
        a = [(t, k) for t, k in upstream if k[0] == kind]
        b = [(t, k) for t, k in downstream if k[0] == kind]
        before = C(k for t, k in a)
        after = C(k for t, k in b)
        if after - before or any(0 < after[k] < n for k, n in before.items()):
            raise ValueError(f"ambiguous or unmatched downstream {kind}")
        validate_forward_times(a, b, precision)
        missing = [t for t, k in a if k not in after]
        result[kind] = dict(
            ingress=len(a),
            downstream=len(b),
            missing=len(missing),
            primary_missing=sum(lo <= t < hi for t in missing),
        )
    return result


def analyze(p, projected=None, source_hashes=None, doublet_counts=None):
    meta = json.loads((p / "meta.json").read_text())
    summ = json.loads((p / "summary.json").read_text())
    assert summ["valid"] and not summ["invalid"] and meta["rerun"] == 0
    srows = [json.loads(l) for l in (p / "snd.jsonl").read_text().splitlines()]
    clock = next(r for r in srows if r["ev"] == "clock")
    off = clock["realtime_ns"] - clock["monotonic_ns"]
    lo = summ["t0_ns"] + 5_000_000_000 + off
    hi = summ["window_end_ns"] + off
    dest = ipaddress.IPv4Address(meta["rcv_ip"]).packed
    check_controls = meta.get("cell") == "10-20-0.1-0.5"
    controls = [[], []] if check_controls else [None, None]
    if projected:
        with gzip.open(projected / (p.name + ".json.gz"), "rt") as stream:
            compact = json.load(stream)
        views = []
        for face in FACES:
            item = compact[face]
            assert item["sha256"] == source_hashes[f"{p.name}/{face}.pcap"]
            views.append(
                (
                    [(t, (seq, size, key)) for t, seq, size, key in item["rows"]],
                    item["header"],
                )
            )
        (a, ah), (b, bh) = views
        if check_controls:
            controls = [
                [(t, (kind, key)) for t, kind, key in compact[f]["controls"]]
                for f in FACES
            ]
    else:
        a, ah = packets(p / "r1-in.pcap", dest, controls[0])
        b, bh = packets(p / "r2-out.pcap", dest, controls[1])
    for k in ("sport", "isn"):
        assert ah[k] == bh[k]
    for face, head in [("r1-in", ah), ("r2-out", bh)]:
        txt = (p / (face + ".tcpdump.txt")).read_text()
        validate_capture_accounting(txt, head["records"], face)
        if "capture_incomplete:" + face in summ["flags"]:
            raise ValueError(
                f"{face}: incomplete native capture flag prevents packet-loss attribution"
            )
    before = C(k for t, k in a)
    after = C(k for t, k in b)
    assert not (after - before), (len(after - before), ah, bh)
    # Mixed-outcome collisions cannot be allocated to an individual ingress attempt.
    collisions = [k for k, n in before.items() if 0 < after[k] < n]
    assert not collisions, ("ambiguous", len(collisions))
    validate_forward_times(a, b, bh["resolution_ns"])
    absent = [k not in after for t, k in a]
    times = [t for t, k in a]
    assert times == sorted(times)
    if doublet_counts is not None:
        doublet_counts[p.name] = eligible_doublets(times, absent, lo, hi, 100_000)
    seen = set()
    maxend = 0
    repeat = []
    below = 0
    for t, k in a:
        seq, n = k[:2]
        rel = (seq - ah["isn"]) % (2**32)
        assert rel < 2**31
        rep = (seq, n) in seen
        below += int(not rep and rel < maxend)
        maxend = max(maxend, rel + n)
        seen.add((seq, n))
        repeat.append(rep)
    assert below == 0, ("overlap/reordering needs classification", below)
    mask = [i for i, t in enumerate(times) if lo <= t < hi]
    indexset = set(mask)
    partition = C(
        ("repeat" if repeat[i] else "first") + ("_missing" if absent[i] else "_passed")
        for i in mask
    )
    pre = p / "pre/record.txt"
    post = p / "post/record.txt"
    delta = {
        kind: snapshot(post, kind) - snapshot(pre, kind) for kind in ("tbf", "netem")
    }
    # Counters include all traffic; report the residual explicitly, incl. probes/control.
    txt = (p / "tbf.txt").read_text()
    q = re.findall(
        r"^@ (\d+)\.(\d+)\nqdisc tbf [^\n]+\n Sent [^\n]+?\(dropped (\d+),[^\n]*\n backlog (\d+)b",
        txt,
        re.M,
    )
    qt = [int(s) * 10**9 + int(fr.ljust(9, "0")) for s, fr, _, _ in q]
    qn = [int(n) for _, _, n, _ in q]
    qback = [int(q[i][3]) for i, t in enumerate(qt) if lo <= t < hi]
    snd = [r for r in srows if r["ev"] == "sample" and lo <= r["t"] + off < hi]
    trace = C()
    if meta["impl"] == "utcp":
        for line in (p / "trace.jsonl").read_text().splitlines():
            r = json.loads(line)
            if lo <= r["t"] + off < hi:
                trace[(r.get("tx", r["ev"]), r.get("bbr_mode", "unknown"))] += 1
    groups = {}
    # Define a batch as forward data attempts linked by adjacent r1 gaps <= cutoff.
    # Use full capture before window selection so ranks at boundaries are preserved.
    for cutoff in [0, 1000, 10000, 100000, 250000]:
        start = 0
        group = {}
        ranks = C()
        sizes = C()
        strata = C()
        batch_recovery = C()
        for j in range(1, len(times) + 1):
            if j < len(times) and times[j] - times[j - 1] <= cutoff:
                continue
            n = j - start
            has_rep = any(repeat[start:j])
            for i in range(start, j):
                if not lo <= times[i] < hi:
                    continue
                rank = i - start + 1
                outcome = "lost" if absent[i] else "passed"
                ranks[f"{min(rank, 9)}_{outcome}"] += 1
                sizes[f"{min(n, 10)}_{outcome}"] += 1
                rclass = "repeat" if repeat[i] else "first"
                batch_recovery[
                    f"{rclass}_batch_has_repeat{int(has_rep)}_{outcome}"
                ] += 1
                if i == max(start, bisect.bisect_left(times, lo)):
                    strata[str(n)] += 1
            start = j
        groups[str(cutoff)] = dict(
            rank=ranks, size=sizes, batches=strata, mixed=batch_recovery
        )
    raw_snd = [r for r in srows if r["ev"] == "sample"]
    sx = [r["t"] + off for r in raw_snd]

    def sender_delta(field):
        sy = [r[field] for r in raw_snd]
        return lerp(sx, sy, hi) - lerp(sx, sy, lo)

    ds = sender_delta("data_segs_out")
    rs = sender_delta("total_retrans")
    assert abs(100 * rs / ds - summ["retrans_pct"]) < 0.000001
    payload_hist = C(k[1] for i, (_, k) in enumerate(a) if i in indexset)
    missing_payload_hist = C(a[i][1][1] for i in mask if absent[i])
    inputs = [
        "r1-in.pcap",
        "r2-out.pcap",
        "r1-in.tcpdump.txt",
        "r2-out.tcpdump.txt",
        "summary.json",
        "meta.json",
        "shape.txt",
        "snd.jsonl",
        "tbf.txt",
        "pre/record.txt",
        "post/record.txt",
    ]
    if meta["impl"] == "utcp":
        inputs.append("trace.jsonl")
    for head in (ah, bh):
        del head["isn"]
    result = dict(
        data_segments_socket=ds,
        retrans_segments_socket=rs,
        primary_payload_bytes=payload_hist,
        primary_missing_payload_bytes=missing_payload_hist,
        lifetime_repeats_missing=sum(absent[i] and repeat[i] for i in range(len(a))),
        run=p.name,
        seed=meta["seed"],
        commit=meta["commit"],
        window_realtime_ns=[lo, hi],
        pcap_r1=ah,
        pcap_r2=bh,
        pcap_non_microsecond_r1=sum(t % 1000 != 0 for t in times),
        primary_r1=partition,
        lifetime_data_missing=sum(absent),
        lifetime_counter_delta=delta,
        first_seen_below_highest=below,
        ambiguous_matching=len(collisions),
        drops_primary_interpolated=lerp(qt, qn, hi) - lerp(qt, qn, lo),
        primary_gaps_ns=distribution([times[i] - times[i - 1] for i in mask if i]),
        primary_tbf_backlog_bytes=distribution(qback),
        queue_sample_spacing_ns=distribution([v - u for u, v in zip(qt, qt[1:])]),
        primary_cwnd=distribution([r["cwnd"] for r in snd]),
        primary_pacing_Bps=distribution([r["pacing_rate"] for r in snd]),
        primary_retrans_pct_socket=summ["retrans_pct"],
        flags=summ["flags"],
        retrans_mode={str(k): v for k, v in trace.items()},
        groups=groups,
        sha256={
            k: source_hashes[f"{p.name}/{k}"]
            if projected and k.endswith(".pcap")
            else digest(p / k)
            for k in inputs
        },
    )

    if check_controls:
        result["forward_controls"] = control_accounting(
            *controls, bh["resolution_ns"], lo, hi
        )
        result["qdisc_unaccounted"] = (
            sum(delta.values())
            - sum(absent)
            - sum(v["missing"] for v in result["forward_controls"].values())
        )
    return result


def report(campaign, out, projected=None, cells=(ZERO_LOSS,)):
    check_schedule(campaign, [n for cell in cells for n in registered_names(cell)])
    source_hashes = {}
    if projected:
        for line in (campaign / "source-manifest.sha256").read_text().splitlines():
            sha, name = line.split("  ", 1)
            source_hashes[name] = sha
    out.mkdir(exist_ok=False)
    for cell in cells:
        cell_report(campaign, out, cell, projected, source_hashes)


def cell_report(campaign, out, cell, projected, source_hashes):
    prefix = PREFIXES[cell]
    doublet_counts = {}
    result = [
        analyze(campaign / name, projected, source_hashes, doublet_counts)
        for name in registered_names(cell)
    ]
    assert all(a["seed"] == b["seed"] for a, b in zip(result[::2], result[1::2]))
    (out / (prefix + "-packet-replay.json")).write_text(
        json.dumps(result, sort_keys=True, indent=1) + "\n"
    )
    rows = []
    for d in result:
        _, suffix = d["run"].rsplit("-r", 1)
        rep, impl = suffix.split("-")
        first = d["primary_r1"]
        doublets, missing = doublet_counts[d["run"]]
        rows.append(
            dict(
                rep=int(rep),
                seed=d["seed"],
                impl=impl,
                socket_retrans_pct=round(d["primary_retrans_pct_socket"], 6),
                r1_first_attempts=first.get("first_passed", 0)
                + first.get("first_missing", 0),
                r1_repeats=first.get("repeat_passed", 0)
                + first.get("repeat_missing", 0),
                first_missing=first.get("first_missing", 0),
                repeat_missing=first.get("repeat_missing", 0),
                two_packet_groups_100us=doublets,
                missing_second_100us=missing,
                missing_second_pct=round(100 * missing / doublets, 5)
                if doublets
                else None,
                interpolated_tbf_drops=round(d["drops_primary_interpolated"], 5),
                lifetime_missing=d["lifetime_data_missing"],
                lifetime_tbf_drops=d["lifetime_counter_delta"]["tbf"],
                lifetime_netem_drops=d["lifetime_counter_delta"]["netem"],
            )
        )
    if cell != ZERO_LOSS:
        for linux, stack in zip(rows[::2], rows[1::2]):
            lr, sr = result[2 * linux["rep"] : 2 * linux["rep"] + 2]
            excess = (stack["first_missing"] + stack["repeat_missing"]) - (
                linux["first_missing"] + linux["repeat_missing"]
            )
            complete = not lr["qdisc_unaccounted"] and not sr["qdisc_unaccounted"]
            for row, record in ((linux, lr), (stack, sr)):
                row.update(
                    qdisc_unaccounted=record["qdisc_unaccounted"],
                    lifetime_missing_echo=record["forward_controls"]["echo_request"][
                        "missing"
                    ],
                    primary_missing_echo=record["forward_controls"]["echo_request"][
                        "primary_missing"
                    ],
                    lifetime_missing_tcp_control=record["forward_controls"][
                        "tcp_control"
                    ]["missing"],
                    pair_primary_data_missing_excess=excess,
                    pair_primary_tbf_excess_lower_bound=excess
                    - stack["lifetime_netem_drops"]
                    if complete
                    else None,
                )
    with (out / (prefix + "-pairs.csv")).open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for cmd in ("project", "report"):
        action = sub.add_parser(cmd)
        action.add_argument("campaign", type=Path)
        action.add_argument("output", type=Path)
        action.add_argument("--all-cells", action="store_true")
        if cmd == "report":
            action.add_argument("--projected", type=Path)
    args = parser.parse_args()
    cells = tuple(PREFIXES) if args.all_cells else (ZERO_LOSS,)
    if args.command == "project":
        project(args.campaign, args.output, cells)
    else:
        report(args.campaign, args.output, args.projected, cells)
