"""Identify archived acquisition attempts and enforce the original paired retry budget."""

import json
import re
from collections import defaultdict
from pathlib import Path


def json_object(path):
    if not path.is_file():
        return {}
    try:
        result = json.loads(path.read_text())
    except (ValueError, UnicodeDecodeError):
        return {}
    return result if isinstance(result, dict) else {}


def endpoint_observation(directory):
    """Timestamps and payload read directly from surviving endpoints, tolerating a truncated final line."""
    times = []
    positive = False
    terminals = {}
    started = set()
    malformed = False
    for name in ("snd", "rcv"):
        path = directory / (name + ".jsonl")
        if not path.is_file():
            continue
        first = None
        with path.open("rb") as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    malformed = True
                    break
                if not isinstance(row, dict):
                    malformed = True
                    break
                event = row.get("ev")
                if event not in ("start", "sample", "summary"):
                    continue
                timestamp = row.get("t")
                if type(timestamp) is int:
                    times.append(timestamp)
                    if event == "start":
                        first = timestamp
                        started.add(name)
                if event == "sample" and any(
                    type(row.get(k)) is int and row[k] > 0
                    for k in (
                        "data_segs_out",
                        "data_segs_in",
                        "bytes_sent",
                        "bytes_received",
                    )
                ):
                    positive = True
                if event == "summary":
                    count = row.get("bytes")
                    positive |= type(count) is int and count > 0
                    terminals[name] = row.get("ok") is True
                    if first is not None and type(row.get("duration_us")) is int:
                        times.append(first + row["duration_us"] * 1000)
    cap = json_object(directory / "capture.json")
    wire_positive = any(
        isinstance(v, dict)
        and isinstance(v.get("data_segs"), int)
        and v["data_segs"] > 0
        for v in cap.values()
    )
    return dict(
        first_ns=min(times, default=None),
        last_ns=max(times, default=None),
        endpoint_payload=positive,
        wire_payload=wire_positive,
        endpoint_starts=sorted(started),
        terminals=terminals,
        malformed_endpoint=malformed,
    )


def identity(relative, meta, planned):
    parts = relative.parts
    if len(parts) >= 3 and parts[-1] == "raw":
        # prepare_trial uses mktemp <registered run>.XXXXXXXX/raw; the run can contain decimal points.
        m = re.fullmatch(r"(.+)\.([A-Za-z0-9]{8})", parts[-2])
        path_name = m.group(1) if m else None
    else:
        path_name = parts[-1]

    def specification(name):
        if not isinstance(name, str):
            return None, None
        base, sep, serial = name.rpartition("-rerun")
        if sep and serial.isdecimal():
            return planned.get(base), int(serial)
        return planned.get(name), 0

    p, pr = specification(path_name)
    m, mr = specification(meta.get("run"))
    if p and "run" in meta and (not m or (p["run"], pr) != (m["run"], mr)):
        raise ValueError(f"contradictory archived path and metadata at {relative}")
    spec = p or m
    retry = pr if p else mr
    if spec:
        for key in ("group", "seed", "rep", "impl", "in_group", "cell", "algo"):
            if key in meta and meta[key] != spec[key]:
                raise ValueError(f"contradictory archived {key} at {relative}")
        if "rerun" in meta and meta["rerun"] != retry:
            raise ValueError(f"contradictory archived rerun at {relative}")
    return (
        spec,
        retry,
        (
            "path and metadata"
            if p and m
            else "registered path"
            if p
            else "metadata"
            if m
            else "unknown"
        ),
    )


def preserved(campaign, planned, archive_files):
    manifest = campaign / "source-manifest.sha256"
    if manifest.is_file():
        files = {
            line.split("  ", 1)[1]
            for line in manifest.read_text().splitlines()
            if line.split("  ", 1)[1].startswith("aside/")
        }
    else:
        files = {
            p.relative_to(campaign).as_posix()
            for p in (campaign / "aside").rglob("*")
            if p.is_file()
        }
    inputs = set(archive_files) | {
        "pre/record.txt",
        "post/record.txt",
        "shape.txt",
        "snd.out",
        "rcv.out",
        "r1-in.pcap",
        "r2-out.pcap",
        "r1-in.tcpdump.txt",
        "r2-out.tcpdump.txt",
    }
    dirs = set()
    for name in files:
        path = Path(name)
        if path.name == "record.txt" and path.parent.name in ("pre", "post"):
            dirs.add(path.parent.parent)
        elif path.name in inputs:
            dirs.add(path.parent)
    result = []
    for relative in sorted(dirs):
        directory = campaign / relative
        available = sorted(n for n in inputs if (relative / n).as_posix() in files)
        meta = json_object(directory / "meta.json")
        summ = json_object(directory / "summary.json")
        spec, retry, provenance = identity(relative, meta, planned)
        seen = endpoint_observation(directory)
        if seen["endpoint_payload"] or seen["wire_payload"]:
            physical = "payload observed"
        elif seen["endpoint_starts"] or seen["terminals"]:
            physical = "endpoint activity; payload indeterminate"
        elif set(available) <= {"meta.json", "shape.txt", "pre/record.txt"}:
            physical = "setup only; transfer unobserved"
        else:
            physical = "indeterminate"
        name = (
            spec["run"] + (f"-rerun{retry}" if retry else "")
            if spec
            else meta.get("run", relative.name)
        )
        result.append(
            dict(
                path=relative.as_posix(),
                run=name,
                identity_source=provenance,
                **{
                    k: spec[k] if spec else None
                    for k in (
                        "group",
                        "seed",
                        "rep",
                        "impl",
                        "in_group",
                        "cell",
                        "algo",
                    )
                },
                rerun=retry,
                counted=False,
                physical=physical,
                saved_validity=summ.get("valid"),
                flags=summ.get("flags", []),
                reasons=summ.get("invalid", []),
                available_inputs=available,
                absent_inputs=sorted(inputs - set(available)),
                **seen,
            )
        )
    return result


def timeline(campaign, families, history):
    events = []
    for members in families.values():
        for meta, summary in members:
            obs = endpoint_observation(campaign / meta["run"])
            events.append(
                dict(
                    path=meta["run"],
                    source="current",
                    group=meta["group"],
                    rerun=meta["rerun"],
                    in_group=meta["in_group"],
                    valid=summary["valid"],
                    payload_observed=bool(
                        obs["endpoint_payload"] or obs["wire_payload"]
                    ),
                    attempted=bool(
                        obs["endpoint_starts"]
                        or obs["terminals"]
                        or obs["endpoint_payload"]
                        or obs["wire_payload"]
                    ),
                    first_ns=obs["first_ns"],
                    last_ns=obs["last_ns"],
                )
            )
    events.extend(
        dict(
            path=h["path"],
            source="preserved",
            group=h["group"],
            rerun=h["rerun"],
            in_group=h["in_group"],
            valid=h["saved_validity"],
            payload_observed=bool(h["endpoint_payload"] or h["wire_payload"]),
            attempted=bool(
                h["endpoint_starts"]
                or h["terminals"]
                or h["endpoint_payload"]
                or h["wire_payload"]
            ),
            first_ns=h["first_ns"],
            last_ns=h["last_ns"],
        )
        for h in history
    )
    dated = sorted(
        (e for e in events if e["first_ns"] is not None),
        key=lambda e: (e["first_ns"], e["path"]),
    )
    for row in events:
        row["order_issue"] = ""
    for index, row in enumerate(dated):
        row["position"] = index
        if not index:
            continue
        previous = dated[index - 1]
        if previous["last_ns"] >= row["first_ns"]:
            row["order_issue"] = f"overlaps previous transfer at {previous['path']}"
        elif (
            previous["group"] is not None
            and row["group"] is not None
            and previous["group"] > row["group"]
        ):
            row["order_issue"] = (
                f"registered group order reversed after {previous['path']}"
            )
    return {r["path"]: r for r in events}


def historical_pairs(items, canonical, chronology):
    """Recover contiguous physical first/second intervals. Never group two runs by their random suffix."""
    failures = []
    issues = []
    split_pairs = []
    confirmed = []
    for item in items:
        if item["physical"] == "setup only; transfer unobserved":
            continue
        if (
            item["physical"] != "payload observed"
            or item["first_ns"] is None
            or item["last_ns"] is None
        ):
            issues.append(f"indeterminate physical attempt or time at {item['path']}")
            continue
        confirmed.append(item)
    confirmed.sort(key=lambda r: (r["first_ns"], r["last_ns"], r["path"]))
    if any(a["last_ns"] >= b["first_ns"] for a, b in zip(confirmed, confirmed[1:])):
        issues.append("overlapping, duplicate or unordered archived transfer intervals")
        return failures, issues, split_pairs
    if (
        confirmed
        and canonical
        and max(r["last_ns"] for r in confirmed) >= min(canonical)
    ):
        issues.append(
            "archived interval interleaves with or follows a current member of the same ordinal"
        )
        return failures, issues, split_pairs
    i = 0
    while i < len(confirmed):
        first = confirmed[i]
        members = [first]
        i += 1
        if (
            first["in_group"] == 0
            and i < len(confirmed)
            and confirmed[i]["in_group"] == 1
        ):
            second = confirmed[i]
            if (
                chronology[second["path"]]["position"]
                != chronology[first["path"]]["position"] + 1
            ):
                issues.append(
                    f"intervening acquisition separates preserved partners {first['path']} and {second['path']}"
                )
                i += 1
                continue
            members.append(second)
            i += 1
        pair = dict(
            group=first["group"],
            rerun=first["rerun"],
            source="preserved",
            paths=[m["path"] for m in members],
            first_ns=members[0]["first_ns"],
            last_ns=members[-1]["last_ns"],
        )
        sources = {chronology[m["path"]]["source"] for m in members}
        if len(sources) > 1:
            pair["source"] = "split between current and preserved"
            split_pairs.append(pair)
        elif sources == {"current"}:
            pair["source"] = "current"
        if len(members) == 2 and all(
            m["saved_validity"] is True
            or (
                m["saved_validity"] is None
                and m["terminals"] == {"snd": True, "rcv": True}
            )
            for m in members
        ):
            issues.append(
                f"earlier possibly valid complete pair requires original selection review: {pair['paths']}"
            )
        else:
            failures.append(pair)
    return failures, issues, split_pairs


def qualify(members, history, independent_count, chronology):
    pairs, bad, native_status = independent_count(members)
    native = defaultdict(list)
    archives = defaultdict(list)
    for meta, s in members:
        native[meta["group"], meta["rerun"]].append((meta, s))
    for h in history:
        archives[h["group"], h["rerun"]].append(h)
    failed = []
    issues = []
    split_pairs = []
    known_failures = set()
    bad = set(bad)
    seen_valid = set()
    ordinals = defaultdict(set)
    for key in sorted(native.keys() | archives.keys()):
        group, retry = key
        active = native.get(key, [])
        originals = archives.get(key, [])
        active_rows = [
            chronology[m["run"]]
            for m, _ in sorted(active, key=lambda x: x[0]["in_group"])
        ]
        for row in active_rows + [chronology[h["path"]] for h in originals]:
            if row["order_issue"]:
                issues.append(f"{row['path']}: {row['order_issue']}")
        # A two-member preservation move can stop after either rename. Resolve the
        # physical chronology across roots before charging the incomplete named group.
        combine = len(active_rows) == 1 and any(
            h["physical"] != "setup only; transfer unobserved" for h in originals
        )
        if combine:
            row = active_rows[0]
            physical = (
                "payload observed" if row["payload_observed"] else "indeterminate"
            )
            originals = [
                *originals,
                dict(row, physical=physical, saved_validity=row["valid"], terminals={}),
            ]
        if key in bad and not combine:
            if any(r["attempted"] for r in active_rows):
                failed.append(dict(group=group, rerun=retry, source="current"))
                known_failures.add(key)
            else:
                issues.append(
                    f"group {group} retry {retry} has no endpoint start or payload to corroborate a failed predecessor"
                )
        timed = [r for r in active_rows if r["first_ns"] is not None]
        if len(timed) == 2:
            left, right = timed
            if (
                left["last_ns"] >= right["first_ns"]
                or left["position"] + 1 != right["position"]
            ):
                issues.append(
                    f"group {group} retry {retry} lacks ordered contiguous original endpoints"
                )
        times = [r["first_ns"] for r in timed]
        older, uncertain, split = historical_pairs(
            originals, [] if combine else times, chronology
        )
        split_pairs.extend(split)
        failed.extend(older)
        issues.extend(uncertain)
        if older:
            known_failures.add(key)
        if active or older:
            ordinals[group].add(retry)
        if (
            len(active) == 2
            and {m["impl"] for m, _ in active} == {"linux", "utcp"}
            and all(s["valid"] for _, s in active)
        ):
            if len(timed) != 2:
                issues.append(
                    f"group {group} retry {retry} lacks two measured endpoint intervals"
                )
            seen_valid.add(key)
    for group, nums in ordinals.items():
        for retry in sorted(nums):
            if retry < 0 or retry > 3:
                issues.append(f"group {group} retry {retry} is outside 0..3")
            for prev in range(min(retry, 4)):
                if (group, prev) not in known_failures or (group, prev) in seen_valid:
                    issues.append(
                        f"group {group} retry {retry} has no failed predecessor at {prev} or follows a valid pair"
                    )
    for group, nums in ordinals.items():
        previous_end = None
        for retry in sorted(nums):
            records = [chronology[m["run"]] for m, _ in native.get((group, retry), [])]
            records += [chronology[h["path"]] for h in archives.get((group, retry), [])]
            timed = [r for r in records if r["first_ns"] is not None]
            if (
                timed
                and previous_end is not None
                and min(r["first_ns"] for r in timed) < previous_end
            ):
                issues.append(
                    f"group {group} retry {retry} ran before its predecessor ended"
                )
            if timed:
                previous_end = max(r["last_ns"] for r in timed)
    if len(failed) > 3 or any(r > 3 for _, r in native):
        status = "invalid (rerun cap)"
    elif issues:
        status = "indeterminate (attempt association)"
    else:
        status = native_status
    allowed = pairs if status in ("ok", "incomplete") else []
    return allowed, dict(
        status=status,
        bad_pairs=failed,
        counted_pairs=len(allowed),
        candidate_pairs=len(pairs),
        split_pairs=split_pairs,
        native_status=native_status,
        association_issues=issues,
    )
