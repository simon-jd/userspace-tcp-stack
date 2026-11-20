#!/usr/bin/env python3
"""Seal private multi-flow evidence and replay metrics from separate archive restores."""

import argparse
import csv
import hashlib
import io
import json
import os
import re
import struct
import subprocess
import sys
import tarfile
from compression import zstd
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAMILY = "m2d-multiflow"


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def manifest(directory):
    directory = directory.resolve()
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"unexpected symlink in tree: {path}")
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = digest(path)
    return result


def manifest_bytes(mapping):
    return "".join(f"{sha}  {name}\n" for name, sha in sorted(mapping.items())).encode()


def add_text(tar, name, contents):
    member = tarfile.TarInfo(name)
    member.size = len(contents)
    tar.addfile(member, io.BytesIO(contents))


def save_archive(source, mapping, full_mapping, out, scratch, label):
    temp = scratch / f"{label}.tar.zst"
    with (
        zstd.open(temp, "wb", level=1) as compressed,
        tarfile.open(fileobj=compressed, mode="w|") as tar,
    ):
        for name in sorted(mapping):
            path = source / name
            member = tar.gettarinfo(path, arcname=f"{FAMILY}/{name}")
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ""
            member.mode = 0o644
            with path.open("rb") as stream:
                tar.addfile(member, stream)
        add_text(tar, "manifest/contents.sha256", manifest_bytes(mapping))
        add_text(tar, "manifest/source.sha256", manifest_bytes(full_mapping))
    checksum = digest(temp)
    target = out / f"{FAMILY}-{label}-{checksum}.tar.zst"
    if target.exists():
        if digest(target) != checksum:
            raise ValueError(f"archive name conflicts with its contents: {target}")
    else:
        os.link(temp, target)
    return target, checksum


def restore(archive, mapping, source_mapping, to):
    to.mkdir()
    with (
        zstd.open(archive) as compressed,
        tarfile.open(mode="r|", fileobj=compressed) as tar,
    ):
        seen = set()
        for member in tar:
            name = member.name
            path = Path(name)
            if (
                not member.isfile()
                or name in seen
                or path.is_absolute()
                or ".." in path.parts
            ):
                raise ValueError(f"unsafe or duplicate archive member {name}")
            if not (
                name in ("manifest/contents.sha256", "manifest/source.sha256")
                or (
                    path.parts[0] == FAMILY
                    and path.relative_to(FAMILY).as_posix() in mapping
                )
            ):
                raise ValueError(f"unexpected archive member {name}")
            seen.add(name)
            target = to / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as src, target.open("xb") as dest:
                while chunk := src.read(4 * 1024**2):
                    dest.write(chunk)
    root = to / FAMILY
    if manifest(root) != mapping:
        raise ValueError("restored file set or content differs")
    if (to / "manifest/contents.sha256").read_bytes() != manifest_bytes(mapping) or (
        to / "manifest/source.sha256"
    ).read_bytes() != manifest_bytes(source_mapping):
        raise ValueError("restored manifest differs")
    return root


def count_packets(path):
    # Read the physical pcap record headers independently of the study's parser.
    size = path.stat().st_size
    order = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    count = 0
    with path.open("rb") as src:
        header = src.read(24)
        if len(header) != 24 or header[:4] not in order:
            return count, "missing or malformed global header"
        packet = struct.Struct(order[header[:4]] + "IIII")
        while raw := src.read(16):
            if len(raw) != 16:
                return count, "truncated record header"
            _, _, incl, orig = packet.unpack(raw)
            if not 0 < incl <= orig or src.tell() + incl > size:
                return count, "truncated or malformed record body"
            src.seek(incl, os.SEEK_CUR)
            count += 1
    return count, "complete"


def physical(root, target):
    with target.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            (
                "path",
                "bytes",
                "records",
                "tcpdump_captured",
                "filter_received",
                "kernel_dropped",
                "status",
            )
        )
        for path in sorted(root.rglob("*.pcap")):
            n, status = count_packets(path)
            candidates = (
                path.with_suffix(".tcpdump.txt"),
                path.with_suffix(".pcap.tcpdump.txt"),
            )
            log = next((p.read_text() for p in candidates if p.is_file()), "")
            counts = [
                m.group(1) if (m := re.search(r"(\d+) packets? " + key, log)) else None
                for key in ("captured", "received by filter", "dropped by kernel")
            ]
            writer.writerow(
                (
                    path.relative_to(root).as_posix(),
                    path.stat().st_size,
                    n,
                    *counts,
                    status,
                )
            )


def run_tables(root, qual, out):
    cmd = [
        sys.executable,
        "-IB",
        str(HERE / "study.py"),
        "tables",
        str(root / "production"),
        "--schedule",
        str(root / "acquisition/schedule.csv"),
        "--gate",
        str(root / qual / "gate-s0"),
        "--controls",
        str(root / qual / "proof/serial-s0"),
        "--out",
        str(out),
    ]
    ret = subprocess.run(cmd, check=False).returncode
    if ret not in (0, 2):
        raise RuntimeError(f"aggregate replay failed with status {ret}")
    if ret == 2 and not (out / "scenarios.csv").is_file():
        raise RuntimeError("aggregate did not emit observed incomplete scenarios")


def endpoint_observations(path):
    out = {"started_ns": None, "ok": None, "bytes": None, "sha256": None}
    if not path.is_file():
        return out
    # Samples can be numerous. Start and terminal records are at opposite
    # ends; physical totals never assume an attempted flow opened a socket.
    with path.open("rb") as source:
        for _ in range(30):
            line = source.readline()
            if not line:
                break
            try:
                row = json.loads(line)
            except ValueError:
                break
            if row.get("ev") == "start":
                out["started_ns"] = row["t"]
                break
        size = path.stat().st_size
        source.seek(max(0, size - 65536))
        if source.tell():
            source.readline()
        for line in source:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("ev") == "summary":
                for field in ("ok", "bytes", "sha256"):
                    out[field] = row.get(field)
    return out


def connections(root, tables, where):
    with (tables / "runs.csv").open() as f:
        counted = {
            r["run"] for r in csv.DictReader(f) if r["counted"].lower() == "true"
        }
    totals = {}
    with where.open("w", newline="") as f:
        cols = (
            "stage",
            "run",
            "flow",
            "backend",
            "counted",
            "sender_started_ns",
            "receiver_started_ns",
            "sender_bytes",
            "receiver_bytes",
            "positive_matched",
            "sender_exit",
            "receiver_exit",
        )
        writer = csv.DictWriter(f, cols)
        writer.writeheader()
        for stage in ("production", "rehearsal"):
            totals[stage] = {
                "directories": 0,
                "receiver_accepts": 0,
                "sender_connects": 0,
                "matching": 0,
                "stack_connected": 0,
                "linux_connected": 0,
                "counted_matching": 0,
            }
            tally = totals[stage]
            for rd in sorted((root / stage).glob("p*-a*-*")):
                if not rd.is_dir():
                    continue
                tally["directories"] += 1
                meta = (
                    json.loads((rd / "meta.json").read_bytes())
                    if (rd / "meta.json").exists()
                    else {}
                )
                roles = {x["id"]: x["backend"] for x in meta.get("flows", [])}
                for path in sorted((rd / "flows").glob("f*")):
                    s = endpoint_observations(path / "snd.jsonl")
                    r = endpoint_observations(path / "rcv.jsonl")
                    valid = (
                        all(x["ok"] is True for x in (s, r))
                        and s["bytes"] == r["bytes"]
                        and (s["bytes"] or 0) > 0
                        and bool(re.fullmatch("[a-f0-9]{64}", s["sha256"] or ""))
                        and s["sha256"] == r["sha256"]
                    )
                    measured = stage == "production" and rd.name in counted
                    backend = roles.get(path.name)
                    tally["matching"] += int(valid)
                    tally["counted_matching"] += int(measured and valid)
                    tally["receiver_accepts"] += r["started_ns"] is not None
                    if s["started_ns"] is not None:
                        tally["sender_connects"] += 1
                        if backend in ("stack", "linux"):
                            tally[backend + "_connected"] += 1
                    exits = {
                        role: (path / f"{role}.exit").read_text().strip()
                        if (path / f"{role}.exit").is_file()
                        else None
                        for role in ("snd", "rcv")
                    }
                    writer.writerow(
                        dict(
                            stage=stage,
                            run=rd.name,
                            flow=path.name,
                            backend=backend,
                            counted=measured,
                            sender_started_ns=s["started_ns"],
                            receiver_started_ns=r["started_ns"],
                            sender_bytes=s["bytes"],
                            receiver_bytes=r["bytes"],
                            positive_matched=valid,
                            sender_exit=exits["snd"],
                            receiver_exit=exits["rcv"],
                        )
                    )
    return totals


def reproject(root, scratch):
    cmd = [sys.executable, "-IB", str(HERE / "study.py"), "capture"]
    scratch.mkdir()
    observed = 0
    for stage in ("rehearsal", "production"):
        for rd in sorted((root / stage).glob("p*-a*-*")):
            if not rd.is_dir():
                continue
            filename = scratch / f"{stage}-{rd.name}.json"
            proc = subprocess.run(
                cmd + [str(rd), "--output", str(filename)],
                check=False,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 3:
                if (rd / "capture-evidence.json").exists():
                    raise ValueError(
                        f"previously observed capture became unreadable in {rd}"
                    )
                continue
            proc.check_returncode()
            original = rd / "capture-evidence.json"
            if original.exists() and json.loads(original.read_bytes()) != json.loads(
                filename.read_bytes()
            ):
                raise ValueError(
                    f"restored physical capture projection differs for {rd.name}"
                )
            if (rd / "qualification.json").is_file() and not original.exists():
                raise ValueError(
                    f"adjudicated capture has no preserved projection: {rd}"
                )
            observed += 1
    return observed


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", type=Path)
    ap.add_argument("archive", type=Path)
    ap.add_argument("scratch", type=Path)
    ap.add_argument("--qualification", default="acquisition-q1")
    args = ap.parse_args()
    src, out, scratch = (
        args.source.resolve(),
        args.archive.resolve(),
        args.scratch.resolve(),
    )
    if (
        src.name != FAMILY
        or src == out
        or src in out.parents
        or src == scratch
        or src in scratch.parents
    ):
        raise ValueError(
            "expected a separate private archive and restoration workspace"
        )
    if not (src / "production-status.json").is_file():
        raise ValueError("campaign has no terminal production receipt")
    out.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(exist_ok=False, parents=True)
    full = manifest(src)
    small = {k: v for k, v in full.items() if not k.endswith(".pcap")}
    original = scratch / "tables-original"
    run_tables(src, args.qualification, original)
    physical(src, scratch / "physical-original.csv")
    totals = connections(src, original, scratch / "connections-original.csv")
    results = {}
    for label, mapping in (("full", full), ("compact", small)):
        archive, sha = save_archive(src, mapping, full, out, scratch, label)
        copied = restore(archive, mapping, full, scratch / f"restore-{label}")
        tables = scratch / f"tables-{label}"
        run_tables(copied, args.qualification, tables)
        reproduced = connections(copied, tables, scratch / f"connections-{label}.csv")
        if reproduced != totals or digest(
            scratch / f"connections-{label}.csv"
        ) != digest(scratch / "connections-original.csv"):
            raise ValueError(f"{label} restored endpoint census differs")
        if manifest(tables) != manifest(original):
            raise ValueError(f"{label} tables or plots differed from original")
        if label == "full":
            physical(copied, scratch / "physical-full.csv")
            if digest(scratch / "physical-original.csv") != digest(
                scratch / "physical-full.csv"
            ):
                raise ValueError("restored physical pcap census differs")
            replays = reproject(copied, scratch / "decoded")
        results[label] = dict(
            name=archive.name,
            sha256=sha,
            archive_bytes=archive.stat().st_size,
            files=len(mapping),
            manifest_sha256=hashlib.sha256(manifest_bytes(mapping)).hexdigest(),
        )
    receipt = dict(
        archives=results,
        connections=totals,
        raw_pcap_files=len(full) - len(small),
        reprojected_scenarios=replays,
        table_files=len(manifest(original)),
        tables_sha256=hashlib.sha256(manifest_bytes(manifest(original))).hexdigest(),
        physical_sha256=digest(scratch / "physical-original.csv"),
    )
    (scratch / "archive-replay.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(receipt, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
