#!/usr/bin/env python3
"""Reconcile all outer calls with the bounded stack inventory. Core is statically linked."""
import argparse
import collections
import csv
import re
import subprocess
import sys
from pathlib import Path


def source_names(key):
    text = Path(__file__).with_name("windows.hpp").read_text()
    block = re.search(r"\b" + key + r"\[\]\{(.*?)\};", text, re.S).group(1)
    return re.findall(r'"([^"]+)"', block)


def resolve(exe, addresses):
    if not addresses:
        return {}
    result = subprocess.check_output(["addr2line", "-a", "-C", "-f", "-i", "-p",
        "-e", str(exe), *(hex(i) for i in sorted(addresses))], text=True)
    rows = {}
    for line in result.splitlines():
        head = re.match(r"(0x[0-9a-f]+): (.*)", line)
        if head:
            pc = int(head[1], 16)
            rows[pc] = [head[2]]
        else:
            rows[pc].append(line.strip())
    return rows


def main():
    args = argparse.ArgumentParser()
    args.add_argument("raw", type=Path)
    args.add_argument("binaries", type=Path)
    opt = args.parse_args()
    phases, paths = source_names("phase_name"), source_names("path_name")
    writer = csv.writer(sys.stdout)
    writer.writerow(("cell","phase","path","api","calls","first_core_frame","executable_frames"))
    for group, pattern in [("sack_driver","sack-sites.log"),("core_driver","*-*-sites.log")]:
        records, addresses = [], set()
        for file in sorted(opt.raw.glob(pattern)):
            totals = collections.Counter()
            name = file.stem
            for line in file.read_text().splitlines():
                if not re.match(r"^[0-9]+,",line):
                    continue
                label,api,num,*frames = line.split(",")
                phase,path = divmod(int(label),len(paths))
                key = (phases[phase],paths[path],api)
                pcs = [int(pc,16) for pc in frames if int(pc,16)<0x40000000]
                totals[key] += int(num)
                addresses.update(pcs)
                records.append((name,*key,num,pcs))
            with file.with_suffix(".csv").open() as src:
                expected = {(r["phase"],r["path"],r["api"]): int(r["outer"])
                            for r in csv.DictReader(src) if int(r["outer"])}
            if totals != expected:
                raise ValueError(f"stack inventory does not reconcile: {name}")
        frames = resolve(opt.binaries/group,addresses)
        for name,phase,path,api,num,pcs in records:
            mapped = [f for pc in pcs for f in frames.get(pc,[])]
            core = next((f for f in mapped if "/src/core/" in f),"external/driver")
            writer.writerow((name,phase,path,api,num,core," | ".join(mapped)))


if __name__ == "__main__":
    main()
