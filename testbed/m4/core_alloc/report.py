#!/usr/bin/env python3
"""Produce compact absolute per-path results and compare protocol artifacts."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

def digest(path):
    with path.open("rb") as src:
        return hashlib.file_digest(src,"sha256").hexdigest()

def readrows(path):
    rows={}
    with path.open() as src:
        for r in csv.DictReader(src):
            key=(r["phase"],r["path"])
            activity=tuple(int(r[k]) for k in ("calls","payload_bytes","packets","logical_segments"))
            item=rows.setdefault(key,[activity,0,0,0,0])
            if item[0]!=activity: raise ValueError(f"inconsistent counters: {path} {key}")
            is_new=r["api"].startswith("_Z")
            item[1 if is_new else 2]+=int(r["entries"])
            item[3 if is_new else 4]+=int(r["outer"])
    return rows

def main():
    p=argparse.ArgumentParser()
    p.add_argument("raw",type=Path)
    p.add_argument("--compare",type=Path)
    p.add_argument("--sites",type=Path,help="directory containing the exact unstripped driver binaries")
    args=p.parse_args()
    receipt=json.loads((args.raw/"receipt.json").read_text())
    if receipt["failures"]: raise ValueError(f'incomplete matrix: {receipt["failures"]}')
    writer=csv.writer(sys.stdout)
    writer.writerow(("cell","epoch","path","calls","payload","packets","logical_segments","new_entries","c_entries","outer_new","outer_c","outer_total","before"))
    if args.compare:
        ref=json.loads((args.compare/"receipt.json").read_text())
        if ref["failures"] or set(receipt["runs"])!=set(ref["runs"]):
            raise ValueError("incomparable coverage")
    for name in sorted(receipt["runs"]):
        if not name.endswith("-count"): continue
        rows=readrows(args.raw/(name+".csv"))
        before=readrows(args.compare/(name+".csv")) if args.compare else {}
        if args.compare:
            if rows.keys()!=before.keys(): raise ValueError(f"{name} path coverage changed")
            for ext in ("wire","events","tx"):
                file=name+"."+ext
                if (args.raw/file).exists() and digest(args.raw/file)!=digest(args.compare/file):
                    raise ValueError(f"ordered transcript changed: {file}")
            if name.startswith("sack-"): pass
            else:
                current=(args.raw/(name+".log")).read_text()
                old=(args.compare/(name+".log")).read_text()
                markers=lambda s: [line for line in s.splitlines() if line.startswith(("trace,","coverage,"))]
                if markers(current)!=markers(old): raise ValueError(f"trace/coverage changed: {name}")
        for key,(traffic,ne,ce,on,oc) in rows.items():
            if before and traffic!=before[key][0]: raise ValueError(f"{name} {key} denominators changed")
            writer.writerow((name,*key,*traffic,ne,ce,on,oc,on+oc,
                             sum(before[key][3:]) if before else ""))
    if args.sites:
        # Driver executables are non-PIE so their raw PCs resolve across ASLR.
        # A frozen linked archive embeds production symbols in these binaries.
        for name in sorted(receipt["runs"]):
            if not name.endswith("-sites") or name.startswith("control"): continue
            exe="sack_driver" if name.startswith("sack-") else "core_driver"
            for line in (args.raw/(name+".log")).read_text().splitlines():
                if not re.match(r"^\d+,",line): continue
                tag,api,n,*frames=line.split(",")
                fixed=[f for f in frames if 0<int(f,16)<0x40000000]
                locations=subprocess.check_output(["addr2line","-C","-f","-i","-p","-e",str(args.sites/exe),*fixed],text=True) if fixed else "unresolved"
                print(f"site {name} {tag} {api} {n}: {locations.strip()}",file=sys.stderr)
if __name__=="__main__":
    main()
