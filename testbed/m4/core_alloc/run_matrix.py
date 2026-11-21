#!/usr/bin/env python3
"""Run in a new immutable attempt directory. Preserve both successful and failed cells."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

MODES = ("bulk","echo","tx_pressure","chunk_pressure","gso","fallback","reorder","loss","pmtu","udp","icmp","multi_waiter","duplicate","pool_pressure","timer_loss","delack")


def sha(path):
    with path.open("rb") as src:
        return hashlib.file_digest(src, "sha256").hexdigest()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("bin",type=Path)
    parser.add_argument("out",type=Path)
    parser.add_argument("--modes",nargs="+",choices=MODES,default=MODES)
    opt=parser.parse_args()
    bin=opt.bin.resolve()
    out=opt.out.resolve()
    out.mkdir(exist_ok=False)
    results={}
    broken=[]
    env=dict(os.environ, LD_PRELOAD=str(bin/"libutcp_heap_probe.so"), LD_BIND_NOW="1")
    def run(name, cmd):
        with (out/(name+".csv")).open("xb") as stdout, (out/(name+".log")).open("xb") as stderr:
            result=subprocess.run(cmd,env=env,stdout=stdout,stderr=stderr)
        results[name]={"returncode":result.returncode,"command":[str(x) for x in cmd]}
        if result.returncode: broken.append(name)
        return result.returncode==0

    try:
        if not all([run("control-c",[bin/"c-control"]),run("control",[bin/"control"]),run("control-sites",[bin/"control","sites"])]):
            return 1
        def same(left,right,reason):
            if sha(left)!=sha(right): broken.append(reason)
        for arm in ("count","sites"):
            run("sack-"+arm,[bin/"sack_driver"]+(["sites"] if arm=="sites" else []))
        same(out/"sack-count.csv",out/"sack-sites.csv","sack-attribution-diverged")
        for mode in opt.modes:
            for trace in ("off","count"):
                for arm in ("count","sites"):
                    name=f"{mode}-{trace}-{arm}"
                    run(name,[bin/"core_driver",mode,trace,arm,out/(name+".wire"),out/(name+".events"),out/(name+".tx")])
                    if arm=="sites":
                        for suffix in ("wire","events","tx","csv"):
                            same(out/(name+"."+suffix),out/(f"{mode}-{trace}-count."+suffix),name+"-"+suffix)
                if trace=="count":
                    for suffix in ("wire","events","tx"):
                        same(out/(f"{mode}-off-count."+suffix),out/(f"{mode}-count-count."+suffix),mode+"-trace-"+suffix)
    finally:
        (out/"receipt.json").write_text(json.dumps({"runs":results,"failures":broken},indent=2)+"\n")
        files=sorted(p for p in out.iterdir() if p.is_file())
        (out/"SHA256SUMS").write_text("".join(sha(p)+"  "+p.name+"\n" for p in files))
    return int(bool(broken))


if __name__=="__main__":
    sys.exit(main())
