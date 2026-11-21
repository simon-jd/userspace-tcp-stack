"""Summarize every pair of adjacent snapshots; retain pre/post traffic."""
import json
from pathlib import Path

def summarize(t,res,read,totals):
    if t.observer.wait(timeout=10)!=0:
        raise RuntimeError("series observer failed")
    paths=t.docker("server","sh","-ec",'ls "$1"/series-*.alloc.json',"sh",t.out+"/server").splitlines()
    phases=[Path(x).name.split(".")[0] for x in paths]
    frames=[json.loads(read(t,phase+".alloc.json")) for phase in phases]
    zero={"sites":{},"calls":0,"bytes":0,"packets_before":[0,0],"packets_after":[0,0]}
    t.capture_json("server","server/zero.alloc.json",zero)
    full=totals(t,"zero",phases[-1])
    chunks=next(v for k,v in full["sites"].items() if k=="11 utcp::ChunkPool::alloc()")
    keys={k for k,(n,b) in frames[-1]["sites"].items() if k.endswith("/11") and b==4096*n}
    if sum(frames[-1]["sites"][k][0] for k in keys)!=chunks[0]:
        raise RuntimeError("ambiguous 4 KiB allocation sites")
    periods=[]
    for i in range(len(phases)-1):
        pa,pb=frames[i:i+2]
        wa,wb=pa["wire_counts"],pb["wire_counts"]
        data=totals(t,phases[i],phases[i+1])
        data.update(start=pa["start_ns"],end=pb["end_ns"],gso_datagrams=wb[0]-wa[0],
            gso_segments=wb[1]-wa[1],
            pool_chunks_start=sum(pa["sites"].get(k,[0,0])[0] for k in keys),
            pool_chunks_end=sum(pb["sites"].get(k,[0,0])[0] for k in keys),
            containing_clock_seconds_peak_bytes={sec:v for sec,v in frames[-1]["outstanding_max_by_second"].items()
                if pa["start_ns"]//10**9<=int(sec)<=pb["end_ns"]//10**9})
        periods.append(data)
    final=frames[-1]["wire_counts"]
    if final[0]!=res["stack_stats"]["dev_tx_gso_datagrams"] or final[1]!=res["stack_stats"]["dev_tx_gso_segments"]:
        raise RuntimeError(f"GSO mismatch {final} vs {res['stack_stats']}")
    return periods
