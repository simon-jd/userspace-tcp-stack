"""Check the original and restored checkpoint packet captures, endpoint ordering and paired seeds.

Usage: python3 physical_checkpoint.py CAMPAIGN EVIDENCE_CSV NEW_DIRECTORY
"""
import csv
import hashlib
import json
import mmap
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

def read(path):
    return json.loads(path.read_text())

def packets(path):
    endian_by_magic={b'\xd4\xc3\xb2\xa1':"<", b'\xa1\xb2\xc3\xd4':">", b'\x4d\x3c\xb2\xa1':"<", b'\xa1\xb2\x3c\x4d':">"}
    with path.open("rb") as raw, mmap.mmap(raw.fileno(), 0, access=mmap.ACCESS_READ) as data:
        endian=endian_by_magic[data[:4]]
        ver0,ver1,_,_,snap,link=struct.unpack_from(endian+"HHIIII",data,4)
        assert (ver0,ver1,link)==(2,4,1) and snap==128, (path,ver0,ver1,snap,link)
        header=struct.Struct(endian+"IIII")
        offset=24; count=0
        while offset<len(data):
            assert offset+16<=len(data),(path,offset)
            sec,frac,taken,wire=header.unpack_from(data,offset)
            assert 0<taken<=min(snap,wire) and offset+16+taken<=len(data),(path,count,offset)
            offset+=16+taken
            count+=1
        assert count and offset==len(data)
        return count,len(data),hashlib.sha256(data).hexdigest()

def bounds(rd):
    starts=[]; ends=[]
    for name in ("snd","rcv"):
        path=rd/(name+".jsonl")
        if not path.exists(): continue
        with path.open() as f:
            rows=[]
            for line in f:
                try: rows.append(json.loads(line))
                except ValueError: break
        start=[r["t"] for r in rows if r.get("ev")=="start"]
        if not start: continue
        assert len(start)==1
        starts.append(start[0])
        final=[r for r in rows if r.get("ev")=="summary"]
        sample=[r["t"] for r in rows if r.get("ev")=="sample"]
        ends += [start[0]+s["duration_us"]*1000 for s in final] + sample + start
    return (min(starts),max(ends)) if starts else None

def kernel_netem(rd,meta):
    """Read the configured delay, loss and seed from the kernel before and after transfer."""
    expected = int(meta["bw_mbit"] * 1e6 * meta["rtt_ms"] / 1000 / 8 * meta["queue_bdp"])
    assert meta["queue_bytes"] == expected, (rd,meta["queue_bytes"],expected)
    values = []
    for phase in ("pre","post"):
        lines = (rd/phase/"record.txt").read_text().splitlines()
        netem, = [line for line in lines if line.startswith("qdisc netem ")]
        assert f" dev {meta['ifaces']['r1_b']} " in netem
        seeds = re.findall(r"\bseed (\d+)\b",netem)
        delays = re.findall(r"\bdelay ([0-9.]+)ms\b",netem)
        losses = re.findall(r"\bloss ([0-9.]+)%",netem)
        assert seeds == [str(meta["seed"])] and list(map(float,delays)) == [meta["rtt_ms"]],(rd,phase,netem)
        assert list(map(float,losses)) == ([meta["loss_pct"]] if meta["loss_pct"] else []),(rd,phase,netem)
        values.append(int(seeds[0]))
    return values

def main(camp,evidence,out):
    with evidence.open() as f:
        rows=list(csv.DictReader(f))
    out.mkdir(parents=True,exist_ok=False)
    counted={r["run"]:r for r in rows if r["counted"]=="1"}
    accepted=defaultdict(list); kernel_seeds={}; spans=[]; missing=[]
    for p in sorted(camp.rglob("meta.json")):
        rd=p.parent; rel=rd.relative_to(camp).as_posix(); ts=bounds(rd)
        if ts: spans.append((*ts,rel))
        else: missing.append(rel)
    spans.sort()
    positions={name:i for i,(_,_,name) in enumerate(spans)}
    records=[]
    for name,row in sorted(counted.items()):
        path=camp/name; meta=read(path/"meta.json")
        assert name in positions
        kernel_seeds[name]=kernel_netem(path,meta)
        assert meta["group"]==int(row["group"]) and meta["rerun"]==int(row["rerun"])
        accepted[(meta["group"],meta["rerun"])].append((meta["in_group"],name,meta["seed"],meta["impl"]))
        capture=read(path/"capture.json")
        for nick in ("r1-in","r2-out"):
            expected=capture[nick]
            # No missing or zero-byte file can satisfy this check.
            n,size,sha=packets(path/(nick+".pcap"))
            log=(path/(nick+".tcpdump.txt")).read_text()
            numbers={}
            for k,pattern in (("captured","captured"),("kernel_dropped","dropped by kernel"),("received_by_filter","received by filter")):
                value=re.search(r"(\d+) packets? "+pattern,log)
                assert value and int(value.group(1))==expected[k], (name,nick,k)
                numbers[k]=int(value.group(1))
            assert n==numbers["captured"] and size==expected["bytes"],(name,nick,n,size)
            records.append((name,nick,n,size,sha,numbers["received_by_filter"],numbers["kernel_dropped"]))
    timelines=[]
    for (group,retry),members in sorted(accepted.items()):
        assert len(members)==2
        a,b=sorted(members)
        assert (a[0],b[0])==(0,1) and a[2]==b[2] and {a[3],b[3]}=={"utcp","linux"}
        i,j=positions[a[1]],positions[b[1]]
        assert j==i+1,(a,b,spans[i:j+1])
        assert spans[i][1]<=spans[j][0],(a,b,spans[i],spans[j])
        timelines.append((group,retry,a[2],a[1],b[1],spans[i][0],spans[i][1],spans[j][0],spans[j][1],*kernel_seeds[a[1]],*kernel_seeds[b[1]]))
    for filename,columns,table in (
        ("capture-audit.csv",("run","interface","physical_packets","bytes","sha256","received_by_filter","kernel_dropped"),records),
        ("pair-order.csv",("group","retry","netem_seed","first","second","first_start_ns","first_end_ns","second_start_ns","second_end_ns","first_kernel_seed_pre","first_kernel_seed_post","second_kernel_seed_pre","second_kernel_seed_post"),timelines)):
        with (out/filename).open("x",newline="") as f:
            w=csv.writer(f,lineterminator="\n"); w.writerow(columns); w.writerows(table)
    result={"observed_transfer_intervals":len(spans),"attempts_without_endpoint_start":missing,
            "counted_runs":len(counted),"counted_pairs":len(accepted),"verified_pcaps":len(records),
            "packets":sum(r[2] for r in records),"capture_bytes":sum(r[3] for r in records),
            "kernel_drops":sum(r[6] for r in records)}
    (out/"physical.json").write_text(json.dumps(result,sort_keys=True,indent=1)+"\n")
    print(json.dumps(result,sort_keys=True))
    assert len(records)==2*len(counted) and len(counted)==2*len(accepted)
if __name__=="__main__":
    main(*(Path(p) for p in sys.argv[1:]))
