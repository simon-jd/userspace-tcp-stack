"""Measure a userspace echo client against a Linux TCP echo server."""
import argparse
import json
import time
from argparse import Namespace
from run import AppTrial, read, totals
from echo_load import PORT, STACK_IP, require

p=argparse.ArgumentParser(description=__doc__)
p.add_argument("--source",required=True)
p.add_argument("--binary",default="build/gcc-release/apps/utcp-echo/utcp-echo")
opt=p.parse_args()
a=Namespace(arm="client",purpose="functional",backend="utcp",cpus=(8,10,12),
    net_base=209,image="utcp-testbed:dev",allocation_counter="build/app-alloc.so",
    binary=opt.binary,binary_source=opt.source,client_source=None,client_binary=None,
    trace=False,queues=1,offload="legacy")
t=AppTrial(a,"m4-app-alloc")
try:
    t.setup()
    addr=t.ips["client"]+":"+str(PORT)
    t.launch("client","--backend","kernel","--listen",addr,"--load-report","--nodelay")
    t.wait("client",lambda row:row.get("open")==0,"stock kernel listener")
    t.launch("server","--backend","utcp","--connect",addr,"--tun","utcp0","--addr",STACK_IP,
        "--profile","linux","--seed","1","--nodelay","--cc","cubic","--pattern-seed","1",
        "--stats",t.out+"/server/stack-stats.jsonl","--load-report","--load-control",t.out+"/control",
        "--connections","16","--concurrency","16","--open-batch","16","--size","1024",
        "--count","288","--rate","480")
    t.wait("server",lambda row:row.get("phase")=="baseline","new client")
    t.network_readback()
    t.gate("open")
    t.wait("server",lambda row:row.get("phase")=="idle" and row["established"]==16,"held sockets")
    t.gate("active")
    started=t.wait("server",lambda row:row.get("phase")=="active","live traffic")["workload_start_ns"]
    for phase,offset in (("active-1",3.8),("active-3",6.8)):
        time.sleep(max(0,started/1e9+offset-time.monotonic()))
        t.count(phase)
    t.wait("server",lambda row:row.get("phase")=="drained","all requests verified")
    t.count("drained")
    t.gate("close")
    summary=t.wait("server",lambda row:row.get("ev")=="summary","client close")
    require(t.processes["server"].wait(timeout=45)==0,"userspace client exit")
    t.docker("client","sh","-ec",'kill -TERM "$(cat "$1/pid")"',"sh",t.out+"/client")
    peer=t.wait("client",lambda row:row.get("ev")=="summary","peer close")
    require(t.processes["client"].wait(timeout=15)==0,"kernel server exit")
    require(summary["ok"] and summary["requests_ok"]==summary["latency_samples"]==4608 and
        summary["errors"]==summary["mismatches"]==peer["errors"]==0 and
        peer["bytes"]==summary["bytes"]==4608*1024 and peer["accepted"]==peer["closed"]==16,
        "endpoint verification mismatch")
    final=t.count("final")
    window=totals(t,"active-1","active-3")
    reports=[json.loads(line) for line in read(t,"events.jsonl").splitlines()]
    reports=[r for r in reports if r.get("phase")=="active"]
    def around(phase):
        snap=json.loads(read(t,phase+".alloc.json"))
        return (max(r["bytes"] for r in reports if r["monotonic_ns"]<snap["start_ns"]),
                min(r["bytes"] for r in reports if r["monotonic_ns"]>snap["end_ns"]))
    lo,hi=around("active-1"),around("active-3")
    window["echo_byte_bounds"]=[hi[0]-lo[1],hi[1]-lo[0]]
    res=dict(volume="utcp-data:"+t.out.removeprefix("/data"),window=window,final=final,
        summary=summary,peer=peer,stack_stats=json.loads(read(t,"stack-stats.jsonl")))
    t.capture_json("server","result.json",res)
    print(json.dumps({k:res[k] for k in ("volume","window","final")}))
finally:
    t.cleanup()
