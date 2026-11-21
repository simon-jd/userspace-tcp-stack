"""Real bulk and gated echo endpoint allocation diagnosis on the isolated Linux testbed."""
import argparse
import collections
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bulk_allocation import BulkTrial, measure
from echo_load import Trial, require

class AppTrial(BulkTrial):
    def save_manifest(self):
        super().save_manifest()
        self.manifest["counter_scope"] = "public glibc allocation functions and replacement C++ new"
    def launch(self,role,*argv):
        if role == "server":
            if "--tun-offload" not in argv:
                argv += ("--tun-offload", self.args.offload)
            if self.args.queues > 1:
                argv += ("--tun-queues",str(self.args.queues))
            if self.args.trace:
                argv += ("--set=test_fixed_pacing_rate=800Mbit","--trace",self.out+"/server/events.trace","--trace-kinds","tx")
        super().launch(role,*argv)
        if role == "server":
            self.docker(role,"sh","-ec",'''
            for i in $(seq 1 400); do
              if [ -s "$1/cpp-new-count" ]; then
                cat "/proc/$(cat "$1/pid")/maps" > "$1/process.maps"
                exit 0
              fi
              sleep 0.01
            done
            exit 1''',"sh",self.out+"/server")
            self.count("startup")
    def count(self,phase):
        return json.loads(self.docker("server","taskset","-c",str(self.affinity["collector"]),
            "nice","-n","10","python3","/utcp/testbed/m4/app_alloc/snapshot.py",
            self.out+"/server",phase))
    def snapshot(self,phase,sockets=True):
        snaps = super().snapshot(phase,sockets)
        r = self.count(phase)
        snaps["server"]["cpp_new"] = {"calls":r["calls"],"sample_ns":r["start_ns"]}
        return snaps
    def network_readback(self):
        if self.args.queues == 1:
            return super().network_readback()
        summary = {}
        for role in ("client","server"):
            pid = self.docker(role,"cat",self.out+"/"+role+"/pid")
            digest = self.docker(role,"sha256sum","/proc/"+pid+"/exe").split()[0]
            require(digest==self.binary_shas[role], "running binary mismatch")
            summary[role] = {"running_sha256":digest,"eth0_features":self.docker(role,"ethtool","-k","eth0")}
            if role == "server":
                raw=self.docker(role,"sh","-c",'grep -h "^iff:" /proc/"$1"/fdinfo/*',"sh",pid)
                require(raw.count("utcp0")==self.args.queues,"active fd count mismatch")
                summary[role]["tun_queues"]=self.docker(role,"ls","-1","/sys/class/net/utcp0/queues").splitlines()
                summary[role]["active_fdinfo"]=raw
        self.capture_json("server","network.json",summary)
        return summary
    def setup(self):
        super().setup()
        if getattr(self.args,"pressure",False):
            self.allocation_counter += ":/utcp/build/app-pressure.so"
            self.docker("server","tc","qdisc","replace","dev","eth0","root","netem","delay","3ms","limit","50000")
        if self.args.queues > 1:
            self.docker("server","ip","tuntap","del","dev","utcp0","mode","tun")
            self.docker("server","ip","tuntap","add","dev","utcp0","mode","tun","vnet_hdr","multi_queue")
            self.docker("server","ip","addr","add","198.18.0.1/24","dev","utcp0")
            self.docker("server","ip","link","set","dev","utcp0","mtu","1500","txqueuelen","10000","up")
        if self.args.offload == "tcpv4":
            self.docker("server","ethtool","-K","eth0","gro","on")
            self.docker("client","ethtool","-K","eth0","tso","on","gso","on","gro","on")

def read(t,path):
    return t.docker("server","cat",t.out+"/server/"+path)

def totals(t,first,last):
    a,b = (json.loads(read(t,key+".alloc.json")) for key in (first,last))
    maps = read(t,"process.maps").splitlines()
    hot = collections.Counter()
    byte_cost = collections.Counter()
    for key,v in b["sites"].items():
        initial = a["sites"].get(key,[0,0])
        n = v[0]-initial[0]
        if not n: continue
        h,kind = key.split("/")
        pc = int(h,16)-1
        sym = None
        for line in maps:
            parts = line.split(maxsplit=5)
            lo,hi = (int(x,16) for x in parts[0].split("-"))
            if lo<=pc<hi and len(parts)==6:
                off = pc-lo+int(parts[2],16)
                image = Path(parts[5]).name
                if image == t.binary_paths["server"].name:
                    sym = subprocess.check_output(["addr2line","-Cf","-e",str(t.binary_paths["server"]),hex(off)],text=True).splitlines()[0]
                else:
                    sym = image+"+"+hex(off)
                break
        sym = f"{kind} {sym or h}"
        hot[sym] += n
        byte_cost[sym] += v[1]-initial[1]
    return {"calls":b["calls"]-a["calls"],"bytes":b["bytes"]-a["bytes"],
        "sites":{key:[v,byte_cost[key]] for key,v in hot.most_common()},
        "tun_datagrams_lower":[v-w for v,w in zip(b["packets_before"],a["packets_after"])],
        "tun_datagrams_upper":[v-w for v,w in zip(b["packets_after"],a["packets_before"])]}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("arm",choices=["send","receive","staged","direct"])
    p.add_argument("--source",required=True)
    p.add_argument("--offload",choices=["legacy","tcpv4"],default="legacy")
    p.add_argument("--pressure",action="store_true")
    p.add_argument("--queues",choices=(1,2),type=int,default=1)
    p.add_argument("--trace",action="store_true")
    a=p.parse_args()
    bulk=a.arm in ("send","receive")
    name="utcp-bulk" if bulk else "utcp-echo"
    a.binary=f"build/gcc-release/apps/{name}/{name}"
    a.purpose="functional"; a.backend="utcp"; a.cpus=(8,10,12)
    a.direct_echo=a.arm=="direct"; a.connections=16; a.count=288; a.size=1024
    a.rate=480; a.backlog=128; a.open_batch=16; a.hold_s=0.35; a.net_base=206
    a.image="utcp-testbed:dev"; a.allocation_counter="build/app-alloc.so"
    a.binary_source=a.source; a.client_binary=a.client_source=None
    t=AppTrial(a,"m4-app-alloc")
    try:
        t.setup()
        res=measure(t,a.arm) if bulk else t.trial()
        last=t.count("final")
        require(last["final"]==1,"counter finalization missing")
        first,end=("steady-start","steady-end") if bulk else ("active-1","active-3")
        res["production_allocation"] = totals(t,first,end)
        res["production_allocation"]["final"]=last
        if not bulk:
            rows=[json.loads(x) for x in read(t,"events.jsonl").splitlines()]
            samples=[row for row in rows if row.get("ev")=="load"]
            def around(phase):
                snap=json.loads(read(t,phase+".alloc.json"))
                return (max(r["bytes"] for r in samples if r["monotonic_ns"] < snap["start_ns"]),
                        min(r["bytes"] for r in samples if r["monotonic_ns"] > snap["end_ns"]))
            begin,finish=around(first),around(end)
            res["production_allocation"]["echo_byte_bounds"]=[finish[0]-begin[1],finish[1]-begin[0]]
        if a.trace:
            verify=t.docker("server","taskset","-c","12","nice","-n","10","python3",
                 "/utcp/testbed/m4/app_alloc/verify_trace.py",t.out+"/server")
            res["trace_verify"]=json.loads(verify)
        res["volume"]="utcp-data:"+t.out.removeprefix("/data")
        t.capture_json("server","result.json",res)
        print(json.dumps({"volume":res["volume"],"arm":a.arm,"window":res["production_allocation"],"trace":res.get("trace_verify")}))
    finally:
        t.cleanup()

if __name__=="__main__":
    main()
