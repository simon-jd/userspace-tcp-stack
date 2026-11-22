"""Read immutable run artifacts from utcp-data and generate the compact evidence."""
import json
from pathlib import Path
import sys

def get(path):
    return json.loads(path.read_text())

def selected(obj,keys):
    return {key:obj[key] for key in keys if key in obj}

records=[]
for label,volume in json.load(sys.stdin):
    d=Path("/data")/volume.removeprefix("utcp-data:/")
    raw=get(d/"result.json")
    manifest=get(d/"run.json")
    if label=="final-10k":
        mem=raw["memory"]["server"]
        records.append(dict(label=label,volume=volume,source=manifest["source"],
            binary=manifest["binary_sha256"],client=raw["client_summary"],server=raw["server_summary"],
            idle=raw["steady"]["server_app"],targets=raw["memory"]["utcp_server_targets"],
            memory={phase:selected(row,["rss_bytes","rss_bytes_delta_per_connection",
                "rss_hwm_bytes","rss_hwm_bytes_delta_per_connection"]) for phase,row in mem.items() if isinstance(row,dict)},
            active=[row["server_app"] for row in raw["active_app"]]))
        continue
    phase={p.name.removesuffix(".alloc.json"):selected(get(p),["calls","bytes","peak_kib","trace_open","trace_close"])
        for p in sorted((d/"server").glob("*.alloc.json")) if not p.name.startswith(("series-","zero."))}
    w=raw.get("production_allocation",raw.get("window"))
    window=selected(w,["calls","bytes","tun_datagrams_lower","tun_datagrams_upper","echo_byte_bounds","sites"])
    client=raw.get("client_summary",raw.get("summary"))
    server=raw.get("server_summary",raw.get("peer",{}))
    bulk=manifest["arguments"].get("arm") in ("send","receive")
    sample_stats={}
    if bulk:
        start,end=(get(d/"server"/(name+".alloc.json")) for name in ("steady-start","steady-end"))
        rows=[json.loads(t) for t in (d/"server/events.jsonl").read_text().splitlines()]
        samples=[r for r in rows if r["ev"]=="sample"]
        def bracket(snap):
            return (max((r for r in samples if r["t"]<=snap["start_ns"]),key=lambda r:r["t"]),
                    min((r for r in samples if r["t"]>=snap["end_ns"]),key=lambda r:r["t"]))
        a,b=bracket(start); c,e=bracket(end)
        direction=manifest["arguments"]["arm"]
        fields=("data_segs_out","bytes_sent") if direction=="send" else ("data_segs_in","bytes_received")
        window["transport_bounds"]={f:[c[f]-b[f],e[f]-a[f]] for f in fields}
        sample_stats={"periodic_samples":len(samples),"zero_send_window_samples":sum(x.get("snd_wnd") ==0 for x in samples),
            "sampled_peak_unacked":max(r["unacked"] for r in samples)}
        server=client["server"];client=client["client"]
    stack=raw["stack_stats"]
    dev={k:v for k,v in stack.items() if k.startswith("dev_") or k in ("trace_blocks","trace_events","TcpExtTCPWinProbe")}
    record=dict(label=label,volume=volume,source=manifest["source"],binary=manifest["binary_sha256"],
        counter=manifest["allocation_counter_sha256"],window=window,phase=phase,device=dev,
        server=selected(server,["ok","accepted","closed","bytes","errors","sha256","staged_bytes","stage_appends","samples","sndbuf_limited_us","rwnd_limited_us"]),
        client=selected(client,["ok","connections","connections_ok","bytes","sha256","errors","mismatches","requests_ok","latency_samples","samples"]),
        periodic=sample_stats)
    if raw.get("trace_verify"): record["trace_verify"]=raw["trace_verify"]
    if raw.get("consecutive_windows"): record["consecutive_windows"]=raw["consecutive_windows"]
    records.append(record)
print(json.dumps(records,indent=2))
