"""Replay the legacy single-queue echo measurement from endpoint evidence."""

import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from statistics import median

archive = Path(sys.argv[1]) / "m4-echo-load"
pair_dir = archive / "paired-1ffcc97"
source = "1ffcc979ce36831441eec99031154a7b454ae25e"
binary = "2d2a23a1e4bccf005f2e1851019c7a4167a7fb43be64504398419140afc7aae7"
frozen = "c787a09212eab4cfecc420e2371ba6ea045a65b251bfa1a640901aa8cec959b3"
expected_args = dict(purpose="timing", cpus=[8,10,11], connections=10_000, open_batch=32,
    backlog=4096, count=5, size=64, rate=5000, hold_s=5.0, offload="legacy", net_base=85)
phases = ("baseline", "idle-start", "idle-end", "active-1", "active-2", "active-3", "drained")
active = phases[3:6]
steady = ("idle-start", "idle-end", "drained")
roles = ("server", "client")
count = 10000
total_requests = 50000
total_bytes = 3200000

def data(path):
    return json.loads(path.read_text())

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def no_error(event):
    return event["errors"] == event.get("mismatches", 0) == 0

def switches(argv):
    flags = {"--load-report", "--nodelay"}
    pairs = {}
    tokens = iter(argv[1:])
    for key in tokens:
        assert key.startswith("--")
        pairs[key] = True if key in flags else next(tokens)
    return pairs

def start(log):
    return datetime.fromisoformat(log.replace("Z", "+00:00"))

def read_kib(snapshot, name):
    return int(re.search(rf"^{name}:\s+(\d+) kB$", snapshot["smaps_rollup"], re.M)[1]) * 1024

assert digest(pair_dir/"summary.json") == frozen
summary = data(pair_dir/"summary.json")
assert summary["source"] == source and summary["binary"] == binary
assert (pair_dir/"plan.txt").read_text().splitlines()[0] == "source " + source
order = [(n, side) for n in range(1, 6) for side in (("utcp", "kernel") if n % 2 else ("kernel", "utcp"))]
progress = [row.split() for row in (pair_dir/"progress.txt").read_text().splitlines()]
assert len(progress) == 21 and progress[-1] == ["completed","2026-11-20T21:48:06Z"]
assert [row[1] for row in progress[:-1:2]] == [f"{p}-{b}" for p,b in order]
assert [row[1] for row in progress[1:-1:2]] == [f"{p}-{b}" for p,b in order]
assert all(row[0] == "start" and len(row) == 3 for row in progress[:-1:2])
assert all(row[0] == "exit" and len(row) == 4 and row[2] == "0" for row in progress[1:-1:2])
assert all(start(a[-1]) <= start(b[-1]) for a,b in zip(progress, progress[1:]))
verified = []
images = set()
kernels = set()
client_commands = set()
server_placement = set()
active_sock_values = []
for index,(pair,backend) in enumerate(order):
    pair_file = pair_dir/f"{pair}-{backend}.json"
    control = data(pair_file)
    assert control["ok"] and not (pair_dir/f"{pair}-{backend}.stderr").read_bytes()
    run_id = control["volume"].split("/")[-1]
    assert run_id.startswith(start(progress[index*2][-1]).strftime("%Y%m%dT%H%M%SZ"))
    root = archive/run_id
    manifest,runtime,result = (data(root/f"{f}.json") for f in ("run","runtime","result"))
    assert not (root/"failure.json").exists()
    assert manifest["run_id"] == run_id and manifest["git_status"] == ""
    assert manifest["binary_sha256"] == binary and all(runtime[r]["running_sha256"] == binary for r in roles)
    assert result["source"] == manifest["source"] == source
    assert result["purpose"] == "timing" and result["backend"] == backend and result["offload"] == "legacy"
    assert result["ok"] and result["connections"] == count
    assert manifest["arguments"]["backend"] == backend
    assert all(manifest["arguments"][name] == value for name,value in expected_args.items())
    assert manifest["transport_address"] == "198.18.0.2" and manifest["port"] == 7000
    assert manifest["cpu_thread_siblings"] == {"8": "8-9", "10": "10-11", "11": "10-11"}
    assert manifest["mtu"] == 1500 and manifest["nofile_requested"] == 32768
    images.add(manifest["docker_image_id"])
    kernels.add(manifest["uname"].split()[2])
    for readback in (manifest["before_cpu"],result["after_cpu"]):
        assert all(f"cpu{n} " in readback["proc_stat"] for n in (8,9,10,11))
        for row in readback["process_placement"].splitlines()[1:]:
            pid,cpu,nice,pcpu,comm = row.split(maxsplit=4)
            if int(cpu) in range(8,12):
                server_placement.add(comm)
    assert (root/"control/open").exists() and (root/"control/active").exists() and (root/"control/close").exists()
    assert all(runtime[r]["links"]["eth0"]["mtu"] == 1500 for r in roles)
    assert "net.ipv4.tcp_congestion_control = cubic" in runtime["client"]["sysctl"]
    assert "net.ipv4.tcp_no_metrics_save = 1" in runtime["client"]["sysctl"]
    assert "198.18.0.2 via 198.19.85.2" in runtime["client"]["route"]
    for feature in ("tcp-segmentation-offload", "generic-segmentation-offload", "generic-receive-offload"):
        assert f"{feature}: off" in runtime["client"]["eth0_features"]
    assert "generic-receive-offload: off" in runtime["server"]["eth0_features"]
    observations = {}
    for role in roles:
        argv = data(root/role/"argv.json")
        assert argv[0] == "/utcp/"+manifest["arguments"]["binary"]
        cmd = switches(argv)
        assert cmd["--load-report"] and cmd["--nodelay"] and cmd["--cc"] == "cubic"
        if role == "client":
            assert cmd.pop("--load-control") == "/data/m4-echo-load/"+run_id+"/control"
            client_commands.add(tuple(sorted(cmd.items())))
            assert cmd == {"--backend": "kernel", "--connect": "198.18.0.2:7000", "--connections": "10000",
                "--concurrency": "10000", "--count": "5", "--size": "64", "--rate": "5000",
                "--open-batch": "32", "--pattern-seed": "1", "--load-report": True, "--cc": "cubic", "--nodelay": True}
        else:
            assert cmd["--backend"] == backend and cmd["--backlog"] == "4096" and cmd["--listen"] == "198.18.0.2:7000"
            if backend == "utcp":
                assert cmd["--tun"] == "utcp0" and cmd["--profile"] == "linux" and cmd["--seed"] == "1" and cmd["--mtu"] == "1500"
        snapshots = {ph: data(root/role/f"{ph}.json") for ph in phases}
        base = snapshots["baseline"]
        pid = int((root/role/"pid").read_text())
        assert base["affinity"] == ([8] if role == "server" else [10])
        assert base["nice"] == 0 and base["cgroup"] == "0::/"
        assert re.search(r"^Max open files\s+32768\s+32768\s+files", base["limits"], re.M)
        assert base["target_tcp"]["established"] == 0
        assert base["sysctl"]["net/ipv4/ip_local_port_range"].split() == ["32768","60999"]
        assert base["sysctl"]["net/ipv4/ip_local_reserved_ports"] == ""
        assert base["sysctl"]["net/ipv4/tcp_max_syn_backlog"] == base["sysctl"]["net/core/somaxconn"] == "4096"
        if role == "server" and backend == "kernel":
            assert len(base["tcp_listeners"]) == 1
            assert base["tcp_listeners"][0].split()[1:4] == ["0","4096","198.18.0.2:7000"]
        for ph,sample in snapshots.items():
            assert sample["role"] == role and sample["phase"] == ph
            assert sample["pid"] == pid and sample["netns"] == base["netns"]
            assert sample["page_bytes"] == 4096 and sample["memory_max"] == "max"
            assert read_kib(sample,"Rss") == sample["rss_bytes"] and read_kib(sample,"Pss") == sample["pss_bytes"]
            assert sample["started_ns"] < sample["ended_ns"]
            assert all(k in sample["memory_stat"] for k in ("anon","kernel","sock","slab","slab_unreclaimable"))
            assert sample["memory_stat"]["slab"] == sample["memory_stat"]["slab_reclaimable"] + sample["memory_stat"]["slab_unreclaimable"]
            assert sample["host_slabinfo_tcp"] and sample["sockstat"].startswith("sockets:")
        for earlier,later in zip(phases,phases[1:]):
            assert snapshots[earlier]["ended_ns"] < snapshots[later]["started_ns"]
        events = [json.loads(line) for line in (root/role/"events.jsonl").read_text().splitlines()]
        load = [e for e in events if e["ev"] == "load"]
        assert all(no_error(e) for e in events)
        assert all(a["monotonic_ns"] <= b["monotonic_ns"] for a,b in zip(load,load[1:]))
        assert events[-1] == result[f"{role}_summary"] and events[-1]["ev"] == "summary"
        observations[role] = (snapshots, load, events[-1])
    server,sv,s_final = observations["server"]
    client,cl,c_final = observations["client"]
    assert server["baseline"]["netns"] != client["baseline"]["netns"]
    hold_start = max(server["idle-start"]["ended_ns"], client["idle-start"]["ended_ns"])
    hold_end = min(server["idle-end"]["started_ns"], client["idle-end"]["started_ns"])
    assert hold_end - hold_start == result["held_ns"] >= 5_000_000_000
    workload_start,workload_end = c_final["workload_start_ns"],c_final["workload_end_ns"]
    assert max(server["idle-end"]["ended_ns"],client["idle-end"]["ended_ns"]) < workload_start < workload_end
    assert workload_end < min(server["drained"]["started_ns"],client["drained"]["started_ns"])
    assert c_final["ok"] and c_final["connections"] == c_final["connections_ok"] == s_final["accepted"] == s_final["closed"] == count
    assert c_final["requests"] == c_final["requests_started"] == c_final["requests_ok"] == c_final["latency_samples"] == total_requests
    assert c_final["bytes"] == s_final["bytes"] == total_bytes and c_final["size"] == 64 and not s_final["udp"]
    assert c_final["offered_requests_per_s"] == 5000
    assert int(total_requests * 1e9 / (workload_end-workload_start)) == c_final["requests_per_s"] == 4999
    assert c_final["duration_us"] == (workload_end-workload_start)//1000
    assert 0 < c_final["latency_min_ns"] <= c_final["latency_p50_ns"] <= c_final["latency_p99_ns"]
    assert control["client"] == c_final and control["memory"] == result["memory"]
    assert all(e["phase"] != "idle" or (e["open"] == e["established"] == count and e["requests_started"] == e["bytes"] == 0) for e in cl)
    assert all(e["monotonic_ns"] >= workload_start or e["bytes"] == 0 for e in sv)
    for role,events,hist in (("server",sv,server),("client",cl,client)):
        steady_events = [e for e in events if e["monotonic_ns"] <= hist["idle-start"]["ended_ns"] and e.get("open") == count]
        assert steady_events and steady_events[-1]["bytes"] == 0
        passed = [e for e in events if steady_events[-1]["monotonic_ns"] <= e["monotonic_ns"] <= hist["drained"]["ended_ns"]]
        assert len(passed) >= 15 and all(e["open"] == count for e in passed)
        if role == "server":
            assert all(e["accepted"] == count and e["closed"] == 0 for e in passed)
            assert all(e["tcp_slots"] == count+1 and e["time_wait_entries"] == 0 for e in passed) if backend == "utcp" else True
        else:
            assert all(e["established"] == count for e in passed)
        assert any(e["bytes"] == total_bytes for e in passed)
        app_steady = result["steady"][f"{role}_app"]
        assert app_steady in events and app_steady["bytes"] == 0 and app_steady["open"] == count
        for ph,activity in zip(active,result["active_app"],strict=True):
            sample = hist[ph]
            assert workload_start <= sample["started_ns"] < sample["ended_ns"] < workload_end
            app = activity[f"{role}_app"]
            assert app in events and app["open"] == count and 0 < app["bytes"] < total_bytes
        assert len({a[f"{role}_app"]["bytes"] for a in result["active_app"]}) == 3
    tuples = [client[ph]["target_tcp"] for ph in steady]
    tuple_hash = tuples[0]["tuple_sha256"]
    assert re.fullmatch("[a-f0-9]{64}", tuple_hash)
    for t in tuples:
        assert t["established"] == count and t["tuple_sha256"] == tuple_hash
        assert t["tx_queue_payload_bytes"] == t["rx_queue_payload_bytes"] == 0
    if backend == "kernel":
        assert "tun_queues" not in runtime["server"] and result["stack_stats"] is None
        assert all(server[ph]["target_tcp"] == client[ph]["target_tcp"] for ph in steady)
        active_sock_values.extend(server[ph]["memory_stat"]["sock"] for ph in active)
    else:
        assert runtime["server"]["tun_queues"] == ["rx-0","tx-0"]
        assert int(runtime["server"]["tun_flags"],16) & 0x4100 == 0
        assert runtime["server"]["links"]["utcp0"]["mtu"] == 1500
        assert all(server[ph]["target_tcp"]["established"] == 0 for ph in steady)
        stats = data(root/"server/stack-stats.jsonl")
        assert stats == result["stack_stats"] and stats["TcpPassiveOpens"] == count
        assert stats["dev_rx_datagrams"] >= total_requests and stats["dev_tx_datagrams"] >= total_requests
        assert all(stats[key] == 0 for key in ("TcpInErrs","TcpInCsumErrors","TcpAttemptFails","TcpEstabResets",
               "TcpExtListenOverflows","TcpExtListenDrops","dev_rx_errors","dev_tx_errors"))
    for role,hist in (("server",server),("client",client)):
        base = hist["baseline"]
        for ph in ("idle-end",*active):
            derived = result["memory"][role]["idle" if ph == "idle-end" else ph]
            current = hist[ph]
            for key in ("rss_bytes","pss_bytes","memory_current_bytes"):
                assert derived[key] == current[key]
                assert derived[key+"_delta"] == current[key] - base[key]
                assert derived[key+"_delta_per_connection"] == derived[key+"_delta"] / count
            for key,value in derived["cgroup_memory_stat_bytes_delta"].items():
                assert value == current["memory_stat"][key] - base["memory_stat"][key]
    b,i,d = [server[ph] for ph in ("baseline","idle-end","drained")]
    memory = dict(rss_base=b["rss_bytes"],rss_idle=i["rss_bytes"],rss_active=max(server[p]["rss_bytes"] for p in active),
        pss_base=b["pss_bytes"],pss_idle=i["pss_bytes"],pss_active=max(server[p]["pss_bytes"] for p in active),
        rss_hwm=d["rss_hwm_bytes"],idle_slab_delta=i["memory_stat"]["slab"]-b["memory_stat"]["slab"],
        active_slab_delta=max(server[p]["memory_stat"]["slab"]-b["memory_stat"]["slab"] for p in active),
        active_sock=max(server[p]["memory_stat"]["sock"] for p in active))
    memory["rss_idle_per_conn"]=(memory["rss_idle"]-memory["rss_base"])/count
    memory["rss_active_per_conn"]=(memory["rss_active"]-memory["rss_base"])/count
    if backend == "utcp":
        target = result["memory"]["utcp_server_targets"]
        assert result["steady"]["server_app"]["tcb_bytes"] == target["tcb_bytes"] == 2208
        assert not target["tcb_bytes_at_most_1_kib"] and not target["idle_rss_delta_per_connection_at_most_2_kib"]
        assert 2048 < memory["rss_idle_per_conn"] < memory["rss_active_per_conn"] <= 12288
        assert memory["rss_active"] <= 128*1024**2 and memory["rss_hwm"] <= 128*1024**2
        assert target["sampled_active_rss_at_most_128_mib"] and target["peak_rss_through_workload_at_most_128_mib"]
        assert target["peak_rss_through_workload_bytes"] == memory["rss_hwm"]
    row = dict(pair=pair,backend=backend,run_id=run_id,hold_s=result["held_ns"]/1e9,
        p50_ns=c_final["latency_p50_ns"],p99_ns=c_final["latency_p99_ns"],achieved_rps=c_final["requests_per_s"],
        runtime_net=manifest["net"],run_args=manifest["arguments"],result_sha256=digest(root/"result.json"),**memory)
    assert row == summary["runs"][index], row
    verified.append(row | {"client_steady_tuple_sha256":tuple_hash,"client_reports_held":sum(e.get("phase")=="idle" for e in cl),
        "fresh_archive_proof": "established namespace tuples, actual load events, monotonic hold and active sample timestamps",
        "verified_replies":total_requests,"verified_client_bytes":total_bytes,"echoed_server_bytes":total_bytes})
assert len(images) == len(kernels) == len(client_commands) == 1
rollup = {}
for backend in ("utcp","kernel"):
    selected = [r for r in verified if r["backend"] == backend]
    rollup[backend] = {}
    for key in summary["rollup"][backend]:
        raw = [r[key] for r in selected]
        rollup[backend][key] = {"min":min(raw),"median":median(raw),"max":max(raw)}
assert rollup == summary["rollup"]
assert len(server_placement) > 1
print(json.dumps(dict(pair_count=len(order)//2,arm_count=len(verified),archive_sha256=frozen,source=source,
    measured_binary_sha256=binary,image_id=next(iter(images)),kernel_release=next(iter(kernels)),
    hold_s_range=[min(r["hold_s"] for r in verified),max(r["hold_s"] for r in verified)],
    client_workload=dict(switches=list(next(iter(client_commands))),offered_requests_per_second=5000,
        achieved_requests_per_second_integer=4999,parallel_connections=10000,replies_per_connection=5,
        bytes_per_reply=64),kernel_active_cgroup_sock_range_bytes=[min(active_sock_values),max(active_sock_values)],
    workload_slot_process_placements_detected=True,rollup=rollup,runs=verified),indent=2))
