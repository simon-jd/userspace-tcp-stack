"""Replay staged/direct echo and allocation probes from sealed volume evidence."""

import hashlib
import json
import math
import sys
from pathlib import Path
from statistics import median


DOC = Path(__file__).resolve().parents[1] / "m4-copy-allocation"
DATA = Path(sys.argv[1])
PRIMARY_RUNNER = "773737be59b4c170a5bf6d72ce6adb65d24dcf99"
STAGED = "95a2d39c006099eaf965dd7bb4def1b44d1e259c"
DIRECT = "5dcbc7657a00522602fad7d7e0684170adb2712b"
FINAL = "0b2887251b2e42054cc7b88f6fc84ace382205e7"
CLIENT = "efef6073b9f2d478f73e0abbd50d06f293f5ce15"
IMAGE = "sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66"
ROLES = ("server", "client")
COPY = ("staged_bytes", "stage_appends", "compacted_bytes", "relocated_bytes")


def load(path):
    return json.loads(path.read_text())


def events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def check(condition, label):
    if not condition:
        raise AssertionError(label)


def readback(volume):
    root = DATA / volume.removeprefix("utcp-data:/")
    manifest = load(root / "run.json")
    runtime = load(root / "runtime.json")
    result = load(root / "result.json")
    check(manifest["run_id"] == root.name and result["ok"] is True, (volume, "status"))
    check(not (root / "failure.json").exists(), (volume, "unexpected failure"))
    check(manifest["docker_image_id"] == IMAGE, (volume, "image"))
    for role in ROLES:
        check(runtime[role]["running_sha256"] == manifest["binary_sha256_by_role"][role],
              (volume, "running binary", role))
    check(runtime["server"]["tun_queues"] == ["rx-0", "tx-0"] and
          int(runtime["server"]["tun_flags"], 16) & 0x4000 == 0,
          (volume, "legacy single queue"))
    check(manifest["arguments"]["offload"] == "legacy", (volume, "offload arg"))
    check(all(runtime[role]["links"]["eth0"]["mtu"] == 1500 for role in ROLES) and
          runtime["server"]["links"]["utcp0"]["mtu"] == 1500, (volume, "MTU"))
    return root, manifest, runtime, result


def echo(volume, mode, n, rounds, rate, hold, runtime_direct, cpus):
    root, manifest, runtime, result = readback(volume)
    args = manifest["arguments"]
    check((args["connections"], args["count"], args["size"], args["rate"], args["hold_s"],
           args["cpus"], args["backend"]) == (n, rounds, 64, rate, hold, cpus, "utcp"),
          (volume, "parameters"))
    check(args["purpose"] == result["purpose"] == ("timing" if n == 10000 else "functional"),
          (volume, "purpose"))
    check(not manifest["git_status"] and args.get("direct_echo", False) == runtime_direct,
          (volume, "clean source and direct mode"))
    check(result["connections"] == n and result["source"] == manifest["source"] and
          result["backend"] == "utcp" and result["offload"] == "legacy",
          (volume, "run source and backend"))
    want = n * rounds
    total = 64 * want
    sample = {}
    histories = {}
    for idx, role in enumerate(ROLES):
        directory = root / role
        argv = load(directory / "argv.json")
        check("--nodelay" in argv and argv[argv.index("--cc") + 1] == "cubic",
              (volume, "Nagle or cc", role))
        check(("--direct-echo" in argv) == (role == "server" and runtime_direct),
              (volume, "actual process argv", role))
        check(argv[argv.index("--backend") + 1] == ("utcp" if role == "server" else "kernel"),
              (volume, "actual backend", role))
        histories[role] = events(directory / "events.jsonl")
        check(histories[role][-1] == result[role + "_summary"], (volume, "endpoint summary", role))
        sample[role] = {phase: load(directory / (phase + ".json")) for phase in
                        ("baseline", "idle-start", "idle-end", "active-1", "active-2",
                         "active-3", "drained")}
        baseline = sample[role]["baseline"]
        check(baseline["nice"] == (0 if n == 10000 else 10) and
              baseline["affinity"] == [cpus[idx]], (volume, "placement", role))
    client, server = (result[role + "_summary"] for role in ("client", "server"))
    check(client["ok"] and client["requests"] == client["requests_started"] ==
          client["requests_ok"] == client["latency_samples"] == want and
          client["connections"] == client["connections_ok"] == server["accepted"] ==
          server["closed"] == n and client["errors"] == client["mismatches"] ==
          server["errors"] == 0 and client["bytes"] == server["bytes"] == total,
          (volume, "endpoint counts and content"))
    expected_copies = (total, want, 0, 0) if mode == "staged" else (0, 0, 0, 0)
    check(tuple(server[k] for k in COPY) == expected_copies, (volume, "mode counters"))
    steady_client = result["steady"]["client_app"]
    steady_server = result["steady"]["server_app"]
    check(steady_client in histories["client"] and steady_server in histories["server"] and
          steady_client["established"] == steady_client["open"] == steady_server["open"] ==
          steady_server["accepted"] == n and steady_server["tcp_slots"] == n+1 and
          steady_client["requests_started"] == steady_client["bytes"] ==
          steady_server["bytes"] == steady_server["closed"] == steady_server["time_wait_entries"] == 0,
          (volume, "idle population and no pre-gate traffic"))
    held_ns = min(sample[role]["idle-end"]["started_ns"] for role in ROLES) - max(
        sample[role]["idle-start"]["ended_ns"] for role in ROLES)
    check(held_ns >= hold * 1_000_000_000 and held_ns == result["held_ns"], (volume, "idle hold"))
    tcp = [sample["client"][phase]["target_tcp"] for phase in ("idle-start", "idle-end", "drained")]
    check(all(value["established"] == n for value in tcp) and
          len({value["tuple_sha256"] for value in tcp}) == 1, (volume, "same established peer tuples"))
    t0, t1 = (client["workload_" + name + "_ns"] for name in ("start", "end"))
    duration = t1 - t0
    check(duration // 1000 == client["duration_us"] and
          want * 1_000_000_000 // duration == client["requests_per_s"] and
          client["offered_requests_per_s"] == rate and
          0 < client["latency_p50_ns"] <= client["latency_p99_ns"],
          (volume, "throughput, latency and interval"))
    cpu = {}
    for role in ROLES:
        records = [sample[role][f"active-{i}"] for i in (1, 2, 3)]
        check(all(t0 < record["started_ns"] <= record["process_cpu"]["sample_ns"] <=
                  record["ended_ns"] < t1 for record in records), (volume, "in-window sample", role))
        first, _, last = [record["process_cpu"] for record in records]
        user = last["user_ticks"] - first["user_ticks"]
        system = last["system_ticks"] - first["system_ticks"]
        hz = first["ticks_per_second"]
        elapsed_ns = last["sample_ns"] - first["sample_ns"]
        cpu[role] = {"start_ns": first["sample_ns"], "end_ns": last["sample_ns"],
                     "user_ticks": user, "system_ticks": system, "ticks_per_second": hz,
                     "cpu_seconds": (user + system) / hz,
                     "cpu_fraction_of_one_core": (user + system) * 1e9 / (hz * elapsed_ns)}
        check(cpu[role] == result["active_process_cpu"][role] and hz == last["ticks_per_second"] == 100 and
              elapsed_ns > 0 and min(user, system) >= 0, (volume, "process ticks", role))
    active_choices = [(a["client_app"]["requests_ok"], a["client_app"]["phase"],
                       a["client_app"]["established"], a["server_app"]["open"])
                      for a in result["active_app"]]
    check(len(active_choices) == 3 and
          sorted({x[0] for x in active_choices}) == [x[0] for x in active_choices] and
          all(0 < verified < want and phase == "active" and c == s == n
              for verified, phase, c, s in active_choices), (volume, "active reply progress"))
    server_snaps = sample["server"]
    baseline_rss = server_snaps["baseline"]["rss_bytes"]
    peak_rss = max(server_snaps[f"active-{i}"]["rss_bytes"] for i in (1, 2, 3))
    idle_delta = server_snaps["idle-end"]["rss_bytes"] - baseline_rss
    hwm_rss = server_snaps["drained"]["rss_hwm_bytes"]
    targets = result["memory"]["utcp_server_targets"]
    check(targets["tcb_bytes"] == steady_server["tcb_bytes"] == 2208 and
          targets["peak_rss_through_workload_bytes"] == hwm_rss and
          targets["verified_tun_rx_tx_queue_pair"] == ["rx-0", "tx-0"], (volume, "RSS targets"))
    check(targets["tcb_bytes_at_most_1_kib"] is False and
          targets["idle_rss_delta_per_connection_at_most_2_kib"] == (idle_delta/n <= 2048) and
          targets["active_rss_delta_per_connection_at_most_12_kib"] == ((peak_rss-baseline_rss)/n <= 12288) and
          targets["peak_rss_through_workload_at_most_128_mib"] == (hwm_rss <= 128*1024**2),
          (volume, "target classification"))
    stats = load(root / "server/stack-stats.jsonl")
    check(stats == result["stack_stats"], (volume, "original stack telemetry"))
    snapshots = (manifest["before_cpu"], result["after_cpu"])
    placement = sorted({int(cols[1]) for snapshot in snapshots
                        for line in snapshot["process_placement"].splitlines()[1:]
                        for cols in [line.split(maxsplit=4)]
                        if int(cols[1]) in (8, 9, 10, 11) and float(cols[3]) > 0})
    for snapshot in snapshots:
        check(all(f"cpu{c} " in snapshot["proc_stat"] for c in cpus) and snapshot["uptime"],
              (volume, "host CPU diagnostics"))
    metrics = {
        "runner_source": manifest["runner_source"], "docker_image_id": manifest["docker_image_id"],
        "source_by_role": manifest["binary_source_by_role"],
        "binary_sha256_by_role": manifest["binary_sha256_by_role"], "affinity": cpus,
        "held_ns": held_ns, "connections": n, "tcb_bytes": targets["tcb_bytes"],
        "verified_requests": want, "verified_bytes": total,
        "client_duration_us": duration // 1000, "client_rate_rps": want*1_000_000_000//duration,
        "p50_ns": client["latency_p50_ns"], "p99_ns": client["latency_p99_ns"],
        **{field: server[field] for field in COPY},
        "active_process_cpu": cpu, "idle_rss_delta_bytes": idle_delta,
        "peak_sampled_active_rss_bytes": peak_rss, "peak_active_rss_delta_bytes": peak_rss-baseline_rss,
        "hwm_rss_bytes": hwm_rss, "dev_rx_datagrams": stats["dev_rx_datagrams"],
        "dev_tx_datagrams": stats["dev_tx_datagrams"], "dev_tx_eagain": stats["dev_tx_eagain"],
        "tun_queues": runtime["server"]["tun_queues"], "host_placement_cpus": placement,
    }
    return metrics, sample, manifest, result


timing = load(DOC / "echo-timing.json")
final = load(DOC / "final-runtime.json")
alloc = load(DOC / "allocations.json")
frozen = {
    "legacy": timing[0]["binary_sha256_by_role"]["server"],
    "direct": timing[1]["binary_sha256_by_role"]["server"],
    "client": timing[0]["binary_sha256_by_role"]["client"],
    "allocation_counter": alloc["allocation_counter_sha256"],
}
check(len(timing) == 10 and len(final) == 4, "campaign row counts")
check(len({row["volume"] for row in [*timing, *final, *alloc["runs"]]}) == 18,
      "archive uniqueness across campaigns")
check([row["arm"] for row in timing] ==
      ["legacy", "direct", "direct", "legacy", "legacy", "direct", "direct", "legacy", "legacy", "direct"],
      "alternating primary order")
check([row["pair"] for row in timing] == [1,1,2,2,3,3,4,4,5,5], "primary pairing")
check([row["order"] for row in timing] == list(range(1, 11)), "primary indices")
primary_rows = []
for row in timing:
    expected_source = STAGED if row["arm"] == "legacy" else DIRECT
    mode = "staged" if row["arm"] == "legacy" else "direct"
    m, _, man, result = echo(row["volume"], mode, 10000, 5, 5000, 5, False, [8, 10, 11])
    check(all(row.get(k) == value for k, value in m.items()), (row["volume"], "compact primary differs"))
    check(m["runner_source"] == PRIMARY_RUNNER and
          m["source_by_role"] == {"server": expected_source, "client": CLIENT} and
          m["binary_sha256_by_role"] == {"server": frozen[row["arm"]], "client": frozen["client"]} and
          result["active_cpp_new"] is None and not man["allocation_counter_sha256"],
          (row["volume"], "clean primary provenance"))
    check(man["cpu_thread_siblings"] == {"8":"8-9", "10":"10-11", "11":"10-11"},
          (row["volume"], "SMT placement"))
    check((m["dev_rx_datagrams"], m["dev_tx_datagrams"], m["dev_tx_eagain"]) ==
          (140000, 130000, 0), (row["volume"], "whole-process TUN counters"))
    primary_rows.append({"volume": row["volume"], "arm": row["arm"], "pair": row["pair"],
                         **{key: m[key] for key in (
                             "held_ns", "client_rate_rps", "p50_ns", "p99_ns",
                             "idle_rss_delta_bytes", "peak_sampled_active_rss_bytes",
                             "peak_active_rss_delta_bytes", "hwm_rss_bytes", "host_placement_cpus")},
                         "server_cpu_s": m["active_process_cpu"]["server"]["cpu_seconds"],
                         "client_cpu_s": m["active_process_cpu"]["client"]["cpu_seconds"]})

quantities = ("held_ns", "client_rate_rps", "p50_ns", "p99_ns", "server_cpu_s", "client_cpu_s",
              "idle_rss_delta_bytes", "peak_sampled_active_rss_bytes", "peak_active_rss_delta_bytes",
              "hwm_rss_bytes")
summary = {}
for arm in ("legacy", "direct"):
    subset = [row for row in primary_rows if row["arm"] == arm]
    summary[arm] = {key: {
        "median": median(values),
        "min": min(values),
        "max": max(values),
    } for key in quantities for values in [[row[key] for row in subset]]}
    check(all(row["client_rate_rps"] == 4999 for row in subset), (arm, "verified rate"))
expect_rows = [
    ("legacy", (64255, 40959, 73727), (790527, 270335, 1310719), (0.25, 0.23, 0.37),
     (0.21, 0.18, 0.27), 54566912, 41127936, 54566912),
    ("direct", (61183, 38911, 115199), (942079, 671743, 1089535), (0.34, 0.23, 0.51),
     (0.25, 0.18, 0.37), 53837824, 40316928, 53846016),
]
for arm, p50, p99, scpu, ccpu, peak, peak_delta, hwm in expect_rows:
    group = summary[arm]
    check(all(tuple(group[field][key] for key in ("median", "min", "max")) == expect
              for field, expect in (("p50_ns", p50), ("p99_ns", p99), ("server_cpu_s", scpu),
                                    ("client_cpu_s", ccpu))), (arm, "published latency and CPU"))
    check(group["idle_rss_delta_bytes"]["median"] == 33341440 and
          group["peak_sampled_active_rss_bytes"]["median"] == peak and
          group["peak_active_rss_delta_bytes"]["median"] == peak_delta and
          group["hwm_rss_bytes"]["median"] == hwm, (arm, "published memory"))

selected = []
final_sha = final[0]["running_sha256_by_role"]["server"]
check([(r["workload"], r["selected_mode"]) for r in final] ==
      [("functional", "staged"), ("functional", "direct"), ("10k", "staged"), ("10k", "direct")],
      "final mode order")
for row in final:
    mode = row["selected_mode"]
    is_direct = mode == "direct"
    physical = row["workload"] == "10k"
    n, rounds, rate, hold = (10000, 5, 5000, 5) if physical else (64, 10, 128, 2)
    cpus = [8, 10, 11] if physical else [24, 25, 26]
    m, _, man, result = echo(row["volume"], mode, n, rounds, rate, hold, is_direct, cpus)
    check(row["explicit_direct_echo"] == is_direct and row["source"] == FINAL and
          row["runner_source"] == m["runner_source"] == FINAL and
          m["source_by_role"] == {"server": FINAL, "client": CLIENT} and
          row["running_sha256_by_role"] == m["binary_sha256_by_role"] ==
          {"server": final_sha, "client": frozen["client"]} and
          result["active_cpp_new"] == row["active_cpp_new"] is None,
          (row["volume"], "final selectable-mode provenance"))
    check(row["cpu_ids"] == m["affinity"] and row["connection_hold_ns"] == m["held_ns"] and
          row["verified_connections"] == m["connections"] and
          all(row[key] == m[key] for key in (*COPY, "verified_requests", "verified_bytes", "tun_queues")),
          (row["volume"], "final selectable-mode counts"))
    selected.append({"volume": row["volume"], "mode": mode, "workload": row["workload"], **m})


allocation_results = []
for row in alloc["runs"]:
    volume = row["volume"]
    name = row["workload"]
    if name.endswith("echo"):
        mode = "staged" if name == "legacy_echo" else "direct"
        m, sample, man, result = echo(volume, mode, 64, 10, 128, 2, False, [24, 25, 26])
        check(row["runner_source"] == man["runner_source"] == "920931ae7be182c6989b4c8d72df06ec713cd47a",
              (volume, "echo allocation runner"))
        check(row["server_source"] == man["source"] == (STAGED if mode == "staged" else DIRECT) and
              row["server_sha256"] == m["binary_sha256_by_role"]["server"] ==
              frozen["legacy" if mode == "staged" else "direct"], (volume, "echo allocation source"))
        check(row["end_to_end_verified_bytes"] == m["verified_bytes"] and
              row["end_to_end_verified_requests"] == m["verified_requests"] and
              row["staged_bytes"] == m["staged_bytes"], (volume, "echo allocation verified counts"))
        def echo_counter_window(first_phase, last_phase):
            first, last = (sample["server"][phase]["cpp_new"] for phase in (first_phase, last_phase))
            for phase, count in ((first_phase, first), (last_phase, last)):
                snapshot = sample["server"][phase]
                check(snapshot["started_ns"] <= count["sample_ns"] <= snapshot["ended_ns"],
                      (volume, phase, "allocation timestamp"))
            return {"start": first, "end": last, "calls": last["calls"]-first["calls"]}
        idle = echo_counter_window("idle-start", "idle-end")
        active = echo_counter_window("active-1", "active-3")
        active["scope"] = "server_process_replaced_cpp_new"
        check(active == row["active_window"] == result["active_cpp_new"] and
              idle == row["idle_window"] and active["calls"] == 42 and idle["calls"] == 70,
              (volume, "echo allocation sample delta"))
        count_file = DATA / volume.removeprefix("utcp-data:/") / "server/cpp-new-count"
        check(int.from_bytes(count_file.read_bytes(), "little") >= active["end"]["calls"],
              (volume, "echo final counter"))
        check("allocation_counter_sha256" not in man, (volume, "legacy manifest provenance"))
        entry = {"mode": mode, "idle_calls": idle["calls"], "verified_requests": m["verified_requests"],
                 "probe_digest_in_original_manifest": None}
    else:
        root, man, runtime, result = readback(volume)
        direction = name.removeprefix("bulk_")
        check(result["direction"] == man["arguments"]["direction"] == direction and
              result["tun_queues"] == ["rx-0", "tx-0"] and man["git_status"] == "",
              (volume, "bulk manifest"))
        check(row["runner_source"] == man["runner_source"] == man["source"] ==
              "f8c36c11b5bb5bc30916ef8eab8e68918c143c00" and
              len(set(man["binary_source_by_role"].values())) == 1 and
              set(man["binary_source_by_role"].values()) == {man["source"]} and
              set(man["binary_sha256_by_role"].values()) == {row["binary_sha256"]},
              (volume, "bulk source and binary provenance"))
        summaries = result["summary"]
        check(len(row["whole_stream_sha256"]) == 64, (volume, "bulk digest length"))
        for role in ROLES:
            summary_row = summaries[role]
            check(summary_row == events(root/role/"events.jsonl")[-1] and summary_row["ok"] and
                  summary_row["sha256"] == row["whole_stream_sha256"] and
                  summary_row["bytes"] == row["end_to_end_verified_bytes"],
                  (volume, role, "bulk bytes and SHA-256"))
        check((summaries["server"]["role"], summaries["client"]["role"]) ==
              (("sender", "receiver") if direction == "send" else ("receiver", "sender")),
              (volume, "bulk directions"))
        server = root/"server"
        first, last = [load(server/(phase+".json"))["cpp_new"] for phase in ("steady-start", "steady-end")]
        server_events = events(server/"events.jsonl")
        packet_samples = [event for event in server_events if event["ev"] == "sample"]
        start = next(event["t"] for event in server_events if event["ev"] == "start")
        check(start < first["sample_ns"] < last["sample_ns"] < start + 8_000_000_000,
              (volume, "bulk warm window within eight seconds"))
        fields = ("bytes_sent", "data_segs_out") if direction == "send" else ("bytes_received", "data_segs_in")
        bracket = lambda ns: ([event for event in packet_samples if event["t"] <= ns][-1],
                              [event for event in packet_samples if event["t"] >= ns][0])
        aa, ab = bracket(first["sample_ns"])
        ba, bb = bracket(last["sample_ns"])
        lower = {field: ba[field]-ab[field] for field in fields}
        upper = {field: bb[field]-aa[field] for field in fields}
        all_counters = {field: [event[field] for event in packet_samples] for field in fields}
        check(all(values == sorted(values) for values in all_counters.values()) and
              aa[fields[0]] >= 8 * 1024**2 and all(0 < lower[field] <= upper[field] for field in fields),
              (volume, "bulk warmup and bounds"))
        active = {"scope": "server_process_replaced_cpp_new", "start": first, "end": last,
                  "calls": last["calls"]-first["calls"], "lower": lower, "upper": upper}
        check(active == row["active_window"] == result["window"] and
              active["calls"] == (26333 if direction == "send" else 416), (volume, "bulk allocation delta"))
        check(int.from_bytes((server/"cpp-new-count").read_bytes(), "little") >= last["calls"],
              (volume, "bulk final counter"))
        check(man["allocation_counter_sha256"] == frozen["allocation_counter"], (volume, "bulk library hash"))
        entry = {"direction": direction, "sha256": row["whole_stream_sha256"], "lower": lower, "upper": upper,
                 "warm_bytes_before_first_read": aa[fields[0]],
                 "probe_digest_in_original_manifest": man["allocation_counter_sha256"]}
    check(man["arguments"]["allocation_counter"] == "build/echo-compare/count_new.so" and
          row["affinity"] == man["arguments"]["cpus"] == [24,25,26], (volume, "allocation probe inputs"))
    allocation_results.append({"workload": name, "volume": volume, "active_calls": active["calls"],
                               "active_window_ns": active["end"]["sample_ns"]-active["start"]["sample_ns"],
                               "verified_bytes": row["end_to_end_verified_bytes"], **entry})

failed_observations = []
for volume in alloc["failed_bulk_observations"]:
    path = DATA / volume.removeprefix("utcp-data:/")
    bad = load(path/"failure.json")
    man = load(path/"run.json")
    check(bad["ok"] is False and bad["run_id"] == man["run_id"] == path.name and
          not (path/"result.json").exists() and not (path/"server/steady-start.json").exists() and
          man["allocation_counter_sha256"] == frozen["allocation_counter"], (volume, "preserved failed bulk probe"))
    marker = "bulk configuration" if not failed_observations else "at least 8 MiB of warm-up traffic"
    check(marker in bad["error"], (volume, "bulk failure reason"))
    failed_observations.append({"volume": volume, "failure_stage": marker, "live_window": False})

print(json.dumps({"ok": True, "frozen_digests": {**frozen, "final_selectable": final_sha},
                  "primary_count": len(primary_rows), "primary_summary": summary,
                  "primary": primary_rows, "final": selected, "allocation": allocation_results,
                  "retained_failed_bulk_observations": failed_observations}, indent=2))
