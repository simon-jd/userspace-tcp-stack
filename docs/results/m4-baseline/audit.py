#!/usr/bin/env python3
"""Recompute the baseline evidence from its private-volume files."""

import argparse
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import subprocess
import sys


def need(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_text())


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_manifest(folder):
    manifest = folder / "SHA256SUMS"
    entries = [line.split("  ", 1)[1][2:] for line in manifest.read_text().splitlines()]
    actual = sorted(str(path.relative_to(folder)) for path in folder.rglob("*")
                    if path.is_file() and path != manifest)
    need(len(entries) == len(actual) and sorted(entries) == actual, "manifest file set differs")
    subprocess.run(["sha256sum", "-c", "--strict", "--quiet", "SHA256SUMS"],
                   cwd=folder, check=True)
    return sha256(manifest)


def replay_endpoint(summary, usage, role, backend, cpu, binary, nbytes, digest):
    need(summary["ok"] is True and summary["ev"] == "summary", "application result was unsuccessful")
    need((summary["role"], summary["backend"], summary["cc"]) == (role, backend, "cubic"),
         "application role, backend or algorithm differs")
    need((summary["bytes"], summary["sha256"]) == (nbytes, digest), "application payload differs")
    need(usage["argv"][0] == binary and usage["affinity"] == [cpu], "binary or CPU differs")
    need(usage["status"] == 0 and usage["timed_out"] is False, "application did not exit normally")
    t_us, bps = summary["duration_us"], summary["goodput_bps"]
    need(t_us > 0 and t_us <= (nbytes * 8e6) / bps <= t_us + 1.1,
         "application duration/goodput differs")
    gb = nbytes / 1e9
    user, system = usage["user_s"], usage["sys_s"]
    need(all(value >= 0 and math.isfinite(value) for value in (user, system)), "invalid wait4 CPU times")
    return {"duration_us": t_us, "user_s_per_gb": user / gb, "sys_s_per_gb": system / gb,
            "total_s_per_gb": (user + system) / gb, "total_retrans": summary["total_retrans"]}


def overlap_cpu(before, after, cpus, total_cgroup_usec, hz):
    def ticks(state):
        return {int(parts[0][3:]): [int(x) for x in parts[1:9]]
                for line in state["stat"].splitlines()
                if re.match(r"^cpu\d+ ", line)
                for parts in [line.split()]}

    def softirqs(state):
        return {parts[0].removesuffix(":"): [int(x) for x in parts[1:]]
                for line in state["softirqs"].splitlines()[1:] for parts in [line.split()]}

    start, end = ticks(before), ticks(after)
    delta = [b - a for cpu in cpus for a, b in zip(start[cpu], end[cpu], strict=True)]
    columns = [sum(delta[index::8]) for index in range(8)]
    total = sum(columns)
    need(total > 0, "host CPU clock did not advance")
    handled = total_cgroup_usec * hz / 1e6
    nonirq = sum(columns[index] for index in (0, 1, 2, 7))
    withirq = nonirq + columns[5] + columns[6]
    result = {"slot_nonirq_remainder_pct": max(0, nonirq - handled) / total * 100,
              "slot_irq_inclusive_remainder_pct": max(0, withirq - handled) / total * 100}
    soft_start, soft_end = softirqs(before), softirqs(after)
    for key in ("NET_RX", "NET_TX", "HRTIMER", "TIMER"):
        if key in soft_start and key in soft_end:
            result[f"slot_{key.lower()}_softirqs"] = sum(soft_end[key][cpu] - soft_start[key][cpu] for cpu in cpus)
    return result


def interface_counts(text, dev):
    match = re.search(rf"(?m)^\d+: {dev}(?:@[^: ]+)?: <[^\n]+$([\s\S]*?)(?=^\d+: |\Z)", text)
    need(match is not None, f"missing {dev} link")
    counters = re.findall(r"(?m)^\s+(?:RX|TX):[^\n]+\n\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", match[1])
    need(len(counters) == 2, f"missing {dev} RX or TX data")
    return tuple(tuple(map(int, values)) for values in counters)


def captured_state(one, side, phase, plan, mode):
    text = (one / f"{side}.{phase}.txt").read_text()
    eth0 = text.split("Features for eth0:\n")[1].split("Features for utcp0:")[0]
    segmentation = "on" if plan.get("ethernet_aggregation", False) else "off"
    for prefix, value in (("tcp-segmentation", segmentation), ("generic-segmentation", segmentation),
                          ("generic-receive", "off")):
        need(re.search(rf"(?m)^{prefix}-offload: {value}", eth0), f"{side} {prefix} differs")
    need(re.search(rf"(?m)^\d+: eth0@[^:]+: .* mtu {plan['mtu']} qdisc noqueue", text),
         f"{side} has inconsistent link MTU or queue")
    need(re.search(rf"(?m)^== affinity\n{plan['cpus'][side]}$", text), f"{side} cpuset mismatch")
    need(re.search(rf"(?m)^ +inet {re.escape(plan['addresses'][side])}/24 ", text), f"{side} IP mismatch")
    need("net.ipv4.tcp_no_metrics_save = 1" in text and not re.search(r"(?m)^default ", text),
         f"{side} TCP metric cache or default route differs")
    if side == "dut":
        need("net.ipv4.ip_forward = 1" in text and
             re.search(r"(?m)^qdisc pfifo .* dev utcp0 root .* limit 10000p", text),
             "DUT forwarding or TUN pfifo differs")
        need(re.search(rf"(?m)^\d+: utcp0: .* mtu {plan['mtu']} qdisc pfifo", text), "TUN MTU differs")
        vnet = "on" if plan["modes"][mode]["vnet"] else "off"
        need(f"tun type tun pi off vnet_hdr {vnet} persist on" in text, "TUN feature differs")
    else:
        need(f"{plan['stack_ip']} via {plan['addresses']['dut']} dev eth0" in text,
             "peer route to stack differs")
    return text


def audit(folder, hz):
    manifest = verify_manifest(folder)
    plan = load(folder / "plan.json")
    compact = load(folder / "compact.json")
    need(len(compact["rows"]) == len(plan["order"]), "partial campaign")
    need(len(plan["order"]) == len(list(folder.glob("*/result.json"))), "attempt file count differs")
    for mode, config in plan["modes"].items():
        need(sha256(folder / "bin" / mode) == config["sha256"], f"{mode} binary hash mismatch")
    for name, digest in plan["runner_sha256"].items():
        need(sha256(folder / "runner" / name) == digest, "runner script hash mismatch")
    image = load(folder / "image.json")
    need(image[0]["Id"] == plan["image"], "frozen image hash mismatch")
    for side in ("dut", "peer"):
        config = load(folder / f"{side}.container.json")[0]
        need(config["HostConfig"]["CpusetCpus"] == str(plan["cpus"][side]) and config["Image"] == plan["image"],
             f"{side} actual Docker CPU placement or image differs")

    rows = []
    for index, (order, stored) in enumerate(zip(plan["order"], compact["rows"], strict=True), 1):
        rep, direction, mode = order
        name = f"{index:02d}-r{rep}-{direction}-{mode}"
        one = folder / name
        need(load(one / "result.json") == stored, f"{name} aggregate differs from individual result")
        need(stored["valid"] is True, f"{name} failed: {stored.get('error')}")
        row = {item: stored[item] for item in ("arm", "repeat", "direction", "mode", "valid")}
        endpoints = ("dut", "peer") if direction == "dut-to-peer" else ("peer", "dut")
        commands = load(one / "commands.json")
        execs = load(one / "exec.json")
        for short, role, side in zip(("send", "recv"), ("sender", "receiver"), endpoints, strict=True):
            usage, app = load(one / f"{short}.usage.json"), load(one / f"{short}.stdout")
            events = [json.loads(line) for line in (one / f"{short}.jsonl").read_text().splitlines()]
            need([event for event in events if event["ev"] == "summary"] == [app],
                 "recorded application outputs differ")
            need(len([event for event in events if event["ev"] == "start" and event["role"] == role]) == 1,
                 "application did not record exactly one start")
            need(execs[short]["argv"] == commands[short] and execs[short]["status"] == 0,
                 "recorded wrapper command or status differs")
            backend = "utcp" if side == "dut" and mode != "kernel" else "kernel"
            binary = f"/data/m4/performance/{plan['run_id']}/bin/{mode if backend == 'utcp' else 'kernel'}"
            need(commands[short][commands[short].index(binary):] == usage["argv"],
                 "recorded process command does not match proposed invocation")
            if short == "recv":
                ready = (one / "listener.ready").read_text().split()
                need(ready == [str(usage["pid"]), backend], "listener readiness PID/backend differs")
            values = replay_endpoint(app, usage, role, backend, plan["cpus"][side], binary,
                                     plan["bytes"], plan["sha256"])
            row.update({f"{short}_{key}": value for key, value in values.items()})
            if short == "recv":
                row["receiver_gbps"] = app["goodput_bps"] / 1e9
                row["receiver_bytes"] = app["bytes"]
                row["sha256"] = app["sha256"]

        for key in set(row) - {"sha256", "arm", "direction", "mode"}:
            need(row[key] == stored[key], f"{name} compact metric {key} differs")

        for side in ("dut", "peer"):
            before = captured_state(one, side, "before", plan, mode)
            after = captured_state(one, side, "after", plan, mode)
            values = [int(re.search(r"(?m)^usage_usec (\d+)$", state)[1]) for state in (before, after)]
            row[f"{side}_cgroup_cpu_s"] = (values[1] - values[0]) / 1e6
            need(values[1] - values[0] == stored["cgroup_usec_delta"][side]["usage_usec"],
                 "cgroup delta differs from raw snapshot")
            devices = ("eth0", "utcp0") if side == "dut" else ("eth0",)
            for dev in devices:
                a, b = (interface_counts(state, dev) for state in (before, after))
                for channel, old, new in zip(("rx", "tx"), a, b, strict=True):
                    row[f"{side}_{dev}_{channel}_drops"] = new[3] - old[3]
                    if dev == "utcp0":
                        row[f"dut_tun_{channel}_packets"] = new[1] - old[1]

        row["stack_dev_rx_datagrams"] = None
        row["stack_dev_tx_datagrams"] = None
        if mode == "kernel":
            need(row["dut_tun_rx_packets"] == row["dut_tun_tx_packets"] == 0, "kernel control touched TUN")
        else:
            short = "send" if endpoints[0] == "dut" else "recv"
            stats = load(one / f"{short}.stats.json")
            need(stats == stored["stack_stats"] and stats["dev_device_failed"] is False,
                 "stack device statistics differ")
            for channel in ("rx", "tx"):
                key = f"dev_{channel}_datagrams"
                need(stats[key] > 0 and row[f"dut_tun_{channel}_packets"] > 0, "missing live TUN traffic")
                row[f"stack_{key}"] = stats[key]
        if not plan["functional"]:
            before, after = (load(one / f"host.{phase}.json") for phase in ("before", "after"))
            total_us = sum(stored["cgroup_usec_delta"][side]["usage_usec"] for side in ("dut", "peer"))
            row.update(overlap_cpu(before, after, [8, 9, 10, 11], total_us, hz))
        rows.append(row)

    groups = {}
    metrics = [key for key in rows[0] if key.endswith("_s_per_gb") or key == "receiver_gbps"]
    for direction, mode in sorted(set((row["direction"], row["mode"]) for row in rows)):
        group = [row for row in rows if row["direction"] == direction and row["mode"] == mode]
        reproduced = {metric: {name: func(row[metric] for row in group)
                              for name, func in (("median", statistics.median), ("min", min), ("max", max))}
                      for metric in metrics}
        need(reproduced == compact["groups"][f"{direction}/{mode}"]["metrics"],
             "summary statistics differ")
        groups[f"{direction}/{mode}"] = reproduced
    return {"sha256_manifest": manifest, "arms": len(rows), "groups": groups, "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("--clock-ticks", type=int, required=True, help="CLK_TCK from measurement host")
    parser.add_argument("--csv", action="store_true", help="emit the independently recomputed rows")
    args = parser.parse_args()
    results = audit(args.campaign, args.clock_ticks)
    if args.csv:
        rows = results["rows"]
        writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    else:
        counts = Counter((row["direction"], row["mode"]) for row in results["rows"])
        print(json.dumps({"sha256_manifest": results["sha256_manifest"], "arms": results["arms"],
                          "counts": {"/".join(name): count for name, count in counts.items()},
                          "groups": results["groups"]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
