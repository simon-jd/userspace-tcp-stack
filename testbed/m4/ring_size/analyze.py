#!/usr/bin/env python3
"""Read an archived campaign, report matched changes and apply the frozen rule."""

import csv
import json
from pathlib import Path
from statistics import median
import sys

from run import ORDER, SIZES

DIRECTIONS = ("dut-to-peer", "peer-to-dut")


def read(path):
    return json.loads(path.read_text())


def metrics(root):
    plan = read(root / "plan.json")
    if plan["scope"] != "both":
        raise ValueError("a combined campaign is required for a default decision")
    blocks = list(map(int, plan["order"]))
    arms = {(b, k): {"block": b, "kib": k} for b in blocks for k in SIZES}
    bulk = read(root / "bulk/compact.json")["rows"]
    receipts = read(root / "bulk/plan.json")
    if any(receipts["modes"][f"ring-{k}"]["sha256"] != plan["builds"][str(k)]["utcp-bulk"]
           for k in SIZES) or receipts["modes"]["kernel"]["sha256"] != plan["builds"]["4"]["utcp-bulk"]:
        raise ValueError("bulk executable differs from the build archive")
    expected = [(b, d, k) for b in blocks
                for d in (DIRECTIONS if b % 2 else DIRECTIONS[::-1]) for k in ORDER[b-1]]
    actual = [(r["repeat"], r["direction"], int(r["mode"].removeprefix("ring-"))) for r in bulk]
    if actual != expected:
        raise ValueError("bulk sequence differs from registered order")
    for r in bulk:
        if not r["valid"] or r["receiver_bytes"] != 1_000_000_000 or r["sha256"] != receipts["sha256"]:
            raise ValueError(f"invalid bulk arm {r['arm']}")
        k = int(r["mode"].removeprefix("ring-"))
        arm = arms[r["repeat"], k]
        prefix = "tx" if r["direction"] == "dut-to-peer" else "rx"
        role = "send" if prefix == "tx" else "recv"
        arm[prefix + "_gbps"] = r["receiver_gbps"]
        arm[prefix + "_dut_cpu"] = r[f"{role}_total_s_per_gb"]
        for endpoint in ("send", "recv"):
            for counter in ("total_s_per_gb", "user_s_per_gb", "sys_s_per_gb",
                            "total_retrans", "bytes_retrans"):
                arm[f"{prefix}_{endpoint}_{counter}"] = r[f"{endpoint}_{counter}"]
    echo = read(root / "echo-index.json")
    if [(r["block"], r["kib"]) for r in echo] != [(b, k) for b in blocks for k in ORDER[b-1]]:
        raise ValueError("echo sequence differs from registered order")
    for row in echo:
        if not row["valid"]:
            raise ValueError(f"invalid echo arm {row}")
        k = row["kib"]
        dest = root / row["dir"]
        r, manifest = read(dest / "result.json"), read(dest / "run.json")
        observed_hash = manifest["binary_sha256_by_role"]
        if (observed_hash["server"] != plan["builds"][str(k)]["utcp-echo"]
                or observed_hash["client"] != plan["builds"]["4"]["utcp-echo"]
                or manifest["source"] != plan["source"] or manifest["git_status"]
                or manifest["docker_image_id"] != plan["image"]):
            raise ValueError(f"echo source, image or executable mismatch in {row['dir']}")
        client = r["client_summary"]
        if (not r["ok"] or not client["ok"] or r["held_ns"] < 5_000_000_000
                or client["requests_ok"] != 50000 or client["bytes"] != 3_200_000
                or client["mismatches"] or client["errors"] or r["connections"] != 10000):
            raise ValueError(f"invalid echo transfer in {row['dir']}")
        m = r["memory"]["server"]
        t = r["memory"]["utcp_server_targets"]
        arm = arms[row["block"], k]
        arm.update(idle_rss_bpc=m["idle"]["rss_bytes_delta_per_connection"],
                   active_rss_bpc=max(m[f"active-{i}"]["rss_bytes_delta_per_connection"] for i in (1, 2, 3)),
                   hwm_bytes=t["peak_rss_through_workload_bytes"],
                   echo_p50_ns=client["latency_p50_ns"], echo_p99_ns=client["latency_p99_ns"],
                   echo_active_cpu_fraction=r["active_process_cpu"]["server"]["cpu_fraction_of_one_core"],
                   idle_allocated_chunks=r["steady"]["server_app"]["chunks"],
                   pool_allocated_chunks=row["allocated_chunks"], pool_backing_bytes=row["allocated_chunk_bytes"])
        if (not 0 <= arm["pool_backing_bytes"] < 1 << 32
                or arm["pool_backing_bytes"] != k * 1024 * arm["pool_allocated_chunks"]):
            raise ValueError(f"pool storage limit or count differs in {row['dir']}")
    return blocks, arms


def summarize(blocks, arms):
    summary = {}
    for k in (2, 8):
        stats = {}
        for key in arms[blocks[0], k].keys() - {"kib", "block"}:
            pairs = [(arms[b, 4][key], arms[b, k][key]) for b in blocks]
            pct = [(val / ref - 1) * 100 if ref else None for ref, val in pairs]
            valid = [v for v in pct if v is not None]
            stats[key] = {"default_median": median(x for x, _ in pairs),
                          "candidate_median": median(y for _, y in pairs), "paired_pct": pct,
                          "median": median(valid) if len(valid) == len(pct) else None,
                          "min": min(valid, default=None), "max": max(valid, default=None),
                          "positive": sum(v > 0 for v in valid), "negative": sum(v < 0 for v in valid)}
        summary[k] = stats
    return summary


def choose(blocks, arms, summary):
    if blocks != list(range(1, 7)):
        return {"decision": "representative blocks only"}
    decisions = {}
    eligible = []
    for k, stats in summary.items():
        reasons = []
        if any(arms[b, k]["idle_rss_bpc"] > 2048 or arms[b, k]["active_rss_bpc"] > 12288
               or arms[b, k]["hwm_bytes"] > 128 * 1024**2 for b in blocks):
            reasons.append("absolute memory limit exceeded")
        benefit = {}
        for key in ("tx_gbps", "rx_gbps", "tx_dut_cpu", "rx_dut_cpu", "active_rss_bpc", "hwm_bytes"):
            s = stats[key]
            higher = key.endswith("gbps")
            gain = s["median"] if higher else -s["median"]
            if gain < -5:
                reasons.append(f"{key} regressed over 5%")
            if gain >= 5 and s["positive" if higher else "negative"] >= 5:
                benefit[key] = gain
        if not benefit:
            reasons.append("no repeatable benefit at or above 5%")
        if not reasons:
            memory = max((-stats[key]["median"] for key in ("active_rss_bpc", "hwm_bytes")
                          if stats[key]["negative"] >= 5), default=0)
            rate = min(stats[key]["median"] for key in ("tx_gbps", "rx_gbps"))
            cpu = min(-stats[key]["median"] for key in ("tx_dut_cpu", "rx_dut_cpu"))
            eligible.append((memory, rate, cpu, -k))
        decisions[k] = {"vetoes": reasons, "qualifying_benefits": benefit}
    return {"selected_kib": -max(eligible)[-1] if eligible else 4, "alternatives": decisions}


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: analyze.py ARCHIVED_RAW_DIRECTORY NEW_OUTPUT_DIRECTORY")
    root, dest = map(Path, sys.argv[1:])
    blocks, arms = metrics(root)
    summary = summarize(blocks, arms)
    report = {"blocks": blocks, "metrics": summary, "selection": choose(blocks, arms, summary)}
    dest.mkdir(parents=True, exist_ok=False)
    with (dest / "absolute.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(next(iter(arms.values()))))
        writer.writeheader()
        writer.writerows(arms.values())
    (dest / "paired.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report["selection"], indent=2))


if __name__ == "__main__":
    main()
