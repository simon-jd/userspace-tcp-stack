#!/usr/bin/env python3
"""Replay the private TUN queue comparison receipts."""
import argparse
import json
from pathlib import Path
import re
from statistics import median
import sys

RUNTIME = "4857492b47b2913bbc27993d7710df7824554376"
BULK_SHA = "721314a504b23ef2940f5ea1e93445d2fceaab2e20bf03ac12d49bdef46013f9"
ECHO_SHA = "07f17af161f2c8e324aa483695298bebebd4e5d295994d8d74c80c62dca8fe3f"
BASELINE = "1427bbe64848c1c158488a2e8776aad2cb0f47c3"


def traffic(stats, count):
    assert (stats["dev_tun_offload"], stats["dev_vnet_hdr_size"]) == ("tcpv4", 10), stats
    assert stats["dev_tun_multi_queue"] and stats["dev_tun_ifindex"] > 0
    assert stats["dev_tun_queues"] == count
    assert not any(stats[key] for key in ("dev_device_failed", "dev_rx_errors", "dev_tx_errors",
                                          "dev_rx_vnet_drops", "TcpInCsumErrors"))
    result = {direction: [stats[f"dev_{direction}_queue_{i}_datagrams"] for i in range(count)]
              for direction in ("rx", "tx")}
    for direction, values in result.items():
        assert stats[f"dev_{direction}_datagrams"] == sum(values) > 0, result
    return result


def active_tun(audit, folder):
    active = audit.load(folder / "tun.active.json")
    assert active["status"] == 0
    for feature in ("tx-checksum-ip-generic", "tx-tcp-segmentation"):
        assert re.search(rf"(?m)^\s*{feature}: on\b", active["stdout"]), folder


def bulk(audit, folder, hz, fixed_rate, repeats):
    plan = audit.load(folder / "plan.json")
    assert plan["runner_source"] == BASELINE and not plan["functional"]
    assert plan["cpus"] == {"dut": 8, "peer": 10}
    assert plan["bytes"] == 1_000_000_000 and plan["ethernet_aggregation"]
    for count in (1, 2):
        mode = plan["modes"][f"mq{count}"]
        expected = [f"--tun-queues={count}", "--tun-offload=tcpv4"]
        if fixed_rate:
            expected.append("--set=test_fixed_pacing_rate=1Gbit")
        assert mode["source"] == RUNTIME and mode["sha256"] == BULK_SHA
        assert mode["vnet"] and mode["multi_queue"] and mode["args"] == expected
    manifest = audit.verify_manifest(folder)
    for mode, info in plan["modes"].items():
        assert audit.sha256(folder / "bin" / mode) == info["sha256"]
    for name, digest in plan["runner_sha256"].items():
        assert audit.sha256(folder / "runner" / name) == digest
    kernel = plan["modes"]["kernel"]
    assert kernel["source"] == "da05184dd3d6766987b236b29db8caa031e7d367"
    assert kernel["args"] == [] and not kernel["multi_queue"] and not kernel["vnet"]
    planned_order = []
    for rep in range(1, repeats + 1):
        directions = ("dut-to-peer", "peer-to-dut")
        modes = ("kernel", "mq1", "mq2")
        if rep % 2 == 0:
            directions, modes = directions[::-1], modes[::-1]
        planned_order.extend([rep, direction, mode] for direction in directions for mode in modes)
    assert plan["order"] == planned_order
    compact = audit.load(folder / "compact.json")
    assert len(compact["rows"]) == len(planned_order) == len(list(folder.glob("*/result.json")))
    rows = []
    for index, ((rep, direction, mode), stored) in enumerate(
            zip(planned_order, compact["rows"], strict=True), 1):
        name = f"{index:02d}-r{rep}-{direction}-{mode}"
        one = folder / name
        assert audit.load(one / "result.json") == stored, name
        assert stored["valid"] and stored["arm"] == name, stored
        row = {"arm": name, "repeat": rep, "direction": direction, "mode": mode}
        sides = ("dut", "peer") if direction == "dut-to-peer" else ("peer", "dut")
        for role, short, side in zip(("sender", "receiver"), ("send", "recv"), sides, strict=True):
            backend = "utcp" if side == "dut" and mode != "kernel" else "kernel"
            variant = mode if backend == "utcp" else "kernel"
            binary = f"/data/m4/performance/{folder.name}/bin/{variant}"
            app = audit.load(one / f"{short}.stdout")
            usage = audit.load(one / f"{short}.usage.json")
            result = audit.replay_endpoint(app, usage, role, backend, plan["cpus"][side],
                                           binary, plan["bytes"], plan["sha256"])
            assert all(stored[f"{short}_{key}"] == val for key, val in result.items()), name
            if short == "recv":
                row["receiver_gbps"] = app["goodput_bps"] / 1e9
                assert row["receiver_gbps"] == stored["receiver_gbps"]
            if side == "dut":
                row["dut_s_per_gb"] = result["total_s_per_gb"]
                row["dut_user_s_per_gb"] = result["user_s_per_gb"]
                row["dut_sys_s_per_gb"] = result["sys_s_per_gb"]
                if backend == "utcp":
                    stats = audit.load(one / f"{short}.stats.json")
                    assert stats == stored["stack_stats"]
                    assert stored["tun_flags"] == "0x5901"
                    active_tun(audit, one)
                    row["fd_traffic"] = traffic(stats, int(mode[-1]))
                    # Each single flow stays on its selected TX FD. Linux may
                    # select a different receive FD during the initial SYN.
                    assert sum(value > 0 for value in row["fd_traffic"]["tx"]) == 1, row
                    row["dev_rx_read_calls"] = stats["dev_rx_read_calls"]
                    row["dev_tx_write_calls"] = stats["dev_tx_write_calls"]
        for phase in ("before", "after"):
            text = (one / f"dut.{phase}.txt").read_text()
            tun_line = re.search(r"(?m)^\s*tun type tun pi off .*$", text)[0]
            assert ("multi_queue" in tun_line) == (mode != "kernel")
            assert f"vnet_hdr {'off' if mode == 'kernel' else 'on'}" in tun_line
            assert "persist on" in tun_line
        group_delta = sum(data["usage_usec"] for data in stored["cgroup_usec_delta"].values())
        host = [audit.load(one / f"host.{phase}.json") for phase in ("before", "after")]
        row.update(audit.overlap_cpu(*host, [8, 9, 10, 11], group_delta, hz))
        rows.append(row)
    return {"sha256_manifest": manifest, "arms": len(rows), "rows": rows,
            "groups": compact["groups"]}


def echoes(audit, folder, hz, repeats):
    manifest = audit.verify_manifest(folder)
    plan = audit.load(folder / "echo-plan.json")
    assert plan["runner_source"] == BASELINE and plan["echo_source"] == RUNTIME
    assert audit.sha256(folder / "echo") == plan["echo_sha256"] == ECHO_SHA
    assert (plan["flows"], plan["size"], plan["count"], plan["offered_rps"]) == (16, 65536, 512, 1000)
    assert plan["endpoint_cpus"] == {"dut": 8, "peer": 10} and plan["offload"] == "tcpv4"
    assert plan["pacing"] == "--set=test_fixed_pacing_rate=1Gbit"
    order = [(rep, n) for rep in range(1, repeats + 1) for n in ((1, 2) if rep % 2 else (2, 1))]
    assert plan["order"] == [list(pair) for pair in order]
    rows = audit.load(folder / "echo-results.json")
    assert len(rows) == 2 * repeats == len(list(folder.glob("*/result.json")))
    for row, (rep, count) in zip(rows, order, strict=True):
        arm = folder / row["arm"]
        assert row["valid"] and row["repeat"] == rep and row["queues"] == count
        assert audit.load(arm / "result.json") == row and row["tun_flags"] == "0x5901"
        active_tun(audit, arm)
        assert (arm / "dut.tun-fds.txt").read_text().count("iff:\tutcp0\n") == count
        assert len((arm / "peer.overlap.txt").read_text().splitlines()) == row["established"] == 16
        assert audit.load(arm / "status.json") == {"client": 0, "server": 0}
        cli, srv = (audit.load(arm / f"{role}.stdout") for role in ("send", "recv"))
        assert cli["ok"] and cli["mismatches"] == cli["errors"] == 0 and srv["errors"] == 0
        assert cli["requests"] == cli["requests_ok"] == 16 * 512
        assert cli["connections_ok"] == srv["accepted"] == 16
        assert cli["bytes"] == srv["bytes"] == row["verified_echo_bytes"] == plan["echo_bytes"]
        assert row["echo_gbps"] == 8 * (cli["bytes"] / 1e9) / (cli["duration_us"] / 1e6)
        for side, role in (("dut", "recv"), ("peer", "send")):
            usage = audit.load(arm / f"{role}.usage.json")
            assert usage["argv"][0] == f"/data/m4/performance/{folder.name}/echo"
            assert usage["affinity"] == [plan["endpoint_cpus"][side]]
            assert usage["status"] == 0 and usage["timed_out"] is False
            assert row[f"{side}_cpu_s_per_gb"] == (usage["user_s"] + usage["sys_s"]) / (cli["bytes"] / 1e9)
        stats = audit.load(arm / "server.stats")
        assert traffic(stats, count) == row["fd_traffic"] and all(map(all, row["fd_traffic"].values()))
        for key in ("dev_rx_read_calls", "dev_tx_write_calls"):
            assert row[key] == stats[key]
        snapshots = [(arm / f"{side}.{phase}.txt").read_text()
                     for side in ("dut", "peer") for phase in ("before", "after")]
        cpu = [int(re.search(r"(?m)^usage_usec (\d+)$", snap)[1]) for snap in snapshots]
        host = [audit.load(arm / f"host.{phase}.json") for phase in ("before", "after")]
        row.update(audit.overlap_cpu(*host, [8, 9, 10, 11], cpu[1] + cpu[3] - cpu[0] - cpu[2], hz))
        row["offered_rps"] = plan["offered_rps"]
        row["accepted_rps"] = cli["requests_per_s"]
    return {"sha256_manifest": manifest, "arms": len(rows), "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--baseline-audit", required=True, type=Path)
    parser.add_argument("--clock-ticks", required=True, type=int)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.baseline_audit.resolve().parent))
    import audit
    assert Path(audit.__file__) == args.baseline_audit.resolve()
    campaigns = {name: bulk(audit, args.root / name, args.clock_ticks, fixed_rate, repeat)
                 for name, fixed_rate, repeat in (("mq-uncapped-p1", False, 1),
                                                  ("mq-paced-p1", True, 1),
                                                  ("mq-uncapped-r1", False, 5),
                                                  ("mq-paced-r1", True, 5))}
    campaigns["mq-echo-r1"] = echoes(audit, args.root / "mq-echo-r1", args.clock_ticks, 5)
    for data in campaigns.values():
        data["host_overlap_arms"] = [row["arm"] for row in data["rows"]
                                     if row["slot_nonirq_remainder_pct"] >= 2]
    for count in (1, 2):
        echo = campaigns["mq-echo-r1"]
        group = [row for row in echo["rows"] if row["queues"] == count]
        echo[f"mq{count}"] = {key: [min(values), median(values), max(values)]
                              for key in ("echo_gbps", "dut_cpu_s_per_gb", "dev_rx_read_calls",
                                          "dev_tx_write_calls")
                              for values in [[row[key] for row in group]]}
    print(json.dumps(campaigns, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
