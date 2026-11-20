"""Verify and summarize the three sealed M4 VNET campaigns without running traffic."""

import argparse
import collections as c
import hashlib
import json
import pathlib
import re
import statistics as s
import subprocess

candidate = "1c6911eeb1c432ae997b00f1fe2206c430d58c3e"
reference = "da05184dd3d6766987b236b29db8caa031e7d367"
runner = "aa21d9354a3829d487188a5097cde29368ee6a0d"
cand_digest = "38607feb53cb4dea4e668f16b773a7c632822a5f0adb1e5a5dea958ea1c7ca7f"
kern_digest = "52b94b903903f80581311ac4070e107f3c5fd2eb0f962d4a155f564ae090d128"
campaigns = {
    "tun-vnet-tcpv4-smoke-1": "109ac5513761df51cd5825006514d637c4fa240c83869a3cfe66970bc3e533fa",
    "tun-checksum-1gb-r5-01": "a8f7b573a45cea06778abd171db8f26fbd7ec4f2a0f3961d47cb4223ff576f63",
    "tun-tcpv4-1gb-r5-01": "3eb45928249f48915d3755b58e7368bef923a7d72177a185755d6c7ac46c6982",
}

def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()

def load(path):
    return json.loads(path.read_text())

def feature(text, key, expected):
    value = re.search(r"(?m)^\s*" + re.escape(key) + r": (\S+)", text)
    assert value and value[1] == expected, (key, expected, value)

def threads(rows):
    result = {}
    for line in rows:
        fields = line.split(None, 5)
        if len(fields) == 6:
            result[tuple(fields[:2])] = (int(fields[2]), int(fields[4]), fields[5])
    return result

def metrics(rows):
    return {k: {"median": s.median(r[k] for r in rows),
                "min": min(r[k] for r in rows), "max": max(r[k] for r in rows)}
            for k in rows[0] if k != "counts"}

def audit(root, run, digest):
    path = root / run
    # Endpoint argv records the original container path even when the archive moves.
    recorded_path = pathlib.PurePosixPath("/data/m4/performance") / run
    assert sha(path / "SHA256SUMS") == digest
    subprocess.run(["sha256sum", "-c", "--quiet", "SHA256SUMS"], cwd=path, check=True)
    entries = {line.split(maxsplit=1)[1].removeprefix("./")
               for line in (path / "SHA256SUMS").read_text().splitlines()}
    assert entries == {str(x.relative_to(path)) for x in path.rglob("*") if x.is_file()
                       and x.name != "SHA256SUMS"}
    plan = load(path / "plan.json")
    smoke = plan["functional"]
    assert plan["run_id"] == run and plan["runner_source"] == runner
    assert plan["bytes"] == (4_000_055 if smoke else 1_000_000_000)
    assert plan["ethernet_aggregation"] is True and plan["mtu"] == 1500
    assert plan["cpus"] == ({"dut": 16, "peer": 18} if smoke else {"dut": 8, "peer": 10})
    assert plan["controller_cpus"] == list(range(16, 24)) and plan["controller_nice"] == 10
    assert set(plan["modes"]) == {
        "kernel", "checksum", "legacy" if run.startswith("tun-checksum-") else "tcpv4"
    }
    expected_sha = ("77465f5ba9eb55dfa849fb59cdcc431c59922ccd05b289365cc92e5c9e608698"
                    if smoke else "57c114707df855575bf7f97161237ef9ece1c41ebd58c104b1a344115d707969")
    assert plan["sha256"] == expected_sha
    for name, expected in plan["runner_sha256"].items():
        assert sha(path / "runner" / name) == expected
    for name, config in plan["modes"].items():
        assert config["multi_queue"] is False
        if name in ("legacy", "checksum", "tcpv4"):
            assert config["args"] == ["--tun-offload=" + name]
            assert config["vnet"] == (name != "legacy")
            assert sha(path / "bin" / name) == config["sha256"] == cand_digest
            assert config["source"] == candidate
        else:
            assert name == "kernel" and config["args"] == [] and config["vnet"] is False
            assert sha(path / "bin" / name) == config["sha256"] == kern_digest
            assert config["source"] == reference
    groups = c.defaultdict(list)
    busy = {}
    flags = c.defaultdict(set)
    for index, (repeat, direction, mode) in enumerate(plan["order"], 1):
        arm = f"{index:02}-r{repeat}-{direction}-{mode}"
        folder = path / arm
        row = load(folder / "result.json")
        assert (row["arm"], row["repeat"], row["direction"], row["mode"], row["valid"]) == (
            arm, repeat, direction, mode, True)
        flags[mode].add(row["tun_flags"])
        send = direction == "dut-to-peer"
        mode_enabled = mode in ("checksum", "tcpv4")
        assert bool(int(row["tun_flags"], 16) & 0x4000) == mode_enabled
        assert not int(row["tun_flags"], 16) & 0x100
        before, after = (threads(load(folder / f"host.{phase}.json")["slot_threads"])
                         for phase in ("before", "after"))
        for key in before.keys() & after.keys():
            cpu, ticks, _ = after[key]
            if cpu in {8, 10} and ticks > before[key][1]:
                busy.setdefault(arm, set()).add(cpu)
        commands = load(folder / "commands.json")
        execution = load(folder / "exec.json")
        dut_app = "send" if send else "recv"
        values = {}
        for app, side in ((dut_app, "dut"), ("recv" if send else "send", "peer")):
            for phase in ("before", "after"):
                state = (folder / f"{side}.{phase}.txt").read_text()
                eth = state.split("Features for eth0:\n", 1)[1].split("Features for utcp0:\n", 1)[0]
                for key, enabled in (("tx-tcp-segmentation", "on"),
                                     ("generic-segmentation-offload", "on"),
                                     ("generic-receive-offload", "off")):
                    feature(eth, key, enabled)
                assert "eth0 root" in state and "net.ipv4.tcp_no_metrics_save = 1" in state
                if side == "dut":
                    assert re.search(r"qdisc pfifo \w+: dev utcp0 root .*limit 10000p", state)
                    header = "vnet_hdr on" if mode_enabled else "vnet_hdr off"
                    assert re.search(r"tun type tun pi off " + header, state)
            usage = load(folder / f"{app}.usage.json")
            summary = load(folder / f"{app}.stdout")
            summary_from_jsonl = [rec for line in (folder / f"{app}.jsonl").read_text().splitlines()
                                  if (rec := json.loads(line))["ev"] == "summary"]
            assert summary_from_jsonl == [summary] and execution[app]["argv"] == commands[app]
            assert execution[app]["status"] == usage["status"] == 0 and not usage["timed_out"]
            assert usage["affinity"] == [plan["cpus"][side]]
            assert usage["argv"] == commands[app][commands[app].index(usage["argv"][0]):]
            argv = usage["argv"]
            assert argv[0] == str(recorded_path / "bin" / (mode if side == "dut" else "kernel"))
            assert argv[argv.index("--cc") + 1] == summary["cc"] == "cubic"
            assert argv[argv.index("--bytes") + 1] == str(plan["bytes"])
            backend = "utcp" if side == "dut" and mode != "kernel" else "kernel"
            assert argv[argv.index("--backend") + 1] == summary["backend"] == backend
            assert summary["role"] == {"send": "sender", "recv": "receiver"}[app]
            assert summary["ok"] and summary["bytes"] == plan["bytes"] and summary["sha256"] == expected_sha
            assert usage["user_s"] >= 0 and usage["sys_s"] >= 0 and usage["wall_ns"] > 0
            gigabytes = plan["bytes"] / 1e9
            duration = summary["duration_us"]
            bps = summary["goodput_bps"]
            assert plan["bytes"] * 8e6 / (duration + 1) - 1 <= bps <= plan["bytes"] * 8e6 / duration
            if app == "recv":
                assert bps / 1e9 == row["receiver_gbps"]
                values["receiver_gbps"] = bps / 1e9
            if side == "dut":
                values["dut_user_s_per_gb"] = usage["user_s"] / gigabytes
                values["dut_system_s_per_gb"] = usage["sys_s"] / gigabytes
                values["dut_cpu_s_per_gb"] = (usage["user_s"] + usage["sys_s"]) / gigabytes
                assert values["dut_cpu_s_per_gb"] == row[f"{app}_total_s_per_gb"]
                if mode != "kernel":
                    assert "--tun-offload=" + mode in argv
                    stats = load(folder / f"{app}.stats.json")
                    assert stats == row["stack_stats"]
                    assert stats["dev_tun_offload"] == mode
                    assert stats["dev_vnet_hdr_size"] == (10 if mode_enabled else 0)
                    assert stats["dev_device_failed"] is False
                    assert 0 == stats["dev_rx_vnet_drops"] == stats["dev_rx_errors"] == stats["dev_tx_errors"]
                    assert 0 == stats["TcpInCsumErrors"]
                    assert bool(stats["dev_rx_csum_valid"] + stats["dev_rx_csum_partial"]) == mode_enabled
                    assert bool(stats["dev_tx_csum_partial"]) == mode_enabled
                    if mode_enabled:
                        active = load(folder / "tun.active.json")
                        assert active["status"] == 0
                        feature(active["stdout"], "tx-checksum-ip-generic", "on")
                        feature(active["stdout"], "tx-tcp-segmentation", "on" if mode == "tcpv4" else "off")
                    for key in ("rx_read_calls", "tx_write_calls"):
                        values[key + "_per_gb"] = stats["dev_" + key] / gigabytes
                    values["counts"] = {k: stats["dev_" + k] for k in
                                        ("tx_csum_partial", "rx_csum_partial", "rx_csum_valid",
                                         "rx_gro_datagrams", "rx_gro_segments",
                                         "tx_gso_datagrams", "tx_gso_segments", "tx_eagain")}
                    for kind in ("tx_gso", "rx_gro"):
                        d, n = (values["counts"][kind + suffix] for suffix in ("_datagrams", "_segments"))
                        if mode != "tcpv4":
                            assert d == n == 0
                        elif (kind == "tx_gso") == send:
                            assert n > d > 0
        groups[direction + "/" + mode].append(values)
    assert len(plan["order"]) == (6 if smoke else 30)
    assert len(groups) == 6 and set(map(len, groups.values())) == {1 if smoke else 5}
    assert sum(1 for p in path.glob("*/result.json")) == len(plan["order"])
    all_groups = {}
    for key, rows in groups.items():
        all_groups[key] = metrics(rows)
        counts = sum((c.Counter(row.get("counts", {})) for row in rows), c.Counter())
        if counts:
            all_groups[key]["counter_sums"] = dict(counts)
            for kind in ("tx_gso", "rx_gro"):
                f, n = counts[kind + "_datagrams"], counts[kind + "_segments"]
                if f:
                    all_groups[key][kind + "_logical_per_aggregate"] = n / f
    perf_path = path / "perf.json"
    perf = load(perf_path) if perf_path.exists() else None
    if perf:
        assert perf["exit"] == 1 and perf["paranoid"] == "4"
    return {
        "id": run,
        "verified_files": len(entries),
        "manifest_sha256": digest,
        "bytes_per_arm": plan["bytes"],
        "payload_sha256": expected_sha,
        "arms": len(plan["order"]),
        "tun_flags": {mode: sorted(values) for mode, values in flags.items()},
        "groups": all_groups,
        "snapshot_interference_cpus": {arm: sorted(cpus) for arm, cpus in busy.items()},
        "ordinary_perf": {key: perf[key] for key in ("argv", "exit", "paranoid", "version")}
                         if perf else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=pathlib.Path, help="directory containing the three campaigns")
    args = parser.parse_args()
    if not __debug__:
        parser.error("archive checks require Python without optimization")
    result = [audit(args.archive, run, digest) for run, digest in campaigns.items()]
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
