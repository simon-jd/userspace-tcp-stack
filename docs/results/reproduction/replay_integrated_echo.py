import hashlib
import json
import sys
from pathlib import Path

SOURCE = "261b91de798bd3a965852a9737cf37e60c7e718e"
BINARY = "15fc2bab42f7c2d4b8b7e2c112f0c7d84e606520e563abf458a8894f4ae94fa3"
IMAGE = "sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66"
PHASES = ("idle-start", "idle-end", "drained")
ROLES = ("server", "client")


def read(path):
    return json.loads(path.read_text())


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check(mode, root):
    direct = mode == "direct"
    assert not (root / "failure.json").exists()
    manifest, runtime, result = (read(root / f"{name}.json") for name in ("run", "runtime", "result"))
    assert manifest["run_id"] == root.name
    assert manifest["source"] == manifest["runner_source"] == result["source"] == SOURCE
    assert manifest["git_status"] == "" and manifest["docker_image_id"] == IMAGE
    assert manifest["binary_source_by_role"] == dict.fromkeys(ROLES, SOURCE)
    assert manifest["binary_sha256_by_role"] == dict.fromkeys(ROLES, BINARY)
    assert all(runtime[role]["running_sha256"] == BINARY for role in ROLES)
    assert runtime["server"]["tun_queues"] == ["rx-0", "tx-0"]
    assert manifest["cpu_thread_siblings"] == {str(cpu): str(cpu) for cpu in (24, 25, 26)}
    args = manifest["arguments"]
    assert args["purpose"] == result["purpose"] == "functional"
    assert args["backend"] == result["backend"] == "utcp"
    assert args["offload"] == result["offload"] == "legacy"
    assert args["connections"] == result["connections"] == 10_000
    assert (args["count"], args["size"], args["rate"], args["hold_s"]) == (5, 64, 5_000, 5.0)
    assert args["cpus"] == [24, 25, 26] and args["direct_echo"] is direct
    assert ("--direct-echo" in read(root / "server/argv.json")) is direct
    assert "--direct-echo" not in read(root / "client/argv.json")
    assert result["ok"] is True
    assert all((root / "control" / gate).is_file() for gate in ("open", "active", "close"))
    shots = {role: {phase: read(root / role / f"{phase}.json") for phase in PHASES} for role in ROLES}
    for cpu, role in zip((24, 25), ROLES, strict=True):
        initial = read(root / role / "baseline.json")
        assert initial["affinity"] == [cpu] and initial["nice"] == 10
        assert initial["target_tcp"]["established"] == 0
        for phase in PHASES:
            shot = shots[role][phase]
            assert shot["pid"] == initial["pid"] and shot["netns"] == initial["netns"]
    tuples = [shots["client"][phase]["target_tcp"] for phase in PHASES]
    assert all(row["established"] == 10_000 for row in tuples)
    assert len({row["tuple_sha256"] for row in tuples}) == 1
    hold_begin = max(shots[role]["idle-start"]["ended_ns"] for role in ROLES)
    hold_end = min(shots[role]["idle-end"]["started_ns"] for role in ROLES)
    assert hold_end - hold_begin == result["held_ns"] >= 5_000_000_000
    events = {role: [json.loads(line) for line in (root / role / "events.jsonl").read_text().splitlines()]
              for role in ROLES}
    assert all(row["errors"] == 0 and row.get("mismatches", 0) == 0
               for values in events.values() for row in values)
    client_idle = [row for row in events["client"] if row.get("phase") == "idle"]
    assert client_idle[0]["monotonic_ns"] <= hold_begin < hold_end <= client_idle[-1]["monotonic_ns"]
    assert all(row["open"] == row["established"] == 10_000
               and row["requests_started"] == row["bytes"] == 0 for row in client_idle)
    server_idle = [row for row in events["server"] if row["ev"] == "load" and
                   hold_begin <= row["monotonic_ns"] <= hold_end]
    assert len(server_idle) >= 2
    assert all(row["open"] == row["accepted"] == 10_000 and row["closed"] == row["bytes"] == 0
               and row["tcp_slots"] == 10_001 and row["time_wait_entries"] == 0 for row in server_idle)
    steady = result["steady"]["server_app"]
    assert steady in events["server"] and steady["open"] == steady["accepted"] == 10_000
    assert steady["closed"] == steady["bytes"] == steady["time_wait_entries"] == 0
    assert steady["tcp_slots"] == 10_001
    client, server = events["client"][-1], events["server"][-1]
    assert client == result["client_summary"] and server == result["server_summary"]
    assert client["ev"] == server["ev"] == "summary" and client["ok"] is True
    assert client["requests_started"] == client["requests_ok"] == 50_000
    assert client["connections_ok"] == server["accepted"] == server["closed"] == 10_000
    assert client["bytes"] == server["bytes"] == 3_200_000
    assert server["staged_bytes"] == (0 if direct else 3_200_000)
    assert server["stage_appends"] == (0 if direct else 50_000)
    assert server["compacted_bytes"] == server["relocated_bytes"] == 0
    stack = result["stack_stats"]
    assert stack == read(root / "server/stack-stats.jsonl")
    assert stack["dev_tun_offload"] == "legacy" and stack["dev_tun_queues"] == 1
    assert stack["dev_rx_queue_0_datagrams"] > 0 and stack["dev_tx_queue_0_datagrams"] > 0
    assert stack["dev_device_failed"] is False
    return {"mode": mode, "run_id": root.name, "volume": f"utcp-data:/m4-echo-load/{root.name}",
            "connections_observed_at_both_endpoints": 10_000, "held_ns": result["held_ns"],
            "client_idle_reports": len(client_idle), "server_full_population_reports_inside_hold": len(server_idle),
            "client_steady_tuple_sha256": tuples[0]["tuple_sha256"], "verified_replies": client["requests_ok"],
            "client_verified_bytes": client["bytes"], "server_echoed_bytes": server["bytes"],
            "staged_bytes": server["staged_bytes"], "stage_appends": server["stage_appends"],
            "compacted_bytes": server["compacted_bytes"], "relocated_bytes": server["relocated_bytes"],
            "errors": client["errors"] + server["errors"], "mismatches": client["mismatches"],
            "server_queues": runtime["server"]["tun_queues"], "executables_sha256": BINARY,
            "result_sha256": sha(root / "result.json"), "manifest_sha256": sha(root / "run.json")}


print(json.dumps([check(mode, Path(path)) for mode, path in zip(("default", "direct"), sys.argv[1:], strict=True)], indent=2))
