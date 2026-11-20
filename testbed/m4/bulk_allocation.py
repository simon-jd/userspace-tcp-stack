#!/usr/bin/env python3
"""Count C++ allocation calls during a warmed single-queue bulk transfer."""

import argparse
import json
import os
import subprocess
import sys
import time

from echo_load import PORT, STACK_IP, Trial, require


class BulkTrial(Trial):
    def latest(self, role):
        # The stdio writer can leave a partial JSON line at its buffer
        # boundary. Fall back to the preceding complete event.
        try:
            tail = self.docker(role, "tail", "-n", "2", f"{self.out}/{role}/events.jsonl")
        except subprocess.CalledProcessError:
            return {}
        for line in reversed(tail.splitlines()):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        return {}


def window(samples, first, last, byte_field, seg_field):
    # The app's transport samples bracket the externally read allocation
    # counters. Keep both bounds instead of assigning packets to an exact
    # interval from asynchronous samples.
    def around(ns):
        before = [event for event in samples if event["t"] <= ns]
        after = [event for event in samples if event["t"] >= ns]
        require(before and after, "allocation sample outside live bulk counters")
        return before[-1], after[0]

    before_first, after_first = around(first["sample_ns"])
    before_last, after_last = around(last["sample_ns"])
    lower = {field: before_last[field] - after_first[field] for field in (byte_field, seg_field)}
    upper = {field: after_last[field] - before_first[field] for field in (byte_field, seg_field)}
    require(first["sample_ns"] < last["sample_ns"] and first["calls"] <= last["calls"]
            and 0 < lower[byte_field] <= upper[byte_field] and 0 < lower[seg_field] <= upper[seg_field],
            "invalid allocation or transport counter delta")
    return {"scope": "server_process_replaced_cpp_new", "start": first, "end": last,
            "calls": last["calls"] - first["calls"], "lower": lower, "upper": upper}


def measure(trial, direction):
    common = ("--cc", "cubic", "--sample-ms", "100", "--jsonl", "-", "--pattern-seed", "1")
    listen_extra = ("--send", "--duration", "8s") if direction == "send" else ("--recv",)
    connect_extra = ("--recv",) if direction == "send" else ("--send", "--duration", "8s")
    trial.launch("server", "--backend", "utcp", "--listen", f"{STACK_IP}:{PORT}",
                 "--tun", "utcp0", "--addr", STACK_IP, "--profile", "linux", "--seed", "1",
                 "--stats", f"{trial.out}/server/stack-stats.jsonl", *common, *listen_extra)
    # The bulk JSON writer buffers output, so the config record alone cannot
    # synchronize a listener that has not yet accepted a connection.
    trial.docker("server", "sh", "-c", """
for i in $(seq 1 100); do
    if p=$(cat "$1/pid" 2>/dev/null) && test -s "$1/cpp-new-count" &&
       find "/proc/$p/fd" -lname /dev/net/tun -print -quit 2>/dev/null | grep -q .; then
        exit 0
    fi
    sleep 0.05
done
exit 1
""", "sh", f"{trial.out}/server")
    trial.launch("client", "--backend", "kernel", "--connect", f"{STACK_IP}:{PORT}",
                 *common, *connect_extra)
    byte_field, seg_field = (("bytes_sent", "data_segs_out") if direction == "send" else
                             ("bytes_received", "data_segs_in"))
    trial.wait("server", lambda row: row.get("ev") == "sample" and row[byte_field] >= 8 * 1024**2,
               "at least 8 MiB of warm-up traffic")
    runtime = trial.network_readback()
    first = trial.snapshot("steady-start", sockets=False)["server"]["cpp_new"]
    time.sleep(2)
    last = trial.snapshot("steady-end", sockets=False)["server"]["cpp_new"]
    summary = {}
    for role in ("server", "client"):
        summary[role] = trial.wait(role, lambda row: row.get("ev") == "summary", "bulk summary")
        require(trial.processes[role].wait(timeout=15) == 0 and summary[role]["ok"],
                f"{role} bulk transfer failed")
    server, peer = summary["server"], summary["client"]
    require(server["sha256"] == peer["sha256"] and server["bytes"] == peer["bytes"] >= 8 * 1024**2,
            "bulk endpoints disagree on bytes or SHA-256")
    rows = trial.docker("server", "cat", f"{trial.out}/server/events.jsonl").splitlines()
    events = [json.loads(row) for row in rows]
    started = next(row["t"] for row in events if row["ev"] == "start")
    samples = [row for row in events if row["ev"] == "sample"]
    require(started < first["sample_ns"] < last["sample_ns"] < started + 8_000_000_000,
            "counter window crossed the scheduled bulk send interval")
    stack = json.loads(trial.docker("server", "cat", f"{trial.out}/server/stack-stats.jsonl"))
    return {"ok": True, "direction": direction, "volume": "utcp-data:" + trial.out.removeprefix("/data"),
            "summary": summary, "window": window(samples, first, last, byte_field, seg_field),
            "tun_queues": runtime["server"]["tun_queues"], "stack_stats": stack}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--direction", choices=("send", "receive"), required=True)
    parser.add_argument("--allocation-counter", required=True)
    parser.add_argument("--image", default=os.environ.get("UTCP_IMAGE", "utcp-testbed:dev"))
    parser.add_argument("--binary", default="build/gcc-release/apps/utcp-bulk/utcp-bulk")
    parser.add_argument("--net-base", type=int, default=88)
    args = parser.parse_args()
    if not 1 <= args.net_base <= 254:
        parser.error("--net-base must be 1..254")
    args.purpose = "functional"
    args.backend = "utcp"
    args.offload = "legacy"
    args.cpus = (24, 25, 26)
    args.binary_source = args.client_source = args.client_binary = None
    try:
        trial = BulkTrial(args, result_dir="m4-bulk-allocation")
    except (OSError, ValueError) as error:
        print(f"invalid benchmark binary or allocation counter: {error}", file=sys.stderr)
        return 1
    try:
        trial.setup()
        result = measure(trial, args.direction)
        trial.capture_json("server", "result.json", result)
        print(json.dumps(result))
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError, KeyError) as error:
        detail = {"ok": False, "run_id": trial.tag, "error": str(error)}
        if isinstance(error, subprocess.CalledProcessError):
            detail["output"] = error.stdout
        if trial.artifacts_created:
            try:
                trial.capture_json("server", "failure.json", detail)
            except (OSError, subprocess.SubprocessError) as save_error:
                detail["artifact_error"] = str(save_error)
        print(json.dumps(detail), file=sys.stderr)
        return 1
    finally:
        trial.cleanup()


if __name__ == "__main__":
    sys.exit(main())
