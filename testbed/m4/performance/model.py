"""Predeclared arm order and metrics derived from endpoint receipts."""

import math
import statistics

DIRECTIONS = ("dut-to-peer", "peer-to-dut")
METRICS = ("receiver_gbps", "send_user_s_per_gb", "send_sys_s_per_gb",
           "send_total_s_per_gb", "recv_user_s_per_gb", "recv_sys_s_per_gb",
           "recv_total_s_per_gb")


def schedule(repeats, candidate, reference=None):
    modes = ["kernel", candidate] if reference is None else ["kernel", reference, candidate]
    return [(rep, direction, mode)
            for rep in range(1, repeats + 1)
            for direction in (DIRECTIONS if rep % 2 else DIRECTIONS[::-1])
            for mode in (modes if rep % 2 else modes[::-1])]


def measure(sender, receiver, goal, digest, backends, cpus):
    result = {"receiver_bytes": goal, "sha256": digest}
    for evidence, role, prefix, backend, cpu in zip(
            (sender, receiver), ("sender", "receiver"), ("send", "recv"), backends, cpus,
            strict=True):
        summary, usage = evidence["summary"], evidence["usage"]
        if (summary.get("ev") != "summary" or summary.get("role") != role
                or summary.get("backend") != backend or summary.get("cc") != "cubic"):
            raise ValueError(f"{role} app identity or congestion algorithm differs")
        if usage.get("status") != 0 or usage.get("timed_out") is not False:
            raise ValueError(f"{role} process did not exit successfully")
        if usage.get("affinity") != [cpu]:
            raise ValueError(f"{role} effective process affinity differs from CPU {cpu}")
        if (summary.get("ok") is not True or summary.get("bytes") != goal
                or summary.get("sha256") != digest):
            raise ValueError(f"{role} transfer did not match the planned bytes and SHA-256")
        duration_us, bps = summary.get("duration_us"), summary.get("goodput_bps")
        if (type(duration_us) is not int or duration_us <= 0 or type(bps) is not int
                or not goal * 8_000_000 / (duration_us + 1) - 1 <= bps <= goal * 8_000_000 / duration_us):
            raise ValueError(f"{role} app duration and goodput are inconsistent")
        user, system = usage.get("user_s"), usage.get("sys_s")
        if any(type(value) not in (float, int) or not math.isfinite(value) or value < 0
               for value in (user, system)):
            raise ValueError(f"{role} has invalid wait4 CPU times")
        gb = goal / 1e9
        result.update({f"{prefix}_user_s_per_gb": user / gb,
                       f"{prefix}_sys_s_per_gb": system / gb,
                       f"{prefix}_total_s_per_gb": (user + system) / gb,
                       f"{prefix}_total_retrans": summary["total_retrans"],
                       f"{prefix}_bytes_retrans": summary["bytes_retrans"],
                       f"{prefix}_duration_us": duration_us})
    result["receiver_gbps"] = receiver["summary"]["goodput_bps"] / 1e9
    return result


def summarize(rows, modes):
    groups = {}
    for direction in DIRECTIONS:
        for mode in modes:
            attempts = [row for row in rows if row["direction"] == direction and row["mode"] == mode]
            valid = [row for row in attempts if row["valid"]]
            group = {"attempts": len(attempts), "valid": len(valid), "metrics": {}}
            for metric in METRICS:
                values = [row[metric] for row in valid]
                if values:
                    group["metrics"][metric] = {
                        "median": statistics.median(values), "min": min(values), "max": max(values)}
            groups[f"{direction}/{mode}"] = group
    return groups
