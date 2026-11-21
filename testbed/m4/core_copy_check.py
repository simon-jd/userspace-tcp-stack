"""Validate GDB copy observations against known streams and expected coverage."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def summarize(rows):
    paths = collections.defaultdict(list)
    for r in rows:
        paths[r["path"]].append(r)
    return {name: {"bytes": sum(r["bytes"] for r in values), "calls": len(values)}
            for name, values in sorted(paths.items())}


def coverage(rows, kinds, start, end):
    cursor = start
    for row in sorted((r for r in rows if r["path"] in kinds), key=lambda r: r["offset"]):
        require(row["offset"] == cursor, (kinds, cursor, row))
        cursor += row["bytes"]
    require(cursor == end, (kinds, cursor, end))


def fixture_bytes(name, path, offset, length):
    if name.startswith("OutOfOrderGro"):
        return bytes((i + 42 if i < 1460 else i - 1460 + 21) & 255
                     for i in range(offset, offset + length))
    if name.startswith("PartialSend"):
        seed = 171 if path in ("app_to_send_ring", "tx_packet") else 57
    else:
        seeds = {"VnetGroFrame": 129, "ReadShutdownWith": 91, "ShutdownBoth": 121,
                 "ReadShutdownStill": 19, "InOrderGroFallsBack": 21}
        seed = next((value for prefix, value in seeds.items() if name.startswith(prefix)), 0)
    return bytes((i + seed) & 255 for i in range(offset, offset + length))


def check_units(path, xml, baseline):
    records = json.loads(path.read_text())
    tests = ET.parse(xml).getroot()
    completed = {f"{t.get('classname')}_{t.get('name')}" for t in tests.iter("testcase")
                 if t.get("result") == "completed" and t.find("failure") is None}
    cases = {
        "PartialSendAndShortReadsKeepTheAcceptedBytes":
            {"app_to_send_ring": (4096, 1), "tx_packet": (4096, 3),
             "rx_packet": (4096, 3), "recv_ring_to_app": (4096, 2)},
        "VnetGroFrameUsesTheOriginalPayloadAcrossChunks":
            {"rx_gro": (4397, 2), "recv_ring_to_app": (4397, 2)},
        "OutOfOrderGroUsesLogicalReceivePath":
            {"rx_gro_fallback": (2920, 3), "rx_packet": (1460, 1), "recv_ring_to_app": (4380, 2)},
        "FreshGsoIsBoundedByTheLogicalCwndAndRetainsPerSegmentRecovery":
            {"app_to_send_ring": (8765, 3), "tx_gso": (5840, 2), "tx_retransmit": (1460, 1)},
        "HeldLargePacketFallsBackToOrdinaryFramesWithoutDroppingData":
            {"app_to_send_ring": (11680, 3), "tx_gso": (5840, 2), "tx_packet": (5840, 5)},
        "InOrderGroFallsBackUnderChunkPressure":
            {"rx_gro_fallback": (2920, 2), "recv_ring_to_app": (2920, 1)},
        "ReadShutdownWithUnreadPrefixAndPendingFinPreservesAdmission":
            {"rx_packet": (4541, 6), "recv_ring_to_app": (73, 1)},
        "ReadShutdownStillChargesOutOfOrderChunksAndPrunesOnHoleFill": {},
        "ShutdownBothDiscardsUnreadDataAndSendsFin": {"rx_packet": (183, 1)},
    }
    if baseline:
        cases["ReadShutdownWithUnreadPrefixAndPendingFinPreservesAdmission"].update(
            discard_at_shutdown=(4427, 3), discard_after_shutdown=(3733, 4),
            rx_after_shutdown=(3692, 3))
        cases["ShutdownBothDiscardsUnreadDataAndSendsFin"].update(discard_at_shutdown=(183, 1))
        cases["ReadShutdownStillChargesOutOfOrderChunksAndPrunesOnHoleFill"].update(
            rx_after_shutdown=(4130, 5), discard_after_shutdown=(4113, 4))
    expected = {"TcpOffload_" + name for name in cases}
    require(completed == expected, ("fixture cases", completed ^ expected))
    require(all(r["case"] in expected for r in records), "unexpected fixture attribution")
    result = {}
    for name, counts in cases.items():
        rows = [r for r in records if r["case"] == "TcpOffload_" + name]
        for r in rows:
            content = fixture_bytes(name, r["path"], r["offset"], r["bytes"])
            require(hashlib.sha256(content).hexdigest() == r["sha256"], (name, r))
        totals = summarize(rows)
        observed = {k: (v["bytes"], v["calls"]) for k, v in totals.items()}
        require(observed == counts, (name, observed, counts))
        result[name] = totals
    return result


def bulk_pattern(size, seed):
    mask = (1 << 64) - 1
    data = bytearray()
    for n in range((size + 7) // 8):
        z = (seed + n * 0x9e3779b97f4a7c15) & mask
        z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & mask
        z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & mask
        data.extend((z ^ (z >> 31)).to_bytes(8, "little"))
    return data[:size]


def check_wire(directory):
    size = 65549
    data = bulk_pattern(size, 271)
    digest = hashlib.sha256(data).hexdigest()
    output = {}
    for mode in ("legacy", "tcpv4"):
        for direction in ("send", "recv"):
            p = directory / f"{mode}-{direction}"
            rows = json.loads((p / "copies.json").read_text())
            stats = json.loads((p / "stack.json").read_text())
            require(stats["dev_tun_offload"] == mode and
                    stats["dev_vnet_hdr_size"] == (0 if mode == "legacy" else 10), p)
            require(all(stats[k] == 0 for k in
                        ("dev_rx_errors", "dev_tx_errors", "dev_rx_vnet_drops")), p)
            for role in ("server", "linux"):
                summary = json.loads((p / f"{role}.jsonl").read_text().splitlines()[-1])
                require(summary["ev"] == "summary" and summary["ok"] and summary["bytes"] == size
                        and summary["sha256"] == digest, (p, role, summary))
            for r in rows:
                off, length = r["offset"], r["bytes"]
                require(0 <= off < off + length <= size and r["case"] == "application", (p, r))
                require(hashlib.sha256(data[off:off + length]).hexdigest() == r["sha256"], (p, r))
            if direction == "send":
                first, second = {"app_to_send_ring"}, {"tx_packet", "tx_gso"}
                exceptional = {"tx_retransmit"}
                aggregate, dev = "tx_gso", "dev_tx_gso_datagrams"
            else:
                first, second = {"rx_packet", "rx_gro", "rx_gro_fallback"}, {"recv_ring_to_app"}
                exceptional = set()
                aggregate, dev = "rx_gro", "dev_rx_gro_datagrams"
            require(all(r["path"] in first | second | exceptional for r in rows), p)
            coverage(rows, first, 0, size)
            coverage(rows, second, 0, size)
            totals = summarize(rows)
            require((stats[dev] > 0) == (mode == "tcpv4"), (p, dev))
            require((aggregate in totals) == (mode == "tcpv4"), (p, aggregate))
            output[p.name] = {"paths": totals, "aggregate_datagrams": stats[dev],
                              "bytes": size, "sha256": digest}
    return output


def main():
    p = argparse.ArgumentParser(description=__doc__)
    cmd = p.add_subparsers(dest="command", required=True)
    unit = cmd.add_parser("unit")
    unit.add_argument("copies", type=Path)
    unit.add_argument("gtest_xml", type=Path)
    unit.add_argument("--baseline", action="store_true")
    wire = cmd.add_parser("wire")
    wire.add_argument("directory", type=Path)
    args = p.parse_args()
    result = (check_units(args.copies, args.gtest_xml, args.baseline) if args.command == "unit"
              else check_wire(args.directory))
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
