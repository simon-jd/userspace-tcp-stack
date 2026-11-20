"""Demultiplex both raw captures once. Store only observed endpoint tuples and echoes."""

import hashlib
import json
import re
import socket
import struct
from collections import Counter
from pathlib import Path


def packets(path, receipt):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        header = stream.read(24)
        magic = {
            b"\xd4\xc3\xb2\xa1": ("<", 1000),
            b"\xa1\xb2\xc3\xd4": (">", 1000),
            b"\x4d\x3c\xb2\xa1": ("<", 1),
            b"\xa1\xb2\x3c\x4d": (">", 1),
        }
        if len(header) != 24 or header[:4] not in magic:
            raise ValueError(f"{path.name}: malformed pcap header")
        endian, scale = magic[header[:4]]
        _, _, _, _, snap, link = struct.unpack(endian + "HHIIII", header[4:])
        if link != 1 or not 54 <= snap <= 262144:
            raise ValueError(
                f"{path.name}: unexpected physical capture link or snaplen"
            )
        digest.update(header)
        packet = struct.Struct(endian + "IIII")
        count = 0
        while raw := stream.read(16):
            if len(raw) != 16:
                raise ValueError(f"{path.name}: partial record header")
            sec, frac, incl, orig = packet.unpack(raw)
            if not 0 < incl <= min(orig, snap):
                raise ValueError(f"{path.name}: inconsistent record lengths")
            frame = stream.read(incl)
            if len(frame) != incl:
                raise ValueError(f"{path.name}: truncated record")
            digest.update(raw)
            digest.update(frame)
            count += 1
            if frame[12:14] == b"\x08\x00":
                yield sec * 10**9 + frac * scale, frame[14:]
    receipt.update(bytes=path.stat().st_size, records=count, sha256=digest.hexdigest())


def tcpdump_counts(text):
    return {
        key: int(m.group(1))
        if (m := re.search(r"(\d+) packets? " + suffix, text))
        else None
        for key, suffix in (
            ("captured", "captured"),
            ("filtered", "received by filter"),
            ("dropped", "dropped by kernel"),
        )
    }


def capture(directory, meta):
    dst = socket.inet_aton(meta["rcv_ip"])
    ping_src = socket.inet_aton(meta["snd_ip"])
    result = {}
    for name in ("r1-in", "r2-out"):
        tuples, echoes, evidence = {}, {}, {}
        for ts, ip in packets(directory / (name + ".pcap"), evidence):
            if len(ip) < 20 or ip[0] >> 4 != 4:
                continue
            ihl = (ip[0] & 15) * 4
            if ip[9] == 1 and name == "r1-in" and len(ip) >= ihl + 8:
                kind = ip[ihl]
                key = struct.unpack_from(">HH", ip, ihl + 4)
                if kind == 8 and ip[12:16] == ping_src and ip[16:20] == dst:
                    if key in echoes:
                        raise ValueError("repeated ICMP request identity")
                    echoes[key] = [*key, ts, None]
                elif (
                    kind == 0
                    and ip[12:16] == dst
                    and ip[16:20] == ping_src
                    and key in echoes
                ):
                    if echoes[key][3] is None:
                        echoes[key][3] = ts - echoes[key][2]
            if ip[9] != 6 or ip[16:20] != dst or len(ip) < ihl + 20:
                continue
            sport, dport, seq = struct.unpack_from(">HHI", ip, ihl)
            key = (ip[12:16], sport, dport)
            if key not in tuples:
                tuples[key] = dict(
                    src=socket.inet_ntoa(key[0]),
                    sport=sport,
                    dst=meta["rcv_ip"],
                    dport=dport,
                    isn=None,
                    data_segments=0,
                    retrans_segments=0,
                    stream_bytes=0,
                    first_data_rt_ns=None,
                    last_data_rt_ns=None,
                )
            row = tuples[key]
            flags = ip[ihl + 13]
            if flags & 2:
                if row["isn"] not in (None, seq):
                    raise ValueError("reused TCP tuple with different ISN")
                row["isn"] = seq
            size = struct.unpack_from(">H", ip, 2)[0] - ihl - (ip[ihl + 12] >> 4) * 4
            if size > 0:
                if row["isn"] is None:
                    raise ValueError("TCP payload without observed SYN")
                end = ((seq - row["isn"] - 1) & 0xFFFFFFFF) + size
                row["data_segments"] += 1
                row["retrans_segments"] += end <= row["stream_bytes"]
                row["stream_bytes"] = max(end, row["stream_bytes"])
                if row["first_data_rt_ns"] is None:
                    row["first_data_rt_ns"] = ts
                row["last_data_rt_ns"] = ts
        evidence.update(
            tuples=list(tuples.values()),
            **tcpdump_counts((directory / (name + ".tcpdump.txt")).read_text()),
        )
        if name == "r1-in":
            evidence["echoes"] = list(echoes.values())
        result[name] = evidence
    return result
