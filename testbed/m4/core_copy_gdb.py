"""GDB batch probe of completed ByteRing memcpy calls (GCC Debug, Linux x86-64).

Use -x with --args and set UTCP_COPY_OUTPUT to a fresh JSON path. Every caller
is classified from its live TCP stack. Read the real source at call entry and
the real destination at return before recording the stream offset and length.
"""
import hashlib
import json
import os
import re
from pathlib import Path

import gdb


def context():
    frames = {}
    counts = {}
    case = "application"
    f = gdb.newest_frame()
    while f:
        name = (f.name() or "").removeprefix("(anonymous namespace)::")
        frames.setdefault(name, f)
        counts[name] = counts.get(name, 0) + 1
        if name.endswith("_Test::TestBody"):
            case = name.split("::")[-2].removesuffix("_Test")
            break
        f = f.older()
    engine = "utcp::TcpEngine::"
    if engine + "send_segment" in frames:
        f = frames[engine + "send_segment"]
        kind = "tx_retransmit" if bool(f.read_var("o")["retrans"]) else (
            "tx_gso" if int(f.read_var("segments")) > 1 else "tx_packet")
    elif "utcp::SendQueue::write" in frames:
        kind = "app_to_send_ring"
    elif "utcp::RecvBuffer::read" in frames:
        if engine + "tcp_shutdown" in frames:
            kind = "discard_at_shutdown"
        elif engine + "data_input" in frames:
            kind = "discard_after_shutdown"
        else:
            kind = "recv_ring_to_app"
    elif engine + "data_input" in frames:
        f = frames[engine + "data_input"]
        if bool(f.read_var("t")["app_read_shut"]):
            kind = "rx_after_shutdown"
        elif counts[engine + "on_segment"] > 1:
            kind = "rx_gro_fallback"
        elif int(f.read_var("s")["meta"]["gso_size"]):
            kind = "rx_gro"
        else:
            kind = "rx_packet"
    else:
        raise RuntimeError(f"unclassified ring copy in {list(frames)}")
    return case, kind


class Probe(gdb.Breakpoint):
    def __init__(self, pc, before):
        super().__init__(f"*{pc}", internal=True)
        self.before = before

    def stop(self):
        global pending, failure
        try:
            inf = gdb.selected_inferior()
            if self.before:
                if pending is not None:
                    raise RuntimeError("interleaved copy in single-threaded probe")
                f = gdb.newest_frame()
                length = int(f.read_register("rdx"))
                if not 0 < length <= 4096:
                    raise RuntimeError(f"unexpected copy length {length}")
                src = int(f.read_register("rsi"))
                dst = int(f.read_register("rdi"))
                case, kind = context()
                pending = (case, kind, int(f.read_var("pos")), dst, bytes(inf.read_memory(src, length)))
            else:
                case, kind, offset, dst, source = pending
                if bytes(inf.read_memory(dst, len(source))) != source:
                    raise RuntimeError(f"{case} {kind} at {offset}: destination differs")
                records.append({"case": case, "path": kind, "offset": offset, "bytes": len(source),
                                "sha256": hashlib.sha256(source).hexdigest()})
                pending = None
            return False
        except Exception as error:
            failure = str(error)
            return True


def main():
    path = Path(os.environ["UTCP_COPY_OUTPUT"])
    if path.exists():
        raise RuntimeError(f"output already exists: {path}")
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("set debuginfod enabled off")
    gdb.execute("set disable-randomization off")
    gdb.execute("start")
    arch = gdb.newest_frame().architecture()
    if arch.name() != "i386:x86-64":
        raise RuntimeError(f"unsupported memcpy ABI: {arch.name()}")
    for method in ("read_at", "write_at"):
        symbol = "utcp::ByteRing::" + method
        asm = gdb.execute("disassemble " + symbol, to_string=True)
        if method == "write_at" and "<memcpy@plt>" not in asm:
            # The discard-aware implementation specializes the write loop.
            asm = gdb.execute("disassemble 'utcp::ByteRing::store_at<true>'", to_string=True)
        calls = re.findall(r"^\s*(0x[0-9a-f]+) <[^>]+>:\s+call\s+.*<memcpy@plt>$", asm, re.M)
        if len(calls) != 1:
            raise RuntimeError(f"{method}: expected exactly one memcpy instruction, saw {calls}")
        pc = int(calls[0], 16)
        Probe(pc, True)
        Probe(pc + arch.disassemble(pc, count=1)[0]["length"], False)
    gdb.execute("continue")
    if failure or pending or int(gdb.parse_and_eval("$_exitcode")) != 0 or not records:
        raise RuntimeError(f"incomplete observation: {failure}; copies={len(records)}")
    with path.open("x") as stream:
        json.dump(records, stream, indent=2)
        stream.write("\n")


records = []
pending = None
failure = None
try:
    main()
except Exception as error:
    gdb.write(f"core copy probe failed: {error}\n", gdb.STDERR)
    gdb.execute("quit 1")
