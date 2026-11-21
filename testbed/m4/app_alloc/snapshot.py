"""Read the measured process's seqlock table externally (Linux/x86-64)."""
import json
import mmap
import struct
import sys
import time
from pathlib import Path

folder, phase = Path(sys.argv[1]), sys.argv[2]
def packets():
    base = Path("/sys/class/net/utcp0/statistics")
    return [int((base / key).read_text()) for key in ("rx_packets", "tx_packets")]
before = packets()
with (folder / "cpp-new-count.all").open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mem:
    for _ in range(10000):
        start = time.monotonic_ns()
        seq = struct.unpack_from("Q",mem)[0]
        if seq % 2:
            continue
        buf = mem[:]
        end = time.monotonic_ns()
        if seq == struct.unpack_from("Q",mem)[0] == struct.unpack_from("Q",buf)[0]:
            break
    else:
        raise RuntimeError("no consistent allocation image")
after = packets()
seq,calls,nbytes,overflow,tc,tb,fc,fb,hwm,final = struct.unpack_from("10Q",buf)
assert not overflow
sites = {f"{pc:x}/{kind}":[n,b] for pc,kind,n,b in struct.iter_unpack("4Q",buf[80:]) if pc}
assert sum(x[0] for x in sites.values()) == calls
assert sum(x[1] for x in sites.values()) == nbytes
out = dict(start_ns=start, end_ns=end, calls=calls, bytes=nbytes, sites=sites, packets_before=before,
           packets_after=after, trace_open=[tc,tb],trace_close=[fc,fb],peak_kib=hwm,final=final)
(folder / (phase+".alloc.json")).write_text(json.dumps(out)+"\n")
print(json.dumps({k:v for k,v in out.items() if k!="sites"}))
