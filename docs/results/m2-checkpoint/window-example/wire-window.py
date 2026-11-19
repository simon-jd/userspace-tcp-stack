"""Review the two CUBIC group-0 runs directly in their original campaign directory.

Run python3 wire-window.py /evidence. Only compact measurements are printed.
The receiver metric uses linear interpolation at the two monotonic boundaries.
r2-out wire bytes count every data transmission, including duplicates. Contiguous
sequence advance includes earlier out-of-order bytes released inside the window.
"""
import bisect
import json
import socket
import struct
import sys
from pathlib import Path

def packets(path):
    magic = {bytes.fromhex(k): v for k, v in [('4d3cb2a1', ('<', 1)), ('d4c3b2a1', ('<', 1000)),
                                              ('a1b23c4d', ('>', 1)), ('a1b2c3d4', ('>', 1000))]}
    with path.open('rb', buffering=1024*1024) as f:
        header = f.read(24)
        endian, scale = magic[header[:4]]
        assert struct.unpack_from(endian+'II', header, 16) == (128, 1)
        unpack = struct.Struct(endian+'IIII').unpack
        while hdr := f.read(16):
            sec, frac, cap, wire = unpack(hdr)
            data = f.read(cap)
            assert len(data) == cap <= min(wire,128)
            yield sec*10**9 + frac*scale, data

def telemetry(path):
    rows = list(map(json.loads, path.open()))
    start, = [z['t'] for z in rows if z['ev'] == 'start']
    clock, = [z for z in rows if z['ev'] == 'clock']
    return start, clock, [(z['t'], z['bytes_received']) for z in rows if z['ev'] == 'sample']

def at(samples, t):
    i = bisect.bisect_left(samples, (t, ))
    if samples[i][0] == t:
        return samples[i][1]
    a, b = samples[i-1], samples[i]
    assert a[0] < t < b[0]
    return a[1] + (b[1]-a[1])*(t-a[0])/(b[0]-a[0])

def run(path):
    meta = json.loads((path/'meta.json').read_text())
    r, _, received = telemetry(path/'rcv.jsonl')
    a, clock, _ = telemetry(path/'snd.jsonl')
    offset = clock['realtime_ns'] - clock['monotonic_ns']
    lo, hi = r+5*10**9, min(a, r)+int(meta['duration_s']*1e9)
    dest = socket.inet_aton(meta['rcv_ip'])
    origin = None
    prefix = 0
    above = []
    snapshots = []
    wire_bytes = 0
    flow = None
    for t, packet in packets(path/'r2-out.pcap'):
        if t >= lo+offset and not snapshots:
            snapshots.append((prefix, sum(b-a for a,b in above)))
        if t > hi+offset:
            break
        if packet[12:14] != bytes.fromhex('0800') or packet[23] != 6 or packet[30:34] != dest:
            continue
        tcp = 14+(packet[14]&15)*4
        ports = struct.unpack_from('!HH', packet, tcp)
        current = (packet[26:30], ports)
        seq = struct.unpack_from('!I', packet, tcp+4)[0]
        if packet[tcp+13]&2:
            assert flow is None or flow == current
            flow, origin = current, (seq+1)%2**32
        size = struct.unpack_from('!H', packet, 16)[0] - (tcp-14) - 4*(packet[tcp+12]>>4)
        if size <= 0:
            continue
        assert current == flow and origin is not None
        left = (seq-origin)%2**32
        right = left+size
        if t >= lo+offset:
            wire_bytes += size
        if right <= prefix:
            continue
        if left <= prefix:
            prefix = max(prefix, right)
        else:
            i = bisect.bisect_left(above, (left,))
            if i and above[i-1][1] >= left:
                i -= 1
            while i < len(above) and above[i][0] <= right:
                l, h = above.pop(i)
                left, right = min(left,l), max(right,h)
            above.insert(i, (left,right))
        while above and above[0][0] <= prefix:
            prefix = max(prefix, above.pop(0)[1])
    snapshots.append((prefix, sum(b-a for a,b in above)))
    assert len(snapshots)==2
    goodput_bytes=at(received, hi)-at(received, lo)
    factor=8e3/(hi-lo)
    return dict(run=path.name, reuse_key=meta['reuse_key'], receiver_accept_ns=r, sender_start_ns=a,
                window_lo_ns=lo,window_hi_ns=hi,window_s=(hi-lo)/1e9,
                wire_payload_bytes=wire_bytes,wire_payload_mbit_s=wire_bytes*factor,
                contiguous_advance_bytes=snapshots[1][0]-snapshots[0][0],
                contiguous_advance_mbit_s=(snapshots[1][0]-snapshots[0][0])*factor,
                above_hole_bytes_at_start=snapshots[0][1],above_hole_bytes_at_end=snapshots[1][1],
                receiver_interpolated_bytes=goodput_bytes,receiver_goodput_mbit_s=goodput_bytes*factor)

base=Path(sys.argv[1])
print(json.dumps([run(base/('100-100-0-2-cubic-r3-'+side)) for side in ['utcp','linux']],indent=2))
