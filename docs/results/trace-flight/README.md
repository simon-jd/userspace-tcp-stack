# Payload bytes in flight

`TraceEvent::in_flight_bytes` counts unique sent payload lacking a cumulative ACK or an accepted SACK. The original `in_flight` field remains in packets. DESIGN §10.2 defines the sampling time of each event and the treatment of partial ACKs, SACK reneging and retransmissions.

## Local Linux capture

Two ordinary transfers sent 1,048,613 bytes from the userspace stack to a stock Linux TCP receiver on an isolated TUN. Each side reported SHA-256 `7ca5890e0b72aea25b3fc98f9d1740526b39b2b0360f53593689df759dddea9c`. The initial sequence was chosen to cross zero during the first data segment. The second transfer dropped one initial data segment at TUN ingress and passed its retransmission.

| Case | TCP packets per capture | TX | RX | Accepted ACK | State | SACK blocks | Retransmitted segments | Peak payload bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Clean | 1,121 | 734 | 387 | 386 | 5 | 0 | 0 | 496,832 |
| One loss | 1,087 | 729 | 358 | 357 | 5 | 8 | 1 | 53,576 |

The stack's TUN recorder and tcpdump at the Linux interface matched in each direction on sequence, acknowledgment, flags, payload length and SACK blocks. The verifier maps TX and RX trace events to those wire records and reconstructs the expected byte count for every TX, RX, accepted ACK and state event. Both rows had zero mismatches and tcpdump reported zero capture drops. Peak packet flight in the clean run was 345. The captures exercised the legacy TUN path.

The existing `tools/m2/plot.py::trace_marks` consumer read a 1,691-line real trace generated with baseline `15d2f1bbdbc5c0d19a004cd59c56e48bc6c5d7ca`. Those records omitted the new key. The same consumer read all 1,903 clean and 1,806 loss records from the updated binary. It found two retransmission marks in the baseline run, zero in the updated clean run and one in the updated loss run.

Reproduce from the repository root using the existing local testbed image and a GCC release build of `utcp-bulk`. Kernel scheduling can change the number of ACKs. Each container has its own network namespace.

```sh
out=$(mktemp -d)
recipe="$PWD/docs/results/trace-flight"
for case_name in clean loss; do
  mkdir "$out/$case_name"
  docker run --rm --network none --cpuset-cpus=28-31 --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$PWD/build/gcc-release/apps/utcp-bulk/utcp-bulk:/bin/utcp-bulk:ro" \
    -v "$recipe/capture.sh:/verify.sh:ro" -v "$out/$case_name:/out" \
    utcp-testbed:dev nice -n 10 bash /verify.sh "$case_name"
  python3 "$recipe/check.py" "$out/$case_name"
done
```

## Cost and coverage

The sender tracks the union of valid SACK byte intervals in the same pass that tags complete transmitted segments. With R disjoint ranges, a block costs O(log R + K) for K erased neighbors. Prefix cleanup costs O(1 + K) for K discarded ranges. Each stored range can be erased once, and each contains at least one still-outstanding payload byte separated from its neighbor by at least one byte. No-SACK connections allocate no range storage. The last cumulative ACK that clears the ranges releases the storage. Snapshot reads take O(1) with any trace mask. On x86-64 GCC 15 both builds measured 216 bytes for SendQueue, 2,208 for Tcb, and 192 for TraceEvent.

A single E-core diagnostic measured the median of seven sets of five million reads. It isolates the field lookup. JSON formatting and throughput are outside that measurement.

| Queued segments | ns/read, no SACK | ns/read, one SACK range |
|---:|---:|---:|
| 16 | 1.46 | 1.18 |
| 1,024 | 1.42 | 1.17 |
| 16,384 | 1.40 | 1.18 |

```sh
g++-15 -O3 -std=c++23 -Iinclude -Isrc docs/results/trace-flight/readcost.cpp \
  build/gcc-release/src/core/libutcp_core.a -o "$out/readcost"
taskset -c 31 nice -n 10 "$out/readcost"
```

GCC release and Clang ASan/UBSan each passed 37 selected cases covering queue accounting, wrap, FIN, ACK/SACK timing, retransmission, reneging and JSON keys. The scripted peer tests also cover a partially SACKed transmit segment, overlapping and repeated blocks, and attaching a sink with earlier SACK coverage still outstanding.

Dedicated cwnd-change, RTT-update and recovery-transition publishers remain separate observability work. The CPU 8–15 throughput campaign and the integrated 10,000-connection memory measurement are outside this field-level verification.
