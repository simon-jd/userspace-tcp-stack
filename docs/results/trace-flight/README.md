# Payload bytes in flight

`TraceEvent::in_flight_bytes` counts unique sent payload lacking a cumulative ACK or an accepted SACK. The original `in_flight` field remains in packets. DESIGN §10.2 defines the sampling time of each event and the treatment of partial ACKs, SACK reneging and retransmissions.

## Integrated runtime on November 21, 2026

An independent run used the default 4 KiB build of
`38f648e462935ca7a448c1e23cc7ac7b1f0ddb58`. A userspace sender and a stock Linux
receiver transferred 451,019 B per run on an isolated legacy TUN. Each endpoint
and the independent payload generator reported SHA-256
`c6bb116a9fd09f0a79fcdd34e399d2f7acfc0dd21a344b6c08cb16ea3e651200`.
The full stack and Linux captures matched in both directions. Both transfers crossed sequence zero.

| Case | TCP packets per capture | TX / RX / accepted ACK / state | Checked snapshots | SACK blocks | Retransmissions | Peak payload in flight |
|---|---:|---|---:|---:|---:|---:|
| Clean | 483 | 317 / 166 / 165 / 5 | 653 | 0 | 0 | 205,160 B |
| One controlled loss | 513 | 317 / 196 / 195 / 5 | 713 | 9 | 1 | 34,752 B |

The independent checker tracked each sent payload byte on the wire. All four
snapshot kinds agreed with it, including the retransmission of 1,448 B that
left 9,144 B outstanding. The older packet-count formula also passed. The plotting
consumer read 1,691 historical events without the new field and all 820 clean and
908 loss events with it. The wire reconstruction excludes timer-internal snapshots.
Dedicated cwnd-change, RTT-update and recovery-transition events remain open.

The Ubuntu report is `~/Desktop/utcp-wt/trace-field-independent-n21.QZeD7uFG/_accept/REPORT.md`
(SHA-256 `ec62bd04edeb19d78b79ca3a609bc1e7c30044b83ddd1202289faedbe7de50fa`).
All 149 checkout inputs to the tested GCC 15 Release binary matched the commit.
The binary's SHA-256 is `6f2531759acd63cd57a5b6b68befaf5f8fb0be64a2ddd433dd8624feb5f91337`.
Raw captures, per-case `clean/oracle.json` and `loss/oracle.json`, the application
receipts and `compatible.jsonl` are at `utcp-data:/trace-field-independent-n21.QZeD7uFG/`.
The 69-entry `SHA256SUMS` has SHA-256
`a9962338368d9287a0011402484941e4d6f4e36eb9811fca4be886dacaa5f701`.

## Local Linux capture

These captures were recorded on the first implementation, commit `6efb1cae93d12b2ed806427bf0bcc0e2e80a2b80`. The offline checks below describe the intermediate memory-and-copy integration.

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

## Memory-and-copy integration

The intermediate trace commit `c991743ddc244d87cc67d8a34b997f4c20eed713` uses
base `fa35221f9f86f3c3b997d839f2bb43d8ec8b305f`. A stream can be absent during handshake or on an idle connection. Those trace snapshots report zero payload without allocating a stream. Once the stream exists, complete SACKed segments use the existing packet scoreboard. One counter holds their total remaining payload. A clipped SACK edge uses a separate ordered set of partial byte ranges. Promoting an edge to a complete segment subtracts any overlapping partial coverage. The send buffer already owns the highest written offset, which the queue now reads directly.

The interval set exists only on connections that have received a partial SACK. In addition to live ranges it retains at most one spare node for a moving edge. Cumulative acknowledgment of all outstanding payload, clearing the scoreboard, and queue purge release the partial storage. An interval operation costs O(log R + K) for R partial ranges and K touched neighbors. Whole-segment-only flows continue to use the existing packet walk and allocate no additional SACK storage. Snapshot reads take O(1) regardless of tracing state.

The allocation test builds 64 ordinary 100-byte segments before counting allocations. A per-byte array independently checks outstanding payload after every ACK. Each version finished with 1,550 bytes outstanding.

| ACK sequence | First implementation | Integrated implementation |
|---|---:|---:|
| First complete SACK | 2 | 0 |
| 30 contiguous complete-segment extensions | 30 | 0 |
| 7 disjoint complete blocks | 7 | 0 |
| First partial range in that flow | 1 | 2 |
| 48 extensions of its right edge | 48 | 0 |
| Extension leaving two separated partial edges | 1 | 1 |
| 899 more extensions across segment boundaries | 899 | 0 |
| 78 repeats | 0 | 0 |

The two initial allocations on the integrated partial path create the optional range container and its first node. A second simultaneously live partial edge needs one more node. The complete path above includes repeated, disjoint, and expanding reports.

| GCC 15 x86-64 layout | Integration base | Trace candidate |
|---|---:|---:|
| Tcb | 1,016 B | 1,016 B |
| StreamState | 1,064 B | 1,064 B |
| SendQueue | 216 B | 216 B |
| RecvBuffer | 152 B | 152 B |
| ByteRing | 88 B | 88 B |
| TxSeg | 80 B | 80 B |
| TraceEvent | 192 B | 192 B |

A single E-core diagnostic measured the median of seven sets of five million field reads. It isolates lookup cost and excludes JSON encoding.

| Queued segments | ns/read, no SACK | ns/read, one complete SACK range |
|---:|---:|---:|
| 16 | 1.48 | 1.48 |
| 1,024 | 1.48 | 1.47 |
| 16,384 | 1.48 | 1.47 |

```sh
out=$(mktemp -d)
for probe in readcost sack_allocations; do
  g++-15 -O3 -std=c++23 -Iinclude -Isrc "docs/results/trace-flight/$probe.cpp" \
    build/gcc-release/src/core/libutcp_core.a -o "$out/$probe"
  taskset -c 23 nice -n 10 "$out/$probe"
done
```

GCC release and Clang ASan/UBSan each passed 58 offline cases in 11 suites. The directed queue and peer tests cover split segments, partial cumulative ACKs, repeated and overlapping SACKs, FIN, wire sequence wrap, retransmission, reneging, JSON keys and the ordering of snapshots. A peer reports both complete and partial coverage before a trace sink is attached. The first RX and next accepted-ACK snapshots preserve both byte ranges.

Dedicated cwnd-change, RTT-update and recovery-transition publishers remain separate observability work. The CPU 8–15 throughput campaign and the integrated 10,000-connection memory measurement are outside this field-level verification.
