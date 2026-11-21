# Per-path userspace TCP core heap measurements

Production baseline `069e56f915a4f94b7c7b824446c05df1c85889fb` and candidate
`b463268e4251f2869e3b8072b13f30783e15fbfb` ran the same 16 public-interface workloads,
plus an internal SACK and RACK queue workload. The candidate recorded **zero allocation
requests in both consecutive 128-round steady epochs on every measured path**. Two
ordinary bulk epochs each sent and received 2,359,296 application bytes. The first
emitted 2,584 datagrams and the second 2,496. Every payload byte was compared to its
expected stream position. Every emitted descriptor, delivered datagram, offload flag,
virtual timestamp, socket event, per-method denominator and trace-kind count matched
between versions. The new dedicated trace events were enabled in the counting-sink arm.

[Per-method results](paths.csv) include both trace arms and every nonempty measured
window. [Window totals](windows.csv) include creation, first burst, warm-up, both
steady epochs and teardown. An ordinary bulk candidate used 43 allocations at
creation, 37 in its first burst, 17 over the next 32 warm-up bursts, and 15 during
teardown. Its two stable sends previously incurred 72 allocations apiece.

| Workload | Stable baseline A / B | Stable candidate A / B |
| --- | ---: | ---: |
| Duplex 64-byte echo, both directions | 12 / 12 | 0 / 0 |
| Ordinary bulk, GSO, exhausted GSO-pool fallback (each) | 72 / 72 | 0 / 0 |
| Two-descriptor TX queue or two-buffer packet pool (each) | 77 / 77 | 0 / 0 |
| Two-chunk send/receive budget | 239 / 238 | 0 / 0 |
| Two waiting connections, FIFO wake and retry | 302 / 303 | 0 / 0 |
| Reordering / loss | 83 / 80 and 83 / 85 | 0 / 0 |
| Duplicate delivery | 72 / 72 | 0 / 0 |
| PMTU reduction and cache expiry | 90 / 109 | 0 / 0 |
| Delayed ACK / loss recovered by transmit timers | 6 / 6 and 7 / 7 | 0 / 0 |
| UDP / ICMP echo | 0 / 0 | 0 / 0 |
| Internal partial-SACK, FIFO drain and PMTU splits | 2,438 / 2,438 | 0 / 0 |

## Allocation sites and fixes

* All 72 ordinary bulk requests in the first epoch came from `SentFifo::on_transmit`.
  Replacing the block deque with a vector and a consumed prefix retains the actual
  per-connection high-water allocation. The FIFO reclaims dead entries before growth
  and amortizes compaction. RACK PMTU rebuild sorts by time and unique segment offset.
* The chunk-pressure epoch had 160 calls from `TcpEngine::wait_for_chunks` plus
  79 from RACK. The wake loop now keeps the vector's storage after posting its events.
  The three-connection control verified that both refused writers received their
  event in FIFO order and successfully transmitted their correct bytes on retry.
* Following 128 complete SACK drains, 1,152 partial-SACK allocations came from
  rebuilding the lazy owner (128) and interval nodes (1,024). The map now recycles
  extracted nodes and retains its established capacity through ACK drains and
  reneging. The closed-connection purge releases the owner. The byte-level oracle
  verified uncovered payload after each change and each duplicate advertisement.
* The combined PMTU split and RACK rebuild had 896 independent requests per epoch.
  The prior split vector allocated 256 times, rebuilding FIFO blocks allocated
  512 times, and stable sort requested scratch 128 times. The send queue expands
  in place from the tail while preserving its forward ID assignment and FIN placement.
  The old ordinary SACK microprobe gave identical results on both revisions, including
  two calls on the first partial interval and one on the second.
* The intermediate vector candidate retained two growth calls in the first stable
  small-echo epoch. Reclaiming dead transmissions before growth removed both. An
  earlier PMTU workload fired the cache timer for the **first time** after the last
  stable transfer and counted one `DueTimerRunner::run` vector growth, on both
  products. Its raw results remain available. The final workload caused ten genuine
  descending PMTU updates and ten expiries, exercising first firing at the start
  and repeatedly reusing the same timer slot in the steady windows.

Across a full counting-sink run, ordinary scenarios exercised 37 RTO firings, 289
delayed-ACK firings, 578 blocked-writer calls in the two-waiter control, 465 observed
TX-backpressure iterations in the two-buffer case, 37 reordered packets, 37
duplicated packets, and 37 data drops in the recovery control. The separate timer
scenario dropped 74 transmissions. The GSO fallback arm emitted 290 aggregates
and 2,426 subsequent full-MSS ordinary datagrams in the same drain batches with
only one large buffer. Offload metadata was passed back to the receive core.

## Scope, controls and regression checks

The Linux/glibc LP64 probe brackets one public API call on one thread at a time.
The raw CSV records all eight replaceable C++ allocation forms and nine public glibc
allocation entry points. Nested delegations are recorded in `entries`; `outer` counts
each outermost request once. Individual controls covered every entry, empty windows
and deletion. The independent C executable directly called nine ELF allocator
symbols. It observed two realloc entries because glibc's reallocarray called realloc
internally, with one top-level request for each API. Both final core archives'
undefined heap symbols and the linked probe symbol tables are archived. Hidden
libc bookkeeping, kernel allocation, and other threads are outside this measurement.
A second pass collected call stacks and matched the count-only pass for every
raw allocation count and each wire/event artifact. `sites.py` reconciled every
outer call to the fixed-capacity stack inventory before symbolization.

The event loop, wall clock, JSON telemetry, physical TUN, multiqueue, real recording,
10k-socket RSS and application staging belong to the separate whole-process
campaign. This deterministic echo driver verifies core calls in both directions.
It does not implement the application's staged/direct toggle. Handshake, delayed ACK,
peer recovery, pool/queue release and PMTU activity ran through public calls; the
fine-grained partial-SACK byte coverage and multi-split queue exercise used the
production queue directly.

| Size on GCC 15 x86-64 (bytes) | Baseline | Candidate |
| --- | ---: | ---: |
| Tcb | 1,016 | 1,016 |
| StreamState | 1,064 | 1,016 |
| SentFifo | 80 | 32 |
| SendQueue | 216 | 216 |
| StackImpl | 4,968 | 4,968 |
| TraceEvent | 216 | 216 |

GCC 15 Release and Clang 21 ASan/UBSan each passed 171 selected ordinary protocol
tests across 21 suites, including the dedicated sender trace and its previous
flight-byte consumer. These checks ran on E-cores at nice 10. This diagnostic
contains no CPU-throughput or latency comparison.

## Replay and evidence

Use Linux x86-64, GCC 15, glibc, Ninja and CMake. For each frozen production tree,
copy only `testbed/m4/core_alloc/` from this report's checkout into the tree.
The deployed core used GCC Release optimization, line information and frame pointers.
Run from each tree's root, assigning fresh output directories.

```sh
taskset -c 16-21 nice -n 10 bash testbed/m4/core_alloc/build.sh build/core-heap
taskset -c 16 nice -n 10 python3 testbed/m4/core_alloc/run_matrix.py build/core-heap /tmp/core-heap-baseline
taskset -c 16 nice -n 10 python3 testbed/m4/core_alloc/sites.py /tmp/core-heap-baseline build/core-heap > /tmp/base-sites.csv
```

Use `/tmp/core-heap-candidate` for the candidate. Compare using
`python3 testbed/m4/core_alloc/report.py /tmp/core-heap-candidate --compare /tmp/core-heap-baseline`.
Source harness `aad32d4a4d618b89317eaa311a437f8b9223db50` used the frozen static
core archives and was relinked for the expanded workloads. [Baseline binary
hashes](base-final-binaries.sha256) and [candidate binary hashes](fix-final-binaries.sha256)
cover the actual archive, driver, sink/allocator probe, controls and legacy microprobe.

Private Docker volume `utcp-data:/m4-core-allocation-n22/20261122-dev-final-v2/`
contains the following archives. The final archive was extracted from the volume,
and both raw SHA256SUMS manifests were reverified file by file.

| Artifact | SHA-256 |
| --- | --- |
| final.tar.gz — both complete final runs and measured binaries | `2e86a19f854c2a77c28d922011ec225b1cc2c3052a41183171eea32ab83ce7f3` |
| history.tar.gz — prior successes, failures and attribution results | `9a832b4e3f9dadc40dddf662e0563c187f32cb6e66e3c31389fd3344e928632a` |
| verification.tar.gz — GCC/Clang checks and size probes | `5917c3d88d03dbb92a3f92187ac9338d4e5a4a27f9442589d6c6800a0a0ed5ef` |
| Baseline final SHA256SUMS | `ef88c2989dec802467fd3341acd711aa5a574ceb4fe946bb5f0a1ef1ac95a780` |
| Candidate final SHA256SUMS | `c2cf44fba9f70eef33f8ed54ee2ec466f1e71dbd9d898e790996639c24807aaf` |
