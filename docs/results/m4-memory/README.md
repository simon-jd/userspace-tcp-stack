# TCP memory at 10,000 established connections

Five paired Linux runs on 2026-11-21 compared source `15d2f1bbdbc5c0d19a004cd59c56e48bc6c5d7ca` with `b749be2a4d6355e301e482e06e0aecaf97814774`. Every pair saved 1,792 bytes of idle server RSS per established connection, or 17,920,000 bytes across the 10,000 connections. Each run verified all 50,000 replies and 3,200,000 bytes with zero errors and mismatches.

| Metric | Baseline | Candidate | Original limit |
| --- | ---: | ---: | ---: |
| GCC release `sizeof(Tcb)` | 2,208 B | 1,016 B | 1,024 B |
| GCC release `sizeof(TimeWaitEntry)` | 64 B | 64 B | 64 B |
| Idle RSS increase per connection, median | 3,334.144 B | 1,542.144 B | 2,048 B |
| Largest active sample per connection, median of trials | 4,113.2032 B | 3,983.3600 B | 12,288 B |
| Process VmHWM through drain, median of trials | 54,624,256 B | 53,264,384 B | 134,217,728 B |

The highest observed candidate active delta was 3,990.7328 B per connection. The highest candidate VmHWM was 53,317,632 B (50.85 MiB). Each candidate run met every memory limit. Per-trial data and the raw run identifiers are in [pairs.csv](pairs.csv).

## Where the bytes went

An untouched socket keeps its negotiated parameters, RTT, ACK/window policy, algorithm-specific congestion model and statistics. The handshake initializes the selected congestion algorithm at its original time. Until further ACK processing or stream traffic, the TCB retains the resulting congestion window, slow-start threshold, pacing rate and pacing requirement. A listener alone owns its accept queue.

Stream queues, retransmission/recovery state, working congestion-control fields and stream accounting are materialized when needed. The additional stream object is 1,064 B on this ABI. Each candidate run reported zero stream objects across 10,001 TCP slots after the idle hold, and 10,000 stream objects once all connections exchanged data. A connection with a materialized stream therefore has 2,080 B of fixed TCB and stream structures. Dynamic queue storage, allocator metadata, timers, application state, pools and other resident pages contribute to the process RSS measurements. The TIME_WAIT figure describes one table entry. Its index and timers also use memory.

## Measurement

The registered schedule was baseline/candidate, candidate/baseline, baseline/candidate, candidate/baseline, baseline/candidate. The first baseline preceded development and the four later baseline trials ran interleaved with the candidate. Both arms used the existing [echo workload and gates](../m4-echo-load/README.md), legacy single-queue TUN, CUBIC, TCP_NODELAY, backlog 4,096, 32 outstanding handshakes, 10,000 live connections, five 64-byte requests each, and a target rate of 5,000 requests/s. The sender, peer and collector ran on CPUs 8, 10 and 12. All holds exceeded five seconds. Each trial independently checked the full connection population at both ends throughout the idle interval and after the final reply.

RSS is the server process's `smaps_rollup` delta from the started server with the listener open, divided by 10,000. Each trial's active value uses its largest of three in-workload samples. VmHWM includes startup and opening through the final verified reply. The median paired active delta was −128.2048 B per connection. The largest active sample and VmHWM are separate measurements.

GCC release produced baseline executable SHA-256 `2fce3e7908a8f3b635e8d6464e1108509724d9ba5441751aacaba99855e2bc5b` and candidate executable SHA-256 `1e650f2ecd2ea65d4b6f26e540852b78027810610a4e3e573a5f3e400ddbee22`. The baseline executable supplied the Linux kernel client in every trial. Both arms used image `sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66`. The Ubuntu host was shared. One-minute load averages before runs ranged from 2.37 to 8.28. The recorded placements include other services and concurrent compilation on CPUs 16–23 during part of the series.

Each run retains its command lines, binary hashes, named file snapshots, process placements and raw results in `utcp-data:/m4-memory-n21/<run-id>/`. The method directory in that volume retains registration, the workload launcher, aggregation and regression commands. The echo launcher only selects the evidence directory. Workload and connection gates execute the respective checkout's runner.

## Transfer checks

The release regression selection passed 458 tests, including classic and model BBR, CUBIC, recovery, timers, SACK, reassembly, PMTU, close, bidirectional transfers, sequence wrap and a new first-stream transition test with NewReno, CUBIC and BBR. All 458 also passed under Clang ASan and UBSan with leak detection and immediate failure on sanitizer findings. Both logs and the sanitizer command are in the method directory.

A real Linux curl client received 100,000,000 seeded bytes from the candidate HTTP server over TUN. In the opposite direction the candidate HTTP client received the same 100,000,000 bytes from Python's standard HTTP server. The independent source digest and both received SHA-256 digests were `f5ff9c82d65a614ba56925b10f148f6f2e011e1f4e6766e6cf9f35b477c25d2b`. Raw verification and binary identities are in `utcp-data:/m4-memory-stock-n21/20261121T220752Z-d5a95773/result.json`.
