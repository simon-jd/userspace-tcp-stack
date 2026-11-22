# Production Linux application allocation measurements

The final userspace endpoint made zero counted allocation calls in each measured legacy bulk send, bulk receive, staged echo server, direct echo server and rate-limited echo client window. All five ran periodic JSON reporting. Recorder growth, new transport high-water marks, startup and shutdown have separate positive costs. The experiment measures allocation requests on one Linux/glibc build. It does not measure kernel allocation, copied bytes, or application throughput changes.

The [preregistered protocol](protocol.md) names the production baseline, 069e56f915a4f94b7c7b824446c05df1c85889fb. The developer live-network comparison used 79ae0a64f0f4d1aa8c181b21523d4a032a944127, including core b463268e4251f2869e3b8072b13f30783e15fbfb. The integration parent at a14886b8e0fb2f589241c2d92d2fbb6bc2d0e7c9 includes the [finished core evidence](../m4-core-alloc/README.md) at 7940a289199a9d666edc4a9dd7554999eb9b7365. Git comparison against the measured source is empty for apps, src, include, the CMake build configuration and the primary allocation counter. [Run index and measured call sites](measurements.json).

An independent run of 79ae0a64 found that a later, wider echo client report could still grow the reusable string once by 961 B. The final product 9342b2bed89c54861f9e3398a19eabc1eefe2a23 reserves the fixed schema bound before establishing connections when echo load reporting is enabled. The largest report has 26 fields, the longest key is 19 ASCII bytes and decimal values need at most 20 bytes. Reserving 1,120 B per reporting process covers the punctuation and fields. The developer maximum-width fixture replayed both real schemas with UINT64_MAX values. Their serialized sizes were 844 and 890 B, each with 0 counted calls. The final bulk ELF matched the live comparison byte for byte. The final echo ELF is e2ff17bd1d039944c7c3a109c850dabf829e03d0a311c9760ed3b4e0c1e5c070. Live numeric tables below retain their original provenance on 79ae0a64.

## Matched live workload

The measured endpoint and Linux TCP peer ran in separate containers on a private routed TUN testbed. CPU 8 ran the measured process, CPU 10 the peer and CPU 12 the collectors. The bulk sender ran for eight seconds with 100 ms application samples, stack statistics and byte-pattern checking. Each echo role used 16 established connections, 288 verified requests per connection, 1,024 bytes per request and a 480 requests/s offer. Echo load reports remained enabled every 500 ms. Every completed bulk trial checked identical peer SHA-256 and transferred byte counts. Each echo trial validated 4,608 requests and 4,718,592 echoed bytes. The standard 10,000-connection check below also used its production hashes and separate application counters.

| Measured userspace role | Original calls / requested B | Final calls / requested B | Verified traffic inside final window |
|---|---:|---:|---|
| Bulk sender | 43,927 / 18,095,359 | 0 / 0 | 698,520–761,236 outgoing data segments, 1,011,089,352–1,101,791,680 B |
| Bulk receiver | 398 / 69,391 | 0 / 0 | 811,684–887,083 incoming data segments, 1,174,997,296–1,284,131,344 B |
| Staged echo server | 149 / 45,741 | 0 / 0 | 1,382 TUN datagrams each way, 1,227,776–1,718,272 echoed B |
| Direct echo server | 160 / 42,618 | 0 / 0 | 1,385 TUN datagrams each way, 1,227,776–1,718,272 echoed B |
| Echo client, Linux echo server | 183 / 54,250 | 0 / 0 | 1,446 TUN datagrams each way, 1,227,776–1,717,248 verified B |

The baseline sender had 34,715 sent-FIFO allocations and 4,408 each in the one-shot callback owner and timer map. The zero-delay continuation comes from the bulk app's 100 µs fairness slice. The receive-side sample formatter and echo reporters repeatedly allocated for escaped keys, numeric values, temporary objects and output. The client retained 47 calls on the first joint candidate, including 11 deque blocks for waiting rate tokens. The final candidate reuses the FIFO and report buffer, preserves the previous report interface and keeps creation-order timer ties and callbacks that cancel themselves. Each test directory stores actual addresses, mapped binaries, symbolized call-site counts and requested bytes.

### Startup, cold traffic and close

The cold snapshot happens after exec with a live process, before the measured connection starts. It includes loader/startup and any activity completed before the observer. The earliest active snapshot includes establishment, cold traffic, first JSON buffers and capacity growth. A bulk post-window delta includes the remainder of the transfer and close. The echo drained-to-exit interval isolates close and final reporting after the gate. The values below are application-process allocation calls.

| Final role | Cumulative at startup snapshot | Startup snapshot to first active snapshot | Active window | Last active snapshot to exit | Drained to exit |
|---|---:|---:|---:|---:|---:|
| Bulk sender | 145 | 1,118 | 0 | 40 | — |
| Bulk receiver | 142 | 72 | 0 | 35 | — |
| Staged echo | 142 | 211 | 0 | 39 | 35 |
| Direct echo | 143 | 195 | 0 | 41 | 38 |
| Echo client | 223 | 190 | 0 | 68 | 59 |

The [run index](measurements.json) preserves cumulative byte totals, peak RSS, every snapshot and all intermediate candidates. In the standard windows peak endpoint RSS through exit was 18,028 KiB for sending bulk, 13,504 KiB for receiving bulk, 13,248 KiB for staged echo, 13,244 KiB for direct echo and 13,516 KiB for the echo client. The fixed-storage instrument is inside these process readings.

## TCPv4 offload, increasing occupancy and flow control

The final sender reported 180,426 GSO datagrams with 8,114,094 constituent segments. Its fixed window had zero calls. At identical settings the first joint candidate observed 57 calls / 663,808 B in the fixed window. These comprise 52 new 4 KiB pool chunks, one chunk pointer vector expansion, one chunk membership vector expansion, one byte-ring slot expansion and one expansion each for the sent FIFO and send queue. The final receiver reported 252,572 GRO datagrams with 9,612,769 constituent segments. Its fixed window had one 8,192 B allocation to extend the ChunkPool free-ID vector. The comparable baseline send and receive windows reported 129,700 / 55,004,521 B and 31,965 / 1,971,487 B respectively.

One additional final TCPv4 sender ran a single uninterrupted transfer with an external sample each second. A fixed-storage diagnostic observed successful reads/writes of that TUN FD, decoded negotiated TCPv4 GSO, and tracked the largest sent sequence end minus the latest observed cumulative ACK. This wire metric includes bytes awaiting cumulative ACK even when SACKed. Its whole-run aggregate counts matched the production counters, 165,958 GSO datagrams and 7,461,482 segments. The retained chunk count uses the symbolized 4,096-byte array-new site in ChunkPool, which retains all allocated chunks. The source checks for ambiguous sites. Exact maxima are grouped by monotonic clock second. Counter snapshots have their own timestamps near those boundaries. The complete adjacent series follows, including mixed and post-traffic windows.

| Interval in order | Calls / requested B | Retained 4 KiB chunks, start → end | GSO datagrams | GSO segments |
|---:|---:|---:|---:|---:|
| 1 | 2 / 425,984 | 1,025 → 1,025 | 20,055 | 901,418 |
| 2 | 0 / 0 | 1,025 → 1,025 | 22,728 | 1,022,418 |
| 3 | 0 / 0 | 1,025 → 1,025 | 21,615 | 971,166 |
| 4 | 0 / 0 | 1,025 → 1,025 | 17,619 | 792,855 |
| 5 | 0 / 0 | 1,025 → 1,025 | 17,233 | 775,485 |
| 6 | 0 / 0 | 1,025 → 1,025 | 22,384 | 1,007,280 |
| 7 | 0 / 0 | 1,025 → 1,025 | 22,476 | 1,011,420 |
| 8 | 7 / 8,370 | 1,025 → 1,025 | 2,452 | 110,340 |
| 9 | 0 / 0 | 1,025 → 1,025 | 0 | 0 |
| 10 | 38 / 25,880 | 1,025 → 1,025 | 0 | 0 |

The observed maximum outstanding reached 4,193,520 payload bytes. The first interval grew the sent FIFO by 98,304 B and send-queue storage by 327,680 B. The eighth includes closing and the tenth includes final stats JSON and libc file I/O. Full symbols and clock-second maxima are in the index. This single-flow occupancy diagnostic adds instrumentation and provides no rate comparison.

A two-queue direct echo retained all 16 verified flows. It recorded RX datagrams of 2,352 / 2,352 and TX datagrams of 2,640 / 2,640 on the two descriptors. TCPv4 was active with single-datagram output for this small request size. No exhausted GSO-pool branch is inferred. The real paused Linux receiver used a 128 KiB socket receive buffer and stopped reading for 120 ms per MiB. The userspace sender recorded 8,070,174 µs limited by the receive window. Its window transferred 18,902,192 B across 13,054 data segments with 0 calls, and the endpoints agreed on the digest. A separate narrowed real TUN send-buffer trial verified TUNSETSNDBUF/TUNGETSNDBUF at 4,096 B and added 3 ms egress delay. It observed zero device-write EAGAIN.

The isolated production-handler check reused tests/interop/backend_transport_check.cpp and AF_UNIX SOCK_SEQPACKET descriptor pairs. Bounded fixed-storage snapshots surrounded each call to the original production drain_tx body. The full queue returned EAGAIN twice with zero allocations, then the original descriptor accepted the pending TCP datagram once with zero allocations on each revision. The peer checked all 28 payload bytes, its sequence and port, no duplicates and no traffic on the wrong queue. FIN processing and the UDP queue-0 fallback passed. The full first application send, which also opens stream storage, cost 8 calls / 5,840 B originally and 6 calls / 5,224 B on the combined core. The peer's vector construction and parsing were outside the instrumented drain intervals. [Probe builder](../../../testbed/m4/app_alloc/fd_probe.py).

## Production trace retention and final output

Trace capture used the production 64 MiB initial reservation, a live 800 Mbit/s configured sender and all TX events. Bulk sampled normally. Original live output contained 541,808 events in two blocks and 326,022,721 JSONL bytes. The final run contained 532,555 events in two blocks and 319,201,664 bytes. Each file was read to EOF, every row parsed as a TX event, all timestamps checked in order and the row count matched the production recorder. The final live formatting phase made 8 allocations / 6,464 B from entry to the trace file open through close. The baseline made 4,334,472 / 1,097,814,195 B. The fixed live window of the final trace arm contained 28 allocations / 105,504 B from 25 new 4 KiB payload chunks and three ring/pool metadata expansions. That run reached 126,280 KiB peak RSS.

A deterministic production-class fixture independently measured both revisions at the exact block boundary and compared the complete files byte for byte. With a 216 B event, one 64 MiB reservation holds 310,689 events. No output file existed after 310,700 events until explicit shutdown formatting. Both 310,700-line files had SHA-256 f343fe6b8299feac5c114a6cf067969d1229f4181d97cc614852fc569c27d3e9.

| Recorder interval | Baseline calls / requested B | Final calls / requested B |
|---|---:|---:|
| Construction, first block and block directory | 2 / 67,108,848 | 2 / 67,108,848 |
| Fill first block | 0 / 0 | 0 / 0 |
| First event in second block | 2 / 67,108,872 | 2 / 67,108,872 |
| Next ten events | 0 / 0 | 0 / 0 |
| Format and write all events | 2,174,907 / 523,489,869 | 8 / 6,464 |

The retained files and phase logs are under utcp-data:/m4-app-alloc/recorder-20261121T235100Z. The [core report](../m4-core-alloc/README.md) covers the trace-off and count-only paths in isolation.

## Standard memory and content regression

A clean uninstrumented timing arm on CPUs 8/10/12 held 10,000 established connections, used five 64 B requests per connection at the configured 5,000 requests/s offer and verified all 50,000 responses, 3,200,000 bytes, with zero mismatches or errors. Idle stream states were zero. All three active samples had 10,000 stream states. The TCB and stream-state layouts were each 1,016 B. Idle process RSS was 28,774,400 B with 1,542.144 incremental B/connection. All three active samples reached 41,984,000 B, 2,863.104 incremental B/connection. Workload RSS HWM was 41,984,000 B. Raw results are in utcp-data:/m4-echo-load/20261121T235011Z-cd6408b7.

## Counting scope and replay

The glibc diagnostic counts successful public malloc, calloc, realloc, reallocarray, aligned allocation APIs and the replaceable C++ scalar/array, aligned and nothrow forms. Realloc records its requested size even when it can reuse the same address. The C++ replacement calls the glibc backend directly and records the outer request once. The mixed positive control observed exactly seven calls and 465 requested B including both API families, aligned, zero-size and realloc calls. The extended public C and eight C++ overload controls observed 14 calls and 241 requested B. An empty interval returned 0/0. The instrument maintains fixed storage from early process initialization, publishes it with a sequence counter and admits the single-threaded benchmark endpoints. Observing, mapping/symbolizing and JSON analysis run outside the measured application. The diagnostic's own shared mmap is excluded. Kernel allocation, raw mmap interfaces and internal allocation APIs that bypass dynamic interposition are outside the count. Per-process RSS supplies a separate physical-memory observation. In inherited raw files the historical field called cpp_new carries all counted outer calls for these runs.

Build the normal release utcp-bulk and utcp-echo targets. Build testbed/m4/app_alloc/counter.cpp as a C++23 optimized shared object under build/app-alloc.so, with -fPIC -shared -ldl. Compile control.cpp at -O0 -fno-builtin and run it with that DSO preloaded. Run run.py with send, receive, staged or direct and --source FULL_SHA. The additional arms use --trace, --offload tcpv4, --queues 2, --paused-peer and --series. The latter uses wire.cpp as build/app-wire.so. The controlled kernel send-buffer test uses --pressure and pressure.cpp as build/app-pressure.so. client.py measures the reverse endpoint role. run.json in every successful directory records process sources, binary hashes, image, CPU placement and arguments. The measured counter ELF SHA-256 is 263870575a23ef75be5ddc8e8319c8fb594c88c0ddcbb8600bbc8fcd23003bb0.

The sealed evidence directory is utcp-data:/m4-app-alloc/archive-20261122-9342b2be. Its RAW.sha256 indexes 901 files in 32 original directories. ARCHIVE.sha256 covers the run index, frozen binaries, source snapshots, controls, fixed-storage diagnostic tools and standalone verification output. Both manifests were rechecked from a separate read-only volume mount. The original bulk and echo server binaries were rebuilt from 069e56f using a source-path prefix map and their ELF hashes matched the original running-process SHA-256 values exactly. The reverse client baseline, combined 79ae echo and final 9342 echo are frozen separately. [Archive receipt](archive-receipt.txt).
