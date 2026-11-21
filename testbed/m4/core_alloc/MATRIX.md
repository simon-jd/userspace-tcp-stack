# Core allocation preregistration

Measure only after the independently accepted trace revision and the shared CPU slot are released. Record its full object ID, source status, compiler/version, full flags and SHA-256 of driver, probe, archive and raw output. The same harness source must run on both exact code revisions. Use a fresh private directory per attempt. Preserve partial runs, diagnostics, stdout/stderr and failed oracles.

## Counter controls

Measure all eight replaceable allocation functions provided by libstdc++ and nine exported glibc entries (malloc, calloc, realloc, aligned_alloc, posix_memalign, memalign, valloc, pvalloc and reallocarray). Report every family entry, including delegation. Count each outermost request once. Deallocations and an empty bracket must produce zero. Exercise each individual function with an explicit dynamic symbol lookup and a live returned pointer, before and inside a control window. Record per-entry results. Use an independent raw C-only window and call site pass; verify stripped attribution is reported as unknown. For quoted zero core paths, check the actual linked archive's undefined symbols and soname/loader bindings. Internal libc calls with hidden visibility, allocator-internal bookkeeping, direct mmap and kernel resources are outside exported-entry accounting.

## Workloads and denominators

Use two endpoints and a deterministic virtual clock, with a counter around only one public method (including packet release) at a time. Assign every run a fixed setup/first/warm and two equal, consecutive steady epochs, plus close. All nonzero counts remain in the CSV. Core geometry and bounded traffic high-water marks are measured; no production global maximum reservation is permitted. Test bootstrapping, repeated complete drains, and a larger burst followed by a repeated burst of the same size. Check data bytes, socket event order, complete ordered datagrams and metadata outside each measurement window. Compare exact transcript hashes when changing solely instrumentation or production allocation behavior. Record per-method calls, core TX objects, IPv4/TCP payload and logical segments. Valid repeated sends and receives must verify all application bytes.

| Workload | Required evidence |
| --- | --- |
| Ordinary sender, receiver and small bidirectional echo | Public send/recv, data receive, pure ACK receive, event poll, pop/release, deadline, timer advance and readiness/info; fixed byte pattern verified and bytes acknowledged, no silent input errors. |
| Positive cadence, idle zero-work and forced deadline | Pending delayed ACK vs fired timer, explicit timer oracles and count. |
| Offload and fallback | Equal payload delivery with TCPv4 GSO metadata on/off; count GSO objects, logical data segments, ordinary frames; bound large buffers, exercise fallback, verify both branches actually hit. |
| Reorder/duplicate and retransmission | Ordinary one-packet delay/one loss; verify application bytes, positive duplicate/rx-reorder or retransmit counters and final ACK. |
| Partial SACK | Repeated clipping and growing block in a segment, across segments and across multiple full queue drains. Track uncovered bytes independently, distinguish first interval allocation and repeated reuse. |
| Transmit queue/pool and chunk waiters | Fixed small queue and one/few chunks; prove blocked/would-block, recovery after resources return, writable delivery and eventual exact application bytes. One and multiple eligible sockets if possible. |
| UDP/ICMP/PMTU | Repeat normal datagrams/echo, check payload/source and ICMP id/seq; trusted ordinary PMTU notification, resegmentation/retransmission and cache expiry. |
| Trace arms | Disabled and allocation-free counting sink with the new event kinds selected; compare packet/event transcript, preserve sink call counts. Real recorder growth/flush and Linux applications are separate assigned runs. |
| Memory/regression | Structure measurements, RSS10k, deterministic ordering, old trace consumer and existing protocol tests on the final candidate. Correlate changes with true baseline path/allocator stacks before changing production. |

Current source inspection identifies deque growth, queue reconstruction and waiters as hypotheses. Only a positive allocation stack attributed to that path is a root cause. Full process totals, application sampling/recording and physical multiqueue/offload are owned by the parallel application campaign. Report each missing or incomplete cell.
