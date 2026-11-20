# M4 single-queue echo and memory

The runner measures one server backend per invocation. The peer runs
`utcp-echo --backend kernel` in both arms. Both use CUBIC, TCP_NODELAY,
the same seeded request bytes and the same IPv4 destination. The two
containers share a private bridge, with the route to the destination
through the server namespace. The userspace arm forwards packets through
one TUN queue pair. The Linux control owns the destination address
locally and terminates TCP in that namespace.

The runner opens at most 32 outstanding handshakes at a time by default.
Both endpoint applications must report the target live population before
the idle hold. The client namespace independently counts distinct
established TCP tuples for the exact destination. The Linux server arm
matches the normalized tuple digest independently from its namespace.
The userspace server counts connections accepted after the handshake and
reports one core TCP slot per live connection plus its listener.
The runner checks both populations at either end of the idle interval
and again after the last verified reply, before permitting either side
to close. There must be zero errors and zero payload bytes before the
active gate. The tuple digest must remain unchanged through the hold and
workload within each run.

The default workload has 10,000 established connections, at least five
seconds all idle, and five 64-byte requests per connection. The client
starts up to 5,000 requests per second across connections using the
existing measured-time token refill, with at most one request outstanding
per connection. The measured interval runs from activation to the last
verified reply. It includes any active scheduling delay but excludes
opening, idle hold and close. Latency is from each request start to its
last verified echo byte and does not include time waiting for a rate token.
The result records actual started and verified request counts, achieved
rate, bytes, sample count and the client's log-linear p50/p99 estimates.
The server's echoed bytes must equal the client's verified bytes.

## Run

Build from the exact checkout on the Ubuntu build CPUs:

```sh
taskset -c 24-27 nice -n 10 cmake --preset gcc-release
taskset -c 24-27 nice -n 10 cmake --build --preset gcc-release -j4
```

The testbed image and `utcp-data` Docker volume must already exist.
The image ID, source SHA, process executable SHA-256, arguments,
requested CPU affinities, actual process limits and network readbacks
are saved with each arm. The binary must be within the same checkout.
The default bridge subnet is `198.19.85.0/24`. Use `--net-base` if
the subnet is occupied. The runner creates named `utcp-m4-echo-*`
containers and its bridge and removes them on exit. It writes no host
sysctls. The isolated testbed needs Docker, NET_ADMIN and /dev/net/tun
for the userspace arm.

An isolated gate regression, including a corrupt reply:

```sh
docker run --rm --name utcp-m4-echo-gate --network none --cpuset-cpus 24-27 \
  -v "$PWD:/utcp:ro" utcp-testbed:dev nice -n 10 python3 \
  /utcp/testbed/m4/echo_gate_test.py /utcp/build/gcc-release/apps/utcp-echo/utcp-echo
```

Small functional runs, repeated with `--backend kernel`:

```sh
taskset -c 26 nice -n 10 python3 testbed/m4/echo_load.py \
  --purpose functional --backend utcp --cpus 24,25,26 \
  --connections 64 --count 10 --rate 128 --hold-s 2
```

A functional 10,000-connection run uses the default workload
parameters with `--purpose functional`. Its evidence can prove
concurrency and payload integrity. Use the following commands on a
clean accepted tree during the allocated timing window for latency and
memory comparisons. The three CPU arguments are the server, client
and collector, in that order.

```sh
taskset -c 12 python3 testbed/m4/echo_load.py \
  --purpose timing --backend kernel --cpus 8,10,12
taskset -c 12 python3 testbed/m4/echo_load.py \
  --purpose timing --backend utcp --offload legacy --cpus 8,10,12
```

For the accepted single-queue offload configuration, run the second
command with its matching `--offload checksum` or `--offload tcpv4`.
The runner precreates TUN with `vnet_hdr` when requested and checks the
negotiated mode in the emitted stack counters. Hold the binary, flags
and workload fixed when comparing two modes in one tree. For a
before/after source comparison, run the same echo workload on the
pre-optimization tree carrying this echo instrumentation and then the
accepted optimized tree. Each result retains its distinct SHA and
binary digest. A 64-byte echo workload need not exercise TCPv4
segmentation or aggregation.

## Memory scope

- Server and client `smaps_rollup` give process RSS and PSS. The
  subtractable baseline is the started server with its listener and the
  client before opening. The idle-end snapshot and three overlapping
  active snapshot windows give total and baseline-delta bytes and
  baseline-delta bytes per established connection, by process. The
  active sample times are checked against client workload boundaries.
- The userspace server reports the compiled `sizeof(Tcb)`, live slots,
  packet pool slots, free pool slots, chunk size, allocated and free
  chunks and queued packets. These are object and pool sizes, and
  omit allocator metadata and container costs. The pool keeps freed
  chunks for reuse. The object size alone does not account for any
  heap allocations owned by a TCB.
- The 1 KiB TCB target is checked directly. The 2 KiB idle and 12 KiB
  active targets are checked against baseline-subtracted server RSS
  divided by the live accepted population. The 128 MiB aggregate
  target is checked separately against active server RSS and its
  process `VmHWM` through the last verified reply. The process high
  water mark includes opening and instrumentation. The runner
  reports target outcomes even when they miss.
- The Linux endpoints' container cgroup v2 reports current, anonymous,
  kernel, socket and slab bytes. Cgroup socket memory covers accounted
  network buffers. Kernel and slab include other in-container work,
  such as the collector, and some accounting scopes overlap.
  Keep the values alongside process RSS/PSS. Avoid adding overlapping
  fields into an estimated socket total. [Linux cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files).
- Each endpoint saves `/proc/net/sockstat{,6}`. IPv4 TCP `inuse` and
  `tw` are per namespace, while TCP `orphan`, `alloc` and `mem`
  can include the host. The latter's page size is recorded. Selected
  TCP slab cache rows from `/proc/slabinfo` are host-global context.
  The targeted TCP tuple count and queue payload lengths are
  namespace-local. Neither describes the full resident size of the
  kernel's per-socket metadata. [Linux IPv4 proc accounting](https://github.com/torvalds/linux/blob/v7.0/net/ipv4/proc.c).
- Sampling runs on a separate CPU and is included in the measured
  workloads. PSS depends on shared mappings across the host and
  cgroup counters can fluctuate or lag. Preserve negative deltas.
  Record concurrent activity on the pinned timing CPUs from the saved
  CPU state if observed.

## Evidence and failure cases

Output lives under `utcp-data:/m4-echo-load/<run-id>` with `run.json`,
`runtime.json`, per-endpoint commands, logs and memory snapshots,
and either `result.json` or `failure.json` once the evidence directory
exists. Kernel listener `ss` Send-Q, SYN backlog, requested userspace
backlog, local port range and reservations, effective nofile limits,
MTU, TUN queue count and readbacks are preserved. A backlog or port
shortage fails while both endpoints are still at baseline. An opener
timeout, early close, pre-gate traffic, stale or incorrect counts, loss
of the full population, a mismatched echo, or a missing sample within
the active interval prevents a successful result. Check endpoint stderr
and the final telemetry for failed runs. The runner preserves evidence
already written if a later gate fails.

The [legacy single-queue baseline](pre-copy.md) records the five paired timing runs.
