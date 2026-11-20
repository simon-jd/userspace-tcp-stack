# M4 single-flow baseline

Five serial 1 GB transfers per arm passed byte and SHA-256 checks in both
directions. The legacy stack achieved a median 3.963 Gbit/s as sender and
4.787 Gbit/s as receiver. The corresponding Linux-to-Linux controls achieved
8.160 and 8.633 Gbit/s. Each stack run was paired with a Linux control at
the same endpoint placement. Stack goodput as a fraction of its paired control
had a median of 48.5% [42.5%, 53.9%] for sending and 50.6% [46.8%, 58.3%]
for receiving.

| Data direction | Backend at DUT | Receiver Gbit/s | Sender user s/GB | Sender system s/GB | Sender total s/GB | Receiver user s/GB | Receiver system s/GB | Receiver total s/GB |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| DUT to peer | Linux | 8.160 [7.643, 9.096] | 0.479 [0.457, 0.498] | 0.337 [0.278, 0.522] | 0.835 [0.755, 0.979] | 0.392 [0.377, 0.411] | 0.290 [0.169, 0.308] | 0.682 [0.568, 0.718] |
| DUT to peer | Stack | 3.963 [3.862, 4.120] | 0.798 [0.790, 0.871] | 1.206 [1.129, 1.249] | 2.025 [1.947, 2.078] | 0.401 [0.380, 0.404] | 0.763 [0.722, 0.819] | 1.165 [1.123, 1.216] |
| Peer to DUT | Linux | 8.633 [8.255, 9.632] | 0.468 [0.414, 0.475] | 0.368 [0.201, 0.526] | 0.839 [0.662, 0.970] | 0.388 [0.371, 0.402] | 0.252 [0.166, 0.338] | 0.633 [0.554, 0.727] |
| Peer to DUT | Stack | 4.787 [3.868, 4.878] | 0.471 [0.469, 0.475] | 0.454 [0.094, 0.521] | 0.923 [0.569, 0.992] | 0.795 [0.779, 0.807] | 0.872 [0.848, 1.270] | 1.675 [1.643, 2.072] |

Each cell reports the median [minimum, maximum]. Total CPU is calculated
per process per run before taking its median. The Linux peer uses the kernel
backend in every arm. Goodput uses the receiver application's interval from
connection establishment to EOF and the receiver-confirmed decimal GB. Linux
wait4 accounts for the application child's full lifetime, including startup,
payload hashing, its own system calls, and close processing. Asynchronous
kernel work can be charged outside the application process. Container cgroup
deltas and host softirq counts remain separate in the receipts and CSV.

The legacy stack reported median TUN RX/TX datagrams per GB of
243,252/692,236 for sending and 690,713/346,114 for receiving. The kernel
controls used no TUN packets. These device counters count successful
datagrams. A syscall-attempt comparison requires a later binary exposing
read and write attempts in both the reference and candidate arms. Source
paths for the software fallback are the TUN drain/flush loops and device
counters in apps/common/utcp_transport.cpp and the payload/hash loops in
apps/utcp-bulk/bulk.cpp. The ordinary process-scoped perf probe on the host
exited 1 with “No supported events found.” Perf 7.0.14 reported access
limited with perf_event_paranoid 4 and effective capabilities zero. The
experiment measured process CPU and software counters. PMU events and sampled
hotspots remain unavailable in this environment.

## Placement and observed noise

The run used the private same-host Docker bridge on 198.19.220.0/24,
DUT 198.19.220.2 at CPU 8 (core 4), and peer 198.19.220.3 at CPU 10
(core 5). CPUs 9 and 11 are the respective SMT siblings. No benchmark
endpoint was assigned to them. The peer reaches stack address 198.18.0.2
through the DUT, whose kernel-side TUN is 198.18.0.1/24. Both Ethernet
links and the one-queue TUN used MTU 1500. Both eth0 links had TSO/GSO/GRO
disabled, with noqueue. The persistent TUN had no VNET header, flags
0x1801, and a 10,000-packet pfifo. Kernel feature flags advertised generic
offloads on the TUN. No TUN header was negotiated or used by the legacy
application. The testbed used permanent peer neighbors, fresh connections,
and disabled TCP metric caching. There was no live packet capture or
traffic shaping. The [protocol](protocol.md) specifies the workload and
paired order.

All 20 production attempts were retained. Sender summaries showed 17–388
retransmissions in five kernel-control arms. Endpoint link drops, TUN pfifo
drops and the slot's softnet drop counters were zero across production.
The pre-run host load averages were 3.87, 4.88 and 3.99, and the host
snapshots recorded other workloads, including a VM process last observed
on CPU 10. Dockerd thread CPU time advanced between snapshots of two arms
in which it was observed on CPU 10. Identity and last-CPU snapshots have
limited temporal resolution. The CSV's host slot remainder is approximate:
subtract the two endpoint cgroups' CPU from per-slot busy ticks, before
and after excluding ambiguous interrupt ticks. Snapshot windows are
staggered, cgroup figures include namespace instrumentation, and task
migration and tick quantization limit attribution. The remainder excluding
interrupt ticks ranged from 0% to 12.2%; four arms reached 2%. Treat these
as evidence of shared-host effects. All observed spread and retransmissions
are included in the table.

## Frozen evidence

Production ran from 2026-11-20 21:27:10 through 21:28:24 UTC on Linux
7.0.0-42-generic x86-64. The binary was compiled from the accepted source
da05184dd3d6766987b236b29db8caa031e7d367 with GCC 15.2.0 Release. The
production runner commit was 5c915b6bea99e205ba179c72275bc728537f3e9f.
The independently generated seed-1 payload digest is
57c114707df855575bf7f97161237ef9ece1c41ebd58c104b1a344115d707969.

| Frozen artifact | SHA-256 |
|---|---|
| Container image | 42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66 |
| utcp-bulk Release, used by both backends | 52b94b903903f80581311ac4070e107f3c5fd2eb0f962d4a155f564ae090d128 |
| libutcp_core.a Release | 774847053a2afd5bb327014d895c306ed5d3ea7b71699208ad0bb5bb550961ea |
| Build and CTest archive manifest | 67268026576bb88b38b3e0062bddd066c6228d04c69ed5ccf1105b6c0658d404 |
| Production archive manifest | 2175e0c0392aa3ae86f61aaf3d9a9cc4ae2d5e8696518c8c91ae5c958371afa1 |
| Four-arm 1 GB timing pilot archive manifest | 703658221146d6df0520bf1868a98eecde66941e9234ea9c6255c0d1cbdf7253 |

The private volume utcp-data holds both the full build and test receipt
under /m4/performance/build-da05184-gcc-release and the production receipt
under /m4/performance/baseline-r1. Production has 385 individually hashed
files, including the two executed binary copies, scripts, predeclared
plan, argv for each endpoint, process receipts, bulk JSONL, software
counters, CPU/queue snapshots, and compact results. The pilot retains the
perf probe. Untimed harness checks are stored separately as
baseline-smoke-01 through baseline-smoke-04. A separate interface
configuration probe exposed an iproute2 requirement to match the persistent
TUN's flags at deletion. The runner now reads and applies those flags
when switching between legacy, VNET and multiqueue modes. The production
legacy configuration used a single mode throughout.

[evidence.csv](evidence.csv) and [summary.json](summary.json) were recomputed
from raw receipts by [audit.py](audit.py). The audit reconciles both
application output streams, the process exit/CPU receipts, command lines,
binary and script hashes, actual interface state and the aggregate
metrics. Review the raw archive read-only from the repository root.

```bash
image=sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66
taskset -c 28-31 nice -n 10 docker run --rm --network none \
  --name utcp-m4-replay-audit --cpuset-cpus 28-31 -v utcp-data:/data:ro \
  -v "$PWD/docs/results/m4-baseline:/audit:ro" "$image" nice -n 10 \
  python3 /audit/audit.py /data/m4/performance/baseline-r1 --clock-ticks 100
```

## Rerun and compare a candidate

The command below uses the frozen production runner checkout and the archived
baseline binary. Run on home-ubuntu from a clean linked worktree at
5c915b6bea99e205ba179c72275bc728537f3e9f. Run the timing arms serially
during an allocated slot. Choose a new run ID and an unused bridge subnet.

```bash
image=sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66
mkdir -p build/replay
taskset -c 28-31 nice -n 10 docker run --rm --network none \
  --name utcp-m4-frozen-bulk --cpuset-cpus 28-31 -v utcp-data:/data:ro \
  "$image" cat /data/m4/performance/baseline-r1/bin/kernel > build/replay/utcp-bulk
chmod +x build/replay/utcp-bulk
printf '%s  %s\n' 52b94b903903f80581311ac4070e107f3c5fd2eb0f962d4a155f564ae090d128 \
  build/replay/utcp-bulk | sha256sum -c -
PYTHONDONTWRITEBYTECODE=1 taskset -c 28-31 nice -n 10 \
  python3 testbed/m4/performance/run.py --run-id baseline-replay-01 \
  --bulk build/replay/utcp-bulk --bulk-source da05184dd3d6766987b236b29db8caa031e7d367 \
  --image "$image" --repeats 5
```

The current runner accepts a separately compiled stack binary through
--candidate-bulk and --candidate-source, which keeps the Linux control
binary fixed. Use --mode and repeat --stack-arg for each app argument.
An optional --reference-mode with --reference-stack-arg uses the same
candidate binary by default. Supply --reference-bulk and --reference-source
for a different reference binary. Enable persistent TUN flags per stack
arm with --tun-vnet / --tun-multi-queue and their --reference- counterparts.
Use --functional and optionally --functional-cpus with a pair inside the
controller's allowed E-cores for untimed work. Set --ethernet-aggregation
only for an experiment that requires Ethernet TSO/GSO. It keeps Ethernet
GRO disabled and changes TSO/GSO for every arm in that campaign. Compare
modes against the matching controls under that shared Ethernet policy.

Run the local harness and independent audit fixtures on E-cores.

```bash
PYTHONDONTWRITEBYTECODE=1 taskset -c 28-31 nice -n 10 python3 -m unittest \
  discover -s testbed/m4/performance -v
PYTHONDONTWRITEBYTECODE=1 taskset -c 28-31 nice -n 10 python3 -m unittest \
  discover -s docs/results/m4-baseline -v
```
