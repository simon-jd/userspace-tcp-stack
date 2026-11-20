# M4 legacy single-queue echo baseline

Five paired runs on 2026-11-20 used source
`1ffcc979ce36831441eec99031154a7b454ae25e` and the same GCC Release
binary in all roles. The binary SHA-256 was
`2d2a23a1e4bccf005f2e1851019c7a4167a7fb43be64504398419140afc7aae7`.
The window ran from 21:44:45 to 21:48:06 UTC. The server ran on CPU 8,
the Linux client on CPU 10 and the collector on CPU 11, CPU 10's SMT
sibling. Both used nice 0. The [runner documentation](README.md)
describes the two paths and accounting scopes.

Each trial verified 10,000 already-established connections at both
endpoints before opening the active gate. Holds ranged from 5.162 to
5.199 s. Each connection had five 64-byte requests. Every trial
verified 50,000 replies and 3,200,000 echoed bytes at both endpoints
with zero failures or mismatches. The offered rate was 5,000 requests/s.
The client reported 4,999 verified requests/s after integer truncation
in each timed arm. Linux's server and client namespaces matched the
target TCP tuple digest throughout all three idle and drain checks.
The legacy userspace server used one TUN queue pair and reported
10,000 accepted connections and 10,001 live core TCP slots.

## Latency

Each value is a client log-linear percentile in microseconds. The
median row summarizes five per-run estimates in each arm.

| Pair | First arm | Userspace p50 | Userspace p99 | Linux p50 | Linux p99 |
| ---: | :--- | ---: | ---: | ---: | ---: |
| 1 | Userspace | 45.311 | 995.327 | 33.791 | 983.039 |
| 2 | Linux | 50.687 | 970.751 | 28.927 | 978.943 |
| 3 | Userspace | 47.359 | 991.231 | 27.135 | 958.463 |
| 4 | Linux | 42.751 | 634.879 | 35.327 | 712.703 |
| 5 | Userspace | 46.335 | 532.479 | 34.559 | 962.559 |
| Median | | 46.335 | 970.751 | 33.791 | 962.559 |

Userspace p50 exceeded Linux p50 in each pair. The p99 ranges
overlapped, and their order varied by pair. The process placement
snapshots showed unrelated host processes on CPUs 8–11, including a
VM, application processes and the container runtime. Placement is
the last CPU recorded for each sampled process. All completed trials
contributed to the table.

## Server memory

Each value is the median of five runs in bytes, except the explicitly
labeled per-connection rows. The active rows use the maximum of three
samples per run. The baseline is the listener process before opens.

| Measure | Legacy userspace | Linux |
| :--- | ---: | ---: |
| Listener RSS | 13,463,552 | 4,481,024 |
| Idle RSS | 46,804,992 | 7,282,688 |
| Peak sampled active RSS | 54,591,488 | 8,081,408 |
| Listener PSS | 10,597,376 | 1,729,536 |
| Idle PSS | 43,942,912 | 4,551,680 |
| Peak sampled active PSS | 51,731,456 | 5,344,256 |
| Idle RSS delta per connection | 3,334.1 | 280.2 |
| Peak sampled active RSS delta per connection | 4,111.2 | 360.0 |
| Idle server cgroup slab delta | 46,600 | 48,255,112 |
| Peak sampled active server cgroup slab delta | 66,680 | 48,267,856 |

The 2,208-byte TCB exceeded the 1 KiB target. Idle RSS delta was
3,334.1 B per connection in all five userspace runs, above the 2 KiB
target. The highest sampled active delta was 4,113.6 B per connection,
within the 12 KiB target. The largest userspace process high-water RSS
was 54,652,928 B, within the 128 MiB target. Linux's active server
cgroup socket-buffer samples ranged from 0 to 61,440 B. The cgroup
slab deltas include non-socket objects. Host-global sockstat and slab
counts accompany the per-namespace tuple and cgroup data.

## Receipts and reproduction

The five-pair order, arguments, image and CPU captures, per-run
receipts, and a verifier that reconstructs the summary are stored
under `utcp-data:/m4-echo-load/paired-1ffcc97/`. Its `summary.json`
SHA-256 is
`c787a09212eab4cfecc420e2371ba6ea045a65b251bfa1a640901aa8cec959b3`.

| Pair | Legacy userspace run | Linux run |
| ---: | :--- | :--- |
| 1 | `20261120T214445Z-244c86df` | `20261120T214505Z-68a1a33b` |
| 2 | `20261120T214545Z-65fc5a6d` | `20261120T214525Z-d6bf071c` |
| 3 | `20261120T214605Z-3fe4542b` | `20261120T214625Z-033eb347` |
| 4 | `20261120T214705Z-5e555fe9` | `20261120T214645Z-1eef92fa` |
| 5 | `20261120T214726Z-7fbc26f7` | `20261120T214746Z-5214a3ef` |

Rebuild at the measured source SHA and invoke the following command
for each arm, changing `--backend` between `utcp` and `kernel` in
the recorded order and using the matching timing grant.

```sh
taskset -c 11 python3 testbed/m4/echo_load.py \
  --purpose timing --backend utcp --cpus 8,10,11 --offload legacy \
  --connections 10000 --open-batch 32 --backlog 4096 \
  --count 5 --size 64 --rate 5000 --hold-s 5 --net-base 85
```

The fresh GCC Release build passed all 1,076 CTest cases at the
measured source. Clang ASan/UBSan passed all 23 focused echo CTest
cases and the real-socket gate and corrupt-reply probe. Logs are in
`utcp-data:/m4-echo-load/ci-1ffcc97/`. These timing results establish
the legacy pre-copy baseline for subsequent matched measurements.
