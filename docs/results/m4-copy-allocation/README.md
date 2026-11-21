# M4 echo staging and C++ allocation diagnostics

Staged echo is the default. A TCP server can use `--direct-echo` to send
from the receive scratch buffer when the connection has no older pending
bytes. The send consumes the accepted prefix synchronously, and an unsent
tail is saved before the scratch buffer is reused. Writable callbacks drain
older data first and the server closes after echoing the bytes before FIN.

The counters track logical app-level byte movements. A staging append
covers scratch-to-pending writes. Compaction moves the remaining vector
tail after dropping a sent prefix. Relocation covers existing vector bytes
moved when capacity grows. This scope excludes transport and packet buffer
copies. Both measured binaries carry the same counter definitions. The later
[core payload study](../m4-core-copy/README.md) measures the ring and packet
boundaries independently on ordinary Linux TCP streams.

## Five paired timing runs

Every arm held 10,000 established connections for at least 5.168 seconds,
then verified 50,000 replies and 3,200,000 payload bytes at both endpoints.
The same Linux client binary offered 5,000 requests/s. Both userspace
servers used legacy single-queue TUN with CUBIC and TCP_NODELAY.

| Per-run metric | Staged median (range) | Direct median (range) |
| --- | ---: | ---: |
| App bytes staged | 3,200,000 | 0 |
| App staging appends | 50,000 | 0 |
| Compaction and relocation bytes | 0 | 0 |
| Verified requests/s | 4,999 | 4,999 |
| Client p50 (µs) | 64.255 (40.959–73.727) | 61.183 (38.911–115.199) |
| Client p99 (µs) | 790.527 (270.335–1,310.719) | 942.079 (671.743–1,089.535) |
| Server active process CPU (s) | 0.25 (0.23–0.37) | 0.34 (0.23–0.51) |
| Client active process CPU (s) | 0.21 (0.18–0.27) | 0.25 (0.18–0.37) |
| Server idle RSS delta per established socket (B) | 3,334.1 | 3,334.1 |
| Server peak sampled active RSS (B) | 54,566,912 | 53,837,824 |
| Server peak active RSS delta per established socket (B) | 4,112.8 | 4,031.7 |
| Server RSS high-water through active work (B) | 54,566,912 | 53,846,016 |

The observed medians show lower staging, active RSS and p50, plus higher
p99 and process CPU. The CPU and latency ranges overlap. The reported
2,208 B TCB and 3,334.1 B idle delta miss their 1 KiB and 2 KiB targets.
The peak sampled active delta and process high-water RSS meet the 12 KiB
per-connection and 128 MiB process targets. All arms completed 140,000
received and 130,000 transmitted TUN datagrams over the life of the
process with zero transmit EAGAIN. See [the compact measurements](echo-timing.json)
for run order, source and executable hashes, and private evidence paths.
The Linux-server control remains in [the preceding echo report](../m4-echo-load/pre-copy.md).

Process CPU is the change between the first and last of three in-workload
`/proc/<pid>/stat` reads, in 100 Hz user and system ticks on this host.
That window covers about three seconds of the ten-second active workload.
The collector ran on CPU 11, the client's SMT sibling. Placement snapshots
showed other host activity on CPUs 8–11 during the campaign. Throughput
uses the full active client interval. Resident memory is baseline-subtracted
where labeled, and active RSS peaks are the maximum of three samples.

### Replay

Build GCC Release from each private source commit and put the three
resulting binaries under `build/echo-compare/` in the runner checkout.

| File | Source commit |
| --- | --- |
| `legacy-server` | `95a2d39c006099eaf965dd7bb4def1b44d1e259c` |
| `direct-server` | `5dcbc7657a00522602fad7d7e0684170adb2712b` |
| `kernel-client` | `efef6073b9f2d478f73e0abbd50d06f293f5ce15` |

```sh
taskset -c 24-27 nice -n 10 cmake --preset gcc-release
taskset -c 24-27 nice -n 10 cmake --build --preset gcc-release -j4 --target utcp-echo
```

Run the harness from clean runner commit
`773737be59b4c170a5bf6d72ce6adb65d24dcf99`. Set `arm=legacy` or
`arm=direct` and the corresponding full `source` from the table.
Run serially in five pairs, reversing order each pair. Use the reserved
timing CPUs and a free bridge subnet.

```sh
taskset -c 11 python3 testbed/m4/echo_load.py --purpose timing --backend utcp \
  --offload legacy --cpus 8,10,11 --net-base 87 \
  --binary "build/echo-compare/$arm-server" --binary-source "$source" \
  --client-binary build/echo-compare/kernel-client \
  --client-source efef6073b9f2d478f73e0abbd50d06f293f5ce15
```

The measured direct build always selected the direct branch. For a run
from the current selectable code, use one server executable in both arms
and add `--direct-echo` to the direct arm. The harness checks both
running executable digests, the live populations and idle hold, verified
bytes and requests, and one TUN queue pair.

## Selectable-mode runtime confirmation

The final selectable runtime came from git commit `0b2887251b2e42054cc7b88f6fc84ace382205e7`.
Both modes used the same server executable and the same frozen Linux
client. A functional run per mode verified 640 replies and 40,960 B at
64 connections. A separate full-size confirmation pair verified 50,000
replies and 3,200,000 B per arm with at least 5.172 seconds of 10,000
established connections. Default staging recorded all 3,200,000 B across
50,000 appends. The opt-in direct mode recorded zero staged bytes and
zero appends. Each server used one legacy TUN queue pair.
The [confirmation rows](final-runtime.json) are separate from the five
pairs used for latency, CPU and RSS comparisons.

## Initialized C++ allocation diagnostics

The positive control called all eight replaceable `operator new` forms.
The observed delta was eight and deletions left the count unchanged. The
collector samples C++ new calls across the server process, including the
event loop and JSON telemetry. Scope excludes direct `malloc` calls,
kernel allocations, and allocator bookkeeping. The process counts exceed
zero and the per-packet zero-allocation target remains unverified.

| Server workload | Calls in sampled window | Matched traffic |
| --- | ---: | --- |
| Staged warm echo | 42 in 1.479 s | 640 requests, 40,960 B end to end |
| Direct warm echo | 42 in 1.503 s | 640 requests, 40,960 B end to end |
| Warm bulk receive | 416 in 2.260 s | 452,834–491,746 in-window data segments, 2,339,193,728 B SHA-256 checked end to end |
| Warm bulk send | 26,333 in 2.237 s | 387,313–423,537 in-window data segments, 2,185,986,728 B SHA-256 checked end to end |

The echo probe sampled the middle of five seconds of active work with
64 already established connections and periodic reporting. Both modes
also counted 70 calls during their roughly 2.3-second idle control windows. Bulk starts
sampling after at least 8 MiB transfers. Its asynchronous TCP-info
samples give upper and lower bounds for in-window bytes and segments.
Both bulk directions verified matching endpoint bytes and SHA-256.
Two earlier bulk diagnostics failed to capture live samples when
stdio buffered the configuration and when a partial line hid the last
full sample. Their raw evidence remains in the private volume.

### Replay allocation diagnostics

```sh
mkdir -p build/echo-compare
taskset -c 24-27 nice -n 10 g++-15 -std=c++23 -O2 -Wall -Wextra -Werror \
  -shared -fPIC testbed/m4/count_new.cpp -o build/echo-compare/count_new.so
taskset -c 24-27 nice -n 10 g++-15 -std=c++23 -O0 -Wall -Wextra -Werror \
  testbed/m4/count_new_probe.cpp -o build/echo-compare/check-count
probe_dir=$(mktemp -d "$PWD/build/echo-compare/probe.XXXXXX")
taskset -c 24-27 nice -n 10 env \
  LD_PRELOAD="$PWD/build/echo-compare/count_new.so" UTCP_NEW_COUNTER="$probe_dir/count" \
  build/echo-compare/check-count
```

For the two echo diagnostics, use the same source and executable
selection as the five-pair timing, with `--purpose functional`,
controller CPU 26 and `--cpus 24,25,26`. Add these flags.

```sh
--allocation-counter build/echo-compare/count_new.so \
  --connections 64 --count 10 --rate 128 --hold-s 2
```

For bulk, build the normal GCC Release `utcp-bulk` target and run both
directions separately.

```sh
taskset -c 26 nice -n 10 python3 testbed/m4/bulk_allocation.py \
  --direction receive --net-base 89 --allocation-counter build/echo-compare/count_new.so
taskset -c 26 nice -n 10 python3 testbed/m4/bulk_allocation.py \
  --direction send --net-base 89 --allocation-counter build/echo-compare/count_new.so
```

See [the compact allocation measurements](allocations.json) for counter
windows and evidence paths.


## Developer checks

At the selectable runtime commit, GCC Release CTest reported 1,076
passes and four missing-tshark skips. The four skipped cases then
passed separately in the testbed image. Clang ASan/UBSan passed all 27
`Echo*` tests and the real-socket gate, including its expected corrupt
reply rejection. The regressions cover full writable sends, a positive
short write, a blocked send that resumes on writable, byte order, and FIN.

```sh
taskset -c 24-27 nice -n 10 ctest --preset gcc-release -j4 --output-on-failure
docker run --rm --network none --cpuset-cpus 24-27 -v "$PWD:$PWD:ro" -w "$PWD" \
  utcp-testbed:dev nice -n 10 build/gcc-release/tests/sim/utcp_sim_tests \
  --gtest_filter='SimPcap.TsharkReadsWithoutErrors:SimPcap.ExpertScript*'
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  taskset -c 24-27 nice -n 10 build/clang-asan/tests/unit/utcp_unit_tests --gtest_filter='Echo*'
docker run --rm --network none --cpuset-cpus 24-27 -v "$PWD:/utcp:ro" \
  utcp-testbed:dev nice -n 10 python3 /utcp/testbed/m4/echo_gate_test.py \
  /utcp/build/clang-asan/apps/utcp-echo/utcp-echo
```
