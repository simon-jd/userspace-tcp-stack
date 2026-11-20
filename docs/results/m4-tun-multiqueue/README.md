# Multi-queue TUN

`--tun-queues N` attaches N independent descriptors to an existing
`IFF_MULTI_QUEUE` device. Each test arm uses a single userspace Stack and
EventLoop. The default CLI continues to use a single-queue TUN. With an
explicit count of 1, the kernel interface has the same multi-queue flag as
the 2-descriptor arm. A stable outgoing TCP four-tuple assigns TX placement,
including VNET aggregates. The kernel can select a different ingress
descriptor. The event loop reads at most 64 datagrams per ready FD per
callback. On EAGAIN, the pending datagram retains its FD before the stack
continues draining in order.

## Functional evidence

- GCC Release at `4857492b47b2913bbc27993d7710df7824554376` passed 1,080 tests
  with four tshark tests skipped. The focused
  `backend_transport_check --expect-stack` delivered a connection handshake
  and FIN on different ingress descriptors and retried a blocked TCP data
  packet on its original nonzero descriptor. A valid UDP datagram used
  queue zero.
- `tests/interop/m4_tun_multiqueue.sh` used the ordinary `utcp-echo` server
  with eight kernel TCP sockets. It verified 3,147,056 distinct echo bytes
  per arm, the same sockets across a seven-second quiet interval, and
  matching ifindex, procfs TUN descriptors, sysfs queue counts, and active
  checksum/segmentation features. Seven seconds exceeds the kernel's
  three-second flow-cache aging time and allows timer rounding. The
  socketpair fixture independently forces the different-ingress case.
  [Linux v7.0 TUN driver](https://github.com/torvalds/linux/blob/v7.0/drivers/net/tun.c#L109)
- Two-descriptor RX/TX datagram counts were legacy `[2206,735]/[3023,1065]`,
  checksum `[762,2143]/[1069,3056]`, and TCPv4 `[276,90]/[341,92]`.
  TCPv4 observed 180 RX aggregates and 92 TX aggregates. The legacy
  pre-change control passed its normal echo transfer and rejected the new
  multi-queue option.
- The bulk runner's 4,000,055-byte functional pilots passed six transfers
  each under uncapped and fixed stack pacing. The separate simultaneous
  echo pilot passed both arms with 16 established connections and
  12,582,912 verified echoed bytes per arm.

## Measurement configuration

The bulk runner is `testbed/m4/performance/run.py` at
`1427bbe64848c1c158488a2e8776aad2cb0f47c3`. Both stack arms use the same
GCC Release binary and TCPv4 checksum and segmentation offload. Linux uses
the frozen reference binary built from `da05184dd3d6766987b236b29db8caa031e7d367`.
Each direction ran one 1 GB pilot and five 1 GB production repetitions per
arm with CUBIC. The DUT ran on CPU 8, the peer on CPU 10. Ethernet TSO/GSO
were enabled and GRO disabled across the arms. Both endpoints verified the
exact byte count and SHA-256 using the runner's independent pattern oracle.

The fixed-rate stack arms use `test_fixed_pacing_rate=1Gbit` for stack TX.
The stack sender's goodput in that workload reflects the rate cap. When the
DUT receives, the Linux peer uses ordinary Linux CUBIC and the stack pacing
setting applies only to stack output. The uncapped run measures the same
configuration with the fixed pacing setting removed. Each bulk throughput
is receiver-reported application goodput. CPU seconds per decimal GB are
derived from the DUT child process's wait4 user and system times.

The simultaneous echo control uses the same topology, offload settings,
MQ flags, and placement. Each arm verifies 16 Linux connections established
at the same time on one userspace echo server and 512 requests of 64 KiB
per connection at an offered rate of 1,000 requests/s across all
connections. The Linux client checks each byte against its generated
request. Each arm transfers 536,870,912 verified echoed bytes. Echo goodput
credits the returned application bytes once. Echo CPU seconds per decimal
GB charge the whole server or client process over those verified bytes,
and therefore include both request and response processing.

## Results

All 12 full-size bulk pilots, 60 production bulk transfers, and 10
concurrent echo attempts passed. Bulk metrics are medians with full
range in brackets. TUN calls cover all directions on the DUT for
one verified decimal GB, including retries and empty reads.

| Workload | DUT | Active FDs | Goodput Gbit/s | DUT CPU s/GB | Reads | Writes |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Uncapped | Send | Kernel | 14.231 [14.014, 14.526] | 0.563 [0.551, 0.569] | — | — |
| Uncapped | Send | 1 | 11.452 [11.143, 11.633] | 0.686 [0.677, 0.707] | 16,571 | 22,896 |
| Uncapped | Send | 2 | 11.540 [11.407, 11.625] | 0.682 [0.677, 0.690] | 16,001 | 22,903 |
| Uncapped | Receive | Kernel | 14.331 [14.139, 14.343] | 0.429 [0.428, 0.434] | — | — |
| Uncapped | Receive | 1 | 14.609 [14.457, 14.663] | 0.519 [0.518, 0.522] | 23,139 | 19,038 |
| Uncapped | Receive | 2 | 14.529 [14.489, 14.630] | 0.520 [0.519, 0.523] | 23,093 | 19,031 |
| Fixed stack pace | Send | Kernel | 14.430 [14.049, 14.589] | 0.555 [0.549, 0.558] | — | — |
| Fixed stack pace | Send | 1 | 0.993 [0.986, 0.994] | 2.157 [1.916, 2.959] | 30,577 | 15,356 |
| Fixed stack pace | Send | 2 | 0.976 [0.970, 0.998] | 2.189 [0.870, 2.617] | 30,488 | 15,355 |
| Fixed stack pace | Receive | Kernel | 14.360 [13.596, 14.498] | 0.436 [0.427, 0.457] | — | — |
| Fixed stack pace | Receive | 1 | 14.473 [13.946, 14.705] | 0.524 [0.519, 0.548] | 23,333 | 18,258 |
| Fixed stack pace | Receive | 2 | 14.362 [13.952, 14.568] | 0.525 [0.521, 0.548] | 23,449 | 19,011 |

Single-flow TCP writes used one selected descriptor in every MQ2 arm.
The uncapped median send goodput rose 0.8% and receive goodput fell
0.5% with two descriptors. The observed CPU and goodput ranges overlap
within each one-versus-two comparison. With fixed pacing, median stack
send CPU rose from 2.157 to 2.189 s/GB, and the receive median write
count rose from 18,258 to 19,011. These comparisons found no
consistent speed or CPU benefit.

| Active FDs | Echo Gbit/s | DUT CPU s/GB | Reads per arm | Writes per arm |
| --- | ---: | ---: | ---: | ---: |
| 1 | 0.52402 [0.52400, 0.52404] | 0.740 [0.705, 0.834] | 41,219 [41,106, 41,258] | 25,424 [25,422, 25,441] |
| 2 | 0.52402 [0.52401, 0.52406] | 0.755 [0.706, 0.845] | 41,260 [41,203, 41,275] | 25,428 [25,412, 25,450] |

Every two-descriptor echo attempt used both FDs for reads and writes.
The lower-traffic FD on each run carried at least 6,212 RX and 6,356
TX datagrams. All clients achieved 999 completed requests/s as
reported by their integer rate counters. Median server CPU rose about
2% with both descriptors active. The event loop still runs on one thread.

The shared-host non-interrupt slot busy remainder met the 2% flag in
seven uncapped, 16 fixed-pace, and three echo production arms, plus one
fixed-pace pilot. These estimates and all attempts remain in the
results. An unrelated process appeared on CPU 10 in the preflight CPU
snapshot. The ordinary process-scoped perf probe exited 1 with
“No supported events found” at paranoid 4. CPU figures use wait4.

## Private evidence

Raw receipts are under `utcp-data:/m4/performance/<campaign>` on Ubuntu.
`evidence.json` records the row-level replay and host-overlap flags.

| Campaign | Arms | SHA-256 of SHA256SUMS |
| --- | ---: | --- |
| `mq-uncapped-p1` | 6 | `42c630ec04ea3ae89d6558ae1e9d0d84493d866d37d5a289210497f81cffa1bf` |
| `mq-paced-p1` | 6 | `af6cd3335bf606d1167d4534b258a48c0b4b5ab43720c2cdaab4d26369e0ba2c` |
| `mq-uncapped-r1` | 30 | `4c5cc30f5cd308a5dc1b50d7e0d18ca8f6572be3dd3cf0f1de14030df70f1af5` |
| `mq-paced-r1` | 30 | `560cbe5816cfecfce284f912277d92c0f739572ef4a5787dfe1edbe85fcac756` |
| `mq-echo-r1` | 10 | `7d128a7af834a638c8527bfd9902893a63e595e271732b6f29b818720cb8afe9` |

The GCC Release binary SHA-256 values were
`721314a504b23ef2940f5ea1e93445d2fceaab2e20bf03ac12d49bdef46013f9`
for bulk and
`07f17af161f2c8e324aa483695298bebebd4e5d295994d8d74c80c62dca8fe3f`
for echo. The functional logs, Release and Clang sanitizer build logs,
live tests, host preflight, and exact timing controller command are under
`utcp-data:/m4/performance/mq-transport-checks`. Its manifest hash is
`be7b6d9e38b5dc2730759de91e5718b366138e80497e1e3bad8145de7a540be8`.

Run the receipt audit from this worktree with the baseline report at
`~/Desktop/utcp-wt/m4-baseline`.

```sh
baseline="$HOME/Desktop/utcp-wt/m4-baseline/docs/results/m4-baseline"
results="$PWD/docs/results/m4-tun-multiqueue"
docker run --rm --network none --cpuset-cpus 28-31 \
  -v utcp-data:/data:ro -v "$results:/mq:ro" -v "$baseline:/baseline:ro" \
  utcp-testbed:dev nice -n 10 python3 /mq/audit.py /data/m4/performance \
  --baseline-audit /baseline/audit.py --clock-ticks "$(getconf CLK_TCK)"
```

For the build and functional checks, run on CPUs 28–31 at nice 10 in
this worktree.

```sh
taskset -c 28-31 nice -n 10 cmake --preset gcc-release
taskset -c 28-31 nice -n 10 cmake --build --preset gcc-release -j4
taskset -c 28-31 nice -n 10 ctest --preset gcc-release -j4
taskset -c 28-31 nice -n 10 tests/interop/m4_tun_multiqueue.sh
taskset -c 28-31 nice -n 10 cmake --preset clang-asan
taskset -c 28-31 nice -n 10 cmake --build --preset clang-asan -j4 \
  --target backend_transport_check utcp-echo
taskset -c 28-31 nice -n 10 ctest --preset clang-asan -j4 \
  -R '^interop\.backend_transport_check(_stack)?$'
taskset -c 28-31 nice -n 10 env UTCP_PRESET=clang-asan \
  tests/interop/m4_tun_multiqueue.sh legacy-2 tcpv4-2
```

Clang ASan/UBSan passed both focused transport CTest cases and both
selected real TUN arms.
