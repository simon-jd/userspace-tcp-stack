# Core ByteRing and ChunkPool size

The six matched blocks on 2026-11-21 select the existing 4 KiB default. The 2 KiB arm cut the median paired pool backing bytes by 52.19%, but cut the active process RSS delta by only 0.12%. The 8 KiB arm raised median paired receive goodput by 5.02%, with three faster blocks and three slower blocks. Neither alternative achieved the predeclared 5% benefit in five of six blocks for goodput, DUT CPU, active RSS or process VmHWM. The [registered rule and order](PROTOCOL.md) were committed before measuring at `e6a2765f8dc4dc9bb1203175cb7040959c6299ed`.

## Measurements

These are the medians of six distinct runs per size. Goodput uses the receiver's verified bytes and elapsed transfer time. DUT TX and RX CPU are the appropriate userspace endpoint's user plus system process time per decimal GB. Echo active RSS is the largest of three in-workload smaps samples per trial, less listener baseline, divided by 10,000. VmHWM is the process peak through the final verified reply.

| Core chunk | DUT TX Gbit/s | DUT RX Gbit/s | TX CPU s/GB | RX CPU s/GB | Idle RSS B/conn | Active RSS B/conn | VmHWM bytes | Pool chunks obtained | Pool backing bytes |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 KiB | 3.768 | 3.937 | 2.129 | 2.035 | 1,542.14 | 3,979.26 | 53,233,664 | 23.5 | 48,128 |
| 4 KiB | 3.836 | 3.894 | 2.090 | 2.058 | 1,542.14 | 3,983.97 | 53,317,632 | 23 | 94,208 |
| 8 KiB | 3.957 | 4.403 | 2.028 | 1.814 | 1,542.14 | 3,993.60 | 53,413,888 | 23.5 | 192,512 |

The decision uses the median of the six within-block percentage changes. Positive CPU, RSS, VmHWM and latency changes are increases in cost.

| Compared with 4 KiB | TX goodput | RX goodput | TX DUT CPU | RX DUT CPU | Active RSS | VmHWM | Echo p99 latency |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 KiB | +0.15% | −3.80% | −0.15% | +4.10% | −0.12% | −0.18% | +27.15% |
| 8 KiB | +2.13% | +5.02% | −2.07% | −4.54% | +0.17% | +0.22% | −0.25% |

Every trial passed the original 2 KiB idle, 12 KiB active and 128 MiB peak limits. The largest process peaks were 50.82, 50.91 and 51.05 MiB in increasing chunk-size order. Idle pool allocations were zero in all 18 trials. The LIFO pool keeps all chunks it obtains from the heap. Across trials, the high-water counts ranged from 20–25, 20–30 and 20–26 chunks respectively, well below the common 4 GiB backing cap. Total backing bytes exclude vector capacity, heap metadata, stream state and other resident memory. Pool allocation calls and process memory have different scopes. The shared host, six replicates and limited connection/request workload bound the inference.

The [absolute values](absolute.csv) cover every block and both directions, including sender and receiver CPU breakdown, retransmissions, RSS, pool storage, echo latency and active process CPU. The [paired analysis](paired.json) contains all individual changes, signs and ranges, plus the computed decision. The original logs retain all attempts, including developmental test assumptions repaired before this series.

## Workload and evidence

The frozen source is `2e21e11111241f0d3a58ecb320550cae7448c0e3`, descended from the integrated memory/copy baseline `fa35221f9f86f3c3b997d839f2bb43d8ec8b305f`. All 36 single-stream transfers exchanged 1,000,000,000 bytes, individually matching the independent seed-1 SHA-256 `57c114707df855575bf7f97161237ef9ece1c41ebd58c104b1a344115d707969`. The application used a fixed 256 KiB write size in every arm. The same 4 KiB Linux peer binary served all three userspace builds. All 18 staged-echo runs held 10,000 verified connections at both endpoints and verified 50,000 responses of 64 bytes, 3,200,000 bytes per run, with zero errors or mismatches. Workload particulars, CPU placement and rejection criteria are in the protocol.

The core CMake option accepts 2048, 4096 or 8192 bytes. The default stack has 2,097,152, 1,048,576 and 524,288 possible chunks respectively. Explicit pool limits still count chunks, as do historically serialized simulator inputs. All three GCC Release builds passed 863 offline unit tests, the 14 remaining kernel/loopback unit tests and 17 short simulator tests. One-second legal-stream checks at each size used the same original 4 KiB-profile generator. All shared batch records agreed. The first checked 16 streams, 372 inserts, 364 reads and 155,289 bytes. Some dedicated pool-exhaustion unit fixtures deliberately address chunk boundaries. The measured bulk and echo workloads are size-independent.

The raw archive is `utcp-data:/m4-ring-size-n21-d01/`. Its 1,243-file manifest SHA-256 is `0fc2080c8377e4fdb00362a300f94bc238af35315bfcda5641543179e8bd1184`. The nested bulk manifest SHA-256 is `aab314c698ec9586c1da1d30bc8116d41b72b86f5f1d2da8e6adb6f0f84b742a`. Both were replayed with sha256sum. The separate method archive `utcp-data:/m4-ring-size-n21-d01-method/` includes the build, regression and workload logs, derived files and verification script. Its manifest SHA-256 is `2d053e8882b1fbcb36067eae730370f21302f7bd10b8521ddcccea461cc97959`. The image digest was `sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66`.

After acquisition, merge `610723e65c42150453100106047a8559774e0131` brought in copy-checker update `7958ea1fc98fbd91f13bb9c0110d13d10f499bc7`. The complete change against the measured commit consists of the separate copy report, its offset checker and its controls. The following Git object inventory is byte-identical across the measured commit and merge. It has 411 paths and SHA-256 `d55b434b47b77a60b64c66cc07d969bcded24e3616a4ff9d733983de28df2913`. Both original copy fixtures pass the updated checker and all four offset changes are rejected.

```sh
git ls-tree -r HEAD -- CMakeLists.txt CMakePresets.json cmake src include apps tests \
  testbed/m4/ring_size testbed/m4/performance testbed/m4/echo_load.py \
  testbed/m4/echo_load_snapshot.py docs/results/m4-ring-size/PROTOCOL.md | sha256sum
```

## Reproduction

Use a clean checkout of the measured commit, the recorded Ubuntu toolchain and image, the utcp-data volume, and a new run ID. Build all three configurations on the E-cores. The default runner executes the six permutations serially, using CPUs 8/10 for bulk and 8/10/12 for echo. Its controller stays on 28–31. For independent representative blocks, choose ascending registered numbers with `--blocks 1,4`. The analysis reports partial coverage for a subset.

```sh
for bytes in 2048 4096 8192; do
  taskset -c 28-31 nice -n 10 cmake --preset gcc-release -B "build/ring-$bytes" \
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache -DUTCP_RING_CHUNK_BYTES="$bytes"
  taskset -c 28-31 nice -n 10 cmake --build "build/ring-$bytes" -j4
done
taskset -c 28-31 nice -n 10 python3 testbed/m4/ring_size/run.py --run-id ring-replay
```

To recompute on a read-only mount of the volume at /data, run the analyzer from the source checkout and pass a fresh output directory.

```sh
(cd /data/m4-ring-size-n21-d01 && sha256sum -c --quiet ROOT-SHA256SUMS)
python3 testbed/m4/ring_size/analyze.py /data/m4-ring-size-n21-d01 /tmp/ring-study-report
```
