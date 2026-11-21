# Dedicated TCP sender events

GCC 15 Release at `069e56f915a4f94b7c7b824446c05df1c85889fb` sent 1,048,613 bytes per transfer to a Linux TCP receiver over legacy TUN. Each case used a new network namespace on CPUs 16–23, nice 10. Each loss rule dropped the first copy of one data segment and passed its retransmission. Both endpoints reported SHA-256 `7ca5890e0b72aea25b3fc98f9d1740526b39b2b0360f53593689df759dddea9c`. Both capture sources matched on TCP sequence, acknowledgment, flags, payload length and SACK blocks, with zero tcpdump capture drops. All six transfers crossed sequence zero.

| Controller | Traffic | Matched packet pairs | cwnd | RTT | Raw RTT independently timed | Recovery edges |
|---|---|---:|---:|---:|---:|---:|
| NewReno | Clean | 1,039 | 287 | 310 | 310 | 0 |
| NewReno | One loss | 1,087 | 38 | 357 | 347 | 3 |
| CUBIC | Clean | 1,129 | 199 | 395 | 395 | 0 |
| CUBIC | One loss | 1,081 | 11 | 351 | 342 | 3 |
| BBR | Clean | 1,076 | 103 | 348 | 348 | 0 |
| BBR | One loss | 1,122 | 119 | 393 | 383 | 3 |

All loss paths were open → disorder → recovery → open. The raw RTT comparison uses the SYN or the first unambiguous cumulatively acknowledged segment and the receiving packet's stack clock. It excludes SACK/retransmission ambiguity in the loss cases. A second checker reconstructs payload bytes at every legacy TX, RX, accepted ACK and TCP state row from the two captures. In these flows every dedicated ACK-path snapshot had the accepted ACK's reconstructed byte count. The plotting consumer read a 1,691-row historical trace and all six new traces, with two historical retransmission marks and exactly one per new loss case.

The implementation source starts at `7ef4b017a74c07184ad9380995cd4ded19f9f7bd`. A first candidate omitted initial cwnd; both endpoints of an ordinary handshake now publish the installed window with its previous values. GCC ran 890 unit tests successfully (two pre-existing disabled); Clang 21 with ASan/UBSan passed 20 targeted tests. Scripted peers covered partial cumulative ACKs, duplicate ACKs, zero-time handshake samples, real data timeouts, suppressed ambiguous RTT, accepted timestamp fallback and a single ACK causing both entry to and exit from CWR. Operation-level publication also instruments REO, PMTU and BBR's transmit-start hook. The six real transfers above did not isolate these three paths.

A separate fixed-clock one-loss replay used all three controllers with a null sink, an attached sink with an empty mask, and a non-allocating sink subscribed only to the three events. For each controller the modes produced identical datagrams, timestamps, delivery/drop decisions, TCP information, stack counters and resource usage. The counted interval (handshake, 12,117-byte send, and recovery, including the harness) made 111 scalar C++ allocations in every mode on the base and candidate builds. All three sent 22 datagrams. The final sink received 19, 19 and 20 events for NewReno, CUBIC and BBR. These are allocation counts for that replay, not timing measurements.

## Independent acceptance

Ten separate Linux transfers of this exact production source checked 4,059,872 delivered bytes, 4,574 packet pairs, 3,536 ordinary payload-byte observations and 1,243 dedicated observations. They included one untimestamped data timeout, SYN loss, individual event masks, a legacy mask and a detached sink. Three independent omission controls rejected a missing RTT, cwnd or recovery event. The additional scripted tests covered equal RTT estimates, late sink attachment and idle restart. The full report is `~/Desktop/utcp-wt/dedicated-events-independent-n22/_accept/REPORT.md`, SHA-256 `82ac49e5627f37faf7360174b4af1585f388244cb9e2cf8199540f3c76864637`. The 188-entry manifest at `utcp-data:/dedicated-events-independent-n22-069e56f915a4/SHA256SUMS` has SHA-256 `737bcaaaf06a45a86d4cc93d192eba523e75b77e0c1fd8f8cad50c5267617c05`.

## Reproduction

Use the repository root and an empty output directory. The measured developer binary SHA-256 is `4bf5d197f060ec71d8002abaadc81786b2dd6def03d729699a5cfbf1255f8101`. The image ID is `sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66`. The two pcaps, application receipts, trace JSONL, filter statistics, per-case check results and verification logs are in `utcp-data:/dedicated-events-final-n22/`. The 101-entry SHA256SUMS has SHA-256 `eff44148f403ee5c02f4f03931ea1e1f036ffbc1d02de31b5bd11eb1679bab07`; verify from that directory with `sha256sum --quiet -c SHA256SUMS`.

```sh
taskset -c 16-23 nice -n 10 cmake --preset gcc-release
taskset -c 16-23 nice -n 10 cmake --build --preset gcc-release -j8 --target utcp-bulk utcp_unit_tests
taskset -c 16-23 nice -n 10 build/gcc-release/tests/unit/utcp_unit_tests
out=$(mktemp -d)
for cc in newreno cubic bbr; do
  for traffic in clean loss; do
    case_dir="$out/$cc-$traffic"
    mkdir "$case_dir"
    docker run --rm --network none --cpuset-cpus 16-23 --cap-add NET_ADMIN --device /dev/net/tun \
      -v "$PWD/build/gcc-release/apps/utcp-bulk/utcp-bulk:/bin/utcp-bulk:ro" \
      -v "$PWD/docs/results/trace-flight/capture.sh:/capture.sh:ro" -v "$case_dir:/out" \
      utcp-testbed:dev nice -n 10 bash /capture.sh "$traffic" "$cc"
    python3 docs/results/trace-flight/check.py "$case_dir"
    python3 docs/results/sender-events/check.py "$case_dir" "$cc" "$traffic"
  done
done
g++-15 -std=c++23 -O2 -Iinclude -Isrc -Itests docs/results/sender-events/parity.cpp \
  build/gcc-release/tests/support/libutcp_test_support.a build/gcc-release/src/core/libutcp_core.a -o "$out/parity"
taskset -c 16-23 nice -n 10 "$out/parity"
```

The independent project and volume preserve their own methods and inputs. All work here used private local refs and ordinary bounded TCP transfers.
