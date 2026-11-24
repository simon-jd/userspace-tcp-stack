# Historical validation evidence

The [source revision index](source-revisions.tsv) records full commit and
tree IDs. This page identifies the original validation commands and records.
M5 reopens the listed summaries and checks their selected file hashes without
running another validation campaign.

## M0 environment and skeleton

M0 ran `ci/docker-ci.sh` and `testbed/verify-env.sh` at
`35c86e1c65cd94bdee458d1da02fa4d28ed026a8` with Ubuntu 26.04 and
image `sha256:1f2e71181861a0c4c4921b4689f3fd13f016d6e8f3dedd9efe90f37d366e02c2`.
The original final logs under `~/Desktop/utcp-wt/m0/.logs/` record 23
passes in each of six presets, a working TUN path, a 20.070 ms average RTT,
9.477 Mbit/s in the shaped test, and a kernel BBR socket. They are anchored by
the [workdir checksums](historical-workdirs.sha256). The GitHub workflow was
never run. Apt package versions other than GoogleTest were unpinned.
[Environment, exact commands and original runtime](../../ENVIRONMENT.md#verify-env)

## M1 interop and simulator

- The combined M1 acceptance at `2079db33ce80039186c7c6aa61a4158f66614fcb`
  ran `tools/sim_sweep.py --seeds 0:100000 --jobs 8` with `gcc-sweep`.
  The 100,000 recorded verdicts are `ok`, with no failure rows in
  `utcp-data:/m1-accept/sweep/`. The historical logs also record eight CI
  presets and two 1 GB netem transfers with matching endpoint SHA-256.
  Earlier repeated sweeps and the expert-dissection amendments are documented
  with their own counts and source. [Simulator driver and cases](../../SIM-BUGS.md#1e5-seed-acceptance-sweep-m1-accept-sweep-test-f)
- The interop driver used `tests/interop/m1_bulk.sh`,
  `m1_httpd.sh`, `m1_http_get.sh`, `m1_udp_icmp.sh`, and
  `m1_linux_ref.sh`, then rendered the case matrix with `m1_matrix.sh`.
  Retained case logs and captures are in `utcp-data:/m1-accept-interop/`
  and `utcp-data:/m1-accept/tb1/`. The published matrix identifies the
  source by run, the three Linux option toggles, PMTU and HTTP cases,
  and incomplete historical packet records.
  [Original interop matrix and commands](../../INTEROP.md)
- Runs 2, 3b and 4 and part of run 3 have overwritten captures.
  The successful public HTTP checks were historically observed and do
  not establish current site availability. The retained D-SACK sweep
  matched 26 of 27 replays in its archived batch. Both run8 and run9
  retained one-count discrepancies in their separate exact checks.
  [D-SACK case](../m3-sim/dsack-capture-counts.md)

## M2 integration and qualification

- The Gen5 strict run at `9b1ce4e8` counted 99,989 passing verdicts and
  11 pacing violations. The fix was `e00dccd`. The retained integrated
  sweep at `53589595609e9d98b952f106fee32a0842d0c748` has all 100,000
  recorded checker verdicts for seeds 0–99,999 under
  `utcp-data:/m2/m2-integrate/53589595609e9d98b952f106fee32a0842d0c748/100k/`.
  Checker success includes allowed non-delivery outcomes. The source trees
  and independent saved replay claims are documented with the results.
  [Strict sweep and persist case](../../SIM-BUGS.md#gen-5-strict-sweep)
- `tests/interop/m2_drops.sh` ran the 40 directed loss traces on the
  integrated runtime. Its original data are under
  `utcp-data:/m2/m2-integrate/5bd13159f8412786d8f619848ac24d0aa19a1641/drops-attempt-1/`.
  The compact archive includes the endpoint and ACK ledger inputs, plus
  the original per-file index. Three physical captures per transfer remain
  separately in the original root. The committed
  [40-entry ACK ledger](../m2-integrate/ack-decisions.jsonl.gz) preserves the
  decoded ACK and send decisions. [Cases, runtime and acquisition](../../RESULTS.md#directed-losses-on-the-integrated-runtime)
- The original bulk interop command was
  `M1_PROFILE=linux M1_CC=cubic tests/interop/m1_bulk.sh A-N1-s2l A-N1-l2s A-N4-s2l A-N4-l2s`.
  Four reported 1,000,000,000-byte transfers matched the independently
  generated payload digest. The two directions' packet captures remain
  under `utcp-data:/m2/m2-integrate/5bd1315-4gb/a1/`. Its compact
  endpoint and decoder inputs are kept in the adjacent `evidence/` directory.
  Both M2 integration compact SHA-256 values and the historical sweep
  summary are in the [historical volume manifest](historical-volume.sha256).
  [Original bulk evidence](../../INTEROP.md)
- The earlier November 14 gates on `d713941` passed 66/67. The
  one-slot diagnostic on `8facd285` passed 67/67 and lacks a peer-slot
  gate and proof. The two later paired qualification families, with their
  distinct keys, are linked from the [replay entry point](README.md#m2-measurement-archives).
  [Calibration chronology](../../RESULTS.md#calibration)

## M3 validation

| Work | Surviving record | Historical result and limits |
| --- | --- | --- |
| Simulator builds and corpus | `utcp-data:/m3-sim-validation/22b7cf3-attempt-1/`, with `build.log`, compiler caches, executable fingerprints and exit. [Build and corpus commands](../m3-sim/README.md#initial-build-and-corpus-receipt) | Production source `22b7cf3`, launcher `00d8722`, 20/20 entries each in `gcc-sweep` and `gcc-asan`. Gen6 launch failed before a counted shard, leaving 0 of 1,000,000 new seeds. The 2,000 serialized replay comparisons and independent captures were unexecuted. |
| Valid-wire and receive-stream model | `~/Desktop/utcp-wt/m3-wire-reference/build/m3-wire-reference-proof.tar.gz`, with source, compiler, per-seed XML and count validator. [Presets, seeds, run command and archive hash](../m3-fuzz/VALID_WIRE_STREAM.md#reproduction-on-ubuntu) | Four seeds at scale 1,024 on base `22b7cf3` with property changeset `9ff87ce`; 1,572,864 valid IPv4 datagrams across TCP, UDP and ICMP and 65,536 streams compared to a naive reassembler. Focused CTest 83/83. Sustained arbitrary-input parser validation was unexecuted. |
| Packetdrill | `~/Desktop/utcp-wt/m3-packetdrill-verify-1.zNTrFT/logs/`. [Command and adapter scope](../m3-packetdrill/README.md#run) · [Upstream, header and executable identities](../m3-packetdrill/verification.md) | Base `22b7cf3`, upstream Packetdrill `15ab46aedd01a5e664ec5cfb2b1888328cdd3901`, frozen Ubuntu image and GCC 15.2. Active and passive IPv4 cases passed twice each in both invocations. Each invocation rejected both expectation controls. The captured run used adapter changeset `9e0d689`. |
| Integrated stock and focused checks | `~/Desktop/utcp-wt/m3-integrated-verify-1.sesTG9NP/` has full stock CTest, independent Packetdrill and focused Clang sanitizer checks. [Integrated results](../../RESULTS.md#m3-validation) | Accepted validation source `da05184`. The report records 8,607 stock CTest passes, 520 matching simulator digests, two matching harness digests, and focused CTest 83/83. |
| Historical cases | [Persist pacing](../m3-sim/persist-pacing.md) · [D-SACK capture counts](../m3-sim/dsack-capture-counts.md) | The saved Gen5 pacing seed and directed test passed after the fix. A later same-input capture at the exact fix source pairs with the original failure capture; the historical passing sweep retained no capture for that seed. The retransmitted-SYN accounting fix reproduced the original D-SACK regression, with the two later one-count discrepancies retained. |

The [host file hash index](historical-workdirs.sha256) is relative to
`~/Desktop/utcp-wt`. The [volume file hash index](historical-volume.sha256) is
relative to the evidence mount. These indices carry selected original records
and are distinct from the capture-free M2 and M4 replays.
