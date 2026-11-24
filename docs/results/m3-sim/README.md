# M3 simulator validation

The initial simulator builds and their corpus checks ran on `main` at
`22b7cf30961cffb4b456c01aafb8c662f404212d` and passed. The stock Gen6
campaign on November 23 covered all 1,000,000 seeds: it found one sender
bug, and after the fix every seed passed and all 2,000 registered replays
matched. [Campaign summary](#stock-gen6-million-seed-campaign)

## Initial build and corpus receipt

The build started at 2026-11-20 19:04:40 UTC and finished at `2026-11-20T19:24:10Z`.
The archived `build.exit` is `0`. The build script provenance is
`00d8722fb5a4829261fd597f52bc1d7ff5ce033a`, with production source equal to
the pinned main outside this study directory. Ubuntu used GCC 15.2.0 and
CMake 4.2.3 in image
`sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66`,
on CPUs 16–23 at nice 10 with Docker network mode `none`.

For each preset, `build.sh` ran `cmake --preset PRESET`,
`cmake --build --preset PRESET`, and `ctest --preset PRESET -R 'sim[.]Corpus/'`.

| Preset | Build settings | Corpus pass count | Simulator SHA-256 |
| --- | --- | ---: | --- |
| `gcc-sweep` | Release, debug checks enabled | 20/20 | `22f1b98201bb6224b443d72231f3fb979312f53548afeba08becb749ec133584` |
| `gcc-asan` | Debug, ASan and UBSan | 20/20 | `e9e0f0c165390b77509abdfe3960fd5ae92b9f8398f26ee4714c8322ec84f79f` |

The build log, exit, provenance, CMake caches and compilation databases are
under `utcp-data:/m3-sim-validation/22b7cf3-attempt-1/`. The `build.log`
SHA-256 is `63871d9c73fece05a880feb4d891f4e80cf2f717c4524e5b5031a5f6e1e1d2e0`.

## Earlier Gen6 launch attempts

The first launcher returned Docker exit `125` with
`invalid reference format`. At `2026-11-20T19:24:51Z`, the temporary
`utcp-m3-sim-sweep` container held only its bootstrap Bash and sleep
processes. The initial attempt archive had no campaign shard records.

The subsequent stock runner launch started and exited at
`2026-11-20T19:27:07Z` before writing a counted shard. On Ubuntu,
`~/Desktop/utcp-wt/m3-stock-transfer/launch.exit` contains `1`.
The corresponding `launch.log` ends with `mkdir: Permission denied`.
Its SHA-256 is
`a48b7d122b5203112d598e8867c177c95e7e16d2179cf3d9c9e49adfc15725af`.

Neither attempt counted a seed. The campaign below replaced them.

## Stock Gen6 million-seed campaign

On November 23 the stock Gen6 generator (`--gen-version 6 --nodes stack
--strict-fast-rexmit`, unchanged `test_isn` and `renege_ppm` values) ran
seeds `[0, 1000000)` in 1,000 receipted shards, with a serialized replay of
every seed divisible by 500 that records a trace and both nodes' egress and
ingress captures.

| Source | Seeds | Verdicts | Replays |
| --- | ---: | --- | --- |
| `51275cc` (before the fix) | 1,000,000 | 999,998 `ok`, 2 `inflight` (seeds 572545 and 969096) | 2,000 registered and 2 failure replays matched |
| `fc46829` (after the fix) | 1,000,000 | 1,000,000 `ok` | 2,000 registered replays matched |

Both failures were real: a BBR ACK cut cwnd from 10 to 8 packets while 9
were in flight, and the next probe timeout sent a new-data tail-loss probe
that raised flight to 10. `LossRecovery::on_pto` now retransmits the last
segment when flight already exceeds cwnd. A unit regression fails on the
old sender and passes on the new one; no checker rule changed. TShark found
zero Error-severity expert items in all 8,008 and 8,000 replay captures.
The passing rows comprise 996,398 complete transfers, 3,328 partial
transfers and 274 runs with no payload delivered; these are legal outcomes
under the campaign's checkers and are counted apart from the verdicts.

An independent review rebuilt the corrected source, rescanned every shard
and replay receipt, reran five seeds including both former failures, and
found 3A PASS (every seed, zero failures) and 3B PASS (all registered
replays). [Development receipt](stock-gen6-2026-11-23.md) ·
[Independent acceptance](stock-gen6-acceptance.md)

A separate defensive normal-session profile, which clears the generator's
`test_isn` and `renege_ppm` node controls, ran the full range before the fix and failed on the same two seeds;
both pass on the fixed source. [Defensive profile and status](defensive-gen6.md#status)

## Historical diagnostics

These two cases use retained Gen5 and M1 evidence from earlier work.

- Positive-window persist pacing. A new same-input, exact-fix-source
  capture now pairs with the original failure capture; the original passing
  sweep itself retained no capture for this seed. [Case notes](persist-pacing.md)
- D-SACK capture replay and SYN retransmissions. The replay corrected the
  original case, and `run8` and `run9` still differ by one dubious D-SACK
  each. [Case notes](dsack-capture-counts.md)
