# M3 simulator validation

The production simulator source is private main
`22b7cf30961cffb4b456c01aafb8c662f404212d`. The initial builds and their
corpus checks passed. The Gen6 long-run acceptance remains open with
**0 of 1,000,000 newly counted seeds**.

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

## Gen6 long-run outcome

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

The long-run evidence still lacks unique coverage of the target seed
range, per-seed verdicts and application-delivery outcomes, the 2,000
serialized replay comparisons, and the independent capture checks.

## Historical diagnostics

These two cases use retained Gen5 and M1 evidence from earlier work.

- Positive-window persist pacing. A new same-input, exact-fix-source
  capture now pairs with the original failure capture; the original passing
  sweep itself retained no capture for this seed. [Case notes](persist-pacing.md)
- D-SACK capture replay and SYN retransmissions. The replay corrected the
  original case, and `run8` and `run9` still differ by one dubious D-SACK
  each. [Case notes](dsack-capture-counts.md)
