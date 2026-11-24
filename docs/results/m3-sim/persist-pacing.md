# Positive-window persist pacing

## Retained corpus input and Gen5 observation

SB-0011 came from the historic strict Gen5 sweep at
`9b1ce4e8cce0fbd10886cb4d3b3f0577212099c0`. For seed 14042, both recorded
runs and the saved-file replay returned `pacing`, one violation, 61 simulator
events, 39 packets, and digest `7354b15a6a08881e`. The diagnostic was
`ordinary paced payload missing gate rate`. The archived `scenario.txt` is
byte-identical to the [current corpus input](../../../tests/sim/corpus/sb-0011-14042.scenario).
Its SHA-256 is `a2374970794a534e426f64ea1493bdefe024e91a53ecbb29c9c8efa505e78189`.

| Simulator time (ns) | Retained evidence |
| ---: | --- |
| 393657667437 | Node B's last preceding paced send was a 1,448-byte retransmission. The trace recorded a 285,895 B/s gate rate. |
| 393660199835 | The archived burst reconstruction places the preceding earliest departure time (EDT) here, after 15 prior payload packets and zero earlier gated-burst violations. |
| 393699893181 | Node B armed persist while the advertised send window was 896 bytes. |
| 393942320047 | Persist fired and the trace recorded a new 896-byte send with `gate_rate=0`, `burst_start=false` and a recorded pacing rate of 286,686 B/s. Frame 20 in `b.egress.pcap` shows the same timestamp, payload length and sequence number 1143593223. |

The trace and packet decode agree on the departure, which was 282.120212 ms
after the reconstructed EDT. The measured violation in seed 14042 was the
missing gate metadata. The packet capture supplies departure time and TCP
payload length. The pacing gate and reconstructed EDT come from the trace.

## Change and verification

The positive-window branch in `on_persist` sent new payload directly when
persist overrode sender silly-window avoidance. Commit
`e00dccd57776e4ff4f1de1e2eb61d2de75c498d1` makes the scheduled persist
deadline respect EDT for gated traffic, records the rate and burst marker,
and advances EDT after a successful send using the number of bytes sent.

At that commit, the retained row for the same Gen5 seed passed with zero
violations, 103 events, 61 packets and digest `cab9382f5ea6b5db`. A wrote
3,709 bytes and B received all 3,709. B wrote 32,877 bytes and A received
all 32,877. The saved corpus input also passed in the current M3
`gcc-sweep` and `gcc-asan` corpus logs. The archived post-fix Gen5 row
supplies a verdict and byte totals. That original sweep did not retain a
capture for seed 14042. A new same-input capture at the exact fix source
commit is recorded below.

The archived `TcpZeroWindow.PositivePersistWindowHonorsAndAdvancesEdt`
test isolates the scheduling change using the same scripted peer, 300-byte
window and fixed 100 B/s pacing rate on the old and restored timer
implementations. With ten warm segments the previous EDT is 10 virtual
seconds after the start. The old implementation emitted data before that
deadline, including in the full-queue variant. With nine warm segments
the old implementation also emitted the successor before the deadline
the 300-byte send should have charged. The restored test passed all three
variants. These are measurements from the directed fixture.

## Same-input packet pair acquired later (2026-11-23)

This is a new reproduction, **not** a capture from the original 100,000-seed
post-fix sweep. That sweep sampled passing seeds divisible by 500, so it kept
only the verdict row for 14042. The preserved pre-fix artifacts remain at the
baseline volume path below. The post-fix run used source commit
`e00dccd57776e4ff4f1de1e2eb61d2de75c498d1` in the isolated worktree
`~/Desktop/utcp-wt/m3-3f-paired-capture-dev-n23/`. Its GCC 15.2.0
`gcc-sweep` build was Release with `UTCP_DCHECKS=ON`; the newly built
`utcp-sim` SHA-256 is
`eb82a40a5387787278566804a224efc7c2c62c4fb0d93820eaf14da5d3c9d26b`.
The historical executable's recorded hash is
`398be2637ceb9e4637f4bf574e8cfd64b88976ff789cc071799b839b5085bcd4`,
but that executable was no longer present at its recorded path. This is the
same source commit and serialized input, with a separately built executable.

Both a generated `--seed 14042 --gen-version 5 --nodes stack
--strict-fast-rexmit` run and a `--scenario` replay of the saved corpus file
wrote traces and four captures, one ingress and one egress at each node.
Both returned `ok`, zero violations, 103 events, 61 packets, digest
`cab9382f5ea6b5db`, and complete 3,709/32,877-byte transfers. All result
fields except wall time match the original post-fix sweep row (row SHA-256
`a6a2652ebf16a8bb1ca997ab26123a0a933556137fa72263ec36d9bd64dc56dc`).
The generated and saved-file runs also have byte-identical scenario, trace and
all four PCAP files. Their scenario SHA-256 is the original
`a2374970794a534e426f64ea1493bdefe024e91a53ecbb29c9c8efa505e78189`.

| Raw file | Pre-fix SHA-256 | New post-fix SHA-256 |
| --- | --- | --- |
| `a.egress.pcap` | `b442f9b838069dbb9e0ee1902eb62d22ff7a953be730ad47ddf7210c749065be` | `0d8088e8bd82b87b04c7807bfdd62a878e5936ad2def71e92cf25640c559bac6` |
| `a.ingress.pcap` | `1c2ccf880d364b495de65891224c3ac66b241eb3813f005140a69409e2dc54ea` | `e9a83a13dbdf274200b2d585393cd7c30e8c0589b76ba0b7f765a620e83603cd` |
| `b.egress.pcap` | `0f34fe8e90c3fd0f32b0861b32a9ecd4784552f9bbd71b37d5173ff05b3fa0c9` | `8bdc80e5e02e2c466ae62b6110e0e76568df5749ffe44f8b44b9c29a242069d2` |
| `b.ingress.pcap` | `2ba601dac7446fdddb1de142d6428588aaa9fc4bc7d90fbdbdcf5183d8c5372a` | `2cc81612690bfcf2345e5894cde35128d717d91088b99d66edbf419224c84c39` |
| `trace.jsonl` | `c8ed5830daced18417a33716d0b550d37beca8b831eb5926a168522e21bc2e44` | `f26a132b0fb2c8c38bfe7ca73d49e0fe425f6a4d3892a2fab8a087fb4569f09d` |

All four pre-fix PCAP files are exact byte prefixes of the corresponding new
post-fix files: the original run stopped at its first checker violation.
Frame 20 of B's egress capture in both runs is the same 896-byte packet,
sequence `1143593223:1143594119`, at PCAP time `393.942320` seconds. The
first trace difference is line 153, at `393942320047` ns, for that packet:
`gate_rate=0`, `burst_start=false` before; `gate_rate=286686`,
`burst_start=true` after. The post-fix trace records the same departure time,
not a delayed departure in this seed. The capture proves packet identity and
time; only the trace records pacing metadata. The directed timer test cited
above is the evidence for earlier-send prevention when EDT is later.

The new raw data, including copies from the read-only original volume, is in
`~/Desktop/utcp-wt/m3-3f-paired-capture-artifacts-n23/`. `pre-fix-copy/`
holds the original copy; `seed-run/seed-14042/` and
`file-run/seed-14042/` hold the four post-fix PCAPs and scenario;
`seed-run/trace.jsonl` and `file-run/trace.jsonl` are their traces.
`SHA256SUMS` hashes 22 raw files and has SHA-256
`c1cb253b2a1c4026f746a7f756b4fa1c7a99712e15761ff06fbe5b86650d0dda`.
The post-fix `seed-run/result.jsonl` SHA-256 is
`b14aeafab5956c11550e3b303fa783d0029378d4adfa4bcf126f0d813540f7bd`.
The new capture supplements the original result row; it does not convert the
historical sweep into a capture-bearing run.

Reproduction commands, with `repo` and `out` set to the two paths above:

```sh
cd "$repo"
taskset -c 16-19 nice -n 10 cmake --preset gcc-sweep
taskset -c 16-19 nice -n 10 cmake --build --preset gcc-sweep -j4 --target utcp-sim
sim="$repo/build/gcc-sweep/apps/utcp-sim/utcp-sim"
taskset -c 16-19 nice -n 10 "$sim" --seed 14042 --gen-version 5 --nodes stack --strict-fast-rexmit --pcap "$out/seed-run" --trace "$out/seed-run/trace.jsonl" --jsonl "$out/seed-run/result.jsonl"
taskset -c 16-19 nice -n 10 "$sim" --scenario "$repo/tests/sim/corpus/sb-0011-14042.scenario" --strict-fast-rexmit --pcap "$out/file-run" --trace "$out/file-run/trace.jsonl" --jsonl "$out/file-run/result.jsonl"
```

## Evidence on Ubuntu

- Original capture, trace, serialized scenario and repeat verdicts are in
  `utcp-data:/m2/m2-integrate/9b1ce4e8cce0fbd10886cb4d3b3f0577212099c0-baseline/100k/failures/seed-14042/`.
  The archived reconstruction and its output are `reconstruct.py` and
  `initial-edt.jsonl` at the baseline root.
- `b.egress.pcap` SHA-256 is
  `0f34fe8e90c3fd0f32b0861b32a9ecd4784552f9bbd71b37d5173ff05b3fa0c9`.
  `trace.jsonl` SHA-256 is
  `c8ed5830daced18417a33716d0b550d37beca8b831eb5926a168522e21bc2e44`.
- The passing seed row is in
  `utcp-data:/m2/m2-integrate/e00dccd57776e4ff4f1de1e2eb61d2de75c498d1/100k/results.jsonl`.
  The directed before/after logs are `persist-old.log` and
  `persist-restored.log` in
  `utcp-data:/m2/m2-integrate/53589595609e9d98b952f106fee32a0842d0c748/controls-a2/`.
  [Simulator bug record](../../SIM-BUGS.md)
