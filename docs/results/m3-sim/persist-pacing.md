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
supplies a verdict and byte totals. A matching post-fix capture for that
seed remains unverified.

The archived `TcpZeroWindow.PositivePersistWindowHonorsAndAdvancesEdt`
test isolates the scheduling change using the same scripted peer, 300-byte
window and fixed 100 B/s pacing rate on the old and restored timer
implementations. With ten warm segments the previous EDT is 10 virtual
seconds after the start. The old implementation emitted data before that
deadline, including in the full-queue variant. With nine warm segments
the old implementation also emitted the successor before the deadline
the 300-byte send should have charged. The restored test passed all three
variants. These are measurements from the directed fixture.

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
