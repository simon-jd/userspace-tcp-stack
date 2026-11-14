# Simulator bugs

Every invariant violation the simulator sweeps found (DESIGN §7.3, §7.4), with its root cause and fix, and the
tshark expert analysis of the sampled seeds. Each entry found by a simulator checker or the sweep's limits has its
dumped scenario in `tests/sim/corpus/` as `<entry>-<seed>.scenario`; CI replays each of them as its own test
(`sim.Corpus/SimCorpusEntry.Passes/*`). Entries found by the tshark check have no corpus file (see sb-0010).

## Violations

| Entry | Seed | Found by | Checker | Symptom | Root cause | Fixing commit |
|---|---|---|---|---|---|---|
| sb-0001 | 5 | m1-tcp-core sweep | InFlightChecker | data sent past the peer's window | an ACK that advanced SND.UNA with an older SEQ did not update SND.WND | dddacee |
| sb-0002 | 209 | m1-tcp-core sweep | hang | the run did not finish | the walk over lost segments did not stop after the last lost segment | ed50a9c |
| sb-0003 | 3106 | m1-tcp-robust 1e4 sweep | TerminationChecker | RST received in CLOSE-WAIT reported as an illegal end | checker: the peer's orphan FIN-WAIT-2 timeout followed by an RST to our next segment is a legal end (Linux frees the orphan after `tcp_fin_timeout`) | 6999c42 (checker) |
| sb-0004 | 5582 | m1-tcp-robust 1e4 sweep | TerminationChecker | as sb-0003 | as sb-0003 | 6999c42 (checker) |
| sb-0005 | 6144 | m1-tcp-robust 1e4 sweep | TerminationChecker | as sb-0003 | as sb-0003 | 6999c42 (checker) |
| sb-0006 | 13775 | m1-accept-sweep 1e5 sweep 1 | timeout (sweep wall-clock limit, 120 s) | the seed ran past 120 s; the sweep's two replays did too | a `nodelay` sender writing 1-7 bytes per `tcp_send` kept one TxSeg per buffered byte in flight, because the send buffer counted payload bytes only (seed 73713: 102040 one- and two-byte segments in flight, cwnd 204080); `Stack::debug_check` walks every TxSeg after every call, so the run took 130-600 s | 76ee00a |
| sb-0007 | 34664 | m1-accept-sweep 1e5 sweep 1 | timeout | as sb-0006 | as sb-0006 | 76ee00a |
| sb-0008 | 73713 | m1-accept-sweep 1e5 sweep 1 | timeout | as sb-0006 | as sb-0006 | 76ee00a |
| sb-0009 | 81519 | m1-accept-sweep 1e5 sweep 1 | timeout | as sb-0006 | as sb-0006 | 76ee00a |
| sb-0010 | 76 sampled seeds (listed below) | m1-accept-sweep tshark run 1 | tshark expert (`tools/tshark_expert.sh`, rule below) | Error-severity items in 149 of the 654 files checked, all Malformed/Protocol items of RSL, GSM over IP, A-bis OML, LBMSRS, SCCP, GSM DTAP, H1, GSUP, LBT-TCP and GSM Cell Broadcast; none in IPv4, ICMP, TCP or UDP | checker: TShark decoded the simulator's byte-pattern TCP payload as application protocols, by port (`tcp.port 5000` → `gsm_ipa`) and by heuristics (`lbmsrs_tcp`, `lbttcp_tcp`, `hi_tcp`); TCP payload is opaque application data (RFC 9293 §2.2) and a port number does not identify the protocol carried (RFC 7605 §5, §7.1) | 6519c25 (checker) |

sb-0006..sb-0009 in detail. A timeout gives no digest, so each seed was replayed twice without the wall-clock
limit (`utcp-sim --seed N`, gcc-sweep build): both runs ended with verdict `ok` and the same digest and event
count (13775: `4e16962578aa72e2`, 12469858 events, 146-166 s; 34664: `52a25857f8d88a0a`, 8257408, 130-148 s;
73713: `daa3948b7a461daa`, 9081122, 546-600 s; 81519: `2476dfcdd52efd7e`, 14400099, 359-394 s). Stack samples of
seed 73713 taken with gdb (25 of 25) were all in `SendQueue::check_invariants` under `Stack::debug_check`. The
stack was correct but held per-segment metadata for every buffered byte. Linux charges each skb its truesize
to the send buffer (`sk_wmem_queued`), so tiny segments fill it long before their payload does. The fix
(76ee00a, DESIGN §4.11) charges the TxSegs held at least `mss_cache`/2 each (`SendQueue::held`); full-sized
segments still count as their payload. After it the four seeds take 7-17 s (gcc-sweep) with verdict `ok`. Tests:
`SendQueue.SegChargeCountsSmallSegments`, `TcpTransfer.OneByteWritesHoldFewSegments` (fails without the charge),
`TcpTransfer.OneByteWritesStayUnwritableUntilChargeHalves` (the writable rule in `tcp_readiness` and for
`ev_writable` uses the charged space, as `sk_stream_is_writeable` uses `sk_wmem_queued`; fails if either rule
counts payload bytes only).
Under gcc-asan the four corpus entries take 390-820 s each, so dbbd47c runs each corpus entry as its own test.

sb-0010 in detail (tshark run 1 below). Seeds with an Error item (all `seed % 500 == 0` of sweep 2, code dbbd47c):
1500 2000 2500 3000 4000 5000 7500 9500 10500 11500 12500 13500 14000 16500 17000 18500 19500 22000 22500 25500
26000 26500 27000 29000 29500 30000 31500 32000 34000 35500 40500 41500 43500 45000 45500 46000 47000 47500 48000
48500 49500 50000 51000 54500 56000 58000 59500 61500 62000 63000 63500 64000 66500 67000 67500 68000 68500 69500
71000 74000 74500 77500 78500 80000 80500 82500 84000 86000 86500 89000 89500 91500 92000 97000 97500 98000.
Files: 49 `a.egress`, 42 `b.egress`, 26 `a.ingress`, 32 `b.ingress` (149). Every one of these seeds had verdict
`ok` in sweep 2, so a corpus replay would not exercise the tshark check; the regression tests are
`SimPcap.ExpertScriptIgnoresPayloadDissectors` (the 6-byte payload that reproduces the RSL error) and
`SimPcap.ExpertScriptFailsOnBadTcpChecksum` (the narrowed check still fails on an Error in the stack's layers).

## 1e5-seed acceptance sweep (m1-accept-sweep, test F)

Command (server, `gcc-sweep` build, CPUs 16-31):

    tools/sim_sweep.py --seeds 0:100000 --jobs 8 --asan-sim build/gcc-asan/apps/utcp-sim/utcp-sim --out DIR

Every failing seed is replayed twice by the sweep (identical digest, or for a crash the rolling digest and event
count, required before a fix) and once under the ASan/UBSan build.

| Run | Code | Seeds | Result | Wall time |
|---|---|---|---|---|
| sweep 1 | 6cbff02 (main) | 0:100000 | 99996 `ok`, 4 `timeout` (13775, 34664, 73713, 81519: sb-0006..sb-0009) | 928 s |
| sweep 2 | dbbd47c | 0:100000 | 100000 `ok`; no timeouts, crashes or replay mismatches; slowest seed 26060, 29.9 s | 725 s |

Total seeds run in this task: 200000 (two full runs), plus the replays above.

## tshark expert analysis

Rule (acceptance test G, fixed before the run):

- Input: the pcaps that `tools/sim_sweep.py` writes for the sampled seeds (`seed % 500 == 0`, 200 seeds in
  0:100000) of the final, clean 1e5-seed run, in `DIR/samples/seed-N/`.
- Command: `tools/tshark_expert.sh DIR/samples`, run in the `utcp-testbed:dev` image (TShark 4.6.4).
- Files checked: every `*.egress.pcap` (before link impairment); the `*.ingress.pcap` files only of seeds whose
  scenario has `bitflip_ppm` and `garbage_ppm` 0 on every link, because bit flips and garbage produce malformed
  frames on ingress by design.
- Pass: every file is readable and no file has an Error-severity expert item. An Error item is investigated like
  an invariant violation: root cause, fix in the stack (or evidence that the dissector is wrong), and an entry in
  the table above.
- Warning-severity items do not fail the check; they are counted by type (group, protocol, summary) below.

### Run 1 (sweep 2 samples, rule as above)

`tools/tshark_expert.sh` as of 6cbff02 (`tshark -n -r FILE -q -z expert`, every dissector on) on
`sweep2/samples`: 654 files checked (146 ingress files of impaired seeds skipped), exit 1. 149 files of 76 seeds
had Error-severity items, all in dissectors above TCP and none in IPv4, ICMP, TCP or UDP:

| Count | Group | Protocol | Summary |
|---|---|---|---|
| 20941 | Malformed | RSL | Malformed Packet (Exception occurred) |
| 1452 | Malformed | GSM over IP | Malformed Packet (Exception occurred) |
| 875 | Malformed | A-bis OML | Malformed Packet (Exception occurred) |
| 461 | Malformed | LBMSRS | Malformed Packet (Exception occurred) |
| 65 | Malformed | SCCP | Malformed Packet (Exception occurred) |
| 62 | Malformed | GSM DTAP | Malformed Packet (Exception occurred) |
| 6 | Malformed | H1 | Malformed Packet (Exception occurred) |
| 3 | Protocol | GSM DTAP | Missing Mandatory element (0x2c) Keypad Facility, rest of dissection is suspect |
| 3 | Malformed | GSUP | Malformed Packet (Exception occurred) |
| 2 | Malformed | LBT-TCP | Malformed Packet (Exception occurred) |
| 2 | Malformed | LBT-TCP | Invalid LBMC header type 0x66 |
| 2 | Malformed | GSM Cell Broadcast Service | Malformed Packet (Exception occurred) |
| 1 | Protocol | GSM DTAP | Missing Mandatory element (0x04) Bearer Capability 1, rest of dissection is suspect |

Root cause: the dissector, not the stack. TCP payload in the simulator is the generator's byte pattern
(DESIGN §7.2), not an application protocol, but TShark 4.6.4 decodes it by port and by heuristics: `tshark -G
decodes` lists `tcp.port 5000 gsm_ipa` (the IPA dissector, which hands the bytes to RSL, A-bis OML, GSM DTAP,
SCCP and GSUP), and `tshark -G heuristic-decodes` lists the TCP heuristics `lbmsrs_tcp`, `lbttcp_tcp` and
`hi_tcp` (H1), all enabled. The workload's server ports are 5000-5007. The 6-byte payload `00 40 00 08 01 02` to
port 5000 gives the same RSL error (`SimPcap.ExpertScriptIgnoresPayloadDissectors`).

Why the dissector is wrong here. RFC 9293 §2.2: "TCP provides a reliable, in-order, byte-stream service to
applications. The application byte-stream is conveyed over the network via TCP segments"; the stack carries the
application's bytes and gives them no meaning, so it cannot be at fault for what the payload decodes to. The
simulator's application writes the generator's byte pattern, not IPA, RSL or LBM. The decoding by port is an
observer's guess that the RFCs on port numbers say is unreliable: RFC 7605 §5, "any interpretation of port numbers
-- except at the endpoints -- may be incorrect, because port numbers are meaningful only at the endpoints", and
§7.1, "an assigned port number is not a guarantee of exclusive use. Traffic for any service might appear on any
port number". The heuristic dissectors guess from the content, and that content is the byte pattern. The
Error items are therefore TShark's reading of payload as a protocol it is not, not a fault in the IPv4, ICMP, TCP or
UDP the stack produces; those layers had no Error item in run 1 either.

Change (amended rule, committed before run 2): `tools/tshark_expert.sh` dissects only the layers the stack
produces, `--only-protocols frame,raw,ip,icmp,tcp,udp,data`, and validates the checksums those layers carry
(`-o ip.check_checksum:TRUE -o tcp.check_checksum:TRUE -o udp.check_checksum:TRUE`; off by default in TShark).
Everything else in the rule above stays. The check still fails on an Error in the stack's layers:
`SimPcap.ExpertScriptFailsOnBadTcpChecksum` writes a segment with a wrong TCP checksum and expects exit 1 with
"Bad checksum"; with the 6cbff02 script that test fails (checksums not validated), as does
`ExpertScriptIgnoresPayloadDissectors`.


### Run 2 (sweep 2 samples, amended rule)

`tools/tshark_expert.sh` as of 6519c25 on the same `sweep2/samples` (TShark 4.6.4, `utcp-testbed:dev`): 654 files
checked (400 egress, 254 ingress; 146 ingress files of seeds with bit flips or garbage skipped), every file
readable, **0 Error-severity items**, exit 0. Warnings by type:

| Warning (group, protocol, summary) | Egress | Ingress | Total |
|---|---|---|---|
| Sequence, TCP, Previous segment(s) not captured (common at capture start) | 3 | 9519 | 9522 |
| Sequence, TCP, D-SACK Sequence | 1020 | 788 | 1808 |
| Sequence, TCP, TCP Zero Window segment | 1118 | 509 | 1627 |
| Sequence, TCP, Connection reset (RST) | 600 | 254 | 854 |

The TCP warnings are the same in run 1. "Previous segment(s) not captured" on ingress follows the link's
losses. The three on egress (seed 47500 `b`, seed 74000 `a` twice) are pure ACKs sent after our FIN whose SEQ is
the FIN's sequence number + 1, which is SND.NXT once the FIN is sent (RFC 9293 §3.4); TShark's sequence
analysis flags them, the stack is right. D-SACK, zero-window and RST segments are part of the generated workloads
(duplication and retransmission, paused readers, aborts and connections to closed ports).
