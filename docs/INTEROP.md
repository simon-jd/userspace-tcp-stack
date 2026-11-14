# Interop evidence (M1)

The M1 interop acceptance runs (DESIGN §11): the stack (`--backend utcp`, profile
`linux`) against Linux 7.0 on the `testbed/m1` testbed. Each case is one row of the
matrix below. Goodput and durations in this file are non-timing: the containers run
on the shared build CPUs, and nothing here is a performance result.

## How the runs were made

```
testbed/m1/build.sh gcc-release utcp-bulk utcp-echo utcp-httpd utcp-http-get backend_transport_check
M1_RESULTS=$PWD/.logs/RUN tests/interop/m1_bulk.sh        # A, B, C
M1_RESULTS=$PWD/.logs/RUN tests/interop/m1_httpd.sh       # D
M1_RESULTS=$PWD/.logs/RUN tests/interop/m1_udp_icmp.sh    # H
M1_RESULTS=$PWD/.logs/RUN tests/interop/m1_http_get.sh    # E
M1_RESULTS=$PWD/.logs/RUN tests/interop/m1_linux_ref.sh   # Linux->Linux reference
tests/interop/m1_matrix.sh .logs/RUN                      # the tables below
M1_RESULTS=$PWD/.logs/RUN tests/interop/m1_apps_retrans.sh 3   # m1-apps test 7, kernel only
```

Each runner starts the testbed if needed (`testbed/m1/up.sh`), takes `PATTERN...` to
run a subset, and writes per case `.logs/RUN/<case>/` in the work directory: `testbed/m1/record.sh` output before
and after (the peer's `nstat -asz`, `ip tcp_metrics show`, `ip -s link show utcp0`,
`tc -s qdisc`, offloads), the programs' JSON output, the stack's counters (`--stats`),
capture summaries, and `row.json`; `RUN/rows.jsonl` collects the rows. Before every
case the peer runs with `net.ipv4.tcp_no_metrics_save = 1`, and the row checks that
`ip tcp_metrics show` was empty. The captures of a run go to
`utcp-data:/m1-accept-interop/RUN/<case>/` (`M1_VOLDIR`, default `m1-accept-interop/RUN`;
`row.json` records it as `captures_dir`), so a later run does not replace them.

The work directory is not kept. Each run's `.logs/RUN/` (every `<case>/` directory with the
`record.sh` output before and after, `row.json`, `dsack.json`, `stack-stats.json`,
`extra.json` and the capture summaries, and the run's `rows.jsonl`) is copied to
`utcp-data:/m1-accept-interop/logs/RUN/`, and the runner logs (`RUN-*.log`) and run scripts
to `utcp-data:/m1-accept-interop/logs/top/`. `tests/interop/m1_matrix.sh` over the copied
directories prints the same tables.

The runs, on 2026-11-14 (the `Run` column of the matrix says which run a row is from):

| Run | Commit | What | Used in the matrix | Captures |
|---|---|---|---|---|
| run2 | 8834aae | all cases | no (found the H-udp, E and paused-reader issues) | none left (replaced by later runs) |
| run3 | 84c031d; the reference rows from the working tree later committed as 5060a88 (below) | all cases and the Linux→Linux reference | reference rows except R-N0-l2l and R-N4-l2l | reference rows only |
| run3b | 84c031d | Linux→stack rows under N3/N4 with the D-SACK checks, E-neverssl.com | no | none left |
| run4 | 5060a88 | stack→Linux rows and D after 3fc5bb1 | no (B-sack1-ts1-ws0-s2l failed: fixed in 2441a7a) | none left |
| run5 | 5493eec | every stack case (A, B, C, D, E, H) with all fixes | stack rows not repeated in run6, except E-neverssl.com | all, except E-neverssl.com |
| run5b | 5493eec | E-neverssl.com again (run5 failed: below) | E-neverssl.com | yes |
| run6 | 484e628 | the rows whose checks changed after the review (A-ecn*, B, C) with the new checks, A-N4-l2s, R-N0-l2l, R-N4-l2l | those rows | yes |
| run7, run8 | 484e628 | A-N4-l2s and R-N4-l2l again (the `TCPSACKDiscard` spread, below) | no | yes |
| run9 | 1f93aa5 (replay counts SYN/FIN retransmissions; stack code as 484e628) | every row with the D-SACK replay checks: A-N4-l2s, A-N3-l2s, B-sack1-*-l2s | no (run5/run6 rows kept; same replay result over their captures) | yes |
| run10, run11 | 1f93aa5 | A-N4-l2s again | no | yes |

Up to run5b every run wrote its captures to `utcp-data:/m1-accept-interop/<case>/`,
and each run replaced the previous run's captures of the cases it ran. The ones left
were moved to `utcp-data:/m1-accept-interop/RUN/<case>/`: run3's reference rows,
run5's stack rows and run5b's E-neverssl.com. The captures of run2, run3b and run4, of
run3's stack rows and of run5's E-neverssl.com no longer exist; their summaries
(`pcap-*.json`) are in the logs. run6 and later runs keep their own.

run3's commit: 84c031d is the head the run started from, but the scripts were synced
during the run. The four `R-N4-100M-sack0-*` cases exist only in the `m1_linux_ref.sh`
of 5060a88 (05:54 PST, its only change), and their directories date from 05:26-05:29
PST, so run3's reference rows ran from the uncommitted working tree that became
5060a88. Its stack rows also used checks older than 84c031d's; they are not in the
matrix.

`tests/interop/m1_matrix.sh .logs/run3 .logs/run5 .logs/run5b .logs/run6` prints the tables
below (a later directory's row replaces an earlier one). The reference rows do not involve the
stack, so the stack fixes after run3 do not affect them. Between run5 (5493eec) and run6
(484e628) only the test scripts and the programs' tests changed (`main_` takes the transport
factory); the stack and the programs' behaviour did not.

### Testbed and CPU pinning

- `utcp-m1-dut` (the stack on `utcp0`, 198.18.0.2; the DUT kernel 198.18.0.1 forwards
  between `utcp0` and `utcp-m1-net`), `utcp-m1-peer` (Linux, 198.19.1.3), and for C the
  chain of `testbed/m1/pmtu.sh`: DUT 198.19.2.2 -- `utcp-m1-net1400` (MTU 1400) -- router
  `utcp-m1-r` -- `utcp-m1-netb` (MTU 1500) -- peer 198.19.3.4. The 1400-byte link is the
  DUT–router hop. So in C-pmtu-s2l the frag-needed comes from the DUT's own forwarding
  kernel (source 198.18.0.1, the stack's first hop: all 10 in run5 and in run6), and only in
  C-pmtu-l2s does the router generate it (source 198.19.3.3, to the peer). No case has
  the stack receive a frag-needed from a router further along the path; that needs the
  1400-byte link on the router–peer side.
- Every container (testbed, captures, tshark analysis) runs with `--cpuset-cpus 16-31`
  (E-cores, shared with other build work on the host); analysis containers also with
  `nice -n 10`. No run used CPUs 0-15. No result here is a timing measurement.
- Offloads: the peer's interfaces tso/gso off (one capture record is one segment), the
  DUT's forwarding interfaces gro off (`testbed/m1/common.sh`).
- Impairments (`testbed/m1/netem.sh`, netem `limit 20000`) on the DUT's egress of
  `eth0` (stack→Linux) and of `utcp0` (Linux→stack):
  N0 none, N1 `delay 1ms loss 1%`, N2 `delay 5ms reorder 10% 50%`, N3 `delay 1ms duplicate 2%`,
  N4 `delay 2ms loss 1% duplicate 1% reorder 5% 50%`.
- The Linux→Linux reference (`m1_linux_ref.sh`) puts a Linux receiver
  (`utcp-m1-accept-interop-ref`, 198.19.9.3, tso/gso/gro off) behind the DUT on a second
  network, with the same netem on both DUT egresses, so it takes the stack's place on
  the same forwarded path.

### Captures

tcpdump, 128-byte snaplen (headers only), in the Docker volume `utcp-data`; RUN is the
`Run` column of the matrix:

- `utcp-data:/m1-accept-interop/RUN/<case>/peer.pcap`: the peer's interface (A, B, C, the
  local E cases, R).
- `utcp-data:/m1-accept-interop/RUN/<case>/utcp0.pcap`: `utcp0` in the DUT (all stack cases;
  egress is captured after the netem qdisc, so duplicates and losses toward the stack
  are visible there).
- `utcp-data:/m1-accept-interop/apps7/apps-t7-<n>/lo.pcap`: m1-apps test 7 reproduction.
- `utcp-data:/m1-accept-interop/logs/RUN/`: the per-case files of each run (above).

The captures stay in the volume (read them with a container that mounts `utcp-data`,
e.g. `docker run --rm -v utcp-data:/data utcp-testbed:dev tshark -r /data/m1-accept-interop/run5/A-N0-s2l/peer.pcap`).

The tshark expert-analysis rule and its results are in
[SIM-BUGS.md, "tshark expert analysis"](SIM-BUGS.md#tshark-expert-analysis).

## Checks per row

Every check is a Python expression in the runner, evaluated by `tests/interop/m1_row.py`
over the deltas of the peer's `nstat -asz` (`peer[...]`), the stack's counters
(`stack[...]`), the capture summaries (`tests/interop/m1_pcap_summary.py`) and the
programs' output; `row.json` lists each check with its result. A row passes only if all
of its checks hold.

| Test | Checks |
|---|---|
| A, B, C (all) | SHA-256 and byte count equal on both ends; `fin_ok`: both sides sent a FIN, each was ACKed, and no RST except the answer to a segment that arrived after the close (see below); `ip tcp_metrics show` empty before; both programs exit 0; `TCPSACKReneging = 0`; `TCPSACKDiscard = 0`, except Linux→stack under N3 and N4 (below) |
| A Linux→stack under N3, N4 and the B rows (N4) | `TCPSACKDiscard` and `TCPDSACKIgnoredDubious` equal to the counts `m1_dsack.py` predicts from the peer capture; every predicted discarded block is a D-SACK for a segment the stack received twice (`utcp0` capture); every D-SACK the stack sent is one |
| A Linux→stack N1, N4 | `TCPSackRecovery > 0` |
| A Linux→stack N3 | `TCPDSACKRecv > 0` |
| A paused reader | stack→Linux: Linux advertised a zero window (capture), `TCPToZeroWindowAdv > 0`, the stack sender was receive-window limited; Linux→stack: the stack advertised a zero window (capture), the stack's `TCPToZeroWindowAdv > 0`, Linux's `tcpi_rwnd_limited > 0` |
| A ECN (peer `tcp_ecn` 1, 3) | at least one SYN or SYN-ACK of each side captured; no ECE/CWR/AE in the stack's SYN or SYN-ACK or in Linux's SYN-ACK, no ECN codepoint on any packet, no ECE/CWR after the handshake; Linux→stack: Linux's SYN carried ECE+CWR (it asked; the stack declined) |
| B | at least one SYN or SYN-ACK of each side captured; Linux's SYN/SYN-ACK carry exactly the enabled options; the stack's SYN offers SACK, timestamps and window scale, its SYN-ACK only what Linux offered; timestamps after the handshake only if on; no SACK blocks if SACK off; Linux→stack with SACK on: `TCPSackRecovery > 0` |
| C | stack→Linux: ICMP 3/4 MTU 1400 to the stack on `utcp0` (from the DUT kernel, see Testbed); the stack's first 1348-byte segment comes after the first of them, none of its segments after that one is longer, and the longer ones sent after the ICMP arrived (new data sent before the stack read it) are all within 10 ms of it; 1448 bytes before; `tcp_info` `pmtu` 1400 and `snd_mss` 1348; Linux→stack: ICMP 3/4 MTU 1400 to the peer, Linux's segments 1348 bytes, Linux's `pmtu` 1400, the stack's `rcv_mss` 1348 |
| D | curl and utcp-httpd exit 0; HTTP 200 and the body's size equal to the file's; SHA-256 of the body (on the peer) equal to the file's (in the DUT); no RST on an open connection from either side; `fin_ok`; `TCPSACKDiscard = 0`, `TCPSACKReneging = 0`; metrics empty |
| E local | utcp-http-get and the concurrent kernel curl exit 0, both bodies' SHA-256 equal to the file's, utcp-http-get's own SHA and length, `fin_ok`, `TCPSACKDiscard = 0`, `TCPSACKReneging = 0`, metrics empty |
| E public | kernel `curl -sI` precheck: 200 and no redirect to https (3 tries); both downloads exit 0; curl got 200; utcp-http-get's body equals kernel curl's (SHA-256 and length); the stack sent no RST on an open connection. Only "interoperates" is reported (Wi-Fi path, no numbers) |
| H | UDP: all 1000 lines came back unchanged, the stack counted 1000 datagrams in and 1000 out, the echo program exited 0; ICMP: 3 replies, the stack counted 3 echo requests and 3 replies |

## Matrix

The nstat column lists the checked counters and the nonzero recovery counters (peer deltas).
E public rows report only "interoperates" (pass) and no numbers. Run5's E-neverssl.com row
failed for a network reason (below); the matrix shows run5b's repeat. The run6 rows replace
run5's rows of the same cases (all of which had passed). run7-run11 are not in the matrix.
run8's and run9's A-N4-l2s each failed one check (`TCPDSACKIgnoredDubious` one below the
replay; see TCPSACKDiscard below).

| Case | Run | Direction | Options | Impairment | Bytes | SHA-256 equal | Duration s (non-timing) | Goodput Mbit/s (non-timing) | Retransmissions (sender total_retrans / peer TcpRetransSegs) | Peer nstat deltas | utcp0 drops (rx/tx) | Result |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A-N0-s2l | run5 | stack->Linux | default | N0 | 1 GB | yes | 4.976 | 1607.7 | 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-N0-l2s | run5 | Linux->stack | default | N0 | 1 GB | yes | 1.937 | 4131.1 | 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-N1-s2l | run5 | stack->Linux | default | N1 | 1 GB | yes | 139.945 | 57.2 | 7139 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-N1-l2s | run5 | Linux->stack | default | N1 | 1 GB | yes | 195.843 | 40.8 | 6894 / 6894 | SACKDiscard 0, SACKReneging 0, SackRecovery 6208, DSACKRecv 8, Timeouts 9 | 0/0 | pass |
| A-N2-s2l | run5 | stack->Linux | default | N2 | 1 GB | yes | 53.227 | 150.3 | 1800 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-N2-l2s | run5 | Linux->stack | default | N2 | 1 GB | yes | 13.006 | 615.1 | 195 / 195 | SACKDiscard 0, SACKReneging 0, SackRecovery 129, DSACKRecv 192, DSACKIgnoredNoUndo 187 | 0/0 | pass |
| A-N3-s2l | run5 | stack->Linux | default | N3 | 1 GB | yes | 4.353 | 1837.7 | 432 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-N3-l2s | run5 | Linux->stack | default | N3 | 1 GB | yes | 2.034 | 3932.4 | 0 / 0 | SACKDiscard 14131, SACKReneging 0, DSACKRecv 14131 (SACKDiscard = 14131 predicted from the capture, all D-SACKs for segments the stack received twice; see TCPSACKDiscard below) | 0/0 | pass |
| A-N4-s2l | run5 | stack->Linux | default | N4 | 1 GB | yes | 240.55 | 33.3 | 7061 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-N4-l2s | run6 | Linux->stack | default | N4 | 1 GB | yes | 300.581 | 26.6 | 6911 / 6911 | SACKDiscard 466, SACKReneging 0, SackRecovery 5761, DSACKRecv 5678, DSACKIgnoredNoUndo 171, Timeouts 6 (SACKDiscard = 466 predicted from the capture, all D-SACKs for segments the stack received twice; see TCPSACKDiscard below) | 0/0 | pass |
| A-pause200-s2l | run5 | stack->Linux | recv-pause 200:1048576 | N0 | 100 MB | yes | 19.1 | 41.9 | 0 / 0 | SACKDiscard 0, SACKReneging 0, ToZeroWindowAdv 1 | 0/0 | pass |
| A-pause200-l2s | run5 | Linux->stack | recv-pause 200:1048576 | N0 | 100 MB | yes | 19.235 | 41.6 | 84 / 84 | SACKDiscard 0, SACKReneging 0, DSACKRecv 84, DSACKIgnoredNoUndo 84 | 0/0 | pass |
| A-pause-s2l | run5 | stack->Linux | recv-pause 500:1048576 | N0 | 100 MB | yes | 47.6 | 16.8 | 0 / 0 | SACKDiscard 0, SACKReneging 0, ToZeroWindowAdv 93 | 0/0 | pass |
| A-pause-l2s | run5 | Linux->stack | recv-pause 500:1048576 | N0 | 100 MB | yes | 47.661 | 16.8 | 26 / 26 | SACKDiscard 0, SACKReneging 0, DSACKRecv 26, DSACKIgnoredNoUndo 26 | 0/0 | pass |
| A-ecn1-s2l | run6 | stack->Linux | peer tcp_ecn=1 | N0 | 100 MB | yes | 0.473 | 1692.0 | 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-ecn1-l2s | run6 | Linux->stack | peer tcp_ecn=1 | N0 | 100 MB | yes | 0.187 | 4289.1 | 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-ecn3-s2l | run6 | stack->Linux | peer tcp_ecn=3 | N0 | 100 MB | yes | 0.481 | 1664.0 | 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-ecn3-l2s | run6 | Linux->stack | peer tcp_ecn=3 | N0 | 100 MB | yes | 0.238 | 3366.0 | 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack0-ts0-ws0-s2l | run6 | stack->Linux | sack0-ts0-ws0 | N4 | 100 MB | yes | 25.088 | 31.9 | 689 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack0-ts0-ws0-l2s | run6 | Linux->stack | sack0-ts0-ws0 | N4 | 100 MB | yes | 64.454 | 12.4 | 1244 / 1244 | SACKDiscard 0, SACKReneging 0, Timeouts 177 | 0/0 | pass |
| B-sack0-ts0-ws1-s2l | run6 | stack->Linux | sack0-ts0-ws1 | N4 | 100 MB | yes | 26.872 | 29.8 | 861 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack0-ts0-ws1-l2s | run6 | Linux->stack | sack0-ts0-ws1 | N4 | 100 MB | yes | 36.707 | 21.8 | 1666 / 1666 | SACKDiscard 0, SACKReneging 0, Timeouts 37 | 0/0 | pass |
| B-sack0-ts1-ws0-s2l | run6 | stack->Linux | sack0-ts1-ws0 | N4 | 100 MB | yes | 26.183 | 30.6 | 704 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack0-ts1-ws0-l2s | run6 | Linux->stack | sack0-ts1-ws0 | N4 | 100 MB | yes | 37.175 | 21.5 | 808 / 808 | SACKDiscard 0, SACKReneging 0, Timeouts 17 | 0/0 | pass |
| B-sack0-ts1-ws1-s2l | run6 | stack->Linux | sack0-ts1-ws1 | N4 | 100 MB | yes | 25.615 | 31.2 | 723 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack0-ts1-ws1-l2s | run6 | Linux->stack | sack0-ts1-ws1 | N4 | 100 MB | yes | 37.521 | 21.3 | 2893 / 2893 | SACKDiscard 0, SACKReneging 0, Timeouts 41 | 0/0 | pass |
| B-sack1-ts0-ws0-s2l | run6 | stack->Linux | sack1-ts0-ws0 | N4 | 100 MB | yes | 22.533 | 35.5 | 688 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack1-ts0-ws0-l2s | run6 | Linux->stack | sack1-ts0-ws0 | N4 | 100 MB | yes | 29.453 | 27.2 | 683 / 683 | SACKDiscard 1, SACKReneging 0, SackRecovery 577, DSACKRecv 558, DSACKIgnoredNoUndo 188 (SACKDiscard = 1 predicted from the capture, all D-SACKs for segments the stack received twice; see TCPSACKDiscard below) | 0/0 | pass |
| B-sack1-ts0-ws1-s2l | run6 | stack->Linux | sack1-ts0-ws1 | N4 | 100 MB | yes | 23.523 | 34.0 | 667 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack1-ts0-ws1-l2s | run6 | Linux->stack | sack1-ts0-ws1 | N4 | 100 MB | yes | 30.078 | 26.6 | 674 / 674 | SACKDiscard 599, SACKReneging 0, SackRecovery 591, DSACKRecv 618, DSACKIgnoredNoUndo 1, Timeouts 1 (SACKDiscard = 599 predicted from the capture, all D-SACKs for segments the stack received twice; see TCPSACKDiscard below) | 0/0 | pass |
| B-sack1-ts1-ws0-s2l | run6 | stack->Linux | sack1-ts1-ws0 | N4 | 100 MB | yes | 25.426 | 31.5 | 708 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack1-ts1-ws0-l2s | run6 | Linux->stack | sack1-ts1-ws0 | N4 | 100 MB | yes | 29.776 | 26.9 | 680 / 680 | SACKDiscard 30, SACKReneging 0, SackRecovery 591, DSACKRecv 576, DSACKIgnoredNoUndo 172 (SACKDiscard = 30 predicted from the capture, all D-SACKs for segments the stack received twice; see TCPSACKDiscard below) | 0/0 | pass |
| B-sack1-ts1-ws1-s2l | run6 | stack->Linux | sack1-ts1-ws1 | N4 | 100 MB | yes | 24.093 | 33.2 | 689 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack1-ts1-ws1-l2s | run6 | Linux->stack | sack1-ts1-ws1 | N4 | 100 MB | yes | 29.524 | 27.1 | 664 / 664 | SACKDiscard 213, SACKReneging 0, SackRecovery 587, DSACKRecv 638, DSACKIgnoredNoUndo 8 (SACKDiscard = 213 predicted from the capture, all D-SACKs for segments the stack received twice; see TCPSACKDiscard below) | 0/0 | pass |
| C-pmtu-s2l | run6 | stack->Linux | PMTU 1400 chain | N0 | 1 GB | yes | 6.288 | 1272.3 | 20 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| C-pmtu-l2s | run6 | Linux->stack | PMTU 1400 chain | N0 | 1 GB | yes | 2.38 | 3361.0 | 12 / 12 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| D-N0-100M | run5 | stack->Linux | curl GET /big.bin | N0 | 100 MB | yes | 0.423345 |  | stack 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| D-N0-1B | run5 | stack->Linux | curl GET /one.bin | N0 | 1 B | yes | 0.000325 |  | stack 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| D-N0-0B | run5 | stack->Linux | curl GET /empty.bin | N0 | 0 B | yes | 0.000379 |  | stack 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| D-N4-100M | run5 | stack->Linux | curl GET /big.bin | N4 | 100 MB | yes | 22.905301 |  | stack 720 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| D-N4-1B | run5 | stack->Linux | curl GET /one.bin | N4 | 1 B | yes | 0.012312 |  | stack 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| D-N4-0B | run5 | stack->Linux | curl GET /empty.bin | N4 | 0 B | yes | 0.008346 |  | stack 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| E-nginx | run5 | Linux->stack | nginx GET /big.bin | N0 | 100 MB | yes |  |  | - / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| E-chunked | run5 | Linux->stack | chunked_server.py GET /chunked/ten.bin | N0 | 10 MB | yes |  |  | - / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| E-deb.debian.org | run5 | Internet->stack | public site; name: --dns 75.75.75.75 (UDP 53 over the stack, through the NAT) | none (NAT, Wi-Fi) |  | yes |  |  |  | n/a |  | pass |
| E-archive.ubuntu.com | run5 | Internet->stack | public site; name: --dns 75.75.75.75 (UDP 53 over the stack, through the NAT) | none (NAT, Wi-Fi) |  | yes |  |  |  | n/a |  | pass |
| E-neverssl.com | run5b | Internet->stack | public site; name: --dns 75.75.75.75 (UDP 53 over the stack, through the NAT) | none (NAT, Wi-Fi) |  | yes |  |  |  | n/a |  | pass |
| E-example.com | run5 | Internet->stack | public site; name: --dns 75.75.75.75 (UDP 53 over the stack, through the NAT) | none (NAT, Wi-Fi) |  | yes |  |  |  | n/a |  | pass |
| E-httpforever.com | run5 | Internet->stack | public site; name: --dns 75.75.75.75 (UDP 53 over the stack, through the NAT) | none (NAT, Wi-Fi) |  | yes |  |  |  | n/a |  | pass |
| H-udp | run5 | Linux->stack->Linux | nc -u, 1000 datagrams | N0 |  | n/a |  |  |  | n/a | 0/0 | pass |
| H-ping | run5 | Linux->stack->Linux | ping -c 3 | N0 |  | n/a |  |  |  | n/a | 0/0 | pass |

Linux->Linux reference (tests/interop/m1_linux_ref.sh; not acceptance cases):

| Case | Run | Options | Impairment | Bytes | SHA-256 equal | Duration s (non-timing) | Retransmissions (sender total_retrans / TcpRetransSegs) | Sender nstat deltas | D-SACK replay (predicted SACKDiscard / dubious, D-SACK ACKs, of them older than snd_una) | Result |
|---|---|---|---|---|---|---|---|---|---|---|
| R-N0-l2l | run6 | default | N0 | 1 GB | yes | 1.919 | 0 / 0 | SACKDiscard 0, SACKReneging 0 |  | pass |
| R-N1-l2l | run3 | default | N1 | 1 GB | yes | 191.509 | 6995 / 6995 | SACKDiscard 0, SACKReneging 0, SackRecovery 6246, DSACKRecv 11, Timeouts 12 |  | pass |
| R-N3-l2l | run3 | default | N3 | 1 GB | yes | 2.711 | 0 / 0 | SACKDiscard 2801, SACKReneging 0, DSACKRecv 6459 | 2801 / 6460, 6460, 3658 | pass |
| R-N4-l2l | run6 | default | N4 | 1 GB | yes | 300.313 | 6885 / 6885 | SACKDiscard 1, SACKReneging 0, SackRecovery 5614, DSACKRecv 5404, DSACKIgnoredNoUndo 567, Timeouts 8 | 1 / 1, 5756, 3 | pass |
| R-N4-100M-1-l2l | run3 | default | N4 | 100 MB | yes | 29.369 | 684 / 684 | SACKDiscard 12, SACKReneging 0, SackRecovery 578, DSACKRecv 550, DSACKIgnoredNoUndo 77 | 12 / 12, 575, 1 | pass |
| R-N4-100M-2-l2l | run3 | default | N4 | 100 MB | yes | 28.147 | 674 / 674 | SACKDiscard 0, SACKReneging 0, SackRecovery 541, DSACKRecv 571, DSACKIgnoredNoUndo 64 | 0 / 0, 606, 0 | pass |
| R-N4-100M-3-l2l | run3 | default | N4 | 100 MB | yes | 30.376 | 740 / 740 | SACKDiscard 1, SACKReneging 0, SackRecovery 649, DSACKRecv 618, DSACKIgnoredNoUndo 66, Timeouts 1 | 1 / 1, 652, 0 | pass |
| R-pause200-l2l | run3 | recv-pause 200:1048576 | N0 | 100 MB | yes | 19.184 | 193 / 193 | SACKDiscard 0, SACKReneging 0, DSACKRecv 193, DSACKIgnoredNoUndo 191 |  | pass |
| R-pause500-l2l | run3 | recv-pause 500:1048576 | N0 | 100 MB | yes | 47.682 | 191 / 191 | SACKDiscard 0, SACKReneging 0, DSACKRecv 191, DSACKIgnoredNoUndo 189 |  | pass |
| R-N4-100M-sack0-ts0-ws0-l2l | run3 | sack0-ts0-ws0 | N4 | 100 MB | yes | 38.528 | 758 / 758 | SACKDiscard 0, SACKReneging 0, Timeouts 47 | 0 / 0, 0, 0 | pass |
| R-N4-100M-sack0-ts0-ws1-l2l | run3 | sack0-ts0-ws1 | N4 | 100 MB | yes | 36.336 | 2387 / 2387 | SACKDiscard 0, SACKReneging 0, Timeouts 46 | 0 / 0, 0, 0 | pass |
| R-N4-100M-sack0-ts1-ws0-l2l | run3 | sack0-ts1-ws0 | N4 | 100 MB | yes | 36.774 | 721 / 721 | SACKDiscard 0, SACKReneging 0, Timeouts 38 | 0 / 0, 0, 0 | pass |
| R-N4-100M-sack0-ts1-ws1-l2l | run3 | sack0-ts1-ws1 | N4 | 100 MB | yes | 35.366 | 1426 / 1426 | SACKDiscard 0, SACKReneging 0, Timeouts 34 | 0 / 0, 0, 0 | pass |

## Results that need an explanation

Linux source references are to the server's Ubuntu 7.0.0-42 kernel tree
(`net/ipv4/tcp_input.c`, `tcp_output.c`).

### TCPSACKDiscard under duplication (A-N3-l2s, A-N4-l2s, B-sack1-*-l2s)

Under N3 and N4, netem duplicates segments toward the stack, and the stack answers each duplicate
with a D-SACK (RFC 2883 §4). Linux 7.0 counts a D-SACK as dubious when the sender has received more
D-SACKed segments than it ever retransmitted (`tcp_dsack_seen`: `dsack_dups > total_retrans`,
`TCPDSACKIgnoredDubious`; `__tcp_retransmit_skb` in `tcp_output.c` adds every retransmitted
segment to `total_retrans`, a retransmitted SYN or bare FIN included). The block is then
checked as an ordinary SACK block
(`tcp_is_sackblock_valid`): above SND.UNA it is valid; at or below SND.UNA it is counted in
`TCPSACKDiscard`, unless the ACK carrying it is older than SND.UNA ("Don't count olds caused by ACK
reordering", `tcp_sacktag_write_queue`). A nonzero `TCPSACKDiscard` in these rows therefore does
not mean a malformed block.

`tests/interop/m1_dsack.py` replays these rules over the peer capture (the order in which the Linux
sender sent data and processed ACKs) and, from the `utcp0` capture, checks which segments the stack
received twice. Every predicted discarded block is a D-SACK for a segment the stack received
twice, and every D-SACK the stack sent is one (`dsack_other` 0). Those are the checks in the
rows. `TCPSACKReneging` is 0 in every row.

Up to 484e628 the replay counted only retransmitted data segments. The second verification's
first A-N4-l2s run (`utcp-data:/m1-accept-interop-verify-2/vrun/A-N4-l2s`) showed the error:
netem dropped the peer's first SYN, so the kernel's `total_retrans` was one ahead of the replay's
count for the whole transfer. The replay predicted 16 dubious D-SACKs and 14 discards; the
kernel counted 6 and 4. Since 1f93aa5 the replay counts SYN and FIN in the sequence space. It
gives 6 and 4 for that run, and ctest `interop.m1_dsack_check` checks the rule. The corrected
replay was run again over all 27 retained peer captures of a Linux sender with SACK under N3 or
N4. These are the Linux→stack N3/N4 and B-sack1-*-l2s rows of run5-run8, the review's and both
verifications' runs, and the Linux→Linux N3/N4 references of run3 and run6-run8. Results:
`utcp-data:/m1-accept-interop/fix3/` (`replay_all.jsonl`, per capture old and new replay output).
In all 27, the captured retransmissions equal the sender's `total_retrans`; before the fix,
two captures were one short (vrun's A-N4-l2s and run8's R-N4-l2l, each with a retransmitted SYN).
The predicted `TCPSACKDiscard` equals the nstat delta in all 27, and the predicted
`TCPDSACKIgnoredDubious` in 26. The exception is run8's A-N4-l2s, an open item (below). The
corrected replay changes no other row's prediction. run9-run11 at 1f93aa5 ran every row with
the replay checks again: A-N4-l2s three times, A-N3-l2s and B-sack1-*-l2s once. The replay was
exact in all of them except run9's A-N4-l2s. There the replay predicted one
`TCPDSACKIgnoredDubious` more than the kernel counted (5280 against 5279; `TCPSACKDiscard` 4611
matched, and the captured retransmissions equal `total_retrans`, 6792), the same as run8.

Under N3 (duplication, no loss) the sender retransmits nothing, so every D-SACK is dubious, and
the count depends only on how many D-SACK ACKs reach the sender and how many of those are older
than SND.UNA:

| Row (run) | Receiver: duplicates received / D-SACKs recorded | D-SACK ACKs reaching the sender | of them older than SND.UNA | `TCPDSACKIgnoredDubious` | `TCPSACKDiscard` |
|---|---|---|---|---|---|
| A-N3-l2s, stack receiver (run5) | 13872 / 13872 | 14131 | 0 | 14131 | 14131 |
| A-N3-l2s (run3b) | not summarized | 14133 | 1 | 14133 | 14132 |
| R-N3-l2l, Linux receiver (run3) | not captured / 13826 | 6460 | 3658 | 6460 | 2801 |

"D-SACKs recorded" is the receiver's `TCPDSACKOldSent + TCPDSACKOfoSent`. The D-SACK ACK counts
include netem's duplicates of ACKs (the ACK path has the same netem). The ratio, 5.0, comes from
two receiver differences:

1. The stack puts every D-SACK on the wire. The Linux receiver records about as many but sends
   fewer: `tcp_dsack_set` keeps one range (`duplicate_sack[0]`), and `__tcp_ack_snd_check` defers
   ACKs while the socket backlog is processed (`tcp_backlog_ack_defer`), so a later duplicate
   replaces the earlier range before an ACK leaves: 13826 recorded, 6460 arrived.
2. 3658 of the Linux receiver's 6460 D-SACK ACKs reached the sender after an ACK with a higher
   number and were skipped. About 4.2 times fewer of the stack's ACKs reached the sender (34871
   against 145567 in the peer captures, both including netem's duplicates; see "ACK frequency"
   below), and none of its D-SACK ACKs was overtaken (1 in run3b).

Under N4 (1 % loss and 1 % duplication) the sender's running D-SACK count (`dsack_dups`) and
its running retransmission count (`total_retrans`) grow at about the same rate, and a D-SACK
is dubious only while the first is ahead. The count is the outcome of that race and varies
widely from run to run with the same code, so no ratio to the reference is given for N4.
A-N4-l2s was run twelve times (run3b at 84c031d, before 3fc5bb1 and 2441a7a, which change the
sender's `tcp_info` accounting and the programs' exit, not the receive path; run5, the review's
run at f811138, run6-run8 and the verifications' runv, vrun and vrun2 at the same stack code,
and run9-run11 at 1f93aa5, which changes only the replay) and R-N4-l2l four times:

| Row (run) | D-SACK ACKs reaching the sender | of them older than SND.UNA | Sender retransmissions | D-SACK ACKs per retransmission | `TCPDSACKIgnoredDubious` | `TCPSACKDiscard` |
|---|---|---|---|---|---|---|
| A-N4-l2s (run3b) | 6790 | 0 | 6912 | 0.98 | 1288 | 1109 |
| A-N4-l2s (run5) | 6832 | 0 | 6961 | 0.98 | 978 | 862 |
| A-N4-l2s (review, `utcp-data:/m1-accept-interop-review/logs/A-N4-l2s`) | 6832 | 0 | 6888 | 0.99 | 222 | 178 |
| A-N4-l2s (run6) | 6861 | 1 | 6911 | 0.99 | 553 | 466 |
| A-N4-l2s (run7) | 6762 | 0 | 6935 | 0.98 | 69 | 59 |
| A-N4-l2s (run8) | 6795 | 0 | 6860 | 0.99 | 2493 (replay 2494) | 2177 |
| A-N4-l2s (first verification, runv, `utcp-data:/m1-accept-interop-verify-1/logs/runv/A-N4-l2s`) | 6717 | 0 | 6724 | 1.00 | 5411 | 4648 |
| A-N4-l2s (second verification, vrun, `utcp-data:/m1-accept-interop-verify-2/logs/vrun/A-N4-l2s`) | 6883 | 0 | 6955 | 0.99 | 6 (replay before 1f93aa5: 16) | 4 (before 1f93aa5: 14) |
| A-N4-l2s (second verification, vrun2) | 6848 | 0 | 6968 | 0.98 | 12 | 11 |
| A-N4-l2s (run9) | 6897 | 0 | 6792 | 1.02 | 5279 (replay 5280) | 4611 |
| A-N4-l2s (run10) | 6941 | 1 | 6940 | 1.00 | 6541 | 5743 |
| A-N4-l2s (run11) | 6655 | 0 | 6840 | 0.97 | 294 | 268 |
| R-N4-l2l, Linux receiver (run3) | 5848 | 8 | 6825 | 0.86 | 131 | 127 |
| R-N4-l2l (run6) | 5756 | 3 | 6885 | 0.84 | 1 | 1 |
| R-N4-l2l (run7) | 5876 | 9 | 6971 | 0.84 | 117 | 110 |
| R-N4-l2l (run8) | 5691 | 7 | 6926 | 0.82 | 0 | 0 |

With the stack, `TCPSACKDiscard` ranged from 4 to 5743 at 0.97-1.02 D-SACK ACKs per
retransmission. With a Linux receiver it ranged from 0 to 127 at 0.82-0.86. The stack's higher
ratio (it sends every D-SACK, point 1 above) keeps the two running counts closer, which makes
dubious D-SACKs more likely. But at about the same ratio the count still differs more than
1000-fold between runs (vrun 4 at 0.99, run10 5743 at 1.00), so it says little about the stack
beyond that ratio. The 100 MB rows show the same: B-sack1-*-l2s 42-609 (run5), 1-599 (run6),
163-630 (run9), 1 and 110 (B-sack1-ts1-ws1-l2s in the two verifications) against 0-12 in
R-N4-100M-{1,2,3}-l2l (run3).

run8's A-N4-l2s failed the check that the replay predicts `TCPDSACKIgnoredDubious` exactly: the
kernel counted 2493, the replay 2494 (`TCPSACKDiscard` 2177 matched, and so did every other
check). The kernel processed the same D-SACKs (`TCPDSACKRecv + TCPDSACKOfoRecv` = 6795, the
replay's D-SACK ACKs; `TCPDSACKRecvSegs` 4302 = 6795 − 2493), so it took one D-SACK as not
dubious that the replay took as dubious, i.e. it had counted one retransmission more at that
ACK than the capture order shows. The captured retransmissions equal `total_retrans` (6860),
so unlike vrun's row this is not a missed retransmission; it is a difference of order.
The kernel can only count a retransmission earlier than the capture shows, never later.
`__tcp_retransmit_skb` adds it to `total_retrans` before the segment reaches the capture
point. An ACK is captured on the peer's interface before TCP processes it. While the sending
program holds the socket lock, `tcp_v4_rcv` (`tcp_ipv4.c` of the v7.0 tree; the Ubuntu tree
has no copy of it) queues arriving ACKs in the socket
backlog (`tcp_add_backlog`), and the backlog is processed in order when the lock is released.
`tcp_ack` ends in `tcp_xmit_recovery`, which sends retransmissions at once. So when two ACKs
wait in the backlog, the first can trigger a retransmission that the kernel counts before it
processes the second, although the capture shows both ACKs before the retransmission. The
replay's `TCPDSACKIgnoredDubious` is therefore an upper bound. The simplest way to be one lower
is an ACK the replay counts dubious with `dsack_dups` exactly one above the retransmissions so
far, followed in the capture by a retransmission before the next D-SACK ACK.
`utcp-data:/m1-accept-interop/fix3/edge.py` lists these ACKs (output in `edge.txt` there).
run8's capture has 25 such ACKs; the retransmission follows 83 us and 97 us after two of them
and 3.3-51 ms after the rest. run9's has 9; the retransmission follows 20, 38 and 113 us after
three of them and 3.5-69 ms after the rest. Which ACK the kernel took as not dubious cannot be
read from either capture. The nine other retained A-N4-l2s captures, where the replay is exact,
have 158 such ACKs. Seven of those have a retransmission 14-153 us after them, and the kernel
counted all seven as dubious. A gap of tens of microseconds is therefore not enough to show
that the kernel reordered at a given ACK. The backlog path above is a mechanism in the Linux
source that gives exactly this one-lower result, but no capture shows it happening.
run8's and run9's rows stay failed and are open items. With the exact check, A-N4-l2s failed
in 2 of the 11 runs that have the D-SACK checks and a capture (run3b had the checks but its
capture is gone). Neither row is in the matrix (run6's row is).

With SACK off (B-sack0-*) there are no D-SACKs, and `TCPSACKDiscard` is 0.

### Paused reader (A-pause200-*, A-pause-*)

The criterion "both stacks saw a zero window" is met by the 500 ms case (A-pause-s2l, A-pause-l2s;
`--recv-pause 500:1048576`). The 200 ms case passes its checks, but in the stack→Linux direction
Linux advertised a zero window only once in the capture (`TCPToZeroWindowAdv` 1; a Linux
receiver of a Linux sender advertised 95, R-pause200-l2l). The cause:

- The Linux receiver uses window scale 10. When its free space falls below one MSS, the
  remaining space up to the right edge it last advertised is often less than 1448 bytes: raw
  window 1 (1024 bytes) in the capture. Linux never shrinks an offered window
  (`tcp_select_window`: "Never shrink the offered window"). It counts `TCPWantZeroWindowAdv`
  instead (125 in A-pause200-s2l) and advertises 1024 bytes.
- The stack's sender does not send a 1024-byte segment into that window. Sender SWS avoidance
  (RFC 9293 §3.8.6.2.1, both profiles, DESIGN §4.9) waits for a full segment or half the largest
  window, until the persist timer's SWS override, which comes at the RTO (at least 200 ms). The
  200 ms pause ends first, so the window reopens without having reached zero.
- A Linux sender fills the last bytes at once (`tcp_mss_split_point` sends the partial segment
  when Nagle allows). In the R-pause200-l2l capture of run3
  (`utcp-data:/m1-accept-interop/run3/R-pause200-l2l/peer.pcap`), 94 of the receiver's 95
  zero-window ACKs follow a sender segment shorter than 1448 bytes (1088 bytes before 68 of
  them, 240 before 14, 64 before 6, 664 before 5, 1192 before 1). Its receiver then has no
  space left and advertises 0.

With the 500 ms pause the override fires, the stack sends the remaining bytes, and Linux
advertised a zero window in 127 ACKs of the capture (A-pause-s2l, `TCPToZeroWindowAdv` 93).
Linux→stack, the stack advertises zero windows in both cases (94 and 161 ACKs in the capture at
200 and 500 ms; Linux→Linux: 95 and 163).

Run3 of this case showed a stack bug, fixed in 3fc5bb1. The stack's sender reported 17.7 s
`sndbuf_limited` and 0.84 s `rwnd_limited` for the 19.1 s transfer (run3), where a Linux sender
reported 0 s and 18.9 s. After the fix (run5): A-pause200-s2l `rwnd_limited` 18.90 s,
`sndbuf_limited` 0 s; A-pause-s2l 46.60 s and 0 s.

### Stack sender: spurious fast retransmissions and RTOs (known, M2a)

- A-N3-s2l (duplication only, no loss): 432 fast retransmissions in 1 recovery (run5; 921 in 7
  in run3, 795 in 3 in run1), all spurious: nothing was lost. They come from M1's NewReno head marking with SACK, which M2a
  replaces (M2-DESIGN §1, REVIEW-LOG A1). Not fixed in M1.
- A-N2-s2l (reordering, no loss): 1800 fast retransmissions in 73 recoveries, and Linux's
  receiver sent 1800 D-SACKs (`TCPDSACKOldSent`): every one was spurious. M1 uses a
  fixed dupthresh of 3 in both profiles; adaptive reordering is M2a's (M2-DESIGN §1.9).
- A-N1-s2l and A-N4-s2l: the stack counted 150 and 133 `TCPTimeouts`. A Linux sender in
  A-N1-l2s had 9 (R-N1-l2l: 12). M1 recovery has no lost-retransmission detection, so a lost
  retransmission is repaired by an RTO; RACK in M2a repairs it without one (M2-TASKS m2a-recovery).
  The stack also counts every RTO expiry, where Linux counts differently (open item from
  m1-tcp-core); this affects the counter, not the wire.

### Linux sender with SACK off and window scaling on (B-sack0-*-ws1-l2s)

The Linux sender's retransmissions in these rows vary between runs and are higher with window
scaling on:

| Row | run3 | run3b | run5 | run6 | Linux receiver (run3, R-N4-100M-sack0-*) |
|---|---|---|---|---|---|
| sack0-ts0-ws0 | 692 | 772 | 1029 | 1244 | 758 |
| sack0-ts1-ws0 | 735 | 708 | 796 | 808 | 721 |
| sack0-ts0-ws1 | 1849 | 1425 | 1340 | 1666 | 2387 |
| sack0-ts1-ws1 | 2135 | 1762 | 1005 | 2893 | 1426 |

A Linux receiver gives the same pattern with the same sender settings. It comes from the Linux
sender's recovery without SACK in a larger window, not from the stack's receiver. The B rows
with SACK on had 667-729 (run5) and 664-683 (run6).

### m1-apps test 7: 91 retransmissions

m1-apps reported 91 retransmissions in its test 7 (kernel backend on both ends, loopback, 100 MB,
receiver `--recv-pause 200:1048576`). `tests/interop/m1_apps_retrans.sh 3` repeats it in a
container with its own network namespace, with `nstat -asz` before and after and a capture of
`lo`. The three runs had 127, 111 and 112 retransmitted segments. In each,
`TcpRetransSegs = TCPLossProbes = TCPDSACKRecv = TCPDSACKOldSent` (127/111/112), `DelayedACKLost`
is the same count, `TCPTimeouts` and `TCPFastRetrans` are 0, and tshark finds no fast
retransmission. Every retransmission is a tail loss probe whose original had arrived: the receiver D-SACKed
it. On loopback the sender's probe timeout is 2·srtt plus 2 ms (`tcp_schedule_loss_probe`,
`TCP_TIMEOUT_MIN_US`). That is shorter than the receiver's delayed ACK (at least 40 ms,
`TCP_DELACK_MIN`), which a paused reader leaves pending: `TCPDelayedACKs` was 97, 97 and 83. They
are Linux-to-Linux behaviour, not losses, and not something to compare with the stack. The A-pause
rows' Linux→stack retransmissions are the same kind: the stack D-SACKed every one (84 and 26,
`TCPDSACKRecv` in the matrix; the peer counted 107 and 221 `TCPLossProbes`, which include probes
with new data). Linux→Linux had 193 (R-pause200-l2l) and 191 (R-pause500-l2l), also all D-SACKed.

### ACK frequency of the stack's receiver (seen on the wire)

In A-N0-l2s (run5) the stack sent 16014 segments for 694245 received (one per 43), in 15151
TUN read batches. The Linux receiver in R-N0-l2l (GRO off)
sent 46363 for 694279 (one per 15). Both follow Linux's `__tcp_ack_snd_check`: with more than one
full segment unacknowledged, ACK at once only if the right window edge advances (or nothing is
unread); otherwise the read sends it (`tcp_cleanup_rbuf`). The stack's application reads after the
backend has passed it a whole TUN batch, so the edge does not move within a batch, and about one
ACK leaves per batch read. DESIGN §3 says host batching does not change protocol decisions such as
ACK frequency. On this receive path it does, through the window rule. This is reported to the
coordinator, not changed here. Under N1 (1 % ACK loss) the Linux sender's RTOs were no more than
Linux→Linux: 9 (7 undone) in A-N1-l2s (13 in run3), 12 in R-N1-l2l.

### Other differences checked against Linux

- Reordered pure ACKs below SND.UNA fail PAWS on both sides: the stack counted `PAWSEstab`
  2400 in A-N2-s2l (run5; 2347 replies held by the limiter, `TCPACKSkippedPAWS`), and Linux
  counted 11022 for the stack's ACKs in A-N2-l2s. Linux 7.0's `tcp_disordered_ack_check` exempts
  only pure duplicate ACKs at SND.UNA, and the stack's `paws_disordered_ack = linux` does the same.
- Linux's zero-window probes (`SEG.SEQ = SND.UNA − 1`) are out of window; replies within 500 ms of
  the previous one are held by the out-of-window ACK limiter: stack 25 (`TCPACKSkippedSeq`,
  A-pause-l2s), Linux receiver 27 (R-pause500-l2l).
- `fin_ok` accepts one kind of RST: in A-N4-l2s (run3b; A-N3-l2s in run2; none in run5 to
  run8) netem duplicated Linux's last ACK. Those captures no longer exist; the summaries in
  `utcp-data:/m1-accept-interop/logs/run3b/A-N4-l2s/pcap-{peer,utcp0}.json` record the RST
  (`rst` 1, `rst_after_close` 1, `rst_open` 0 for the stack). `tests/interop/m1_pcap_summary_check.py`
  (ctest `interop.m1_pcap_summary_check`) checks on hand-written segments that this RST is
  exempt and that an RST mid-transfer, an RST|ACK after the close, an RST with another
  sequence number and an RST before the stack's FIN was ACKed are not.
  The stack, in LAST-ACK, had closed on the first copy and answered the second with
  `<SEQ=SEG.ACK><CTL=RST>` (RFC 9293 §3.10.7.1), as Linux does when no socket matches
  (`tcp_v4_send_reset`). The capture summary counts it as `rst_after_close`.
- The stack's receiver pulls its advertised right window edge (SEG.ACK + window << 10) back by
  less than 2^10 bytes, up to tens of thousands of times per 1 GB run under loss or
  duplication; a Linux receiver does not. Counted in the `utcp0` captures by
  `m1_pcap_summary.py` (`edge_retreats`, ACKs below an earlier SEG.ACK skipped; in `row.json`
  from run6 on): A-N0-l2s 20, A-N1-l2s 18341, A-N3-l2s 13571 (run5); A-N4-l2s 29255 (run5),
  8519, 10956 and 22470 (run6-run8); B-sack1-ts1-ws1-l2s 2818 (run5) and 879 (run6),
  B-sack1-ts0-ws1-l2s 1287 (run6); A-ecn1-l2s 17, A-ecn3-l2s 16, C-pmtu-l2s 19 (run6); 0 in
  the B rows without window scaling. The largest step in every row is 1016 bytes or less. The
  Linux receiver in R-N0-l2l and R-N4-l2l: 0 (run3 peer captures, and run6-run8 for R-N4-l2l). The cause is deliberate: `RcvWindow`
  rounds the window that keeps the edge down to a multiple of 2^wscale (DESIGN §4.10, listed
  there as a deviation from Linux), because the stack's buffer limit is hard; Linux
  `tcp_select_window` rounds the current window up (`ALIGN(cur_win, 1 << rcv_wscale)`, "Never
  shrink the offered window", with `tcp_shrink_window` at its default 0) over its soft
  limit. RFC 7323 §2.4 describes this choice (advertise past the earlier edge, perhaps past
  the buffer, or shrink the window) and requires implementations to handle a shrinking
  window; the stack's acceptance and storage use the highest edge advertised (§2.4 rule 1),
  so nothing sent into the earlier window is dropped. The Linux senders handled it (every row passed).
  Not changed in M1.
- Open Linux differences listed by m1-tcp-core and m1-tcp-robust: rcv_wup ACK acceptance,
  ICMP net/host unreachable to a SYN-RECEIVED child, autocork for one-byte `nodelay` writes, the
  error reported for an RST in CLOSE-WAIT, and `TCPTimeouts` counting. No run showed the first
  four on the wire. The stack sent no challenge ACK and no RST on an open connection in any run.
  No ICMP message other than C's frag-needed (10, C-pmtu-s2l) and H's echo requests reached it. No program wrote one byte at a time.
  `TCPTimeouts` is a counter difference (above).
- E-neverssl.com: in run3 the stack resolved the name over UDP (1 query, 1 answer, the same
  address as the DUT's resolver), but its 11 SYNs (at 0, 1, 2, 3, 4, 5, 7, 11, ... s, Linux's
  schedule with `tcp_syn_linear_timeouts` 4) got no answer in 131 s. A kernel `curl -sI`
  precheck to the same site had also timed out once a minute earlier. The runner repeated the
  case with `--resolve`, which passed. run3b repeated it with `--dns`, which passed. In run5
  the precheck timed out once (15 s) and then got 200; the `--dns` run again got no SYN-ACK, and
  in the `--resolve` repeat utcp-http-get got the page (200, 3961 bytes) but the kernel curl
  started at the same time in the DUT timed out (exit 28), so the row failed: the site did not
  answer the kernel either. run5b (same commit) passed with `--dns`; that row is in the matrix.
  The run5 failure's files are in `utcp-data:/m1-accept-interop/logs/run5/E-neverssl.com/`
  (its capture was replaced by run5b's) and it is listed under open items.

## Fixes made by these runs

| Commit | Case | Fix | Regression test |
|---|---|---|---|
| 37b8bac | A-N3-s2l: `TcpExtTCPOrigDataSent` 1,381,424 for 690,715 segments | count once per new segment (`tcp_output.cpp`) | `TcpTransfer.OrigDataSentCountsEachNewSegmentOnce` |
| 8834aae | E-chunked: utcp-http-get exited after its close; the server's FIN (0.15 ms later) was never ACKed and was retransmitted | `Transport::finish_closing`: the client programs run the loop until their closed connections are done (at most 2 s) | `backend_transport_check --expect-stack` (`finish_closing` check; ctest `interop.backend_transport_check_stack`); that the programs call it: `BulkMain`, `HttpGetMain`, `EchoMain.MainFinishesClosingAfterRun` (9593c70; each fails without its program's call) |
| 3fc5bb1 | A-pause200-s2l: 17.7 s `sndbuf_limited`, 0.84 s `rwnd_limited` | start `sndbuf_limited` as Linux `tcp_cwnd_validate` does; DESIGN §10.1 | `TcpInfo.FullSendBufferBehindClosedWindowIsRwndLimited` |
| 4d133e0 | A-N3-l2s `fin_ok` | checker: the RST answering a segment after the close is not an RST on an open connection (above) | `tests/interop/m1_pcap_summary_check.py` (484e628, ctest `interop.m1_pcap_summary_check`): the exempt RST and four RSTs that must still count |
| 2441a7a | B-sack1-ts1-ws0-s2l (run4): utcp-bulk exited while the stack's connection was in TIME-WAIT; Linux's FIN, sent 4 times, was dropped at `utcp0` (tx_dropped 4) and never ACKed, so `fin_ok` failed | `finish_closing` also waits until no TIME-WAIT entry is left (at most 2 s, which covers three FIN retransmissions), so a retransmitted FIN is ACKed again | `backend_transport_check --expect-stack` (`finish_closing` re-sends the FIN after 200 ms and expects a second ACK) |
| f960663 | all rows | `--stats FILE` for the utcp backend (the stack's counters for the rows) | `backend_transport_check` stats_file check |

Test-harness fixes in the runners: H-udp sends its first line 0.5 s after `nc -u` starts
(in run2, two lines written while nc was starting left as one 68-byte datagram, so the stack
counted 999). E prechecks each public site up to 3 times and records a replacement
(info.cern.ch, captive.apple.com) if one still fails; no replacement was needed in run3, run5 or run5b.

## Open items

- E-neverssl.com is unreliable from this host: SYNs from both the stack and the kernel went
  unanswered in run3 and run5 (above). It passed in run3b and run5b. Not a stack failure as far
  as the captures show, but not explained further.
- DESIGN §3 says host batching does not change protocol decisions such as ACK frequency. On the
  receive path it does (one ACK per TUN batch, "ACK frequency" above). Reported to the
  coordinator; DESIGN is not changed here. Coordinator decision (2026-11-14): assigned to M2
  (m2-found): the receiver's ACK frequency must not depend on the host's batch size.
- Known and assigned to M2a, not fixed here: spurious fast retransmissions of the stack sender
  under duplication and reordering (A-N3-s2l, A-N2-s2l) and RTO repair of lost retransmissions
  (A-N1-s2l, A-N4-s2l).
- The D-SACK-related `TCPSACKDiscard` of a Linux sender is 5.0 times the Linux→Linux count
  under N3, explained above (the stack sends every D-SACK and fewer ACKs, so none are merged or
  overtaken). Under N4 the count is a race between two running counters and varied from 4 to
  5743 over twelve runs with the stack (0 to 127 over four with Linux); no ratio is claimed. The
  stack sends nothing a Linux receiver would not also send.
- run8's and run9's A-N4-l2s: the replay predicted one `TCPDSACKIgnoredDubious` more than the
  kernel counted (2494 against 2493; 5280 against 5279). The captured retransmissions equal
  `total_retrans`, so the difference is one of order. The replay is an upper bound because the
  socket backlog can make the kernel count a retransmission before it processes an ACK captured
  earlier. Each capture has ACKs where the kernel could have been one lower, but neither shows
  which one. Both rows stay failed and the check is unchanged (exact equality). After 1f93aa5
  these are the only mismatches among the 27 retained captures and the eight rows of run9-run11.
  A check that accepts the replay minus such ACKs is possible but needs a bound on how late the
  kernel processes an ACK. Coordinator decision (2026-11-14): the check stays exact and both
  rows stay failed as recorded. They do not block M1 acceptance: `TCPSACKDiscard` matched the
  replay in every run, the matrix row (run6) passes, and the one-count difference has a
  mechanism in the Linux source that can only lower the kernel's count.
- The stack's receiver pulls the right window edge back by less than 2^wscale (above). This
  is the deliberate rounding of DESIGN §4.10, not an open item; listed here because Linux
  does not do it.
- The Linux differences listed by m1-tcp-core and m1-tcp-robust that no run exercised on the
  wire (above) remain open.

