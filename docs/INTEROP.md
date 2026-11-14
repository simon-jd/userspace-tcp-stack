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
run a subset, and writes per case `RUN/<case>/`: `testbed/m1/record.sh` output before
and after (the peer's `nstat -asz`, `ip tcp_metrics show`, `ip -s link show utcp0`,
`tc -s qdisc`, offloads), the programs' JSON output, the stack's counters (`--stats`),
capture summaries, and `row.json`; `RUN/rows.jsonl` collects the rows. Before every
case the peer runs with `net.ipv4.tcp_no_metrics_save = 1`, and the row checks that
`ip tcp_metrics show` was empty.

The runs, on 2026-11-14 (the `Run` column of the matrix says which run a row is from):

| Run | Commit | What | Used in the matrix |
|---|---|---|---|
| run2 | 8834aae | all cases | no (found the H-udp, E and paused-reader issues; captures kept) |
| run3 | 84c031d | all cases and the Linux→Linux reference | reference rows only |
| run3b | 84c031d | Linux→stack rows under N3/N4 with the D-SACK checks, E-neverssl.com | no |
| run4 | 5060a88 | stack→Linux rows and D after 3fc5bb1 | no (B-sack1-ts1-ws0-s2l failed: fixed in 2441a7a) |
| run5 | 5493eec | every stack case (A, B, C, D, E, H) with all fixes | all stack rows except E-neverssl.com |
| run5b | 5493eec | E-neverssl.com again (run5 failed: below) | E-neverssl.com |

`tests/interop/m1_matrix.sh .logs/run3 .logs/run5 .logs/run5b` prints the tables below (a later
directory's row replaces an earlier one). The reference rows do not involve the stack, so the
stack fixes after run3 do not affect them.

### Testbed and CPU pinning

- `utcp-m1-dut` (the stack on `utcp0`, 198.18.0.2; the DUT kernel 198.18.0.1 forwards
  between `utcp0` and `utcp-m1-net`), `utcp-m1-peer` (Linux, 198.19.1.3), and for C the
  router `utcp-m1-r` with the 1400-byte link (`testbed/m1/pmtu.sh`).
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

tcpdump, 128-byte snaplen (headers only), in the Docker volume `utcp-data`:

- `utcp-data:/m1-accept-interop/<case>/peer.pcap`: the peer's interface (A, B, C, the
  local E cases, R).
- `utcp-data:/m1-accept-interop/<case>/utcp0.pcap`: `utcp0` in the DUT (all stack cases;
  egress is captured after the netem qdisc, so duplicates and losses toward the stack
  are visible there).
- `utcp-data:/m1-accept-interop/apps-t7-<n>/lo.pcap`: m1-apps test 7 reproduction.

The captures stay in the volume (read them with a container that mounts `utcp-data`,
e.g. `docker run --rm -v utcp-data:/data utcp-testbed:dev tshark -r /data/m1-accept-interop/A-N0-s2l/peer.pcap`).

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
| A ECN (peer `tcp_ecn` 1, 3) | no ECE/CWR/AE in the stack's SYN or SYN-ACK or in Linux's SYN-ACK, no ECN codepoint on any packet, no ECE/CWR after the handshake; Linux→stack: Linux's SYN carried ECE+CWR (it asked; the stack declined) |
| B | Linux's SYN/SYN-ACK carry exactly the enabled options; the stack's SYN offers SACK, timestamps and window scale, its SYN-ACK only what Linux offered; timestamps after the handshake only if on; no SACK blocks if SACK off; Linux→stack with SACK on: `TCPSackRecovery > 0` |
| C | stack→Linux: ICMP 3/4 MTU 1400 to the stack on `utcp0`, stack segments ≤ 1348 bytes after it (1448 before), `tcp_info` `pmtu` 1400 and `snd_mss` 1348; Linux→stack: ICMP 3/4 MTU 1400 to the peer, Linux's segments 1348 bytes, Linux's `pmtu` 1400, the stack's `rcv_mss` 1348 |
| D | curl and utcp-httpd exit 0; HTTP 200 and the body's size equal to the file's; SHA-256 of the body (on the peer) equal to the file's (in the DUT); no RST on an open connection from either side; `fin_ok`; `TCPSACKDiscard = 0`, `TCPSACKReneging = 0`; metrics empty |
| E local | utcp-http-get and the concurrent kernel curl exit 0, both bodies' SHA-256 equal to the file's, utcp-http-get's own SHA and length, `fin_ok`, `TCPSACKDiscard = 0`, `TCPSACKReneging = 0`, metrics empty |
| E public | kernel `curl -sI` precheck: 200 and no redirect to https (3 tries); both downloads exit 0; curl got 200; utcp-http-get's body equals kernel curl's (SHA-256 and length); the stack sent no RST on an open connection. Only "interoperates" is reported (Wi-Fi path, no numbers) |
| H | UDP: all 1000 lines came back unchanged, the stack counted 1000 datagrams in and 1000 out, the echo program exited 0; ICMP: 3 replies, the stack counted 3 echo requests and 3 replies |

## Matrix

The nstat column lists the checked counters and the nonzero recovery counters (peer deltas).
E public rows report only "interoperates" (pass) and no numbers. Run5's E-neverssl.com row
failed for a network reason (below); the matrix shows run5b's repeat.

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
| A-N4-l2s | run5 | Linux->stack | default | N4 | 1 GB | yes | 293.373 | 27.3 | 6961 / 6961 | SACKDiscard 862, SACKReneging 0, SackRecovery 5768, DSACKRecv 5688, DSACKIgnoredNoUndo 133, Timeouts 5 (SACKDiscard = 862 predicted from the capture, all D-SACKs for segments the stack received twice; see TCPSACKDiscard below) | 0/0 | pass |
| A-pause200-s2l | run5 | stack->Linux | recv-pause 200:1048576 | N0 | 100 MB | yes | 19.1 | 41.9 | 0 / 0 | SACKDiscard 0, SACKReneging 0, ToZeroWindowAdv 1 | 0/0 | pass |
| A-pause200-l2s | run5 | Linux->stack | recv-pause 200:1048576 | N0 | 100 MB | yes | 19.235 | 41.6 | 84 / 84 | SACKDiscard 0, SACKReneging 0, DSACKRecv 84, DSACKIgnoredNoUndo 84 | 0/0 | pass |
| A-pause-s2l | run5 | stack->Linux | recv-pause 500:1048576 | N0 | 100 MB | yes | 47.6 | 16.8 | 0 / 0 | SACKDiscard 0, SACKReneging 0, ToZeroWindowAdv 93 | 0/0 | pass |
| A-pause-l2s | run5 | Linux->stack | recv-pause 500:1048576 | N0 | 100 MB | yes | 47.661 | 16.8 | 26 / 26 | SACKDiscard 0, SACKReneging 0, DSACKRecv 26, DSACKIgnoredNoUndo 26 | 0/0 | pass |
| A-ecn1-s2l | run5 | stack->Linux | peer tcp_ecn=1 | N0 | 100 MB | yes | 0.507 | 1579.4 | 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-ecn1-l2s | run5 | Linux->stack | peer tcp_ecn=1 | N0 | 100 MB | yes | 0.199 | 4021.6 | 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-ecn3-s2l | run5 | stack->Linux | peer tcp_ecn=3 | N0 | 100 MB | yes | 0.502 | 1595.0 | 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| A-ecn3-l2s | run5 | Linux->stack | peer tcp_ecn=3 | N0 | 100 MB | yes | 0.197 | 4054.2 | 0 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack0-ts0-ws0-s2l | run5 | stack->Linux | sack0-ts0-ws0 | N4 | 100 MB | yes | 30.089 | 26.6 | 797 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack0-ts0-ws0-l2s | run5 | Linux->stack | sack0-ts0-ws0 | N4 | 100 MB | yes | 50.427 | 15.9 | 1029 / 1029 | SACKDiscard 0, SACKReneging 0, Timeouts 105 | 0/0 | pass |
| B-sack0-ts0-ws1-s2l | run5 | stack->Linux | sack0-ts0-ws1 | N4 | 100 MB | yes | 26.474 | 30.2 | 724 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack0-ts0-ws1-l2s | run5 | Linux->stack | sack0-ts0-ws1 | N4 | 100 MB | yes | 36.008 | 22.2 | 1340 / 1340 | SACKDiscard 0, SACKReneging 0, Timeouts 46 | 0/0 | pass |
| B-sack0-ts1-ws0-s2l | run5 | stack->Linux | sack0-ts1-ws0 | N4 | 100 MB | yes | 28.086 | 28.5 | 785 / 1 | SACKDiscard 0, SACKReneging 0, Timeouts 1 | 0/0 | pass |
| B-sack0-ts1-ws0-l2s | run5 | Linux->stack | sack0-ts1-ws0 | N4 | 100 MB | yes | 38.435 | 20.8 | 796 / 796 | SACKDiscard 0, SACKReneging 0, Timeouts 44 | 0/0 | pass |
| B-sack0-ts1-ws1-s2l | run5 | stack->Linux | sack0-ts1-ws1 | N4 | 100 MB | yes | 25.307 | 31.6 | 821 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack0-ts1-ws1-l2s | run5 | Linux->stack | sack0-ts1-ws1 | N4 | 100 MB | yes | 37.664 | 21.2 | 1005 / 1005 | SACKDiscard 0, SACKReneging 0, Timeouts 37 | 0/0 | pass |
| B-sack1-ts0-ws0-s2l | run5 | stack->Linux | sack1-ts0-ws0 | N4 | 100 MB | yes | 24.72 | 32.4 | 721 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack1-ts0-ws0-l2s | run5 | Linux->stack | sack1-ts0-ws0 | N4 | 100 MB | yes | 30.447 | 26.3 | 729 / 729 | SACKDiscard 42, SACKReneging 0, SackRecovery 655, DSACKRecv 613, DSACKIgnoredNoUndo 173 (SACKDiscard = 42 predicted from the capture, all D-SACKs for segments the stack received twice; see TCPSACKDiscard below) | 0/0 | pass |
| B-sack1-ts0-ws1-s2l | run5 | stack->Linux | sack1-ts0-ws1 | N4 | 100 MB | yes | 25.087 | 31.9 | 733 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack1-ts0-ws1-l2s | run5 | Linux->stack | sack1-ts0-ws1 | N4 | 100 MB | yes | 29.027 | 27.6 | 667 / 667 | SACKDiscard 609, SACKReneging 0, SackRecovery 564, DSACKRecv 609 (SACKDiscard = 609 predicted from the capture, all D-SACKs for segments the stack received twice; see TCPSACKDiscard below) | 0/0 | pass |
| B-sack1-ts1-ws0-s2l | run5 | stack->Linux | sack1-ts1-ws0 | N4 | 100 MB | yes | 23.4 | 34.2 | 684 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack1-ts1-ws0-l2s | run5 | Linux->stack | sack1-ts1-ws0 | N4 | 100 MB | yes | 29.031 | 27.6 | 683 / 683 | SACKDiscard 124, SACKReneging 0, SackRecovery 572, DSACKRecv 565, DSACKIgnoredNoUndo 113 (SACKDiscard = 124 predicted from the capture, all D-SACKs for segments the stack received twice; see TCPSACKDiscard below) | 0/0 | pass |
| B-sack1-ts1-ws1-s2l | run5 | stack->Linux | sack1-ts1-ws1 | N4 | 100 MB | yes | 23.135 | 34.6 | 682 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| B-sack1-ts1-ws1-l2s | run5 | Linux->stack | sack1-ts1-ws1 | N4 | 100 MB | yes | 29.247 | 27.4 | 709 / 709 | SACKDiscard 488, SACKReneging 0, SackRecovery 581, DSACKRecv 623, DSACKIgnoredNoUndo 3 (SACKDiscard = 488 predicted from the capture, all D-SACKs for segments the stack received twice; see TCPSACKDiscard below) | 0/0 | pass |
| C-pmtu-s2l | run5 | stack->Linux | PMTU 1400 chain | N0 | 1 GB | yes | 6.549 | 1221.6 | 20 / 0 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
| C-pmtu-l2s | run5 | Linux->stack | PMTU 1400 chain | N0 | 1 GB | yes | 2.412 | 3316.3 | 12 / 12 | SACKDiscard 0, SACKReneging 0 | 0/0 | pass |
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
| R-N0-l2l | run3 | default | N0 | 1 GB | yes | 1.917 | 0 / 0 | SACKDiscard 0, SACKReneging 0 |  | pass |
| R-N1-l2l | run3 | default | N1 | 1 GB | yes | 191.509 | 6995 / 6995 | SACKDiscard 0, SACKReneging 0, SackRecovery 6246, DSACKRecv 11, Timeouts 12 |  | pass |
| R-N3-l2l | run3 | default | N3 | 1 GB | yes | 2.711 | 0 / 0 | SACKDiscard 2801, SACKReneging 0, DSACKRecv 6459 | 2801 / 6460, 6460, 3658 | pass |
| R-N4-l2l | run3 | default | N4 | 1 GB | yes | 293.672 | 6825 / 6825 | SACKDiscard 127, SACKReneging 0, SackRecovery 5578, DSACKRecv 5489, DSACKIgnoredNoUndo 540, Timeouts 4 | 127 / 131, 5848, 8 | pass |
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
`TCPDSACKIgnoredDubious`). The block is then checked as an ordinary SACK block
(`tcp_is_sackblock_valid`): above SND.UNA it is valid; at or below SND.UNA it is counted in
`TCPSACKDiscard`, unless the ACK carrying it is older than SND.UNA ("Don't count olds caused by ACK
reordering", `tcp_sacktag_write_queue`). A nonzero `TCPSACKDiscard` in these rows therefore does
not mean a malformed block.

`tests/interop/m1_dsack.py` replays these rules over the peer capture (the order in which the Linux
sender sent data and processed ACKs) and, from the `utcp0` capture, checks which segments the stack
received twice. In every Linux→stack row under N3 and N4 and in every Linux→Linux reference row
under N3 and N4, the predicted `TCPSACKDiscard` and `TCPDSACKIgnoredDubious` equal the nstat deltas
exactly. Every predicted discarded block is a D-SACK for a segment the stack received twice, and
every D-SACK the stack sent is one (`dsack_other` 0). Those are the checks in the rows.
`TCPSACKReneging` is 0 in every row.

| Profile, size | Row (run) | Receiver: duplicates received / D-SACKs recorded | D-SACK ACKs reaching the sender | of them older than SND.UNA | Sender retransmissions | `TCPDSACKIgnoredDubious` | `TCPSACKDiscard` |
|---|---|---|---|---|---|---|---|
| N3, 1 GB | A-N3-l2s, stack receiver (run5) | 13872 / 13872 | 14131 | 0 | 0 | 14131 | 14131 |
| N3, 1 GB | R-N3-l2l, Linux receiver (run3) | not captured / 13826 | 6460 | 3658 | 0 | 6460 | 2801 |
| N4, 1 GB | A-N4-l2s (run5) | 6829 / 6829 | 6832 | 0 | 6961 | 978 | 862 |
| N4, 1 GB | R-N4-l2l (run3) | not captured / 6838 | 5848 | 8 | 6825 | 131 | 127 |
| N4, 100 MB | B-sack1-*-l2s, 4 rows (run5) | 670-758 / same | 673-758 | 0 | 667-729 | 45-684 | 42-609 |
| N4, 100 MB | R-N4-100M-{1,2,3}-l2l (run3) | not captured / 663-722 | 575-652 | 0-1 | 674-740 | 0-12 | 0-12 |

"D-SACKs recorded" is the receiver's `TCPDSACKOldSent + TCPDSACKOfoSent`. The D-SACK ACK counts
include netem's duplicates of ACKs (the ACK path has the same netem).

The ratios to the reference (5.0 under N3, 6.8 under N4 at 1 GB, larger at 100 MB) come from
the replayed rule's inputs. The same holds in run3b (14132 and 1109 against the same reference
rows).

1. The stack puts every D-SACK on the wire. The Linux receiver records about as many but sends
   fewer: `tcp_dsack_set` keeps one range (`duplicate_sack[0]`), and `__tcp_ack_snd_check` defers
   ACKs while the socket backlog is processed (`tcp_backlog_ack_defer`), so a later duplicate
   replaces the earlier range before an ACK leaves. Under N3, 13826 were recorded and 6460 arrived;
   under N4, 6838 and 5848.
2. Under N3, 3658 of the Linux receiver's 6460 D-SACK ACKs reached the sender after an ACK with a
   higher number and were skipped. About 4.2 times fewer of the stack's ACKs reached
   the sender (34871 against 145567 in the peer captures, both including netem's duplicates; see
   "ACK frequency" below), and none of its D-SACK ACKs was overtaken (1 in
   run3b).
3. Under N4, duplicates (1 %) and retransmissions (about 1 % loss) are about equal, so the
   sender's running D-SACK count stays near its running retransmission count, and the dubious
   count depends on how often the first exceeds the second. D-SACK ACKs per retransmission were
   0.98 (A-N4-l2s) and 0.94-1.07 (B rows) with the stack, against 0.86 (R-N4-l2l) and 0.84-0.90
   (R-N4-100M) with Linux.

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
  when Nagle allows; in the R-pause200-l2l capture of run2, segments of 1016, 664, ... bytes end
  each burst before the zero window). Its
  receiver then has no space left and advertises 0.

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

| Row | run3 | run3b | run5 | Linux receiver (run3, R-N4-100M-sack0-*) |
|---|---|---|---|---|
| sack0-ts0-ws0 | 692 | 772 | 1029 | 758 |
| sack0-ts1-ws0 | 735 | 708 | 796 | 721 |
| sack0-ts0-ws1 | 1849 | 1425 | 1340 | 2387 |
| sack0-ts1-ws1 | 2135 | 1762 | 1005 | 1426 |

A Linux receiver gives the same pattern with the same sender settings. It comes from the Linux
sender's recovery without SACK in a larger window, not from the stack's receiver. The B rows
with SACK on had 667-729 (run5).

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
- `fin_ok` accepts one kind of RST: in A-N4-l2s (run3b; A-N3-l2s in run2; none in run5) netem
  duplicated Linux's last ACK.
  The stack, in LAST-ACK, had closed on the first copy and answered the second with
  `<SEQ=SEG.ACK><CTL=RST>` (RFC 9293 §3.10.7.1), as Linux does when no socket matches
  (`tcp_v4_send_reset`). The capture summary counts it as `rst_after_close`.
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
  The run5 failure stays in `.logs/run5/E-neverssl.com` and is listed under open items.

## Fixes made by these runs

| Commit | Case | Fix | Regression test |
|---|---|---|---|
| 37b8bac | A-N3-s2l: `TcpExtTCPOrigDataSent` 1,381,424 for 690,715 segments | count once per new segment (`tcp_output.cpp`) | `TcpTransfer.OrigDataSentCountsEachNewSegmentOnce` |
| 8834aae | E-chunked: utcp-http-get exited after its close; the server's FIN (0.15 ms later) was never ACKed and was retransmitted | `Transport::finish_closing`: the client programs run the loop until their closed connections are done (at most 2 s) | `backend_transport_check --expect-stack` (`finish_closing` check; ctest `interop.backend_transport_check_stack`) |
| 3fc5bb1 | A-pause200-s2l: 17.7 s `sndbuf_limited`, 0.84 s `rwnd_limited` | start `sndbuf_limited` as Linux `tcp_cwnd_validate` does; DESIGN §10.1 | `TcpInfo.FullSendBufferBehindClosedWindowIsRwndLimited` |
| 4d133e0 | A-N3-l2s `fin_ok` | checker: the RST answering a segment after the close is not an RST on an open connection (above) | (test scripts) |
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
  coordinator; DESIGN is not changed here.
- Known and assigned to M2a, not fixed here: spurious fast retransmissions of the stack sender
  under duplication and reordering (A-N3-s2l, A-N2-s2l) and RTO repair of lost retransmissions
  (A-N1-s2l, A-N4-s2l).
- The D-SACK-related `TCPSACKDiscard` of a Linux sender is 5.0 (N3) and 6.8 (N4) times the
  Linux→Linux count. The cause is explained above (the stack sends every D-SACK and one ACK
  per batch, so none are merged or overtaken); the stack sends nothing a Linux receiver would
  not also send.
- The Linux differences listed by m1-tcp-core and m1-tcp-robust that no run exercised on the
  wire (above) remain open.

