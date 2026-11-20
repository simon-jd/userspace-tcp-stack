# D-SACK capture replay and SYN retransmissions

The M1 Linux-to-stack case `A-N4-l2s` in `vrun` transferred all
1,000,000,000 bytes with matching SHA-256. Its original capture checker
nevertheless failed both D-SACK counter assertions. The raw `nstat` logs
showed before/after counts of 0 to 6 for `TCPDSACKIgnoredDubious` and 0 to
4 for `TCPSACKDiscard`. The old checker predicted 16 and 14 and counted
6,954 retransmissions against the sender's `total_retrans` of 6,955.

| UTC time on 2026-11-14 | Capture and frame | Packet |
| --- | --- | --- |
| 19:05:58.862455 | Peer, frame 1 | First sender SYN, raw sequence 3222020595 |
| 19:05:59.869083 | Peer, frame 2 | Second SYN in the same flow with the same sequence, 1.006628 s later |
| 19:05:59.871129 | Stack, frame 1 | SYN with the same sequence. This is the first SYN in the stack capture. |
| 19:05:59.871208 | Stack, frame 2 | SYN-ACK |

The capture order and repeated sequence support the historical diagnosis
that the first SYN was lost before reaching the stack. The checker counted
payload segments, so it missed one sender retransmission near the start of
the flow. Linux's `total_retrans` includes retransmitted SYNs and bare
FINs. That count affects whether a received D-SACK is classified as dubious
and which duplicate SACK block is counted as discarded.

Commit `1f93aa57c87d1a75a010a2b2736b756409152906` extends the replay's
sequence-space accounting to SYN and FIN. It adds the
`interop.m1_dsack_check` fixture for those cases. The change is in the
capture checker and its tests. Retained replay outputs record both checker
versions on the same capture.

| Counter | Kernel | Original replay | Corrected replay |
| --- | ---: | ---: | ---: |
| Sender total retransmissions | 6,955 | 6,954 | 6,955 |
| `TCPDSACKIgnoredDubious` | 6 | 16 | 6 |
| `TCPSACKDiscard` | 4 | 14 | 4 |

Across the 27 retained replays, the corrected checker matched sender
retransmissions and `TCPSACKDiscard` in all 27, and
`TCPDSACKIgnoredDubious` in 26. The unresolved `run8` row has 6,860
retransmissions and 2,177 discards on both sides, with 2,494 predicted
dubious D-SACKs against 2,493 from the kernel. The later `run9` row also
differs by one, 5,280 versus 5,279, with exact retransmission and discard
counts. Both historical rows retain their failed exact-check verdicts.

One plausible mechanism is that a socket-backlog ACK triggered a
retransmission that Linux counted before processing the next ACK, while
the capture recorded both ACKs before the retransmission. The `run8`
archive lists candidates with captured ACK-to-retransmission gaps of
83 and 97 microseconds. The kernel's processing order for each candidate remains unresolved.

## Evidence on Ubuntu

- Retained captures are in
  `utcp-data:/m1-accept-interop-verify-2/vrun/A-N4-l2s/`.
  SHA-256 for `peer.pcap` is
  `380bdde048e87f3005c5e36fdc3a56ad1384ce70905d036de438ae453dfc1f53`
  and for `utcp0.pcap` is
  `fd0f7cbd665b2388fd7aa57c91b1ec9b6cd0393f393c3999d8937be118bf287c`.
- Original application, checker and counter records are in
  `utcp-data:/m1-accept-interop-verify-2/logs/vrun/A-N4-l2s/`.
  The paired replay results and timing excerpts are `replay_all.jsonl`
  and `edge.txt` in `utcp-data:/m1-accept-interop/fix3/`.
  `replay_all.jsonl` SHA-256 is
  `763e7b571ba554d898aae57e2f256f8954551eaa8959c1f90fc67008072dc0a6`.
  [Historical interop report](../../INTEROP.md)
