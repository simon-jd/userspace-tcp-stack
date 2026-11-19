# Comparison results (M2)

The stack against Linux 7.0 on the comparison testbed (DESIGN §14). Sections and owners (M2 work
breakdown): Method, Calibration, Gap rule and thresholds, Which runs count, Timing hygiene (m2d-testbed);
Comparison with Linux traces (m2-integrate); Checkpoint (m2-checkpoint); Core matrix (m2d-matrix);
Multi-flow (m2d-multiflow); Ablation (m2d-ablation).

"Gap rule and thresholds" and "Which runs count" are fixed before the first matrix run and are not
changed afterwards; the commit that fixed them is named in each.

## Method

**Topology** (`testbed/m2/`, DESIGN §14). Per slot four containers from `utcp-testbed:dev`, sender
`snd`, routers `r1` and `r2`, receiver `rcv`, on three Docker bridge networks:

```
snd --(a)-- r1 --(b)-- r2 --(c)-- rcv      netem on r1's b side (data direction), tbf on r2's c side
slot N: a = 198.19.X.0/24, b = X+1, c = X+2, X = 10+4N (slots 0, 1); the stack on TUN utcpK in snd, 198.18.(8N+K).2
```

The Linux sender is the kernel of `snd`; the stack runs in the same container on a TUN device, so both
senders share the path, the receiver and the ping probe. The receiver is always Linux
(`utcp-bulk --backend kernel --recv`). No default routes and permanent neighbour entries between the
hops: every packet crosses both routers and no ARP crosses netem.

**Path of one run** (`testbed/m2/shape.sh`, created fresh for every run):
- r1 → r2: `netem limit 20000 delay RTTms [loss random P% seed S]`, the whole base RTT and all loss. No
  jitter (no reordering). The ACK direction has no qdisc, delay or loss.
- r2 → rcv: `tbf rate BWmbit burst B limit Q`, B = max(2·1514, BW · 1 ms) bytes, Q = the cell's queue in
  bytes. tbf counts the 14-byte Ethernet header: a full frame is 1514 bytes and payload efficiency at
  most 1448/1514 = 95.6 %.
- Sender: veth `noqueue`, tso and gso off; routers and receiver: gro off; TUNs `pfifo limit 10000`,
  `txqueuelen 10000`.
- Buffers: sender `tcp_wmem = 4096 16384 67108864`, receiver `tcp_rmem` default `4096 131072 33554432`,
  `tcp_no_metrics_save = 1` and `ip tcp_metrics flush` before each run on both.

**Cells.** Bandwidth {10, 100} Mbit/s × RTT {20, 100} ms × loss {0, 0.1, 1} % × queue {0.5, 2} × BDP,
BDP = BW · RTT / 8 (25 000, 125 000, 250 000 and 1 250 000 bytes); 30 s runs at 20 ms, 60 s at 100 ms.
The netem seed is the same for the stack run and the Linux run of one (cell, algorithm, repetition)
and differs between repetitions; pings share the qdisc, so equal seeds mean equal loss processes, not
equal dropped segments.

**One run** (`tools/m2/matrix.py`): shape; `record.sh` before; captures and the tbf sampler start; the
receiver listens; `ping -D -O -i 0.05 -s 56` from `snd` to `rcv` starts 3 s before the sender; the
sender (`utcp-bulk --send --duration S --sample-ms 10`, `--cc X`) runs; `record.sh` after; analysis.
The ping RTTs are taken from the r1-in capture, which sees each echo request and its reply (paired by
ICMP id and sequence, nanosecond timestamps): iputils prints RTTs of 100 ms and more as whole
milliseconds (10-100 ms with 0.1 ms), too coarse for the 100 ms cells. The capture RTT leaves out the
two sender-r1 veth hops (microseconds), which the run's idle base removes as well; `ping.txt` is used
only for a run without the capture. The
stack sender also gets `--set snd_buf_max=64Mi --set rcv_buf_max=32Mi --set gso_max_size=G` (G from the
sender interface's measured `gso_ipv4_max_size`, DESIGN §14.6), `--stats` and `--trace` (retransmissions
and RTOs, kept in memory and written at exit). Plans (`matrix.py run PLAN.toml`, DESIGN §14.7) run each
stack run and the Linux run of the same cell, algorithm and repetition back to back in one slot with one
netem seed; the group order, the netem seeds and the order inside each pair come from the plan's seed.
An invalid group is rerun as a whole right after it (both runs, the same seed and order). `run` refuses
two slots at once (the serial decision below), a non-timing slot unless told (`--nontiming`, the runs
are marked `timing` false), a slot without a passing calibration gate of the same reuse key (`--gate`;
`--no-gate` only outside timing campaigns), and a campaign with runs of another reuse key (`--rekey`
moves those groups aside and reruns them).

**Window.** Every metric uses [t₀ + 5 s, t_end] on CLOCK_MONOTONIC, t₀ = the receiver's accept time (the
`start` line of its JSONL), t_end = min(t₀ + S, the sender's `start` line + S). The sender writes for S
from its own start (its connect returning), which is one RTT before t₀ because all delay is on the data
path; t₀ + S alone would put that RTT after the last write into the window. Counters at the bounds are
interpolated linearly between the 10 ms samples. The drain after the sender stops writing is outside
the window. CLOCK_REALTIME times (captures, ping, the tbf sampler) convert with the clock pair that
`utcp-bulk` writes first in its JSONL.

**Metrics** (`tools/m2/analyze.py`):

| Metric | Definition | Source |
|---|---|---|
| Goodput | Δ`bytes_received` over the window × 8 / window length | receiver JSONL |
| Retransmission rate | Δ`total_retrans` / Δ`data_segs_out` over the window, in % | sender JSONL (same keys for both senders); cross-check below |
| Spurious retransmissions | Δ`dsack_dups` over the window | sender JSONL |
| Queueing delay p50, p99 | ping RTT − base over pings sent in the window; base = median of the replies received before t₀ (3 s idle); lost pings counted, excluded | echo requests and replies in the r1-in capture (`ping.txt` without it) |
| sndbuf-, rwnd-limited time | Δ`sndbuf_limited_us`, Δ`rwnd_limited_us` / window | sender JSONL |
| Jain index | (Σx)² / (n·Σx²) over per-flow goodput in [t_join + 20 s, t₀ + S] | receiver JSONL per flow |
| Convergence time | first t after flow n's join from which every flow's 1 s mean goodput (100 ms steps) stays within ±20 % of C/n for 5 s; "not converged" if none | receiver JSONL per flow |
| Loop lateness p99, max | the stack's EventLoop histogram | `utcp-bulk` summary; the histogram in `--stats` |
| Sender counters | `TcpRetransSegs`, `TcpExtTCPSackRecovery`, `TcpExtTCPLossProbes`, `TcpExtTCPTimeouts`, ... (same names) | Linux: the sender's `nstat` before and after; stack: `--stats` |
| Testbed counters | netem and tbf sent/dropped, tbf backlog (10 ms sampler), interface and qdisc drops, softnet drops and time_squeeze on the slot CPUs, `nstat`; the stack's device errors (invalid) and transmit-queue or pool waits (`loop_pending_calls`, flagged) | `record.sh` before and after, `tbf.txt`, `--stats` |
| Softirq time on slot CPUs | Δ irq and softirq jiffies of the slot CPUs; Δ NET_RX, NET_TX, HRTIMER, TIMER | `/proc/stat`, `/proc/softirqs` in `record.sh` |
| Foreign CPU time | CPU time on the slot CPUs that is not the run's, as a fraction of their time: lower bound Δbusy − Δirq − Δsoftirq − Δ(the four containers' cgroup usage), upper bound Δbusy − Δcontainers (the kernel samples irq time per tick, so softirq that interrupted our tasks is in both) | `/proc/stat` and each container's `cpu.stat` `usage_usec` in `record.sh` |
| Capture cross-check | over the window: data segments and retransmissions in the r1-in capture against the sender's Δ`data_segs_out` and Δ`total_retrans`, data segments in r2-out against the receiver's Δ`data_segs_in`; a difference above max(20, 0.1 %) segments (retransmissions max(3, 5 %)) is flagged | captures (10 ms bins in `capture.json`), JSONL |

Percentiles interpolate linearly between closest ranks.

**Captures.** `tcpdump -s 128 'not ether multicast'` on r1's interface from the sender (`r1-in`) and on
r2's interface to the receiver (`r2-out`), calibration also r1's interface toward r2 after netem
(`r1-out`), written to the `utcp-data` volume under `/m2/<campaign>/<run>/`; the runner logs each
capture's size. Each capture's `packets dropped by kernel` and `packets received by filter` versus
`captured` are checked; tcpdump is stopped 1.5 s after the pings, which stop once the connection has
closed at both ends, so that its 1 s ring blocks are delivered.

**Raw data and archive.** Per run in the volume: `meta.json` (cell, implementation, algorithm,
repetition, order, slot, start time, kernel, image id, commit, binary and core-library sha256, build,
iproute2, cpusets, tbf B and Q, netem line and seed, uptime and top CPU users, for the stack the `--set`
list and the measured `gso_ipv4_max_size`, reuse key), `snd.jsonl`, `rcv.jsonl`, `ping.txt`, `tbf.txt`,
`pre/` and `post/record.txt`, the captures, `capture.json`, for the stack `stats.json` and `trace.jsonl`,
and `summary.json`. `meta.json` also has the algorithm label, the plan group and rerun number, `timing`
and the calibration gate the run relied on. In the repository
`docs/results/m2-<campaign>/runs.csv` and `cells.csv`. The analysis archive (every input except the
captures, with a sha256 manifest) goes to `/m2/archive/` in the volume; `analyze.py tables --archive`
regenerates `runs.csv` and `cells.csv` byte for byte from it.

**Reuse key.** sha256 over the `utcp-bulk` binary and core library hashes, the build, `uname -r`, the
image id, a hash of `testbed/m2` and `tools/m2`, and the containers' `net.ipv4.tcp_*`/`net.core.*`
sysctls and the `tcp_cubic`/`tcp_bbr` module parameters. A run is reused in a later campaign only with
an equal key; otherwise both sides of the cell rerun. `matrix.py run` compares every finished run of the
plan with the key it would give now and refuses a mix; `cells.csv` lists the keys of each cell's counted
runs and marks a cell with more than one "mixed reuse keys" (no verdict).

## Calibration

The calibration gate (M2 design §5.4, DESIGN §14.4), Linux to Linux (CUBIC) for items 1-5 and the stack
for item 6, run on slot 0 and then on slot 1 on 2026-11-14 with commit d713941, kernel 7.0.0-42-generic,
image `utcp-testbed:dev` (`sha256:42acf2a264d9`), `utcp-bulk` from `build/tb-gcc-release`:

```
testbed/m2/up.sh --slot 0; testbed/m2/up.sh --slot 1
UTCP_M2_JOB=utcp-m2d-testbed tools/m2/matrix.py calibrate --slot 0 --campaign m2d-testbed/calib-s0
UTCP_M2_JOB=utcp-m2d-testbed tools/m2/matrix.py calibrate --slot 1 --campaign m2d-testbed/calib-s1
tools/m2/matrix.py gate-table --campaign m2d-testbed/calib-s0 --campaign m2d-testbed/calib-s1
```

Every run's files are in the `utcp-data` volume under `/m2/m2d-testbed/calib-s{0,1}/`, with `gate.json`
and the per-item table `gate.md`. Items and pass conditions:

1. Idle ping, 200 at 50 ms: median within [RTT, RTT + 1 ms], p99 ≤ RTT + 2 ms. Since 2026-11-16 the
   RTTs come from a capture next to the pinging end (r1's sender side; for item 6's ping from the
   receiver, r2's receiver side); the table below is from ping's own output, whole milliseconds at
   100 ms.
2. One Linux CUBIC flow, 0 % loss: goodput ≥ 98 % of the payload rate (BW · 1448/1514), gated with the 2×BDP
   queue; the 0.5×BDP value is reported.
3. Loss 0.1 % and 1 % (Linux CUBIC, both queues): data segments lost on the netem hop, counted as r1-in
   minus r1-out in the captures, inside the exact binomial interval for the offered count at
   α = 0.01/16 (Bonferroni over the 16 tests). Both captures must be complete (0 dropped by the kernel,
   every packet the filter received written), since a packet missing from r1-out would count as a
   netem loss; the gate below predates this check (its captures had 0 kernel drops; the 4 incomplete
   ones are listed under the table).
4. In item 2's run: the tbf backlog reaches [0.9, 1] · Q; at every drop it reaches the tail-drop bound
   (no drop interval with the sampled backlog below Q − 1514 − B − BW · Δt, Δt the sample spacing); and
   ping max − base is within 10 % of the largest backlog a ping can find,
   ((Q − 98) div 1514 · 1514 + 98) · 8 / BW. Where Q ≤ 1514 + B + BW · Δt the bound is not positive and
   any backlog meets it: at 10 ms sampling that is the 0.5×BDP queue at 10 Mbit/s, 20 ms (Q 12 500 B,
   lowest bound −8 272 and −8 746 B on slots 0 and 1) and at 100 Mbit/s, 20 ms (Q 125 000 B, −48 027 and
   −52 989 B). In those two cells the drop check was not testable and item 4 rests on the backlog
   reaching 0.9 · Q and on the ping; `gate.md` now says "not testable at 10 ms sampling" there.
5. In every run of items 2-3: no interface, qdisc or softnet drop, no `time_squeeze`, no capture drop.
6. The stack: idle ping from the receiver to the stack within 0.2 ms of the kernel's; one stack NewReno run
   at 100 Mbit/s, 20 ms, 0 %, 2×BDP with goodput at item 2's threshold, no drops, no device errors.

| Slot | BW, RTT, queue | 1: ping median / p99 (ms) | 2: goodput, % of BW | 4: backlog max, % of Q; ping max - base / target (ms) | 3: loss % at 0.1 / 1 (lost segments in the accepted interval) | 5: drops, squeeze | Pass |
|---|---|---|---|---|---|---|---|
| 0 | 10 Mbit/s, 20 ms, 2xBDP | 20.10 / 20.20 | 95.49 | 99.9; 38.7 / 38.8 | 0.092 (23 in [10, 44]) / 1.058 (161 in [112, 196]) | 0 of 3 runs | yes |
| 0 | 10 Mbit/s, 20 ms, 0.5xBDP | 20.10 / 20.10 | 95.48 (not gated) | 97.7; 9.2 / 9.8 | 0.089 (22 in [10, 43]) / 0.968 (155 in [119, 205]) | 0 of 3 runs | yes |
| 0 | 10 Mbit/s, 100 ms, 2xBDP | 100.00 / 100.00 | 95.50 | 99.5; 198.0 / 199.9 | 0.112 (35 in [14, 52]) / 1.025 (68 in [40, 96]) | 0 of 3 runs | yes |
| 0 | 10 Mbit/s, 100 ms, 0.5xBDP | 100.00 / 100.00 | 95.49 (not gated) | 99.5; 49.0 / 49.7 | 0.137 (31 in [8, 41]) / 1.069 (73 in [42, 98]) | 0 of 3 runs | yes |
| 0 | 100 Mbit/s, 20 ms, 2xBDP | 20.10 / 20.20 | 95.63 | 99.6; 39.2 / 40.0 | 0.097 (60 in [37, 91]) / 1.088 (179 in [123, 210]) | 0 of 3 runs | yes |
| 0 | 100 Mbit/s, 20 ms, 0.5xBDP | 20.10 / 20.20 | 95.63 (not gated) | 99.3; 9.1 / 9.9 | 0.086 (56 in [39, 94]) / 0.899 (163 in [137, 229]) | 0 of 3 runs | yes |
| 0 | 100 Mbit/s, 100 ms, 2xBDP | 100.00 / 100.00 | 95.63 | 99.9; 200.0 / 200.0 | 0.083 (42 in [28, 77]) / 0.914 (74 in [52, 113]) | 0 of 3 runs | yes |
| 0 | 100 Mbit/s, 100 ms, 0.5xBDP | 100.00 / 100.00 | 95.63 (not gated) | 99.8; 50.0 / 49.9 | 0.137 (28 in [7, 37]) / 0.837 (75 in [59, 123]) | 0 of 3 runs | yes |
| 1 | 10 Mbit/s, 20 ms, 2xBDP | 20.10 / 20.20 | 95.49 | 99.9; 38.7 / 38.8 | 0.092 (23 in [10, 44]) / 1.065 (163 in [113, 197]) | 0 of 3 runs | yes |
| 1 | 10 Mbit/s, 20 ms, 0.5xBDP | 20.10 / 20.20 | 95.48 (not gated) | 97.7; 9.0 / 9.8 | 0.093 (23 in [10, 43]) / 0.948 (153 in [120, 206]) | 0 of 3 runs | yes |
| 1 | 10 Mbit/s, 100 ms, 2xBDP | 100.00 / 100.00 | 95.50 | 99.5; 198.0 / 199.9 | 0.108 (35 in [15, 53]) / 1.098 (69 in [38, 91]) | 0 of 3 runs | yes |
| 1 | 10 Mbit/s, 100 ms, 0.5xBDP | 100.00 / 100.00 | 95.49 (not gated) | 99.5; 49.0 / 49.7 | 0.130 (30 in [9, 41]) / 1.142 (74 in [39, 94]) | 0 of 3 runs | yes |
| 1 | 100 Mbit/s, 20 ms, 2xBDP | 20.10 / 20.20 | 95.63 | 99.9; 39.2 / 40.0 | 0.097 (61 in [37, 91]) / 1.066 (174 in [122, 208]) | 0 of 3 runs | yes |
| 1 | 100 Mbit/s, 20 ms, 0.5xBDP | 20.10 / 20.20 | 95.61 (not gated) | 99.4; 9.2 / 9.9 | 0.086 (56 in [39, 94]) / 0.912 (166 in [138, 230]) | 0 of 3 runs | yes |
| 1 | 100 Mbit/s, 100 ms, 2xBDP | 100.00 / 100.00 | 95.63 | 99.9; 200.0 / 200.0 | 0.078 (40 in [29, 78]) / 0.923 (71 in [49, 108]) | 0 of 3 runs | yes |
| 1 | 100 Mbit/s, 100 ms, 0.5xBDP | 100.00 / 100.00 | 95.63 (not gated) | 99.6; 50.0 / 49.9 | 0.125 (26 in [7, 38]) / 0.904 (83 in [61, 126]) | 0 of 3 runs | yes |

| Slot | Item 6 part | Result | Pass |
|---|---|---|---|
| 0 | ping | idle ping median rcv to stack 20.1 ms, snd kernel to rcv 20.1 ms | yes |
| 0 | run | stack NewReno 100 Mbit/s, 20 ms, 0 %, 2xBDP: 65.42 Mbit/s (threshold 93.73); retransmitted 0.29 %; rwnd-limited 20.7 %, sndbuf-limited 0.0 %; loop lateness p99 bucket <= 32767 ns; drops none | NO |
| 0 | path | stack NewReno 100 Mbit/s, 20 ms, 0 %, 2xBDP, --snd-buf 400000: 95.62 Mbit/s (threshold 93.73); retransmitted 0.00 %; rwnd-limited 0.0 %, sndbuf-limited 4.1 %; loop lateness p99 bucket <= 524287 ns; drops none | yes |
| 1 | ping | idle ping median rcv to stack 20.2 ms, snd kernel to rcv 20.1 ms | yes |
| 1 | run | stack NewReno 100 Mbit/s, 20 ms, 0 %, 2xBDP: 66.54 Mbit/s (threshold 93.73); retransmitted 0.28 %; rwnd-limited 19.7 %, sndbuf-limited 0.0 %; loop lateness p99 bucket <= 262143 ns; drops none | NO |
| 1 | path | stack NewReno 100 Mbit/s, 20 ms, 0 %, 2xBDP, --snd-buf 400000: 95.62 Mbit/s (threshold 93.73); retransmitted 0.00 %; rwnd-limited 0.0 %, sndbuf-limited 7.7 %; loop lateness p99 bucket <= 1048575 ns; drops none | yes |

**First calibration, November 14.** Items 1-5 (Linux to Linux) passed on both slots in all 8 (bandwidth, RTT, queue) cells. Item 6
passes its ping part and fails its run on both slots: the stack (M1 code) reaches 65.4 and 66.5 Mbit/s
against the 93.73 Mbit/s threshold. NewReno's slow-start overshoot overflows the 2×BDP queue (0.28-0.29 %
of segments retransmitted, 647 and 632 tbf drops), and the M1 sender's recovery repairs about one hole
per RTT (INTEROP.md open items), so the receiver's window stops advancing and the sender is
rwnd-limited for 20 % of the window. The same run
with the stack's send buffer at 400 000 B (below BDP + queue, no loss) carries 95.62 Mbit/s on both
slots. Each historical gate retained 66 passing rows and the failed default-buffer transfer.

Captures: 68 per slot, 996.7 MB (slot 0) and 996.4 MB (slot 1) in total, at most 95.6 MB for one
capture; 0 packets dropped by kernel in every one. In 4 runs (1 on slot 0, 3 on slot 1) 1 to 5 packets
were counted by the filter and not written (flag `capture_incomplete`); the last packets in those
captures are the host's SSDP multicast (`198.19.X.1 > 239.255.255.250.1900`), which arrives in bursts
and sat in the last ring block. The gate's captures were taken without a filter; since then the runner
captures with `not ether multicast`. The netem drop counter exceeds the data segments lost on the
netem hop by the pings it dropped. Item 4's ping maxima are within 0.8 ms of the attainable target.

**Testbed checks.** `tests/interop/m2_testbed.sh --slot 0` and `--slot 1` after the gate (commit 1b0105f):
106 checks ok on each, none failed: containers, networks, addresses, routes, cpusets and sysctls; every
`record.sh` item; `shape.sh` for the 8 (bandwidth, RTT, queue) combinations at 0, 0.1 and 1 % loss;
2000 pings at 10 % loss with seed 1234 twice lose the same `icmp_seq` set and seed 1235 a different one;
`down.sh` removes exactly the slot.

**Scripted drops** (§4.2, `testbed/m2/drop.sh`, `tests/interop/m2_testbed_drops.sh`, M2 tasks test 10), on
the non-timing slot 2 with the Linux sender, 100 Mbit/s, 20 ms, a 40×BDP queue, 5 MB per run; what r1
(and r2) dropped is read from the captures before and after the router with `tools/m2/dropcheck.py`, which
also computes from the capture before the router which segments the rule must latch (DESIGN §14.5).

The first version (up to commit 80ee74e) matched the exact sequence ISN + 1 + OFF. It dropped nothing in
3 runs (one copy-1 run of the fix pass, two copy-12 runs of the three verification passes): the Linux
sender sent a short segment earlier in the stream (1360 B at offset 192 584, 512 B at 195 480, 840 B at
440 192), so offset 1 448 000 was no segment start. Replayed on the two verification captures, the current
rule latches 1 448 512 and 1 448 840, the first starts at or after the offset. Its watcher, `tcpdump -c 1`,
armed 21-64 ms after the SYN (54 logs, including 5 passes of the range rule with that watcher, all PASS),
more than the 20 ms RTT.

Current version (a target latches the first segment start in [OFF, OFF + N·1448); AF_PACKET watcher):
`tests/interop/m2_testbed_drops.sh --slot 2 --campaign m2d-testbed/refix-drops11` .. `refix-drops15`, five
passes in a row on 2026-11-17, all PASS (6 cases each). Each capture complete (90 captures, received by
filter = captured, 0 dropped by kernel). The watchers armed 2.2-2.7 ms after the SYN. Per pass:

| Case | Armed | Dropped by r1 (offset, copy) | Dropped by r2 | Result |
|---|---|---|---|---|
| copy1 | r1: offset 1 448 000, copy 1 | 1 448 000, copy 1 (#1003-#1004 in r1-in) | none | 5/5 pass |
| copy2 | r1: offset 1 448 000, copy 2; r2: copy 1 | 1 448 000, copy 2 (#1290-#1329) | 1 448 000, copy 1 (#1003 of r1-out) | 5/5 pass |
| copy12 | r1: offset 1 448 000, copies 1 and 2 | 1 448 000, copies 1 and 2 | none | 5/5 pass |
| mid | r1: offset 1 448 700, copy 1 | 1 449 448, copy 1 (the next segment start) | none | 5/5 pass |
| burst | r1: offset 2 896 000, 5 segments, copy 1 | 2 896 000 + 1448·k, k = 0..4, copy 1 | none | 5/5 pass |
| ct | r1: `ct original packets 500` | #500, offset 716 760-719 656, copy 1 (a first transmission) | none | 5/5 pass |

No pass had a short segment before its target, so the shifted-boundary case was exercised live only by
`mid` (an offset that is no segment start) and offline by the replay above. These 5 MB runs are shorter than
the analysis window, so `summary.json` marks them invalid for the statistics; they are mechanism checks only.

### Integrated calibration, November 19, 2026

Both slots passed on commit `3f48c30dbf70240d50234f095eaca6de24fc0625`. Each full calibration
covered all eight bandwidth, RTT and queue combinations, both loss rates, and both stack NewReno
transfers. The fixed stack goodput threshold was 93.727873 Mbit/s. Each gate consumer rechecked
62 source fingerprints. The separate slot 0 diagnostic on `8facd285` passed 67/67 under key
`96d5b26f1e9db5fd7e971c8a5a304c420fb1605078a7ff8ce5d9c82bcfddcff7`.
Its default and capped rates were 95.625960 and 95.617249 Mbit/s. Its peer slot and proof were
never acquired. The November 14 runs above each passed 66/67. Their original gate JSON files
under `/m2/m2d-testbed/calib-s{0,1}/` retain SHA-256
`1cc7cd9ba1cd19decaf2c13f61eb02529b8b637b29efbaa8d920d6ec23f95631` and
`167490c922089a8a719e0e0e9a24bca82393aea3b119f7571d5fba34bc1637d2`, respectively.

| Final slot | Passing rows by item 1–6 | Default / capped NewReno (Mbit/s) | Stack / kernel idle medians (ms) | Signed difference (ms) |
|---|---|---:|---:|---:|
| 0 | 8 / 8 / 16 / 8 / 24 / 3 | 95.625513 / 95.617723 | 20.0906315 / 20.0544080 | +0.0362235 |
| 1 | 8 / 8 / 16 / 8 / 24 / 3 | 95.625965 / 95.617396 | 20.0836445 / 20.0569400 | +0.0267045 |

| BW (Mbit/s) | RTT (ms) | Queue (×BDP) | Linux goodput, slots 0 / 1 (Mbit/s) | Idle ping p99, slots 0 / 1 (ms) |
|---:|---:|---:|---:|---:|
| 10 | 20 | 0.5 | 9.5491 / 9.5491 | 20.1309 / 20.1870 |
| 10 | 20 | 2 | 9.5491 / 9.5492 | 20.1719 / 20.1961 |
| 10 | 100 | 0.5 | 9.5495 / 9.5495 | 100.1210 / 100.2120 |
| 10 | 100 | 2 | 9.5495 / 9.5497 | 100.1410 / 100.1984 |
| 100 | 20 | 0.5 | 95.6255 / 95.6236 | 20.1601 / 20.1459 |
| 100 | 20 | 2 | 95.6255 / 95.6255 | 20.1991 / 20.2141 |
| 100 | 100 | 0.5 | 95.6258 / 95.6260 | 100.1327 / 100.1237 |
| 100 | 100 | 2 | 95.6264 / 96.1082 | 100.1745 / 100.1790 |

Slot 1's 96.1082 Mbit/s value comes from the receiver's TCP_INFO counter. The router capture
shows 3,307,232 unique bytes already above the first hole at the start of the window. Closing
the holes credited those buffered bytes during the window. At the end, all captured bytes formed
one contiguous sequence. The TCP payload actually crossing the router in the 54.899956 s window
measured 95.626314 Mbit/s.

Each slot had 24 connected Linux CUBIC senders and two stack NewReno senders. All 52 transfers
had matching endpoint byte counts and SHA-256. Independent interpolation of the receiver samples
reproduced all reported goodputs. Each run covered both ends of its measured window.
Reparsing the 136 transfer captures recovered 16,840,981 records. All filter and captured
counts matched, with zero kernel capture drops. The 20 separate idle wire captures contained
4,000 replies to 4,000 requests. The kernel controls probed the receiver from the sender.
The stack probes ran from the Linux receiver to the stack TUN address. Default sndbuf-limited time
was zero on both slots. The 400,000-byte controls spent 3.761% and 3.840% of their respective
windows sndbuf-limited. All four transfers had zero rwnd-limited time.

The canonical GCC 15.2 release build used `-O3 -DNDEBUG` in container path
`/home/postedism/Desktop/utcp-wt/int-wire40`. Its executable and core library matched the
functional-test build and the archived diagnostic binaries byte for byte. The 429-file source
snapshot was checked against the Git tree on both hosts. Both live slots had the same key,
`cd50db51c944442c8f1158f6b5e48f01ab3f913d9b96034a675af9a8aed9c1fd`.
The kernel was `7.0.0-42-generic`, with scripts digest
`43bf359c7ba1bf5d40f3a58ef7c4c9e5ba82737038b6d25ba35aa52d55b72912` and sysctl/module digest
`795239ee27aa80ccc53bfffd887dddc48aaba8497ce72e08c1f23e1320cbadcf`. The topology records
show sender veth TSO/GSO off and forwarding-interface GRO off. The sender had a 64 MiB TCP
send-buffer maximum, the receiver a 32 MiB receive-buffer maximum, and both had
`tcp_no_metrics_save=1`.

The runs were acquired serially on the assigned topologies. For a clean reproduction use a fresh
campaign name with the same frozen inputs. The original invocations were

```sh
set -euo pipefail
export UTCP_M2_PREFIX=utcp-m2-finalgate UTCP_M2_JOB=utcp-m2-finalgate-runner
sha=3f48c30dbf70240d50234f095eaca6de24fc0625
for n in 0 1; do
    taskset -c 16-31 nice -n 10 python3 tools/m2/matrix.py calibrate \
        --slot "$n" --campaign "m2-integrate/${sha}-calib-a1-s$n"
done
```

The raw roots in `utcp-data` are `/m2/m2-integrate/${sha}-calib-a1-s{0,1}/`.
The corresponding `/m2/archive/m2-integrate-${sha}-calib-a1-s{0,1}-audit-1/` directories
hold the non-pcap inputs and per-file raw indices. Adjacent `-physical-a1/` directories
hold the independent packet counts, RTTs, load and per-run statistics.

| Slot | Gate JSON SHA-256 | Compact analysis archive SHA-256 |
|---|---|---|
| 0 | `a3f4d37564f8fea9704c69775c63fec05e61e05cebb3f2d18fba7e80dbb596d8` | `b6d15cdb97fec301583606b1142281c12b77c93bfabfb278ace438bccc94324b` |
| 1 | `8049131065bc7d9c9956beb4ba51009daf79168feabc36303f4b620d761d0c3d` | `4e7ba3c7838078f662f41006b16b7f1b0b8b435343e94d3148a6f43577132c74` |

The original diagnostic gate JSON has SHA-256
`801093b249e62b7e4ac0b7e8851d3e82a99cab22fa26683dfadb69de9f8ae053` in
`/m2/m2-integrate/8facd2852d3d42c77a8204e2cf7d6ae28a7044c7-calib-a1-s0/`.
For a later timing checkout, `/m2/archive/m2-integrate-${sha}-final-handoff-a1/README.md`
contains the tested binary restore and live gate-consumer commands. Its manifest SHA-256 is
`a246c0002e2409f33d3b7f0aea3a352bca3fad27a160b09ffc6c7193133786d6`. The underlying source,
binaries, compiler cache, full topology and sysctls are in the sibling `-final-freeze-a1/` archive.
Its manifest SHA-256 is `ac39786b0eec79f52bc79f51a2d6700796d172525f5e3f464b7a8dc24abdea49`.

## Gap rule and thresholds

Fixed before the first matrix run, in commit d713941 (branch `m2d-testbed`), which added this section;
amended on 2026-11-16, still before any matrix run, in commit 80ee74e (same branch), which added
this sentence (a metric needs 5 values per side for a verdict); not changed afterwards (PLAN 2d; M2
design §5.10). Implemented in `tools/m2/analyze.py` (`gap_verdict`, constants at the top).

Per cell and algorithm, the stack (`linux_compat`) and Linux are compared on the statistics of their
counted runs (next section): median, minimum and maximum of 5 runs.

- **Goodput, queueing delay p50, queueing delay p99** (each separately): a **gap** when the medians
  differ by more than 10 % of the Linux median **and** the two 5-run ranges [min, max] do not overlap
  (touching ranges overlap). A stack result better than Linux by that much is a gap too.
- **Values per side.** A metric that has fewer than 5 values on a side among the counted runs (for
  example a run without ping replies in the window) gets no verdict ("n/a"); `cells.csv` gives the
  count per metric.
- **Below resolution.** A queueing-delay gap whose absolute median difference is below 1 ms (strictly;
  exactly 1 ms is a plain gap) is marked "gap (below resolution)". It stays a gap. Its written cause is "below measurement resolution" (the
  user's decision of 2026-11-14, PLAN §10): about the resolution of ping, netem and the per-run base;
  no further root-cause work.
- **Retransmission rate:** a gap when the stack's median exceeds Linux's by more than an absolute
  threshold **and** the ranges do not overlap. Thresholds, in percentage points of retransmitted
  segments over data segments sent: **0.05** at 0 % and 0.1 % loss, **0.2** at 1 % loss. A stack that
  retransmits less than Linux has no retransmission gap.
- **Reported, not a gap by themselves:** Jain index differences above 0.05; convergence time;
  spurious retransmissions; limited-time fractions; loop lateness.
- Each gap cell gets a cause from the traces and captures, or a fix; after a fix the cell is rerun in
  full and both results are kept. Cells worse than Linux stay in the tables.

**Transient-dominated cells**, named before the first run (M2 design §5.5): 100 Mbit/s, 100 ms, 0 % loss
with the 0.5×BDP and the 2×BDP queue, for NewReno and CUBIC. A Reno or CUBIC window of about 1240
(0.5×BDP) to 2480 (2×BDP) packets needs about 60-120 s per sawtooth or queue fill, longer than the
55 s window, so these cells measure the phase set by slow-start exit, not steady state. Run lengths
stay as PLAN fixes them; these cells are marked in every table.

## Which runs count

Fixed before the first matrix run, in commit d713941 (branch `m2d-testbed`), which added this section
(M2 design §5.3, §5.6); amended on 2026-11-16, still before any matrix run, in commit 80ee74e (same
branch), which added this sentence: groups instead of single runs are counted and rerun, the stack's
own drops and missing sender data invalidate, foreign CPU time and capture mismatches are flagged.
Implemented in `tools/m2/analyze.py` (`summarize_run`, `select_runs`) and `tools/m2/matrix.py`
(`run_plan`).

- **Invalid runs** (out of the statistics, kept and marked in `runs.csv`, rerun): a non-zero rx or tx
  drop counter on any interface of the four containers (sender eth0, routers, receiver, the ACK path,
  the `utcp*` TUNs) or a `utcp*` pfifo drop; softnet drops on the slot's CPUs; drops in the ACK
  direction's qdiscs (they are `noqueue`; the rule guards a qdisc added there); the stack's
  `DeviceStats` tx or rx errors or a device failure; datagrams the stack dropped itself
  (`IpOutDiscards`, `TcpExtTCPRcvQDrop`, `TcpExtTCPOFODrop` in `--stats`); either `utcp-bulk` not ok or
  different SHA-256 at the two ends; a missing receiver or sender JSONL; receiver or sender samples
  that do not cover the window.
- **Flagged runs** (in the statistics, flag shown): `time_squeeze` on the slot's CPUs; sndbuf- or
  rwnd-limited time ≥ 1 % of the window; capture kernel drops or an incomplete capture; foreign CPU
  time on the slot's CPUs ≥ 2 % of their time (lower bound, Method); a capture cross-check difference
  (Method); the stack waiting for transmit-queue or pool space (`loop_pending_calls`). A buffer change
  made because of a limited-time flag reruns the whole cell for both senders.
- **Groups.** A group is the runs of one cell, algorithm and repetition that run back to back in one
  slot with one netem seed (the stack run and the Linux run). A group is valid when it has a run of
  every implementation of the cell and all of them are valid. An invalid group is rerun as a whole
  right after it (`<run>-rerunK`, the same seed and in-group order).
- **Counting.** Per (cell, algorithm) the statistics use exactly the runs of the first 5 valid groups
  in run order, so the counted stack and Linux runs are the same pairs. When a (cell, algorithm) has
  had more than 3 invalid groups it is reported **invalid** and gets no verdict; with fewer than 5
  valid groups it is reported incomplete; when its counted runs carry more than one reuse key it is
  reported "mixed reuse keys" and gets no verdict.
- Each counted cell reports the median and the range (minimum, maximum) of its 5 runs per metric, and
  the number of values per metric.

## Timing hygiene

Fixed parts (M2 design §6):
- Slot 0 uses CPUs 8-11 (sender 8,9; receiver 10; routers 11), slot 1 CPUs 12-15 (12,13; 14; 15).
  Builds and analysis use 16-31 with `nice -n 10`; CPUs 0-7 are not used. At most one run per slot.
- Every run records `uptime`, the top CPU users, the threads last seen on CPUs 8-15, and the slot CPUs'
  `/proc/stat` busy, irq and softirq deltas, `/proc/softirqs` and `/proc/net/softnet_stat`; since
  2026-11-16 also the four containers' cgroup CPU usage, from which `summary.json` and `runs.csv` give
  the foreign CPU time on the slot's CPUs (Method; flagged at 2 %). The November 15 NewReno runs predate it.
- The softirq work of the whole path (r1 forwarding, netem, tbf, the receiver's TCP input and ACKs, the
  ACKs' processing at the sender) runs mostly on the CPU that transmitted, the sender's core; the
  stack's loop lateness therefore includes it, and both senders see the same work on the same core.

**Decision: timing runs are serial**: never two timing runs at once on CPUs 8-15. Plans run with one
slot (`matrix.py run PLAN --slot 0`; `run` refuses a second slot without `--parallel`); a gate run on
slot 1 runs while slot 0 is idle. Two slots at once failed the pre-registered criterion of M2 design §6
(stack loop lateness max in parallel ≤ 2 × serial) on slot 1. The decision rests on that maximum, which
comes from one run (below).

**Parallel-mode proof** (M2 design §6, DESIGN §14.7), 2026-11-15 08:33-09:30 PST, commit ba1766f, kernel
7.0.0-42-generic, image `sha256:42acf2a264d9`, 5 repetitions per item; serial on slot 0, then the same
list on slots 0 and 1 at once:

```
testbed/m2/up.sh --slot 0; testbed/m2/up.sh --slot 1
UTCP_M2_JOB=utcp-m2d-testbed tools/m2/matrix.py proof --campaign m2d-testbed/proof
```

Files in `utcp-data` under `/m2/m2d-testbed/proof/` (`proof.json`, `proof.md`, `serial-s0/`,
`parallel-s0/`, `parallel-s1/`). Gate items 1, 2 and 4 (Linux CUBIC, 2×BDP, 0 %) pass in all four
(bandwidth, RTT) pairs on both parallel slots: ping medians equal to the serial ones (limit 0.2 ms),
goodput medians within 0.005 % (limit 1 %), tbf backlog maxima within 0.004 % (limit 2 %), ranges
overlapping. Stack NewReno, 100 Mbit/s, 20 ms, 0 %, 2×BDP, with the trace:

| Metric | Serial (slot 0) | Parallel slot 0 | Parallel slot 1 | Limit | Pass |
|---|---|---|---|---|---|
| goodput median [range] (Mbit/s) | 65.93 [65.69, 67.44] | 65.73 [65.62, 65.83] | 65.94 [65.30, 67.84] | ±2 %, ranges overlap | yes / yes |
| loop lateness p99, pooled histogram (ns) | 65 535 | 65 535 | 131 071 | ≤ 1 log2 bucket above serial | yes / yes |
| loop lateness max over 5 runs (ns) | 2 372 926 | 2 141 416 | 4 996 323 | ≤ 2 × serial | yes / **no** |
| ping p99 median (ms), reported | 39.40 | 39.31 | 39.41 | - | - |

Slot 1's p99 is one log2 bucket higher than the serial value. The histogram's buckets are a factor of 2
wide, so a p99 one bucket up lies anywhere from just above to almost 4 × the serial one: "≤ 2 ×" can be
neither shown nor refuted there. The first report (2026-11-15, kept as `proof-2026-11-15.md`) compared
the bucket edges, 131 071 > 2 × 65 535, and failed it; the evaluation now reads "≤ 2 ×" as at most one
bucket higher and passes it (`proof.md` regenerated from the same runs on 2026-11-16, no new runs). Slot
1's per-run p99 was in that bucket in 3 of 5 runs, the serial and parallel slot 0 runs in 1 of 5 at
most. Slot 1's max comes from one run (r4, 5.0 ms; the other four
1.30-2.11 ms); 2.1 × the serial max. The serial runs were all on slot 0, so this does not separate the
effect of the parallel run from a difference between the two slots' cores, nor from other tenants'
load on CPUs 12-15 during that run (the foreign CPU time was not measured then; from the records'
`/proc/stat`, CPUs 12-15, idle as far as the testbed goes, were 2.0-7.1 % busy during the 30 serial
runs). The serial decision does not depend on separating them. The CPUs 8-15 are not
isolated on this host: every run's `threads_on_8_15` lists other services' processes last seen there
(airflow, grok-bot, kubelet, containerd, minio, editors, browsers), and the 1-minute load average was
2.7-11.2 during the proof. Timing runs therefore record and keep this per run (meta.json `uptime`,
`top_cpu`, `threads_on_8_15`), as M2 design §6 requires.

The same runs check the buffers (§5.3): sndbuf-limited time 0 in every stack and Linux run. Linux's
rwnd-limited time is 0; the stack sender is rwnd-limited for about 20.7 % of the window (13.1 % and 0 %
in two runs, 18.0 % in one), with the Linux receiver's 32 MiB maximum buffer. The cause was not examined here; with M1
recovery this run also falls short of the gate's goodput (Calibration, item 6), and m2-integrate's gate
rerun on M2 recovery checks both.

**Trace overhead** (M2 design §5.6), stack NewReno 100 Mbit/s, 20 ms, 0 %, 2×BDP, serial on slot 0,
5 runs with `--trace` and 5 without, in the same proof campaign (`stack-trace-r*`, `stack-notrace-r*`):
goodput median 65.93 Mbit/s [65.69, 67.44] with the trace and 65.89 [65.67, 68.83] without; pooled
lateness p99 65 535 ns both; lateness max 1.81-2.37 ms with, 1.78-2.11 ms without; 623-709 trace events
per run. No cost is visible at this event count. The core does not emit `cwnd` or `recovery` events
yet (DESIGN §14.6), so these traces hold only retransmissions and RTOs; once those kinds are emitted
the measurement is repeated.

### Integrated CUBIC parallel proof, November 19, 2026

The frozen calibration build ran 15 trace-enabled `linux_compat` CUBIC transfers at 100 Mbit/s,
20 ms, zero configured loss and 2×BDP. All endpoint SHA-256 values and byte counts matched,
and all 15 senders reported CUBIC throughout the measured window. The five serial transfers
ran on slot 0. Five subsequent pairs had simultaneous measured windows on slots 0 and 1,
with overlap 24.978921–24.979886 s (99.996222–99.999913% of the longer window).
The proof uses receiver acceptance plus five seconds as the lower bound, and the earlier of the
sender and receiver duration endpoints as the upper bound. The two slots share a boot ID. All 30 transfer captures replayed, totaling 11,144,434 records,
with matching filter and captured counts and zero kernel capture drops.

| Metric | Serial slot 0 | Parallel slot 0 | Parallel slot 1 |
|---|---:|---:|---:|
| Goodput median [range], Mbit/s | 95.625730 [95.625495–95.625975] | 95.625862 [95.625727–95.625961] | 95.625800 [95.625502–95.625857] |
| Pooled histogram samples | 20,979 | 21,520 | 21,163 |
| Pooled loop lateness p99 bucket upper edge, ns | 32,767 | 65,535 | 65,535 |
| Exact greatest loop lateness, ns | 2,618,734 | 2,774,214 | 2,956,912 |
| Median of per-run ping RTT p99, ms | 59.8132 | 59.7474 | 59.8185 |
| Median of per-run queueing delay p99, ms | 39.7381 | 39.6687 | 39.7710 |
| Greatest sndbuf- / rwnd-limited time, % of window | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| Foreign CPU lower bound, range (%) | 1.795–6.065 | 6.327–27.279 | 2.209–4.686 |

| Repetition | Serial exact max (ns) | Parallel slot 0 exact max (ns) | Parallel slot 1 exact max (ns) | Overlap (s) |
|---:|---:|---:|---:|---:|
| 0 | 2,362,432 | 2,774,214 | 2,956,912 | 24.979614 |
| 1 | 1,654,352 | 2,750,379 | 1,206,505 | 24.979779 |
| 2 | 2,195,985 | 2,012,068 | 2,006,609 | 24.978921 |
| 3 | 1,413,836 | 2,006,075 | 1,420,729 | 24.979110 |
| 4 | 2,618,734 | 1,916,306 | 1,098,404 | 24.979886 |

The CUBIC proof passed all predeclared comparisons on both slots. The earlier NewReno proof
still determines the serial production schedule.

The allowed parallel goodput median difference was 2% with overlapping ranges. The allowed
pooled p99 change was one log2 bucket. The exact parallel maximum limit was
5,237,468 ns, twice the exact serial maximum. Each reported loop maximum was independently
checked against the sender terminal record and the backend statistics. The ping RTT values
come from request/reply captures, with the base subtracted only for the queueing-delay row.

All 15 runs retained host uptime, top CPU users, other threads last seen on CPUs 8–15,
per-CPU busy/irq/softirq ticks and container cgroup usage. Foreign CPU time varied during the
two full calibration gates as well. Its lower bound ranged from 0.966% to 14.541% on slot 0
and 0.889% to 9.667% on slot 1. The 2% flag appeared in 16/26 and
17/26 calibration transfers, respectively, and 14/15 proof transfers. The per-run
metadata and per-CPU deltas are retained with the raw data.

```sh
set -euo pipefail
export UTCP_M2_PREFIX=utcp-m2-finalgate UTCP_M2_JOB=utcp-m2-finalgate-runner
sha=3f48c30dbf70240d50234f095eaca6de24fc0625
taskset -c 16-31 nice -n 10 python3 tools/m2/matrix.py proof \
    --campaign "m2-integrate/${sha}-proof-a1-cubic" --cubic-only
```

The historical NewReno proof JSON still has SHA-256
`a055af5f4c652032b376be8549395d2221ec2a8a017deab9eb248cec15c8e1e6` under `/m2/m2d-testbed/proof/`.

The original raw root is `utcp-data:/m2/m2-integrate/${sha}-proof-a1-cubic/`.
Its proof JSON SHA-256 is `61678ae37526bc0b15fbe896ecfa2b9f9af4c1cfa0af80e4e18b0681a2ce1ab4`.
The non-pcap archive has 245 entries and SHA-256
`83a1d773e8c3c9a27f55351abfb4a53b3f01bf4c69859badc3fa78f5475920a5` in
`/m2/archive/m2-integrate-${sha}-proof-a1-cubic-audit-1/`. The adjacent
`-physical-a1/physical-replay.json` records the independent packet, time-window and histogram checks.

## Comparison with Linux traces

### Historical recovery runs on the M1 testbed

These 1 GB transfers used the M2 recovery implementation with a NewReno stack sender. The N2 Linux
reference used CUBIC. The [N0 receiver ACK counts](INTEROP.md#ack-frequency-of-the-stacks-receiver)
come from separate transfers in the reverse direction.

| Stack sender case | M1 run5 | M2 recovery build | M2 first verification | M2 second verification |
|---|---:|---:|---:|---:|
| N1 loss, RTO expiries | 150 | 8 | 0 | 9 |
| N4 loss, duplication and reordering, RTO expiries | 133 | 5 | 8 | 0 |

The M1 Linux reference sender counted 12 timeouts on N1 (run3) and 8 on N4 (run6). Captures at
both endpoints show that the receiver had already sent a covering ACK for all 8 N1 expiries in
the M2 build and all 9 in the second verification. In the build's N4 run, 3 of the
5 timeout retransmissions first delivered the missing bytes. The receiver had missed 2, 2 and 3
earlier copies of those segments. The sender had one retransmission in flight and SACKs for every
other outstanding segment. With no later delivery to reveal that loss to RACK, the RTO supplied
the fallback. The receiver had already acknowledged the other two. Both N3 duplication-only runs
(build and second verification) had zero retransmissions, down from 432 in M1 run5.

N2 injected reordering only. Over ten M2 runs through the first repair pass the stack counted
1083–5253 fast retransmissions (median 2582), spanning the M1 run5 count of 1800. In the M2 build,
2833 fast retransmissions accompanied 2779 D-SACKed segments and 87 recoveries. The separate second
verification saw 734 fast retransmissions, 730 D-SACKed segments and 49 recoveries. The respective
Linux reference runs had 306 and 508 **total** retransmissions and 194 and 176 partial undos.
D-SACKs confirm duplicate delivery. Linux can undo a spurious loss decision on a partial ACK. The
stack lacks this recovery-undo path, a plausible contributor to its extra retransmissions. The
counter totals do not assign a cause to each retransmission or isolate the effect of undo.

The archived M2 captures are in `utcp-data:/m2/m2a-recovery/p2/` and
`utcp-data:/m2/m2a-recovery-verify-2/m1/`. The per-timeout capture comparisons and sender
`TCP_INFO` samples are in `utcp-data:/m2/m2a-recovery/refix2/results.json`.

### Directed losses on the integrated runtime

All 40 transfers on November 18, 2026 Pacific matched the sender and Linux receiver byte counts and
SHA-256. Across 20 stack/Linux pairs the senders retransmitted the same hole-relative byte ranges,
in the same order and with the same copy numbers. Their complete ACK-by-ACK transmissions differed
in every pair. The largest consequence was in the 100,000-byte tail test. Three stack runs waited
for a retransmission timeout and exited with cwnd 2. All four Linux runs repaired the hole on the
probe's SACK and exited with cwnd 38–54.

The build used source `5bd13159f8412786d8f619848ac24d0aa19a1641`, GCC 15.2 release, and kernel
7.0.0-42-generic. Slot 2's four containers used CPUs 16–31, a 100 Mbit/s link, 20 ms base RTT,
40 BDP of queue, and zero random loss. Both senders used the same Linux receiver and per-case
application byte count. The stack selected `linux_compat` with Linux CC flavor, PRR and RACK/TLP.
Connected sender samples confirmed NewReno or CUBIC on every run. The stack configuration line
describes defaults before the per-socket algorithm selection.

**What was captured.** The 32 longer transfers each sent 3,000,000 bytes. For the eight 100,000-byte
transfers the last two original payloads started at 98,464 (1,448 bytes) and 99,912 (88 bytes).
All burst, lost-retransmission and tail targets occurred in slow start, as shown by the stack TX
trace and bracketing Linux samples. The router armed 2.3–3.3 ms after the SYN. Comparison of the
upstream and downstream packets found
all 96 intended drops, including the avoidance warm-ups, and no additional drops of the test flows.
All 120 captures agreed with their filter counts and recorded zero kernel drops. An independent
decoder verified all 350,412 capture records, then reproduced 2,222 ACK groups and 3,627 data
transmissions in the measured intervals. In 978 groups the ACK was followed by no send. The analyzer
uses capture record order at both ends of each interval and checks observed losses against the
selected workload's byte count, offset ranges and copy numbers. New run summaries store the ledger's
SHA-256. The paired report checks the digest, group count, opening transmission and closing ACK.
Original summaries retain the count and interval endpoints for checking the archived ledgers.
The run count and these short episodes are independent of
the calibration and throughput tables above.

| Case | Algorithm | Post-exit cwnd, r1 | Post-exit cwnd, r2 | First repair to covering ACK, RTTs, r1 | First repair to covering ACK, RTTs, r2 | ACK groups, r1 | ACK groups, r2 |
|---|---|---:|---:|---:|---:|---:|---:|
| Single, slow start | NewReno | 12/11 | 12/12 | 1.00/1.00 | 1.01/1.00 | 22/27 | 19/24 |
| Single, slow start | CUBIC | 16/16 | 16/17 | 1.00/1.00 | 1.01/0.99 | 17/24 | 24/24 |
| Single, avoidance | NewReno | 23/23 | 23/23 | 0.99/0.98 | 0.98/0.98 | 28/31 | 29/30 |
| Single, avoidance | CUBIC | 25/24 | 25/25 | 1.00/0.97 | 0.97/1.00 | 27/24 | 24/25 |
| Five consecutive originals | NewReno | 47/46 | 47/46 | 1.19/1.11 | 1.08/1.38 | 119/122 | 87/103 |
| Five consecutive originals | CUBIC | 65/65 | 65/65 | 1.10/1.08 | 1.10/1.12 | 82/84 | 87/122 |
| Lost first retransmission | NewReno | 47/76 | 47/46 | 2.10/2.36 | 2.07/2.05 | 136/110 | 101/87 |
| Lost first retransmission | CUBIC | 65/65 | 65/64 | 2.10/2.05 | 2.10/2.33 | 90/91 | 59/128 |
| Last two originals | NewReno | 2/39 | 39/38 | 9.56/2.00 | 1.94/2.00 | 23/24 | 19/34 |
| Last two originals | CUBIC | 2/53 | 2/54 | 9.57/2.00 | 12.18/2.00 | 23/34 | 25/33 |

Each cell is stack/Linux for repetition r1 or r2. The covering ACK reaches the highest byte sent
before the first repair. RTTs use each sender's last sampled SRTT before the target drop. The stack
supplies its first qualifying post-ACK trace in Open/Disorder. Linux supplies the first 10 ms
TCP_INFO sample in Open/Disorder covering the ACK. This can include ACKs beyond the measured flight.
Entry and exit brackets, the duration bounds in RTTs, the original-drop-to-covering-ACK duration and
each sample's cwnd and ssthresh are in the [paired observations](results/m2-integrate/directed-drops.json).

**ACKs and congestion windows.** In 18 pairs the first difference included a different cumulative
ACK. In the other two, the preceding ACK matched and the sends grouped after it differed. The
ledger retains empty ACK groups, SACK order, new data and repeated bytes. These are independent
flows. A packet following an ACK at r1 establishes wire order. Pacing, timers and packets already in
flight preclude assigning that send to a specific kernel ACK handler from a capture alone.

- At slow-start loss the stack's target was offset 19,280 and Linux's was 18,824. The last
  cumulative ACK before the dropped packet was respectively 4,800 and 15,928 bytes behind the hole.
  Both were in slow start, with ssthresh 2,147,483,647. In both NewReno pairs the resulting stack/Linux
  ssthresh was 12/11. In r2 the qualifying Linux sample included 8,688 more acknowledged bytes
  and showed cwnd 12. For CUBIC both thresholds were 16. Linux's r2 sample covered another 10,136 bytes
  and showed 17. Each sender retransmitted only the one hole in the target interval.
- Avoidance used an earlier single loss to exit slow start. Its covering ACK preceded the measured
  target in every flow. Both bounding Linux samples and the stack's original-TX trace showed
  cwnd at or above ssthresh when the target was sent. The warm-up accounts for one of the two
  SACK recoveries in every avoidance transfer. NewReno reached threshold 23 throughout. On CUBIC r1,
  the last pre-entry cwnds were 36/35 and the new thresholds 25/24, consistent with CUBIC's
  threshold of floor(cwnd × 717/1024). In r2 both pre-entry cwnds were 36 and both thresholds were 25.
- All eight burst runs repaired offsets 0, 1,448, 2,896, 4,344 and 5,792 relative to the first hole.
  The NewReno r2 stack spread those repairs across ACK-group indices 35, 37, 39, 41 and 43.
  Linux sent them in groups 88, 89, 89, 89 and 89. At the first repair, the SACK block above the
  burst reached byte 11,584/92,672 relative to the hole, and the pre-repair flight extended
  139,008/220,096 bytes above it. In r1 both used every second ACK group for the five repairs.
  In both CUBIC pairs the spacing between successive repair groups was 1, 1, 2, 1 on both sides.
  The NewReno thresholds were 47/46 in both pairs, the CUBIC thresholds 65/65.
  The last pre-entry stack cwnd was 94 in each burst. Linux NewReno r2 sampled cwnd 93 before
  entry. In the other three Linux bursts the last pre-entry sample was still at 79, so it bounds
  the observation time without resolving the final slow-start increments.
- In all eight lost-retransmission runs, copies 1 and 2 of the same offset disappeared at r1.
  The sender repaired it with copy 3 without a timeout. NewReno r1 had the largest cwnd difference
  among the long transfers. At first repair, 118,736/308,424 bytes extended beyond the hole, and
  3/52 ACKs had been observed starting with the first SACK above it. The last pre-entry cwnds were
  94/153. Integer halving gives the observed thresholds and exit cwnds of 47/76. For CUBIC r2,
  the last pre-entry cwnds were 94/92 and thresholds 65/64. The Linux capture locates the later
  first repair in both runs. Its TCP_INFO samples do not resolve each intervening kernel decision.
- For the non-tail transfers, whole-run counters showed one SACK recovery for each one-loss, burst
  or lost-retransmission case and two for avoidance, with one exception. Linux burst/CUBIC r1
  entered a second recovery after the five target repairs. Both copies of bytes
  [780472, 781920) passed r1 and r2. The receiver D-SACKed that range at cumulative ACK 878,936.
  Linux counted six fast retransmissions and one partial undo. All other long transfers had zero
  undo events. All 32 had zero loss probes, probe recoveries and timeouts. The historical A-N2
  reordering results above concern separate transfers.

**Why three stack tails waited for the timeout.** Each sender used one loss probe for the final
88 bytes and then received cumulative ACK 98,464 with SACK [99,912, 100,001), including the FIN.
The other missing packet was the 1,448-byte segment at 98,464. The loss probe was the first repair,
so the table's repair-to-covering-ACK interval includes the entire wait for this segment.

| Algorithm, rep | Stack probe-to-SACK minus min RTT (µs) | Stack state on SACK | Stack SACK to first-hole retransmission (ms, router 1) | Linux probe-to-SACK minus min RTT (µs, router 1) | Linux SACK to first-hole retransmission (ms, router 1) |
|---|---:|---|---:|---:|---:|
| NewReno r1 | 20,124.015 − 20,168 = −43.985 | Disorder | 157.670 | +17.703 | 0.021 |
| NewReno r2 | 20,141.640 − 20,112 = +29.640 | Recovery | 0.053 | +39.476 | 0.021 |
| CUBIC r1 | 20,158.153 − 20,196 = −37.847 | Disorder | 157.781 | +37.376 | 0.018 |
| CUBIC r2 | 20,126.539 − 20,183 = −56.461 | Disorder | 206.948 | +13.775 | 0.026 |

The stack's monotonic TX and ACK traces give its probe RTT. Its min RTT stayed at the sampled value
across that ACK. For a retransmitted segment, a probe RTT below the existing minimum makes the ACK
ambiguous, so RACK skips advancing its transmission timestamp. Linux v7.0 uses the same test
(`net/ipv4/tcp_input.c:1583–1603`). With a negative delta the trace showed one SACKed and zero
lost segments. No further ACK arrived before the RTO. The timer sent the earlier hole in Loss and
cwnd was 2 on exit. With a positive delta that SACK put the stack in Recovery, marked one segment lost
and immediately retransmitted it. The stack implementation is in [rack.cpp](../src/core/tcp/rack.cpp).

For Linux the probe RTT is the router measurement and the minimum is the sender sample. All four
router measurements exceeded the sampled minimum. The ensuing first-hole retransmission appeared
18–26 µs after the SACK, and all four runs recorded SACK recovery. The exact Linux processing-clock
delta is unavailable. Every tail recorded one loss probe and zero probe recoveries. The four Linux
tails and stack NewReno r2 each recorded one SACK recovery and zero timeouts. The other three
stack tails each recorded zero SACK recoveries and one timeout. Linux never entered a timeout
episode here, so these runs exercise neither its post-RTO F-RTO send choice nor spurious-RTO undo.

**Reproduction and records.** From a clean checkout of the measured revision, run the following
on the test host with a fresh campaign name. The original basename was `drops-attempt-1`.

```sh
export UTCP_M2_PREFIX=utcp-m2-i40 UTCP_TB_PREFIX=utcp-m2-i40 UTCP_M2_JOB=utcp-m2-i40-runner
export UTCP_COMMIT=$(git rev-parse HEAD) UTCP_CPUS=16-31
build=build/tb-gcc-release
docker run --rm --name utcp-m2-i40-build-release --cpuset-cpus 16-31 --user "$(id -u):$(id -g)" \
  -v "$PWD:$PWD" -w "$PWD" utcp-testbed:dev nice -n 10 bash -ec \
  'cmake --preset gcc-release -B "$1" && cmake --build "$1" -j4 --target utcp-bulk' bash "$build"
taskset -c 16-31 nice -n 10 testbed/m2/up.sh --slot 2 --nontiming
taskset -c 16-31 nice -n 10 tests/interop/m2_drops.sh --campaign "m2-integrate/$UTCP_COMMIT/drops-attempt-2"
taskset -c 16-31 nice -n 10 testbed/m2/down.sh --slot 2
```

The original volume path is
`utcp-data:/m2/m2-integrate/5bd13159f8412786d8f619848ac24d0aa19a1641/drops-attempt-1/`.
Each run retains three pcaps, the 10 ms samples, router rules, counters and the recovery analysis.
`audit/files.sha256` indexes the raw files and `audit/compact-inputs.tar.gz` contains the
endpoint/trace inputs and ACK reports without pcaps. The adjacent directory
`drops-audit-controls-1` retains copies of one measured Linux flow. The clean copy passed.
Changing one sender sample's algorithm, truncating a capture by one byte and changing the requested
drop from copy 1 to copy 2 each failed the corresponding check. The original run data remained intact.

The [compressed ACK ledger](results/m2-integrate/ack-decisions.jsonl.gz) contains one JSON line
per transfer. Each group contains the cumulative ACK, ordered SACK blocks, and sends between
this ACK and the next. Each send contains its offset, payload length, copy number and count of
previously sent bytes. All offsets are relative to that run's first comparison hole.
