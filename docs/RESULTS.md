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

**Window.** Every metric uses [t₀ + 5 s, t₀ + S] on CLOCK_MONOTONIC, t₀ = the receiver's accept time (the
`start` line of its JSONL); counters at the bounds are interpolated linearly between the 10 ms
samples. The drain after the sender stops writing is outside it. CLOCK_REALTIME times (ping, the
tbf sampler) convert with the clock pair that `utcp-bulk` writes first in its JSONL.

**Metrics** (`tools/m2/analyze.py`):

| Metric | Definition | Source |
|---|---|---|
| Goodput | Δ`bytes_received` over the window × 8 / (S − 5 s) | receiver JSONL |
| Retransmission rate | Δ`total_retrans` / Δ`data_segs_out` over the window, in % | sender JSONL (same keys for both senders); cross-check from the r1-in capture |
| Spurious retransmissions | Δ`dsack_dups` over the window | sender JSONL |
| Queueing delay p50, p99 | ping RTT − base over pings sent in the window; base = median of the replies received before t₀ (3 s idle); lost pings counted, excluded | `ping.txt` |
| sndbuf-, rwnd-limited time | Δ`sndbuf_limited_us`, Δ`rwnd_limited_us` / window | sender JSONL |
| Jain index | (Σx)² / (n·Σx²) over per-flow goodput in [t_join + 20 s, t₀ + S] | receiver JSONL per flow |
| Convergence time | first t after flow n's join from which every flow's 1 s mean goodput (100 ms steps) stays within ±20 % of C/n for 5 s; "not converged" if none | receiver JSONL per flow |
| Loop lateness p99, max | the stack's EventLoop histogram | `utcp-bulk` summary |
| Testbed counters | netem and tbf sent/dropped, tbf backlog (10 ms sampler), interface and qdisc drops, softnet drops and time_squeeze on the slot CPUs, `nstat` | `record.sh` before and after, `tbf.txt` |

Percentiles interpolate linearly between closest ranks.

**Captures.** `tcpdump -s 128` on r1's interface from the sender (`r1-in`) and on r2's interface to the
receiver (`r2-out`), calibration also r1's interface toward r2 after netem (`r1-out`), written to the
`utcp-data` volume under `/m2/<campaign>/<run>/`. Each capture's `packets dropped by kernel` and
`packets received by filter` versus `captured` are checked; tcpdump is stopped 1.5 s after the last
traffic so that its 1 s ring blocks are delivered.

**Raw data and archive.** Per run in the volume: `meta.json` (cell, implementation, algorithm,
repetition, order, slot, start time, kernel, image id, commit, binary and core-library sha256, build,
iproute2, cpusets, tbf B and Q, netem line and seed, reuse key), `snd.jsonl`, `rcv.jsonl`, `ping.txt`,
`tbf.txt`, `pre/` and `post/record.txt`, the captures, `capture.json`, `summary.json`. In the repository
`docs/results/m2-<campaign>/runs.csv` and `cells.csv`. The analysis archive (every input except the
captures, with a sha256 manifest) goes to `/m2/archive/` in the volume; `analyze.py tables --archive`
regenerates `runs.csv` and `cells.csv` byte for byte from it.

**Reuse key.** sha256 over the `utcp-bulk` binary and core library hashes, the build, `uname -r`, the
image id, a hash of `testbed/m2` and `tools/m2`, and the containers' `net.ipv4.tcp_*`/`net.core.*`
sysctls and the `tcp_cubic`/`tcp_bbr` module parameters. A run is reused in a later campaign only with
an equal key; otherwise both sides of the cell rerun.

## Calibration

Pending: filled from the gate runs on slots 0 and 1 (§5.4 of the M2 design).

## Gap rule and thresholds

Fixed before the first matrix run, in the commit that added this section; not changed afterwards
(PLAN 2d; M2 design §5.10). Implemented in `tools/m2/analyze.py` (`gap_verdict`, constants at the top).

Per cell and algorithm, the stack (`linux_compat`) and Linux are compared on the statistics of their
counted runs (next section): median, minimum and maximum of 5 runs.

- **Goodput, queueing delay p50, queueing delay p99** (each separately): a **gap** when the medians
  differ by more than 10 % of the Linux median **and** the two 5-run ranges [min, max] do not overlap
  (touching ranges overlap). A stack result better than Linux by that much is a gap too.
- **Below resolution.** A queueing-delay gap whose absolute median difference is below 1 ms is marked
  "gap (below resolution)". It stays a gap. Its written cause is "below measurement resolution" (the
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

Fixed before the first matrix run, in the commit that added this section (M2 design §5.3, §5.6).
Implemented in `tools/m2/analyze.py` (`summarize_run`, `select_runs`).

- **Invalid runs** (out of the statistics, kept and marked in `runs.csv`, rerun): a non-zero rx or tx
  drop counter on any interface of the four containers (sender eth0, routers, receiver, the ACK path,
  the `utcp*` TUNs) or a `utcp*` pfifo drop; softnet drops on the slot's CPUs; drops in the ACK
  direction's qdiscs; the stack's `DeviceStats` tx or rx errors or a device failure; either
  `utcp-bulk` not ok or different SHA-256 at the two ends; receiver samples that do not cover the
  window.
- **Flagged runs** (in the statistics, flag shown): `time_squeeze` on the slot's CPUs; sndbuf- or
  rwnd-limited time ≥ 1 % of the window; capture kernel drops or an incomplete capture. A buffer change
  made because of a limited-time flag reruns the whole cell for both senders.
- **Counting.** Per (cell, algorithm) and side, the statistics use exactly the first 5 valid runs in run
  order. Each invalid run is rerun. When a (cell, algorithm) has needed more than 3 reruns (invalid
  runs over both sides together), it is reported **invalid** and gets no verdict; with fewer than 5
  valid runs on a side it is reported incomplete.
- Each counted cell reports the median and the range (minimum, maximum) of its 5 runs per metric.

## Timing hygiene

Fixed parts (M2 design §6):
- Slot 0 uses CPUs 8-11 (sender 8,9; receiver 10; routers 11), slot 1 CPUs 12-15 (12,13; 14; 15).
  Builds and analysis use 16-31 with `nice -n 10`; CPUs 0-7 are not used. At most one run per slot.
- Every run records `uptime`, the top CPU users, the threads last seen on CPUs 8-15, and the slot CPUs'
  `/proc/stat` busy, irq and softirq deltas, `/proc/softirqs` and `/proc/net/softnet_stat`.
- The softirq work of the whole path (r1 forwarding, netem, tbf, the receiver's TCP input and ACKs, the
  ACKs' processing at the sender) runs mostly on the CPU that transmitted, the sender's core; the
  stack's loop lateness therefore includes it, and both senders see the same work on the same core.

Pending (m2d-testbed, part 2): the parallel-mode proof (serial against two-slot runs of gate items 1,
2 and 4 and of stack NewReno at 100 Mbit/s, 20 ms, 0 %, 2×BDP), the trace-overhead measurement, and the
decision whether timing runs use one slot or two.
