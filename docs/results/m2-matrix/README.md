# Serial M2 congestion-control matrix

The [registered experiment](plan.toml) compares NewReno, CUBIC and BBRv1 on the userspace stack and Linux. On the private Ubuntu host, the acquisition writes into `utcp-data:/m2/m2-matrix/`. The measured checkout is `4f9c9b89e16188fd65f3961af967cc3d83370d12` and its executable sources match `769311e157dea0e7983a2cd5bd086736339dc62b`. The [runtime freeze](../m2-bbr/README.md) identifies the two restored binaries, image, script tree and both slot calibrations. The earlier checkpoint used a different binary fingerprint. Every observation in this schedule comes from a new transfer.

## Acquisition

Seed `2026111905` schedules 360 consecutive stack/Linux pairs across 24 conditions. Bandwidth is 10 or 100 Mbit/s, RTT is 20 or 100 ms, forward-path random loss is 0%, 0.1% or 1%, and queue size is 0.5 or 2 bandwidth-delay products. Five distinct seeds cover each condition and algorithm. Endpoint order varies by pair. Send time is 30 s at 20 ms RTT and 60 s at 100 ms RTT. The analysis window begins five seconds after the receiver accepts and ends at the earlier endpoint's start plus send time.

Both idle slots passed the matching 67-item gate, including all 62 source fingerprints per slot. The CUBIC-only concurrency check replayed from 15 real transfers and all five required overlaps. After closing slot 1, slot 0 ran the schedule serially on CPUs 8–11. The calibration input digests and reuse key were checked before starting. Other processes shared the host. Per-transfer CPU flags accompany the reported results.

The stack uses the complete Linux-compatible configuration and three registered buffer/GSO settings. Each sender socket selects its named algorithm. A stack configuration record can report the profile's default NewReno while its connected socket reports CUBIC or BBR. The Linux sender requests kernel `reno` for NewReno and the sampler reports its `TCP_CONGESTION` readback as `newreno`. Receivers use the recorded Linux default CUBIC. Every endpoint records its own timestamps, sample stream, final congestion-control name, delivered byte count and payload SHA-256.

The default stack filter records congestion-window, recovery, RTO and retransmission events. One allocated trace block can remain empty over a successful transfer. The independent replay accepts zero events only with an enabled sink, a present zero-byte trace, matching native event counts and zero corroborating retransmission, timeout and loss-probe counts. In that case the event stream has no observations of BBR modes. The separate 10 ms socket samples still report the socket algorithm and congestion window.

Run `python3 -IB docs/results/m2-matrix/test_matrix_evidence.py` from the checkout to exercise these checks and the gap boundaries. Ground truth for the plan is available directly from the frozen runner.

```bash
sha256sum docs/results/m2-matrix/plan.toml
python3 -B tools/m2/matrix.py expand docs/results/m2-matrix/plan.toml --slots 1 | sha256sum
```

The two SHA-256 results are `9a418b50e2d15530ceb9fe429467498bf5c177e6b93609d81b24258af02661ba` and `18be22c23775f69ad508fcaf26cd21fd87d3f19f36488842c21e2d8972a95d23`.

## Reading the measurements

The native per-run CSV preserves validity, exclusion reasons and flags. The evidence table marks counted pairs. The first five complete valid pairs supply the two per-side distributions. An invalid member causes a whole-pair retry with the same seed and endpoint order, subject to the three-retry limit for that condition and algorithm. The original attempts remain in the raw archive, including any partially written files. Separately preserved interrupted attempts are listed in their own inventory.

Goodput and both queue-delay measurements use the registered 10% median difference and disjoint ranges test. A delay gap below 1 ms keeps its verdict and the preregistered cause of measurement resolution. A retransmission gap requires a higher stack median and disjoint ranges. The absolute threshold is 0.05 percentage points at 0% or 0.1% configured loss and 0.2 points at 1% loss. NewReno and CUBIC at 100 Mbit/s, 100 ms and 0% random loss were designated transient-dominated before acquisition.

The additional metrics preserve sender counters, capture-based retransmissions, DSACKed segments, limited times, application-loop lateness, cwnd samples, pacing and delivery rates, queue drops and backlog, IRQ/softirq work, and sender CPU contention. The minimum, median, maximum and available observation count are reported per side. Rates and ping statistics use the measurement window. Queue and kernel `nstat` deltas span the full transfer and can include startup or drain. Jain fairness and multi-flow convergence are outside this single-sender experiment.

Linux v7.0 increments `TcpExtTCPFullUndo`, `TcpExtTCPPartialUndo`, `TcpExtTCPDSACKUndo` and `TcpExtTCPLossUndo` at distinct congestion-window restoration paths in `net/ipv4/tcp_input.c`. The F-RTO restoration branch of `tcp_try_undo_loss` increments `TcpExtTCPSpuriousRTOs` as well as `TcpExtTCPLossUndo`. These two counts can refer to one event. The sixth counter, `TcpExtTCPSpuriousRtxHostQueues`, records an attempted retransmission or probe whose earlier skb clone still occupied a host queue (`skb_still_in_host_queue` in v7.0 `tcp_output.c`). Sender-container deltas are interpreted only on the Linux sender. Absence of a spurious-RTO restoration count does not count how many times the kernel considered F-RTO.

For each Linux sender with a positive between-snapshot timeout delta, the r1 ingress projection preserves capture time, data sequence relative to that flow's original SYN, and segment payload length. The projection stays in the private compact archive. The replay reads every earlier outgoing data segment before classifying a new high sequence end during Loss. `kernel-rto-runs.csv` reports per-run outcomes and `kernel-loss-spans.csv` separates warmup, the primary window, and drain. A segment bracketed by two adjacent observations of Loss is distinguished from one in a leading or trailing transition interval. Individual transitions between the roughly 10 ms socket samples remain unresolved. Multiple timeouts can occur within one sampled Loss span. The whole-transfer timeout total has no individual event timestamps. New sequence data in a sampled Loss interval is compatible with a post-timeout new-data send. These observations alone do not identify the kernel's per-ACK F-RTO decision.

## Replaying a finished campaign

Use the frozen image, a read-only checkout and a private writable volume directory. Packet captures remain on the Ubuntu host. The archive names are checksum-addressed and the full archive includes its own per-file manifest. The compact archive contains non-packet acquisition inputs, its SHA-256 manifest, the full source manifest and receipts from the packet-level scan. Tables, selected overlays and endpoint diagnostics can be reconstructed directly from the compact archive. Validating packet bytes themselves requires the full archive.

```bash
docker run --rm -it --network none --cpuset-cpus 16-31 \
  -v "$PWD:/utcp:ro" -v utcp-data:/data:ro -v utcp-data:/store \
  sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66 \
  nice -n 10 bash
```

Inside that shell, use a new working directory on the evidence volume.

```bash
set -euo pipefail
res=/utcp/docs/results/m2-matrix
archive=/data/m2/archive
work=$(mktemp -d /store/m2/archive/m2d-matrix-replay.XXXXXXXX)
export TMPDIR="$work" MPLCONFIGDIR="$work/mpl"
(cd "$archive" && sha256sum -c "$res/archives.sha256")
compact=$(awk '$2 ~ /-analysis-.*tar.gz$/ {print $2}' "$res/archives.sha256")
python3 -IB /utcp/tools/m2/analyze.py tables "$work/native" --archive "$archive/$compact"
for f in runs.csv cells.csv; do cmp "$work/native/$f" "$res/$f"; done
tar xzf "$archive/$compact" -C "$work"
camp="$work/m2-matrix"
(cd "$camp" && sha256sum --quiet -c MANIFEST.sha256)
python3 -IB "$res/audit.py" "$camp" "$work/observed"
python3 -IB "$res/loss_replay.py" report "$camp" "$camp/wire-loss-inputs" "$work/wire-report"
python3 -IB /utcp/tools/m2/plot.py "$camp" "$work/plots" > "$work/plot-selection.log"
python3 -IB "$res/report.py" "$camp" "$work/native" "$work/observed" \
  "$work/plot-selection.log" "$work/report"
for f in "$work/observed/"* "$work/report/"* "$work/wire-report/"* "$camp/physical-replay/"*; do cmp "$f" "$res/${f##*/}"; done
diff -qr "$work/plots" "$res/plots"
```

For packet-level replay, extract the full archive into a separate directory, verify its per-file manifest, scan the saved headers and compare the original acquisition order and capture checksums.

```bash
raw=$(awk '$2 ~ /-raw-.*tar.gz$/ {print $2}' "$res/archives.sha256")
mkdir "$work/full"
tar xzf "$archive/$raw" -C "$work/full"
full="$work/full/m2-matrix"
(cd "$full" && sha256sum --quiet -c ../manifest/raw.sha256)
python3 -IB /utcp/docs/results/m2-checkpoint/verify/physical_checkpoint.py \
  "$full" "$res/evidence.csv" "$work/fresh-physical"
diff -qr "$work/fresh-physical" "$camp/physical-replay"
python3 -IB "$res/loss_replay.py" extract "$full" "$res/evidence.csv" "$work/fresh-wire-inputs"
diff -qr "$work/fresh-wire-inputs" "$camp/wire-loss-inputs"
```
