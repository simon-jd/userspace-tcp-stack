# Replaying the multi-flow study

Run the study tools inside the frozen image on an offline analysis CPU. Every input path below is relative to the study's root within the evidence volume, except the checked-out Python files and the output directory.

```sh
study=docs/results/m2-multiflow/study.py
python3 -I "$study" capture "$attempt"
python3 -I "$study" run "$attempt" --schedule "$schedule" --gate "$gate"
python3 -I "$study" tables "$production" --schedule "$schedule" --gate "$gate" \
    --controls "$proof/serial-s0" --out "$out"
python3 docs/results/m2-multiflow/test_study.py
```

The capture command streams both pcaps, records the count and SHA-256 of each file, and writes `capture-evidence.json`. It pairs ICMP requests and replies by ID and sequence on r1 ingress. A missing reply retains its send timestamp. It identifies TCP data by the observed source and destination addresses and ports, and binds payload sequence space measured from the SYN to each endpoint's byte count. Raw restore should regenerate this projection and compare bytes. Compact restore reads the retained projection. A capture decode missing physical input or finding malformed packet evidence returns code 3 and a JSON reason. Operational exceptions propagate separately.

The run command reopens the frozen schedule, observed process arguments, launch times, closure files, endpoint samples, final summaries, trace and stats, kernel shaping records and interface counters. It checks each stack trace against its actual socket tuple. The measured sender CC comes from the sender's complete sample stream. The kernel transport records Linux `reno` as `newreno`. Every link drop and reverse-path qdisc drop invalidates a run under the registered rules. The ordinary capture-loss, foreign-CPU, limited-time, blocked and counter-mismatch flags stay with counted observations. A rehearsal uses `run --pilot`; its convergence has status `unobserved-calibration` when a matching capacity has not been measured.

## Time windows

All endpoint calculations use monotonic nanoseconds. The origin is the earliest incumbent receiver accept. The late join uses the last physical flow's receiver accept. Nominal end is origin plus the registered wall duration. The operational active cutoff is the earliest of nominal end and each observed sender connect plus its registered write duration. The program emits neither a timestamp for the write-stop callback nor one for the last application write. Flows retain different starts. Each primary rate measures bytes from that receiver's accept plus five seconds to active end. Both Jain indexes start at actual join plus twenty seconds, using cumulative receiver bytes interpolated at shared ends. `runs.csv` preserves the absolute bounds, join error and drain difference. `flows.csv` records each flow's own start, write end, delivery rates, tuple and TUN deltas.

Interpolation requires a measured bracket no wider than 100 ms, the registered scan step. Every observed sample interval above 100 ms is also a blind interval for ongoing convergence. The eight-stack rehearsal's median receiver intervals were 10.001 ms to three decimal places; its largest was 12.480 ms. A cumulative-byte difference with well-observed boundaries remains directly measurable across an internal gap. A sliding one-second mean used for proving a five-second event must have continuous sampling support throughout its one-second lookback.

The calibration input is the read-back, source-checked item-2 receiver goodput for this slot, reuse key, bandwidth, RTT and 2×BDP queue. Its gate, source run and byte digests travel with each result. Beginning one second after the observed late accept, every 100 ms the analysis compares each flow's trailing one-second rate to 80–120% of calibrated capacity divided by the physical flow count. Fifty-one consecutive qualifying grid points establish five seconds. An observed participant outside the band rules out a grid point even if another participant lacks coverage. Otherwise a missing participant makes that point unknown. A fully covered trace is cross-checked against the existing convergence routine.

`converged` records the first confirmed onset and the earliest possible onset given missing observations, including the first periodic sample after accept. When those differ, the first confirmed time is an upper bound on the actual first qualifying grid onset. `right-censored` means every possible five-second hold before the common active end contains an observed violation. The raw observed horizon and the last onset at which a full hold could have been observed are separate columns. `unobserved-sampling` means an unknown interval could contain a hold and no hold could be confirmed. The scenario table reports event counts and the median/range of confirmed times conditional on convergence.

## Counting, comparisons and figures

Both sides of a counted pair must have matching roles, seed, slot, boot and runtime key, in frozen chronological order. Tables reopen acquisition qualification digests and recompute metrics from the original inputs. A failed or interrupted attempt stays in the run inventory. Only a subsequent complete pair can supply either counted side. More than three invalid groups in a scenario suppress its verdict. A missing planned pair, mixed key or changed evidence also prevents a completed comparison.

For each physical role ID, the report gives the median and observed minimum/maximum over its five repetitions. A goodput gap requires disjoint closed ranges and a difference greater than 10% of the Linux-role median. A nominal Jain median difference greater than 0.05 is reported separately. Five repetitions provide observed ranges, with no population confidence interval or causal inference. In coexistence cases the two Linux CUBIC incumbents and the delayed physical stack role retain their own identifiers even if an algorithm label repeats.

For each side, choose the lowest registered repetition ID attaining the median aggregate receiver rate in the fully active common fairness window. The figure shows both selected real runs as aligned panels, with per-flow 100 ms receiver rates and observed join times. The one-flow comparison binds the five serial CUBIC proof senders to the study key; their registered writes last 30 seconds. Scenario 3 lasts 60 seconds, with 60-second registered writes for the seven incumbents and 40 seconds for late flow f7. Each sender's lifetime histogram contains timer observations during its own setup, transfer and drain. The histogram count and the span from its initial clock record to the final sender sample quantify exposure. The p99 uses the inclusive upper bound of the observed rank's logarithmic nanosecond bucket, capped at the exact maximum. The maximum is directly observed. Lateness comparisons describe this placement and offered load. They do not isolate a core-sharing effect.

## Sealed evidence export

The `archive.sh` wrapper uses the frozen image to create and restore the full
and compact archives on the private volume. It exports the small results and
qualification receipts as the checkout owner, using the verified compact
restore. The archive manifest binds each exported acquisition receipt.

```sh
stage=/data/m2/archive/m2d-multiflow-verify-final01
docs/results/m2-multiflow/archive.sh --export-only acquisition-q1 "$stage"
sha256sum -c docs/results/m2-multiflow/measured/source.sha256
sha256sum -c docs/results/m2-multiflow/measured/production-source-approved
```

`--export-only` requires a completed replay in the supplied directory. It
reads the existing restore and leaves both archives and the live evidence
unchanged. The normal two-argument invocation creates a new replay in a fresh
stage directory. The first export attempt reached both completed archive
restores and then failed on permissions while copying the original qualification
receipts. The export retry read the manifest-verified copies from the compact
restore while preserving the original receipt permissions and archive digests.

## Rechecking loss and delivered share in scenarios 8 and 10

The full restore regenerates the per-role data-segment counts from the r1-in
and r2-out captures. For each run, join `flows.csv` to `network.csv` by `run`.
Sum `r1-in_data_segments` minus `r2-out_data_segments` across the physical roles,
then compare with `tbf.dropped` and `netem.dropped` in the network records.
The independent raw comparison also matched packet identities by flow and
checked for unmatched egress packets. Its code and per-scenario readback are in
`~/Desktop/utcp-wt/m2d-multiflow-review-methodology` on the private host. Run
`bash ~/Desktop/utcp-wt/m2d-multiflow-review-methodology/recovery.sh` there, and
read `physical-gap-evidence/scenario-08.json` and `scenario-10.json` in that
checkout. The raw capture comparison describes the observed forward path.
Endpoint and capture retransmission counters have different observation points
and their flagged discrepancies remain in `runs.csv`.

The late role's delivery share uses its `fair_active_bps` divided by the sum of
all roles' rates in that run. Calculate the median and range of these shares
across the five runs on each side. Both endpoints of the rate window are common
within a run, so the rate share is also the share of delivered bytes.
