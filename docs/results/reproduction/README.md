# Private evidence and offline reproduction

The acquisition records and packet captures live on the private Ubuntu host.
The repository carries the reports, analysis code, revision and checksum
indices, and replay entry points. The
[source revision index](source-revisions.tsv) gives the full commit and Git
tree for each locally known acquisition, runtime, and validation checkout.

The M2 commands restore capture-free inputs and compare the regenerated
tables, diagnostics, and figures byte for byte. The M4 command verifies the
stored input files in place and regenerates the numerical reports in a fresh
directory. The [historical inventory](historical.md) covers M0, M1, M2
integration, and M3, with their commands and surviving receipts.

## Start an offline analysis shell

Run on Ubuntu from the repository root. This example creates a fresh scratch
subdirectory of the existing private volume and makes only that subdirectory
writable in the analysis container. The source volume and checkout are
read-only. There is no network access. The frozen analysis image contains
Python 3.14.4, Matplotlib 3.10.7, and the campaign tools. Python 3.14 is
required for the standard library Zstandard reader used by the multiflow
archive.

```bash
set -euo pipefail
image=sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66
scratch=$(docker run --pull never --rm --network none --cpuset-cpus 20-27 \
    --mount type=volume,src=utcp-data,dst=/store \
    --entrypoint mktemp "$image" -d /store/reproduction.XXXXXXXX)
printf 'Scratch volume directory: %s\n' "$scratch"
docker run --pull never --rm -it --network none --cpuset-cpus 20-27 \
    --cap-drop all --cap-add dac_override \
    --mount "type=bind,src=$PWD,dst=/utcp,readonly" \
    --mount type=volume,src=utcp-data,dst=/data,readonly \
    --mount "type=volume,src=utcp-data,dst=/work,volume-subpath=${scratch#/store/}" \
    --entrypoint nice "$image" -n 10 bash
```

Use a host directory mounted read-only at `/data` to replay from a relocated
archive with the same relative paths. Use an independent writable mount at
`/work` for scratch. Each campaign creates its own exclusive working directory
and prints its path and verification outcome. Allow space for the uncompressed
endpoint logs and pipeline intermediates, especially the core matrix.

## M2 measurement archives

Archive paths in the table are relative to `utcp-data:/m2/archive/`. Raw roots
are relative to `utcp-data:/m2/`. The linked receipts give the complete archive
names and SHA-256 digests. The runtime source and gate identify the actual
binaries, tooling, and calibration. The acquisition commit identifies the
runner and registered plan. All five campaigns used Ubuntu kernel
`7.0.0-42-generic` and the frozen image above.

| Replay name | Acquisition / runtime | Original raw root | Retained compact inputs / full captures | Replayed result and archive hashes |
| --- | --- | --- | ---: | --- |
| `checkpoint` | `170b21f` / `3f48c30` | `m2-checkpoint/` | 1,600 / 320 | 160 transfers, 32 aggregates, 16 PNGs. [Results](../../RESULTS.md#checkpoint) · [Archive checksums](../m2-checkpoint/archives.sha256) |
| `bbr` | `769311e` / `769311e` | `m2c-bbr/smoke-769311e-a1/` | 100 / 20 | 10 transfers, 2 aggregates, 1 PNG. Archive subdirectory `m2c-bbr-smoke-769311e-verification-a1/`. [Results](../m2-bbr/README.md#smoke-replay) · [Archive checksums](../m2-bbr/ARCHIVES.sha256) |
| `ablation` | `35a14fb` / `3f48c30` | `m2d-ablation/` | 1,400 / 280 | 140 transfers, 28 aggregates, 14 PNGs. [Results](../../RESULTS.md#ablation) · [Archive checksums](../m2-ablation/archives.sha256) |
| `matrix` | `4f9c9b8` / `769311e` | `m2-matrix/` | 10,844 / 1,440 | 720 transfers, 144 aggregates, 72 PNGs, gap and loss reports. [Results](../m2-matrix/README.md) · [Archive checksums](../m2-matrix/archives.sha256) |
| `multiflow` | `c2be4cd` / `67d4b48` | `m2d-multiflow/` | 6,497 / 392 | 100 production scenarios, 300 matching connections, 20 table and plot files, plus endpoint census. [Results](../../RESULTS.md#multi-flow) · [Archive and manifest checksums](../m2-multiflow/measured/archive-replay.json) |

In the analysis shell, use the tracked replay entry points.

```bash
set -euo pipefail
repro=/utcp/docs/results/reproduction
python3 -B "$repro/replay_qualification.py" /data /work
for campaign in checkpoint bbr ablation matrix multiflow; do
    "$repro/replay_m2.sh" "$campaign" /data /work
done
```

The ablation command uses the committed table generator, evidence audit,
report renderer, plotter, and plot-selection checker. It runs directly from the
committed scripts, independent of `build/ablation-ops`.

The three earliest compacts omit their campaign-level `plan.json`. The helper
reads the original plan bytes from each raw root, verifies them against the
exact `plan.json` entry of the Git-pinned full-source manifest, and writes a
checksum-bound `plan-supplement/<campaign>/` in the new scratch directory.
A previously saved supplement can be supplied as the fourth argument to
`replay_m2.sh`; the same authenticated hash check applies. A missing or changed
plan causes a failure. The matrix's compact already contains the plan. Its
hash is also checked against the full-source manifest. Each compact member
shared with the full-source index must match its original file hash. The
matrix adds [27 identified derived inputs](m2-matrix-derived-inputs.txt),
including the embedded full-source manifest and packet projections. Older
compacts may omit original files from their retained sets.

| Campaign | Expanded `plan.json` SHA-256 |
| --- | --- |
| Checkpoint | `31b864ba948e4e54e8b422c4ace9f0a18fbd68f6b1e058ee250309b3a326f099` |
| BBR smoke | `7f1b0577ce9a3038467941f23c7dafe2b0d5c402024a233d1c0ce5fb2284f323` |
| Ablation | `9064bb5493cca8911bf13eff6e777b9df7b104996b6a1fa0b4ec9fc172d0dc70` |
| Core matrix | `fd680b2d4cfe4fd9bcfe765379f69ea57ac2bb874379f8745c66a65d202603a7` |

The [qualification manifest](m2-qualification-inputs.sha256) anchors the
original freeze, gate, and proof receipts for both older runtime families.
Its checker restores the six capture-free gate/proof compacts in fresh
scratch and verifies the archived files, each original gate's 67 criteria
and 62 source fingerprints, and 15 same-runtime proof transfers with five
overlapping pairs per family.

- Checkpoint and ablation use
  `cd50db51c944442c8f1158f6b5e48f01ab3f913d9b96034a675af9a8aed9c1fd`.
  The [integrated gate record](../../RESULTS.md#integrated-calibration-november-19-2026)
  identifies the binary and topology freeze, both calibration roots, and
  the handoff.
- BBR smoke and core matrix use
  `f0ecf3e4882789e261bb9fa8a3da91adf519b7b0f8f2c8d9b8dbfee286c1013e`.
  The [BBR gate record](../m2-bbr/README.md#live-calibration) identifies the
  binary, topology, and release receipts.
- Multiflow uses
  `ad713cad0d39dcec867c31937a0c902094b4e72c515dbef985e04b03abf0935e`.
  Its [freeze](../m2-multiflow/measured/freeze.json),
  [qualification](../m2-multiflow/measured/qualified.json), and
  [terminal receipt](../m2-multiflow/measured/production-status.json)
  bind the schedule, deployed runtime, and accepted calibrations.

[M5 output bundle digests](m2-replayed-output.tsv) bind the sorted
individual SHA-256 entries for the regenerated comparison files. The
bundles include native tables, checked endpoint and report outputs, and
figures. Multiflow includes the endpoint census. Diagnostic transcripts
and previously archived physical-replay receipts are outside these bundles.

The replay reads saved endpoint telemetry, packet projections, and prior
capture receipts where applicable. Independent decoding, capture lengths,
wire checksums, packet drops, and missing-packet interpretations depend on the
separate raw archives. Older capture files and their historical limitations
are indexed in the [historical inventory](historical.md).

## M4 performance and functional records

The original M4 bulk and queue inputs are under `utcp-data:/m4/performance/`.
The [performance archive index](m4-performance-manifests.sha256) pins 12
original manifests. The [echo and allocation index](m4-echo-allocation-inputs.sha256)
covers 887 current files in 33 retained directories. It adds a per-file
inventory for the echo and allocation runs whose historical bindings were
the published row records, executable and result digests, and paired summary.
The raw inputs remain in their original directories. The
[numerical replay output digests](m4-replay-results.sha256) pin the nine
independent M4 report outputs.

| Study | Acquisition and runtime identity | Evidence and scope |
| --- | --- | --- |
| Single-flow bulk | Runner `5c915b6`, executable `da05184` | `baseline-pilot-01` and `baseline-r1`, four pilot and 20 production arms, with matched bytes, directions, CPU and rate. Build and test receipt at `build-da05184-gcc-release`. [Original commands and limits](../m4-baseline/README.md) |
| VNET checksum and TCPv4 | Runner `aa21d93`, stack executable `1c6911e`, Linux endpoint executable `da05184` | `tun-vnet-tcpv4-smoke-1`, `tun-checksum-1gb-r5-01`, `tun-tcpv4-1gb-r5-01`. Six smoke and 60 comparison arms. Packet bytes remain separately in `~/Desktop/utcp-wt/m4-tun-vnet/.logs/wire-release/`, identified by [wire-capture.sha256](../m4-tun-vnet/wire-capture.sha256). [Original commands and limits](../m4-tun-vnet/README.md) |
| Multiqueue | Runtime `4857492`, precise binary hashes in the [report](../m4-tun-multiqueue/README.md#private-evidence) | Ten echo arms, 12 bulk pilot arms and 60 bulk comparison arms over the five `mq-*` archive roots. `mq-transport-checks` retains 23 functional build and runtime records. [Original commands and limits](../m4-tun-multiqueue/README.md) |
| Legacy echo | `1ffcc97`, [matching binary and frozen summary hashes](../m4-echo-load/pre-copy.md#receipts-and-reproduction) | `utcp-data:/m4-echo-load/paired-1ffcc97/` and its ten underlying arm directories. Recomputes latency, counters and memory deltas across five stack/Linux pairs. [Original commands and limits](../m4-echo-load/pre-copy.md) |
| Staged/direct echo and allocation | Staged `95a2d39`, direct `5dcbc76`, client `efef607`, timing runner `773737b`, selectable `0b28872`, allocation runners `920931a` and `f8c36c1` | Ten timing arms, four selectable confirmations, four warm allocation diagnostics and two failed bulk probes. Paths and running binary identities are in [echo-timing.json](../m4-copy-allocation/echo-timing.json), [final-runtime.json](../m4-copy-allocation/final-runtime.json), and [allocations.json](../m4-copy-allocation/allocations.json). [Original commands and limits](../m4-copy-allocation/README.md) |
| Accepted integration | `261b91d`; echo executable SHA-256 `15fc2bab42f7c2d4b8b7e2c112f0c7d84e606520e563abf458a8894f4ae94fa3` | `utcp-data:/m4-echo-load/20261120T224631Z-13ee3744` and `utcp-data:/m4-echo-load/20261120T224653Z-a0e10a5a`. Two functional echo arms with 50,000 verified replies each. [Integrated results](../../RESULTS.md#m4-bulk-tun-and-echo) |

```bash
python3 -B /utcp/docs/results/reproduction/replay_m4.py /data /work
```

The M4 command reuses the tracked bulk, VNET and multiqueue auditors.
The echo and allocation readers retain the historical verifier calculations
and use the checked-in compact reports for the expected executable identities.
The CPU calculations use the original 100 Hz clock ticks recorded on the
measurement host. None of these commands starts a workload. Echo p50 and p99
are read from the verified endpoint reports, with per-arm and grouped values
recomputed. Full raw latency samples and new wire observations are outside
that replay.
