#!/usr/bin/env bash
# Run inside the frozen testbed image. /utcp and /data are read-only; /store
# is the private evidence volume mounted separately for archival products.
set -euo pipefail
camp=/data/m2/m2-matrix
dest=/store/m2/archive
docs=/utcp/docs/results/m2-matrix
verify=/utcp/docs/results/m2-checkpoint/verify
tools=/utcp/tools/m2
stage=$(mktemp -d "$dest/m2d-matrix-verification.XXXXXXXX")
export TMPDIR="$stage" MPLCONFIGDIR="$stage/matplotlib" PYTHONDONTWRITEBYTECODE=1 LC_ALL=C
echo "working in $stage"
python3 -IB "$verify/seal_raw.py" "$camp" "$dest" >"$stage/raw-receipt.txt"
raw=$(awk 'NR==1 {print $2}' "$stage/raw-receipt.txt")
mkdir "$stage/full-restore"
tar xzf "$raw" -C "$stage/full-restore"
full="$stage/full-restore/m2-matrix"
(cd "$full" && sha256sum --quiet -c ../manifest/raw.sha256)
python3 -IB "$tools/analyze.py" tables "$stage/native" --campaign "$camp"
python3 -IB "$docs/audit.py" "$camp" "$stage/observed"
python3 -IB "$verify/physical_checkpoint.py" "$camp" "$stage/observed/evidence.csv" "$stage/physical"
python3 -IB "$docs/replay_captures.py" "$camp" "$stage/physical/capture-replay.csv" --jobs 4
python3 -IB "$docs/loss_replay.py" extract "$camp" "$stage/observed/evidence.csv" "$stage/wire-loss-inputs"
python3 -IB "$docs/loss_replay.py" report "$camp" "$stage/wire-loss-inputs" "$stage/wire-report"
python3 -IB "$tools/plot.py" "$camp" "$stage/plots" >"$stage/plot-selection.log"
python3 -IB "$docs/report.py" "$camp" "$stage/native" "$stage/observed" "$stage/plot-selection.log" "$stage/report"
python3 -IB "$verify/physical_checkpoint.py" "$full" "$stage/observed/evidence.csv" "$stage/full-physical"
python3 -IB "$docs/replay_captures.py" "$full" "$stage/full-physical/capture-replay.csv" --jobs 4
diff -qr "$stage/physical" "$stage/full-physical"
python3 -IB "$docs/loss_replay.py" extract "$full" "$stage/observed/evidence.csv" "$stage/full-loss-inputs"
diff -qr "$stage/wire-loss-inputs" "$stage/full-loss-inputs"
python3 -IB "$docs/bbr_queue.py" report "$camp" "$stage/shallow-queue" --all-cells
python3 -IB "$docs/bbr_queue.py" project "$camp" "$stage/wire-queue-inputs" --all-cells
python3 -IB "$docs/bbr_queue.py" project "$full" "$stage/full-wire-queue-inputs" --all-cells
diff -qr "$stage/wire-queue-inputs" "$stage/full-wire-queue-inputs"
python3 -IB "$docs/compact.py" "$camp" "$stage/compact.tar.gz" --physical "$stage/physical" --source-manifest "$stage/full-restore/manifest/raw.sha256" --loss-inputs "$stage/wire-loss-inputs" --queue-inputs "$stage/wire-queue-inputs"
csum=$(sha256sum "$stage/compact.tar.gz" | cut -d' ' -f1)
compact="$dest/m2-matrix-analysis-$csum.tar.gz"
if ! ln "$stage/compact.tar.gz" "$compact"; then cmp "$stage/compact.tar.gz" "$compact"; fi
python3 -IB "$tools/analyze.py" tables "$stage/from-archive" --archive "$compact"
diff -qr "$stage/native" "$stage/from-archive"
mkdir "$stage/compact-restore"
tar xzf "$compact" -C "$stage/compact-restore"
small="$stage/compact-restore/m2-matrix"
(cd "$small" && sha256sum --quiet -c MANIFEST.sha256)
test -z "$(find "$small" -name '*.pcap' -print -quit)"
diff -qr "$stage/physical" "$small/physical-replay"
python3 -IB "$docs/audit.py" "$small" "$stage/replayed"
diff -qr "$stage/observed" "$stage/replayed"
python3 -IB "$docs/loss_replay.py" report "$small" "$small/wire-loss-inputs" "$stage/small-wire-report"
diff -qr "$stage/wire-report" "$stage/small-wire-report"
python3 -IB "$docs/bbr_queue.py" report "$small" "$stage/small-shallow-queue" --projected "$small/wire-queue-inputs" --all-cells
diff -qr "$stage/shallow-queue" "$stage/small-shallow-queue"
python3 -IB "$tools/plot.py" "$small" "$stage/compact-plots" >"$stage/compact-plots.log"
diff -qr "$stage/plots" "$stage/compact-plots"
python3 -IB "$docs/report.py" "$small" "$stage/from-archive" "$stage/replayed" "$stage/compact-plots.log" "$stage/compact-report"
diff -qr "$stage/report" "$stage/compact-report"
mkdir "$stage/export"
cp -a "$stage/plots" "$stage/export/plots"
cp "$stage/native/"*.csv "$stage/observed/"* "$stage/physical/"* "$stage/report/"* "$stage/wire-report/"* "$stage/shallow-queue/"* "$stage/export/"
{ head -2 "$stage/raw-receipt.txt"; sha256sum "$compact"; } | sed 's@/store/m2/archive/@@' >"$stage/export/archives.sha256"
cat "$stage/export/archives.sha256" "$stage/physical/physical.json" "$stage/raw-receipt.txt"
echo "VERIFIED_STAGE=$stage"
