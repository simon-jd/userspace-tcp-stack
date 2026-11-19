#!/usr/bin/env bash
# Run inside the frozen image after timing has stopped. /data and /utcp are
# read-only; /store is the same private volume mounted for verified outputs.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
camp=/data/m2/m2d-ablation
dest=/store/m2/archive
stage=$(mktemp -d "$dest/m2d-ablation-verification.XXXXXXXX")
export TMPDIR="$stage" MPLCONFIGDIR="$stage/matplotlib"
tools=/utcp/tools/m2
docs=/utcp/docs/results/m2-ablation
previous=/utcp/docs/results/m2-checkpoint/verify
ops=/utcp/build/ablation-ops
receipts=/store/m2/m2d-ablation/acquisition
mkdir -p "$receipts"
python3 -B - >"$receipts/final-runtime.sha256" <<'PY_RUNTIME'
import sys
from pathlib import Path
sys.path.insert(0, "/utcp/docs/results/m2-ablation")
import audit as a
root=Path("/utcp")
checks = {
    "apps/utcp-bulk/utcp-bulk": (a.BULK, a.matrix.sha256_file(root/"build/tb-gcc-release/apps/utcp-bulk/utcp-bulk")),
    "src/core/libutcp_core.a": (a.CORE, a.matrix.sha256_file(root/"build/tb-gcc-release/src/core/libutcp_core.a")),
    "testbed/m2+tools/m2": (a.SCRIPTS, a.matrix.tree_hash(root/"testbed/m2",root/"tools/m2")),
}
for name,(expected,observed) in checks.items():
    assert observed == expected, (name,observed)
    print(observed,name)
PY_RUNTIME
cp -p "$docs/plan.toml" "$docs/rfc-profile.json" "$ops/restore-checkpoint.sh" "$ops/launch.sh" "$ops/session.sh" "$ops"/start*.log "$ops"/start*.status "$receipts/"
for attempt in "$ops"/launch.*; do cp -a "$attempt" "$receipts/"; done
(cd /data/m2/archive && sha256sum -c /utcp/docs/results/m2-checkpoint/archives.sha256) >"$stage/checkpoint-checksums.txt"
python3 -B "$tools/analyze.py" tables "$stage/native" --campaign "$camp"
python3 -B "$docs/audit.py" "$camp" "$stage/raw-audit"
python3 -B "$docs/report.py" "$camp" "$stage/raw-audit/evidence.csv" "$stage/native/cells.csv" "$stage/raw-tables"
python3 -B "$previous/physical_checkpoint.py" "$camp" "$stage/raw-audit/evidence.csv" "$stage/raw-physical"
python3 -IB "$tools/plot.py" "$camp" "$stage/raw-plots" >"$stage/raw-plots.txt"
python3 -B "$tools/analyze.py" archive "$camp" "$stage/analysis.tar.gz"
python3 -B "$tools/analyze.py" tables "$stage/compact-tables" --archive "$stage/analysis.tar.gz"
for file in runs.csv cells.csv; do cmp "$stage/native/$file" "$stage/compact-tables/$file"; done
python3 -B "$previous/seal_raw.py" "$camp" "$dest" >"$stage/raw-receipt"
raw=$(awk 'NR==1 {print $2}' "$stage/raw-receipt")
mkdir "$stage/complete-restore"
tar xzf "$raw" -C "$stage/complete-restore"
restored="$stage/complete-restore/m2d-ablation"
(cd "$restored" && sha256sum --quiet -c ../manifest/raw.sha256)
python3 -B "$previous/physical_checkpoint.py" "$restored" "$stage/raw-audit/evidence.csv" "$stage/restored-physical"
diff -qr "$stage/raw-physical" "$stage/restored-physical"
python3 -B "$tools/analyze.py" tables "$stage/restored-tables" --campaign "$restored"
for file in runs.csv cells.csv; do cmp "$stage/native/$file" "$stage/restored-tables/$file"; done
mkdir "$stage/compact-restore"
tar xzf "$stage/analysis.tar.gz" -C "$stage/compact-restore"
compact="$stage/compact-restore/m2d-ablation"
(cd "$compact" && sha256sum --quiet -c MANIFEST.sha256)
cp "$restored/plan.json" "$compact/plan.json"
python3 -B "$docs/audit.py" "$compact" "$stage/compact-audit"
diff -qr "$stage/raw-audit" "$stage/compact-audit"
python3 -B "$docs/report.py" "$compact" "$stage/compact-audit/evidence.csv" "$stage/compact-tables/cells.csv" "$stage/rebuilt-report"
diff -qr "$stage/raw-tables" "$stage/rebuilt-report"
python3 -IB "$tools/plot.py" "$compact" "$stage/compact-plots" >"$stage/compact-plots.txt"
diff -qr "$stage/raw-plots" "$stage/compact-plots"
python3 -B "$docs/plot_selection.py" "$camp" "$stage/raw-audit/evidence.csv" "$stage/raw-plots.txt" "$stage/plot-selection.csv"
digest=$(sha256sum "$stage/analysis.tar.gz" | cut -d' ' -f1)
analysis="$dest/m2d-ablation-analysis-$digest.tar.gz"
if ! ln "$stage/analysis.tar.gz" "$analysis"; then cmp "$analysis" "$stage/analysis.tar.gz"; fi
cp -p "$receipts/final-runtime.sha256" "$stage/native/"*.csv "$stage/raw-audit/"* "$stage/raw-physical/"* "$stage/raw-tables/"* "$stage/plot-selection.csv" "$stage/checkpoint-checksums.txt" /out/
cp -a "$stage/raw-plots" /out/plots
{ head -2 "$stage/raw-receipt"; sha256sum "$analysis"; } | sed 's@/store/m2/archive/@@' >/out/archives.sha256
cat "$stage/raw-receipt" /out/archives.sha256 "$stage/raw-physical/physical.json"
echo "VERIFIED_STAGE=$stage"
