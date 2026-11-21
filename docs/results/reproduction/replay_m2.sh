#!/usr/bin/env bash
# Run from the frozen analysis image. The input checkout and volume are read-only.
set -euo pipefail
if [[ $# -lt 3 || $# -gt 4 ]]; then
    echo "usage: $0 {checkpoint|bbr|ablation|matrix|multiflow} DATA SCRATCH_PARENT [PLAN_SUPPLEMENTS]" >&2
    exit 2
fi
study=$1
data=$(realpath -e "$2")
scratch=$(realpath -e "$3")
here=$(cd -- "$(dirname -- "$0")" && pwd -P)
resroot=$(dirname "$here")
repo=$(cd "$resroot/../.." && pwd -P)
tools=$repo/tools/m2
verify=$resroot/m2-checkpoint/verify
export PYTHONDONTWRITEBYTECODE=1
case "$study" in
    checkpoint) campaign=m2-checkpoint ;;
    bbr) campaign=smoke-769311e-a1 ;;
    ablation) campaign=m2d-ablation ;;
    matrix) campaign=m2-matrix ;;
    multiflow) campaign=m2d-multiflow ;;
    *) echo "unknown campaign: $study" >&2; exit 2 ;;
esac
if [[ "$scratch/" == "$data/"* || "$data/" == "$scratch/"* ||
      "$scratch/" == "$repo/"* || "$repo/" == "$scratch/"* ]]; then
    echo "scratch parent must be separate from the evidence and checkout mounts" >&2
    exit 2
fi
work=$(mktemp -d "$scratch/$study.XXXXXXXX")
printf 'WORK=%s\n' "$work"
args=()
if [[ $# == 4 ]]; then args+=(--plans "$4"); fi
python3 -IB "$here/replay_archive.py" "$study" "$data" "$work" "${args[@]}"
export TMPDIR=$work MPLCONFIGDIR=$work/matplotlib
camp=$work/restored/$campaign
res=$resroot/m2-$study
if [[ "$study" == "multiflow" ]]; then
    python3 -B "$here/replay_multiflow.py" "$camp" "$work"
    exit
fi
python3 -IB "$tools/analyze.py" tables "$work/native" --campaign "$camp"
cmp "$work/native/runs.csv" "$res/runs.csv"
cmp "$work/native/cells.csv" "$res/cells.csv"
case "$study" in
    checkpoint)
        sha=170b21fd9fb172f6917484fcde32d23bdd55f630
        key=cd50db51c944442c8f1158f6b5e48f01ab3f913d9b96034a675af9a8aed9c1fd
        gate=m2-integrate/3f48c30dbf70240d50234f095eaca6de24fc0625-calib-a1-s0
        python3 -IB "$verify/checkpoint_inputs.py" "$repo" "$camp" "$work/native/cells.csv" "$work/audit" "$sha" "$key" "$gate"
        for f in evidence.csv overlay-runs.csv; do cmp "$work/audit/$f" "$res/$f"; done
        python3 -IB "$verify/verify_endpoint_cc.py" "$camp" "$work/audit/evidence.csv" "$work/endpoint-cc.csv"
        python3 -IB "$verify/verify_profile_trace.py" "$camp" "$work/audit/evidence.csv" "$verify/linux-profile.json" "$work/profile-trace.csv"
        python3 -IB "$verify/diagnostics.py" "$repo" "$camp" "$work/audit/evidence.csv" "$work/trace-diagnostics.csv"
        for f in endpoint-cc.csv profile-trace.csv trace-diagnostics.csv; do cmp "$work/$f" "$res/$f"; done
        python3 -IB "$res/render_tables.py" "$work/native" >"$work/tables.md"
        python3 -IB "$res/render_tables.py" "$res" | cmp - "$work/tables.md"
        ;;
    bbr)
        python3 -IB "$res/verify/smoke_replay.py" "$repo" "$camp" "$work/audit" "$res/freeze.json"
        for f in evidence.csv endpoint-cc.csv bbr-trace.json medians.json; do cmp "$work/audit/$f" "$res/$f"; done
        python3 -IB "$verify/diagnostics.py" "$repo" "$camp" "$work/audit/evidence.csv" "$work/diagnostics.csv"
        cmp "$work/diagnostics.csv" "$res/diagnostics.csv"
        ;;
    ablation)
        python3 -IB "$res/audit.py" "$camp" "$work/audit"
        python3 -IB "$res/report.py" "$camp" "$work/audit/evidence.csv" "$work/native/cells.csv" "$work/report"
        ;;
    matrix)
        python3 -IB "$res/audit.py" "$camp" "$work/audit"
        python3 -IB "$res/loss_replay.py" report "$camp" "$camp/wire-loss-inputs" "$work/wire-report"
        python3 -IB "$res/bbr_queue.py" report "$camp" "$work/shallow-queue" --projected "$camp/wire-queue-inputs" --all-cells
        for f in "$work/wire-report/"* "$work/shallow-queue/"* "$camp/physical-replay/"*; do
            cmp "$f" "$res/${f##*/}"
        done
        ;;
esac
python3 -IB "$tools/plot.py" "$camp" "$work/plots" >"$work/plot-selection.log"
diff -qr "$work/plots" "$res/plots"
case "$study" in
    checkpoint)
        python3 -IB "$verify/compare_overlay.py" "$work/audit/overlay-runs.csv" "$work/plot-selection.log"
        ;;
    ablation)
        python3 -IB "$res/plot_selection.py" "$camp" "$work/audit/evidence.csv" "$work/plot-selection.log" "$work/plot-selection.csv"
        cmp "$work/plot-selection.csv" "$res/plot-selection.csv"
        ;;
    matrix)
        python3 -IB "$res/report.py" "$camp" "$work/native" "$work/audit" "$work/plot-selection.log" "$work/report"
        ;;
esac
if [[ "$study" == "ablation" || "$study" == "matrix" ]]; then
    for f in "$work/audit/"* "$work/report/"*; do cmp "$f" "$res/${f##*/}"; done
fi
printf 'Verified %s tables, diagnostics and plots\n' "$study"
