#!/usr/bin/env bash
set -euo pipefail
archive=${1:?usage: campaign.sh ARCHIVE}
for ((i=0; i<240; i++)); do
    [[ ! -f "$archive/build.exit" ]] || break
    sleep 10
done
test "$(cat "$archive/build.exit")" = 0
source_dir=docs/results/m3-sim
cp .m3-sweep-provenance "$archive/sweep-provenance.txt"
export PYTHONDONTWRITEBYTECODE=1
mkdir "$archive/observer-control"
rc=0
python3 "$source_dir/observe_sweep.py" --seeds 0:4 --jobs 1 --cpus 16-23 --chunk 2 \
    --gen-version 6 --nodes stack --strict-fast-rexmit --plant-fail 0 --sample-mod 0 \
    --out "$archive/observer-control" > "$archive/observer-control/runner.log" 2>&1 || rc=$?
test "$rc" = 1
python3 - "$archive/observer-control" <<'PY'
import json
import sys
from pathlib import Path

data = Path(sys.argv[1])
summary = json.loads((data / "summary.json").read_text())
assert summary["failures"] == [0], summary
assert summary["missing"] == [2, 3], summary
assert [json.loads(line)["seed"] for line in (data / "observed.jsonl").read_text().splitlines()] == [0, 1]
assert "original non-ok seed" in (data / "runner.log").read_text()
PY
bash "$source_dir/sweep.sh" "$archive" 0 10000
first="$archive/shards/000000000-000010000"
bash tools/tshark_expert.sh "$first/samples" > "$first/expert.log" 2>&1
bash "$source_dir/sweep.sh" "$archive" 10000 1000000
