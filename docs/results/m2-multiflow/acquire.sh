#!/usr/bin/env bash
# Start counted acquisition after the qualification readback and offline validation.
set -euo pipefail
cd "$(dirname "$0")/../../.."
qualifier=${1:?qualification label required}
[[ $qualifier =~ ^[a-z][a-z0-9-]{0,48}$ ]]
export UTCP_M2_PREFIX=utcp-m2-multiflow UTCP_M2_JOB=utcp-m2-multiflow-helper
export UTCP_IMAGE=sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66
export PYTHONDONTWRITEBYTECODE=1
mkdir -p .logs
campaign=m2d-multiflow/$qualifier
host_commit=$(git rev-parse HEAD)
gate=$campaign/gate-s0
proof=$campaign/proof
# Bind the exact offline source in addition to the standard hashed runtime key.
docker run --rm --network none --name "utcp-m2-multiflow-bind-$$" --cpuset-cpus 16-31 \
  -v utcp-data:/data -v "$PWD:/utcp:ro" "$UTCP_IMAGE" nice -n 10 bash -ec '
    label=$1; head=$2
    rd=/data/m2/m2d-multiflow/acquisition
    cd /utcp
    test -s "/data/m2/m2d-multiflow/$label/qualified.json"
    dir=docs/results/m2-multiflow
    inputs=("$dir"/{study.py,study_tables.py,study_report.py,capture_evidence.py,schedule.csv,protocol.md,qualify.py}
            tools/m2/{multiflow,matrix,analyze}.py testbed/m2/multiflow.sh)
    checksum=$(sha256sum "${inputs[@]}")
    if [[ -e $rd/source.sha256 ]]; then
      cmp <(printf "%s\n" "$checksum") "$rd/source.sha256"
    else
      mkdir -p "$rd/source"
      cp --parents "${inputs[@]}" "$rd/source"
      printf "%s\n" "$checksum" >"$rd/source.sha256"
      printf "%s\n" "$head" >"$rd/source-commit.txt"
    fi
    (cd "$rd/source"; sha256sum -c "$rd/source.sha256")
    cp "$dir/acquire.sh" "$rd/launch-production.sh"
  ' bash "$qualifier" "$host_commit"
set +e
testbed/m2/multiflow.sh produce --gate "$gate" --proof "$proof"
rc=$?
set -e
printf '%s\n' "$rc" > .logs/production.rc
exit "$rc"
