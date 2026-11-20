#!/usr/bin/env bash
# Run after the stop/qualification receipts and the complete source tree are sealed.
# --export-only reuses a completed replay in the supplied scratch directory.
set -euo pipefail
cd "$(dirname "$0")/../../.."
export_only=false
if [[ ${1:-} == --export-only ]]; then
  export_only=true
  shift
fi
qualifier=${1:?qualification label required}
scratch=${2:?fresh absolute directory on the evidence volume required}
[[ $# == 2 ]]
[[ $qualifier =~ ^[a-z][a-z0-9-]{0,48}$ ]]
[[ $scratch =~ ^/data/m2/archive/m2d-multiflow-verify-[a-zA-Z0-9-]+$ ]]
name=utcp-m2-multiflow-archive-$$
image=sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66
if ! $export_only; then
  docker run --rm --network none --name "$name" --cpuset-cpus 16-31 \
    -v "$PWD:/utcp:ro" -v utcp-data:/data "$image" nice -n 10 \
    python3 -IB /utcp/docs/results/m2-multiflow/archive_replay.py \
    /data/m2/m2d-multiflow /data/m2/archive "$scratch" --qualification "$qualifier"
fi
# Publish only tables, plots, and checksums in the private source checkout.
docker run --rm --network none --name "$name-export" --cpuset-cpus 16-31 \
  --user "$(id -u):$(id -g)" -v "$PWD/docs/results/m2-multiflow:/results" \
  -v utcp-data:/data:ro "$image" nice -n 10 bash -euo pipefail -c '
  scratch=$1; qual=$2
  restore=$scratch/restore-compact
  cd "$restore/m2d-multiflow"
  test -s "$scratch/archive-replay.json"
  receipts=("$qual/freeze.json" "$qual/qualified.json" production-status.json
            acquisition/source.sha256 acquisition/source-commit.txt
            acquisition/production-source-approved acquisition/post-key.txt)
  for file in "${receipts[@]}"; do
    awk -v file="$file" '\''$2 == file { print; found++ } END { exit found != 1 }'\'' \
      "$restore/manifest/contents.sha256" | sha256sum --check --strict
  done
  mkdir -p /results/measured
  cp -R "$scratch/tables-original/." /results/measured/
  cp "$scratch/physical-original.csv" /results/measured/physical-captures.csv
  cp "$scratch/connections-original.csv" /results/measured/physical-connections.csv
  cp "$scratch/archive-replay.json" /results/measured/
  cp "${receipts[@]}" /results/measured/
  ' bash "$scratch" "$qualifier"
