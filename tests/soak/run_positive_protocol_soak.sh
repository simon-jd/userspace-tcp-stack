#!/usr/bin/env bash
set -euo pipefail

if (( $# != 5 )); then
  echo 'usage: run_positive_protocol_soak.sh BINARY NEW_OUTPUT_DIR SECONDS MIN_COMMON_SECONDS SEED' >&2
  exit 2
fi

binary=$1
output=$2
seconds=$3
minimum=$4
seed=$5
first_cpu=${UTCP_SOAK_FIRST_CPU:-22}
[[ -x $binary && $seconds =~ ^[1-9][0-9]*$ && $minimum =~ ^[1-9][0-9]*$ &&
   $seed =~ ^[1-9][0-9]*$ && $seconds -ge $minimum &&
   $first_cpu =~ ^(0|[1-9][0-9]*)$ ]] || exit 2
mkdir "$output"

lanes=(ipv4 options stream peers)
pids=()
for i in "${!lanes[@]}"; do
  lane=${lanes[i]}
  taskset -c "$((first_cpu + i))" nice -n 10 "$binary" --lane "$lane" --seed "$seed" \
    --seconds "$seconds" > "$output/$lane.log" 2>&1 &
  pids+=("$!")
done

failed=0
for i in "${!lanes[@]}"; do
  if wait "${pids[i]}"; then
    status=0
  else
    status=$?
    failed=1
  fi
  echo "$status" > "$output/${lanes[i]}.status"
done
if (( failed != 0 )); then
  echo "one or more lanes failed; inspect $output" >&2
  exit 1
fi
python3 "$(dirname "$0")/verify_positive_protocol_soak.py" "$output" "$minimum" "$seed"
