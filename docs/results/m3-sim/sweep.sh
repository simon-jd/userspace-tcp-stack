#!/usr/bin/env bash
set -euo pipefail
archive=${1:?usage: sweep.sh ARCHIVE [BEGIN [END]]}
begin=${2:-0}
end=${3:-1000000}
step=10000
test "$(cat "$archive/build.exit")" = 0
mkdir -p "$archive/shards"
export ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
export PYTHONDONTWRITEBYTECODE=1
for ((lo=begin; lo<end; lo+=step)); do
    hi=$((lo+step < end ? lo+step : end))
    printf -v shard '%09d-%09d' "$lo" "$hi"
    output="$archive/shards/$shard"
    mkdir "$output"
    cmd=(python3 docs/results/m3-sim/observe_sweep.py
        --seeds "$lo:$hi" --jobs 8 --cpus 16-23 --chunk 200 --timeout 120
        --gen-version 6 --nodes stack --strict-fast-rexmit --sample-mod 500 --progress 1000
        --sim build/gcc-sweep/apps/utcp-sim/utcp-sim
        --asan-sim build/gcc-asan/apps/utcp-sim/utcp-sim
        --out "$output")
    printf '%q ' "${cmd[@]}" > "$output/command.sh"
    printf '\n' >> "$output/command.sh"
    date -u +%FT%TZ > "$output/start.utc"
    printf '%s %s start\n' "$(cat "$output/start.utc")" "$shard"
    rc=0
    "${cmd[@]}" > "$output/runner.log" 2>&1 || rc=$?
    date -u +%FT%TZ > "$output/end.utc"
    printf '%s\n' "$rc" > "$output/exit"
    printf '%s %s exit=%d\n' "$(cat "$output/end.utc")" "$shard" "$rc"
    if ((rc != 0)); then
        exit "$rc"
    fi
done
