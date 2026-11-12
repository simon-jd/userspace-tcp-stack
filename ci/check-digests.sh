#!/usr/bin/env bash
# DESIGN §7.2, §13.1: the g++ and clang builds give the same simulator
# digests. Runs `utcp-sim --seed-range A:B` from two build trees and compares
# the digest of every seed. utcp-sim prints one JSONL RunResult line per seed
# (§7.4) with "seed" and "digest" keys; the utcp-sim side is m1-sim's, which
# may refine how this script reads it. ci/run.sh calls it after the
# gcc-release and clang-release presets pass.
#
# Usage: ci/check-digests.sh [--seeds A:B] [TREE_A TREE_B]
#   default seeds 0:20, trees build/gcc-release build/clang-release.
# Exits 0 with "skipped" while either tree has no utcp-sim (before m1-sim).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
seeds=0:20
if [[ ${1:-} == --seeds ]]; then
  seeds=$2
  shift 2
fi
tree_a=${1:-$repo/build/gcc-release}
tree_b=${2:-$repo/build/clang-release}

sim_a=$tree_a/apps/utcp-sim/utcp-sim
sim_b=$tree_b/apps/utcp-sim/utcp-sim
if [[ ! -x $sim_a || ! -x $sim_b ]]; then
  echo "check-digests: skipped (no utcp-sim in $tree_a or $tree_b)"
  exit 0
fi

# "seed digest" per RunResult line, sorted by seed.
digests() {
  "$1" --seed-range "$seeds" |
    sed -n -E 's/.*"seed":([0-9]+).*"digest":"?([0-9A-Za-z]+)"?.*/\1 \2/p' | sort -n
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
digests "$sim_a" >"$work/a"
digests "$sim_b" >"$work/b"
if [[ ! -s $work/a ]]; then
  echo "check-digests: FAILED (no seed/digest lines from $sim_a)"
  exit 1
fi
if ! diff -u "$work/a" "$work/b"; then
  echo "check-digests: FAILED (digests differ between $tree_a and $tree_b)"
  exit 1
fi
echo "check-digests: ok ($(wc -l <"$work/a") seeds, $seeds)"
