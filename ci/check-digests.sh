#!/usr/bin/env bash
# DESIGN §7.2, §13.1: the g++ and clang builds give the same simulator
# digests. Runs `utcp-sim --seed-range A:B` from two build trees and compares
# the digest of every seed. utcp-sim prints one JSONL RunResult line per seed
# (§7.4) with "seed" and "digest" keys. The digest covers every datagram a
# node sends and every datagram delivered to one (after the link
# impairments), so a link pipeline that differs between the compilers shows
# too. Synthetic-node runs are cheap, so they cover more seeds (0:500 holds
# about 25 seeds with garbage corruption). ci/run.sh calls it after the
# gcc-release and clang-release presets pass.
#
# Usage: ci/check-digests.sh [--seeds A:B] [--synthetic-seeds A:B] [TREE_A TREE_B]
#   default seeds 0:20 (stack nodes) and 0:500 (synthetic nodes; --seeds
#   alone sets both), trees build/gcc-release build/clang-release.
# Exits 0 with "skipped" while either tree has no utcp-sim (before m1-sim).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
seeds=0:20
syn_seeds=0:500
syn_given=0
while [[ ${1:-} == --seeds || ${1:-} == --synthetic-seeds ]]; do
  if [[ $1 == --seeds ]]; then
    seeds=$2
  else
    syn_seeds=$2
    syn_given=1
  fi
  shift 2
done
if ((!syn_given)) && [[ $seeds != 0:20 ]]; then
  syn_seeds=$seeds
fi
tree_a=${1:-$repo/build/gcc-release}
tree_b=${2:-$repo/build/clang-release}

sim_a=$tree_a/apps/utcp-sim/utcp-sim
sim_b=$tree_b/apps/utcp-sim/utcp-sim
if [[ ! -x $sim_a || ! -x $sim_b ]]; then
  echo "check-digests: skipped (no utcp-sim in $tree_a or $tree_b)"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# "seed digest" per RunResult line, sorted by seed, for utcp-sim $1 with
# --nodes $2 over seeds $3. utcp-sim exits 1 when a run fails (with the
# link-stub Stack every stack-node workload fails); only exit statuses above 1
# (usage error, crash) make the comparison fail.
digests() {
  local rc=0
  "$1" --seed-range "$3" --nodes "$2" >"$work/raw" || rc=$?
  if ((rc > 1)); then
    echo "check-digests: FAILED ($1 --nodes $2 exited with status $rc)" >&2
    return 1
  fi
  sed -n -E 's/.*"seed":([0-9]+).*"digest":"?([0-9A-Za-z]+)"?.*/\1 \2/p' "$work/raw" | sort -n
}

total=0
for nodes in stack synthetic; do
  range=$seeds
  [[ $nodes == synthetic ]] && range=$syn_seeds
  digests "$sim_a" "$nodes" "$range" >"$work/a"
  digests "$sim_b" "$nodes" "$range" >"$work/b"
  if [[ ! -s $work/a ]]; then
    echo "check-digests: FAILED (no seed/digest lines from $sim_a --nodes $nodes)"
    exit 1
  fi
  if ! diff -u "$work/a" "$work/b"; then
    echo "check-digests: FAILED (--nodes $nodes digests differ between $tree_a and $tree_b)"
    exit 1
  fi
  total=$((total + $(wc -l <"$work/a")))
done
echo "check-digests: ok ($total runs: seeds $seeds with stack nodes, $syn_seeds with synthetic nodes)"
