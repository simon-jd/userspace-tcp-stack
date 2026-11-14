#!/usr/bin/env bash
# DESIGN §7.2, §13.1: the g++ and clang builds give the same simulator
# digests. Runs `utcp-sim --seed-range A:B` from two build trees and compares
# the digest of every seed. utcp-sim prints one JSONL RunResult line per seed
# (§7.4) with "seed" and "digest" keys. The digest covers every datagram a
# node sends and every datagram delivered to one (after the link
# impairments), so a link pipeline that differs between the compilers shows
# too. Synthetic-node runs are cheap, so they cover more seeds (0:500 holds
# about 25 seeds with garbage corruption). It then compares the TCP harness
# digests that the unit test TcpDeterminism prints (m1-tcp-core acceptance
# test 7). ci/run.sh calls it after the gcc-release and clang-release presets
# pass.
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
# --nodes $2 over seeds $3. utcp-sim exits 1 when a run fails (verdict not
# ok). With stack nodes that fails CI: the TCP engine works, so a checker
# violation in these seeds is a regression (seed 5 caught a window bug). With
# synthetic nodes it is a finding for the sweep, not a compiler difference.
# Exit statuses above 1 (usage error, crash) always fail.
digests() {
  local rc=0
  "$1" --seed-range "$3" --nodes "$2" >"$work/raw" || rc=$?
  if ((rc > 1)) || { ((rc == 1)) && [[ $2 == stack ]]; }; then
    echo "check-digests: FAILED ($1 --nodes $2 exited with status $rc)" >&2
    grep -v '"verdict":"ok"' "$work/raw" | head -5 >&2 || true
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

# The TCP harness runs of tests/unit/tcp_determinism_test.cpp print
# "TcpDeterminism digest <scenario> <hex>"; both builds must agree.
unit_a=$tree_a/tests/unit/utcp_unit_tests
unit_b=$tree_b/tests/unit/utcp_unit_tests
if [[ ! -x $unit_a || ! -x $unit_b ]]; then
  echo "check-digests: FAILED (unit test binaries missing: $unit_a, $unit_b)"
  exit 1
fi
for side in a b; do
  unit=$unit_a
  [[ $side == b ]] && unit=$unit_b
  if ! "$unit" --gtest_filter='TcpDeterminism.*' >"$work/unit-raw"; then
    echo "check-digests: FAILED ($unit --gtest_filter=TcpDeterminism.* failed)" >&2
    exit 1
  fi
  grep '^TcpDeterminism digest ' "$work/unit-raw" >"$work/unit-$side" || true
done
# One digest per profile (rfc, linux_compat).
harness=$(wc -l <"$work/unit-a")
if ((harness < 2)); then
  echo "check-digests: FAILED ($harness TcpDeterminism digest lines from $unit_a, want 2)"
  exit 1
fi
if ! diff -u "$work/unit-a" "$work/unit-b"; then
  echo "check-digests: FAILED (TcpDeterminism digests differ between $tree_a and $tree_b)"
  exit 1
fi
echo "check-digests: ok ($total runs: seeds $seeds with stack nodes, $syn_seeds with synthetic nodes;" \
  "$harness TCP harness digests)"
