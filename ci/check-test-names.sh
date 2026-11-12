#!/usr/bin/env bash
# Every *_test.cpp under one test directory links into one binary
# (tests/unit -> utcp_unit_tests, tests/sim -> utcp_sim_tests), so:
# 1. each suite name in <stem>_test.cpp starts with the stem in PascalCase
#    (RecvBuffer* in recv_buffer_test.cpp, WireTcp* in wire_tcp_test.cpp);
# 2. no suite name appears in two files of the same directory.
# Suites are the first argument of TEST, TEST_F, TEST_P, TYPED_TEST,
# TYPED_TEST_P and TYPED_TEST_SUITE(_P).
#
# Usage: ci/check-test-names.sh [dir...]   (default: tests/unit tests/sim)
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if (($# > 0)); then
  dirs=("$@")
else
  dirs=("$repo/tests/unit" "$repo/tests/sim")
fi

failed=0
checked=0
for dir in "${dirs[@]}"; do
  [[ -d $dir ]] || continue
  declare -A owner=()
  while IFS= read -r -d '' file; do
    checked=$((checked + 1))
    base=$(basename "$file" _test.cpp)
    # snake_case stem -> PascalCase prefix
    prefix=$(awk -v s="$base" 'BEGIN {
      n = split(s, parts, "_"); out = "";
      for (i = 1; i <= n; i++) out = out toupper(substr(parts[i], 1, 1)) substr(parts[i], 2);
      print out }')
    # A suite name may appear several times in one file; check each once.
    suites=$(grep -E -o '^[[:space:]]*(TEST|TEST_F|TEST_P|TYPED_TEST|TYPED_TEST_P|TYPED_TEST_SUITE|TYPED_TEST_SUITE_P)[[:space:]]*\([[:space:]]*[A-Za-z_][A-Za-z0-9_]*' "$file" |
      sed -E 's/.*\([[:space:]]*//' | sort -u || true)
    for suite in $suites; do
      if [[ $suite != "$prefix"* ]]; then
        echo "${file#"$repo"/}: suite $suite does not start with $prefix"
        failed=1
      fi
      if [[ -n ${owner[$suite]:-} && ${owner[$suite]} != "$file" ]]; then
        echo "${file#"$repo"/}: suite $suite also in ${owner[$suite]#"$repo"/}"
        failed=1
      else
        owner[$suite]=$file
      fi
    done
  done < <(find "$dir" -type f -name '*_test.cpp' -print0 | sort -z)
  unset owner
done

if ((failed)); then
  echo "check-test-names: FAILED ($checked files checked)"
  exit 1
fi
echo "check-test-names: ok ($checked files checked)"
