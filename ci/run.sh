#!/usr/bin/env bash
# Configure, build and test every preset (or the presets given as arguments).
# Runs inside the utcp-testbed image; on the server use ci/docker-ci.sh.
# Exit status is non-zero if any step of any preset fails.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

all_presets=(gcc-debug gcc-release gcc-asan clang-debug clang-release clang-asan gcc-sweep clang-fuzz)
if (($# > 0)); then
  presets=("$@")
else
  presets=("${all_presets[@]}")
fi

echo "== toolchain"
g++-15 --version | head -1
clang++-21 --version | head -1
cmake --version | head -1
echo "ninja $(ninja --version)"
dpkg-query -W -f 'googletest ${Version}\n' googletest 2>/dev/null || true
echo "nproc $(nproc)"

declare -A result
failed=0
for p in "${presets[@]}"; do
  echo
  echo "== preset $p"
  start=$SECONDS
  if ! cmake --preset "$p"; then
    result[$p]="FAIL (configure)"
  elif ! cmake --build --preset "$p"; then
    result[$p]="FAIL (build)"
  elif ! ctest --preset "$p"; then
    result[$p]="FAIL (test)"
  else
    result[$p]="ok"
  fi
  [[ ${result[$p]} == ok ]] || failed=1
  echo "== preset $p: ${result[$p]} ($((SECONDS - start)) s)"
done

echo
echo "== summary"
for p in "${presets[@]}"; do
  printf '%-14s %s\n' "$p" "${result[$p]}"
done
exit "$failed"
