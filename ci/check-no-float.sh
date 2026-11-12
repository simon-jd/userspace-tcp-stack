#!/usr/bin/env bash
# Fails if floating point appears in code that must use integer arithmetic
# only (DESIGN §2.2, §13.1): the core (src/core), the core's public headers
# (include/utcp/*.hpp except the backend's tun_device.hpp and event_loop.hpp,
# and include/utcp/defs/*.def and *.hpp), and the simulator (every .cpp and
# .hpp under src/sim and include/utcp/sim, so the scenario generator and the
# link pipeline are covered whatever their file names).
#
# A simulator file that is neither generator nor link pipeline (pcap writer,
# results and JSONL output, wall-clock reporting) may opt out with a line
#   // utcp-no-float: exempt (<reason>)
# The marker is honoured only under src/sim and include/utcp/sim; exempt files
# are listed in the output.
#
# Each file is reduced to its comment-free tokens with the preprocessor in
# "already preprocessed" mode (g++ -fpreprocessed -dD -E -P: comments removed,
# no includes or macro expansion), string literals are blanked, and the rest is
# searched for the keywords float and double, the other floating-point type
# names, and floating literals (1.5, .5, 1e9, 0x1p3).
#
# Usage: ci/check-no-float.sh                 check the tree this script is in
#        ci/check-no-float.sh --files F...    check only the given files (no exemptions)
# Environment: UTCP_GXX (default g++-15, else g++); UTCP_NO_FLOAT_ROOT
# replaces the repository root of the tree check (self-test).
set -euo pipefail

repo=${UTCP_NO_FLOAT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
gxx=${UTCP_GXX:-}
if [[ -z $gxx ]]; then
  if command -v g++-15 >/dev/null 2>&1; then gxx=g++-15; else gxx=g++; fi
fi

files=()
exempt=()
marker='^[[:space:]]*//[[:space:]]*utcp-no-float:[[:space:]]*exempt[[:space:]]*\([^)]+\)'
if [[ ${1:-} == --files ]]; then
  shift
  files=("$@")
else
  while IFS= read -r -d '' f; do files+=("$f"); done < <(
    {
      [[ -d $repo/src/core ]] &&
        find "$repo/src/core" -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' -o -name '*.def' \) -print0
      [[ -d $repo/include/utcp ]] && find "$repo/include/utcp" -maxdepth 1 -type f -name '*.hpp' \
        ! -name tun_device.hpp ! -name event_loop.hpp -print0
      [[ -d $repo/include/utcp/defs ]] &&
        find "$repo/include/utcp/defs" -type f \( -name '*.def' -o -name '*.hpp' \) -print0
      true
    } | sort -z)
  while IFS= read -r -d '' f; do
    if grep -E -q "$marker" "$f"; then
      exempt+=("$f")
    else
      files+=("$f")
    fi
  done < <(
    for d in "$repo/src/sim" "$repo/include/utcp/sim"; do
      [[ -d $d ]] || continue
      find "$d" -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) -print0
    done | sort -z)
fi
for f in ${exempt[@]+"${exempt[@]}"}; do
  echo "check-no-float: exempt ${f#"$repo"/}: $(grep -E -o -m1 "$marker" "$f" | sed -E 's/^[[:space:]]*//')"
done
if ((${#files[@]} == 0)); then
  echo "check-no-float: no files to check" >&2
  exit 1
fi

types='float|double|_Float[0-9]+x?|float_t|double_t|float(16|32|64|128)_t|bfloat16_t'
literals="[0-9][0-9']*\.[0-9']*([eE][-+]?[0-9]+)?|(^|[^A-Za-z0-9_.])\.[0-9]|[0-9][0-9']*[eE][-+]?[0-9]|0[xX][0-9a-fA-F']*\.?[0-9a-fA-F']*[pP][-+]?[0-9]"
pattern="(^|[^A-Za-z0-9_])($types)([^A-Za-z0-9_]|$)|(^|[^A-Za-z0-9_])($literals)"

failed=0
for f in "${files[@]}"; do
  if ! stripped=$("$gxx" -fpreprocessed -dD -E -P -x c++ "$f" 2>&1); then
    echo "check-no-float: $gxx failed on $f:" >&2
    echo "$stripped" >&2
    failed=1
    continue
  fi
  # Blank character literals first (so '"' does not open a string), then
  # strings, then hexadecimal integer literals (their digits can look like an
  # exponent: 0x12'5e7); hexadecimal floats keep their p exponent and stay.
  hits=$(printf '%s\n' "$stripped" |
    sed -E "s/'([^'\\\\]|\\\\.)'/' '/g; s/\"([^\"\\\\]|\\\\.)*\"/\"\"/g" |
    sed -E "s/0[xX][0-9a-fA-F']+([^0-9a-fA-F'.pP]|\$)/0\\1/g" |
    grep -E -n "$pattern" || true)
  if [[ -n $hits ]]; then
    failed=1
    while IFS= read -r line; do
      echo "floating point in ${f#"$repo"/}: ${line#*:}"
    done <<<"$hits"
  fi
done

if ((failed)); then
  echo "check-no-float: FAILED (${#files[@]} files checked)"
  exit 1
fi
echo "check-no-float: ok (${#files[@]} files checked)"
