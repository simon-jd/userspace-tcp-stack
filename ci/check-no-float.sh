#!/usr/bin/env bash
# Fails if floating point appears in code that must use integer arithmetic
# only (DESIGN §2.2, §13.1): the core (src/core), the core's public headers
# (include/utcp/*.hpp except the backend's tun_device.hpp and event_loop.hpp,
# and include/utcp/defs/*.def), and the simulator's scenario generator and link
# pipeline: files under src/sim or include/utcp/sim whose name starts with
# "scenario", "gen" or "link".
#
# Each file is reduced to its comment-free tokens with the preprocessor in
# "already preprocessed" mode (g++ -fpreprocessed -dD -E -P: comments removed,
# no includes or macro expansion), string literals are blanked, and the rest is
# searched for the keywords float and double, the other floating-point type
# names, and floating literals (1.5, .5, 1e9, 0x1p3).
#
# Usage: ci/check-no-float.sh                 check the tree this script is in
#        ci/check-no-float.sh --files F...    check only the given files
# Environment: UTCP_GXX (default g++-15, else g++).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
gxx=${UTCP_GXX:-}
if [[ -z $gxx ]]; then
  if command -v g++-15 >/dev/null 2>&1; then gxx=g++-15; else gxx=g++; fi
fi

files=()
if [[ ${1:-} == --files ]]; then
  shift
  files=("$@")
else
  while IFS= read -r -d '' f; do files+=("$f"); done < <(
    {
      find "$repo/src/core" -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' -o -name '*.def' \) -print0
      find "$repo/include/utcp" -maxdepth 1 -type f -name '*.hpp' \
        ! -name tun_device.hpp ! -name event_loop.hpp -print0
      find "$repo/include/utcp/defs" -type f -name '*.def' -print0 2>/dev/null || true
      for d in "$repo/src/sim" "$repo/include/utcp/sim"; do
        [[ -d $d ]] || continue
        find "$d" -type f \( -name 'scenario*' -o -name 'gen*' -o -name 'link*' \) \
          \( -name '*.cpp' -o -name '*.hpp' \) -print0
      done
    } | sort -z)
fi
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
