#!/usr/bin/env bash
# Run directed §4.2 comparisons on the existing, non-timing slot 2.
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
exec python3 "$repo/tools/m2/recovery_compare.py" run "$@"
