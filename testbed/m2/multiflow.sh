#!/usr/bin/env bash
# Execute the multi-flow supervisor with this study's private topology and image.
set -euo pipefail
export UTCP_M2_PREFIX=utcp-m2-multiflow UTCP_M2_JOB=utcp-m2-multiflow-helper
export UTCP_IMAGE=sha256:42acf2a264d9cf8a0986791550279b33dbcde1604ab5bdbd39c32097bac44d66
root=$(cd "$(dirname "$0")/../.." && pwd)
exec taskset -c 16-31 nice -n 10 python3 -IB "$root/tools/m2/multiflow.py" "$@"
