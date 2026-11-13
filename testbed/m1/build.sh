#!/usr/bin/env bash
# Builds the programs the testbed runs, inside the testbed image (so they run
# in the DUT and the peer), as the calling user, on the build CPUs (16-31,
# nice 10, at most 8 jobs). The build directory is build/tb-<preset>, which
# the containers see as /utcp/build/tb-<preset>.
#
# Usage: testbed/m1/build.sh [PRESET] [TARGET...]
#   PRESET   a configure preset (default gcc-release)
#   TARGET   build only these targets (default: everything)
# Environment: UTCP_IMAGE (default utcp-testbed:dev).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
  sed -n '2,/^source/p' "$0" | sed '$d; s/^# \{0,1\}//'
  exit 0
fi
preset=${1:-gcc-release}
shift || true
targets=("$@")
dir=build/tb-$preset

target_args=()
for t in "${targets[@]}"; do
  target_args+=(--target "$t")
done

echo "building $dir (preset $preset${targets:+, targets ${targets[*]}}) in $tb_image"
docker run --rm --name utcp-m1-build --user "$(id -u):$(id -g)" \
  --cpuset-cpus 16-31 -v "$tb_repo:$tb_repo" -w "$tb_repo" "$tb_image" \
  bash -euo pipefail -c '
    dir=$1 preset=$2
    shift 2
    nice -n 10 cmake --preset "$preset" -B "$dir" >/dev/null
    nice -n 10 cmake --build "$dir" -j8 "$@"' bash "$dir" "$preset" "${target_args[@]}"
echo "built $tb_repo/$dir (in the containers: /utcp/$dir)"
