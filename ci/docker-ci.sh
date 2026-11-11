#!/usr/bin/env bash
# Runs ci/run.sh in a throwaway container from the testbed image, pinned to
# the build CPUs. The source tree is mounted read-only and copied into the
# container, so nothing is written to the host checkout.
# Usage: ci/docker-ci.sh [preset...]
# Environment: UTCP_IMAGE (default utcp-testbed:dev), UTCP_CI_CPUS (default 16-31).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=${UTCP_IMAGE:-utcp-testbed:dev}
cpus=${UTCP_CI_CPUS:-16-31}
name=utcp-ci-$(date +%Y%m%d-%H%M%S)-$$

cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "container $name, image $image ($(docker image inspect -f '{{.Id}}' "$image")), cpus $cpus"
docker run --rm --name "$name" --cpuset-cpus "$cpus" \
  -v "$repo:/src:ro" "$image" \
  bash -c '
    set -euo pipefail
    mkdir /work
    tar -C /src --exclude=./build --exclude="./build-*" --exclude=./.git --exclude=./.logs -cf - . |
      tar -C /work -xf -
    cd /work
    exec nice -n 10 ci/run.sh "$@"' bash "$@"
