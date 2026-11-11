#!/usr/bin/env bash
# Builds the testbed/CI image from testbed/Dockerfile.
# Usage: testbed/build-image.sh [tag]     (default tag: utcp-testbed:dev)
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tag=${1:-utcp-testbed:dev}

docker build --progress=plain -t "$tag" -f "$here/Dockerfile" "$here"

echo "built $tag"
docker image inspect "$tag" --format 'image id {{.Id}}  size {{.Size}} bytes'
docker run --rm --name "utcp-build-check-$$" "$tag" bash -c '
  set -e
  g++-15 --version | head -1
  clang++-21 --version | head -1
  cmake --version | head -1
  echo "ninja $(ninja --version)"
  dpkg-query -W -f "googletest \${Version}\n" googletest'
