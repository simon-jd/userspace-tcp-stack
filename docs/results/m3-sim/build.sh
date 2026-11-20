#!/usr/bin/env bash
set -euo pipefail
archive=${1:?usage: build.sh ARCHIVE}
mkdir -p "$archive"
set -x
date -u
uname -srvmo
cmake --version
g++-15 --version
tshark --version
for preset in gcc-sweep gcc-asan; do
    cmake --preset "$preset"
    cmake --build --preset "$preset"
    ctest --preset "$preset" -R 'sim[.]Corpus/'
    cp "build/$preset/compile_commands.json" "$archive/compile-$preset.json"
    cp "build/$preset/CMakeCache.txt" "$archive/cache-$preset.txt"
done
sha256sum build/{gcc-sweep,gcc-asan}/apps/utcp-sim/utcp-sim
sha256sum tests/sim/corpus/*.scenario tools/sim_sweep.py tools/tshark_expert.sh
date -u
