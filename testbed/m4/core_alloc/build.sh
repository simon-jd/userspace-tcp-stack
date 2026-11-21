#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
here=$root/testbed/m4/core_alloc
bin=${1:?supply a new build directory}
mkdir -p "$bin"
bin=$(realpath "$bin")
cxx=${CXX:-g++-15}
cmake -S "$root" -B "$bin/core" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_FLAGS_RELEASE="-O3 -g1 -DNDEBUG -fno-omit-frame-pointer" \
  -DCMAKE_CXX_COMPILER="$cxx" -DUTCP_BUILD_TESTS=OFF
cmake --build "$bin/core" -j"${JOBS:-4}" --target utcp_core
common=(-std=c++23 -O2 -g -fno-omit-frame-pointer -Wall -Wextra -Werror)
"$cxx" "${common[@]}" -fPIC -shared "$here/heap_probe.cpp" -ldl -o "$bin/libutcp_heap_probe.so"
link=(-L"$bin" -Wl,-rpath,"$bin" -Wl,-z,now -lutcp_heap_probe -ldl)
"$cxx" "${common[@]}" -fno-builtin "$here/probe_control.cpp" "${link[@]}" -o "$bin/control"
for driver in core_driver sack_driver; do
  "$cxx" "${common[@]}" -no-pie -I"$root/include" -I"$root/src" -I"$root/tests" \
    "$here/$driver.cpp" "$root/tests/support/packet_builder.cpp" \
    "$bin/core/src/core/libutcp_core.a" "${link[@]}" -o "$bin/$driver"
done
nm -uC "$bin/core/src/core/libutcp_core.a" > "$bin/core-undefined.txt"
sha256sum "$bin"/{control,core_driver,sack_driver,libutcp_heap_probe.so,core/src/core/libutcp_core.a}
