#!/usr/bin/env bash
# Exercise the normal echo application on independent FDs of the same TUN.
# Build utcp-echo first. Optional arguments select individual mode-count arms.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
echo_bin=/src/build/${UTCP_PRESET:-gcc-release}/apps/utcp-echo/utcp-echo
image=${UTCP_IMAGE:-utcp-testbed:dev}
if [[ $# == 0 ]]; then set -- legacy-default legacy-1 legacy-2 checksum-2 tcpv4-2; fi

docker run --rm -i --name "utcp-m4-multiqueue-functional-$$" --network none \
  --cpuset-cpus 28-31 --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$repo:/src:ro" -e "ECHO_BIN=$echo_bin" "$image" nice -n 10 bash -s -- "$@" <<'CONTAINER'
set -euo pipefail
tmp=$(mktemp -d)
trap 'cat "$tmp"/*.err >&2 || true' ERR
ip link set lo up
uname -r
port=5125
for arm in "$@"; do
  mode=${arm%-*}
  count=${arm##*-}
  tun_flags=() args=()
  if [[ $mode != legacy ]]; then tun_flags+=(vnet_hdr); fi
  if [[ $count != default ]]; then
    tun_flags+=(multi_queue)
    args+=(--tun-queues "$count")
  fi
  prefix=$tmp/$arm
  ip tuntap add dev utcp0 mode tun "${tun_flags[@]}"
  ip addr add 198.18.0.1/24 dev utcp0
  ip link set utcp0 up
  "$ECHO_BIN" --backend utcp --tun utcp0 --addr 198.18.0.2 --seed 1 \
    --tun-offload "$mode" "${args[@]}" --stats "$prefix.stats" --listen "$port" \
    >"$prefix.app" 2>"$prefix.err" &
  pid=$!
  ready=0
  for _ in {1..150}; do
    if ! kill -0 "$pid" 2>/dev/null; then wait "$pid"; exit 1; fi
    if grep -q 'TCP echo on' "$prefix.err"; then ready=1; break; fi
    sleep .02
  done
  [[ $ready == 1 ]]
  ip tuntap show dev utcp0
  ethtool -k utcp0 >"$prefix.features"
  timeout 25s python3 /src/tests/interop/m4_tun_multiqueue.py exercise "$pid" "$port" "$count"
  kill -TERM "$pid"
  wait "$pid"
  python3 /src/tests/interop/m4_tun_multiqueue.py verify "$prefix" "$mode" "$count"
  ip tuntap del dev utcp0 mode tun "${tun_flags[@]}"
  port=$((port + 1))
done
CONTAINER
