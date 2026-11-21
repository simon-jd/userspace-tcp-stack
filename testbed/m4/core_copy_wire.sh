#!/usr/bin/env bash
# One normal Linux TCP connection per private network namespace, with a
# functional (non-timing) GDB recording on the userspace server only.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
volume_dir=${1:?pass a fresh directory name for utcp-data/m4}
[[ $volume_dir =~ ^[a-zA-Z0-9._-]+$ && $volume_dir != . && $volume_dir != .. ]]
bin=${2:-build/gcc-debug/apps/utcp-bulk/utcp-bulk}
image=${UTCP_IMAGE:-utcp-testbed:dev}
cpus=${UTCP_COPY_CPUS:-24-27}
docker run --rm --network none --cpuset-cpus "$cpus" -v utcp-data:/data "$image" \
  mkdir "/data/m4/$volume_dir"
for mode in legacy tcpv4; do
  for direction in send recv; do
    docker run --rm --network none --cpuset-cpus "$cpus" --cap-add NET_ADMIN --device /dev/net/tun \
      --mount "type=volume,src=utcp-data,dst=/out,volume-subpath=m4/$volume_dir" \
      --mount "type=bind,src=$root,dst=$root,readonly" -w "$root" \
      --mount type=bind,src=/usr/bin/gdb,dst=/usr/bin/gdb,readonly \
      --mount type=bind,src=/usr/share/gdb,dst=/usr/share/gdb,readonly \
      --mount type=bind,src=/usr/lib/x86_64-linux-gnu,dst=/probe-libs,readonly \
      "$image" nice -n 10 bash -euo pipefail -s -- "$bin" "$mode" "$direction" <<'INNER'
bin=$1 mode=$2 direction=$3
out=/out/$mode-$direction
mkdir "$out"
sha256sum "$bin" >"$out/program.sha256"
vnet=()
[[ $mode == legacy ]] || vnet=(vnet_hdr)
ip link set lo up
ip tuntap add dev utcp0 mode tun "${vnet[@]}"
ip addr add 198.18.0.1/24 dev utcp0
ip link set dev utcp0 mtu 1500 up
ip -details tuntap show >"$out/interface.txt"
common=(--bytes 65549 --sample-ms 0 --pattern-seed 271 --cc cubic --jsonl)
server=("$bin" --backend utcp --listen 198.18.0.2:7304 --tun utcp0 --addr 198.18.0.2
        --tun-offload "$mode" --seed 1 --stats "$out/stack.json" "--$direction"
        "${common[@]}" "$out/server.jsonl")
other=send
[[ $direction == send ]] && other=recv
env LD_LIBRARY_PATH=/probe-libs UTCP_COPY_OUTPUT="$out/copies.json" timeout 90 \
  gdb --batch -nx -q -ex 'unset environment LD_LIBRARY_PATH' -x testbed/m4/core_copy_gdb.py \
  --args "${server[@]}" >"$out/debugger.log" 2>&1 &
debugger=$!
trap 'kill "$debugger" 2>/dev/null || true' EXIT
for _ in {1..200}; do
  kill -0 "$debugger"
  if [[ -s "$out/server.jsonl" ]] || ip -details link show utcp0 | grep -q LOWER_UP; then break; fi
  sleep .05
done
timeout 60 "$bin" --backend kernel --connect 198.18.0.2:7304 "--$other" \
  "${common[@]}" "$out/linux.jsonl" >"$out/client.log" 2>&1
wait "$debugger"
trap - EXIT
INNER
  done
done
