#!/usr/bin/env bash
# Exercise both directions with real Linux TCP and TUN file descriptors.
# Run after building utcp-bulk; UTCP_PRESET defaults to gcc-release.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
bin=/src/build/${UTCP_PRESET:-gcc-release}/apps/utcp-bulk/utcp-bulk
image=${UTCP_IMAGE:-utcp-testbed:dev}

docker run --rm -i --name "utcp-m4-offload-functional-$$" --network none \
  --cpuset-cpus 16-23 --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$repo:/src:ro" -e "BULK=$bin" "$image" nice -n 10 bash -s <<'CONTAINER'
set -euo pipefail
ip link set lo up
uname -r
tmp=$(mktemp -d)
trap 'cat "$tmp"/*.err 2>/dev/null >&2 || true' ERR
bytes=4000055
port=5125
for mode in legacy checksum tcpv4; do
  tun_flags=()
  if [[ $mode != legacy ]]; then tun_flags=(vnet_hdr); fi
  ip tuntap add dev utcp0 mode tun "${tun_flags[@]}"
  ip addr add 198.18.0.1/24 dev utcp0
  ip link set utcp0 up
  for direction in gro gso; do
    prefix=$tmp/$mode-$direction
    largs=() cargs=(--send)
    if [[ $direction == gso ]]; then largs=(--send) cargs=(); fi
    timeout 15s "$BULK" --backend utcp --tun utcp0 --addr 198.18.0.2 --seed 1 \
      --tun-offload="$mode" --stats "$prefix.stats" --listen "$port" --bytes "$bytes" \
      --sample-ms 0 "${largs[@]}" >"$prefix.u" 2>"$prefix.u.err" &
    upid=$!
    ready=0
    for _ in {1..100}; do
      kill -0 "$upid" 2>/dev/null || break
      if [[ $(cat /sys/class/net/utcp0/operstate) == up ]]; then ready=1; break; fi
      sleep .02
    done
    if [[ $ready != 1 ]]; then
      wait "$upid" || { cat "$prefix.u.err" >&2; exit 2; }
      echo "TUN fd never attached" >&2
      exit 1
    fi
    ethtool -k utcp0 >"$prefix.features"
    timeout 15s "$BULK" --backend kernel --connect "198.18.0.2:$port" --bytes "$bytes" \
      --sample-ms 0 "${cargs[@]}" >"$prefix.k" 2>"$prefix.k.err"
    wait "$upid"
    python3 - "$prefix" "$mode" "$direction" "$bytes" <<'PY'
import hashlib
import json
import pathlib
import struct
import sys

prefix, mode, direction, count = sys.argv[1:]
need = int(count)
stats, a, b = (json.loads(pathlib.Path(prefix + suffix).read_text()) for suffix in
               (".stats", ".u", ".k"))
features = pathlib.Path(prefix + ".features").read_text()
mask = (1 << 64) - 1
expected = bytearray()
for i in range((need + 7) // 8):
    z = (1 + i * 0x9e3779b97f4a7c15) & mask
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & mask
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & mask
    expected.extend(struct.pack("<Q", z ^ (z >> 31)))
assert a["bytes"] == b["bytes"] == need
assert a["sha256"] == b["sha256"] == hashlib.sha256(expected[:need]).hexdigest()
assert stats["dev_tun_offload"] == mode
assert stats["dev_vnet_hdr_size"] == (0 if mode == "legacy" else 10)
assert stats["dev_rx_vnet_drops"] == stats["dev_rx_errors"] == stats["dev_tx_errors"] == 0
assert stats["TcpInCsumErrors"] == 0
rx_metadata = stats["dev_rx_csum_partial"] + stats["dev_rx_csum_valid"]
assert bool(rx_metadata) == (mode != "legacy")
assert bool(stats["dev_tx_csum_partial"]) == (mode != "legacy")
for key, feature in (("tx-checksum-ip-generic", mode != "legacy"),
                     ("tx-tcp-segmentation", mode == "tcpv4")):
    assert next(line for line in features.splitlines() if line.strip().startswith(key + ":")).split()[1] == (
        "on" if feature else "off"), features
for kind, key in (("gro", "dev_rx_gro"), ("gso", "dev_tx_gso")):
    datagrams, segments = (stats[key + "_" + suffix] for suffix in ("datagrams", "segments"))
    if mode == "tcpv4" and direction == kind:
        assert segments > datagrams > 0, stats
    elif mode != "tcpv4":
        assert segments == datagrams == 0, stats
print(json.dumps({"mode": mode, "direction": direction, "bytes": need, "sha256": a["sha256"],
                  **{key: value for key, value in stats.items() if key.startswith("dev_")}}))
PY
    port=$((port + 1))
  done
  ip tuntap del dev utcp0 mode tun "${tun_flags[@]}"
done
CONTAINER
