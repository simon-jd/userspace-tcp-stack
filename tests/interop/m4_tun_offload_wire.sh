#!/usr/bin/env bash
# Verify segmentation and completed checksums at a Linux peer's veth ingress.
# Usage: m4_tun_offload_wire.sh ARTIFACT_DIR. Build utcp-bulk first.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
out=${1:?Pass a directory for the pcap and logs}
mkdir -p "$out"
bin=/src/build/${UTCP_PRESET:-gcc-release}/apps/utcp-bulk/utcp-bulk
image=${UTCP_IMAGE:-utcp-testbed:dev}
base=${UTCP_M4_WIRE_SUBNET:-88}
net=utcp-m4-tun-wire-$$
dut=$net-dut
peer=$net-peer
dut_ip=198.19.$base.2
peer_ip=198.19.$base.3
stack_ip=198.18.0.2
bytes=4000055
port=5125

docker network create --internal --subnet "198.19.$base.0/24" "$net" >/dev/null
cleanup() {
  docker rm -f "$dut" "$peer" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null
}
trap cleanup EXIT

common=(--rm --network "$net" --cpuset-cpus 16-23 --cap-add NET_ADMIN -v "$repo:/src:ro")
docker run -d "${common[@]}" --name "$dut" --ip "$dut_ip" --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 "$image" sleep 90 >/dev/null
docker run -d "${common[@]}" --name "$peer" --ip "$peer_ip" "$image" sleep 90 >/dev/null
docker exec "$dut" ip tuntap add dev utcp0 mode tun vnet_hdr
docker exec "$dut" ip addr add 198.18.0.1/24 dev utcp0
docker exec "$dut" ip link set utcp0 up
docker exec "$peer" ip route add 198.18.0.0/24 via "$dut_ip"
# Force segmentation and software checksum completion before the capture.
docker exec "$dut" ethtool -K eth0 tso off gso off gro off tx off
docker exec "$peer" ethtool -K eth0 gro off
docker exec "$dut" ethtool -k eth0 >"$out/dut-eth0.features"
docker exec "$peer" ethtool -k eth0 >"$out/peer-eth0.features"

docker exec -d "$peer" bash -c 'echo $$ >/tmp/capture.pid
  exec nice -n 10 tcpdump -p -i eth0 -Q in -U -s 1600 -w /tmp/tx.pcap "host 198.18.0.2 and tcp" 2>/tmp/capture.log'
capture_ready=0
for _ in {1..50}; do
  if docker exec "$peer" grep -q 'listening on' /tmp/capture.log; then capture_ready=1; break; fi
  sleep .04
done
test "$capture_ready" = 1

docker exec "$dut" nice -n 10 timeout 15s "$bin" --backend utcp --tun utcp0 \
  --tun-offload=tcpv4 --listen "$port" --stats /tmp/stack.stats --seed 1 --send \
  --bytes "$bytes" --sample-ms 0 >"$out/dut.json" 2>"$out/dut.err" &
dut_pid=$!
ready=0
for _ in {1..50}; do
  if [[ $(docker exec "$dut" cat /sys/class/net/utcp0/operstate) == up ]]; then ready=1; break; fi
  sleep .04
done
test "$ready" = 1
docker exec "$dut" ethtool -k utcp0 >"$out/dut-tun.features"
docker exec "$peer" nice -n 10 timeout 15s "$bin" --backend kernel \
  --connect "$stack_ip:$port" --bytes "$bytes" --sample-ms 0 >"$out/peer.json" 2>"$out/peer.err"
wait "$dut_pid"
docker exec "$peer" bash -c 'kill -INT "$(cat /tmp/capture.pid)"'
for _ in {1..50}; do
  if docker exec "$peer" grep -q 'packets dropped by kernel' /tmp/capture.log; then break; fi
  sleep .04
done
docker cp "$peer:/tmp/tx.pcap" "$out/tx.pcap"
docker cp "$peer:/tmp/capture.log" "$out/capture.log"
docker cp "$dut:/tmp/stack.stats" "$out/stack.stats"
grep -qx '0 packets dropped by kernel' "$out/capture.log"
docker exec "$peer" nice -n 10 tshark -r /tmp/tx.pcap \
  -o ip.check_checksum:TRUE -o tcp.check_checksum:TRUE \
  -Y "ip.src == $stack_ip and tcp.len > 0" -T fields \
  -e ip.len -e ip.checksum.status -e tcp.checksum.status -e tcp.seq_raw -e tcp.payload \
  >"$out/wire.tsv" 2>"$out/tshark.err"

taskset -c 16-23 nice -n 10 python3 - "$out" "$bytes" <<'PY'
import hashlib
import json
import pathlib
import sys

out, count = pathlib.Path(sys.argv[1]), int(sys.argv[2])
stats = json.loads((out / "stack.stats").read_text())
assert stats["dev_tx_gso_segments"] > stats["dev_tx_gso_datagrams"] > 0, stats
assert stats["dev_tx_errors"] == stats["dev_rx_vnet_drops"] == 0, stats
assert "tx-tcp-segmentation: on" in (out / "dut-tun.features").read_text()
assert "tx-tcp-segmentation: off" in (out / "dut-eth0.features").read_text()

payloads = {}
first = None
frames = 0
for line in (out / "wire.tsv").read_text().splitlines():
    ip_len, ip_checksum, tcp_checksum, seq, payload = line.split("\t")
    assert 40 < int(ip_len) <= 1500, line
    assert ip_checksum == tcp_checksum == "1", line
    seq = int(seq)
    if first is None:
        first = seq
    off = (seq - first) % (1 << 32)
    data = bytes.fromhex(payload.replace(":", ""))
    assert payloads.setdefault(off, data) == data
    frames += 1

sha = hashlib.sha256()
pos = 0
for offset, data in sorted(payloads.items()):
    assert pos == offset, (pos, offset)
    sha.update(data)
    pos += len(data)
assert pos == count and frames >= len(payloads) > 0
for log in ("dut.json", "peer.json"):
    app = json.loads((out / log).read_text())
    assert app["bytes"] == pos and app["sha256"] == sha.hexdigest(), app
print(json.dumps({"wire_frames": frames, "unique_segments": len(payloads), "bytes": pos,
                  "sha256": sha.hexdigest(), "gso_datagrams": stats["dev_tx_gso_datagrams"],
                  "gso_segments": stats["dev_tx_gso_segments"]}))
PY
