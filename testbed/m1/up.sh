#!/usr/bin/env bash
# Starts the M1 interop testbed (DESIGN §11): network utcp-m1-net, the DUT
# utcp-m1-dut with TUN utcp0 and IP forwarding, and the Linux peer
# utcp-m1-peer with a route to the stack's subnet via the DUT.
#
# utcp0 is a persistent TUN interface (ip tuntap), configured here: kernel
# side 198.18.0.1/24, MTU 1500, txqueuelen 10000 (also the size of tun's
# packet ring), root qdisc pfifo limit 10000 (netem.sh replaces it). The
# stack, or M0's tun_probe, attaches to it with TUNSETIFF (IFF_TUN|IFF_NO_PI)
# and uses 198.18.0.2. IPv6 is off in the DUT, so utcp0 carries only IPv4
# (the stack's protocol, DESIGN §1.2). The peer runs with
# net.ipv4.tcp_no_metrics_save=1 and tso/gso off on its interface; the DUT's
# eth0 has gro off (common.sh: netem then acts on single packets in both
# directions).
#
# Usage: testbed/m1/up.sh [--cpus LIST] [--peer-sysctl KEY=VALUE]...
#   --cpus LIST          --cpuset-cpus of both containers (default $UTCP_CPUS or 16-31;
#                        8-15 for timing runs). Later pmtu.sh and combo.sh
#                        containers take the DUT's cpuset unless UTCP_CPUS is set.
#   --peer-sysctl K=V    an extra sysctl for the peer (repeatable; combo.sh uses this)
# Environment: UTCP_IMAGE (default utcp-testbed:dev).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

peer_extra=()
while (($# > 0)); do
  case $1 in
    --cpus) tb_cpus=${2:?--cpus needs a value}; shift 2 ;;
    --peer-sysctl) peer_extra+=("${2:?--peer-sysctl needs a value}"); shift 2 ;;
    -h | --help) sed -n '2,/^source/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) tb_die "unknown argument $1 (see --help)" ;;
  esac
done

for c in "${tb_containers[@]}"; do
  if tb_exists "$c"; then
    tb_die "container $c exists; run testbed/m1/down.sh first"
  fi
done
docker image inspect "$tb_image" >/dev/null 2>&1 || tb_die "image $tb_image not found"

echo "image $tb_image ($(docker image inspect -f '{{.Id}}' "$tb_image")), cpus $tb_cpus"
tb_ensure_network "$tb_net" "$tb_net_subnet" "$tb_net_gw"

docker run -d --name "$tb_dut" --hostname "$tb_dut" \
  --network "$tb_net" --ip "$tb_dut_ip" \
  --cap-add NET_ADMIN --device /dev/net/tun --cpuset-cpus "$tb_cpus" \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 --sysctl net.ipv6.conf.default.disable_ipv6=1 \
  -v "$tb_repo:/utcp:ro" \
  "$tb_image" sleep infinity >/dev/null
tb_sh "$tb_dut" "
  ip tuntap add dev $tb_tun mode tun
  ip addr add $tb_tun_kernel/24 dev $tb_tun
  ip link set dev $tb_tun mtu $tb_tun_mtu txqueuelen $tb_tun_txqueuelen up
  tc qdisc replace dev $tb_tun root pfifo limit $tb_tun_txqueuelen
"
tb_offloads "$tb_dut" "$tb_dut_ip" "${tb_forward_offloads[@]}"
echo "started $tb_dut ($tb_dut_ip, $tb_tun $tb_tun_kernel/24, stack $tb_tun_stack)"

tb_start_peer "${peer_extra[@]}"
echo "started $tb_peer ($tb_peer_ip, route $tb_tun_subnet via $tb_dut_ip)"

echo
echo "== $tb_dut: ip link show $tb_tun; tc qdisc show dev $tb_tun; ip route; forwarding"
tb_sh "$tb_dut" "
  ip link show $tb_tun
  tc qdisc show dev $tb_tun
  ip route
  sysctl net.ipv4.ip_forward
"
echo "== $tb_peer: sysctls read back; ip route; ip tcp_metrics show"
peer_keys=()
for s in "${tb_peer_sysctls[@]}" "${peer_extra[@]}"; do
  peer_keys+=("${s%%=*}")
done
tb_exec "$tb_peer" sysctl "${peer_keys[@]}"
tb_exec "$tb_peer" ip route
echo "tcp_metrics entries: $(tb_exec "$tb_peer" ip tcp_metrics show | wc -l)"
echo "== offloads (ethtool -k)"
tb_show_offloads "$tb_peer" "$tb_peer_ip"
tb_show_offloads "$tb_dut" "$tb_dut_ip"
