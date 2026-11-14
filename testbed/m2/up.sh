#!/usr/bin/env bash
# Starts slot N of the M2 comparison testbed (DESIGN §14, common.sh has the
# topology): networks a, b, c; containers snd, r1, r2, rcv with their
# addresses, static routes (no default route, so nothing bypasses the
# routers), sysctls, offloads and cpusets; in snd the TUN interfaces
# utcp0..utcp7 (MTU 1500, txqueuelen 10000, root qdisc pfifo limit 10000).
#
#   snd: tso off, gso off on eth0, whose qdisc stays noqueue; IP forwarding
#        between eth0 and the TUNs; tcp_wmem max 64 MB; tcp_no_metrics_save.
#   r1, r2: gro off on both interfaces; no qdisc until shape.sh.
#   rcv: gro off; tcp_no_metrics_save; tcp_rmem left at the default.
#   every container runs with --init, so processes the scripts start and stop
#   (tcpdump, ping, the drop watcher) are reaped.
#   neighbours: permanent ARP entries between adjacent hops (no ARP on the
#           path, none through netem).
#   routes: snd -> nets b, c via r1; r1 -> net c via r2, 198.18.8N.0/21 via
#           snd; r2 -> net a and the stack via r1; rcv -> nets a, b and the
#           stack via r2.
#
# Prints the state record.sh would print for the slot's interfaces.
#
# Usage: testbed/m2/up.sh --slot N [--nontiming]
#   --slot N       slot index (0, 1: timing slots on CPUs 8-11 and 12-15;
#                  2-9: non-timing instances on 16-31)
#   --nontiming    put every container on CPUs 16-31 also for slots 0 and 1
# Environment: UTCP_M2_PREFIX (default utcp-m2), UTCP_IMAGE (default
# utcp-testbed:dev), UTCP_DATA_VOLUME (default utcp-data).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if [[ ${1:-} == -h || ${1:-} == --help ]]; then m2_help "$0"; exit 0; fi
m2_parse_slot "$@"
((${#m2_args[@]} == 0)) || tb_die "unknown argument ${m2_args[0]} (see --help)"

for c in "${m2_containers[@]}"; do
  tb_exists "$c" && tb_die "container $c exists; run testbed/m2/down.sh --slot $m2_n first"
done
docker image inspect "$tb_image" >/dev/null 2>&1 || tb_die "image $tb_image not found"
docker volume inspect "$m2_volume" >/dev/null 2>&1 || tb_die "volume $m2_volume not found"

echo "slot $m2_n: image $tb_image ($(docker image inspect -f '{{.Id}}' "$tb_image"))"
echo "cpus: snd $m2_cpus_snd, rcv $m2_cpus_rcv, r1 and r2 $m2_cpus_router"
tb_ensure_network "$m2_net_a" "$m2_subnet_a" "$m2_gw_a"
tb_ensure_network "$m2_net_b" "$m2_subnet_b" "$m2_gw_b"
tb_ensure_network "$m2_net_c" "$m2_subnet_c" "$m2_gw_c"

# run NAME NET IP CPUS SYSCTL_ARRAY_NAME [EXTRA_ARGS...]
run() {
  local name=$1 net=$2 ip=$3 cpus=$4 arr=$5
  shift 5
  local -n sysctls=$arr
  local args=() s
  for s in "${sysctls[@]}"; do args+=(--sysctl "$s"); done
  docker run -d --init --name "$name" --hostname "$name" \
    --network "$net" --ip "$ip" \
    --cap-add NET_ADMIN --cpuset-cpus "$cpus" \
    "${args[@]}" "$@" \
    -v "$tb_repo:/utcp:ro" -v "$m2_volume:/data" \
    "$tb_image" sleep infinity >/dev/null
}

run "$m2_snd" "$m2_net_a" "$m2_snd_ip" "$m2_cpus_snd" m2_snd_sysctls --device /dev/net/tun
run "$m2_r1" "$m2_net_a" "$m2_r1_ip_a" "$m2_cpus_router" m2_router_sysctls
docker network connect --ip "$m2_r1_ip_b" "$m2_net_b" "$m2_r1"
run "$m2_r2" "$m2_net_b" "$m2_r2_ip_b" "$m2_cpus_router" m2_router_sysctls
docker network connect --ip "$m2_r2_ip_c" "$m2_net_c" "$m2_r2"
run "$m2_rcv" "$m2_net_c" "$m2_rcv_ip" "$m2_cpus_rcv" m2_rcv_sysctls

tun_setup=""
for ((k = 0; k < m2_ntun; ++k)); do
  tun_setup+="
    ip tuntap add dev $(m2_tun $k) mode tun
    ip addr add $(m2_tun_kernel_ip $k)/24 dev $(m2_tun $k)
    ip link set dev $(m2_tun $k) mtu $m2_mtu txqueuelen $m2_tun_txqueuelen up
    tc qdisc replace dev $(m2_tun $k) root pfifo limit $m2_tun_txqueuelen"
done
tb_sh "$m2_snd" "
  ip route del default
  ip route add $m2_subnet_b via $m2_r1_ip_a
  ip route add $m2_subnet_c via $m2_r1_ip_a
  $tun_setup
"
tb_sh "$m2_r1" "
  ip route del default
  ip route add $m2_subnet_c via $m2_r2_ip_b
  ip route add $m2_stack_net via $m2_snd_ip
"
tb_sh "$m2_r2" "
  ip route del default
  ip route add $m2_subnet_a via $m2_r1_ip_b
  ip route add $m2_stack_net via $m2_r1_ip_b
"
tb_sh "$m2_rcv" "
  ip route del default
  ip route add $m2_subnet_a via $m2_r2_ip_c
  ip route add $m2_subnet_b via $m2_r2_ip_c
  ip route add $m2_stack_net via $m2_r2_ip_c
"

# Permanent neighbour entries between the hops: no ARP crosses netem (an ARP
# packet would take a draw from netem's PRNG, shifting the seeded loss
# sequence, and could itself be lost or delayed).
mac() { docker exec "$1" cat "/sys/class/net/$(tb_ifname "$1" "$2")/address"; }
neigh() {  # neigh CONTAINER OWN_IP PEER_CONTAINER PEER_IP
  tb_exec "$1" ip neigh replace "$4" lladdr "$(mac "$3" "$4")" dev "$(tb_ifname "$1" "$2")" nud permanent
}
neigh "$m2_snd" "$m2_snd_ip" "$m2_r1" "$m2_r1_ip_a"
neigh "$m2_r1" "$m2_r1_ip_a" "$m2_snd" "$m2_snd_ip"
neigh "$m2_r1" "$m2_r1_ip_b" "$m2_r2" "$m2_r2_ip_b"
neigh "$m2_r2" "$m2_r2_ip_b" "$m2_r1" "$m2_r1_ip_b"
neigh "$m2_r2" "$m2_r2_ip_c" "$m2_rcv" "$m2_rcv_ip"
neigh "$m2_rcv" "$m2_rcv_ip" "$m2_r2" "$m2_r2_ip_c"

tb_offloads "$m2_snd" "$m2_snd_ip" "${tb_sender_offloads[@]}"
tb_offloads "$m2_r1" "$m2_r1_ip_a" "${tb_forward_offloads[@]}"
tb_offloads "$m2_r1" "$m2_r1_ip_b" "${tb_forward_offloads[@]}"
tb_offloads "$m2_r2" "$m2_r2_ip_b" "${tb_forward_offloads[@]}"
tb_offloads "$m2_r2" "$m2_r2_ip_c" "${tb_forward_offloads[@]}"
tb_offloads "$m2_rcv" "$m2_rcv_ip" "${tb_forward_offloads[@]}"

for c in "${m2_containers[@]}"; do
  echo "started $c (cpus $(docker container inspect -f '{{.HostConfig.CpusetCpus}}' "$c"))"
done
echo
"$m2_dir/record.sh" --slot "$m2_n" --brief up
