#!/usr/bin/env bash
# The PMTU chain (DESIGN §11): DUT -- utcp-m1-net1400 (MTU 1400) -- router
# utcp-m1-r -- utcp-m1-netb (MTU 1500) -- peer, on top of up.sh's testbed.
#
#   DUT 198.19.2.2 on utcp-m1-net1400, route 198.19.3.0/24 via the router
#   router 198.19.2.3 / 198.19.3.3, IP forwarding, route 198.18.0.0/24 via the DUT
#   peer 198.19.3.4 on utcp-m1-netb, route 198.18.0.0/24 via the router
#
# The stack's 1500-byte DF datagrams toward the peer's 198.19.3.4 get ICMP
# 3/4 (MTU 1400) from the DUT kernel, back into the TUN; Linux's 1500-byte DF
# datagrams toward the stack get ICMP 3/4 from the router. The router runs on
# the DUT's cpuset unless UTCP_CPUS is set (common.sh). The peer's new
# interface gets tso/gso off, the router's and the DUT's new ones gro off
# (common.sh), as on utcp-m1-net.
#
# Usage: testbed/m1/pmtu.sh [up]   build the chain (up.sh must have run)
#        testbed/m1/pmtu.sh down   remove the router and both networks, and point
#                                  the peer's route back at the DUT
# Environment: UTCP_IMAGE, UTCP_CPUS (common.sh).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

cmd=${1:-up}
case $cmd in
  up)
    tb_running "$tb_dut" || tb_die "$tb_dut is not running (testbed/m1/up.sh)"
    tb_running "$tb_peer" || tb_die "$tb_peer is not running (testbed/m1/up.sh)"
    tb_exists "$tb_router" && tb_die "$tb_router exists (pmtu.sh down first)"
    tb_ensure_network "$tb_net1400" "$tb_net1400_subnet" "$tb_net1400_gw" 1400
    tb_ensure_network "$tb_netb" "$tb_netb_subnet" "$tb_netb_gw"

    docker run -d --name "$tb_router" --hostname "$tb_router" \
      --network "$tb_net1400" --ip "$tb_router_ip1400" \
      --cap-add NET_ADMIN --cpuset-cpus "$tb_cpus" \
      --sysctl net.ipv4.ip_forward=1 \
      "$tb_image" sleep infinity >/dev/null
    docker network connect --ip "$tb_router_ipb" "$tb_netb" "$tb_router"
    docker network connect --ip "$tb_dut_ip1400" "$tb_net1400" "$tb_dut"
    docker network connect --ip "$tb_peer_ipb" "$tb_netb" "$tb_peer"

    tb_offloads "$tb_peer" "$tb_peer_ipb" "${tb_sender_offloads[@]}"
    tb_offloads "$tb_router" "$tb_router_ip1400" "${tb_forward_offloads[@]}"
    tb_offloads "$tb_router" "$tb_router_ipb" "${tb_forward_offloads[@]}"
    tb_offloads "$tb_dut" "$tb_dut_ip1400" "${tb_forward_offloads[@]}"

    tb_exec "$tb_dut" ip route replace "$tb_netb_subnet" via "$tb_router_ip1400"
    tb_exec "$tb_router" ip route replace "$tb_tun_subnet" via "$tb_dut_ip1400"
    tb_exec "$tb_peer" ip route replace "$tb_tun_subnet" via "$tb_router_ipb"
    echo "chain up: $tb_dut $tb_dut_ip1400 -- $tb_net1400 (MTU 1400) -- $tb_router -- $tb_netb -- $tb_peer $tb_peer_ipb (router cpus $tb_cpus)"
    for c in "$tb_dut" "$tb_router" "$tb_peer"; do
      echo "== $c: links with their MTU; ip route"
      tb_exec "$c" ip -o link show | awk '$2 != "lo:" {print $2, $4, $5}'
      tb_exec "$c" ip route
    done
    echo "== offloads (ethtool -k)"
    tb_show_offloads "$tb_peer" "$tb_peer_ipb"
    tb_show_offloads "$tb_router" "$tb_router_ip1400"
    tb_show_offloads "$tb_router" "$tb_router_ipb"
    tb_show_offloads "$tb_dut" "$tb_dut_ip1400"
    ;;
  down)
    if tb_exists "$tb_router"; then
      docker rm -f "$tb_router" >/dev/null
      echo "removed $tb_router"
    fi
    for c in "$tb_dut" "$tb_peer"; do
      for n in "$tb_net1400" "$tb_netb"; do
        if tb_net_exists "$n" && tb_exists "$c" &&
          docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$n" | grep -qw "$c"; then
          docker network disconnect "$n" "$c"
        fi
      done
    done
    if tb_running "$tb_dut"; then
      tb_exec "$tb_dut" ip route del "$tb_netb_subnet" 2>/dev/null || true
    fi
    if tb_running "$tb_peer"; then
      tb_exec "$tb_peer" ip route replace "$tb_tun_subnet" via "$tb_dut_ip"
    fi
    for n in "$tb_net1400" "$tb_netb"; do
      if tb_net_exists "$n"; then
        docker network rm "$n" >/dev/null
        echo "removed network $n"
      fi
    done
    ;;
  -h | --help) sed -n '2,/^source/p' "$0" | sed '$d; s/^# \{0,1\}//' ;;
  *) tb_die "usage: pmtu.sh [up|down]" ;;
esac
