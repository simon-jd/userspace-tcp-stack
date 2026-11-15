# Shared settings and helpers of the M1 interop testbed (DESIGN §11). Sourced
# by the scripts in this directory, not run on its own.
#
# Topology (up.sh):
#   utcp-m1-peer 198.19.1.3 --- utcp-m1-net 198.19.1.0/24 --- 198.19.1.2 eth0 utcp-m1-dut
#   DUT: TUN utcp0, kernel side 198.18.0.1/24, the stack is 198.18.0.2;
#        IP forwarding on; the peer routes 198.18.0.0/24 via the DUT.
# PMTU chain (pmtu.sh):
#   DUT 198.19.2.2 --- utcp-m1-net1400 198.19.2.0/24 (MTU 1400) --- 198.19.2.3 utcp-m1-r
#   utcp-m1-r 198.19.3.3 --- utcp-m1-netb 198.19.3.0/24 (MTU 1500) --- 198.19.3.4 peer
#
# The testbed creates only the containers and networks named below, and
# down.sh removes exactly these. Other tasks' utcp-* objects are never touched.
# The names and subnets above are the defaults; UTCP_TB_PREFIX and
# UTCP_TB_NET_BASE give another task its own copy (M2-TASKS "M1 testbed per
# task"): containers and networks <prefix>-dut, <prefix>-net, ... and subnets
# 198.19.<base>, <base+1>, <base+2>. The TUN side (198.18.0.0/24) is local to
# each DUT and the peer's route to it, so it stays the same.
#
# Environment:
#   UTCP_TB_PREFIX    name prefix of every container and network (default
#                     utcp-m1; M2 tasks use utcp-m2-<task>)
#   UTCP_TB_NET_BASE  third octet of the first subnet, 1-253 (default 1:
#                     198.19.1-3; M2-TASKS assigns m2a 20, m2b-cc 24,
#                     m2b-rate-pacing 28, m2-integrate 32)
#   UTCP_IMAGE  image for every container (default utcp-testbed:dev)
#   UTCP_CPUS   --cpuset-cpus of every container started (8-15 for timing
#               runs). Unset: the running DUT's cpuset (so pmtu.sh's router and
#               combo.sh's peers follow `up.sh --cpus`), else 16-31.
#
# Segmentation offloads (DESIGN §11; PLAN 2d turns them off on the sender):
# Linux TCP always builds GSO super-packets (up to 64 KB). A veth with TSO
# passes them on whole, the forwarding DUT keeps them whole, and TUN without
# IFF_VNET_HDR splits them only after utcp0's qdisc, so netem would drop,
# duplicate and reorder bursts of about 24 segments in the Linux -> stack
# direction while the stack -> Linux direction is per packet. So every Linux
# sender interface gets tso and gso off (the kernel splits before the veth)
# and every forwarding interface gro off (nothing merges them again); a
# qdisc then counts packets (pfifo limit 10000, netem limit 20000).
# The repository is mounted read-only at /utcp in the DUT and the peer, so
# programs built with testbed/m1/build.sh are at /utcp/build/tb-<preset>/.

set -euo pipefail

tb_repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tb_image=${UTCP_IMAGE:-utcp-testbed:dev}

tb_prefix=${UTCP_TB_PREFIX:-utcp-m1}
[[ $tb_prefix =~ ^utcp-[a-z0-9][a-z0-9.-]*$ ]] ||
  { echo "UTCP_TB_PREFIX must match utcp-[a-z0-9][a-z0-9.-]*, not '$tb_prefix'" >&2; exit 1; }
tb_net_base=${UTCP_TB_NET_BASE:-1}
[[ $tb_net_base =~ ^[0-9]+$ ]] && ((tb_net_base >= 1 && tb_net_base <= 253)) ||
  { echo "UTCP_TB_NET_BASE must be 1-253, not '$tb_net_base'" >&2; exit 1; }
tb_o1=$tb_net_base
tb_o2=$((tb_net_base + 1))
tb_o3=$((tb_net_base + 2))

tb_dut=$tb_prefix-dut
tb_peer=$tb_prefix-peer
tb_router=$tb_prefix-r
tb_containers=("$tb_dut" "$tb_peer" "$tb_router")

tb_net=$tb_prefix-net
tb_net1400=$tb_prefix-net1400
tb_netb=$tb_prefix-netb
tb_networks=("$tb_net" "$tb_net1400" "$tb_netb")

tb_net_subnet=198.19.$tb_o1.0/24
tb_net_gw=198.19.$tb_o1.1
tb_dut_ip=198.19.$tb_o1.2
tb_peer_ip=198.19.$tb_o1.3

tb_net1400_subnet=198.19.$tb_o2.0/24
tb_net1400_gw=198.19.$tb_o2.1
tb_dut_ip1400=198.19.$tb_o2.2
tb_router_ip1400=198.19.$tb_o2.3

tb_netb_subnet=198.19.$tb_o3.0/24
tb_netb_gw=198.19.$tb_o3.1
tb_router_ipb=198.19.$tb_o3.3
tb_peer_ipb=198.19.$tb_o3.4

tb_tun=utcp0
tb_tun_kernel=198.18.0.1
tb_tun_stack=198.18.0.2
tb_tun_subnet=198.18.0.0/24
tb_tun_mtu=1500
tb_tun_txqueuelen=10000

# Every peer starts with these (DESIGN §11: cached RTT and reordering would
# seed later runs).
tb_peer_sysctls=(net.ipv4.tcp_no_metrics_save=1)

# ethtool -K settings (see the offload note above).
tb_sender_offloads=(tso off gso off)
tb_forward_offloads=(gro off)

if [[ -n ${UTCP_CPUS:-} ]]; then
  tb_cpus=$UTCP_CPUS
else
  tb_cpus=$(docker container inspect -f '{{.HostConfig.CpusetCpus}}' "$tb_dut" 2>/dev/null || true)
  tb_cpus=${tb_cpus:-16-31}
fi

tb_die() {
  echo "$(basename "$0"): $*" >&2
  exit 1
}

tb_exists() { docker container inspect "$1" >/dev/null 2>&1; }
tb_running() { [[ $(docker container inspect -f '{{.State.Running}}' "$1" 2>/dev/null) == true ]]; }
tb_net_exists() { docker network inspect "$1" >/dev/null 2>&1; }

# Runs a command in a container, as root.
tb_exec() {
  local c=$1
  shift
  docker exec "$c" "$@"
}

# tb_sh CONTAINER SCRIPT: runs a bash script in a container, as root.
tb_sh() {
  docker exec "$1" bash -euo pipefail -c "$2"
}

# tb_ensure_network NAME SUBNET GATEWAY [MTU]
tb_ensure_network() {
  local name=$1 subnet=$2 gw=$3 mtu=${4:-}
  if tb_net_exists "$name"; then
    local have
    have=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$name")
    [[ $have == "$subnet" ]] || tb_die "network $name exists with subnet $have, not $subnet"
    return
  fi
  local args=(--driver bridge --subnet "$subnet" --gateway "$gw")
  if [[ -n $mtu ]]; then
    args+=(--opt "com.docker.network.driver.mtu=$mtu")
  fi
  docker network create "${args[@]}" "$name" >/dev/null
  echo "network $name $subnet${mtu:+ mtu $mtu}"
}

# The interface of container $1 that holds address $2.
tb_ifname() {
  docker exec "$1" ip -o -4 addr show | awk -v a="$2" '{split($4, p, "/"); if (p[1] == a) print $2}'
}

# tb_offloads CONTAINER ADDRESS SETTING...: ethtool -K on the interface of
# CONTAINER that holds ADDRESS (tb_sender_offloads or tb_forward_offloads).
tb_offloads() {
  local c=$1 addr=$2
  shift 2
  local dev
  dev=$(tb_ifname "$c" "$addr")
  [[ -n $dev ]] || { echo "no interface with $addr in $c" >&2; return 1; }
  docker exec "$c" ethtool -K "$dev" "$@" >/dev/null
}

# tb_show_offloads CONTAINER ADDRESS: one line, e.g. "utcp-m1-peer eth0
# 198.19.1.3: tso off gso off gro off".
tb_show_offloads() {
  local c=$1 addr=$2
  local dev
  dev=$(tb_ifname "$c" "$addr")
  [[ -n $dev ]] || { echo "$c: no interface with $addr"; return 1; }
  echo "$c $dev $addr: $(docker exec "$c" ethtool -k "$dev" | awk -F': ' '
    $1 == "tcp-segmentation-offload" {t = $2}
    $1 == "generic-segmentation-offload" {g = $2}
    $1 == "generic-receive-offload" {r = $2}
    END {print "tso " t " gso " g " gro " r}')"
}

# tb_start_peer [SYSCTL=VALUE...]: starts utcp-m1-peer on utcp-m1-net with
# tb_peer_sysctls plus the given sysctls, tso/gso/gro off on its interface
# and a route to the stack's subnet via the DUT. Fails if docker (the
# kernel) rejects a sysctl.
tb_start_peer() {
  local args=()
  local s
  for s in "${tb_peer_sysctls[@]}" "$@"; do
    args+=(--sysctl "$s")
  done
  docker run -d --name "$tb_peer" --hostname "$tb_peer" \
    --network "$tb_net" --ip "$tb_peer_ip" \
    --cap-add NET_ADMIN --cpuset-cpus "$tb_cpus" \
    "${args[@]}" \
    -v "$tb_repo:/utcp:ro" \
    "$tb_image" sleep infinity >/dev/null || return 1
  tb_offloads "$tb_peer" "$tb_peer_ip" "${tb_sender_offloads[@]}" || return 1
  tb_exec "$tb_peer" ip route add "$tb_tun_subnet" via "$tb_dut_ip" || return 1
}
