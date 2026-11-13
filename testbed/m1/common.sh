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
#
# Environment:
#   UTCP_IMAGE  image for every container (default utcp-testbed:dev)
#   UTCP_CPUS   --cpuset-cpus of every container (default 16-31; 8-15 for timing runs)
# The repository is mounted read-only at /utcp in the DUT and the peer, so
# programs built with testbed/m1/build.sh are at /utcp/build/tb-<preset>/.

set -euo pipefail

tb_repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tb_image=${UTCP_IMAGE:-utcp-testbed:dev}
tb_cpus=${UTCP_CPUS:-16-31}

tb_dut=utcp-m1-dut
tb_peer=utcp-m1-peer
tb_router=utcp-m1-r
tb_containers=("$tb_dut" "$tb_peer" "$tb_router")

tb_net=utcp-m1-net
tb_net1400=utcp-m1-net1400
tb_netb=utcp-m1-netb
tb_networks=("$tb_net" "$tb_net1400" "$tb_netb")

tb_net_subnet=198.19.1.0/24
tb_net_gw=198.19.1.1
tb_dut_ip=198.19.1.2
tb_peer_ip=198.19.1.3

tb_net1400_subnet=198.19.2.0/24
tb_net1400_gw=198.19.2.1
tb_dut_ip1400=198.19.2.2
tb_router_ip1400=198.19.2.3

tb_netb_subnet=198.19.3.0/24
tb_netb_gw=198.19.3.1
tb_router_ipb=198.19.3.3
tb_peer_ipb=198.19.3.4

tb_tun=utcp0
tb_tun_kernel=198.18.0.1
tb_tun_stack=198.18.0.2
tb_tun_subnet=198.18.0.0/24
tb_tun_mtu=1500
tb_tun_txqueuelen=10000

# Every peer starts with these (DESIGN §11: cached RTT and reordering would
# seed later runs).
tb_peer_sysctls=(net.ipv4.tcp_no_metrics_save=1)

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

# tb_start_peer [SYSCTL=VALUE...]: starts utcp-m1-peer on utcp-m1-net with
# tb_peer_sysctls plus the given sysctls and a route to the stack's subnet
# via the DUT. Fails if docker (the kernel) rejects a sysctl.
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
  tb_exec "$tb_peer" ip route add "$tb_tun_subnet" via "$tb_dut_ip" || return 1
}
