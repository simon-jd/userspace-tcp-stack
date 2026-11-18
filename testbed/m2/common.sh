# Shared settings and helpers of the M2 comparison testbed (DESIGN §14).
# Sourced by the scripts in this directory, not run on its own. It sources
# testbed/m1/common.sh for the generic helpers (tb_exists, tb_ifname,
# tb_offloads, tb_show_offloads, tb_ensure_network, ...); the M1 names it
# defines are not used here.
#
# Topology of slot N (up.sh --slot N):
#
#   snd --(net a)-- r1 --(net b)-- r2 --(net c)-- rcv
#                     netem on r1's b side, tbf on r2's c side
#
#   containers ${prefix}-sN-{snd,r1,r2,rcv}, networks ${prefix}-sN-{a,b,c},
#   prefix = $UTCP_M2_PREFIX (default utcp-m2)
#   net a 198.19.X.0/24: snd .2, r1 .3      X = 10+4N for N = 0, 1 (the timing
#   net b 198.19.X+1.0/24: r1 .3, r2 .4         slots); 40+4(N-2) for N >= 2
#   net c 198.19.X+2.0/24: r2 .4, rcv .5        (non-timing instances)
#   stack: TUN utcp0..utcp7 in snd, kernel side 198.18.(8N+k).1/24, the
#          stack's address 198.18.(8N+k).2 (k = flow index)
#
# Slots ≥ 2 do not use 198.19.(18..32): the M1 testbeds of the M2 tasks take
# 198.19.(base..base+2) with bases 20, 24, 28 and 32 (M2-TASKS).
#
# CPUs (§6): slot 0: snd 8,9, rcv 10, r1 and r2 11; slot 1: 12,13 / 14 / 15;
# slots ≥ 2 and up.sh --nontiming: every container 16-31.
#
# Every container mounts the repository read-only at /utcp (programs built
# with testbed/m1/build.sh are at /utcp/build/tb-<preset>/) and the volume
# $UTCP_DATA_VOLUME (default utcp-data) at /data (run outputs and captures,
# /data/m2/<campaign>/<run>/).

source "$(dirname "${BASH_SOURCE[0]}")/../m1/common.sh"

m2_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
m2_prefix=${UTCP_M2_PREFIX:-utcp-m2}
m2_volume=${UTCP_DATA_VOLUME:-utcp-data}
m2_ntun=8
m2_tun_txqueuelen=10000
m2_mtu=1500
m2_netem_limit=20000

# Sender sysctls (§5.3): tcp_wmem max 64 MB so the Linux sender's buffer never
# limits; no cached metrics between runs. Receiver: tcp_rmem stays at the
# kernel default (4096 131072 33554432), recorded by record.sh.
m2_snd_sysctls=(
  "net.ipv4.ip_forward=1"
  "net.ipv4.tcp_wmem=4096 16384 67108864"
  "net.ipv4.tcp_no_metrics_save=1"
  "net.ipv6.conf.all.disable_ipv6=1"
  "net.ipv6.conf.default.disable_ipv6=1"
)
m2_router_sysctls=(
  "net.ipv4.ip_forward=1"
  "net.ipv6.conf.all.disable_ipv6=1"
  "net.ipv6.conf.default.disable_ipv6=1"
)
m2_rcv_sysctls=(
  "net.ipv4.tcp_no_metrics_save=1"
  "net.ipv6.conf.all.disable_ipv6=1"
  "net.ipv6.conf.default.disable_ipv6=1"
)

# m2_slot N [nontiming]: sets every per-slot name, address and cpuset.
m2_slot() {
  local n=$1 nontiming=${2:-0}
  [[ $n =~ ^[0-9]$ ]] || tb_die "slot must be 0-9, not '$n'"
  m2_n=$n
  m2_base=$m2_prefix-s$n
  m2_snd=$m2_base-snd
  m2_r1=$m2_base-r1
  m2_r2=$m2_base-r2
  m2_rcv=$m2_base-rcv
  m2_containers=("$m2_snd" "$m2_r1" "$m2_r2" "$m2_rcv")
  m2_net_a=$m2_base-a
  m2_net_b=$m2_base-b
  m2_net_c=$m2_base-c
  m2_networks=("$m2_net_a" "$m2_net_b" "$m2_net_c")

  local x
  if ((n < 2)); then x=$((10 + 4 * n)); else x=$((40 + 4 * (n - 2))); fi
  m2_subnet_a=198.19.$x.0/24
  m2_subnet_b=198.19.$((x + 1)).0/24
  m2_subnet_c=198.19.$((x + 2)).0/24
  m2_gw_a=198.19.$x.1
  m2_gw_b=198.19.$((x + 1)).1
  m2_gw_c=198.19.$((x + 2)).1
  m2_snd_ip=198.19.$x.2
  m2_r1_ip_a=198.19.$x.3
  m2_r1_ip_b=198.19.$((x + 1)).3
  m2_r2_ip_b=198.19.$((x + 1)).4
  m2_r2_ip_c=198.19.$((x + 2)).4
  m2_rcv_ip=198.19.$((x + 2)).5
  # The stack's subnets 198.18.(8N+k).0/24, k = 0..7, are one /21.
  m2_stack_net=198.18.$((8 * n)).0/21

  if ((nontiming)) || ((n >= 2)); then
    m2_cpus_snd=16-31 m2_cpus_rcv=16-31 m2_cpus_router=16-31
  elif ((n == 0)); then
    m2_cpus_snd=8,9 m2_cpus_rcv=10 m2_cpus_router=11
  else
    m2_cpus_snd=12,13 m2_cpus_rcv=14 m2_cpus_router=15
  fi
}

# TUN k of the slot: name, kernel-side address, stack address.
m2_tun() { echo "utcp$1"; }
m2_tun_kernel_ip() { echo "198.18.$((8 * m2_n + $1)).1"; }
m2_tun_stack_ip() { echo "198.18.$((8 * m2_n + $1)).2"; }

# Interface names (found by address; docker names them eth0, eth1 by the order
# of the network connections).
m2_if_snd() { tb_ifname "$m2_snd" "$m2_snd_ip"; }
m2_if_r1_a() { tb_ifname "$m2_r1" "$m2_r1_ip_a"; }
m2_if_r1_b() { tb_ifname "$m2_r1" "$m2_r1_ip_b"; }
m2_if_r2_b() { tb_ifname "$m2_r2" "$m2_r2_ip_b"; }
m2_if_r2_c() { tb_ifname "$m2_r2" "$m2_r2_ip_c"; }
m2_if_rcv() { tb_ifname "$m2_rcv" "$m2_rcv_ip"; }

m2_require_up() {
  local c
  for c in "${m2_containers[@]}"; do
    tb_running "$c" || tb_die "$c is not running (testbed/m2/up.sh --slot $m2_n)"
  done
}

# m2_parse_slot "$@": handles --slot N and --nontiming and leaves the other
# arguments in m2_args.
m2_parse_slot() {
  local slot="" nontiming=0
  m2_args=()
  while (($# > 0)); do
    case $1 in
      --slot) slot=${2:?--slot needs a value}; shift 2 ;;
      --nontiming) nontiming=1; shift ;;
      *) m2_args+=("$1"); shift ;;
    esac
  done
  [[ -n $slot ]] || tb_die "--slot N is required"
  m2_slot "$slot" "$nontiming"
}

m2_help() { sed -n '2,/^source/p' "$1" | sed '$d; s/^# \{0,1\}//'; }
