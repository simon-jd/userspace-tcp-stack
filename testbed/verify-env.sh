#!/usr/bin/env bash
# M0 environment checks, run on the Docker host:
#   a. TUN    A container with NET_ADMIN and /dev/net/tun runs apps/tun_probe,
#             which creates a TUN interface (IFF_TUN|IFF_NO_PI). The script
#             gives it 198.18.0.1/24, pings 198.18.0.2 (routed into the
#             interface), and the probe reports the echo requests it read from
#             the fd. The probe also answers them, so ping gets replies.
#   b. qdisc  On the sender's egress: netem (delay 20ms, limit 20000) as root
#             with a tbf child at 10mbit. Ping RTT and iperf3 throughput to a
#             second container.
#   c. BBR    iperf3 -C bbr between two containers; ss -ti on the sender shows
#             bbr as the congestion control.
# Host `lsmod | grep -E 'netem|tbf|bbr'` is printed before and after, to show
# whether the modules were auto-loaded. Containers and the network are named
# utcp-m0-<run>-* and removed on exit.
#
# Pass criteria (fixed before the first run):
#   a. tun_probe exits 0 after reading 3 ICMP echo requests 198.18.0.1 ->
#      198.18.0.2 with valid IPv4 and ICMP checksums, and ping receives 3/3.
#   b. Avg RTT of 20 pings (after an ARP warm-up) in [20.0, 21.0] ms: netem
#      adds 20 ms in one direction and the veth path adds about 0.1 ms. iperf3 receiver goodput in
#      [9.0, 10.0] Mbit/s: tbf counts Ethernet frames, so 1448-byte payloads in
#      1514-byte frames give about 9.56 Mbit/s at 10 Mbit/s.
#   c. iperf3 reports sender_tcp_congestion "bbr", and ss -ti on the sender
#      shows a connection to the server with congestion control "bbr" and a
#      bbr:(...) block.
#
# Usage: testbed/verify-env.sh
# Environment: UTCP_IMAGE (utcp-testbed:dev), UTCP_BUILD_CPUS (16-31, check a
# builds the probe), UTCP_TIMING_CPUS (8-15, checks b and c), UTCP_M0_SUBNET
# (198.19.255.0/24, the Docker network).
set -uo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=${UTCP_IMAGE:-utcp-testbed:dev}
build_cpus=${UTCP_BUILD_CPUS:-16-31}
timing_cpus=${UTCP_TIMING_CPUS:-8-15}
subnet=${UTCP_M0_SUBNET:-198.19.255.0/24}
run=utcp-m0-$(date +%m%d%H%M%S)-$$
net=$run-net
containers=()

cleanup() {
  if ((${#containers[@]} > 0)); then
    docker rm -f "${containers[@]}" >/dev/null 2>&1
  fi
  docker network rm "$net" >/dev/null 2>&1
  echo "cleaned up: ${containers[*]} $net"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

section() { printf '\n===== %s\n' "$*"; }

declare -A status
declare -A summary
result() {  # check PASS|FAIL text
  status[$1]=$2
  summary[$1]=$3
  echo "RESULT $1: $2 - $3"
}

start() {  # name docker-run-args...
  local name=$1
  shift
  containers+=("$name")
  docker run -d --name "$name" --network "$net" "$@" >/dev/null
}

ip_of() {
  docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$1"
}

wait_listen() {  # container port
  docker exec "$1" bash -c "for i in \$(seq 100); do ss -ltn | grep -q ':$2 ' && exit 0; sleep 0.1; done; exit 1"
}

in_range() {  # value lo hi
  awk -v x="$1" -v lo="$2" -v hi="$3" 'BEGIN { exit !(x != "" && x + 0 >= lo && x + 0 <= hi) }'
}

# Busy percentage of each CPU in [lo, hi] over one second, from /proc/stat.
cpu_busy() {
  local a b
  a=$(grep -E '^cpu[0-9]+ ' /proc/stat)
  sleep 1
  b=$(grep -E '^cpu[0-9]+ ' /proc/stat)
  paste -d' ' <(echo "$a") <(echo "$b") | awk -v lo="$1" -v hi="$2" '
    { n = substr($1, 4) + 0
      if (n < lo || n > hi) next
      t1 = 0; for (i = 2; i <= 9; i++) t1 += $i
      t2 = 0; for (i = 13; i <= 20; i++) t2 += $i
      idle = ($16 + $17) - ($5 + $6)
      printf "cpu%d %.0f%%  ", n, (t2 > t1) ? 100 * (1 - idle / (t2 - t1)) : 0 }
    END { print "" }'
}

section "host"
echo "run $run, image $image ($(docker image inspect -f '{{.Id}}' "$image" 2>/dev/null || echo missing))"
echo "kernel $(uname -r)"
uptime
echo "top CPU users:"
ps -eo pid,pcpu,comm --sort=-pcpu | head -6
echo "busy over 1 s on timing CPUs $timing_cpus: $(cpu_busy "${timing_cpus%-*}" "${timing_cpus#*-}")"
echo "lsmod before:"
lsmod | grep -E 'netem|tbf|bbr' || echo "  (none of netem/tbf/bbr loaded)"

if ! docker network create --driver bridge --subnet "$subnet" "$net" >/dev/null; then
  echo "cannot create Docker network $net on $subnet"
  exit 1
fi
echo "network $net ($subnet)"

# ---------------------------------------------------------------- a. TUN
check_tun() {
  section "a. TUN"
  local c=$run-tun
  start "$c" --cap-add NET_ADMIN --device /dev/net/tun --cpuset-cpus "$build_cpus" \
    -v "$repo:/src:ro" "$image" sleep infinity
  echo "building tun_probe in $c (cpus $build_cpus)"
  if ! docker exec "$c" bash -c '
      nice -n 10 cmake -S /src -B /tmp/build -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_COMPILER=g++-15 -DUTCP_BUILD_TESTS=OFF >/tmp/build.log 2>&1 &&
      nice -n 10 cmake --build /tmp/build --target tun_probe -j8 >>/tmp/build.log 2>&1'; then
    docker exec "$c" tail -40 /tmp/build.log
    result a FAIL "tun_probe did not build"
    return
  fi

  docker exec -d "$c" bash -c '/tmp/build/apps/tun_probe/tun_probe --name utcp0 --count 3 \
    --timeout-ms 15000 --reply >/tmp/probe.log 2>&1; echo $? >/tmp/probe.rc'
  if ! docker exec "$c" bash -c 'for i in $(seq 100); do ip link show utcp0 >/dev/null 2>&1 && exit 0
                                   [ -f /tmp/probe.rc ] && exit 1; sleep 0.1; done; exit 1'; then
    docker exec "$c" cat /tmp/probe.log
    result a FAIL "TUN interface utcp0 did not appear"
    return
  fi
  echo "\$ ip addr add 198.18.0.1/24 dev utcp0; ip link set utcp0 up"
  docker exec "$c" bash -c 'ip addr add 198.18.0.1/24 dev utcp0 && ip link set utcp0 up' 2>&1
  echo "\$ ip -d link show utcp0"
  docker exec "$c" ip -d link show utcp0
  echo "\$ ip route get 198.18.0.2"
  docker exec "$c" ip route get 198.18.0.2
  echo "\$ ping -c 3 -i 0.2 -W 2 198.18.0.2"
  local ping_out
  ping_out=$(docker exec "$c" ping -c 3 -i 0.2 -W 2 198.18.0.2 2>&1)
  echo "$ping_out"
  docker exec "$c" bash -c 'for i in $(seq 200); do [ -f /tmp/probe.rc ] && exit 0; sleep 0.1; done; exit 1'
  local rc probe_log n_req n_rx
  rc=$(docker exec "$c" cat /tmp/probe.rc 2>/dev/null)
  probe_log=$(docker exec "$c" cat /tmp/probe.log)
  echo "tun_probe output (exit ${rc:-none}):"
  echo "$probe_log"
  n_req=$(grep -cE 'IPv4 198\.18\.0\.1 -> 198\.18\.0\.2 proto 1 .*header-checksum ok; ICMP echo request .* checksum ok' <<<"$probe_log")
  n_rx=$(sed -nE 's/.* ([0-9]+) received.*/\1/p' <<<"$ping_out")
  if [[ $rc == 0 && $n_req -ge 3 && ${n_rx:-0} == 3 ]]; then
    result a PASS "tun_probe read $n_req ICMP echo requests from the TUN fd (checksums ok); ping got $n_rx/3 replies"
  else
    result a FAIL "probe exit ${rc:-none}, echo requests read ${n_req:-0}, ping replies ${n_rx:-0}/3"
  fi
}

# ---------------------------------------------------------------- b. netem + tbf
check_qdisc() {
  section "b. netem + tbf"
  local r=$run-qrecv s=$run-qsend rip
  start "$r" --cpuset-cpus "$timing_cpus" "$image" iperf3 -s
  start "$s" --cap-add NET_ADMIN --cpuset-cpus "$timing_cpus" "$image" sleep infinity
  rip=$(ip_of "$r")
  wait_listen "$r" 5201
  echo "sender $s ($(ip_of "$s")) -> receiver $r ($rip), cpus $timing_cpus"
  local tc_cmds='tc qdisc replace dev eth0 root handle 1: netem delay 20ms limit 20000 &&
                 tc qdisc add dev eth0 parent 1:1 handle 10: tbf rate 10mbit burst 16kb limit 64kb'
  echo "\$ $(tr -s ' \n' ' ' <<<"$tc_cmds")"
  if ! docker exec "$s" bash -c "$tc_cmds" 2>&1; then
    result b FAIL "tc could not add netem/tbf (see error above)"
    return
  fi
  docker exec "$s" tc qdisc show dev eth0
  echo "sender offloads: $(docker exec "$s" ethtool -k eth0 | grep -E '^(tcp|generic)-segmentation-offload' | tr -s '\n' ' ')"

  # Resolve ARP first: otherwise the first echo request waits for an ARP
  # reply that itself crosses netem, and measures 2 x 20 ms.
  echo "\$ ping -c 2 -i 0.2 $rip   (ARP warm-up, not measured)"
  docker exec "$s" ping -c 2 -i 0.2 -q "$rip" | tail -1
  docker exec "$s" ip neigh show dev eth0
  echo "\$ ping -c 20 -i 0.2 $rip"
  local ping_out rtt
  ping_out=$(docker exec "$s" ping -c 20 -i 0.2 "$rip" 2>&1)
  echo "$ping_out" | sed -n '2,$p'
  rtt=$(sed -nE 's#^rtt min/avg/max/mdev = [0-9.]+/([0-9.]+)/.*#\1#p' <<<"$ping_out")

  echo "\$ iperf3 -c $rip -t 10 -O 2 -J"
  local mbps
  docker exec "$s" bash -c "iperf3 -c $rip -t 10 -O 2 -J >/tmp/iperf.json"
  mbps=$(docker exec "$s" python3 -c '
import json
d = json.load(open("/tmp/iperf.json"))
if "error" in d:
    print("error:", d["error"]); raise SystemExit
e = d["end"]
print("%.3f" % (e["sum_received"]["bits_per_second"] / 1e6))
print("sender %.3f Mbit/s, retransmits %s, receiver %.3f Mbit/s over %.1f s (first 2 s omitted)" % (
    e["sum_sent"]["bits_per_second"] / 1e6, e["sum_sent"].get("retransmits"),
    e["sum_received"]["bits_per_second"] / 1e6, e["sum_received"]["seconds"]))')
  tail -n +2 <<<"$mbps"
  mbps=$(head -1 <<<"$mbps")

  echo "\$ tc -s qdisc show dev eth0"
  docker exec "$s" tc -s qdisc show dev eth0

  if in_range "$rtt" 20.0 21.0 && in_range "$mbps" 9.0 10.0; then
    result b PASS "ping avg RTT $rtt ms (want 20.0-21.0), iperf3 receiver $mbps Mbit/s (want 9.0-10.0)"
  else
    result b FAIL "ping avg RTT ${rtt:-none} ms (want 20.0-21.0), iperf3 receiver ${mbps:-none} Mbit/s (want 9.0-10.0)"
  fi
}

# ---------------------------------------------------------------- c. BBR
check_bbr() {
  section "c. BBR"
  local r=$run-bbrrecv s=$run-bbrsend rip
  start "$r" --cpuset-cpus "$timing_cpus" "$image" iperf3 -s
  start "$s" --cap-add NET_ADMIN --cpuset-cpus "$timing_cpus" "$image" sleep infinity
  rip=$(ip_of "$r")
  wait_listen "$r" 5201
  echo "sender $s ($(ip_of "$s")) -> receiver $r ($rip), cpus $timing_cpus"
  echo "sender sysctl before: $(docker exec "$s" sysctl -n net.ipv4.tcp_available_congestion_control)" \
       "(available), default $(docker exec "$s" sysctl -n net.ipv4.tcp_congestion_control)"
  echo "\$ iperf3 -c $rip -C bbr -t 5 -J & sleep 2; ss -tin dst $rip"
  local ss_out cc
  ss_out=$(docker exec "$s" bash -c "iperf3 -c $rip -C bbr -t 5 -J >/tmp/bbr.json 2>&1 & pid=\$!
                                     sleep 2; ss -tin dst $rip; wait \$pid")
  echo "$ss_out"
  cc=$(docker exec "$s" python3 -c '
import json
d = json.load(open("/tmp/bbr.json"))
if "error" in d:
    print("error:", d["error"]); raise SystemExit
e = d["end"]
print(e.get("sender_tcp_congestion"))
print("iperf3: sender_tcp_congestion %s, receiver_tcp_congestion %s, %.0f Mbit/s, retransmits %s" % (
    e.get("sender_tcp_congestion"), e.get("receiver_tcp_congestion"),
    e["sum_received"]["bits_per_second"] / 1e6, e["sum_sent"].get("retransmits")))')
  tail -n +2 <<<"$cc"
  cc=$(head -1 <<<"$cc")
  echo "sender sysctl after: $(docker exec "$s" sysctl -n net.ipv4.tcp_available_congestion_control) (available)"

  local n_bbr
  n_bbr=$(grep -cE '^[[:space:]]+bbr .*bbr:\(' <<<"$ss_out")
  if [[ $cc == bbr && $n_bbr -ge 1 ]]; then
    result c PASS "iperf3 sender_tcp_congestion bbr; ss -ti shows $n_bbr connection(s) to $rip using bbr with bbr:(...) info"
  else
    result c FAIL "iperf3 sender_tcp_congestion '${cc:-none}', ss connections showing bbr: ${n_bbr:-0}"
  fi
}

check_tun
check_qdisc
check_bbr

section "modules"
echo "lsmod after:"
lsmod | grep -E 'netem|tbf|bbr' || echo "  (none of netem/tbf/bbr loaded)"

section "summary"
passed=0
for k in a b c; do
  echo "$k: ${status[$k]:-FAIL} - ${summary[$k]:-not run}"
  [[ ${status[$k]:-} == PASS ]] && passed=$((passed + 1))
done
echo "verify-env: $passed/3 PASS"
((passed == 3))
