#!/usr/bin/env bash
# Checks of the M2 testbed scripts (M2-TASKS m2d-testbed tests 1 and 2,
# DESIGN §14) on slot N, which must be down when the script starts:
#   up:     up.sh creates exactly ${prefix}-sN-{snd,r1,r2,rcv} and networks
#           ${prefix}-sN-{a,b,c} with the subnets, addresses, routes (no
#           default route), cpusets and sysctls of common.sh;
#   record: record.sh prints qdiscs, offloads, gso_ipv4_max_size, rx/tx drops,
#           softnet, bridge-nf; sender eth0 noqueue with tso and gso off; every
#           utcp* pfifo limit 10000; gro off on the routers and the receiver;
#   shape:  shape.sh for all 8 (bandwidth, RTT, queue) combinations, each also
#           with 0.1 % and 1 % loss and a seed: tc -s shows netem limit 20000,
#           the delay, loss and seed on r1's b side only, tbf rate, burst B
#           and limit Q on r2's c side only, nothing on the reverse direction;
#   seed:   2000 pings through 10 % loss with seed 1234 twice lose the same
#           icmp_seq set; seed 1235 loses a different one;
#   down:   down.sh removes exactly the slot's containers and networks.
# Prints "ok"/"FAIL" per check; exit 1 if any failed.
#
# Usage: tests/interop/m2_testbed.sh --slot N [--nontiming] [--keep]
#   --keep  leave the slot up at the end (default: down.sh)
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tbdir=$here/../../testbed/m2
slot="" nontiming=() keep=0
while (($# > 0)); do
  case $1 in
    --slot) slot=$2; shift 2 ;;
    --nontiming) nontiming=(--nontiming); shift ;;
    --keep) keep=1; shift ;;
    -h | --help) sed -n '2,/^set -uo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n $slot ]] || { echo "--slot N is required" >&2; exit 2; }
# shellcheck source=../../testbed/m2/common.sh
source "$tbdir/common.sh"
set +e
m2_slot "$slot" "${#nontiming[@]}"
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
expect() { if [[ $2 == "$3" ]]; then ok "$1"; else bad "$1: expected '$3', got '$2'"; fi; }

# Other testbed slots (helper containers of other tasks come and go by
# themselves); one collation for sort and comm.
export LC_ALL=C
others_before=$(docker ps -a --format '{{.Names}}' | grep "^$m2_prefix-s[0-9]-" | grep -v "^$m2_base-" | sort)
nets_before=$(docker network ls --format '{{.Name}}' | grep "^$m2_prefix-s[0-9]-" | grep -v "^$m2_base-" | sort)

# --- up
"$tbdir/up.sh" --slot "$slot" "${nontiming[@]}" >/tmp/m2_testbed_up.$$ 2>&1 || { cat /tmp/m2_testbed_up.$$; bad "up.sh failed"; exit 1; }
rm -f /tmp/m2_testbed_up.$$
expect "containers" "$(docker ps --format '{{.Names}}' | grep "^$m2_base-" | sort | tr '\n' ' ')" \
  "$(printf '%s\n' "${m2_containers[@]}" | sort | tr '\n' ' ')"
for i in 0 1 2; do
  n=${m2_networks[$i]}
  want=$([[ $i == 0 ]] && echo "$m2_subnet_a" || ([[ $i == 1 ]] && echo "$m2_subnet_b" || echo "$m2_subnet_c"))
  expect "network $n" "$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$n" 2>/dev/null)" "$want"
done
expect "slot networks" "$(docker network ls --format '{{.Name}}' | grep "^$m2_base-" | sort | tr '\n' ' ')" \
  "$(printf '%s\n' "${m2_networks[@]}" | sort | tr '\n' ' ')"
addrs() { docker exec "$1" ip -o -4 addr show | awk '$2 != "lo" {print $4}' | sort | tr '\n' ' '; }
expect "snd addresses" "$(addrs "$m2_snd" | tr ' ' '\n' | grep -v '^198\.18\.' | tr '\n' ' ')" "$m2_snd_ip/24 "
expect "snd TUN addresses" "$(addrs "$m2_snd" | tr ' ' '\n' | grep -c '^198\.18\.')" 8
expect "r1 addresses" "$(addrs "$m2_r1")" "$(printf '%s\n' "$m2_r1_ip_a/24" "$m2_r1_ip_b/24" | sort | tr '\n' ' ')"
expect "r2 addresses" "$(addrs "$m2_r2")" "$(printf '%s\n' "$m2_r2_ip_b/24" "$m2_r2_ip_c/24" | sort | tr '\n' ' ')"
expect "rcv addresses" "$(addrs "$m2_rcv")" "$m2_rcv_ip/24 "
for k in 0 7; do
  expect "utcp$k address" "$(docker exec "$m2_snd" ip -o -4 addr show dev "utcp$k" | awk '{print $4}')" \
    "$(m2_tun_kernel_ip $k)/24"
done
for c in "${m2_containers[@]}"; do
  expect "$c no default route" "$(docker exec "$c" ip route show default | wc -l)" 0
done
via() { docker exec "$1" ip -o route get "$2" | sed -n 's/.* via \([0-9.]*\) .*/\1/p'; }
expect "snd -> rcv via r1" "$(via "$m2_snd" "$m2_rcv_ip")" "$m2_r1_ip_a"
expect "r1 -> rcv via r2" "$(via "$m2_r1" "$m2_rcv_ip")" "$m2_r2_ip_b"
expect "r1 -> stack via snd" "$(via "$m2_r1" "$(m2_tun_stack_ip 3)")" "$m2_snd_ip"
expect "r2 -> stack via r1" "$(via "$m2_r2" "$(m2_tun_stack_ip 0)")" "$m2_r1_ip_b"
expect "r2 -> snd via r1" "$(via "$m2_r2" "$m2_snd_ip")" "$m2_r1_ip_b"
expect "rcv -> stack via r2" "$(via "$m2_rcv" "$(m2_tun_stack_ip 7)")" "$m2_r2_ip_c"
expect "rcv -> snd via r2" "$(via "$m2_rcv" "$m2_snd_ip")" "$m2_r2_ip_c"
cpus() { docker container inspect -f '{{.HostConfig.CpusetCpus}}' "$1"; }
expect "snd cpuset" "$(cpus "$m2_snd")" "$m2_cpus_snd"
expect "rcv cpuset" "$(cpus "$m2_rcv")" "$m2_cpus_rcv"
expect "r1 cpuset" "$(cpus "$m2_r1")" "$m2_cpus_router"
expect "r2 cpuset" "$(cpus "$m2_r2")" "$m2_cpus_router"
expect "snd tcp_wmem" "$(docker exec "$m2_snd" sysctl -n net.ipv4.tcp_wmem | tr -s '\t ' ' ')" "4096 16384 67108864"
expect "snd no_metrics_save" "$(docker exec "$m2_snd" sysctl -n net.ipv4.tcp_no_metrics_save)" 1
expect "rcv no_metrics_save" "$(docker exec "$m2_rcv" sysctl -n net.ipv4.tcp_no_metrics_save)" 1
expect "rcv tcp_rmem" "$(docker exec "$m2_rcv" sysctl -n net.ipv4.tcp_rmem | tr -s '\t ' ' ')" "4096 131072 33554432"
for c in "${m2_containers[@]}"; do
  expect "$c neighbours permanent" "$(docker exec "$c" ip neigh show nud permanent | wc -l)" \
    "$([[ $c == "$m2_r1" || $c == "$m2_r2" ]] && echo 2 || echo 1)"
done
expect "ping snd -> rcv" "$(docker exec "$m2_snd" ping -c 1 -W 2 "$m2_rcv_ip" >/dev/null && echo ok)" ok

# --- record
rec=$("$tbdir/record.sh" --slot "$slot" check)
for c in "${m2_containers[@]}"; do
  for what in "ip -s -d link" "tc -s -raw qdisc" offloads sysctl cpuset; do
    grep -qx "== $c $what" <<<"$rec" && ok "record: $c $what" || bad "record: no '== $c $what'"
  done
done
for what in "uname -r" softnet_stat bridge-nf "module parameters" /proc/stat /proc/softirqs uptime top "threads on 8-15"; do
  grep -qx "== host $what" <<<"$rec" && ok "record: host $what" || bad "record: no '== host $what'"
done
for c in "$m2_snd" "$m2_rcv"; do
  grep -qx "== $c nstat -asz" <<<"$rec" && ok "record: $c nstat" || bad "record: no nstat for $c"
done
section() { awk -v h="== $1 $2" '$0 == h {on = 1; next} /^== / {on = 0} on' <<<"$rec"; }
grep -q 'gso_ipv4_max_size [0-9]' <<<"$(section "$m2_snd" "ip -s -d link")" && ok "record: gso_ipv4_max_size" \
  || bad "record: no gso_ipv4_max_size"
grep -q 'RX: *bytes packets errors dropped' <<<"$(section "$m2_r1" "ip -s -d link")" && ok "record: drops" \
  || bad "record: no rx/tx drop counters"
snd_eth=$(m2_if_snd)
grep -q "^qdisc noqueue .* dev $snd_eth root" <<<"$(section "$m2_snd" "tc -s -raw qdisc")" \
  && ok "sender $snd_eth noqueue" || bad "sender $snd_eth not noqueue"
expect "sender offloads" "$(section "$m2_snd" offloads | grep "^$snd_eth:" | awk '{print $2, $3, $4, $5}')" \
  "tso off gso off"
expect "utcp* pfifo limit 10000" "$(section "$m2_snd" "tc -s -raw qdisc" | grep -c '^qdisc pfifo .* dev utcp[0-7] root .*limit 10000p')" 8
expect "utcp* txqueuelen 10000" "$(section "$m2_snd" "ip -s -d link" | grep -E '^[0-9]+: utcp[0-7]:' | grep -c 'qlen 10000')" 8
for c in "$m2_r1" "$m2_r2" "$m2_rcv"; do
  expect "$c gro off" "$(section "$c" offloads | grep -v '^lo:' | grep -vc 'gro off')" 0
done

# --- shape
q_of() { awk -v b="$1" -v r="$2" -v x="$3" 'BEGIN {printf "%d", b * 1000000 * r / 8000 * x}'; }
for bw in 10 100; do
  for rtt in 20 100; do
    for qx in 2 0.5; do
      for loss in 0 0.1 1; do
        seed=$((bw * 1000 + rtt * 10 + ${loss/./}))
        args=(--bw "$bw" --rtt "$rtt" --queue-bdp "$qx")
        [[ $loss != 0 ]] && args+=(--loss "$loss" --seed "$seed")
        out=$("$tbdir/shape.sh" --slot "$slot" "${args[@]}") || { bad "shape.sh ${args[*]}"; continue; }
        q=$(q_of "$bw" "$rtt" "$qx")
        b=$((bw * 125)); ((b >= 3028)) || b=3028
        r1b=$(awk -v h="== $m2_r1 $(m2_if_r1_b) tc -s -raw qdisc" '$0 == h {getline; print}' <<<"$out")
        r2c=$(awk -v h="== $m2_r2 $(m2_if_r2_c) tc -s -raw qdisc" '$0 == h {getline; print}' <<<"$out")
        r1a=$(awk -v h="== $m2_r1 $(m2_if_r1_a) tc -s -raw qdisc" '$0 == h {getline; print}' <<<"$out")
        r2b=$(awk -v h="== $m2_r2 $(m2_if_r2_b) tc -s -raw qdisc" '$0 == h {getline; print}' <<<"$out")
        want_netem="limit 20000 delay ${rtt}ms"
        [[ $loss != 0 ]] && want_netem+=" loss ${loss}% seed $seed"
        name="shape $bw Mbit/s $rtt ms ${qx}xBDP loss $loss"
        if [[ $r1b == "qdisc netem "*" root "*"$want_netem"* && $r2c == "qdisc tbf "*"rate ${bw}Mbit burst ${b}b "*"limit ${q}b"* \
              && $r1a == "qdisc noqueue "* && $r2b == "qdisc noqueue "* ]]; then
          ok "$name (Q $q B, B $b B)"
        else
          bad "$name: r1b '$r1b' r2c '$r2c' r1a '$r1a' r2b '$r2b'"
        fi
      done
    done
  done
done

# --- seed: the same seed drops the same packets
lost_set() {
  "$tbdir/shape.sh" --slot "$slot" --bw 100 --rtt 20 --queue-bdp 2 --loss 10 --seed "$1" >/dev/null
  docker exec "$m2_snd" ping -n -i 0.002 -c 2000 -W 1 "$m2_rcv_ip" 2>/dev/null |
    sed -n 's/.*icmp_seq=\([0-9]*\) .*/\1/p' | sort -n |
    awk 'BEGIN {for (i = 1; i <= 2000; i++) seen[i] = 0} {seen[$1] = 1} END {for (i = 1; i <= 2000; i++) if (!seen[i]) print i}' |
    tr '\n' ' '
}
a=$(lost_set 1234) b=$(lost_set 1234) c=$(lost_set 1235)
na=$(wc -w <<<"$a")
if [[ $a == "$b" && $na -gt 100 && $na -lt 320 ]]; then ok "seed 1234 twice: the same $na pings lost"; else bad "seed 1234: run 1 lost $na, runs differ: $([[ $a == "$b" ]] && echo no || echo yes)"; fi
if [[ $a != "$c" ]]; then ok "seed 1235 loses other pings ($(wc -w <<<"$c"))"; else bad "seed 1235 lost the same pings"; fi
"$tbdir/shape.sh" --slot "$slot" --clear >/dev/null

# --- down
if ((!keep)); then
  "$tbdir/down.sh" --slot "$slot" >/dev/null || bad "down.sh exit status"
  expect "down: slot containers" "$(docker ps -a --format '{{.Names}}' | grep -c "^$m2_base-")" 0
  expect "down: slot networks" "$(docker network ls --format '{{.Name}}' | grep -c "^$m2_base-")" 0
  # Containers of other tasks may come and go meanwhile; none may be removed by
  # down.sh, which only names the slot's own.
  others_after=$(docker ps -a --format '{{.Names}}' | grep "^$m2_prefix-s[0-9]-" | grep -v "^$m2_base-" | sort)
  gone=$(comm -23 <(echo "$others_before") <(echo "$others_after") | tr '\n' ' ')
  [[ -z ${gone// /} ]] && ok "down: other testbed slots' containers untouched" || bad "down: other slots' containers gone: $gone"
  nets_after=$(docker network ls --format '{{.Name}}' | grep "^$m2_prefix-s[0-9]-" | grep -v "^$m2_base-" | sort)
  gone=$(comm -23 <(echo "$nets_before") <(echo "$nets_after") | tr '\n' ' ')
  [[ -z ${gone// /} ]] && ok "down: other testbed slots' networks untouched" || bad "down: other slots' networks gone: $gone"
fi
echo "m2_testbed slot $slot: $( ((fail)) && echo FAIL || echo PASS)"
exit "$fail"
