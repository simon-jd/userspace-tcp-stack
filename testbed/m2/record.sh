#!/usr/bin/env bash
# Records the state and counters of slot N (§5.2 of the M2 design, DESIGN
# §14), before and after every run:
#   per container: ip -s -d link (MTU, gso_ipv4_max_size, txqueuelen, rx/tx
#     drops of every interface, the utcp* TUNs included), tc -s qdisc (every
#     interface, -raw so that tbf shows its limit: noqueue, pfifo, netem, tbf
#     with their counters), offloads
#     (tso, gso, gro, lro per interface), routes, cpuset;
#   snd and rcv: the net.ipv4.tcp_* and net.core.* sysctls, nstat -asz;
#   host: uname -r, /proc/net/softnet_stat (one line per CPU, the CPU
#     number in front), the cpu lines of /proc/stat, /proc/softirqs,
#     /proc/sys/net/bridge/bridge-nf-call-{iptables,ip6tables,arptables}
#     ("absent" without br_netfilter), tcp_cubic and tcp_bbr module
#     parameters, uptime, the top CPU users.
# Each section starts with "== <where> <what>"; the first line has the label
# and the UTC time. tools/m2/analyze.py parses this format.
#
# Usage: testbed/m2/record.sh --slot N [--brief] [LABEL] > FILE
#   --brief   without the sysctls, nstat, /proc/softirqs, /proc/stat and the
#             process list (what up.sh prints)
# Environment: UTCP_M2_PREFIX (default utcp-m2).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if [[ ${1:-} == -h || ${1:-} == --help ]]; then m2_help "$0"; exit 0; fi
m2_parse_slot "$@"
brief=0
label=record
for a in "${m2_args[@]}"; do
  case $a in
    --brief) brief=1 ;;
    -*) tb_die "unknown option $a" ;;
    *) label=$a ;;
  esac
done
m2_require_up

echo "# $label slot $m2_n $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

# The per-container part, one docker exec each.
per_container='
  c=$1 brief=$2
  echo "== $c ip -s -d link"
  ip -s -d link show
  echo "== $c tc -s -raw qdisc"
  tc -s -raw qdisc show
  echo "== $c offloads"
  for d in $(ip -o link show | awk -F": " "{split(\$2, a, \"@\"); print a[1]}"); do
    [ "$d" = lo ] && continue
    ethtool -k "$d" 2>/dev/null | awk -v d="$d" -F": " "
      \$1 == \"tcp-segmentation-offload\" {t = \$2}
      \$1 == \"generic-segmentation-offload\" {g = \$2}
      \$1 == \"generic-receive-offload\" {r = \$2}
      \$1 == \"large-receive-offload\" {l = \$2}
      END {print d \": tso \" t \" gso \" g \" gro \" r \" lro \" l}"
  done
  echo "== $c ip route"
  ip route
  if [ "$brief" = 0 ] && [ "$3" = full ]; then
    echo "== $c sysctl"
    sysctl -a 2>/dev/null | grep -E "^net\.(ipv4\.tcp_|core\.)" | sort
    echo "== $c nstat -asz"
    nstat -asz
  fi
'
for c in "${m2_containers[@]}"; do
  full=short
  [[ $c == "$m2_snd" || $c == "$m2_rcv" ]] && full=full
  docker exec "$c" bash -c "$per_container" bash "$c" "$brief" "$full"
  echo "== $c cpuset"
  docker container inspect -f '{{.HostConfig.CpusetCpus}}' "$c"
done

echo "== host uname -r"
uname -r
echo "== host softnet_stat"
# One line per online CPU in CPU order (net/core/net-procfs.c); recent
# kernels add the CPU number as the 13th field. The first column added here is
# the line index.
awk '{print NR - 1, $0}' /proc/net/softnet_stat
echo "== host bridge-nf"
for f in iptables ip6tables arptables; do
  p=/proc/sys/net/bridge/bridge-nf-call-$f
  if [[ -r $p ]]; then echo "bridge-nf-call-$f $(cat "$p")"; else echo "bridge-nf-call-$f absent"; fi
done
echo "== host module parameters"
for m in tcp_cubic tcp_bbr; do
  if [[ -d /sys/module/$m/parameters ]]; then
    for p in /sys/module/$m/parameters/*; do echo "$m.$(basename "$p") $(cat "$p")"; done
  else
    echo "$m not loaded or no parameters"
  fi
done
if ((!brief)); then
  echo "== host /proc/stat"
  grep '^cpu' /proc/stat
  echo "== host /proc/softirqs"
  cat /proc/softirqs
  echo "== host uptime"
  uptime
  echo "== host top"
  ps -eo pid,psr,pcpu,comm --sort=-pcpu | head -15
fi
