#!/usr/bin/env bash
# Removes the M1 testbed: containers <prefix>-dut, <prefix>-peer, <prefix>-r and
# networks <prefix>-net, <prefix>-net1400, <prefix>-netb (prefix UTCP_TB_PREFIX,
# default utcp-m1; common.sh), then checks that none of them is left. Only these
# names are removed; other <prefix>-* objects (e.g. utcp-m1-apps-*) are listed,
# not touched.
# Exit status 1 if a testbed container or network remains.
#
# Usage: testbed/m1/down.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
  sed -n '2,/^source/p' "$0" | sed '$d; s/^# \{0,1\}//'
  exit 0
fi

for c in "${tb_containers[@]}"; do
  if tb_exists "$c"; then
    docker rm -f "$c" >/dev/null
    echo "removed container $c"
  fi
done
for n in "${tb_networks[@]}"; do
  if tb_net_exists "$n"; then
    docker network rm "$n" >/dev/null
    echo "removed network $n"
  fi
done

left=0
for c in "${tb_containers[@]}"; do
  if tb_exists "$c"; then
    echo "container $c is still there" >&2
    left=1
  fi
done
for n in "${tb_networks[@]}"; do
  if tb_net_exists "$n"; then
    echo "network $n is still there" >&2
    left=1
  fi
done

others=$(docker ps -a --format '{{.Names}}' | awk -v p="$tb_prefix-" 'index($0, p) == 1' || true)
other_nets=$(docker network ls --format '{{.Name}}' | awk -v p="$tb_prefix-" 'index($0, p) == 1' || true)
echo "testbed containers and networks left: $( ((left)) && echo some || echo none)"
echo "$tb_prefix-* containers now: ${others:-none}"
echo "$tb_prefix-* networks now: ${other_nets:-none}"
exit "$left"
