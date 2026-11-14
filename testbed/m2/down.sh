#!/usr/bin/env bash
# Removes slot N of the M2 testbed: containers ${prefix}-sN-{snd,r1,r2,rcv}
# and networks ${prefix}-sN-{a,b,c}, then checks that none of them is left.
# Only these names are removed; other utcp-* objects are listed, not touched.
# Exit status 1 if one of the slot's containers or networks remains.
#
# Usage: testbed/m2/down.sh --slot N
# Environment: UTCP_M2_PREFIX (default utcp-m2).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if [[ ${1:-} == -h || ${1:-} == --help ]]; then m2_help "$0"; exit 0; fi
m2_parse_slot "$@"
((${#m2_args[@]} == 0)) || tb_die "unknown argument ${m2_args[0]} (see --help)"

for c in "${m2_containers[@]}"; do
  if tb_exists "$c"; then
    docker rm -f "$c" >/dev/null
    echo "removed container $c"
  fi
done
for n in "${m2_networks[@]}"; do
  if tb_net_exists "$n"; then
    docker network rm "$n" >/dev/null
    echo "removed network $n"
  fi
done

left=0
for c in "${m2_containers[@]}"; do
  if tb_exists "$c"; then echo "container $c is still there" >&2; left=1; fi
done
for n in "${m2_networks[@]}"; do
  if tb_net_exists "$n"; then echo "network $n is still there" >&2; left=1; fi
done
echo "slot $m2_n containers and networks left: $( ((left)) && echo some || echo none)"
echo "utcp-* containers now: $(docker ps -a --format '{{.Names}}' | grep '^utcp-' | sort | tr '\n' ' ')"
echo "utcp-* networks now: $(docker network ls --format '{{.Name}}' | grep '^utcp-' | sort | tr '\n' ' ')"
exit "$left"
