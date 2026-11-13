#!/usr/bin/env bash
# m1-backend test 2: the EventLoop's wake-up lateness, a timing run. Runs
# backend_lateness (10 000 waits on 1 ms deadlines) in a container pinned to
# the timing CPUs, once without --spin-us and once per value in --spin-us,
# and records the machine's load before and after: uptime, the busy share of
# each timing CPU over 2 s (/proc/stat), the top CPU users and the threads
# that last ran on the timing CPUs. There is no pass threshold; the numbers
# are the result.
#
# Needs: testbed/m1/build.sh gcc-release backend_lateness
# Usage: tests/interop/backend_lateness.sh [--count N] [--spin-us "US..."]
#   --count N        waits per run (default 10000)
#   --spin-us "LIST" extra runs with these --spin-us values (default "50")
# Environment: UTCP_IMAGE (default utcp-testbed:dev), UTCP_TIMING_CPUS
# (default 8-15), UTCP_PRESET (default gcc-release).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
image=${UTCP_IMAGE:-utcp-testbed:dev}
cpus=${UTCP_TIMING_CPUS:-8-15}
preset=${UTCP_PRESET:-gcc-release}
name=utcp-m1-backend-lateness
count=10000
spins="50"
while (($# > 0)); do
  case $1 in
    --count) count=${2:?}; shift 2 ;;
    --spin-us) spins=${2?}; shift 2 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
prog=build/tb-$preset/tests/interop/backend_lateness
[[ -x $repo/$prog ]] || { echo "missing $repo/$prog (testbed/m1/build.sh $preset backend_lateness)" >&2; exit 2; }
[[ $cpus =~ ^([0-9]+)-([0-9]+)$ ]] || { echo "UTCP_TIMING_CPUS must be a range A-B" >&2; exit 2; }
lo=${BASH_REMATCH[1]}
hi=${BASH_REMATCH[2]}

cpu_snapshot() {
  awk -v lo="$lo" -v hi="$hi" '$1 ~ /^cpu[0-9]+$/ {
      n = substr($1, 4) + 0
      if (n >= lo && n <= hi) print $1, $2+$3+$4+$5+$6+$7+$8+$9, $5+$6
    }' /proc/stat
}

record_load() {
  echo "== $1: uptime"
  uptime
  echo "== $1: busy share of CPUs $cpus over 2 s"
  local a b
  a=$(cpu_snapshot)
  sleep 2
  b=$(cpu_snapshot)
  paste -d' ' <(echo "$a") <(echo "$b") |
    awk '{t = $5 - $2; i = $6 - $3; printf "%s %.1f%%  ", $1, (t > 0 ? 100 * (t - i) / t : 0)} END {print ""}'
  echo "== $1: top CPU users (ps, CPU share over each process's lifetime)"
  ps -eo pid,psr,pcpu,etime,comm --sort=-pcpu | head -11
  echo "== $1: threads that last ran on CPUs $cpus with pcpu > 0"
  ps -eLo pid,tid,psr,pcpu,comm --sort=-pcpu |
    awk -v lo="$lo" -v hi="$hi" 'NR == 1 || ($3 >= lo && $3 <= hi && $4 > 0)' | head -15
}

docker image inspect "$image" >/dev/null
echo "image $image ($(docker image inspect -f '{{.Id}}' "$image")), container cpus $cpus, $count waits of 1 ms"
record_load before
for spin in 0 $spins; do
  echo
  echo "== run: --spin-us $spin"
  docker run --rm --name "$name" --cpuset-cpus "$cpus" -v "$repo:/utcp:ro" "$image" \
    "/utcp/$prog" --count "$count" --period-us 1000 --spin-us "$spin" --label "spin-us $spin"
done
echo
record_load after
