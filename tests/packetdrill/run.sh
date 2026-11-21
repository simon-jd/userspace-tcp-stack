#!/usr/bin/env bash
# Run the nonblocking IPv4 cases with the unmodified, pinned Packetdrill.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
root="$PWD"
mode=${1:-}
if (( $# > 1 )) || [[ -n "$mode" && "$mode" != "--upstream-ordinary" ]]; then
  echo "Usage: $0 [--upstream-ordinary]" >&2
  exit 2
fi
container_options=()
if [[ "$mode" == "--upstream-ordinary" ]]; then
  container_options=(--read-only --security-opt no-new-privileges)
fi
cpus="${UTCP_PACKETDRILL_CPUS:-30,31}"
image="${UTCP_PACKETDRILL_IMAGE:-utcp-testbed:dev}"
revision=15ab46aedd01a5e664ec5cfb2b1888328cdd3901
work=build/packetdrill
upstream="$work/upstream"
packetdrill="$upstream/gtests/net/packetdrill"
core_build=build/m3-packetdrill-core
mkdir -p "$work/receipts"
logs="$(mktemp -d "$work/receipts/run-XXXXXXXX")"

if [[ ! -x "$packetdrill/packetdrill" ]] ||
   [[ "$(git -C "$upstream" rev-parse HEAD)" != "$revision" ]] ||
   ! git -C "$upstream" diff --quiet HEAD; then
  echo "Build the pinned Packetdrill checkout first. See docs/results/m3-packetdrill/README.md." >&2
  exit 1
fi

image_id="$(docker image inspect "$image" --format '{{.Id}}')"
limited=(taskset -c "$cpus" nice -n 10)
"${limited[@]}" cmake --preset gcc-debug -B "$core_build" -DCMAKE_POSITION_INDEPENDENT_CODE=ON
"${limited[@]}" cmake --build "$core_build" --target utcp_core -j2
"${limited[@]}" g++-15 -std=c++23 -g -D_GLIBCXX_ASSERTIONS -Wall -Wextra -Wpedantic \
  -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wimplicit-fallthrough -Wformat=2 -Werror \
  -fvisibility=hidden -fPIC -shared -isystem "$packetdrill" -Iinclude \
  tests/packetdrill/adapter.cpp "$core_build/src/core/libutcp_core.a" \
  -Wl,--exclude-libs,ALL -Wl,-z,defs -o "$work/utcp_packetdrill.so"

{
  printf 'stack=%s\npacketdrill=%s\ncpus=%s\n' "$(git rev-parse HEAD)" "$revision" "$cpus"
  printf 'container_image=%s\n' "$image_id"
  uname -rm
  g++-15 -dumpfullversion
  sha256sum "$packetdrill/packetdrill" "$packetdrill/packetdrill.h" "$work/utcp_packetdrill.so"
  readelf --wide --dyn-syms "$work/utcp_packetdrill.so" | awk '/ packetdrill_interface_init$/'
} >"$logs/tools.txt"

run_packetdrill() {
  local script="$1" dir="${2:-/work}"
  "${limited[@]}" docker run --pull never --rm --name "utcp-m3-packetdrill-$$" --network none --cap-drop ALL \
    --cpuset-cpus "$cpus" --ulimit memlock=67108864:67108864 --user "$(id -u):$(id -g)" \
    "${container_options[@]}" --mount "type=bind,src=$root,dst=/work,readonly" --workdir "$dir" "$image_id" \
    /usr/bin/timeout 8s /usr/bin/nice -n 10 "/work/$packetdrill/packetdrill" \
    --ip_version=ipv4 --local_ip=192.0.2.2 --remote_ip=198.51.100.2 \
    --so_filename="/work/$work/utcp_packetdrill.so" --so_flags=192.0.2.2 \
    --strict_segments --tolerance_usecs=1000 --tolerance_percent=0 -v "${@:3}" "$script"
}

check_log() {
  local pattern="$1" log="$2"
  if ! grep -Eq "$pattern" "$log"; then
    echo "Missing expected result in $log ($pattern)" >&2
    cat "$log" >&2
    exit 1
  fi
}

for iteration in 1 2; do
  active="$logs/active-$iteration.log"
  passive="$logs/passive-$iteration.log"
  for kind in active passive; do
    log="$logs/$kind-$iteration.log"
    if ! run_packetdrill "tests/packetdrill/$kind-open.pkt" >"$log" 2>&1; then
      cat "$log" >&2
      exit 1
    fi
    check_log '^utcp-packetdrill initialized$' "$log"
    check_log '^utcp-packetdrill state=established ' "$log"
  done
  check_log '^utcp-packetdrill write=5$' "$active"
  check_log '^utcp-packetdrill state=time_wait ' "$active"
  check_log '^utcp-packetdrill rx=4 tx=5 sleeps=[1-9][0-9]* clock_reads=[1-9][0-9]* regressions=0 fds=0 tcp_slots=0 time_wait=1 queued=0$' "$active"
  check_log '^utcp-packetdrill read=4 nonzero=0$' "$passive"
  check_log '^utcp-packetdrill timer=delack ' "$passive"
  check_log '^utcp-packetdrill read=0 nonzero=0$' "$passive"
  check_log '^utcp-packetdrill state=last_ack ' "$passive"
  check_log '^utcp-packetdrill rx=6 tx=4 sleeps=[1-9][0-9]* clock_reads=[1-9][0-9]* regressions=0 fds=0 tcp_slots=0 time_wait=0 queued=0$' "$passive"
  printf 'run %s: active open and passive open passed\n' "$iteration"
done

if [[ "$mode" == "--upstream-ordinary" ]]; then
  family="$upstream/gtests/net/tcp"
  close_case=close/close-local-close-then-remote-fin.pkt
  candidates=(blocking/blocking-{accept,connect,read,write}.pkt "$close_case" nagle/https_client.pkt)
  for candidate in "${candidates[@]}"; do
    dir="/work/$family/${candidate%/*}"
    name=${candidate##*/}
    sha256sum "$family/$candidate" >>"$logs/upstream.sha256"
    status=0
    run_packetdrill "$name" "$dir" --dry_run >"$logs/$name.parse.log" 2>&1 || status=$?
    printf 'parse\t%s\t%s\n' "$candidate" "$status" | tee -a "$logs/upstream.tsv"
    if (( status != 0 )); then
      cat "$logs/$name.parse.log" >&2
      exit 1
    fi
  done

  # Exercise one ordinary original through its Linux preamble in the restricted container.
  name=${close_case##*/}
  status=0
  run_packetdrill "$name" "/work/$family/close" >"$logs/$name.live.log" 2>&1 || status=$?
  printf 'execute\t%s\t%s\n' "$close_case" "$status" | tee -a "$logs/upstream.tsv"
  if (( status == 1 )); then
    check_log '^utcp-packetdrill initialized$' "$logs/$name.live.log"
    check_log 'setting key "net.ipv4.tcp_rmem".*Read-only file system' "$logs/$name.live.log"
    check_log 'Cannot find device "tun0"' "$logs/$name.live.log"
    check_log 'error executing init command: non-zero status 1' "$logs/$name.live.log"
    echo "Upstream close case stopped in Linux initialization, before handshake."
  elif (( status == 0 )); then
    check_log '^utcp-packetdrill state=established ' "$logs/$name.live.log"
    echo "Upstream close case ran to completion."
  else
    cat "$logs/$name.live.log" >&2
    exit 1
  fi
  printf 'Receipts: %s\n' "$logs"
  exit 0
fi

sed 's/^+0 > \. 1:1(0) ack 1$/+0 > . 1:1(0) ack 2/' tests/packetdrill/active-open.pkt \
  >"$logs/bad-expected-ack.pkt"
{
  cat tests/packetdrill/active-open.pkt
  printf '+0 > . 7:7(0) ack 2\n'
} >"$logs/missing-egress.pkt"

for kind in bad-expected-ack missing-egress; do
  log="$logs/$kind.log"
  status=0
  run_packetdrill "$logs/$kind.pkt" >"$log" 2>&1 || status=$?
  if [[ "$status" != 1 ]]; then
    echo "$kind returned $status, expected an assertion exit of 1" >&2
    cat "$log" >&2
    exit 1
  fi
  printf '%s: rejected with exit %s\n' "$kind" "$status"
done
check_log 'tcp_ack_seq: expected: 2 .* vs actual: 1' "$logs/bad-expected-ack.log"
check_log 'no fitting datagram within transmit wait' "$logs/missing-egress.log"
check_log 'IP header overflows packet: packet of 0 bytes' "$logs/missing-egress.log"

if [[ -n "$(docker ps -a --filter "name=^/utcp-m3-packetdrill-$$$" --format '{{.Names}}')" ]]; then
  echo 'Packetdrill container still exists after --rm' >&2
  exit 1
fi
printf 'Receipts: %s\n' "$logs"
