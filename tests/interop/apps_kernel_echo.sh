#!/usr/bin/env bash
# m1-apps acceptance test 5 (utcp-echo --backend kernel, over loopback in one
# container on CPUs 16-31): 1000 connections x 100 requests, every echoed
# byte verified (50 connections at a time; then with --rate and large
# requests); the UDP mode answers `nc -u`.
# Usage: tests/interop/apps_kernel_echo.sh   (see apps_kernel_common.sh)
source "$(dirname "${BASH_SOURCE[0]}")/apps_kernel_common.sh"
build_apps

run_in_container echo "$container_lib"'
E=$B/apps/utcp-echo/utcp-echo
js() { python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get(sys.argv[2]))" "$1" "$2"; }
$E --backend kernel --listen 7000 > /tmp/tcp.out 2> /tmp/tcp.err &
tpid=$!
$E --backend kernel --listen 7001 --udp > /tmp/udp.out 2> /tmp/udp.err &
upid=$!
wait_port 7000 || fail start "TCP server not listening"
wait_port 7001 udp || fail start "UDP server not listening"

# client NAME ARGS...: runs the client; the summary must say ok with every request.
client() {
  local name=$1; shift
  local out rc; out=$($E --backend kernel --connect 127.0.0.1:7000 "$@" 2>/tmp/cerr); rc=$?
  echo "$out"
  if [[ $rc == 0 && $(js "$out" ok) == True && $(js "$out" requests_ok) == $(js "$out" requests) && $(js "$out" mismatches) == 0 ]]; then
    pass "$name: $(js "$out" requests_ok) requests verified on $(js "$out" connections_ok) connections, p50 $(js "$out" latency_p50_ns) ns, p99 $(js "$out" latency_p99_ns) ns, p999 $(js "$out" latency_p999_ns) ns"
  else fail "$name" "exit $rc: $(cat /tmp/cerr)"; fi
}
client "1000 x 100 x 64 B, concurrency 50" --connections 1000 --count 100 --size 64 --concurrency 50
client "1000 x 100 x 1 B, concurrency 1" --connections 1000 --count 100 --size 1 --concurrency 1
client "20 x 10 x 300000 B, concurrency 4, 200 req/s" --connections 20 --count 10 --size 300000 --concurrency 4 --rate 200

for msg in hello "two words" "$(head -c 1400 /dev/zero | tr "\0" u)"; do
  got=$(printf "%s" "$msg" | timeout 3 nc -u -w1 127.0.0.1 7001 | head -c 2000)
  [[ $got == "$msg" ]] && pass "nc -u echo of ${#msg} bytes" || fail "nc -u" "sent ${#msg} bytes, got ${#got}: ${got:0:40}"
done

kill -TERM $tpid $upid; wait $tpid $upid
cat /tmp/tcp.out /tmp/udp.out
s=$(cat /tmp/tcp.out)
[[ $(js "$s" errors) == 0 ]] && pass "TCP server: $(js "$s" accepted) accepted, $(js "$s" errors) errors" || fail "TCP server" "$s"
' | summarize
