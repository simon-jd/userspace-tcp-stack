#!/usr/bin/env bash
# m1-backend test 7 (needs the m1-ip Stack; with the link stub nothing is
# answered): backend_udp_echo, a UDP echo server on UtcpTransport, runs on
# utcp0 in the DUT with --pcap. From the peer, `ping -c 3 198.18.0.2` gets
# replies from the stack (no tun_probe runs) and `nc -u` sends 100
# datagrams, each echoed unchanged. Then the server is stopped with SIGINT and
# prints its counters, and tcpdump reads its pcap file. Brings the testbed up
# and down itself (testbed/m1/up.sh, down.sh).
#
# Needs: testbed/m1/build.sh gcc-release backend_udp_echo
# Usage: tests/interop/backend_udp_echo.sh
# Environment: UTCP_IMAGE, UTCP_CPUS (testbed/m1/common.sh), UTCP_PRESET
# (default gcc-release).
set -uo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tb=$repo/testbed/m1
preset=${UTCP_PRESET:-gcc-release}
prog=build/tb-$preset/tests/interop/backend_udp_echo
[[ -x $repo/$prog ]] || { echo "missing $repo/$prog (testbed/m1/build.sh $preset backend_udp_echo)" >&2; exit 2; }
dut=utcp-m1-dut
peer=utcp-m1-peer
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$tb/up.sh" || exit 1
docker exec "$dut" "/utcp/$prog" --port 7 --pcap /tmp/backend_udp_echo.pcap >"$tmp/echo.log" 2>&1 &
echo_pid=$!
for _ in $(seq 50); do
  grep -q '^listening on' "$tmp/echo.log" && break
  sleep 0.1
done
cat "$tmp/echo.log"

echo "== processes named tun_probe in $dut: $(docker exec "$dut" pgrep -c tun_probe || true)"
echo "== $peer: ping -c 3 198.18.0.2"
docker exec "$peer" ping -c 3 -W 2 198.18.0.2 | tee "$tmp/ping.log"

echo "== $peer: 100 datagrams with nc -u to 198.18.0.2:7"
for i in $(seq 1 100); do printf 'datagram %03d from the peer\n' "$i"; done >"$tmp/sent.txt"
docker exec -i "$peer" bash -c '
  while IFS= read -r line; do printf "%s\n" "$line"; sleep 0.01; done |
    nc -u -w 2 198.18.0.2 7' <"$tmp/sent.txt" >"$tmp/received.txt"
echo "sent $(wc -l <"$tmp/sent.txt") lines, received $(wc -l <"$tmp/received.txt") lines"

# -f: the process name is cut to 15 characters ("backend_udp_ech").
docker exec "$dut" pkill -INT -f "/utcp/$prog"
wait "$echo_pid"
echo_rc=$?
echo "== backend_udp_echo exit status $echo_rc, summary:"
tail -1 "$tmp/echo.log" | tee "$tmp/summary.json"
echo "== tcpdump -r of its pcap (first 6 records)"
docker exec "$dut" tcpdump -r /tmp/backend_udp_echo.pcap -n -tttt 2>&1 | head -6

ok=1
summary=$(cat "$tmp/summary.json")
if grep -qF "3 packets transmitted, 3 received" "$tmp/ping.log" &&
  cmp -s "$tmp/sent.txt" "$tmp/received.txt" &&
  [[ $summary == *'"echoed":100,'* && $summary =~ \"IcmpOutEchoReps\":3[,}] ]] &&
  ((echo_rc == 0)); then
  ok=0
fi
"$tb/down.sh"
if ((ok == 0)); then
  echo "-- test 7: PASS (ping 3/3 answered by the stack, 100/100 datagrams echoed unchanged)"
else
  echo "-- test 7: FAIL"
fi
exit "$ok"
