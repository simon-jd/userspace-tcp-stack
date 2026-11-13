#!/usr/bin/env bash
# m1-backend acceptance tests 3-6 on the M1 testbed (testbed/m1), plus a NAT
# check. Each step prints the commands' output, then a PASS/FAIL line; a
# summary follows. Exit status 1 if any step failed.
#   3  up.sh; from the peer `ping -c 3 198.18.0.2` gets 3 replies from M0's
#      tun_probe --reply on utcp0; utcp0 has txqueuelen 10000 and a pfifo root;
#      the peer reads back tcp_no_metrics_save = 1
#   4  pmtu.sh; backend_tun_tool writes a 1500-byte DF datagram toward the peer
#      and `tcpdump -i utcp0` in the DUT shows the ICMP 3/4 with MTU 1400 coming
#      back; a 1500-byte DF ping from the peer toward the stack gets ICMP 3/4
#      from the router
#   nat  nat.sh; a DNS query from 198.18.0.2 through utcp0 to the host's
#      upstream resolver gets an answer (needs Internet access)
#   5  netem.sh N1..N4 (and N0) shows the qdiscs on both interfaces; combo.sh
#      check starts peers with the 8 SACK/TS/WS settings and tcp_ecn 1 and 3
#   6  down.sh leaves no testbed container or network
#
# Needs: testbed/m1/build.sh gcc-release tun_probe backend_tun_tool
# Usage: tests/interop/backend_testbed.sh
# Environment: UTCP_IMAGE, UTCP_CPUS (testbed/m1/common.sh), UTCP_PRESET
# (default gcc-release: programs in build/tb-$UTCP_PRESET).
set -uo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tb=$repo/testbed/m1
preset=${UTCP_PRESET:-gcc-release}
bin=/utcp/build/tb-$preset
for p in apps/tun_probe/tun_probe tests/interop/backend_tun_tool; do
  [[ -x $repo/build/tb-$preset/$p ]] || {
    echo "missing $repo/build/tb-$preset/$p (testbed/m1/build.sh $preset tun_probe backend_tun_tool)" >&2
    exit 2
  }
done
dut=utcp-m1-dut
peer=utcp-m1-peer
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

summary=()
failed=0
step() {
  echo
  echo "######## $1"
}
verdict() {  # NAME OK(0/1) DETAIL
  if (($2 == 0)); then
    echo "-- $1: PASS ($3)"
    summary+=("$1 PASS: $3")
  else
    echo "-- $1: FAIL ($3)"
    summary+=("$1 FAIL: $3")
    failed=1
  fi
}
has() { grep -qF -- "$2" "$1"; }

# --- 3
step "test 3: up.sh, ping through tun_probe --reply"
"$tb/up.sh" | tee "$tmp/up.log"
up_rc=${PIPESTATUS[0]}
docker exec "$dut" "$bin/apps/tun_probe/tun_probe" --name utcp0 --reply --count 3 \
  --timeout-ms 15000 >"$tmp/probe.log" 2>&1 &
probe=$!
sleep 1
docker exec "$peer" ping -c 3 -W 2 198.18.0.2 | tee "$tmp/ping.log"
wait "$probe"
probe_rc=$?
echo "-- tun_probe output:"
cat "$tmp/probe.log"
ok=1
replies=$(grep -c 'wrote 84 bytes: ICMP echo reply' "$tmp/probe.log")
((up_rc == 0)) && has "$tmp/ping.log" "3 packets transmitted, 3 received" && ((probe_rc == 0)) &&
  ((replies == 3)) && has "$tmp/up.log" "qdisc pfifo state" && has "$tmp/up.log" "qlen 10000" &&
  has "$tmp/up.log" "limit 10000p" && has "$tmp/up.log" "net.ipv4.tcp_no_metrics_save = 1" && ok=0
verdict "test 3" "$ok" "ping 3/3 answered by tun_probe ($replies replies written), utcp0 qlen 10000 + pfifo limit 10000p, peer tcp_no_metrics_save = 1"

# --- 4
step "test 4: pmtu.sh, ICMP 3/4 from the DUT into utcp0 and from the router to the peer"
"$tb/pmtu.sh" up
pmtu_rc=$?
docker exec "$dut" timeout 10 tcpdump -i utcp0 -n -l -v -c 2 >"$tmp/tcpdump.log" 2>&1 &
td=$!
sleep 1.5
docker exec "$dut" "$bin/tests/interop/backend_tun_tool" df --dst 198.19.3.4 --size 1500 | tee "$tmp/df.log"
df_rc=${PIPESTATUS[0]}
wait "$td"
echo "-- tcpdump -i utcp0 -n -v -c 2 in $dut:"
cat "$tmp/tcpdump.log"
echo "-- from $peer: ping -M do -s 1472 -c 1 198.18.0.2"
docker exec "$peer" ping -M do -s 1472 -c 1 -W 2 198.18.0.2 | tee "$tmp/dfping.log"
ok=1
((pmtu_rc == 0 && df_rc == 0)) && has "$tmp/tcpdump.log" "length 1500)" &&
  has "$tmp/tcpdump.log" "198.18.0.1 > 198.18.0.2: ICMP 198.19.3.4 unreachable - need to frag (mtu 1400)" &&
  has "$tmp/dfping.log" "From 198.19.3.3 icmp_seq=1 Frag needed and DF set (mtu = 1400)" && ok=0
verdict "test 4" "$ok" "DUT -> utcp0: ICMP 3/4 mtu 1400 for the 1500-byte DF datagram; router 198.19.3.3 -> peer: Frag needed (mtu = 1400)"
"$tb/pmtu.sh" down

# --- NAT
step "nat: nat.sh, DNS query from the stack's address through utcp0"
"$tb/nat.sh" | tee "$tmp/nat.log"
nat_rc=${PIPESTATUS[0]}
dns=$(docker exec "$dut" cat /run/utcp-m1-dns 2>/dev/null)
docker exec "$dut" "$bin/tests/interop/backend_tun_tool" dns --server "$dns" --name example.com | tee "$tmp/dns.log"
dns_rc=${PIPESTATUS[0]}
ok=1
((nat_rc == 0 && dns_rc == 0)) && ok=0
verdict "nat" "$ok" "masquerade + route to resolver $dns; $(grep -c '^  A ' "$tmp/dns.log") A records for example.com"
"$tb/nat.sh" off

# --- 5
step "test 5: netem.sh N1..N4, N0; combo.sh check"
ok=0
declare -A want=(
  [N1]="delay 1ms loss 1%"
  [N2]="delay 5ms reorder 10% 50%"
  [N3]="delay 1ms duplicate 2%"
  [N4]="delay 2ms loss 1% duplicate 1% reorder 5% 50%")
for p in N1 N2 N3 N4; do
  "$tb/netem.sh" "$p" | tee "$tmp/netem.log"
  rc=${PIPESTATUS[0]}
  n=$(grep -c "^qdisc netem .* limit 20000 ${want[$p]} seed" "$tmp/netem.log")
  if ((rc != 0 || n != 2)); then
    echo "-- $p: expected 2 netem qdiscs with \"${want[$p]}\", found $n"
    ok=1
  fi
done
"$tb/netem.sh" N0 | tee "$tmp/netem.log"
has "$tmp/netem.log" "qdisc pfifo" && has "$tmp/netem.log" "qdisc noqueue" || ok=1
"$tb/combo.sh" check | tee "$tmp/combo.log"
combo_rc=${PIPESTATUS[0]}
((combo_rc == 0)) || ok=1
verdict "test 5" "$ok" "N1-N4 netem on eth0 and utcp0, N0 back to noqueue/pfifo; combo.sh check: $(grep -c '  ok$' "$tmp/combo.log")/10 ok"

# --- 6
step "test 6: down.sh"
"$tb/down.sh"
down_rc=$?
left=$(docker ps -a --format '{{.Names}}' | grep -E '^utcp-m1-(dut|peer|r)$' || true)
left_nets=$(docker network ls --format '{{.Name}}' | grep -E '^utcp-m1-(net|net1400|netb)$' || true)
ok=1
((down_rc == 0)) && [[ -z $left && -z $left_nets ]] && ok=0
verdict "test 6" "$ok" "no utcp-m1-{dut,peer,r} containers, no utcp-m1-{net,net1400,netb} networks"

echo
echo "######## summary"
printf '%s\n' "${summary[@]}"
exit "$failed"
