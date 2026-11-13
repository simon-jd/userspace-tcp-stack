#!/usr/bin/env bash
# m1-backend acceptance tests 3-6 on the M1 testbed (testbed/m1), plus a NAT
# check. Each step prints the commands' output, then a PASS/FAIL line; a
# summary follows. Exit status 1 if any step failed.
#   3  up.sh; from the peer `ping -c 3 198.18.0.2` gets 3 replies from M0's
#      tun_probe --reply on utcp0; utcp0 has txqueuelen 10000 and a pfifo root;
#      the peer reads back tcp_no_metrics_save = 1
#   offloads  the peer's interface has tso and gso off, the DUT's eth0 gro
#      off, and a TCP flow from the peer (iperf3 -n 8M to the DUT) reaches the
#      DUT's eth0 as single segments (tcpdump: no payload above 1460 bytes;
#      with TSO on they arrive as GSO packets of up to 64 KB, which netem on
#      utcp0 would drop or duplicate whole)
#   4  pmtu.sh; backend_tun_tool writes a 1500-byte DF datagram toward the peer
#      and `tcpdump -i utcp0` in the DUT shows the ICMP 3/4 with MTU 1400 coming
#      back; a 1500-byte DF ping from the peer toward the stack gets ICMP 3/4
#      from the router
#   transport  backend_transport_check --tun utcp0 in the DUT (UtcpTransport
#      checks over a socketpair, open() refuses a wrong MTU and accepts 1500);
#      with utcp0 down, open() fails with "not running"
#   nat  nat.sh; a DNS query from 198.18.0.2 through utcp0 to the host's
#      upstream resolver gets an answer (needs Internet access); a datagram
#      from 198.18.0.2 to the peer arrives with that source (not
#      masqueraded); `on` and `off` flush the DUT's conntrack entries of
#      198.18.0.2 (needs an image with nftables and conntrack)
#   5  netem.sh N1..N4 (and N0) shows the qdiscs on both interfaces; combo.sh
#      check starts peers with the 8 SACK/TS/WS settings and tcp_ecn 1 and 3
#   6  down.sh leaves no testbed container or network
#
# Needs: testbed/m1/build.sh gcc-release tun_probe backend_tun_tool backend_transport_check backend_udp_echo
# Usage: tests/interop/backend_testbed.sh
# Environment: UTCP_IMAGE, UTCP_CPUS (testbed/m1/common.sh), UTCP_PRESET
# (default gcc-release: programs in build/tb-$UTCP_PRESET).
set -uo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tb=$repo/testbed/m1
preset=${UTCP_PRESET:-gcc-release}
bin=/utcp/build/tb-$preset
for p in apps/tun_probe/tun_probe tests/interop/backend_tun_tool \
  tests/interop/backend_transport_check tests/interop/backend_udp_echo; do
  [[ -x $repo/build/tb-$preset/$p ]] || {
    echo "missing $repo/build/tb-$preset/$p (testbed/m1/build.sh $preset tun_probe backend_tun_tool backend_transport_check backend_udp_echo)" >&2
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

# --- Offloads
step "offloads: the peer's TCP segments reach the DUT one packet at a time"
eth=$(docker exec "$dut" ip -o -4 addr show | awk '$4 ~ /^198\.19\.1\.2\// {print $2}')
docker exec -d "$dut" iperf3 -s -1 -p 5201
docker exec "$dut" timeout 20 tcpdump -i "$eth" -n -q -l -c 1000 \
  'tcp and src host 198.19.1.3 and dst port 5201 and greater 100' >"$tmp/seg.log" 2>&1 &
td=$!
sleep 1.5
docker exec "$peer" iperf3 -c 198.19.1.2 -p 5201 -n 8M | tail -4
wait "$td"
segs=$(grep -c ' tcp [0-9]*$' "$tmp/seg.log")
max_seg=$(awk 'NF >= 2 && $(NF-1) == "tcp" && $NF ~ /^[0-9]+$/ && $NF + 0 > m + 0 {m = $NF} END {print m + 0}' "$tmp/seg.log")
echo "-- tcpdump -i $eth in $dut: $segs data packets from the peer, largest TCP payload $max_seg bytes"
ok=1
grep -q "^$peer [^ ]* 198.19.1.3: tso off gso off" "$tmp/up.log" &&
  grep -q "^$dut [^ ]* 198.19.1.2: .* gro off" "$tmp/up.log" &&
  ((segs > 100 && max_seg > 0 && max_seg <= 1460)) && ok=0
verdict "offloads" "$ok" "peer tso/gso off, DUT eth0 gro off; $segs data packets from the peer, largest payload $max_seg bytes (want <= 1460)"

# --- UtcpTransport on utcp0
step "transport: backend_transport_check --tun utcp0; open() with utcp0 down"
docker exec "$dut" "$bin/tests/interop/backend_transport_check" --tun utcp0 | tee "$tmp/tc.log"
tc_rc=${PIPESTATUS[0]}
docker exec "$dut" ip link set utcp0 down
docker exec "$dut" timeout 10 "$bin/tests/interop/backend_udp_echo" 2>&1 | tee "$tmp/downopen.log"
downopen_rc=${PIPESTATUS[0]}
docker exec "$dut" ip link set utcp0 up
ok=1
((tc_rc == 0 && downopen_rc == 1)) && has "$tmp/downopen.log" "is not running" && ok=0
verdict "transport" "$ok" "$(grep -c '^PASS' "$tmp/tc.log") self-checks passed; open() on a down utcp0 refused"

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
# A datagram from the stack's address to the peer, with NAT on: not masqueraded.
to_peer() {  # writes 198.18.0.2:40001 -> 198.19.1.3:9 into utcp0, prints what the peer saw
  docker exec "$peer" timeout 5 tcpdump -i eth0 -n -l -c 1 'udp and dst port 9' 2>/dev/null &
  local td=$!
  sleep 1
  docker exec "$dut" "$bin/tests/interop/backend_tun_tool" df --dst 198.19.1.3 --size 200 \
    --timeout-ms 300 >/dev/null 2>&1
  wait "$td"
}
to_peer | tee "$tmp/topeer.log"
# conntrack entries of the stack's address: there are some now, and nat.sh off
# flushes them (as nat.sh on did with the ones made before it).
ct_count() { docker exec "$dut" conntrack -L -s 198.18.0.2 2>/dev/null | grep -c . || true; }
ct_on=$(ct_count)
"$tb/nat.sh" off | tee "$tmp/natoff.log"
ct_off=$(ct_count)
to_peer >/dev/null
ct_before_on=$(ct_count)
"$tb/nat.sh" | tee -a "$tmp/natoff.log" >/dev/null
ct_after_on=$(ct_count)
echo "-- conntrack entries of 198.18.0.2: $ct_on with NAT on, $ct_off after nat.sh off; $ct_before_on before nat.sh on, $ct_after_on after"
ok=1
((nat_rc == 0 && dns_rc == 0)) && has "$tmp/topeer.log" "IP 198.18.0.2.40001 > 198.19.1.3.9:" &&
  ((ct_on > 0 && ct_off == 0 && ct_before_on > 0 && ct_after_on == 0)) && ok=0
verdict "nat" "$ok" "masquerade + route to resolver $dns; $(grep -c '^  A ' "$tmp/dns.log") A records for example.com; to the peer from $(grep -o 'IP [0-9.]* >' "$tmp/topeer.log" | head -1 | cut -d' ' -f2) (want 198.18.0.2.40001); conntrack flushed by off ($ct_on -> $ct_off) and on ($ct_before_on -> $ct_after_on)"
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
