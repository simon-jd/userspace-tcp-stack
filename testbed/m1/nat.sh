#!/usr/bin/env bash
# NAT in the DUT (DESIGN §9, §11), so the stack (198.18.0.2) reaches public
# sites and a DNS resolver: an nftables masquerade rule for 198.18.0.0/24 out
# of the DUT's utcp-m1-net interface (Docker's own NAT on the host then
# covers the DUT's address), and a host route in the DUT to the host's
# upstream DNS resolver via utcp-m1-net's gateway. Docker's resolver
# 127.0.0.11 is loopback inside each container, so the stack cannot use it.
#
# Only destinations outside 198.18.0.0/15 (RFC 2544's benchmarking range,
# which holds every testbed address and no public site) are masqueraded:
# traffic between the stack and the Linux peer keeps 198.18.0.2. Packets to
# masqueraded destinations that conntrack marks invalid (out of its TCP
# window) would skip NAT and leave with 198.18.0.2; they are dropped and
# counted instead (`nft list table ip utcp_m1_nat`).
#
# Conntrack runs in the DUT whether or not NAT is on (Docker's embedded DNS
# rules create a nat table in every container), and a connection keeps the
# NAT binding it got when its first packet passed. So `on` and `off` flush
# the DUT's conntrack table (conntrack -F, only this network namespace): a
# flow that was live before `on` would otherwise stay un-NATed, and one
# started under NAT would stay NATed after `off`. A flush breaks NATed flows
# that are live at `off`; run it between tests. Without the conntrack tool
# (an image older than testbed/Dockerfile) nat.sh says so and goes on, and
# the change applies only to flows started after it.
#
# The resolver is --dns IP, else the first IPv4 nameserver of the host's
# /run/systemd/resolve/resolv.conf (systemd-resolved's upstream servers),
# else of /etc/resolv.conf (127.0.0.0/8 skipped). It is printed and written
# to /run/utcp-m1-dns in the DUT, for `utcp-http-get --dns`.
#
# Usage: testbed/m1/nat.sh [on] [--dns IP]
#        testbed/m1/nat.sh off
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

table=utcp_m1_nat
testbed_range=198.18.0.0/15

# Flushes the DUT's conntrack table; prints what happened.
flush_conntrack() {
  if tb_exec "$tb_dut" sh -c 'command -v conntrack' >/dev/null 2>&1; then
    echo "conntrack -F in $tb_dut: $(tb_exec "$tb_dut" conntrack -F 2>&1 | tail -1)"
  else
    echo "WARNING: no conntrack tool in $tb_dut (rebuild the image with testbed/build-image.sh):" \
      "flows started before this call keep their NAT binding" >&2
  fi
}

host_resolver() {
  local f ip
  for f in /run/systemd/resolve/resolv.conf /etc/resolv.conf; do
    [[ -r $f ]] || continue
    ip=$(awk '$1 == "nameserver" && $2 ~ /^[0-9.]+$/ && $2 !~ /^127\./ {print $2; exit}' "$f")
    if [[ -n $ip ]]; then
      echo "$ip"
      return
    fi
  done
}

cmd=on
dns=""
while (($# > 0)); do
  case $1 in
    on | off) cmd=$1; shift ;;
    --dns) dns=${2:?--dns needs a value}; shift 2 ;;
    -h | --help) sed -n '2,/^source/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) tb_die "unknown argument $1 (see --help)" ;;
  esac
done
tb_running "$tb_dut" || tb_die "$tb_dut is not running (testbed/m1/up.sh)"
eth=$(tb_ifname "$tb_dut" "$tb_dut_ip")
[[ -n $eth ]] || tb_die "no interface with $tb_dut_ip in $tb_dut"

if [[ $cmd == off ]]; then
  old=$(tb_exec "$tb_dut" cat /run/utcp-m1-dns 2>/dev/null || true)
  tb_sh "$tb_dut" "
    nft delete table ip $table 2>/dev/null || true
    if [[ -n '$old' ]]; then ip route del $old/32 2>/dev/null || true; fi
    rm -f /run/utcp-m1-dns
  "
  flush_conntrack
  echo "NAT off in $tb_dut"
  exit 0
fi

[[ -n $dns ]] || dns=$(host_resolver)
[[ $dns =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || tb_die "no IPv4 DNS resolver found; give --dns IP"

tb_sh "$tb_dut" "
  nft delete table ip $table 2>/dev/null || true
  nft -f - <<'NFT'
table ip $table {
  chain forward {
    type filter hook forward priority filter; policy accept;
    ip saddr $tb_tun_subnet ip daddr != $testbed_range oifname \"$eth\" ct state invalid counter drop
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $tb_tun_subnet ip daddr != $testbed_range oifname \"$eth\" masquerade
  }
}
NFT
  ip route replace $dns/32 via $tb_net_gw dev $eth
  echo $dns > /run/utcp-m1-dns
"
flush_conntrack
echo "NAT on in $tb_dut: $tb_tun_subnet masqueraded out of $eth to destinations outside $testbed_range; DNS resolver $dns via $tb_net_gw"
echo "== nft list table ip $table"
tb_exec "$tb_dut" nft list table ip "$table"
echo "== ip route get $dns from $tb_tun_stack iif $tb_tun"
tb_exec "$tb_dut" ip route get "$dns" from "$tb_tun_stack" iif "$tb_tun" || true
