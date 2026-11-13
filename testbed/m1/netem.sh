#!/usr/bin/env bash
# Installs a netem profile on the DUT (DESIGN §11): on the egress of the
# DUT's interface on utcp-m1-net (eth0: stack -> Linux) and of utcp0
# (Linux -> stack), so the peer's own egress has no qdisc. Prints
# `tc -s qdisc` of both interfaces afterwards.
#
# Profiles (all netem qdiscs with limit 20000):
#   N0  none: eth0 back to its default (noqueue), utcp0 back to pfifo limit 10000
#   N1  delay 1ms loss 1%
#   N2  delay 5ms reorder 10% 50%
#   N3  delay 1ms duplicate 2%
#   N4  delay 2ms loss 1% duplicate 1% reorder 5% 50%
#
# Usage: testbed/m1/netem.sh N0|N1|N2|N3|N4
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

profile=${1:-}
case $profile in
  N0) params="" ;;
  N1) params="delay 1ms loss 1%" ;;
  N2) params="delay 5ms reorder 10% 50%" ;;
  N3) params="delay 1ms duplicate 2%" ;;
  N4) params="delay 2ms loss 1% duplicate 1% reorder 5% 50%" ;;
  -h | --help) sed -n '2,/^source/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
  *) tb_die "usage: netem.sh N0|N1|N2|N3|N4" ;;
esac
tb_running "$tb_dut" || tb_die "$tb_dut is not running (testbed/m1/up.sh)"
eth=$(tb_ifname "$tb_dut" "$tb_dut_ip")
[[ -n $eth ]] || tb_die "no interface with $tb_dut_ip in $tb_dut"

# Delete, then add: `tc qdisc replace` on an existing netem keeps the
# parameters the new profile does not name (N3 after N2 would keep the
# reorder).
tb_sh "$tb_dut" "
  tc qdisc del dev $eth root 2>/dev/null || true
  tc qdisc del dev $tb_tun root 2>/dev/null || true
"
if [[ -z $params ]]; then
  tb_exec "$tb_dut" tc qdisc add dev "$tb_tun" root pfifo limit "$tb_tun_txqueuelen"
else
  tb_sh "$tb_dut" "
    tc qdisc add dev $eth root netem $params limit 20000
    tc qdisc add dev $tb_tun root netem $params limit 20000
  "
fi
echo "profile $profile${params:+: $params limit 20000} on $tb_dut $eth and $tb_tun egress"
echo "== tc -s qdisc show dev $eth"
tb_exec "$tb_dut" tc -s qdisc show dev "$eth"
echo "== tc -s qdisc show dev $tb_tun"
tb_exec "$tb_dut" tc -s qdisc show dev "$tb_tun"
