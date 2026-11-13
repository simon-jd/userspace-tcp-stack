#!/usr/bin/env bash
# Records the testbed's counters (DESIGN §11), to go with every interop run:
#   DUT:  ip -s link show utcp0 (TUN drops), tc -s qdisc (every interface)
#   peer: nstat -asz (all absolute counters, zeros included; the history file
#         is not updated, so deltas come from two records), ip tcp_metrics show
#   both: tso/gso/gro of the testbed interfaces (ethtool -k; common.sh)
# Each section starts with a "== <container> <command>" line; the first line
# has the label and the UTC time.
#
# Usage: testbed/m1/record.sh [LABEL] > FILE
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
  sed -n '2,/^source/p' "$0" | sed '$d; s/^# \{0,1\}//'
  exit 0
fi
label=${1:-record}
tb_running "$tb_dut" || tb_die "$tb_dut is not running (testbed/m1/up.sh)"
tb_running "$tb_peer" || tb_die "$tb_peer is not running (testbed/m1/up.sh)"

echo "# $label $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
echo "== $tb_dut ip -s link show $tb_tun"
tb_exec "$tb_dut" ip -s link show "$tb_tun"
echo "== $tb_dut tc -s qdisc"
tb_exec "$tb_dut" tc -s qdisc
echo "== $tb_peer nstat -asz"
tb_exec "$tb_peer" nstat -asz
echo "== $tb_peer ip tcp_metrics show"
tb_exec "$tb_peer" ip tcp_metrics show
echo "== offloads (ethtool -k)"
tb_show_offloads "$tb_peer" "$tb_peer_ip"
tb_show_offloads "$tb_dut" "$tb_dut_ip"
