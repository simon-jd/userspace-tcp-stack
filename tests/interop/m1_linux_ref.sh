#!/usr/bin/env bash
# Linux-to-Linux reference runs for docs/INTEROP.md (not acceptance cases):
# utcp-bulk --backend kernel on the peer sends to utcp-bulk --backend kernel
# in a receiver container that sits behind the DUT, so the Linux receiver
# takes the stack's place on a forwarded path with the same netem:
#
#   utcp-m1-peer 198.19.1.3 -- utcp-m1-net -- DUT eth0 198.19.1.2
#   DUT 198.19.9.2 -- utcp-m1-accept-interop-refnet 198.19.9.0/24 (MTU 1500)
#        -- 198.19.9.3 utcp-m1-accept-interop-ref (the Linux receiver)
#
# netem.sh's profile is on the DUT's eth0 egress (the receiver's ACKs) and
# the same netem (limit 20000) on the DUT's refnet egress (the data), as the
# profile is on utcp0 in the Linux->stack cases. The DUT forwards single
# segments: the peer has tso/gso off, the DUT's refnet interface gro off
# (testbed/m1/common.sh), the receiver tso/gso off. (netem on the peer's own
# egress would act on whole GSO bursts, which Linux TCP always builds.)
#
#   R-N0-l2l, R-N1-l2l, R-N3-l2l, R-N4-l2l   1 GB
#   R-N4-100M-{1,2,3}-l2l                    100 MB under N4 (the size of the B rows)
#   R-N4-100M-sack0-ts{0,1}-ws{0,1}-l2l      100 MB under N4, the sender (peer) with
#                                            combo.sh's sack/ts/ws combination, as in B
#   R-pause200-l2l, R-pause500-l2l           100 MB under N0, the receiver
#                                            with --recv-pause 200:1048576 / 500:1048576
# Under N3 and N4, m1_dsack.py replays the sender's D-SACK accounting from the
# capture (CASE/dsack.json); the row checks that it predicts the sender's
# TCPSACKDiscard and TCPDSACKIgnoredDubious exactly, as in the stack rows.
#
# Records what m1_bulk.sh records (record.sh before and after: the peer's
# nstat is the sender's; a capture of the peer's interface) plus the
# receiver's `nstat -asz` before and after, and writes a row. The receiver
# container, its network and the DUT's link to it are removed at the end.
#
# Usage: tests/interop/m1_linux_ref.sh [PATTERN...]   (list: print the cases)
source "$(dirname "${BASH_SOURCE[0]}")/m1_lib.sh"

port=5002
ref=$m1_prefix-ref
refnet=$m1_prefix-refnet
refnet_subnet=198.19.9.0/24
refnet_gw=198.19.9.1
dut_ref_ip=198.19.9.2
ref_ip=198.19.9.3

all_cases() {
  printf '%s\n' R-N0-l2l R-N1-l2l R-N3-l2l R-N4-l2l R-N4-100M-1-l2l R-N4-100M-2-l2l R-N4-100M-3-l2l \
    R-pause200-l2l R-pause500-l2l R-N4-100M-sack0-ts0-ws0-l2l R-N4-100M-sack0-ts0-ws1-l2l \
    R-N4-100M-sack0-ts1-ws0-l2l R-N4-100M-sack0-ts1-ws1-l2l
}

netem_params() {
  case $1 in
    N0) echo "" ;;
    N1) echo "delay 1ms loss 1%" ;;
    N2) echo "delay 5ms reorder 10% 50%" ;;
    N3) echo "delay 1ms duplicate 2%" ;;
    N4) echo "delay 2ms loss 1% duplicate 1% reorder 5% 50%" ;;
  esac
}

ref_up() {
  tb_exists "$ref" && return 0
  tb_ensure_network "$refnet" "$refnet_subnet" "$refnet_gw"
  docker run -d --name "$ref" --hostname "$ref" --network "$refnet" --ip "$ref_ip" \
    --cap-add NET_ADMIN --cpuset-cpus "$tb_cpus" --sysctl net.ipv4.tcp_no_metrics_save=1 \
    -v "$m1_repo:/utcp:ro" "$tb_image" sleep infinity >/dev/null
  docker network connect --ip "$dut_ref_ip" "$refnet" "$tb_dut"
  tb_offloads "$ref" "$ref_ip" "${tb_sender_offloads[@]}"
  tb_offloads "$tb_dut" "$dut_ref_ip" "${tb_forward_offloads[@]}"
  tb_exec "$ref" ip route add "$tb_net_subnet" via "$dut_ref_ip"
  tb_exec "$tb_peer" ip route replace "$refnet_subnet" via "$tb_dut_ip"
  {
    tb_show_offloads "$tb_peer" "$tb_peer_ip"
    tb_show_offloads "$tb_dut" "$tb_dut_ip"
    tb_show_offloads "$tb_dut" "$dut_ref_ip"
    tb_show_offloads "$ref" "$ref_ip"
  } >"$M1_RESULTS/ref-offloads.txt"
}

ref_down() {
  tb_exists "$tb_peer" && tb_exec "$tb_peer" ip route del "$refnet_subnet" 2>/dev/null
  if tb_exists "$tb_dut" &&
    docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$refnet" 2>/dev/null | grep -qw "$tb_dut"; then
    docker network disconnect "$refnet" "$tb_dut"
  fi
  docker rm -f "$ref" >/dev/null 2>&1
  tb_net_exists "$refnet" && docker network rm "$refnet" >/dev/null
}

ref_case() {
  local c=$1
  local netem=${c#R-} bytes=1G bytes_n=1000000000 recv_extra=() opts=default
  netem=${netem%%-*}
  if [[ $netem == pause* ]]; then
    recv_extra=(--recv-pause "${netem#pause}:1048576")
    opts="recv-pause ${netem#pause}:1048576"
    netem=N0 bytes=100M bytes_n=100000000
  fi
  [[ $c == *-100M-* ]] && bytes=100M bytes_n=100000000
  local combo=default
  if [[ $c =~ ^R-N4-100M-(sack[01]-ts[01]-ws[01])-l2l$ ]]; then
    combo=${BASH_REMATCH[1]} opts=${BASH_REMATCH[1]}
  fi
  m1_peer_for "$combo"
  m1_pmtu down
  ref_up
  # A peer that combo.sh just started has no route to the reference network.
  tb_exec "$tb_peer" ip route replace "$refnet_subnet" via "$tb_dut_ip"
  m1_case_dir "$c"
  local r=$M1_RESULTS/$c
  m1_netem "$netem" >"$r/netem.txt" 2>&1
  local params rdev
  params=$(netem_params "$netem")
  rdev=$(tb_ifname "$tb_dut" "$dut_ref_ip")
  tb_exec "$tb_dut" tc qdisc del dev "$rdev" root 2>/dev/null
  if [[ -n $params ]]; then
    # shellcheck disable=SC2086
    tb_exec "$tb_dut" tc qdisc add dev "$rdev" root netem $params limit 20000
  fi
  tb_exec "$tb_dut" tc -s qdisc show dev "$rdev" >>"$r/netem.txt"
  local metrics
  metrics=$(( $(m1_metrics_count) + $(tb_exec "$ref" ip tcp_metrics show | wc -l) ))
  m1_log "$c: Linux $tb_peer_ip -> DUT -> Linux $ref_ip $bytes $netem $opts"
  m1_record "$c" before
  tb_exec "$ref" nstat -asz >"$r/ref-before.nstat"
  m1_cap_start "$c" peer "$tb_peer" "$tb_peer_ip" "tcp port $port" || return 1
  local B=$m1_bin/apps/utcp-bulk/utcp-bulk
  tb_exec "$ref" timeout 1800 "$B" --backend kernel --sample-ms 100 --jsonl - --listen "$port" \
    --recv --bytes "$bytes" "${recv_extra[@]}" >"$r/recv.out" 2>"$r/recv.err" &
  local rpid=$!
  m1_wait_kernel_listen "$ref" "$port"
  tb_exec "$tb_peer" timeout 1800 "$B" --backend kernel --sample-ms 100 --jsonl - \
    --connect "$ref_ip:$port" --send --bytes "$bytes" >"$r/send.out" 2>"$r/send.err"
  local src=$?
  wait "$rpid"
  local rrc=$?
  sleep 2
  m1_record "$c" after
  tb_exec "$ref" nstat -asz >"$r/ref-after.nstat"
  tb_exec "$tb_dut" tc -s qdisc show dev "$rdev" >>"$r/netem.txt"
  m1_cap_stop "$c" peer
  tb_exec "$tb_dut" tc qdisc del dev "$rdev" root 2>/dev/null
  # m1_pcap_summary's "stack" side is the Linux receiver here.
  m1_analyze "$c" peer "$ref_ip"
  local dsack_checks=()
  if [[ $netem == N3 || $netem == N4 ]]; then
    m1_dsack "$c" "$tb_peer_ip" peer
    dsack_checks=("check:peer['TcpExtTCPSACKDiscard']==dsack['sender']['pred_discard']"
      "check:peer['TcpExtTCPDSACKIgnoredDubious']==dsack['sender']['pred_dubious']")
  fi
  python3 -I - "$r" "$metrics" "$src" "$rrc" <<'PY'
import json, sys
r, metrics, src, rrc = sys.argv[1:5]
def ns(p):
    d = {}
    for ln in open(p):
        s = ln.split()
        if len(s) >= 2 and s[1].isdigit():
            d[s[0]] = int(s[1])
    return d
b, a = ns(f"{r}/ref-before.nstat"), ns(f"{r}/ref-after.nstat")
rcv = {k: a[k] - b.get(k, 0) for k in a if a[k] - b.get(k, 0)}
json.dump({"metrics_before": int(metrics), "send_exit": int(src), "recv_exit": int(rrc),
           "receiver_nstat": rcv}, open(f"{r}/extra.json", "w"))
PY
  m1_row "$c" "test=R" "direction=Linux->Linux (reference)" "options=$opts" "impairment=$netem" \
    "bytes_n=$bytes_n" "peer_sysctls=$(m1_peer_sysctls)" "cpus=$tb_cpus" \
    "captures=$m1_volume:/$m1_voldir/$c/peer.pcap" \
    'check:sha_ok' "check:extra['send_exit']==0 and extra['recv_exit']==0" \
    "check:extra['metrics_before']==0" "${dsack_checks[@]}"
}

if [[ ${1:-} == list ]]; then
  all_cases
  exit 0
fi
m1_need_programs apps/utcp-bulk/utcp-bulk
patterns=("$@")
((${#patterns[@]})) || patterns=('*')
m1_testbed_up
status=0
while read -r c; do
  for p in "${patterns[@]}"; do
    # shellcheck disable=SC2053
    if [[ $c == $p ]]; then
      ref_case "$c" || status=1
      break
    fi
  done
done < <(all_cases)
m1_netem N0 >/dev/null
ref_down
exit "$status"
