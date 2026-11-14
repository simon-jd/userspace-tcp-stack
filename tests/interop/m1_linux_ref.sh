#!/usr/bin/env bash
# Linux-to-Linux reference runs for docs/INTEROP.md (not acceptance cases):
# 1 GB from utcp-bulk --backend kernel on the peer to utcp-bulk --backend
# kernel on the DUT's own kernel (198.19.1.2, port 5002), under a netem
# profile on both directions of that path: netem.sh's qdisc on the DUT's eth0
# egress (the ACKs) plus the same netem on the peer's eth0 egress (the data),
# removed after the run. So the Linux sender sees the same impairment as in
# the Linux->stack cases, with a Linux receiver instead of the stack.
#
#   R-N0-l2l, R-N1-l2l, R-N3-l2l, R-N4-l2l
#
# Records the same files as m1_bulk.sh (record.sh before and after: the
# peer's nstat is the sender's; a capture of the peer's interface), plus
# `nstat -asz` of the DUT before and after (the receiver), and writes a row.
#
# Usage: tests/interop/m1_linux_ref.sh [PATTERN...]   (list: print the cases)
source "$(dirname "${BASH_SOURCE[0]}")/m1_lib.sh"

port=5002

all_cases() { printf '%s\n' R-N0-l2l R-N1-l2l R-N3-l2l R-N4-l2l; }

netem_params() {
  case $1 in
    N0) echo "" ;;
    N1) echo "delay 1ms loss 1%" ;;
    N2) echo "delay 5ms reorder 10% 50%" ;;
    N3) echo "delay 1ms duplicate 2%" ;;
    N4) echo "delay 2ms loss 1% duplicate 1% reorder 5% 50%" ;;
  esac
}

ref_case() {
  local c=$1
  local netem=${c#R-}
  netem=${netem%%-*}
  m1_peer_for default
  m1_pmtu down
  m1_case_dir "$c"
  local r=$M1_RESULTS/$c
  m1_netem "$netem" >"$r/netem.txt" 2>&1
  local params peth
  params=$(netem_params "$netem")
  peth=$(tb_ifname "$tb_peer" "$tb_peer_ip")
  tb_exec "$tb_peer" tc qdisc del dev "$peth" root 2>/dev/null
  if [[ -n $params ]]; then
    # shellcheck disable=SC2086
    tb_exec "$tb_peer" tc qdisc add dev "$peth" root netem $params limit 20000
  fi
  tb_exec "$tb_peer" tc -s qdisc show dev "$peth" >>"$r/netem.txt"
  local metrics
  metrics=$(m1_metrics_count)
  m1_log "$c: Linux $tb_peer_ip -> Linux $tb_dut_ip 1G $netem (both directions)"
  m1_record "$c" before
  tb_exec "$tb_dut" nstat -asz >"$r/dut-before.nstat"
  m1_cap_start "$c" peer "$tb_peer" "$tb_peer_ip" "tcp port $port" || return 1
  local B=$m1_bin/apps/utcp-bulk/utcp-bulk
  tb_exec "$tb_dut" timeout 1800 "$B" --backend kernel --sample-ms 100 --jsonl - --listen "$port" \
    --recv --bytes 1G >"$r/recv.out" 2>"$r/recv.err" &
  local rpid=$!
  m1_wait_kernel_listen "$tb_dut" "$port"
  tb_exec "$tb_peer" timeout 1800 "$B" --backend kernel --sample-ms 100 --jsonl - \
    --connect "$tb_dut_ip:$port" --send --bytes 1G >"$r/send.out" 2>"$r/send.err"
  local src=$?
  wait "$rpid"
  local rrc=$?
  sleep 2
  m1_record "$c" after
  tb_exec "$tb_dut" nstat -asz >"$r/dut-after.nstat"
  m1_cap_stop "$c" peer
  tb_exec "$tb_peer" tc qdisc del dev "$peth" root 2>/dev/null
  # The receiver is 198.19.1.2: m1_pcap_summary's "stack" side is the DUT kernel here.
  m1_analyze "$c" peer "$tb_dut_ip"
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
b, a = ns(f"{r}/dut-before.nstat"), ns(f"{r}/dut-after.nstat")
dut = {k: a[k] - b.get(k, 0) for k in a if a[k] - b.get(k, 0)}
json.dump({"metrics_before": int(metrics), "send_exit": int(src), "recv_exit": int(rrc),
           "dut_nstat": dut}, open(f"{r}/extra.json", "w"))
PY
  m1_row "$c" "test=R" "direction=Linux->Linux (reference)" "options=default" "impairment=$netem" \
    "bytes_n=1000000000" "peer_sysctls=$(m1_peer_sysctls)" "cpus=$tb_cpus" \
    "captures=$m1_volume:/$m1_voldir/$c/peer.pcap" \
    'check:sha_ok' "check:extra['send_exit']==0 and extra['recv_exit']==0"
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
exit "$status"
