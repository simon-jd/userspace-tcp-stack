#!/usr/bin/env bash
# M1 interop acceptance test H (docs/INTEROP.md), on the testbed of testbed/m1:
#   H-udp   utcp-echo --udp on the stack (utcp-m1-dut, --backend utcp, port 7);
#           from the Linux peer, `nc -u` sends 1000 datagrams (one line each,
#           1 ms apart); every one must come back unchanged, and the stack
#           counts 1000 datagrams in and 1000 out
#   H-ping  `ping -c 3 198.18.0.2` from the peer gets 3 replies from the stack
#           (the echo server is running; nothing else holds utcp0)
# Each case: record.sh before and after, a capture of utcp0, the stack's
# --stats, one row (m1_row.py).
#
# Usage: tests/interop/m1_udp_icmp.sh [PATTERN...]  (list: print the cases)
# Needs: testbed/m1/build.sh gcc-release utcp-echo. Starts the testbed if
# needed and leaves it running. Exit status 1 if any case failed.
source "$(dirname "${BASH_SOURCE[0]}")/m1_lib.sh"

stack_ip=$tb_tun_stack

all_cases() { printf '%s\n' H-udp H-ping; }

start_echo() {
  local r=$1
  tb_exec "$tb_dut" rm -f /run/utcp-stats.json
  tb_exec "$tb_dut" "$m1_bin/apps/utcp-echo/utcp-echo" --backend utcp --listen 7 --udp \
    --stats /run/utcp-stats.json >"$r/echo.out" 2>"$r/echo.err" &
  echo_pid=$!
  sleep 1
}

stop_echo() {
  local r=$1
  tb_exec "$tb_dut" pkill -TERM -f "$m1_bin/apps/utcp-echo/utcp-echo"
  wait "$echo_pid"
  echo_rc=$?
  tb_exec "$tb_dut" cat /run/utcp-stats.json >"$r/stack-stats.json" 2>/dev/null
}

h_case() {
  local c=$1
  m1_peer_for default
  m1_pmtu down
  m1_case_dir "$c"
  local r=$M1_RESULTS/$c
  m1_netem N0 >"$r/netem.txt" 2>&1
  m1_log "$c"
  m1_record "$c" before
  m1_cap_start "$c" utcp0 "$tb_dut" "$tb_tun" "udp or icmp" || return 1
  start_echo "$r"
  local checks=() opts
  if [[ $c == H-udp ]]; then
    opts="nc -u, 1000 datagrams"
    for i in $(seq 1 1000); do printf 'datagram %04d from the Linux peer\n' "$i"; done >"$r/sent.txt"
    # -i: the lines come from stdin. nc sends what one read() of the pipe
    # returns as one datagram, so the first line is written 0.5 s after nc
    # starts (in run2, two lines written while nc was starting left as one
    # 68-byte datagram) and the lines 1 ms apart.
    docker exec -i "$tb_peer" bash -c "{ sleep 0.5; while IFS= read -r line; do printf '%s\n' \"\$line\"; sleep 0.001; done; } |
      nc -u -w 3 $stack_ip 7" <"$r/sent.txt" >"$r/received.txt" 2>"$r/nc.err"
    local same=0
    cmp -s "$r/sent.txt" "$r/received.txt" && same=1
    echo "{\"sent_lines\": $(wc -l <"$r/sent.txt"), \"received_lines\": $(wc -l <"$r/received.txt"), \"same\": $same}" \
      >"$r/extra.json"
    checks=("check:extra['same']==1 and extra['received_lines']==1000"
      "check:stack['UdpInDatagrams']==1000 and stack['UdpOutDatagrams']==1000")
  else
    opts="ping -c 3"
    tb_exec "$tb_peer" ping -c 3 -W 2 "$stack_ip" >"$r/ping.txt" 2>&1
    local got
    got=$(awk '/packets transmitted/ {print $4}' "$r/ping.txt")
    echo "{\"replies\": ${got:-0}}" >"$r/extra.json"
    checks=("check:extra['replies']==3" "check:stack['IcmpInEchos']==3 and stack['IcmpOutEchoReps']==3")
  fi
  stop_echo "$r"
  m1_record "$c" after
  m1_cap_stop "$c" utcp0
  python3 -I - "$r" "$echo_rc" <<'PY'
import json, sys
r, rc = sys.argv[1:3]
d = json.load(open(f"{r}/extra.json"))
d["echo_exit"] = int(rc)
json.dump(d, open(f"{r}/extra.json", "w"))
PY
  local direction="Linux->stack->Linux"
  m1_row "$c" "test=H" "direction=$direction" "options=$opts" "impairment=N0" \
    "peer_sysctls=$(m1_peer_sysctls)" "cpus=$tb_cpus" \
    "captures=$m1_volume:/$m1_voldir/$c/utcp0.pcap" "${checks[@]}" "check:extra['echo_exit']==0"
}

if [[ ${1:-} == list ]]; then
  all_cases
  exit 0
fi
m1_need_programs apps/utcp-echo/utcp-echo
patterns=("$@")
((${#patterns[@]})) || patterns=('*')
m1_testbed_up
status=0
while read -r c; do
  for p in "${patterns[@]}"; do
    # shellcheck disable=SC2053
    if [[ $c == $p ]]; then
      h_case "$c" || status=1
      break
    fi
  done
done < <(all_cases)
exit "$status"
