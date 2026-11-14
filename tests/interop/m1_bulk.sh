#!/usr/bin/env bash
# M1 interop acceptance tests A, B and C (docs/INTEROP.md): utcp-bulk on the
# stack in utcp-m1-dut (--backend utcp, profile linux) against utcp-bulk
# --backend kernel on the Linux peer, on the testbed of testbed/m1.
#
#   A-N<k>-s2l, A-N<k>-l2s   1 GB stack->Linux / Linux->stack under netem N0..N4
#   A-pause200-s2l, -l2s     100 MB, the receiver with --recv-pause 200:1048576
#   A-pause-s2l, A-pause-l2s 100 MB, the receiver with --recv-pause 500:1048576
#                            (200 ms ends before the sender's persist/SWS-override
#                            timer, which fills a sub-MSS window: docs/INTEROP.md)
#   A-ecn<k>-s2l, -l2s       100 MB under N0, peer with net.ipv4.tcp_ecn=k (1, 3)
#   B-<combo>-s2l, -l2s      100 MB under N4, peer with combo.sh's sack/ts/ws combination
#   C-pmtu-s2l, C-pmtu-l2s   1 GB under N0 over the PMTU chain (MTU 1400 link)
#
# For each case: the peer runs with the case's sysctls (combo.sh) and
# tcp_no_metrics_save=1, `ip tcp_metrics show` is checked empty, record.sh
# runs before and after, tcpdump captures the peer's interface and utcp0
# (m1_lib.sh), the stack writes its counters (--stats), and m1_row.py checks
# the results and writes the row (results in $M1_RESULTS/<case>/).
#
# Usage: tests/interop/m1_bulk.sh [PATTERN...]   cases whose name matches a
#        shell pattern (default: all, in the order above); `list` prints them.
# Needs: testbed/m1/build.sh gcc-release utcp-bulk. Starts the testbed if it
# is not running and leaves it running (testbed/m1/down.sh removes it).
# Exit status 1 if any case failed.
source "$(dirname "${BASH_SOURCE[0]}")/m1_lib.sh"

port=5001
stack_ip=$tb_tun_stack

all_cases() {
  local n d c s t w
  for n in N0 N1 N2 N3 N4; do
    for d in s2l l2s; do echo "A-$n-$d"; done
  done
  for d in s2l l2s; do echo "A-pause200-$d"; done
  for d in s2l l2s; do echo "A-pause-$d"; done
  for c in ecn1 ecn3; do
    for d in s2l l2s; do echo "A-$c-$d"; done
  done
  for s in 0 1; do
    for t in 0 1; do
      for w in 0 1; do
        for d in s2l l2s; do echo "B-sack$s-ts$t-ws$w-$d"; done
      done
    done
  done
  for d in s2l l2s; do echo "C-pmtu-$d"; done
}

# bulk_case CASE: sets the case's parameters, runs it, writes its row.
bulk_case() {
  local c=$1
  local test=${c%%-*} dir=${c##*-} rest=${c#*-}
  rest=${rest%-*}
  local bytes=1G bytes_n=1000000000 netem=N0 combo=default recv_extra=() pmtu=0 opts=default
  local checks=('check:sha_ok' "check:fin_ok('peer')" "check:extra['metrics_before']==0"
    "check:peer['TcpExtTCPSACKReneging']==0")
  case $test-$rest in
    A-N[0-4])
      netem=$rest
      if [[ $dir == l2s && ($netem == N1 || $netem == N4) ]]; then
        checks+=("check:peer['TcpExtTCPSackRecovery']>0")
      fi
      if [[ $dir == l2s && $netem == N3 ]]; then
        checks+=("check:peer['TcpExtTCPDSACKRecv']>0")
      fi
      ;;
    A-pause | A-pause200)
      local pause=500:1048576
      [[ $rest == pause200 ]] && pause=200:1048576
      bytes=100M bytes_n=100000000 recv_extra=(--recv-pause "$pause") opts="recv-pause $pause"
      if [[ $dir == s2l ]]; then
        # Linux's receiver advertised 0; the stack's sender was held by it.
        checks+=("check:pcap['peer']['by']['remote']['zero_win']>0"
          "check:peer['TcpExtTCPToZeroWindowAdv']>0" "check:send['rwnd_limited_us']>0")
      else
        checks+=("check:pcap['peer']['by']['stack']['zero_win']>0"
          "check:stack['TcpExtTCPToZeroWindowAdv']>0" "check:send['rwnd_limited_us']>0")
      fi
      ;;
    A-ecn[13])
      bytes=100M bytes_n=100000000 combo=$rest opts="peer tcp_ecn=${rest#ecn}"
      # Not negotiated: no ECE/CWR/AE in the stack's SYN or SYN-ACK, none in
      # Linux's SYN-ACK, no ECN codepoint on any packet.
      # (all() and any() over the SYNs need them captured: at least one each.)
      checks+=("check:len(pcap['peer']['by']['stack']['syns'])>=1 and len(pcap['peer']['by']['remote']['syns'])>=1"
        "check:not any(s['ece'] or s['cwr'] or s['ae'] for s in pcap['peer']['by']['stack']['syns'])"
        "check:not any(s['ack'] and (s['ece'] or s['ae']) for s in pcap['peer']['by']['remote']['syns'])"
        "check:pcap['peer']['by']['stack']['ecn_ip']==0 and pcap['peer']['by']['remote']['ecn_ip']==0"
        "check:pcap['peer']['by']['stack']['ece_cwr_after_syn']==0 and pcap['peer']['by']['remote']['ece_cwr_after_syn']==0")
      if [[ $dir == l2s ]]; then
        checks+=("check:any(not s['ack'] and s['ece'] and s['cwr'] for s in pcap['peer']['by']['remote']['syns'])")
      fi
      ;;
    B-sack[01]-ts[01]-ws[01])
      bytes=100M bytes_n=100000000 netem=N4 combo=$rest opts=$rest
      local s=${rest:4:1} t=${rest:8:1} w=${rest:12:1}
      local S T W
      S=$([[ $s == 1 ]] && echo True || echo False)
      T=$([[ $t == 1 ]] && echo True || echo False)
      W=$([[ $w == 1 ]] && echo True || echo False)
      # Linux's SYN or SYN-ACK carries exactly the enabled options; the
      # stack's SYN offers all three, its SYN-ACK only what Linux offered;
      # after the handshake timestamps and SACK blocks appear only if on.
      checks+=("check:len(pcap['peer']['by']['stack']['syns'])>=1 and len(pcap['peer']['by']['remote']['syns'])>=1"
        "check:all(x['sack_perm']==$S and x['ts']==$T and (x['wscale'] is not None)==$W for x in pcap['peer']['by']['remote']['syns'])"
        "check:all((x['sack_perm'] and x['ts'] and x['wscale'] is not None) if not x['ack'] else (x['sack_perm']==$S and x['ts']==$T and (x['wscale'] is not None)==$W) for x in pcap['peer']['by']['stack']['syns'])"
        "check:(pcap['peer']['by']['stack']['ts_after_syn']>0)==$T and (pcap['peer']['by']['remote']['ts_after_syn']>0)==$T")
      if [[ $s == 0 ]]; then
        checks+=("check:pcap['peer']['by']['stack']['sack_segs']==0 and pcap['peer']['by']['remote']['sack_segs']==0")
      elif [[ $dir == l2s ]]; then
        checks+=("check:peer['TcpExtTCPSackRecovery']>0")
      fi
      ;;
    C-pmtu)
      pmtu=1 opts="PMTU 1400 chain"
      if [[ $dir == s2l ]]; then
        # The stack's segments shrink after the first frag-needed reached it:
        # its first 1348-byte segment follows that ICMP message and none is
        # longer after it. Segments longer than 1348 bytes after the ICMP are
        # the ones sent before the stack read it (new data at the old size,
        # within 39 us in run5); they must all be within 10 ms of it, far
        # below the 200 ms minimum RTO that a stack ignoring the ICMP would
        # wait for.
        checks+=("check:any(i['type']==3 and i['code']==4 and i['mtu']==1400 and i['dst']=='$stack_ip' for i in pcap['utcp0']['icmp'])"
          "check:pcap['utcp0']['icmp_frag_needed_to_stack_first_t'] is not None and pcap['utcp0']['stack_first_len_t'] is not None and pcap['utcp0']['stack_first_len_t']>pcap['utcp0']['icmp_frag_needed_to_stack_first_t']"
          "check:pcap['utcp0']['stack_max_len_after_first_len']<=1348"
          "check:pcap['utcp0']['stack_over_len_after_icmp']==0 or pcap['utcp0']['stack_over_len_after_icmp_last_dt']<=0.01"
          "check:pcap['utcp0']['by']['stack']['max_len']==1448"
          "check:extra['send_last_sample']['pmtu']==1400"
          "check:extra['send_last_sample']['snd_mss']==1348")
      else
        checks+=("check:any(i['type']==3 and i['code']==4 and i['mtu']==1400 and i['dst']=='$tb_peer_ipb' for i in pcap['peer']['icmp'])"
          "check:pcap['peer']['by']['remote']['len_top'][0][0]==1348"
          "check:extra['send_last_sample']['pmtu']==1400"
          "check:extra['recv_last_sample']['rcv_mss']==1348")
      fi
      ;;
    *) tb_die "unknown case $c" ;;
  esac
  # TCPSACKDiscard: 0, except Linux->stack under duplication (N3, N4), where
  # Linux 7.0 discards D-SACKs for duplicates it never retransmitted
  # (tcp_dsack_seen: dsack_dups > total_retrans). There the count must be
  # exactly the one m1_dsack.py predicts from the peer's capture, and every
  # predicted block must be a D-SACK for a segment the stack received twice
  # (utcp0 capture), and every D-SACK the stack sent must be one.
  local dsack=0
  if [[ $dir == l2s && ($netem == N3 || $netem == N4) && $pmtu == 0 ]]; then
    dsack=1
    checks+=("check:peer['TcpExtTCPSACKDiscard']==dsack['sender']['pred_discard']"
      "check:peer['TcpExtTCPDSACKIgnoredDubious']==dsack['sender']['pred_dubious']"
      "check:dsack['sender']['pred_discard_dup']==dsack['sender']['pred_discard']"
      "check:dsack['receiver']['dsack_other']==0")
  else
    checks+=("check:peer['TcpExtTCPSACKDiscard']==0")
  fi

  m1_peer_for "$combo"
  if ((pmtu)); then m1_pmtu up; else m1_pmtu down; fi
  local peer_addr=$tb_peer_ip
  ((pmtu)) && peer_addr=$tb_peer_ipb
  m1_case_dir "$c"
  local r=$M1_RESULTS/$c
  m1_netem "$netem" >"$r/netem.txt" 2>&1
  local metrics
  metrics=$(m1_metrics_count)
  m1_log "$c: $dir $bytes $netem peer=$combo ($(m1_peer_sysctls)) metrics=$metrics"
  m1_record "$c" before
  m1_cap_start "$c" peer "$tb_peer" "$peer_addr" "tcp port $port or icmp" || return 1
  m1_cap_start "$c" utcp0 "$tb_dut" "$tb_tun" "tcp port $port or icmp" || return 1

  local B=$m1_bin/apps/utcp-bulk/utcp-bulk
  local stack_args=(--backend utcp --stats /run/utcp-stats.json --sample-ms 100 --jsonl -)
  local kern_args=(--backend kernel --sample-ms 100 --jsonl -)
  local t0 t1 rpid spid
  t0=$(date +%s.%N)
  tb_exec "$tb_dut" rm -f /run/utcp-stats.json
  if [[ $dir == s2l ]]; then
    tb_exec "$tb_peer" timeout 1800 "$B" "${kern_args[@]}" --listen "$port" --recv --bytes "$bytes" \
      "${recv_extra[@]}" >"$r/recv.out" 2>"$r/recv.err" &
    rpid=$!
    m1_wait_kernel_listen "$tb_peer" "$port" || echo "kernel receiver not listening" >>"$r/recv.err"
    tb_exec "$tb_dut" timeout 1800 "$B" "${stack_args[@]}" --connect "$peer_addr:$port" --send \
      --bytes "$bytes" >"$r/send.out" 2>"$r/send.err" &
    spid=$!
  else
    tb_exec "$tb_dut" timeout 1800 "$B" "${stack_args[@]}" --listen "$port" --recv --bytes "$bytes" \
      "${recv_extra[@]}" >"$r/recv.out" 2>"$r/recv.err" &
    rpid=$!
    sleep 1
    tb_exec "$tb_peer" timeout 1800 "$B" "${kern_args[@]}" --connect "$stack_ip:$port" --send \
      --bytes "$bytes" >"$r/send.out" 2>"$r/send.err" &
    spid=$!
  fi
  wait "$spid"
  local src=$?
  wait "$rpid"
  local rrc=$?
  t1=$(date +%s.%N)
  sleep 2  # the last ACKs, and the peer's FIN retransmissions if the stack's ACK was lost
  m1_record "$c" after
  m1_cap_stop "$c" peer
  m1_cap_stop "$c" utcp0
  tb_exec "$tb_dut" cat /run/utcp-stats.json >"$r/stack-stats.json" 2>/dev/null
  m1_analyze "$c" peer "$stack_ip"
  m1_analyze "$c" utcp0 "$stack_ip" 1348
  ((dsack)) && m1_dsack "$c" "$peer_addr" peer utcp0
  python3 -I - "$r" "$metrics" "$src" "$rrc" "$t0" "$t1" <<'PY'
import json, sys
r, metrics, src, rrc, t0, t1 = sys.argv[1:7]
def last_sample(path):
    s = None
    for ln in open(path):
        if '"ev":"sample"' in ln:
            s = ln
    return json.loads(s) if s else {}
json.dump({"metrics_before": int(metrics), "send_exit": int(src), "recv_exit": int(rrc),
           "wall_s": round(float(t1) - float(t0), 3),
           "send_last_sample": last_sample(f"{r}/send.out"),
           "recv_last_sample": last_sample(f"{r}/recv.out")}, open(f"{r}/extra.json", "w"))
PY
  checks+=("check:extra['send_exit']==0 and extra['recv_exit']==0")
  local direction="stack->Linux"
  [[ $dir == l2s ]] && direction="Linux->stack"
  m1_row "$c" "test=$test" "direction=$direction" "options=$opts" "impairment=$netem" \
    "bytes_n=$bytes_n" "peer_sysctls=$(m1_peer_sysctls)" "cpus=$tb_cpus" \
    "captures=$m1_volume:/$m1_voldir/$c/{peer,utcp0}.pcap" "${checks[@]}"
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
      bulk_case "$c" || status=1
      break
    fi
  done
done < <(all_cases)
m1_netem N0 >/dev/null
exit "$status"
