#!/usr/bin/env bash
# Reproduces m1-apps acceptance test 7 (kernel backend on both ends, loopback
# in a container with --network none, 100 MB, receiver with --recv-pause
# 200:1048576) and records what the retransmissions are (docs/INTEROP.md,
# "m1-apps test 7 retransmissions"): `nstat -asz` before and after (the
# container's own network namespace: only this transfer), the sender's
# summary, and a 128-byte capture of lo in utcp-data:/$M1_VOLDIR/apps-t7-<n>/lo.pcap
# (m1_lib.sh; default m1-accept-interop/<run>)
# with a tshark breakdown of the sender's retransmitted segments
# (tcp.analysis.retransmission, zero-window probes, window-full).
#
# Usage: tests/interop/m1_apps_retrans.sh [RUNS]   (default 3)
# Needs: testbed/m1/build.sh gcc-release utcp-bulk. Results in $M1_RESULTS/apps-t7-<n>/.
source "$(dirname "${BASH_SOURCE[0]}")/m1_lib.sh"

runs=${1:-3}
m1_need_programs apps/utcp-bulk/utcp-bulk
status=0
for n in $(seq 1 "$runs"); do
  c=apps-t7-$n
  m1_case_dir "$c"
  r=$M1_RESULTS/$c
  m1_log "$c"
  docker rm -f "$m1_prefix-apps" >/dev/null 2>&1
  docker run --rm --name "$m1_prefix-apps" --network none --cpuset-cpus 16-31 \
    --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$m1_repo:/utcp:ro" -v "$m1_volume:/data" -e B="$m1_bin" -e C="$c" -e V="$m1_voldir" \
    "$tb_image" bash -c '
      cd /tmp
      sysctl net.ipv4.tcp_no_metrics_save net.ipv4.tcp_sack net.ipv4.tcp_timestamps net.ipv4.tcp_ecn
      tcpdump -i lo -n -s 128 -B 262144 -U -w /data/$V/$C/lo.pcap tcp port 5001 2> tcpdump.err &
      tpid=$!
      for i in $(seq 50); do grep -q "listening on" tcpdump.err && break; sleep 0.1; done
      echo "== nstat before"; nstat -asz
      $B/apps/utcp-bulk/utcp-bulk --backend kernel --listen 5001 --bytes 100000000 \
        --recv-pause 200:1048576 --sample-ms 0 > recv.out 2> recv.err &
      lpid=$!
      for i in $(seq 100); do ss -Hltn "sport = :5001" | grep -q . && break; sleep 0.05; done
      $B/apps/utcp-bulk/utcp-bulk --backend kernel --connect 127.0.0.1:5001 --send \
        --bytes 100000000 --sample-ms 0 > send.out 2> send.err
      wait $lpid
      sleep 1
      echo "== nstat after"; nstat -asz
      kill -INT $tpid; wait $tpid
      echo "== tcpdump"; cat tcpdump.err
      echo "== send"; cat send.out send.err
      echo "== recv"; cat recv.out recv.err
      echo "== tshark: sender (port 5001 is the receiver) segments by kind"
      f=/data/$V/$C/lo.pcap
      for flt in "tcp.dstport==5001 && tcp.len>0" \
                 "tcp.dstport==5001 && tcp.analysis.retransmission" \
                 "tcp.dstport==5001 && tcp.analysis.fast_retransmission" \
                 "tcp.dstport==5001 && tcp.analysis.spurious_retransmission" \
                 "tcp.dstport==5001 && tcp.analysis.zero_window_probe" \
                 "tcp.dstport==5001 && tcp.analysis.window_full" \
                 "tcp.srcport==5001 && tcp.window_size_value==0" \
                 "tcp.srcport==5001 && tcp.analysis.zero_window_probe_ack" \
                 "tcp.srcport==5001 && tcp.analysis.window_update"; do
        printf "%-70s %s\n" "$flt" "$(tshark -r $f -n -Y "$flt" 2>/dev/null | wc -l)"
      done
      echo "== tshark: first 40 retransmissions with the preceding receiver window"
      tshark -r $f -n -Y "tcp.dstport==5001 && tcp.analysis.retransmission" \
        -T fields -e frame.number -e frame.time_relative -e tcp.seq -e tcp.len \
        -e tcp.analysis.retransmission -e tcp.analysis.zero_window_probe 2>/dev/null | head -40
    ' >"$r/run.txt" 2>&1 || status=1
done
exit "$status"
