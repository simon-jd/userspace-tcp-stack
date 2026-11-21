#!/bin/bash
# Run inside the disposable network namespace described in README.md.
set -euo pipefail
case "${1:-}" in clean|loss) ;; *) echo "usage: capture.sh clean|loss" >&2; exit 2 ;; esac
# Optional second argument selects a controller and the dedicated sender events.
trace_kinds=state,tx,rx,ack,timer,rto
cc=()
if [[ $# -ge 2 ]]; then
  case "$2" in newreno|cubic|bbr) ;; *) exit 2 ;; esac
  cc=(--cc "$2")
  trace_kinds+=,cwnd,rtt,recovery
fi
cd /out
ip tuntap add dev flt0 mode tun
ip addr add 198.18.0.1/30 dev flt0
ip link set flt0 up
if [ "$1" = loss ]; then
  # With ISN 4294967200 and 1448-byte payloads, segment 3 starts at 0xaf1.
  # One ordinary segment in the initial flight is dropped. Its retransmission passes.
  tc qdisc add dev flt0 ingress
  tc filter add dev flt0 ingress protocol ip prio 1 u32 \
    match ip protocol 6 0xff match u32 0x00000af1 0xffffffff at 24 \
    action drop random determ pass 2
fi
tcpdump -Z root -i flt0 -n -U -s 128 -B 4096 -w peer.pcap 'tcp port 7301' >tcpdump.out 2>tcpdump.err &
cap_pid=$!
timeout 30 utcp-bulk --backend kernel --listen 198.18.0.1:7301 --recv --bytes 1048613 --jsonl peer.jsonl >peer.out 2>peer.err &
peer_pid=$!
for i in {1..100}; do ss -ntl | grep -q ':7301' && grep -q 'listening on' tcpdump.err && break; sleep .02; done
timeout 30 utcp-bulk --backend utcp --tun flt0 --addr 198.18.0.2 --connect 198.18.0.1:7301 --send --bytes 1048613 --nodelay --set test_isn=4294967200 --pcap stack.pcap --trace trace.jsonl --trace-kinds "$trace_kinds" "${cc[@]}" --jsonl stack.jsonl >stack.out 2>stack.err
wait "$peer_pid"
sleep 1
kill -INT "$cap_pid"
wait "$cap_pid"
tc -s filter show dev flt0 ingress > filter.txt
chmod a+r ./*
cat tcpdump.err
