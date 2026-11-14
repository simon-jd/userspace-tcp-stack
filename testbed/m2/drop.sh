#!/usr/bin/env bash
# Scripted drops on a router of slot N (§4.2 of the M2 design, DESIGN §14):
# drop chosen copies of chosen TCP sequence numbers of the connection to the
# receiver, or the N-th packet of the connection.
#
# By sequence and copy number (arm): a watcher in the router waits for the
# connection's SYN on the interface from the sender, reads its ISN and adds
# ISN + 1 + OFF (OFF = stream byte offset of the segment's first byte) to the
# set of target sequences. For a target, nft sets seen1, seen2, ... count the
# copies: the first packet carrying the sequence goes into seen1, a packet
# already in seen1 but not seen2 into seen2, and so on; copy K is dropped when
# K is listed in --copies (1 = the original, 2 = the first retransmission).
# Copies above the highest listed one pass. Matching is on the segment's first
# sequence number: a retransmission that starts elsewhere (repacketised) is
# not counted. The watcher arms within a few milliseconds of the SYN, before
# the first data segment can arrive (one RTT later); it logs the times.
#
# By packet count (ct): `ct original packets N drop`: the N-th packet of the
# connection in the original direction (SYN = 1), which is a first
# transmission only if nothing was retransmitted before it.
#
# The rules sit in table "ip utcp_drop", forward hook, priority filter, on
# packets to the receiver's address and --dport. Counters: `drop.sh show`.
#
# Usage:
#   testbed/m2/drop.sh --slot N arm [--router r1|r2] --offsets OFF[,OFF...] --copies K[,K...]
#                      [--dport P] [--log FILE]
#   testbed/m2/drop.sh --slot N ct [--router r1|r2] --packet N [--dport P]
#   testbed/m2/drop.sh --slot N show|clear [--router r1|r2]
# --log FILE: the watcher's log, a path inside the router (e.g. under /data).
# Default router r1, port 5201. `arm` returns once the watcher is waiting.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if [[ ${1:-} == -h || ${1:-} == --help ]]; then m2_help "$0"; exit 0; fi
m2_parse_slot "$@"
set -- "${m2_args[@]}"
cmd=${1:-}
shift || true
router=r1 offsets="" copies="" dport=5201 packet="" logf=/run/utcp-drop.log
while (($# > 0)); do
  case $1 in
    --router) router=${2:?}; shift 2 ;;
    --offsets) offsets=${2:?}; shift 2 ;;
    --copies) copies=${2:?}; shift 2 ;;
    --dport) dport=${2:?}; shift 2 ;;
    --packet) packet=${2:?}; shift 2 ;;
    --log) logf=${2:?}; shift 2 ;;
    *) tb_die "unknown argument $1 (see --help)" ;;
  esac
done
m2_require_up
case $router in
  r1) c=$m2_r1 in_if=$(m2_if_r1_a) ;;
  r2) c=$m2_r2 in_if=$(m2_if_r2_b) ;;
  *) tb_die "--router r1 or r2" ;;
esac
dst=$m2_rcv_ip

clear_table() {
  tb_sh "$c" "
    nft delete table ip utcp_drop 2>/dev/null || true
    for f in /run/utcp-drop-tcpdump.pid /run/utcp-drop-watcher.pid; do
      if [ -f \$f ]; then kill \$(cat \$f) 2>/dev/null || true; fi; rm -f \$f
    done
    true"
}

case $cmd in
  clear)
    clear_table
    echo "drop: $c cleared"
    ;;
  show)
    tb_exec "$c" nft list table ip utcp_drop
    ;;
  ct)
    [[ $packet =~ ^[0-9]+$ ]] || tb_die "--packet N is required"
    clear_table
    tb_sh "$c" "nft -f - <<'EOF'
table ip utcp_drop {
  chain forward_hook {
    type filter hook forward priority filter; policy accept;
    ip daddr $dst tcp dport $dport ct original packets $packet counter drop
  }
}
EOF"
    echo "drop: $c drops packet $packet of the connection to $dst:$dport"
    ;;
  arm)
    [[ $offsets =~ ^[0-9]+(,[0-9]+)*$ ]] || tb_die "--offsets OFF[,OFF...] is required"
    [[ $copies =~ ^[1-9](,[1-9])*$ ]] || tb_die "--copies K[,K...] (1-9) is required"
    kmax=$(tr ',' '\n' <<<"$copies" | sort -n | tail -1)
    sets="" rules="  chain copies {\n"
    for ((k = 1; k <= kmax; ++k)); do
      sets+="  set seen$k { typeof tcp sequence; flags dynamic; size 65535; }\n"
    done
    verdict() { [[ ,$copies, == *,$1,* ]] && echo "counter drop" || echo "counter accept"; }
    rules+="    tcp sequence @seen$kmax counter accept\n"
    for ((k = kmax - 1; k >= 1; --k)); do
      rules+="    tcp sequence @seen$k add @seen$((k + 1)) { tcp sequence } $(verdict $((k + 1)))\n"
    done
    rules+="    add @seen1 { tcp sequence } $(verdict 1)\n  }\n"
    clear_table
    tb_sh "$c" "nft -f - <<EOF
table ip utcp_drop {
  set targets { typeof tcp sequence; }
$(printf "%b" "$sets")
  chain forward_hook {
    type filter hook forward priority filter; policy accept;
    ip daddr $dst tcp dport $dport tcp sequence @targets jump copies
  }
$(printf "%b" "$rules")
}
EOF"
    # The watcher: first SYN to dst:dport on the interface from the sender.
    # shellcheck disable=SC2016
    watcher='
      echo $$ > /run/utcp-drop-watcher.pid
      exec >> "$1" 2>&1
      in_if=$2 dst=$3 dport=$4 offsets=$5 copies=$6
      rm -f /run/utcp-drop-tcpdump.err
      tcpdump -i "$in_if" -n -l -S -c 1 --immediate-mode \
        "dst host $dst and tcp dst port $dport and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn" \
        > /run/utcp-drop-syn.txt 2> /run/utcp-drop-tcpdump.err &
      echo $! > /run/utcp-drop-tcpdump.pid
      echo "$EPOCHREALTIME waiting offsets $offsets copies $copies"
      wait $!
      line=$(cat /run/utcp-drop-syn.txt)
      isn=$(sed -n "s/.* seq \([0-9]*\).*/\1/p" <<<"$line")
      echo "$EPOCHREALTIME syn isn $isn: $line"
      [ -n "$isn" ] || exit 1
      els=""
      for off in ${offsets//,/ }; do els+="${els:+, }$(( (isn + 1 + off) % 4294967296 ))"; done
      nft add element ip utcp_drop targets "{ $els }"
      echo "$EPOCHREALTIME armed sequences $els"
    '
    docker exec -d "$c" bash -c "$watcher" bash "$logf" "$in_if" "$dst" "$dport" "$offsets" "$copies"
    wait_s=0
    until tb_sh "$c" "grep -q 'listening on' /run/utcp-drop-tcpdump.err 2>/dev/null"; do
      sleep 0.05
      wait_s=$((wait_s + 1))
      ((wait_s < 100)) || tb_die "the watcher in $c did not start"
    done
    echo "drop: $c armed: offsets $offsets copies $copies, connection to $dst:$dport (log $logf)"
    ;;
  *) tb_die "usage: drop.sh --slot N arm|ct|show|clear ... (see --help)" ;;
esac
