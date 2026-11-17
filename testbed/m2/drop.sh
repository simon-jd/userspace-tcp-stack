#!/usr/bin/env bash
# Scripted drops on a router of slot N (§4.2 of the M2 design, DESIGN §14):
# drop chosen copies of chosen TCP sequence numbers of the connection to the
# receiver, or the N-th packet of the connection.
#
# By segment and copy number (arm): a target is a stream byte offset OFF and a
# count N (default 1). It selects the first N segments whose first byte lies
# in [OFF, OFF + N*SPAN) (SPAN default 1448, the sender's MSS with
# timestamps), in the order they reach the router; the range ends early at
# the next target's offset. Every segment is at most one MSS long, so such a
# range always holds N segment starts whatever sizes the sender chose (a
# short segment earlier in the stream moves every later boundary; an offset
# need not be a boundary). Only packets with payload count (one rule per TCP
# data offset compares the IP length with the headers).
# A watcher in the router waits for the connection's SYN on the interface
# from the sender, reads its ISN and adds the target ranges ISN + 1 + [lo, hi)
# to an interval verdict map that jumps to the target's chain. The chain
# latches a segment start: n1..nN count the starts latched (a start in the
# range after the N-th passes untouched); the latched sequence numbers go in
# c1, and sets c1, c2, ... count their copies: a packet whose sequence is in
# c(j) but not c(j+1) is copy j+1. Copy K is dropped when K is listed in
# --copies (1 = the original, 2 = the first retransmission); copies above the
# highest listed one pass. A retransmission that starts at another sequence
# number (repacketised) is not counted. The watcher arms within a few
# milliseconds of the SYN, before the first data segment can arrive (one RTT
# later); it logs the times and ranges. tools/m2/dropcheck.py --targets
# computes from a capture before the router which segments the rule latches.
#
# By packet count (ct): `ct original packets N drop`: the N-th packet of the
# connection in the original direction (SYN = 1), which is a first
# transmission only if nothing was retransmitted before it.
#
# The rules sit in table "ip utcp_drop", forward hook, priority filter, on
# packets to the receiver's address and --dport. Counters: `drop.sh show`.
#
# Usage:
#   testbed/m2/drop.sh --slot N arm [--router r1|r2] --offsets OFF[:N][,OFF[:N]...] --copies K[,K...]
#                      [--span B] [--dport P] [--log FILE]
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
router=r1 offsets="" copies="" span=1448 dport=5201 packet="" logf=/run/utcp-drop.log
while (($# > 0)); do
  case $1 in
    --router) router=${2:?}; shift 2 ;;
    --offsets) offsets=${2:?}; shift 2 ;;
    --copies) copies=${2:?}; shift 2 ;;
    --span) span=${2:?}; shift 2 ;;
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
    [[ $offsets =~ ^[0-9]+(:[0-9]+)?(,[0-9]+(:[0-9]+)?)*$ ]] || tb_die "--offsets OFF[:N][,OFF[:N]...] is required"
    [[ $copies =~ ^[1-9](,[1-9])*$ ]] || tb_die "--copies K[,K...] (1-9) is required"
    [[ $span =~ ^[1-9][0-9]*$ ]] || tb_die "--span B: a positive byte count"
    kmax=$(tr ',' '\n' <<<"$copies" | sort -n | tail -1)
    verdict() { [[ ,$copies, == *,$1,* ]] && echo "counter drop" || echo "counter accept"; }
    # Targets sorted by offset; target i's range is [off, off + n*span), cut at
    # the next target's offset. Passed to the watcher as off:len:i.
    mapfile -t tg < <(tr ',' '\n' <<<"$offsets" | awk -F: '{print $1, ($2 == "" ? 1 : $2)}' | sort -n -k1,1)
    ranges="" decl="" chains=""
    for ((i = 0; i < ${#tg[@]}; ++i)); do
      read -r off n <<<"${tg[i]}"
      ((n >= 1 && n <= 64)) || tb_die "offset $off: N must be 1-64"
      len=$((n * span))
      if ((i + 1 < ${#tg[@]})); then
        read -r next _ <<<"${tg[i + 1]}"
        ((next > off)) || tb_die "offset $off is listed twice"
        ((next - off < len)) && len=$((next - off))
      fi
      ranges+="${ranges:+ }$off:$len:$i"
      for ((k = 1; k <= kmax; ++k)); do
        decl+="  set t${i}_c$k { typeof tcp sequence; flags dynamic; size 64; }\n"
      done
      for ((j = 1; j <= n; ++j)); do
        decl+="  set t${i}_n$j { typeof ip daddr; flags dynamic; size 4; }\n"
      done
      chains+="  chain t$i {\n    tcp sequence @t${i}_c$kmax counter accept\n"
      for ((k = kmax - 1; k >= 1; --k)); do
        chains+="    tcp sequence @t${i}_c$k add @t${i}_c$((k + 1)) { tcp sequence } $(verdict $((k + 1)))\n"
      done
      chains+="    ip daddr @t${i}_n$n counter accept\n"
      for ((j = n - 1; j >= 1; --j)); do
        chains+="    ip daddr @t${i}_n$j add @t${i}_n$((j + 1)) { ip daddr } add @t${i}_c1 { tcp sequence } $(verdict 1)\n"
      done
      chains+="    add @t${i}_n1 { ip daddr } add @t${i}_c1 { tcp sequence } $(verdict 1)\n  }\n"
    done
    # Packets with payload only: IP length above the IP and TCP headers.
    hook=""
    for ((d = 5; d <= 15; ++d)); do
      hook+="    ip daddr $dst tcp dport $dport ip hdrlength 5 tcp doff $d ip length > $((20 + 4 * d)) tcp sequence vmap @targets\n"
    done
    clear_table
    tb_sh "$c" "nft -f - <<EOF
table ip utcp_drop {
  map targets { typeof tcp sequence : verdict; flags interval; }
$(printf "%b" "$decl")
  chain forward_hook {
    type filter hook forward priority filter; policy accept;
$(printf "%b" "$hook")
  }
$(printf "%b" "$chains")
}
EOF"
    # The watcher: first SYN to dst:dport on the interface from the sender.
    # shellcheck disable=SC2016
    watcher='
      echo $$ > /run/utcp-drop-watcher.pid
      exec >> "$1" 2>&1
      in_if=$2 dst=$3 dport=$4 ranges=$5 copies=$6
      rm -f /run/utcp-drop-tcpdump.err
      tcpdump -i "$in_if" -n -l -S -c 1 --immediate-mode \
        "dst host $dst and tcp dst port $dport and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn" \
        > /run/utcp-drop-syn.txt 2> /run/utcp-drop-tcpdump.err &
      echo $! > /run/utcp-drop-tcpdump.pid
      echo "$EPOCHREALTIME waiting ranges (offset:length:target) $ranges copies $copies"
      wait $!
      line=$(cat /run/utcp-drop-syn.txt)
      isn=$(sed -n "s/.* seq \([0-9]*\).*/\1/p" <<<"$line")
      echo "$EPOCHREALTIME syn isn $isn: $line"
      [ -n "$isn" ] || exit 1
      els=""
      for r in $ranges; do
        IFS=: read -r off len i <<<"$r"
        lo=$(( (isn + 1 + off) % 4294967296 )) hi=$(( (isn + off + len) % 4294967296 ))
        if ((hi >= lo)); then els+="${els:+, }$lo-$hi : jump t$i"
        else els+="${els:+, }$lo-4294967295 : jump t$i, 0-$hi : jump t$i"; fi  # wraps
      done
      nft add element ip utcp_drop targets "{ $els }"
      echo "$EPOCHREALTIME armed sequences $els"
    '
    docker exec -d "$c" bash -c "$watcher" bash "$logf" "$in_if" "$dst" "$dport" "$ranges" "$copies"
    wait_s=0
    until tb_sh "$c" "grep -q 'listening on' /run/utcp-drop-tcpdump.err 2>/dev/null"; do
      sleep 0.05
      wait_s=$((wait_s + 1))
      ((wait_s < 100)) || tb_die "the watcher in $c did not start"
    done
    echo "drop: $c armed: offsets $offsets span $span copies $copies, connection to $dst:$dport (log $logf)"
    ;;
  *) tb_die "usage: drop.sh --slot N arm|ct|show|clear ... (see --help)" ;;
esac
