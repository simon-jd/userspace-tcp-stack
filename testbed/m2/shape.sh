#!/usr/bin/env bash
# Installs the path of one run on slot N (§5.2 of the M2 design, DESIGN §14),
# fresh every time (delete, then add):
#   r1, interface on net b (data direction):
#     netem limit 20000 delay ${RTT}ms [loss random ${P}%] [seed ${S}]
#     the whole base RTT and all loss; no jitter, so no reordering.
#   r2, interface on net c (to the receiver):
#     tbf rate ${BW}mbit burst B limit Q
#     B = max(2*1514, BW * 1 ms) bytes; Q = the queue in bytes. tbf counts
#     skb->len, which on veth includes the 14-byte Ethernet header.
#   r1's interface on net a and r2's on net b (the ACK direction): no qdisc
#   (veth's noqueue).
# Prints "shape: ..." with every value, then tc -s qdisc of the four router
# interfaces.
#
# Usage: testbed/m2/shape.sh --slot N --bw MBIT --rtt MS (--queue BYTES | --queue-bdp X)
#                            [--loss PERCENT] [--seed S]
#        testbed/m2/shape.sh --slot N --clear
#   --queue-bdp X   Q = X * BDP, BDP = BW * RTT / 8 bytes (rounded down)
#   --loss PERCENT  netem random loss (e.g. 0.1, 1); 0 or absent: no loss
#   --seed S        netem's PRNG seed (TCA_NETEM_PRNG_SEED); absent: the
#                   kernel draws one
#   --clear         remove both qdiscs
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

if [[ ${1:-} == -h || ${1:-} == --help ]]; then m2_help "$0"; exit 0; fi
m2_parse_slot "$@"
set -- "${m2_args[@]}"
bw="" rtt="" queue="" queue_bdp="" loss="" seed="" clear=0
while (($# > 0)); do
  case $1 in
    --bw) bw=${2:?}; shift 2 ;;
    --rtt) rtt=${2:?}; shift 2 ;;
    --queue) queue=${2:?}; shift 2 ;;
    --queue-bdp) queue_bdp=${2:?}; shift 2 ;;
    --loss) loss=${2:?}; shift 2 ;;
    --seed) seed=${2:?}; shift 2 ;;
    --clear) clear=1; shift ;;
    *) tb_die "unknown argument $1 (see --help)" ;;
  esac
done
m2_require_up

if_r1_a=$(m2_if_r1_a) if_r1_b=$(m2_if_r1_b) if_r2_b=$(m2_if_r2_b) if_r2_c=$(m2_if_r2_c)
for v in if_r1_a if_r1_b if_r2_b if_r2_c; do
  [[ -n ${!v} ]] || tb_die "interface $v not found"
done

# Fresh: delete whatever is there on all four (the reverse direction keeps
# noqueue). "tc qdisc del" fails when there is none.
tb_sh "$m2_r1" "tc qdisc del dev $if_r1_a root 2>/dev/null || true; tc qdisc del dev $if_r1_b root 2>/dev/null || true"
tb_sh "$m2_r2" "tc qdisc del dev $if_r2_b root 2>/dev/null || true; tc qdisc del dev $if_r2_c root 2>/dev/null || true"

if ((clear)); then
  echo "shape: slot $m2_n cleared"
else
  [[ $bw =~ ^[0-9]+$ && $bw -gt 0 ]] || tb_die "--bw MBIT (a positive integer) is required"
  [[ $rtt =~ ^[0-9]+$ ]] || tb_die "--rtt MS (an integer) is required"
  bdp=$((bw * 1000000 * rtt / 8000))
  if [[ -n $queue_bdp ]]; then
    [[ -z $queue ]] || tb_die "give one of --queue and --queue-bdp"
    q=$(awk -v b="$bdp" -v x="$queue_bdp" 'BEGIN {printf "%d", b * x}')
  else
    [[ $queue =~ ^[0-9]+$ ]] || tb_die "--queue BYTES or --queue-bdp X is required"
    q=$queue
  fi
  burst=$((bw * 1000000 / 8000))
  ((burst >= 2 * 1514)) || burst=$((2 * 1514))
  netem="netem limit $m2_netem_limit delay ${rtt}ms"
  if [[ -n $loss && $loss != 0 ]]; then
    [[ $loss =~ ^[0-9]+(\.[0-9]+)?$ ]] || tb_die "--loss: a percentage, not '$loss'"
    netem+=" loss random ${loss}%"
  fi
  if [[ -n $seed ]]; then
    [[ $seed =~ ^[0-9]+$ ]] || tb_die "--seed: an unsigned integer, not '$seed'"
    netem+=" seed $seed"
  fi
  tbf="tbf rate ${bw}mbit burst $burst limit $q"
  tb_exec "$m2_r1" tc qdisc add dev "$if_r1_b" root $netem
  tb_exec "$m2_r2" tc qdisc add dev "$if_r2_c" root $tbf
  echo "shape: slot $m2_n bw_mbit $bw rtt_ms $rtt bdp_bytes $bdp queue_bytes $q burst_bytes $burst" \
    "loss_pct ${loss:-0} seed ${seed:-none}"
  echo "shape: $m2_r1 $if_r1_b root $netem"
  echo "shape: $m2_r2 $if_r2_c root $tbf"
fi
for p in "$m2_r1 $if_r1_a" "$m2_r1 $if_r1_b" "$m2_r2 $if_r2_b" "$m2_r2 $if_r2_c"; do
  read -r c d <<<"$p"
  echo "== $c $d tc -s -raw qdisc"
  tb_exec "$c" tc -s -raw qdisc show dev "$d"
done
