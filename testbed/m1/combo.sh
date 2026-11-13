#!/usr/bin/env bash
# Linux peers with other TCP option settings (DESIGN §11): the 8 combinations
# of net.ipv4.tcp_{sack,timestamps,window_scaling} and net.ipv4.tcp_ecn 1 and
# 3, each set with `docker run --sysctl` (per network namespace), on top of
# net.ipv4.tcp_no_metrics_save=1. `check` exits 1 if a value was rejected or
# reads back changed (the table says which).
#
# Usage: testbed/m1/combo.sh list
#        testbed/m1/combo.sh start NAME   replace utcp-m1-peer with a peer for NAME
#        testbed/m1/combo.sh check        start a peer for every NAME in turn, print the
#                                         values read back inside it, then restore the
#                                         default peer
# NAME: sack{0,1}-ts{0,1}-ws{0,1} (e.g. sack1-ts0-ws1), ecn1, ecn3, or default.
# The new peer is on utcp-m1-net only (rerun pmtu.sh for the PMTU chain). A
# value the kernel rejects makes `start` fail and is reported by `check`.
# Environment: UTCP_IMAGE, UTCP_CPUS (common.sh).
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

readback_keys=(net.ipv4.tcp_sack net.ipv4.tcp_timestamps net.ipv4.tcp_window_scaling
  net.ipv4.tcp_ecn net.ipv4.tcp_no_metrics_save)

all_names() {
  local s t w
  for s in 0 1; do
    for t in 0 1; do
      for w in 0 1; do
        echo "sack$s-ts$t-ws$w"
      done
    done
  done
  echo ecn1
  echo ecn3
}

# The sysctls of NAME, one per line.
sysctls_of() {
  local name=$1
  if [[ $name =~ ^sack([01])-ts([01])-ws([01])$ ]]; then
    echo "net.ipv4.tcp_sack=${BASH_REMATCH[1]}"
    echo "net.ipv4.tcp_timestamps=${BASH_REMATCH[2]}"
    echo "net.ipv4.tcp_window_scaling=${BASH_REMATCH[3]}"
  elif [[ $name =~ ^ecn([0-9]+)$ ]]; then
    echo "net.ipv4.tcp_ecn=${BASH_REMATCH[1]}"
  elif [[ $name == default ]]; then
    :
  else
    tb_die "unknown combination $name (combo.sh list)"
  fi
}

# Replaces the peer. Prints docker's error and returns 1 if it fails.
start_peer_for() {
  local name=$1
  local -a want
  mapfile -t want < <(sysctls_of "$name")
  tb_net_exists "$tb_net" || tb_die "network $tb_net does not exist (testbed/m1/up.sh)"
  if tb_exists "$tb_peer"; then
    docker rm -f "$tb_peer" >/dev/null
  fi
  local err
  if ! err=$(tb_start_peer "${want[@]}" 2>&1); then
    echo "$err" >&2
    docker rm -f "$tb_peer" >/dev/null 2>&1 || true
    return 1
  fi
}

readback() {
  tb_exec "$tb_peer" sysctl -n "${readback_keys[@]}" | paste -sd' '
}

cmd=${1:-}
case $cmd in
  list)
    while read -r n; do
      echo "$n: $(sysctls_of "$n" | paste -sd' ')"
    done < <(all_names)
    ;;
  start)
    name=${2:?usage: combo.sh start NAME}
    sysctls_of "$name" >/dev/null
    start_peer_for "$name" || tb_die "the peer for $name did not start"
    echo "started $tb_peer for $name: $(sysctls_of "$name" | paste -sd' ')"
    echo "read back (${readback_keys[*]#net.ipv4.}): $(readback)"
    ;;
  check)
    tb_net_exists "$tb_net" || tb_die "network $tb_net does not exist (testbed/m1/up.sh)"
    printf '%-14s %-70s %s\n' NAME "REQUESTED" "READ BACK (sack ts ws ecn no_metrics_save)"
    status=0
    while read -r n; do
      req=$(sysctls_of "$n" | sed 's/net\.ipv4\.//' | paste -sd' ')
      if ! err=$(start_peer_for "$n" 2>&1); then
        printf '%-14s %-70s REJECTED: %s\n' "$n" "$req" "$(echo "$err" | tail -1)"
        status=1
        continue
      fi
      got=$(readback)
      # Each requested value must read back unchanged.
      verdict=ok
      while IFS='=' read -r key val; do
        [[ -z $key ]] && continue
        have=$(tb_exec "$tb_peer" sysctl -n "$key")
        [[ $have == "$val" ]] || verdict="DIFFERS ($key=$have)"
      done < <(sysctls_of "$n"; printf '%s\n' "${tb_peer_sysctls[@]}")
      [[ $verdict == ok ]] || status=1
      printf '%-14s %-70s %s  %s\n' "$n" "$req" "$got" "$verdict"
    done < <(all_names)
    start_peer_for default || tb_die "the default peer did not start"
    echo "restored the default peer: $(readback)"
    exit "$status"
    ;;
  -h | --help) sed -n '2,/^source/p' "$0" | sed '$d; s/^# \{0,1\}//' ;;
  *) tb_die "usage: combo.sh list | start NAME | check" ;;
esac
