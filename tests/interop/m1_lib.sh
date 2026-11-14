# Shared helpers of the M1 interop acceptance runs (tests/interop/m1_*.sh,
# docs/INTEROP.md). Sourced, not run on its own. Uses the testbed of
# testbed/m1 (containers utcp-m1-dut, utcp-m1-peer, utcp-m1-r).
#
# Every run (one case) gets:
#   $M1_RESULTS/<case>/          small files on the host: record.sh output
#                                before and after, program output, the
#                                stack's --stats line, capture summaries,
#                                row.json (the matrix row) and run.log
#   utcp-data:/m1-accept-interop/<case>/*.pcap
#                                tcpdump captures (128-byte snaplen: headers
#                                only), kept in the Docker volume utcp-data
# and one line in $M1_RESULTS/rows.jsonl.
#
# Capture and analysis containers are named utcp-m1-accept-interop-* and
# removed when they end. They share the network namespace of the testbed
# container they watch (--network container:NAME), so the testbed scripts
# are unchanged.
#
# Environment:
#   M1_RESULTS  results directory on the host (default <repo>/.logs/interop)
#   UTCP_PRESET build preset of the programs (default gcc-release; built with
#               testbed/m1/build.sh)

source "$(dirname "${BASH_SOURCE[0]}")/../../testbed/m1/common.sh"
set +e  # runs go on after a failed check; each check is recorded instead

m1_repo=$tb_repo
m1_preset=${UTCP_PRESET:-gcc-release}
m1_bin=/utcp/build/tb-$m1_preset
M1_RESULTS=${M1_RESULTS:-$m1_repo/.logs/interop}
m1_volume=utcp-data
m1_voldir=m1-accept-interop
m1_prefix=utcp-m1-accept-interop
mkdir -p "$M1_RESULTS"

m1_log() { echo "[$(date -u +%H:%M:%S)] $*"; }

m1_need_programs() {
  local p
  for p in "$@"; do
    [[ -x $m1_repo/build/tb-$m1_preset/$p ]] ||
      tb_die "missing build/tb-$m1_preset/$p (testbed/m1/build.sh $m1_preset)"
  done
}

# Starts the testbed if it is not running.
m1_testbed_up() {
  if tb_running "$tb_dut" && tb_running "$tb_peer"; then
    return 0
  fi
  "$tb_repo/testbed/m1/down.sh" >/dev/null 2>&1
  "$tb_repo/testbed/m1/up.sh" >"$M1_RESULTS/up.log" 2>&1 || {
    cat "$M1_RESULTS/up.log"
    tb_die "testbed/m1/up.sh failed"
  }
  echo default >"$M1_RESULTS/.peer_combo"
}

# The peer's tcp_* sysctls as "sack ts ws ecn no_metrics_save".
m1_peer_sysctls() {
  tb_exec "$tb_peer" sysctl -n net.ipv4.tcp_sack net.ipv4.tcp_timestamps \
    net.ipv4.tcp_window_scaling net.ipv4.tcp_ecn net.ipv4.tcp_no_metrics_save | paste -sd' '
}

# m1_peer_for COMBO: makes sure the peer runs with combo.sh's COMBO
# (default, sack1-ts0-ws1, ecn1, ...). A new peer has no PMTU chain link.
m1_peer_for() {
  local want=$1 have=""
  have=$(cat "$M1_RESULTS/.peer_combo" 2>/dev/null)
  if [[ $have == "$want" ]] && tb_running "$tb_peer"; then
    return 0
  fi
  if tb_exists "$tb_router"; then
    "$tb_repo/testbed/m1/pmtu.sh" down >/dev/null
  fi
  "$tb_repo/testbed/m1/combo.sh" start "$want" >"$M1_RESULTS/combo-$want.log" 2>&1 || {
    cat "$M1_RESULTS/combo-$want.log"
    tb_die "combo.sh start $want failed"
  }
  echo "$want" >"$M1_RESULTS/.peer_combo"
}

# m1_pmtu up|down: the PMTU chain (testbed/m1/pmtu.sh), idempotent.
m1_pmtu() {
  if [[ $1 == up ]]; then
    tb_exists "$tb_router" && return 0
    "$tb_repo/testbed/m1/pmtu.sh" up >"$M1_RESULTS/pmtu-up.log" 2>&1 || {
      cat "$M1_RESULTS/pmtu-up.log"
      tb_die "pmtu.sh up failed"
    }
  else
    tb_exists "$tb_router" || return 0
    "$tb_repo/testbed/m1/pmtu.sh" down >>"$M1_RESULTS/pmtu-down.log" 2>&1
  fi
}

m1_netem() { "$tb_repo/testbed/m1/netem.sh" "$1"; }

# m1_case_dir CASE: creates (empties) the host and volume directories.
m1_case_dir() {
  local c=$1
  rm -rf "${M1_RESULTS:?}/$c"
  mkdir -p "$M1_RESULTS/$c"
  docker run --rm --name "$m1_prefix-mk" -v "$m1_volume:/data" "$tb_image" \
    bash -c "rm -rf /data/$m1_voldir/$c && mkdir -p /data/$m1_voldir/$c" >/dev/null
}

# m1_cap_start CASE NAME CONTAINER ADDRESS FILTER: tcpdump on the interface
# of CONTAINER that holds ADDRESS (or the interface named ADDRESS if it is
# not an address), 128-byte snaplen, into utcp-data:/m1-accept-interop/CASE/NAME.pcap.
m1_cap_start() {
  local c=$1 name=$2 ctr=$3 addr=$4 filter=$5 dev
  if [[ $addr =~ ^[0-9.]+$ ]]; then
    dev=$(tb_ifname "$ctr" "$addr")
  else
    dev=$addr
  fi
  [[ -n $dev ]] || tb_die "no interface for $addr in $ctr"
  docker rm -f "$m1_prefix-cap-$name" >/dev/null 2>&1
  docker run -d --name "$m1_prefix-cap-$name" --network "container:$ctr" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cpuset-cpus "$tb_cpus" \
    -v "$m1_volume:/data" "$tb_image" \
    tcpdump -i "$dev" -n -s 128 -B 262144 -U -w "/data/$m1_voldir/$c/$name.pcap" "$filter" >/dev/null
  local i
  for i in $(seq 50); do
    docker logs "$m1_prefix-cap-$name" 2>&1 | grep -q 'listening on' && return 0
    sleep 0.1
  done
  echo "capture $name did not start: $(docker logs "$m1_prefix-cap-$name" 2>&1 | tail -2)" >&2
  return 1
}

# m1_cap_stop CASE NAME: stops the capture; its statistics go to CASE/cap-NAME.txt.
m1_cap_stop() {
  local c=$1 name=$2
  docker kill -s INT "$m1_prefix-cap-$name" >/dev/null 2>&1
  docker wait "$m1_prefix-cap-$name" >/dev/null 2>&1
  docker logs "$m1_prefix-cap-$name" >"$M1_RESULTS/$c/cap-$name.txt" 2>&1
  docker rm -f "$m1_prefix-cap-$name" >/dev/null 2>&1
}

# m1_in_volume COMMAND...: runs a bash command in a container with utcp-data
# at /data and the case directories at /res (read-write), on the build CPUs.
m1_in_volume() {
  docker run --rm --name "$m1_prefix-ana-$BASHPID-$RANDOM" --cpuset-cpus 16-31 \
    -v "$m1_volume:/data" -v "$M1_RESULTS:/res" -v "$m1_repo:/utcp:ro" \
    "$tb_image" nice -n 10 bash -c "$*"
}

# m1_analyze CASE NAME STACK_IP [LEN]: one pass of tshark over CASE/NAME.pcap, then
# m1_pcap_summary (below) writes CASE/pcap-NAME.json: per sender (stack /
# linux / other), packet counts, SYN options, FIN/RST counts, zero windows,
# ECN marks, payload sizes, timestamps and SACK blocks after the handshake,
# and the ICMP errors seen.
m1_analyze() {
  local c=$1 name=$2 stack_ip=$3 len=${4:-}
  m1_in_volume "
    f=/data/$m1_voldir/$c/$name.pcap
    tshark -r \$f -n -o tcp.analyze_sequence_numbers:FALSE -o tcp.desegment_tcp_streams:FALSE \
      -Y 'tcp && !icmp' -T fields -E separator=';' -E occurrence=f \
      -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags \
      -e tcp.len -e tcp.window_size_value -e tcp.options.mss_val -e tcp.options.sack_perm \
      -e tcp.options.timestamp.tsval -e tcp.options.wscale.shift -e tcp.options.sack_le \
      -e ip.dsfield.ecn -e ip.flags.df -e tcp.seq_raw -e tcp.ack_raw > /tmp/tcp.txt 2>/tmp/tshark.err
    tshark -r \$f -n -Y icmp -T fields -E separator=';' -E occurrence=f \
      -e frame.time_epoch -e ip.src -e ip.dst -e icmp.type -e icmp.code -e icmp.mtu \
      > /tmp/icmp.txt 2>>/tmp/tshark.err
    python3 -I /utcp/tests/interop/m1_pcap_summary.py $stack_ip /tmp/tcp.txt /tmp/icmp.txt /tmp/tshark.err $len \
      > /res/$c/pcap-$name.json
  "
}

# m1_dsack CASE SENDER_IP SENDER_CAP [RECEIVER_CAP]: m1_dsack.py over
# CASE/SENDER_CAP.pcap (the Linux data sender's interface) and, if given,
# CASE/RECEIVER_CAP.pcap (next to the receiver), into CASE/dsack.json.
m1_dsack() {
  local c=$1 sender=$2 scap=$3 rcap=${4:-}
  local f fields=""
  for f in ip.src ip.dst tcp.srcport tcp.dstport tcp.flags tcp.seq_raw tcp.len tcp.ack_raw \
    tcp.options.sack_le tcp.options.sack_re; do
    fields+=" -e $f"
  done
  m1_in_volume "
    tsh() {
      tshark -r /data/$m1_voldir/$c/\$1.pcap -n -o tcp.analyze_sequence_numbers:FALSE \
        -o tcp.relative_sequence_numbers:FALSE -o tcp.desegment_tcp_streams:FALSE \
        -Y 'tcp && !icmp' -T fields -E separator=';' -E occurrence=a -E aggregator=, \
       $fields > /tmp/\$1.txt 2>>/tmp/tshark.err
    }
    tsh $scap
    ${rcap:+tsh $rcap}
    python3 -I /utcp/tests/interop/m1_dsack.py $sender /tmp/$scap.txt ${rcap:+/tmp/$rcap.txt} \
      > /res/$c/dsack.json
  "
}

# m1_metrics_empty: prints the number of `ip tcp_metrics show` entries on the peer.
m1_metrics_count() { tb_exec "$tb_peer" ip tcp_metrics show | wc -l; }

# m1_record CASE WHEN: testbed/m1/record.sh into CASE/WHEN.rec.
m1_record() { "$tb_repo/testbed/m1/record.sh" "$1 $2" >"$M1_RESULTS/$1/$2.rec" 2>&1; }

# m1_wait_kernel_listen CONTAINER PORT: until a kernel socket listens.
m1_wait_kernel_listen() {
  local i
  for i in $(seq 100); do
    tb_exec "$1" ss -Hltn "sport = :$2" | grep -q . && return 0
    sleep 0.05
  done
  return 1
}

# m1_row CASE KEY=VALUE... CHECK...: writes CASE/row.json and appends it to
# rows.jsonl (m1_row.py: reads the files of CASE, evaluates the checks).
m1_row() {
  python3 -I "$m1_repo/tests/interop/m1_row.py" "$M1_RESULTS" "$@"
}
