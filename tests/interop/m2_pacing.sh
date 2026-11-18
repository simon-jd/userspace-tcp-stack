#!/usr/bin/env bash
# Pacing on the real backend (M2-TASKS m2b-rate-pacing test 4, M2 design
# §2.5): utcp-bulk on the stack in the M1 testbed's DUT sends for SECONDS
# with `--set test_fixed_pacing_rate=RATE` to utcp-bulk --backend kernel on
# the Linux peer. The knob counts payload bytes, so the Linux receiver's
# goodput (application bytes over its connection's lifetime) must be within
# 2 % of RATE. Reported per run: both goodputs, the stack loop's wake-up
# lateness (p50, p99, p99.9, max: utcp-bulk's summary), and an EDT replay of
# the stack's tx trace (the recurrence of M2 design §4.4: bursts sent before
# the modelled departure, burst sizes, and how late burst starts were against
# the modelled departure when the gate held them).
#
# Timing run: give the testbed a timing slot's CPUs (UTCP_CPUS or --cpus,
# e.g. 12-15; M2 design §6) and run it only while the task holds the slot.
# Records uptime, the top CPU users and the /proc/stat busy, irq and softirq
# deltas of the slot's CPUs per run, and every process seen on them.
#
# Path: no netem with --delay-ms 0; otherwise netem delay D ms (limit 20000)
# on the DUT's eth0 and utcp0 egress, so the RTT is 2 D (default 10: 20 ms,
# the M2 cells' shortest RTT, where a 50 Mbit/s burst is 4 packets).
# gso_max_size is set from the DUT eth0's gso_ipv4_max_size − 320 − 1 as the
# M2 runner does (DESIGN §14.6).
#
# Usage: tests/interop/m2_pacing.sh [--rate R] [--seconds S] [--delay-ms D]
#        [--runs N] [--cpus LIST] [--no-trace]
# Environment: UTCP_TB_PREFIX, UTCP_TB_NET_BASE (testbed/m1/common.sh),
#   M1_RESULTS (results directory), M1_VOLDIR (where the traces go in
#   utcp-data), UTCP_PRESET (default gcc-release; testbed/m1/build.sh),
#   UTCP_COMMIT (recorded; default: git rev-parse of the checkout).
# Starts the testbed if it is not running and leaves it running
# (testbed/m1/down.sh removes it). Exit status 1 if a run failed its check.
rate=50Mbit secs=20 delay_ms=10 runs=1 trace=1 cpus=${UTCP_CPUS:-}
while (($# > 0)); do
  case $1 in
    --rate) rate=$2; shift 2 ;;
    --seconds) secs=$2; shift 2 ;;
    --delay-ms) delay_ms=$2; shift 2 ;;
    --runs) runs=$2; shift 2 ;;
    --cpus) cpus=$2; shift 2 ;;
    --no-trace) trace=0; shift ;;
    -h | --help) sed -n '2,/^rate=/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument $1 (see --help)" >&2; exit 2 ;;
  esac
done
[[ -n $cpus ]] || { echo "give the timing slot's CPUs: --cpus LIST or UTCP_CPUS" >&2; exit 2; }
export UTCP_CPUS=$cpus
source "$(dirname "${BASH_SOURCE[0]}")/m1_lib.sh"

port=5001

# CPU list "12-15" or "12,13" -> "12 13 14 15".
cpu_list() {
  local part out=()
  IFS=, read -ra parts <<<"$1"
  for part in "${parts[@]}"; do
    if [[ $part == *-* ]]; then
      out+=($(seq "${part%-*}" "${part#*-}"))
    else
      out+=("$part")
    fi
  done
  echo "${out[*]}"
}
slot_cpus=$(cpu_list "$cpus")

# host_record FILE: uptime, the top CPU users, /proc/stat of the slot's CPUs
# and the processes last seen on them.
host_record() {
  {
    echo "## $(date -u +%FT%T.%NZ)"
    uptime
    ps -eo pid,psr,pcpu,comm --sort=-pcpu | head -15
    local c
    for c in $slot_cpus; do grep "^cpu$c " /proc/stat; done
    echo "# processes last on CPUs $cpus"
    ps -eLo pid,tid,psr,pcpu,comm | awk -v l=" $slot_cpus " 'NR > 1 && index(l, " " $3 " ") && $4 > 0'
  } >>"$1"
}

# netem_path D: delay D ms on both egresses of the DUT (0: back to N0).
netem_path() {
  local d=$1 eth
  if ((d == 0)); then
    m1_netem N0 >/dev/null
    return
  fi
  eth=$(tb_ifname "$tb_dut" "$tb_dut_ip")
  tb_sh "$tb_dut" "
    tc qdisc del dev $eth root 2>/dev/null || true
    tc qdisc del dev $tb_tun root 2>/dev/null || true
    tc qdisc add dev $eth root netem delay ${d}ms limit 20000
    tc qdisc add dev $tb_tun root netem delay ${d}ms limit 20000
  "
}

# The EDT replay and the burst statistics of a utcp-bulk --trace file (JSON
# lines) on stdin; one JSON object on stdout.
replay_py=$(cat <<'PY'
import json, sys
bursts = []  # [t_ns, rate, bytes, segments]
for ln in sys.stdin:
    if '"kind":"tx"' not in ln:
        continue
    e = json.loads(ln)
    if not e.get("len") or not e.get("gate_rate"):
        continue
    if e["burst_start"] or not bursts:
        bursts.append([e["t"], e["gate_rate"], e["len"], 1])
    else:
        b = bursts[-1]
        b[2] += e["len"]
        b[3] += 1
nxt = None
early, held_late, sizes = [], [], {}
for t, r, n, k in bursts:
    sizes[k] = sizes.get(k, 0) + 1
    late = None
    if nxt is not None:
        if t + 1000 < nxt:
            early.append(nxt - t)
        late = max(0, t - nxt)
        held_late.append(late)
    base = t if nxt is None else max(nxt, t)
    ln = n * 10**9 // r
    ln -= min(ln // 2, late if late is not None else ln)
    nxt = base + ln
def pct(v, q):
    if not v:
        return None
    v = sorted(v)
    return v[min(len(v) - 1, int(q * len(v)))]
# Burst starts within 1 ms after the modelled departure: the ones the gate
# held (later ones started on an ACK after an idle gate).
held = [x for x in held_late if x <= 1_000_000]
print(json.dumps({
    "bursts": len(bursts), "early": len(early), "early_max_ns": max(early) if early else 0,
    "segments_per_burst": {str(k): sizes[k] for k in sorted(sizes)},
    "start_after_departure_le_1ms": len(held),
    "start_after_departure_p50_ns": pct(held, 0.5), "start_after_departure_p99_ns": pct(held, 0.99),
    "start_after_departure_max_ns": max(held) if held else None,
}))
PY
)

# run_case N: one run; writes $M1_RESULTS/pacing-N/{send,recv}.out,
# host.txt, replay.json, result.json and prints the result line.
run_case() {
  local c=pacing-$1
  m1_case_dir "$c"
  local r=$M1_RESULTS/$c
  local B=$m1_bin/apps/utcp-bulk/utcp-bulk
  local eth gso g
  eth=$(tb_ifname "$tb_dut" "$tb_dut_ip")
  gso=$(tb_exec "$tb_dut" ip -d -j link show "$eth" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["gso_ipv4_max_size"])')
  g=$((gso - 320 - 1))
  {
    echo "uname $(uname -r)"
    echo "commit ${UTCP_COMMIT:-$(git -C "$m1_repo" rev-parse --short HEAD 2>/dev/null || echo none)} image $(docker image inspect -f '{{.Id}}' "$tb_image" | cut -c1-19)"
    echo "cpus $cpus delay_ms $delay_ms rate $rate seconds $secs $eth gso_ipv4_max_size $gso -> gso_max_size $g"
    tb_exec "$tb_dut" tc qdisc show
  } >"$r/setup.txt"
  local trace_args=()
  ((trace)) && trace_args=(--trace /run/utcp-trace.jsonl --trace-kinds tx)
  tb_exec "$tb_dut" rm -f /run/utcp-stats.json /run/utcp-trace.jsonl
  host_record "$r/host.txt"
  local t0 t1 rpid spid
  t0=$(date +%s.%N)
  tb_exec "$tb_peer" timeout $((secs + 120)) "$B" --backend kernel --sample-ms 100 --jsonl - \
    --listen "$port" --recv >"$r/recv.out" 2>"$r/recv.err" &
  rpid=$!
  m1_wait_kernel_listen "$tb_peer" "$port" || echo "kernel receiver not listening" >>"$r/recv.err"
  tb_exec "$tb_dut" timeout $((secs + 120)) "$B" --backend utcp --stats /run/utcp-stats.json \
    --sample-ms 100 --jsonl - "${trace_args[@]}" --set "test_fixed_pacing_rate=$rate" \
    --set "gso_max_size=$g" --connect "$tb_peer_ip:$port" --send --duration "$secs" \
    >"$r/send.out" 2>"$r/send.err" &
  spid=$!
  wait "$spid"
  local src=$?
  wait "$rpid"
  local rrc=$?
  t1=$(date +%s.%N)
  host_record "$r/host.txt"
  tb_exec "$tb_dut" cat /run/utcp-stats.json >"$r/stack-stats.json" 2>/dev/null
  echo '{}' >"$r/replay.json"
  if ((trace)); then
    # Through a pipe into an analysis container on the build CPUs; the trace
    # itself is kept in utcp-data, not on the host disk.
    tb_exec "$tb_dut" cat /run/utcp-trace.jsonl |
      docker run --rm -i --name "$m1_prefix-ana-$BASHPID" --cpuset-cpus 16-31 \
        -e REPLAY_PY="$replay_py" -v "$m1_volume:/data" "$tb_image" nice -n 10 bash -c "
          tee /data/$m1_voldir/$c/trace.jsonl | python3 -I -c \"\$REPLAY_PY\"" >"$r/replay.json"
    tb_exec "$tb_dut" rm -f /run/utcp-trace.jsonl
  fi
  python3 -I - "$r" "$rate" "$src" "$rrc" "$t0" "$t1" <<'PY'
import json, re, sys
r, rate, src, rrc, t0, t1 = sys.argv[1:7]
def summary(path):
    s = {}
    for ln in open(path):
        if '"ev":"summary"' in ln:
            s = json.loads(ln)
    return s
m = re.fullmatch(r"(\d+)(Mbit|Gbit|kbit)", rate)
want_bps = int(m.group(1)) * {"kbit": 10**3, "Mbit": 10**6, "Gbit": 10**9}[m.group(2)]
snd, rcv = summary(f"{r}/send.out"), summary(f"{r}/recv.out")
replay = json.load(open(f"{r}/replay.json"))
got = rcv.get("goodput_bps", 0)
res = {
    "want_bps": want_bps, "recv_goodput_bps": got, "send_goodput_bps": snd.get("goodput_bps"),
    "recv_bytes": rcv.get("bytes"), "recv_duration_us": rcv.get("duration_us"),
    "error_pct": round(100.0 * (got - want_bps) / want_bps, 3),
    "lateness_count": snd.get("lateness_count"), "lateness_p50_ns": snd.get("lateness_p50_ns"),
    "lateness_p99_ns": snd.get("lateness_p99_ns"), "lateness_p999_ns": snd.get("lateness_p999_ns"),
    "lateness_max_ns": snd.get("lateness_max_ns"), "total_retrans": snd.get("total_retrans"),
    "send_exit": int(src), "recv_exit": int(rrc), "send_ok": snd.get("ok"), "recv_ok": rcv.get("ok"),
    "sha_equal": snd.get("sha256") == rcv.get("sha256"),
    "wall_s": round(float(t1) - float(t0), 3), "replay": replay,
}
res["pass"] = (res["send_exit"] == 0 and res["recv_exit"] == 0 and res["sha_equal"]
               and abs(got - want_bps) <= 0.02 * want_bps and replay.get("early", 0) == 0)
json.dump(res, open(f"{r}/result.json", "w"), indent=1)
print(json.dumps(res))
PY
  python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["pass"] else 1)' \
    "$r/result.json"
}

m1_need_programs apps/utcp-bulk/utcp-bulk
m1_testbed_up
m1_pmtu down
netem_path "$delay_ms"
m1_log "pacing: rate $rate for ${secs}s, delay ${delay_ms}ms each way, cpus $cpus, $runs run(s)"
status=0
for ((i = 1; i <= runs; i++)); do
  run_case "$i" || status=1
done
m1_netem N0 >/dev/null
exit "$status"
