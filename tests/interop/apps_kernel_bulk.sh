#!/usr/bin/env bash
# m1-apps acceptance tests 1 and 7 (utcp-bulk, kernel backend, kernel to
# kernel over loopback in one container on CPUs 16-31; non-timing):
#  1. 1 GB each direction (the connecting side sends, then the listening
#     side sends): sender and receiver SHA-256 equal; the JSONL samples have
#     every DESIGN §10.1 field and inflight; median sample interval 10 +- 1 ms
#     and no gap above 50 ms; the summary has goodput, retransmissions,
#     busy, rwnd- and sndbuf-limited times.
#  7. --recv-pause 200:1048576, 100 MB: SHA-256 equal; the sender's samples
#     show rwnd_limited > 0.
# Extra: for 55, 119 and 1000055 bytes (55 mod 64, the SHA-256 padding
# boundary) both digests equal Python's hashlib.sha256 of the pattern rebuilt
# in Python, so our SHA-256 and pattern are checked against independent code.
# Usage: tests/interop/apps_kernel_bulk.sh   (see apps_kernel_common.sh)
source "$(dirname "${BASH_SOURCE[0]}")/apps_kernel_common.sh"
build_apps

run_in_container bulk "$container_lib"'
cat > /tmp/check_jsonl.py <<"PY"
import json, statistics, sys
path, role, need_rwnd = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
fields = ("cc_name state ca_state snd_wscale rcv_wscale rto_us ato_us srtt_us rttvar_us min_rtt_us cwnd "
          "ssthresh snd_mss rcv_mss adv_mss pmtu bytes_sent bytes_retrans bytes_acked bytes_received "
          "segs_out segs_in data_segs_out data_segs_in pacing_rate delivery_rate delivered app_limited "
          "busy_time_us rwnd_limited_us sndbuf_limited_us unacked sacked lost retrans total_retrans "
          "dsack_dups reordering reord_seen rcv_rtt_us rcv_space rcv_ssthresh snd_wnd rcv_wnd "
          "notsent_bytes last_data_sent_us last_data_recv_us last_ack_recv_us inflight").split()
lines = [json.loads(l) for l in open(path)]
samples = [l for l in lines if l.get("ev") == "sample"]
summary = [l for l in lines if l.get("ev") == "summary"]
errs = []
if len(summary) != 1: errs.append("%d summary lines" % len(summary))
if len(samples) < 10: errs.append("only %d samples" % len(samples))
missing = sorted({f for s in samples for f in fields if f not in s})
if missing: errs.append("missing fields " + ",".join(missing))
t = [s["t"] for s in samples]
gaps = [(b - a) / 1e6 for a, b in zip(t, t[1:])]
med = statistics.median(gaps) if gaps else 0
if not 9.0 <= med <= 11.0: errs.append("median interval %.3f ms" % med)
if gaps and max(gaps) > 50: errs.append("max gap %.3f ms" % max(gaps))
for k in ("goodput_bps", "total_retrans", "bytes_retrans", "busy_us", "rwnd_limited_us",
          "sndbuf_limited_us", "sha256", "bytes", "duration_us", "lateness_p99_ns"):
    if summary and k not in summary[0]: errs.append("summary lacks " + k)
rwnd = max((s["rwnd_limited_us"] for s in samples), default=0)
if need_rwnd and rwnd <= 0: errs.append("rwnd_limited stays 0")
print("%s %s: %d samples, median interval %.3f ms, max gap %.3f ms, last rwnd_limited %d us%s"
      % (path, role, len(samples), med, max(gaps) if gaps else 0, rwnd,
         "" if not errs else " -- " + "; ".join(errs)))
sys.exit(1 if errs else 0)
PY
cat > /tmp/pattern_sha.py <<"PY"
# SHA-256 of the utcp-bulk pattern (bulk.hpp pattern_fill): byte o is byte o % 8,
# little-endian, of splitmix64(seed + (o / 8) * golden).
import hashlib, struct, sys
n, seed = int(sys.argv[1]), int(sys.argv[2])
M = (1 << 64) - 1
def splitmix64(z):
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & M
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & M
    return z ^ (z >> 31)
data = b"".join(struct.pack("<Q", splitmix64((seed + i * 0x9e3779b97f4a7c15) & M))
                for i in range((n + 7) // 8))[:n]
print(hashlib.sha256(data).hexdigest())
PY
cd /tmp
sha() { python3 -c "import json,sys; print(json.loads(sys.argv[1])[\"sha256\"])" "$1"; }
field() { python3 -c "import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])" "$1" "$2"; }

# xfer NAME LISTEN_ROLE CONNECT_ROLE BYTES [RECV_EXTRA]
xfer() {
  local name=$1 lrole=$2 crole=$3 bytes=$4 extra=${5:-}
  local lx= cx= sender
  if [[ $lrole == send ]]; then lx="--send --bytes $bytes"; cx="--bytes $bytes $extra"; sender=l
  else lx="--bytes $bytes $extra"; cx="--send --bytes $bytes"; sender=c; fi
  $B/apps/utcp-bulk/utcp-bulk --backend kernel --listen 5001 $lx --jsonl $name.l.jsonl > $name.l.out 2> $name.l.err &
  local lpid=$!
  wait_port 5001 || { fail $name "listener did not start"; kill $lpid; return; }
  $B/apps/utcp-bulk/utcp-bulk --backend kernel --connect 127.0.0.1:5001 $cx --jsonl $name.c.jsonl > $name.c.out 2> $name.c.err
  local crc=$?
  wait $lpid; local lrc=$?
  cat $name.l.out $name.c.out
  if [[ $crc != 0 || $lrc != 0 ]]; then fail $name "exit codes listener $lrc connector $crc: $(cat $name.l.err $name.c.err)"; return; fi
  local ls cs; ls=$(sha "$(cat $name.l.out)"); cs=$(sha "$(cat $name.c.out)")
  local lb cb; lb=$(field "$(cat $name.l.out)" bytes); cb=$(field "$(cat $name.c.out)" bytes)
  if [[ $ls == "$cs" && $lb == "$bytes" && $cb == "$bytes" ]]; then pass "$name sha256 equal ($ls, $lb bytes)"
  else fail $name "sha256 $ls vs $cs, bytes $lb vs $cb"; fi
  local need_rwnd=0; [[ -n $extra ]] && need_rwnd=1
  if python3 /tmp/check_jsonl.py $name.$sender.jsonl sender $need_rwnd; then pass "$name sender jsonl"
  else fail "$name sender jsonl" "see the line above"; fi
  local recv=c; [[ $sender == c ]] && recv=l
  if python3 /tmp/check_jsonl.py $name.$recv.jsonl receiver 0; then pass "$name receiver jsonl"
  else fail "$name receiver jsonl" "see the line above"; fi
}

echo "-- test 1: 1 GB, connector sends"
xfer t1-up recv send 1000000000
echo "-- test 1: 1 GB, listener sends"
xfer t1-down send recv 1000000000
echo "-- test 7: 100 MB, receiver pauses 200 ms every 1 MiB"
xfer t7-pause recv send 100000000 "--recv-pause 200:1048576"
echo "-- SHA-256 and pattern against hashlib"
for n in 55 119 1000055; do
  $B/apps/utcp-bulk/utcp-bulk --backend kernel --listen 5001 --bytes $n --sample-ms 0 > h.l.out 2> h.l.err &
  lpid=$!
  wait_port 5001 || { fail "hashlib $n" "listener did not start"; kill $lpid; continue; }
  $B/apps/utcp-bulk/utcp-bulk --backend kernel --connect 127.0.0.1:5001 --send --bytes $n --sample-ms 0 > h.c.out 2> h.c.err
  crc=$?; wait $lpid; lrc=$?
  want=$(python3 /tmp/pattern_sha.py $n 1)
  ls=$(sha "$(cat h.l.out)"); cs=$(sha "$(cat h.c.out)")
  if [[ $crc == 0 && $lrc == 0 && $ls == "$want" && $cs == "$want" ]]; then pass "hashlib $n bytes: $want"
  else fail "hashlib $n" "exit $lrc/$crc, receiver $ls, sender $cs, hashlib $want: $(cat h.l.err h.c.err)"; fi
done
' | summarize
