#!/usr/bin/env bash
# Verifies the scripted-drop mechanism of testbed/m2/drop.sh (M2-TASKS
# m2d-testbed test 10, DESIGN §14.5) on a non-timing instance, with the Linux
# sender (CUBIC), 100 Mbit/s, 20 ms, a 40xBDP queue (no tbf drops), no netem
# loss, 5 MB per run:
#   copy1:  r1 drops copy 1 (the original) of the segment latched at offset
#           1448000;
#   copy2:  r1 drops copy 2 of it and r2 drops copy 1, so that a copy 2
#           exists: r1 loses exactly copy 2, r2 exactly copy 1, and both
#           latched the same segment;
#   copy12: r1 drops copies 1 and 2 (a lost retransmission);
#   mid:    copy 1 at offset 1448700, inside a segment: the next segment
#           start is latched;
#   burst:  copy 1 of 5 consecutive segments from offset 2896000;
#   ct:     r1 drops `ct original packets 500`, which must be a data segment's
#           first transmission (copy 1).
# For each, tools/m2/dropcheck.py lists what r1 dropped (r1-in vs r1-out) and,
# for copy2, what r2 dropped (r1-out vs r2-out), and computes from the capture
# before each router which segments the rule must latch (--targets): the
# first segment starts at or after the offset, wherever the Linux sender put
# its boundaries. The script checks that each target latched its N segments
# and that the dropped packets are exactly the intended copies of them, and
# that each watcher armed less than one RTT after the SYN (its log).
# Prints PASS/FAIL per case; exit 1 if any failed. Outputs under
# /data/m2/<campaign>/ in the utcp-data volume.
#
# Usage: tests/interop/m2_testbed_drops.sh [--slot N] [--campaign NAME]
#   (default slot 2, campaign m2d-testbed/drops; the slot must be up, e.g.
#   testbed/m2/up.sh --slot 2)
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
slot=2 campaign=m2d-testbed/drops
while (($# > 0)); do
  case $1 in
    --slot) slot=$2; shift 2 ;;
    --campaign) campaign=$2; shift 2 ;;
    -h | --help) sed -n '2,/^set -e/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
image=${UTCP_IMAGE:-utcp-testbed:dev}
volume=${UTCP_DATA_VOLUME:-utcp-data}
job=${UTCP_M2_JOB:-utcp-m2-runner}
off=1448000 rtt=20
fail=0

# check RUN WANT DROP-ARGS...: WANT is JSON {"r1": [OFFSETS, [COPIES]] or
# null, "r2": likewise, "ct": N}; OFFSETS as drop.sh's --offsets.
check() {
  python3 "$repo/tools/m2/matrix.py" one --slot "$slot" --campaign "$campaign" --run "$1" \
    --bw 100 --rtt "$rtt" --queue-bdp 40 --duration 30 --bytes 5000000 --extra-capture "${@:3}" >/dev/null
  local rd=/data/m2/$campaign/$1
  local rcv_ip
  rcv_ip=$(docker run --rm --name "$job-drops-$$" -v "$volume:/data:ro" "$image" \
    python3 -c "import json; print(json.load(open('$rd/meta.json'))['rcv_ip'])")
  local t1 t2 out
  t1=$(python3 -c 'import json, sys; w = json.loads(sys.argv[1]); print(w["r1"][0] if w.get("r1") else "")' "$2")
  t2=$(python3 -c 'import json, sys; w = json.loads(sys.argv[1]); print(w["r2"][0] if w.get("r2") else "")' "$2")
  out=$(docker run --rm --name "$job-drops-$$" --cpuset-cpus 16-31 -v "$volume:/data" -v "$repo:/utcp:ro" "$image" \
    bash -c "python3 -I /utcp/tools/m2/dropcheck.py $rd/r1-in.pcap $rd/r1-out.pcap $rcv_ip 5201 ${t1:+--targets $t1} > $rd/drop-r1.json
             python3 -I /utcp/tools/m2/dropcheck.py $rd/r1-out.pcap $rd/r2-out.pcap $rcv_ip 5201 ${t2:+--targets $t2} > $rd/drop-r2.json
             python3 -I -c '
import json, re, sys
sys.path.insert(0, \"/utcp/tools/m2\")
from dropcheck import target_ranges
d = {r: json.load(open(\"$rd/drop-%s.json\" % r)) for r in (\"r1\", \"r2\")}
want = json.loads(sys.argv[1])
ok, exp, got, lat, armed = True, {}, {}, {}, {}
for r in (\"r1\", \"r2\"):
    got[r] = sorted((m[\"offset\"], m[\"copy\"]) for m in d[r][\"missing\"])
    if want.get(r):
        spec, copies = want[r]
        lat[r] = d[r][\"latched\"]
        # The watcher armed within one RTT (20 ms) of the SYN, before the
        # first data segment can reach the router.
        m = re.search(r\"armed ([0-9.]+) ms after it [(]nft rc 0[)]\", open(\"$rd/drop-%s.log\" % r).read())
        armed[r] = float(m.group(1)) if m else None
        ok = ok and armed[r] is not None and armed[r] < $rtt
        # Every target latched its N segments (a target that never came
        # would otherwise pass with nothing dropped).
        ok = ok and [len(x) for x in lat[r]] == [n for _, _, n in target_ranges(spec)]
        exp[r] = sorted((x, k) for xs in lat[r] for x in xs for k in copies)
    elif r == \"r1\" and want.get(\"ct\"):
        got[r] = [m[\"index\"] for m in d[r][\"missing\"]]
        exp[r] = [want[\"ct\"]]
        # The dropped packet must be a first transmission of data.
        ok = ok and all(m[\"copy\"] == 1 and m[\"len\"] > 0 for m in d[r][\"missing\"])
    else:
        exp[r] = []
    ok = ok and got[r] == exp[r]
# Both routers armed at the same offsets latch the same segments.
if want.get(\"r1\") and want.get(\"r2\") and want[\"r1\"][0] == want[\"r2\"][0]:
    ok = ok and lat[\"r1\"] == lat[\"r2\"]
print(json.dumps({\"isn\": d[\"r1\"][\"isn\"], \"r1_in\": d[\"r1\"][\"before\"], \"r1_out\": d[\"r1\"][\"after\"],
                  \"r2_out\": d[\"r2\"][\"after\"], \"latched\": lat, \"armed_ms\": armed, \"r1_dropped\": d[\"r1\"][\"missing\"],
                  \"r2_dropped\": d[\"r2\"][\"missing\"]}))
print(\"PASS\" if ok else \"FAIL expected %s got %s latched %s armed %s ms\" % (exp, got, lat, armed))
' '$2'")
  echo "== $1: $(tail -1 <<<"$out")"
  head -1 <<<"$out"
  [[ $(tail -1 <<<"$out") == PASS ]] || fail=1
}

c=/data/m2/$campaign
check copy1 "{\"r1\": [\"$off\", [1]]}" \
  --drop "arm --router r1 --offsets $off --copies 1 --log $c/copy1/drop-r1.log"
check copy2 "{\"r1\": [\"$off\", [2]], \"r2\": [\"$off\", [1]]}" \
  --drop "arm --router r1 --offsets $off --copies 2 --log $c/copy2/drop-r1.log" \
  --drop "arm --router r2 --offsets $off --copies 1 --log $c/copy2/drop-r2.log"
check copy12 "{\"r1\": [\"$off\", [1, 2]]}" \
  --drop "arm --router r1 --offsets $off --copies 1,2 --log $c/copy12/drop-r1.log"
check mid "{\"r1\": [\"$((off + 700))\", [1]]}" \
  --drop "arm --router r1 --offsets $((off + 700)) --copies 1 --log $c/mid/drop-r1.log"
check burst "{\"r1\": [\"$((2 * off)):5\", [1]]}" \
  --drop "arm --router r1 --offsets $((2 * off)):5 --copies 1 --log $c/burst/drop-r1.log"
check ct "{\"ct\": 500}" --drop "ct --router r1 --packet 500"
echo "m2_testbed_drops: $( ((fail)) && echo FAIL || echo PASS)"
exit "$fail"
