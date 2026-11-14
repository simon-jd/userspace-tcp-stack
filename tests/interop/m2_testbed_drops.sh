#!/usr/bin/env bash
# Verifies the scripted-drop mechanism of testbed/m2/drop.sh (M2-TASKS
# m2d-testbed test 10, DESIGN §14) on a non-timing instance, with the Linux
# sender (CUBIC), 100 Mbit/s, 20 ms, a 40xBDP queue (no tbf drops), no netem
# loss, 5 MB per run:
#   copy1:  r1 drops copy 1 of offset 1448000 (the original);
#   copy2:  r1 drops copy 2 of offset 1448000 and r2 drops copy 1, so that a
#           copy 2 exists: r1 loses exactly copy 2, r2 exactly copy 1;
#   copy12: r1 drops copies 1 and 2 (a lost retransmission);
#   ct:     r1 drops `ct original packets 500` (a first transmission).
# For each, tools/m2/dropcheck.py lists what r1 dropped (r1-in vs r1-out) and,
# for copy2, what r2 dropped (r1-out vs r2-out); the script checks that the
# list is exactly the intended packets. Prints PASS/FAIL per case; exit 1 if
# any failed. Outputs under /data/m2/<campaign>/ in the utcp-data volume.
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
off=1448000
fail=0

check() {
  python3 "$repo/tools/m2/matrix.py" one --slot "$slot" --campaign "$campaign" --run "$1" \
    --bw 100 --rtt 20 --queue-bdp 40 --duration 30 --bytes 5000000 --extra-capture "${@:3}" >/dev/null
  local rd=/data/m2/$campaign/$1
  local rcv_ip
  rcv_ip=$(docker run --rm --name "$job-drops-$$" -v "$volume:/data:ro" "$image" \
    python3 -c "import json; print(json.load(open('$rd/meta.json'))['rcv_ip'])")
  local out
  out=$(docker run --rm --name "$job-drops-$$" --cpuset-cpus 16-31 -v "$volume:/data" -v "$repo:/utcp:ro" "$image" \
    bash -c "python3 -I /utcp/tools/m2/dropcheck.py $rd/r1-in.pcap $rd/r1-out.pcap $rcv_ip 5201 > $rd/drop-r1.json
             python3 -I /utcp/tools/m2/dropcheck.py $rd/r1-out.pcap $rd/r2-out.pcap $rcv_ip 5201 > $rd/drop-r2.json
             python3 -I -c '
import json, sys
r1 = json.load(open(\"$rd/drop-r1.json\")); r2 = json.load(open(\"$rd/drop-r2.json\"))
want = json.loads(sys.argv[1])
got = {\"r1\": [(m[\"offset\"], m[\"copy\"]) if want[\"by\"] == \"seq\" else m[\"index\"] for m in r1[\"missing\"]],
       \"r2\": [(m[\"offset\"], m[\"copy\"]) for m in r2[\"missing\"]]}
exp = {\"r1\": [tuple(x) if isinstance(x, list) else x for x in want[\"r1\"]],
       \"r2\": [tuple(x) for x in want[\"r2\"]]}
print(json.dumps({\"isn\": r1[\"isn\"], \"r1_in\": r1[\"before\"], \"r1_out\": r1[\"after\"],
                  \"r2_out\": r2[\"after\"], \"r1_dropped\": r1[\"missing\"], \"r2_dropped\": r2[\"missing\"]}))
print(\"PASS\" if got == exp else \"FAIL expected %s got %s\" % (exp, got))
' '$2'")
  echo "== $1: $(tail -1 <<<"$out")"
  head -1 <<<"$out"
  [[ $(tail -1 <<<"$out") == PASS ]] || fail=1
}

check copy1 "{\"by\": \"seq\", \"r1\": [[$off, 1]], \"r2\": []}" \
  --drop "arm --router r1 --offsets $off --copies 1 --log /data/m2/$campaign/copy1/drop-r1.log"
check copy2 "{\"by\": \"seq\", \"r1\": [[$off, 2]], \"r2\": [[$off, 1]]}" \
  --drop "arm --router r1 --offsets $off --copies 2 --log /data/m2/$campaign/copy2/drop-r1.log" \
  --drop "arm --router r2 --offsets $off --copies 1 --log /data/m2/$campaign/copy2/drop-r2.log"
check copy12 "{\"by\": \"seq\", \"r1\": [[$off, 1], [$off, 2]], \"r2\": []}" \
  --drop "arm --router r1 --offsets $off --copies 1,2 --log /data/m2/$campaign/copy12/drop-r1.log"
check ct "{\"by\": \"index\", \"r1\": [500], \"r2\": []}" --drop "ct --router r1 --packet 500"
echo "m2_testbed_drops: $( ((fail)) && echo FAIL || echo PASS)"
exit "$fail"
