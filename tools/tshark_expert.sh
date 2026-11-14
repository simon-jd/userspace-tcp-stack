#!/usr/bin/env bash
# Runs `tshark -q -z expert` on simulator pcaps (DESIGN §7.4).
#
# Usage: tools/tshark_expert.sh DIR...
#   Each DIR is a sweep output directory, a samples/ or failures/ directory,
#   or one seed-N directory (utcp-sim --pcap DIR writes DIR/seed-N/). Every
#   seed directory with a scenario.txt is checked: its *.egress.pcap files
#   always, its *.ingress.pcap files only if the scenario has no bit flips
#   and no garbage (impairment produces malformed frames on ingress by
#   design).
#
# Only the layers the stack produces are dissected (raw IP, IPv4, ICMP, TCP,
# UDP; payload as data), with the IPv4, TCP and UDP checksums validated. The
# payload is the simulator's byte pattern: with every dissector on, TShark
# decodes it by port and heuristics (the IPA dissector claims TCP port 5000,
# the workload's first server port) and reports Malformed errors in RSL,
# A-bis OML, GSM DTAP and others (docs/SIM-BUGS.md, tshark expert analysis).
#
# Fails (exit 1) on any Error-severity expert item or a file tshark cannot
# read; tallies Warning-severity items by protocol and summary. Exit 2 on
# usage errors or when tshark is missing.
set -euo pipefail

tshark_args=(-n --only-protocols frame,raw,ip,icmp,tcp,udp,data
  -o ip.check_checksum:TRUE -o tcp.check_checksum:TRUE -o udp.check_checksum:TRUE)

if (($# == 0)); then
  echo "usage: $0 DIR..." >&2
  exit 2
fi
if ! command -v tshark >/dev/null; then
  echo "tshark_expert: tshark not found (use the testbed image)" >&2
  exit 2
fi

# True if scenario file $1 has a non-zero bitflip_ppm or garbage_ppm.
impaired() {
  grep -Eq '^link\.[0-9]+\.(bitflip_ppm|garbage_ppm)=[1-9]' "$1"
}

files=0
skipped=0
failed=0
warnings=$(mktemp)
trap 'rm -f "$warnings"' EXIT

while IFS= read -r -d '' scenario; do
  dir=$(dirname "$scenario")
  pcaps=("$dir"/*.egress.pcap)
  if impaired "$scenario"; then
    skipped=$((skipped + $(find "$dir" -maxdepth 1 -name '*.ingress.pcap' | wc -l)))
  else
    pcaps+=("$dir"/*.ingress.pcap)
  fi
  for f in "${pcaps[@]}"; do
    [[ -e $f ]] || continue
    files=$((files + 1))
    if ! out=$(tshark "${tshark_args[@]}" -r "$f" -q -z expert 2>&1); then
      echo "tshark_expert: $f: tshark failed:"
      echo "$out"
      failed=1
      continue
    fi
    # Sections are "Errors (N)", "Warns (N)", "Notes (N)", "Chats (N)" (as
    # TShark 4.6 prints them; "Warnings (N)" is accepted too), each followed
    # by a ruler, a header line and one line per item: frequency, group,
    # protocol, summary.
    errors=$(awk '/^Errors \(/ { sub(/^Errors \(/, ""); sub(/\).*/, ""); print; exit }' <<<"$out")
    if [[ -n $errors && $errors != 0 ]]; then
      echo "tshark_expert: $f: $errors Error-severity item(s):"
      awk '/^Errors \(/ { on = 1; next } /^[A-Z][a-z]+ \(/ { on = 0 } on' <<<"$out"
      failed=1
    fi
    awk '/^(Warns|Warnings) \(/ { on = 1; next } /^[A-Z][a-z]+ \(/ { on = 0 }
         on && $1 ~ /^[0-9]+$/ { n = $1; $1 = ""; sub(/^ +/, ""); print n "\t" $0 }' \
      <<<"$out" >>"$warnings"
  done
done < <(find "$@" -name scenario.txt -print0 | sort -z)

if ((files == 0)); then
  echo "tshark_expert: no pcaps found under $*" >&2
  exit 1
fi
echo "tshark_expert: $files file(s) checked, $skipped ingress file(s) of impaired seeds skipped"
if [[ -s $warnings ]]; then
  echo "Warnings (count, group protocol summary):"
  awk -F'\t' '{ c[$2] += $1 } END { for (k in c) printf "%8d  %s\n", c[k], k }' "$warnings" |
    sort -rn
fi
if ((failed)); then
  echo "tshark_expert: FAILED"
  exit 1
fi
echo "tshark_expert: ok (no Error-severity items)"
