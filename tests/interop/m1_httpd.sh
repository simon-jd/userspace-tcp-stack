#!/usr/bin/env bash
# M1 interop acceptance test D (docs/INTEROP.md): curl on the Linux peer
# downloads files from utcp-httpd on the stack (utcp-m1-dut, --backend utcp,
# profile linux), on the testbed of testbed/m1.
#
#   D-N0-100M, D-N0-1B, D-N0-0B   100 MB, 1-byte and empty file under N0
#   D-N4-100M, D-N4-1B, D-N4-0B   the same under N4
#
# The files are made in the DUT (/srv/www: 100 MB from /dev/urandom, "x",
# empty) and their SHA-256 taken there with sha256sum. utcp-httpd runs once
# per case with --stats; curl's body goes through sha256sum on the peer.
# Each case: record.sh before and after, captures of the peer's interface
# and utcp0 (port 80), one row (m1_row.py). Default peer (combo.sh default).
#
# Usage: tests/interop/m1_httpd.sh [PATTERN...]  (list: print the cases)
# Needs: testbed/m1/build.sh gcc-release utcp-httpd. Starts the testbed if
# needed and leaves it running. Exit status 1 if any case failed.
source "$(dirname "${BASH_SOURCE[0]}")/m1_lib.sh"

stack_ip=$tb_tun_stack
www=/srv/www

all_cases() {
  local n f
  for n in N0 N4; do
    for f in 100M 1B 0B; do echo "D-$n-$f"; done
  done
}

make_files() {
  tb_sh "$tb_dut" "
    mkdir -p $www
    [[ -s $www/big.bin ]] || head -c 100000000 /dev/urandom > $www/big.bin
    printf x > $www/one.bin
    : > $www/empty.bin
    cd $www && sha256sum big.bin one.bin empty.bin
  " >"$M1_RESULTS/files.sha256"
}

file_sha() { awk -v f="$1" '$2 == f {print $1}' "$M1_RESULTS/files.sha256"; }

httpd_case() {
  local c=$1
  local netem=${c#D-}
  netem=${netem%%-*}
  local which=${c##*-} file bytes_n
  case $which in
    100M) file=big.bin bytes_n=100000000 ;;
    1B) file=one.bin bytes_n=1 ;;
    0B) file=empty.bin bytes_n=0 ;;
  esac
  m1_peer_for default
  m1_pmtu down
  m1_case_dir "$c"
  local r=$M1_RESULTS/$c
  m1_netem "$netem" >"$r/netem.txt" 2>&1
  local metrics
  metrics=$(m1_metrics_count)
  m1_log "$c: curl http://$stack_ip/$file under $netem metrics=$metrics"
  m1_record "$c" before
  m1_cap_start "$c" peer "$tb_peer" "$tb_peer_ip" "tcp port 80 or icmp" || return 1
  m1_cap_start "$c" utcp0 "$tb_dut" "$tb_tun" "tcp port 80 or icmp" || return 1
  tb_exec "$tb_dut" rm -f /run/utcp-stats.json
  tb_exec "$tb_dut" "$m1_bin/apps/utcp-httpd/utcp-httpd" --backend utcp --listen 80 --root "$www" \
    --log --stats /run/utcp-stats.json >"$r/httpd.out" 2>"$r/httpd.err" &
  local hpid=$!
  local i
  for i in $(seq 50); do
    grep -q 'serving' "$r/httpd.err" && break
    sleep 0.1
  done
  # curl: body through sha256sum; status, size and time on stderr.
  tb_exec "$tb_peer" bash -c "set -o pipefail; timeout 600 curl -sS -o - \
      -w '%{stderr}%{http_code} %{size_download} %{time_total} %{num_connects}\n' \
      http://$stack_ip/$file | sha256sum" >"$r/curl.sha" 2>"$r/curl.meta"
  local crc=$?
  sleep 1
  tb_exec "$tb_dut" pkill -TERM -f "$m1_bin/apps/utcp-httpd/utcp-httpd"
  wait "$hpid"
  local hrc=$?
  sleep 1
  m1_record "$c" after
  m1_cap_stop "$c" peer
  m1_cap_stop "$c" utcp0
  tb_exec "$tb_dut" cat /run/utcp-stats.json >"$r/stack-stats.json" 2>/dev/null
  m1_analyze "$c" peer "$stack_ip"
  m1_analyze "$c" utcp0 "$stack_ip"
  local want have meta
  want=$(file_sha "$file")
  have=$(awk '{print $1}' "$r/curl.sha")
  meta=$(tail -1 "$r/curl.meta")
  python3 -I - "$r" "$metrics" "$crc" "$hrc" "$want" "$have" "$meta" <<'PY'
import json, sys
r, metrics, crc, hrc, want, have, meta = sys.argv[1:8]
m = meta.split()
json.dump({"metrics_before": int(metrics), "curl_exit": int(crc), "httpd_exit": int(hrc),
           "sha_file": want, "sha_curl": have,
           "http_code": int(m[0]) if len(m) > 0 and m[0].isdigit() else None,
           "size_download": int(m[1]) if len(m) > 1 and m[1].isdigit() else None,
           "time_total_s": float(m[2]) if len(m) > 2 else None},
          open(f"{r}/extra.json", "w"))
PY
  m1_row "$c" "test=D" "direction=stack->Linux" "options=curl GET /$file" "impairment=$netem" \
    "bytes_n=$bytes_n" "peer_sysctls=$(m1_peer_sysctls)" "cpus=$tb_cpus" \
    "captures=$m1_volume:/$m1_voldir/$c/{peer,utcp0}.pcap" \
    "check:extra['curl_exit']==0 and extra['httpd_exit']==0" \
    "check:extra['sha_file']!='' and extra['sha_file']==extra['sha_curl']" \
    "check:extra['http_code']==200 and extra['size_download']==$bytes_n" \
    "check:extra['metrics_before']==0" \
    "check:pcap['peer']['by']['stack']['rst_open']==0 and pcap['peer']['by']['remote']['rst_open']==0" \
    "check:fin_ok('peer')" \
    "check:peer['TcpExtTCPSACKDiscard']==0 and peer['TcpExtTCPSACKReneging']==0"
}

if [[ ${1:-} == list ]]; then
  all_cases
  exit 0
fi
m1_need_programs apps/utcp-httpd/utcp-httpd
patterns=("$@")
((${#patterns[@]})) || patterns=('*')
m1_testbed_up
make_files
status=0
while read -r c; do
  for p in "${patterns[@]}"; do
    # shellcheck disable=SC2053
    if [[ $c == $p ]]; then
      httpd_case "$c" || status=1
      break
    fi
  done
done < <(all_cases)
m1_netem N0 >/dev/null
exit "$status"
