#!/usr/bin/env bash
# M1 interop acceptance test E (docs/INTEROP.md): utcp-http-get on the stack
# (utcp-m1-dut, --backend utcp, profile linux) against
#   E-nginx      nginx on the Linux peer, a 100 MB file
#   E-chunked    tests/interop/chunked_server.py on the peer (chunked framing
#                with extensions and trailers), a 10 MB file
#   E-<site>     the public candidates deb.debian.org, archive.ubuntu.com,
#                neverssl.com, example.com and httpforever.com, through the
#                DUT's NAT (testbed/m1/nat.sh)
# Each download is compared with kernel curl fetching the same URL at the
# same time in the DUT (SHA-256 and length of the body). Public sites: the
# URL is first checked with kernel `curl -sI` in the DUT for a 200 without a
# redirect to HTTPS (up to 3 tries, 5 s apart); a candidate that fails is
# recorded as replaced and the next unused replacement site (info.cern.ch,
# captive.apple.com) is fetched in its place under its own case name; and
# the name is resolved over the stack's UDP with --dns set to the host's
# upstream resolver through the NAT (nat.sh's choice, /run/utcp-m1-dns in the
# DUT); if that fails, the run is repeated with --resolve and an address from
# the DUT's resolver, and the row says so. Public sites cross the host's
# Wi-Fi path: their rows report only whether the download interoperated.
#
# Usage: tests/interop/m1_http_get.sh [PATTERN...]  (list: print the cases)
# Needs: testbed/m1/build.sh gcc-release utcp-http-get. Starts the testbed if
# needed and leaves it running (NAT off at the end). Exit status 1 if any case failed.
source "$(dirname "${BASH_SOURCE[0]}")/m1_lib.sh"

stack_ip=$tb_tun_stack
www=/srv/www

# name URL for the public candidates.
public_sites=(
  "deb.debian.org http://deb.debian.org/debian/README"
  "archive.ubuntu.com http://archive.ubuntu.com/ubuntu/dists/noble/Release"
  "neverssl.com http://neverssl.com/"
  "example.com http://example.com/"
  "httpforever.com http://httpforever.com/"
)

# Replacements for a candidate that fails the precheck, in order of use.
replacement_sites=(
  "info.cern.ch http://info.cern.ch/"
  "captive.apple.com http://captive.apple.com/"
)

all_cases() {
  echo E-nginx
  echo E-chunked
  local s
  for s in "${public_sites[@]}"; do echo "E-${s%% *}"; done
}

# For m1_matrix.sh: the replacement cases, marked optional with a trailing '?'.
optional_cases() {
  local s
  for s in "${replacement_sites[@]}"; do echo "E-${s%% *}?"; done
}

peer_servers() {
  tb_sh "$tb_peer" "
    mkdir -p $www
    [[ -s $www/big.bin ]] || head -c 100000000 /dev/urandom > $www/big.bin
    [[ -s $www/ten.bin ]] || head -c 10000000 /dev/urandom > $www/ten.bin
    cat > /tmp/nginx.conf <<'NG'
worker_processes 1;
pid /tmp/nginx.pid;
error_log /tmp/nginx.err;
events { worker_connections 64; }
http {
  access_log off;
  client_body_temp_path /tmp/nginx-body;
  proxy_temp_path /tmp/nginx-proxy;
  fastcgi_temp_path /tmp/nginx-fcgi;
  uwsgi_temp_path /tmp/nginx-uwsgi;
  scgi_temp_path /tmp/nginx-scgi;
  server { listen 8080; root $www; }
}
NG
    pgrep -x nginx >/dev/null || nginx -c /tmp/nginx.conf
    # (pgrep -f would match this bash, whose command line names the script.)
    if ! ss -Hltn 'sport = :8081' | grep -q .; then
      nohup python3 -I /utcp/tests/interop/chunked_server.py --port 8081 --root $www > /tmp/cs.log 2>&1 &
    fi
    for i in \$(seq 50); do
      ss -Hltn 'sport = :8080' | grep -q . && ss -Hltn 'sport = :8081' | grep -q . && break
      sleep 0.1
    done
    cd $www && sha256sum big.bin ten.bin
  " >"$M1_RESULTS/peer-files.sha256"
}

stop_peer_servers() {
  tb_sh "$tb_peer" "nginx -c /tmp/nginx.conf -s stop 2>/dev/null; pkill -f '^python3 -I /utcp/tests/interop/chunked_server.py'; true"
}

# get_case CASE URL TEST_KIND [EXTRA ARGS FOR utcp-http-get]
get_case() {
  local c=$1 url=$2 kind=$3
  shift 3
  m1_case_dir "$c"
  local r=$M1_RESULTS/$c
  m1_netem N0 >"$r/netem.txt" 2>&1
  local metrics
  metrics=$(m1_metrics_count)
  m1_log "$c: utcp-http-get $url $*"
  m1_record "$c" before
  m1_cap_start "$c" utcp0 "$tb_dut" "$tb_tun" "tcp or udp port 53 or icmp" || return 1
  [[ $kind == local ]] && { m1_cap_start "$c" peer "$tb_peer" "$tb_peer_ip" "tcp port 8080 or tcp port 8081 or icmp" || return 1; }
  tb_exec "$tb_dut" rm -f /run/utcp-stats.json
  # Kernel curl in the DUT, at the same time.
  tb_exec "$tb_dut" bash -c "set -o pipefail; timeout 600 curl -sS -o - \
      -w '%{stderr}%{http_code} %{size_download} %{time_total}\n' '$url' | sha256sum" \
    >"$r/curl.sha" 2>"$r/curl.meta" &
  local cpid=$!
  tb_exec "$tb_dut" bash -c "set -o pipefail; timeout 600 $m1_bin/apps/utcp-http-get/utcp-http-get \
      --backend utcp --stats /run/utcp-stats.json --timeout 300 $* -o - '$url' 2>/tmp/get.err \
      | sha256sum > /tmp/get.sha; echo \${PIPESTATUS[0]} > /tmp/get.rc" >"$r/get.out" 2>"$r/get.err"
  wait "$cpid"
  local crc=$?
  tb_exec "$tb_dut" cat /tmp/get.err >"$r/get.stderr"
  local grc gsha
  grc=$(tb_exec "$tb_dut" cat /tmp/get.rc)
  gsha=$(tb_exec "$tb_dut" cat /tmp/get.sha | awk '{print $1}')
  sleep 1
  m1_record "$c" after
  m1_cap_stop "$c" utcp0
  [[ $kind == local ]] && m1_cap_stop "$c" peer
  tb_exec "$tb_dut" cat /run/utcp-stats.json >"$r/stack-stats.json" 2>/dev/null
  m1_analyze "$c" utcp0 "$stack_ip"
  [[ $kind == local ]] && m1_analyze "$c" peer "$stack_ip"
  # utcp-http-get writes the body to stdout (-o -) and its JSON summary to
  # stderr then; the body went through sha256sum.
  python3 -I - "$r" "$metrics" "$crc" "$grc" "$gsha" "$*" <<'PY'
import json, sys
r, metrics, crc, grc, gsha, args = sys.argv[1:7]
m = open(f"{r}/curl.meta").read().split()
summ = {}
for ln in open(f"{r}/get.stderr"):
    ln = ln.strip()
    if ln.startswith("{"):
        try:
            summ = json.loads(ln)
        except ValueError:
            pass
json.dump({"metrics_before": int(metrics), "curl_exit": int(crc),
           "get_exit": int(grc) if grc.strip().isdigit() else None,
           "sha_get_body": gsha, "sha_curl": open(f"{r}/curl.sha").read().split()[0]
           if open(f"{r}/curl.sha").read().split() else "",
           "curl_http_code": int(m[0]) if m and m[0].isdigit() else None,
           "curl_size": int(m[1]) if len(m) > 1 and m[1].isdigit() else None,
           "get_summary": summ, "get_args": args},
          open(f"{r}/extra.json", "w"))
PY
}

local_case() {
  local c=$1 url kind=local bytes_n opts
  m1_peer_for default
  m1_pmtu down
  "$tb_repo/testbed/m1/nat.sh" off >/dev/null 2>&1
  peer_servers
  if [[ $c == E-nginx ]]; then
    url=http://$tb_peer_ip:8080/big.bin bytes_n=100000000 opts="nginx GET /big.bin"
  else
    url=http://$tb_peer_ip:8081/chunked/ten.bin bytes_n=10000000 opts="chunked_server.py GET /chunked/ten.bin"
  fi
  get_case "$c" "$url" "$kind"
  local want
  want=$(awk -v f="$(basename "$url")" '$2 == f {print $1}' "$M1_RESULTS/peer-files.sha256")
  m1_row "$c" "test=E" "direction=Linux->stack" "options=$opts" "impairment=N0" \
    "bytes_n=$bytes_n" "url=$url" "peer_sysctls=$(m1_peer_sysctls)" "cpus=$tb_cpus" \
    "captures=$m1_volume:/$m1_voldir/$c/{peer,utcp0}.pcap" \
    "check:extra['get_exit']==0 and extra['curl_exit']==0" \
    "check:extra['sha_get_body']=='$want' and extra['sha_curl']=='$want'" \
    "check:extra['get_summary'].get('sha256')=='$want' and extra['get_summary'].get('bytes')==$bytes_n" \
    "check:extra['metrics_before']==0" \
    "check:fin_ok('peer')" \
    "check:peer['TcpExtTCPSACKDiscard']==0 and peer['TcpExtTCPSACKReneging']==0"
}

public_case() {
  local c=$1 name=${1#E-} url="" s
  for s in "${public_sites[@]}" "${replacement_sites[@]}"; do
    [[ ${s%% *} == "$name" ]] && url=${s#* }
  done
  m1_peer_for default
  m1_pmtu down
  "$tb_repo/testbed/m1/nat.sh" on >"$M1_RESULTS/nat-$name.log" 2>&1 || {
    cat "$M1_RESULTS/nat-$name.log"
    return 1
  }
  local dns
  dns=$(tb_exec "$tb_dut" cat /run/utcp-m1-dns)
  # Precheck: kernel curl -sI in the DUT: 200 and no redirect to https.
  local head code loc try
  : >"$M1_RESULTS/precheck-$name.txt"
  for try in 1 2 3; do
    head=$(tb_exec "$tb_dut" curl -sSI -m 15 "$url" 2>&1 | tr -d '\r')
    code=$(echo "$head" | awk 'NR == 1 && /^HTTP/ {print $2}')
    loc=$(echo "$head" | awk 'tolower($1) == "location:" {print $2}')
    { echo "== try $try $(date -Is)"; echo "$head"; } >>"$M1_RESULTS/precheck-$name.txt"
    [[ $code == 200 && $loc != https:* ]] && break
    sleep 5
  done
  if [[ $code != 200 || $loc == https:* ]]; then
    local repl="" used
    for s in "${replacement_sites[@]}"; do
      used=$(grep -c "^E-${s%% *}$" "$M1_RESULTS/.replacements_used" 2>/dev/null)
      if [[ ${used:-0} == 0 && $c != "E-${s%% *}" ]]; then
        repl=E-${s%% *}
        break
      fi
    done
    m1_case_dir "$c"
    echo "{\"precheck_code\": \"$code\", \"precheck_location\": \"$loc\", \"precheck_tries\": 3}" \
      >"$M1_RESULTS/$c/extra.json"
    m1_row "$c" "test=E" "direction=Internet->stack" \
      "options=public candidate; kernel curl -sI precheck failed 3 times (precheck-$name.txt)" \
      "impairment=none (NAT, Wi-Fi)" "url=$url" "replaced_by=${repl:-none left}" "check:False"
    if [[ -n $repl ]]; then
      echo "$repl" >>"$M1_RESULTS/.replacements_used"
      public_case "$repl"
      return
    fi
    return 1
  fi
  get_case "$c" "$url" public --dns "$dns"
  local how="--dns $dns (UDP 53 over the stack, through the NAT)"
  if [[ $(python3 -I -c "import json,sys; print(json.load(open(sys.argv[1]))['get_exit'])" \
    "$M1_RESULTS/$c/extra.json") != 0 ]]; then
    local ip
    ip=$(tb_exec "$tb_dut" getent ahostsv4 "${url#http://}" | awk 'NR == 1 {print $1}')
    ip=${ip:-$(tb_exec "$tb_dut" getent ahostsv4 "$(echo "$url" | cut -d/ -f3)" | awk 'NR == 1 {print $1}')}
    mv "$M1_RESULTS/$c" "$M1_RESULTS/$c-dns-failed"
    get_case "$c" "$url" public --resolve "$(echo "$url" | cut -d/ -f3):$ip"
    how="--resolve (the --dns run failed: $c-dns-failed)"
  fi
  m1_row "$c" "test=E" "direction=Internet->stack" "options=public site; name: $how" \
    "impairment=none (NAT, Wi-Fi)" "url=$url" "cpus=$tb_cpus" \
    "captures=$m1_volume:/$m1_voldir/$c/utcp0.pcap" \
    "check:extra['get_exit']==0 and extra['curl_exit']==0" \
    "check:extra['curl_http_code']==200" \
    "check:extra['sha_get_body']==extra['get_summary'].get('sha256')" \
    "check:extra['sha_get_body']==extra['sha_curl'] and extra['get_summary'].get('bytes')==extra['curl_size']" \
    "check:pcap['utcp0']['by']['stack']['rst_open']==0"
}

if [[ ${1:-} == list ]]; then
  all_cases
  optional_cases
  exit 0
fi
rm -f "$M1_RESULTS/.replacements_used"
m1_need_programs apps/utcp-http-get/utcp-http-get
patterns=("$@")
((${#patterns[@]})) || patterns=('*')
m1_testbed_up
status=0
while read -r c; do
  for p in "${patterns[@]}"; do
    # shellcheck disable=SC2053
    if [[ $c == $p ]]; then
      case $c in
        E-nginx | E-chunked) local_case "$c" || status=1 ;;
        *) public_case "$c" || status=1 ;;
      esac
      break
    fi
  done
done < <(all_cases)
"$tb_repo/testbed/m1/nat.sh" off >/dev/null 2>&1
stop_peer_servers
exit "$status"
