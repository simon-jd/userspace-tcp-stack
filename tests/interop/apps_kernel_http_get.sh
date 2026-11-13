#!/usr/bin/env bash
# m1-apps acceptance test 3 (utcp-http-get --backend kernel, over loopback in
# one container on CPUs 16-31): the body's SHA-256 equals sha256sum of the
# served file when fetched from nginx (Content-Length) and from
# chunked_server.py (chunked with extensions and trailers, read-to-close, and
# chunked after a 100 Continue); a 3xx is an error. Extras: the -o file, a
# name resolved through --dns (chunked_server.py's stub DNS) and --resolve.
# Usage: tests/interop/apps_kernel_http_get.sh   (see apps_kernel_common.sh)
source "$(dirname "${BASH_SOURCE[0]}")/apps_kernel_common.sh"
build_apps

run_in_container http-get "$container_lib"'
mkdir -p /tmp/www
head -c 50000000 /dev/urandom > /tmp/www/big.bin
head -c 1234567 /dev/urandom > /tmp/www/mid.bin
printf x > /tmp/www/one.bin
: > /tmp/www/empty.bin
cat > /tmp/nginx.conf <<"NG"
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
  server { listen 8080; root /tmp/www; }
}
NG
nginx -c /tmp/nginx.conf || fail nginx "did not start"
python3 -I /src/tests/interop/chunked_server.py --port 8081 --root /tmp/www --dns-port 53 > /tmp/cs.log 2>&1 &
wait_port 8080 || fail nginx "not listening"
wait_port 8081 || fail chunked_server "not listening"
wait_port 53 udp || fail dns "stub DNS not listening on port 53"
G=$B/apps/utcp-http-get/utcp-http-get
cd /tmp
js() { python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d.get(sys.argv[2]))" "$1" "$2"; }

# get NAME URL FILE [ARGS...]: fetch, compare with sha256sum of FILE.
get() {
  local name=$1 url=$2 file=$3; shift 3
  local out rc
  out=$($G --backend kernel "$url" -o /tmp/body "$@" 2>/tmp/err); rc=$?
  local want have outsha; want=$(sha256sum < "$file" | cut -d" " -f1)
  have=$(js "$out" sha256); outsha=$(sha256sum < /tmp/body | cut -d" " -f1)
  if [[ $rc == 0 && $have == "$want" && $outsha == "$want" ]]; then
    pass "$name sha256 $have ($(js "$out" bytes) bytes, framing $(js "$out" framing), trailers $(js "$out" trailers))"
  else fail "$name" "exit $rc, sha256 $have / file $outsha, want $want: $out $(cat /tmp/err)"; fi
}

for f in big.bin mid.bin one.bin empty.bin; do
  get "nginx $f" http://127.0.0.1:8080/$f www/$f
done
for f in big.bin mid.bin one.bin empty.bin; do
  get "chunked $f" http://127.0.0.1:8081/chunked/$f www/$f
  get "read-to-close $f" http://127.0.0.1:8081/close/$f www/$f
done
get "100 Continue then chunked" http://127.0.0.1:8081/continue/mid.bin www/mid.bin
out=$($G --backend kernel http://127.0.0.1:8081/chunked/one.bin 2>/dev/null)
[[ $(js "$out" trailers) == 2 ]] && pass "chunked trailers kept (2)" || fail trailers "$out"

out=$($G --backend kernel http://127.0.0.1:8081/redirect/one.bin 2>/tmp/err); rc=$?
if [[ $rc != 0 ]] && grep -q "redirect 302" /tmp/err; then pass "3xx is an error (exit $rc: $(tail -1 /tmp/err))"
else fail 3xx "exit $rc: $out $(cat /tmp/err)"; fi
out=$($G --backend kernel http://127.0.0.1:8080/missing 2>/tmp/err); rc=$?
[[ $rc != 0 && $(js "$out" status) == 404 ]] && pass "404 exits non-zero" || fail 404 "exit $rc $out"

get "--resolve" http://files.test:8080/mid.bin www/mid.bin --resolve files.test:127.0.0.1
get "--dns (A query to the stub on 127.0.0.1:53)" http://files.example:8080/mid.bin www/mid.bin --dns 127.0.0.1
nginx -c /tmp/nginx.conf -s stop
' | summarize
