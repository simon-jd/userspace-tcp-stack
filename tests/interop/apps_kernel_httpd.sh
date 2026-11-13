#!/usr/bin/env bash
# m1-apps acceptance test 2 (utcp-httpd --backend kernel, curl as the client,
# over loopback in one container on CPUs 16-31): a 100 MB random file, a
# 1-byte file and an empty file downloaded with sha256sum equal; HEAD; 404;
# paths escaping the root rejected (curl --path-as-is, also percent-encoded),
# and symbolic links out of the root answered 404 while one inside is served;
# `curl URL1 URL2` reuses one connection; 405, 414 and 505 as extras.
# Usage: tests/interop/apps_kernel_httpd.sh   (see apps_kernel_common.sh)
source "$(dirname "${BASH_SOURCE[0]}")/apps_kernel_common.sh"
build_apps

run_in_container httpd "$container_lib"'
mkdir -p /tmp/www/sub
head -c 100000000 /dev/urandom > /tmp/www/big.bin
printf x > /tmp/www/one.txt
: > /tmp/www/empty.txt
echo "<p>index</p>" > /tmp/www/sub/index.html
echo secret > /tmp/secret.txt
ln -s ../secret.txt /tmp/www/out_rel.txt
ln -s /tmp/secret.txt /tmp/www/out_abs.txt
ln -s one.txt /tmp/www/in.txt
$B/apps/utcp-httpd/utcp-httpd --backend kernel --listen 8080 --root /tmp/www --log > /tmp/httpd.out 2> /tmp/httpd.err &
hpid=$!
wait_port 8080 || fail start "utcp-httpd did not listen"
u=http://127.0.0.1:8080
cd /tmp
for f in big.bin one.txt empty.txt; do
  rm -f got
  code=$(curl -s -o got -w "%{http_code}" $u/$f)
  want=$(sha256sum < www/$f | cut -d" " -f1); have=$(sha256sum < got | cut -d" " -f1)
  if [[ $code == 200 && $want == "$have" ]]; then pass "GET $f sha256 $have ($(stat -c %s got) bytes)"
  else fail "GET $f" "status $code, sha256 $have, want $want"; fi
done
code=$(curl -s -o got -w "%{http_code}" $u/sub/); grep -q index got && [[ $code == 200 ]] && pass "GET directory index" || fail "GET directory index" "status $code"

h=$(curl -sI $u/big.bin | tr -d "\r")
if grep -q "^HTTP/1.1 200" <<<"$h" && grep -qi "^content-length: 100000000$" <<<"$h"; then pass "HEAD big.bin (200, Content-Length 100000000, no body)"
else fail HEAD "$h"; fi
n=$( { printf "HEAD /one.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"; sleep 0.5; } | nc -q1 127.0.0.1 8080 | wc -c)
h1=$( { printf "HEAD /one.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"; sleep 0.5; } | nc -q1 127.0.0.1 8080 | tail -c 4 | od -An -c | tr -d " ")
[[ $h1 == "\r\n\r\n" ]] && pass "HEAD sends the head only ($n bytes, ends with the empty line)" || fail "HEAD body" "$n bytes, ends with $h1"

code=$(curl -s -o /dev/null -w "%{http_code}" $u/missing.txt); [[ $code == 404 ]] && pass "404 for a missing file" || fail 404 "status $code"
for p in "/../secret.txt" "/sub/../../secret.txt" "/%2e%2e/secret.txt" "/sub/%2E%2E/%2e%2e/secret.txt" "/..%2fsecret.txt"; do
  rm -f got
  code=$(curl -s --path-as-is -o got -w "%{http_code}" "$u$p")
  if [[ $code == 400 ]] && ! grep -q secret got; then pass "escaping path $p rejected (400)"
  else fail "escaping path $p" "status $code, body $(head -c 40 got)"; fi
done
for p in /out_rel.txt /out_abs.txt; do
  rm -f got
  code=$(curl -s -o got -w "%{http_code}" "$u$p")
  if [[ $code == 404 ]] && ! grep -q secret got; then pass "symlink out of the root $p rejected (404)"
  else fail "symlink $p" "status $code, body $(head -c 40 got)"; fi
done
code=$(curl -s -o got -w "%{http_code}" $u/in.txt)
[[ $code == 200 && $(cat got) == x ]] && pass "symlink inside the root served" || fail "symlink inside" "status $code"

out=$(curl -s -o /dev/null -o /dev/null -w "%{num_connects}\n" $u/one.txt $u/empty.txt | tr "\n" " ")
[[ $out == "1 0 " ]] && pass "two URLs on one connection (num_connects $out)" || fail "connection reuse" "num_connects $out"
v=$(curl -sv -o /dev/null -o /dev/null $u/one.txt $u/empty.txt 2>&1 | grep -ciE "re-?using (existing|connection)")
[[ $v -ge 1 ]] && pass "curl -v reports the reuse ($v)" || fail "curl -v reuse" "no reuse line"

code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d x $u/one.txt); [[ $code == 405 ]] && pass "405 for POST" || fail 405 "status $code"
long=$(head -c 9000 /dev/zero | tr "\0" a)
code=$(curl -s -o /dev/null -w "%{http_code}" "$u/$long"); [[ $code == 414 ]] && pass "414 for a 9000-byte target" || fail 414 "status $code"
r=$( { printf "GET /one.txt HTTP/2.0\r\nHost: x\r\n\r\n"; sleep 0.5; } | nc -q1 127.0.0.1 8080 | head -1 | tr -d "\r")
[[ $r == "HTTP/1.1 505 HTTP Version Not Supported" ]] && pass "505 for HTTP/2.0 in a request line" || fail 505 "$r"
r=$( { printf "GET /one.txt HTTP/1.1\r\nHost: x\r\n\r\nGET /empty.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"; sleep 0.5; } | nc -q1 127.0.0.1 8080 | grep -o "HTTP/1.1 200" | wc -l)
[[ $r == 2 ]] && pass "two pipelined requests answered in order" || fail pipelining "$r responses"

kill -TERM $hpid; wait $hpid
cat /tmp/httpd.out
' | summarize
