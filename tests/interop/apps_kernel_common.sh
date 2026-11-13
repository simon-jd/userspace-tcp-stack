# Shared by tests/interop/apps_kernel_*.sh (m1-apps acceptance tests, kernel
# backend). Sourced, not run.
#
# Each test runs one container from the testbed image named
# utcp-m1-apps-<test>, with --network none (loopback only), pinned to the
# build CPUs (16-31, non-timing), with the repository mounted read-only at
# /src. The programs come from $UTCP_BUILD (default build/gcc-release),
# built first in a throwaway container as the calling user unless
# UTCP_SKIP_BUILD=1.
#
# Environment: UTCP_IMAGE (utcp-testbed:dev), UTCP_TEST_CPUS (16-31),
# UTCP_PRESET (gcc-release), UTCP_SKIP_BUILD.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
image=${UTCP_IMAGE:-utcp-testbed:dev}
cpus=${UTCP_TEST_CPUS:-16-31}
preset=${UTCP_PRESET:-gcc-release}
build=build/$preset

build_apps() {
  if [[ ${UTCP_SKIP_BUILD:-0} == 1 ]]; then
    return
  fi
  echo "== building $preset (utcp-bulk utcp-echo utcp-httpd utcp-http-get)"
  docker run --rm --name "utcp-m1-apps-build-$$" --cpuset-cpus "$cpus" \
    --user "$(id -u):$(id -g)" -v "$repo:/src" -w /src "$image" bash -c "
      set -e
      nice -n 10 cmake --preset $preset >/dev/null
      nice -n 10 cmake --build --preset $preset --target utcp-bulk utcp-echo utcp-httpd utcp-http-get"
}

# run_in_container NAME SCRIPT: runs SCRIPT with bash in a fresh container;
# $B is the build directory inside it. Output goes to stdout; the verdict
# comes from summarize (a container that fails to start prints no PASS).
run_in_container() {
  local name=utcp-m1-apps-$1 script=$2
  docker rm -f "$name" >/dev/null 2>&1 || true
  # shellcheck disable=SC2064
  trap "docker rm -f $name >/dev/null 2>&1 || true" EXIT
  docker run --rm --name "$name" --network none --cpuset-cpus "$cpus" \
    -v "$repo:/src:ro" -e B="/src/$build" -w /tmp "$image" bash -c "$script" 2>&1 || true
}

# The checks inside the containers print "PASS name" or "FAIL name: why";
# summarize reads that output on stdin and fails if any FAIL or no PASS.
summarize() {
  local out
  out=$(cat)
  printf '%s\n' "$out"
  local pass fail
  pass=$(grep -c '^PASS ' <<<"$out" || true)
  fail=$(grep -c '^FAIL ' <<<"$out" || true)
  echo "== $pass passed, $fail failed"
  [[ $fail -eq 0 && $pass -gt 0 ]]
}

# Shell functions for the container side, prepended to each script.
container_lib='
set -uo pipefail
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: $2"; }
check() { local name=$1; shift; if "$@"; then pass "$name"; else fail "$name" "command failed: $*"; fi; }
# wait_port PORT [udp]: until a socket listens on PORT (5 s). Uses ss, not a
# connection, so a one-connection server (utcp-bulk) is not disturbed.
wait_port() {
  local opt=-Hltn; [[ ${2:-} == udp ]] && opt=-Hlun
  for _ in $(seq 50); do ss $opt "sport = :$1" | grep -q . && return 0; sleep 0.1; done
  return 1
}
'
