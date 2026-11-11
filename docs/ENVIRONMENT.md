# Environment

Everything is built and tested inside one Docker image, `utcp-testbed:dev`,
built from `testbed/Dockerfile`. The same image is the testbed for the
network experiments.

## Host

| | |
|---|---|
| OS | Ubuntu 26.04.1 LTS |
| Kernel | 7.0.0-42-generic (`#42-Ubuntu SMP PREEMPT_DYNAMIC Thu Oct 15 08:06:44 UTC 2026`) |
| CPU | Intel i9-13900K, 32 threads: 0-15 P-core threads, 16-31 E-cores |
| Docker | 29.9.3, containerd image store, cgroup v2, no user namespace remapping |

CPU use: builds, unit tests and CI run on CPUs 16-31 (`--cpuset-cpus 16-31`,
`nice -n 10`, at most 8 jobs). Throughput and latency measurements run in
containers pinned to CPUs 8-15.

## Image

| | |
|---|---|
| Base | `ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c` (index digest; linux/amd64 manifest `sha256:157dc3d6e4a3e4f2c68d12df9df9ed6e808b59af6d4c3757b432b4f519916725`) |
| Built image | `sha256:1f2e71181861a0c4c4921b4689f3fd13f016d6e8f3dedd9efe90f37d366e02c2`, 2.08 GB, built 2026-11-11 |
| Build | `testbed/build-image.sh` (non-interactive apt install, `--no-install-recommends`) |

The base is pinned by digest and GoogleTest by package version. The other
packages come from the 26.04 archive at build time, so a rebuild can pick up
archive updates; the image lists every installed package and version in
`/usr/share/utcp-testbed/packages.txt`. Versions in the image above:

| Package | Version |
|---|---|
| gcc-15, g++-15, libstdc++-15-dev | 15.2.0-16ubuntu1 |
| clang-21, libclang-rt-21-dev (sanitizer and libFuzzer runtimes), llvm-21 | 1:21.1.8-6ubuntu1 |
| binutils | 2.46-3ubuntu2 |
| cmake | 4.2.3-2ubuntu2 |
| ninja-build | 1.13.2-1 |
| googletest (pinned) | 1.17.0-1build1 |
| iperf3 | 3.20-2 |
| tcpdump | 4.99.6-1 |
| tshark | 4.6.4-1 |
| nginx | 1.28.3-2ubuntu1.12 |
| iproute2 (ip, tc, ss) | 6.19.0-1ubuntu1.1 |
| ethtool | 1:6.19-1 |
| iputils-ping | 3:20250605-1ubuntu1 |
| curl | 8.18.0-1ubuntu2.8 |
| netcat-openbsd | 1.234-1 |
| python3, python3-numpy, python3-matplotlib | 3.14.3-0ubuntu2, 1:2.3.5+ds-3ubuntu1, 3.10.7+dfsg1-2build1 |
| procps | 2:4.0.4-9ubuntu1 |
| git | 1:2.53.0-1ubuntu1.1 |

libFuzzer was checked once by hand: `clang++-21 -fsanitize=fuzzer,address,undefined`
on a three-byte trap target builds, runs and finds the crashing input.

## Build

CMake (minimum 3.28) with Ninja, C++23 without extensions. Presets in
`CMakePresets.json`; build trees go to `build/<preset>`.

| Preset | Compiler | Build type | Extra |
|---|---|---|---|
| gcc-debug | gcc-15 / g++-15 | Debug | `_GLIBCXX_ASSERTIONS` |
| gcc-release | gcc-15 / g++-15 | Release | |
| gcc-asan | gcc-15 / g++-15 | Debug | ASan + UBSan |
| clang-debug | clang-21 / clang++-21 | Debug | `_GLIBCXX_ASSERTIONS` |
| clang-release | clang-21 / clang++-21 | Release | |
| clang-asan | clang-21 / clang++-21 | Debug | ASan + UBSan |

Both compilers use libstdc++ 15. The asan presets compile and link everything,
GoogleTest included, with `-fsanitize=address,undefined
-fno-sanitize-recover=all -fno-omit-frame-pointer`; their test presets set
`ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1`
and `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1`. A planted signed
overflow and a heap over-read in core code each fail the test run on both asan
presets (checked by hand on 2026-11-11 in a throwaway copy).

There is no TSan preset: the core is single-threaded (PLAN section 2).

### Warnings

All project targets: `-Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor
-Woverloaded-virtual -Wimplicit-fallthrough -Wformat=2 -Werror`, on both
compilers (`cmake/Warnings.cmake`).

`utcp_core` also gets `-Wconversion -Wsign-conversion -Wold-style-cast
-Wcast-qual`. The core does the wire-format arithmetic, where an implicit
narrowing or sign change is usually a bug. The backend, apps and tests do not
get this set: system call return types (`ssize_t`, `socklen_t`) and test
literals would need casts that add noise without catching much.

GoogleTest is third-party code and is built without the project flags. With
clang 21 its own source triggers `-Wcharacter-conversion`
(`gtest-printers.h:528`), which is turned off for the `gtest` target only.

### Unit tests

GoogleTest 1.17.0 from the distro source package (`/usr/src/googletest`), built
in each build tree with the preset's compiler and flags. `gtest_discover_tests`
registers one ctest entry per test case (`unit.<Suite>.<Test>`).

### Core symbol check

`core.forbidden_symbols` runs `cmake/CheckCoreSymbols.cmake` on
`libutcp_core.a`: it lists the archive's undefined symbols with `nm -C -u` and
fails on system call wrappers, clocks, random sources, threads, stdio and
iostreams. `core.forbidden_symbols_selftest` runs it on a library that calls
`write`, `steady_clock::now` and `std::random_device`, and passes only if all
three are reported.

## CI

- `ci/run.sh [preset...]`: inside the image, configure, build and ctest each
  preset (default: all six), print a summary, exit non-zero if any step failed.
- `ci/docker-ci.sh [preset...]`: on the host, runs `ci/run.sh` in a throwaway
  `utcp-ci-*` container on CPUs 16-31 with `nice -n 10`. The checkout is
  mounted read-only and copied into the container.
- `.github/workflows/ci.yml`: builds the image from `testbed/Dockerfile`,
  pushes it to GHCR under a tag derived from the Dockerfile hash, then runs
  `ci/run.sh <preset>` in that image as a container job, one matrix entry per
  preset. GitHub-hosted runners do not have g++ 15 or clang 21, hence the
  container. Not run yet: the repository has not been pushed to GitHub.

Last result (2026-11-11, `ci/docker-ci.sh` on commit 35c86e1): all six
presets ok, 23 of 23 tests passed in each, about 50 s wall time for all six.

## verify-env

`testbed/verify-env.sh` runs three checks, each in throwaway `utcp-m0-*`
containers on a `utcp-m0-*` Docker network (subnet 198.19.255.0/24), removed
on exit. It prints `uptime`, the top CPU users and the load on CPUs 8-15
first, and host `lsmod | grep -E 'netem|tbf|bbr'` before and after.

| Check | What it does | Pass criteria |
|---|---|---|
| a. TUN | In a container with `--cap-add NET_ADMIN --device /dev/net/tun` (CPUs 16-31), `apps/tun_probe` creates `utcp0` with `IFF_TUN\|IFF_NO_PI`. The script assigns 198.18.0.1/24 and pings 198.18.0.2, which routes into `utcp0`. The probe reads the packets from the fd, checks the IPv4 header and ICMP checksums with `utcp_core`, and answers each echo request (checksum updated per RFC 1624, cross-checked against a full recompute). | Probe exits 0 after 3 echo requests 198.18.0.1 -> 198.18.0.2 with valid checksums, and ping gets 3/3 replies. |
| b. qdiscs | Two containers on CPUs 8-15. Sender egress: `netem delay 20ms limit 20000` as root (`1:`), `tbf rate 10mbit burst 16kb limit 64kb` as its child (`parent 1:1`). Two unmeasured pings resolve ARP, then 20 pings, then `iperf3 -t 10 -O 2`, then `tc -s qdisc`. | Ping avg RTT in [20.0, 21.0] ms; iperf3 receiver goodput in [9.0, 10.0] Mbit/s (expected about 9.56: tbf counts 1514-byte frames carrying 1448 bytes of payload). |
| c. BBR | Two containers on CPUs 8-15; `iperf3 -C bbr -t 5`, and `ss -tin` on the sender after 2 s. | iperf3 reports `sender_tcp_congestion` bbr, and ss shows the connection with `bbr` and a `bbr:(...)` block. |

Tolerances were fixed before the first run.

### Last result (2026-11-11)

`testbed/verify-env.sh` on commit 35c86e1 (run `utcp-m0-1111125321-412369`):
3/3 PASS.

- a. PASS: tun_probe read 3 ICMP echo requests from the TUN fd with valid
  checksums and wrote 3 replies, each RFC 1624 update matching a full
  recompute; ping 3/3 received, RTT min/avg/max 0.061/0.070/0.078 ms.
- b. PASS: ping RTT min/avg/max/mdev 20.041/20.070/20.104/0.019 ms over 20
  pings. iperf3: receiver 9.477 Mbit/s, sender 9.437 Mbit/s, 6 retransmits,
  10.1 s after 2 s omitted. `tc -s`: netem and tbf each sent 15160792 bytes in
  10056 packets, 30 dropped (tbf queue limit), backlog 0 at the end.
- c. PASS: `ss -ti` showed the data connection with `bbr` and
  `bbr:(bw:104256000000bps,mrtt:0.002,pacing_gain:1.25,cwnd_gain:2)`; iperf3
  `sender_tcp_congestion` bbr, 91583 Mbit/s over veth (no qdisc).
- Before the run: load average 2.96; CPUs 8-15 were 0-14% busy over 1 s
  (cpu8 10%, cpu9 6%, cpu10 14%, cpu11 0%, cpu12 8%, cpu13 1%, cpu14 10%,
  cpu15 4%); top CPU users were other tenants' processes (`td-legacy-vm`
  36%, `chrome` 12%, `grok-bot` 12%).

Earlier runs the same day: the second (same code) passed 3/3 with
20.085 ms and 9.479 Mbit/s in check b; the first failed check b, see below.

Module auto-load, from the first run on this host: `lsmod` showed none of
`sch_netem`, `sch_tbf`, `tcp_bbr` before and all three after. The containers
loaded them on first use (`tc qdisc add ... netem`/`tbf`, and
`setsockopt(TCP_CONGESTION, "bbr")` from a container with `NET_ADMIN`); no
`modprobe` was run. They stay loaded on the host.

The first run failed check b: ping avg 21.092 ms because the first ping took
40.131 ms. The neighbour table was empty, so that echo request waited for ARP
resolution, and the ARP request itself went through netem (confirmed
separately: first ping 40.1 ms, then 20.1 ms). The script now sends two
unmeasured pings first; the tolerance was not changed.
