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

`testbed/Dockerfile` now also installs `nftables` (the DUT's NAT,
`testbed/m1/nat.sh`). The image above predates that. Built from the new
Dockerfile on 2026-11-12 as `utcp-m1-backend-testbed:dev`
(`sha256:375ae816b3e0e2a21e2253418de767815776c9b747082016bcb188433eb3c440`,
2.11 GB), it has the same compilers, CMake, Ninja and GoogleTest. Differences
in packages.txt: added nftables 1.1.6-1, libnftables1 1.1.6-1 and
libnftnl11 1.3.1-1; archive updates of libc6, libc6-dev, libc6-i386, libc-bin,
libc-dev-bin and libc-gconv-modules-extra (2.43-2ubuntu2.4 to 2.43-2ubuntu2.7)
and of python3-pil and python3-pil.imagetk (12.1.1-2ubuntu1.4 to
12.1.1-2ubuntu1.5).

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
| gcc-sweep | gcc-15 / g++-15 | Release | `UTCP_DCHECKS=ON` (simulator sweeps) |
| clang-fuzz | clang-21 / clang++-21 | RelWithDebInfo | ASan + UBSan, `UTCP_DCHECKS=ON`, libFuzzer targets (`UTCP_FUZZ=ON`) |

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
  preset (default: all eight), print a summary, exit non-zero if any step
  failed. With gcc-release and clang-release it also compares the simulator
  digests of the two builds (`ci/check-digests.sh`). CTest runs at most one
  test per CPU and at most eight. `UTCP_TEST_TIMEOUT_SCALE=N` multiplies every
  test time limit: the presets' 300 s default and the 1,500 s that the long
  simulator tests set (CMake cache variable of the same name).
- `ci/docker-ci.sh [preset...]`: on the host, runs `ci/run.sh` in a throwaway
  `utcp-ci-*` container on CPUs 16-31 with `nice -n 10`. The checkout is
  mounted read-only and copied into the container.
- `.github/workflows/ci.yml`: builds the image from `testbed/Dockerfile`,
  pushes it to GHCR under a tag derived from the Dockerfile hash, then runs
  `ci/run.sh <preset>` in that image as a container job, one matrix entry per
  preset. GitHub-hosted runners do not have g++ 15 or clang 21, hence the
  container. The runners have 4 vCPUs. In the first run, on commit 102ef04,
  six presets passed and both ASan presets failed only on time limits: with
  eight tests at a time their tests took 2.5 to 5.3 times as long as on the
  server, and the longest simulator tests ran out of time. The workflow
  therefore sets `UTCP_TEST_TIMEOUT_SCALE=4`.

Server result (2026-11-24, `ci/docker-ci.sh` on commit 102ef04 with
`UTCP_CI_CPUS=16-23`, image `utcp-testbed:dev`): all eight presets ok,
1,111 to 1,116 tests passed in each, and the gcc-release and clang-release
simulator digests matched. The first result (2026-11-13, commit bc86f27 of the
m1-backend branch) had 236-239 tests per preset.

GitHub result (`UTCP_TEST_TIMEOUT_SCALE=4`, four tests at a time): all eight
presets passed on commit 2fe36cc (2026-11-24) and again on commit 7a7a838
(2026-11-25), with 1,111 tests in each debug, release and sweep preset, 1,112
in each ASan preset and 1,116 in clang-fuzz. The slowest test was the sb-0007
corpus replay in gcc-asan, at 1,923 s and 2,248 s against its 6,000 s limit,
and gcc-asan was the longest job, at about 62 and 72 minutes. Each matrix
entry runs one preset, so the gcc-release and clang-release digest
comparison runs only on the server.

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

## M1 interop testbed (`testbed/m1/`)

DESIGN §11. Scripts run on the host; the settings are in
`testbed/m1/common.sh`. Containers run from `$UTCP_IMAGE` (default
`utcp-testbed:dev`; nat.sh needs an image with nftables and conntrack) on
`$UTCP_CPUS` (8-15 for timing runs; unset: the running DUT's cpuset, so the
router of pmtu.sh and the peers of combo.sh follow `up.sh --cpus`, else
16-31), with the checkout mounted read-only at `/utcp`. `testbed/m1/build.sh [preset] [target...]` builds the programs inside
the image as the calling user into `build/tb-<preset>` (`/utcp/build/tb-<preset>`
in the containers).

```
utcp-m1-peer 198.19.1.3 -- utcp-m1-net 198.19.1.0/24 -- 198.19.1.2 eth0 utcp-m1-dut
  DUT: TUN utcp0, kernel side 198.18.0.1/24, stack 198.18.0.2; IP forwarding; IPv6 off
  peer: route 198.18.0.0/24 via 198.19.1.2; net.ipv4.tcp_no_metrics_save=1; tso, gso off
PMTU chain (pmtu.sh):
utcp-m1-dut 198.19.2.2 -- utcp-m1-net1400 (MTU 1400) -- 198.19.2.3 utcp-m1-r 198.19.3.3 -- utcp-m1-netb -- 198.19.3.4 utcp-m1-peer
```

| Script | Does |
|---|---|
| `up.sh [--cpus LIST] [--peer-sysctl K=V]...` | network, DUT, peer. utcp0 is a persistent TUN (`ip tuntap`) with MTU 1500, txqueuelen 10000 (also the size of tun's packet ring) and root qdisc `pfifo limit 10000`; the stack or `tun_probe` attaches to it. Prints `ip link`, `tc qdisc`, routes and the peer's sysctls. |
| `down.sh` | removes exactly the three containers and three networks above and checks that none is left; other `utcp-m1-*` objects are listed, not touched |
| `netem.sh N0..N4` | netem (`limit 20000`) on the DUT's eth0 egress (stack to Linux) and utcp0 egress (Linux to stack): N1 `delay 1ms loss 1%`, N2 `delay 5ms reorder 10% 50%`, N3 `delay 1ms duplicate 2%`, N4 `delay 2ms loss 1% duplicate 1% reorder 5% 50%`; N0 restores noqueue and pfifo. Deletes and re-adds the qdiscs: `tc qdisc replace` on an existing netem keeps the parameters the new profile does not name. |
| `combo.sh list \| start NAME \| check` | peers with `--sysctl net.ipv4.tcp_{sack,timestamps,window_scaling}` in all 8 combinations and `tcp_ecn` 1 and 3; `check` starts each and prints the values read back |
| `pmtu.sh [up\|down]` | the PMTU chain above |
| `nat.sh [on] [--dns IP] \| off` | nftables masquerade for 198.18.0.0/24 out of the DUT's eth0 to destinations outside 198.18.0.0/15 (so stack-peer traffic keeps 198.18.0.2), packets to those destinations that conntrack marks invalid dropped and counted, and a /32 route to the host's upstream DNS resolver (first IPv4 `nameserver` of `/run/systemd/resolve/resolv.conf`; 75.75.75.75 on this host), written to `/run/utcp-m1-dns` in the DUT. `on` and `off` flush the DUT's conntrack table (see below). |
| `record.sh [LABEL]` | DUT `ip -s link show utcp0` and `tc -s qdisc`, peer `nstat -asz` and `ip tcp_metrics show`, tso/gso/gro of the peer's and the DUT's interfaces |

Attaching to utcp0 turns its carrier on, but the kernel drops the packets it
sends to the interface (utcp0 TX dropped) until its link watcher has
re-enabled the qdisc. A DF datagram written within microseconds of the attach
lost its ICMP reply in 1 of 4 tries. `TunDevice::wait_running` waits until
`/sys/class/net/<if>/operstate` is `up`, then 1 ms more; `UtcpTransport::open`
and `backend_tun_tool` call it (15 of 15 tries then got the reply).
`/proc/sys` is read-only in the containers, so `ip route flush cache` fails
there; sysctls are set with `docker run --sysctl`. `UtcpTransport::open`
refuses an interface that `/sys/class/net` does not list: TUNSETIFF would
create a new one, down, that disappears with the fd.

Offloads. Linux TCP always builds GSO packets of up to 64 KB, and a veth
with TSO (Docker's default) passes them on whole; the forwarding DUT keeps
them whole, and utcp0 (TUN without `IFF_VNET_HDR`) splits them only after its
qdisc. With the peer's defaults (tso on), an 8 MB iperf3 flow reached the
DUT's eth0 as packets of up to 65160 payload bytes (45 segments; 135 of 201
captured data packets above 1460), so netem on utcp0 would drop, duplicate and
reorder bursts in the Linux-to-stack direction while the stack writes single
packets in the other, and the pfifo and netem limits would count bursts. So
the peer's interfaces get `ethtool -K
tso off gso off` (its kernel splits before the veth; PLAN 2d does the same for
its sender) and the forwarding interfaces of the DUT and the router `gro off`
(Docker's default; set so nothing merges segments again). `tc -s` counts
`gso_segs`, so its packet counts do not show the difference; the offloads
step of `backend_testbed.sh` checks the segment sizes that reach the DUT.

NAT and conntrack. Conntrack runs in the DUT with or without NAT (Docker's
embedded-DNS rules put a nat table in every container on a user-defined
network), and a connection keeps the NAT binding its first packet got. So
`nat.sh on` and `off` run `conntrack -F` in the DUT (its network namespace
only): otherwise a flow live before `on` would stay un-NATed and one started
under NAT would stay NATed after `off`. The flush breaks NATed flows live at
`off`. With an image without the conntrack tool nat.sh prints a warning and
the change applies only to flows started after it.

Checks: `tests/interop/backend_testbed.sh` (m1-backend tests 3-6, the
offloads, the UtcpTransport self-check on utcp0, and through the NAT a DNS
query, an un-masqueraded datagram to the peer and the conntrack flushes),
`tests/interop/backend_lateness.sh` (test 2, timing),
`tests/interop/backend_udp_echo.sh` (test 7, needs the m1-ip Stack).

`nft` and `conntrack` are in the image only once it is rebuilt from
`testbed/Dockerfile`; with the older `utcp-testbed:dev` the nat step of
`backend_testbed.sh` fails (`nft: command not found`).

### Last results (2026-11-13, image `utcp-m1-backend-testbed:dev`)

- `backend_testbed.sh`: all PASS. Peer ping 3/3 answered by `tun_probe
  --reply` on utcp0 (`qdisc pfifo ... qlen 10000`, `limit 10000p`, peer
  `tcp_no_metrics_save = 1`); offloads: peer tso/gso off, DUT eth0 gro off,
  1000 captured data packets of an iperf3 flow from the peer, the largest with
  1448 payload bytes (with tso/gso turned back on: up to 65160);
  `backend_transport_check --tun utcp0` 18/18 and open() on a down utcp0
  refused; a 1500-byte DF datagram from 198.18.0.2 to 198.19.3.4 got
  `198.18.0.1 > 198.18.0.2: ICMP 198.19.3.4 unreachable - need to frag (mtu
  1400)` on utcp0, and the peer's `ping -M do -s 1472` got `From 198.19.3.3
  ... Frag needed and DF set (mtu = 1400)`; through the NAT a DNS query got 2
  A records and a datagram to the peer arrived as `198.18.0.2.40001 >
  198.19.1.3.9` (198.18.0.7 also kept its address and port), and `off`/`on`
  flushed the conntrack entries of 198.18.0.2 (2 to 0, 1 to 0); N1-N4 and N0
  installed on eth0 and utcp0; all 10 combo.sh peers read back the requested
  values with tso/gso off (tcp_ecn=3 accepted); down.sh left nothing.
- `up.sh --cpus 20-23`, then `pmtu.sh up` and `combo.sh start` without
  `UTCP_CPUS`: router and new peer on 20-23; with `UTCP_CPUS=16-31` the peer
  on 16-31.
- `backend_lateness.sh` (2026-11-12, container on CPUs 8-15, which were 0-4.5
  % busy with other tenants' processes before and after): 10 000 waits of 1
  ms, lateness p50 2.44 us, p90 8.65 us, p99 11.9 us, p99.9 47.8 us, max 247
  us, process CPU 0.25 %. With `--spin-us 50`: p50 95 ns, p99 1.11 us, p99.9
  4.05 us, max 491 us, CPU 4.9 % (spinning 458 ms of 10.0 s). Not rerun after
  the loop began sampling at the wake-up: the program has no fd callbacks and
  computes its samples from the handler's time.
- `backend_udp_echo.sh`: not run on this branch (the Stack is the link stub).
  On a local merge with the m1-ip branch: ping 3/3 answered by the stack,
  100/100 datagrams echoed unchanged. With `--pcap` (2026-11-12), the file
  held 624 bytes (header and 6 records) while the program was still running
  after 3 pings, and the same 624 bytes after `pkill -KILL`.
- `backend_transport_check --expect-stack` on that merge: 24/24 (gcc-release,
  gcc-asan), 20 of 20 repeated runs under gcc-asan.
