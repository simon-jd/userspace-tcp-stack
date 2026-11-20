# userspace-tcp-stack

This C++23 project implements an IPv4 endpoint for TCP, UDP and ICMP. The TCP core takes packets,
time and a seeded random source as inputs. The same code runs over Linux TUN and in a
discrete-event simulator. The Linux backend runs the same applications on kernel sockets for
comparison.

[Quick start](#quick-start) · [Linux TUN](#use-the-linux-tun-backend) ·
[Protocol design](docs/DESIGN.md) · [Linux interoperability](docs/INTEROP.md) ·
[Measured results](docs/RESULTS.md) · [Reproducibility index](docs/results/reproduction/README.md)

## Status

| Milestone | Status |
|---|---|
| M0 and M1 | Toolchain, deterministic core, simulator, TUN backend and TCP interoperability complete |
| M2a and M2b | Loss recovery, delivery-rate sampling, pacing, NewReno and CUBIC complete |
| M2c and M2d | [BBRv1 paired smoke](docs/RESULTS.md#bbrv1-paired-smoke), [24-cell NewReno/CUBIC/BBRv1 matrix](docs/RESULTS.md#core-matrix), and [multi-flow study](docs/RESULTS.md#multi-flow) complete |
| M3 | [Valid-wire and receive-stream tests, two IPv4 Packetdrill cases, and simulator corpus checks](docs/RESULTS.md#m3-validation) verified. The fresh one-million-seed simulator run and the sustained arbitrary-input parser and reassembly campaign [remain open](docs/RESULTS.md#pending-validation). |
| M4 | Legacy bulk and 10,000-connection echo measurements, opt-in TUN and direct echo modes, and allocation diagnostics are recorded. [M4 results](docs/RESULTS.md#m4-bulk-tun-and-echo) |
| M5 | Private build and evidence guides. [Reproduction commands and archive inventory](docs/results/reproduction/README.md) |

The implementation covers the TCP state machine (RFC 9293), timestamps and window scaling
(RFC 7323), SACK and D-SACK (RFCs 2018 and 2883), RST handling (RFC 5961), retransmission
timeouts (RFC 6298), initial sequence numbers and port selection (RFC 9293 §3.4.1 and RFC 6056), IPv4
path MTU discovery and ICMP handling (RFCs 1191 and 5927), and NewReno (RFCs 5681 and 6582).
The recovery and congestion-control profiles include SACK loss recovery (RFC 6675), RACK-TLP
(RFC 8985), proportional rate reduction (RFC 9937), CUBIC (RFC 9438) and HyStart++ (RFC 9406).
The Linux-compatible profile uses Linux-style RACK, PRR and classic HyStart. It also supports
BBRv1. [Profiles and implementation details](docs/DESIGN.md#39-configuration-and-profiles) ·
[Protocol references](docs/DESIGN.md#protocol-references)

## Checkpoint

Across eight network conditions, the userspace sender's median receiver goodput was **98.36–101.41%
of Linux for NewReno** and **95.43–102.85% for CUBIC**. The largest percentage deficit was CUBIC at 10 Mbit/s,
100 ms and 1% loss, with 1.321 Mbit/s for the stack and 1.384 Mbit/s for Linux. Sixty-three of
64 metric comparisons received a “no gap” verdict under the preset rules. The one
formal gap was NewReno p99 queue delay at 100 Mbit/s, 20 ms and 1% loss, lower by 0.066 ms on
the stack and below measurement resolution.

These results cover 160 valid serial transfers on one shared host. All retained the external CPU
load flag. The full tables report five paired runs per condition, both ranges and all four
verdicts. [Checkpoint results, raw-data locations and overlays](docs/RESULTS.md#checkpoint)

## Later measurements

On the November 2026 four-container shaped testbed, the 720-transfer single-flow
matrix used the Linux-compatible stack profile, a Linux receiver and five
same-seed pairs per algorithm and condition. Across its 24 conditions,
median receiver goodput was 97.91–102.03% of Linux for NewReno, 93.21–101.80%
for CUBIC and 99.85–100.60% for BBRv1. The two substantive gaps were higher
BBRv1 retransmission rates in the 10 Mbit/s, 20 ms, 0.5-BDP queue conditions
at 0% and 0.1% configured random loss. In the shared-bottleneck study, the late BBRv1
flow joining Linux CUBIC had a median Jain index of 0.878 versus 0.996 for
the Linux baseline, and neither arm converged in the five measured pairs.
[Single-flow results](docs/RESULTS.md#core-matrix) ·
[Multi-flow results](docs/RESULTS.md#multi-flow)

In the November 20, 2026 same-host Docker bridge studies, five 1 GB single-flow
CUBIC repeats per arm compared receiver goodput and process CPU. Legacy
stack send and receive medians were 3.963 and 4.787 Gbit/s versus 8.160
and 8.633 Gbit/s for the corresponding Linux controls with Ethernet offloads
disabled. In a separate matched-offload comparison, TCPv4 offload raised
the stack medians to 11.332 and 14.226 Gbit/s from 3.793 and 4.828 Gbit/s
with checksum-only TUN. Its process CPU per GB remained above Linux in both
directions. Two active TUN FDs showed no consistent benefit on one event loop.

At 10,000 connections, direct echo eliminated measured app staging in its
paired workload. Its median CPU and p99 rose within overlapping run ranges.
The 2,208 B TCB and about 3,334 B idle RSS growth per established connection
missed their targets. PMU access was denied, and bounded warm-process C++
allocation counts were nonzero. [M4 methods, individual studies and limits](docs/RESULTS.md#m4-bulk-tun-and-echo)

## Non-goals

- IPv6, TLS, QUIC, MPTCP (MP_CAPABLE is ignored, so peers fall back to plain
  TCP, RFC 8684 §3.1).
- IP fragmentation and reassembly. Every datagram is sent with DF set and is
  never larger than the path MTU. Received fragments are dropped and counted.
- ECN. The SYN never carries ECE/CWR, an ECN or AccECN SYN is answered with
  AE = CWR = ECE = 0 (RFC 3168 §6.1.1), data is sent Not-ECT and CE marks are
  ignored.
- TCP Fast Open. Data on a SYN is not acknowledged; the TFO option is ignored.
- Urgent data (URG is never sent; a received urgent pointer is ignored and the
  data delivered inline, RFC 6093 §5) and IP options (skipped on receipt,
  never sent).
- SYN cookies, PLPMTUD (RFC 4821/8899) and keepalive in M1. F-RTO (RFC 5682)
  and DSACK/timestamp undo are not modelled in any milestone.
- Running unmodified applications (no socket shim, no LD_PRELOAD); forwarding
  or routing (one endpoint, one interface, one address); a multi-threaded core.

## Layout

| Path | Contents |
|---|---|
| `include/utcp/` | Public headers (namespace `utcp`) |
| `src/core/` | `utcp_core`: wire formats, IPv4, ICMP, UDP, TCP. No system calls, no I/O, no clocks, no threads |
| `src/sim/` | `utcp_sim`: simulated network for running core instances against each other |
| `src/backend/` | `utcp_backend`: TUN device and event loop |
| `apps/` | Programs, one CMake target each |
| `tests/unit/`, `tests/sim/`, `tests/interop/`, `tests/fuzz/` | Tests |
| `testbed/` | Image Dockerfile and testbed scripts |
| `ci/` | CI scripts |
| `docs/` | Documentation |
| `tools/` | Analysis and plotting scripts |

## Build and test

Builds run inside the `utcp-testbed:dev` image (g++ 15, clang 21, CMake,
Ninja, GoogleTest); see [docs/ENVIRONMENT.md](docs/ENVIRONMENT.md).

```sh
testbed/build-image.sh            # build the image once
ci/docker-ci.sh                   # all presets in a throwaway container
ci/docker-ci.sh clang-asan        # one preset
testbed/verify-env.sh             # TUN, netem/tbf and BBR checks
```

Inside the image, or anywhere with the same toolchain:

```sh
cmake --preset gcc-debug && cmake --build --preset gcc-debug && ctest --preset gcc-debug
cmake --workflow --preset clang-asan   # configure, build and test in one step
```

Presets: `gcc-debug`, `gcc-release`, `gcc-asan`, `clang-debug`,
`clang-release`, `clang-asan` (asan = ASan + UBSan, no recovery), `gcc-sweep`
(Release with `UTCP_DCHECKS`, for simulator sweeps) and `clang-fuzz` (libFuzzer
targets, ASan + UBSan, `UTCP_DCHECKS`).

## Quick start

From the repository root on Linux with the build toolchain installed:

```sh
cmake --preset gcc-release
cmake --build --preset gcc-release --target utcp-bulk utcp-echo utcp-httpd utcp-http-get
```

Run the listener in one shell and the corresponding client in another.
These loopback examples use kernel sockets.

### Single-flow bulk benchmark

```sh
# Listener
build/gcc-release/apps/utcp-bulk/utcp-bulk --backend kernel --listen 127.0.0.1:5201 --recv --bytes 1Mi
# Client
build/gcc-release/apps/utcp-bulk/utcp-bulk --backend kernel --connect 127.0.0.1:5201 --send --bytes 1Mi --cc cubic
```

Both endpoints print the byte count and SHA-256 of the generated payload.

### TCP echo

```sh
# Listener
build/gcc-release/apps/utcp-echo/utcp-echo --backend kernel --listen 127.0.0.1:5202
# Client
build/gcc-release/apps/utcp-echo/utcp-echo --backend kernel --connect 127.0.0.1:5202 --connections 1 --size 64 --count 5
```

The client verifies five replies. Stop the listener with Ctrl-C.

### Single-file transfer

```sh
# Listener
build/gcc-release/apps/utcp-httpd/utcp-httpd --backend kernel --listen 127.0.0.1:8080 --root docs
# Client
build/gcc-release/apps/utcp-http-get/utcp-http-get --backend kernel --output build/design-download.md http://127.0.0.1:8080/DESIGN.md
cmp docs/DESIGN.md build/design-download.md
```

Stop the listener with Ctrl-C after the comparison.

## Use the Linux TUN backend

The userspace backend needs IPv4, access to `/dev/net/tun`, and a Linux TUN
interface with a kernel-side address and route to the stack's separate IPv4
address. Pass `--backend utcp --tun IFNAME --addr STACK_IP` and match
`--mtu` to the device MTU. The testbed provisions interfaces and routes
in isolated Docker containers with `NET_ADMIN`.

Legacy framing and a single TUN FD are the defaults. On a TUN configured
with `vnet_hdr`, use `--tun-offload=checksum` for TCP checksum offload or
`--tun-offload=tcpv4` for TCPv4 checksum and segmentation offload. On an
existing `multi_queue` TUN, use `--tun-queues N` (1–64) to attach N active
FDs to the same device. The live queue comparison covers one and two FDs on
one event loop. Echo uses staging by default. Pass `--direct-echo` on a TCP
listener to send from the receive scratch buffer when the connection has
no older pending bytes. [TUN and queue behavior](docs/DESIGN.md#8-backends)

After building the release targets and Docker image above, run the bounded
TUN checks from the repository root. The first transfers 4,000,055 B in
both directions in each of the three modes and checks SHA-256. The wire
check uses an isolated subnet and saves a capture.

```sh
tests/interop/m4_tun_offload.sh
tests/interop/m4_tun_offload_wire.sh "$(mktemp -d "$PWD/build/m4-tun-wire.XXXXXXXX")"
tests/interop/m4_tun_multiqueue.sh
```

[Read-only VNET replay](docs/results/m4-tun-vnet/README.md#sealed-evidence-and-replay) ·
[10,000-connection echo and kernel comparison](docs/results/m4-echo-load/README.md) ·
[Echo copy, C++ allocation and final-mode confirmation](docs/results/m4-copy-allocation/README.md)

## Run the comparison testbed

Use the [reproducibility index](docs/results/reproduction/README.md) to read or
replay existing campaigns. To inspect the registered 720-transfer schedule
without starting containers or transfers, run
`python3 -B tools/m2/matrix.py expand docs/results/m2-matrix/plan.toml --slots 1`.

A new measurement uses Linux, Docker, a TUN device and the CPU layout in
the [environment description](docs/ENVIRONMENT.md). The runner starts the stack sender with
`--backend utcp --profile linux` or the kernel sender with `--backend kernel`. Both send to the
same kernel receiver across the shaped router path.

This example creates fresh campaign names, runs both full calibration gates, and then runs the
checkpoint on slot 0. Run it from the repository root with both timing slots available. For a
byte-identical replay of the measured calibration inputs, see the [freeze and restore recipe](docs/RESULTS.md#integrated-calibration-november-19-2026).

```bash
set -euo pipefail
stamp=$(date -u +%Y%m%d-%H%M%S)
campaign="checkpoint-$stamp"
export UTCP_M2_PREFIX="utcp-m2-$campaign" UTCP_TB_PREFIX="utcp-m2-$campaign"
export UTCP_M2_JOB="utcp-m2-$campaign-runner"
docker volume create utcp-data
testbed/m1/build.sh gcc-release utcp-bulk
mkdir -p "build/$campaign"
plan="build/$campaign/plan.toml"
sed "s/^campaign = .*/campaign = \"$campaign\"/" docs/results/m2-checkpoint/plan.toml > "$plan"
active=()
cleanup_slots() {
    for slot in "${active[@]}"; do python3 -B tools/m2/matrix.py down --slot "$slot"; done
}
trap cleanup_slots EXIT
for slot in 0 1; do
    active+=("$slot")
    python3 -B tools/m2/matrix.py up --slot "$slot"
    python3 -B tools/m2/matrix.py calibrate --slot "$slot" --campaign "$campaign-gate-s$slot"
done
python3 -B tools/m2/matrix.py down --slot 1
active=(0)
python3 -B tools/m2/matrix.py run "$plan" --slot 0 --gate "$campaign-gate-s0"
python3 -B tools/m2/matrix.py down --slot 0
active=()
python3 -B tools/m2/matrix.py tables --campaign "$campaign" --out "/data/m2/$campaign/tables"
python3 -B tools/m2/matrix.py plot --campaign "$campaign"
```

The reduced matrix covers one flow, eight network conditions, two loss levels and a queue of
twice the bandwidth-delay product. Its largest zero-loss cell is transient-dominated. Linux
spurious-loss undo and F-RTO are outside the implemented scope. [Measurement method and decision rules](docs/RESULTS.md#method)
