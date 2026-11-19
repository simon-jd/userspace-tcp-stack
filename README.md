# userspace-tcp-stack

This C++23 project implements an IPv4 endpoint for TCP, UDP and ICMP. The TCP core takes packets,
time and a seeded random source as inputs. The same code runs over Linux TUN and in a
discrete-event simulator. The Linux backend runs the same applications on kernel sockets for
comparison. [Protocol design](docs/DESIGN.md) · [Linux interoperability](docs/INTEROP.md)

## Status

| Milestone | Status |
|---|---|
| M0 and M1 | Toolchain, deterministic core, simulator, TUN backend and TCP interoperability complete |
| M2a and M2b | Loss recovery, delivery-rate sampling, pacing, NewReno and CUBIC complete |
| M2c and M2d | BBRv1 and the full 24-cell matrix pending |
| M3–M5 | Pending |

The implementation covers the TCP state machine (RFC 9293), timestamps and window scaling
(RFC 7323), SACK and D-SACK (RFCs 2018 and 2883), RST handling (RFC 5961), retransmission
timeouts (RFC 6298), initial sequence numbers and port selection (RFCs 6528 and 6056), IPv4
path MTU discovery and ICMP handling (RFCs 1191 and 5927), and NewReno (RFCs 5681 and 6582).
The recovery and congestion-control profiles include SACK loss recovery (RFC 6675), RACK-TLP
(RFC 8985), proportional rate reduction (RFC 9937), CUBIC (RFC 9438) and HyStart++ (RFC 9406).
The Linux-compatible profile uses Linux-style RACK, PRR and classic HyStart. [Profiles and implementation details](docs/DESIGN.md#39-configuration-and-profiles)

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
(Release with `UTCP_DCHECK`, for simulator sweeps) and `clang-fuzz` (libFuzzer
targets, ASan + UBSan, `UTCP_DCHECK`).

## Run a transfer

Inside the Linux build environment, build the release target with
`cmake --preset gcc-release && cmake --build --preset gcc-release --target utcp-bulk`.
Start a receiver in one shell and then the sender in another.
Both endpoints print the transferred byte count and a SHA-256 digest.

```sh
bulk=build/gcc-release/apps/utcp-bulk/utcp-bulk
"$bulk" --backend kernel --listen 5201 --recv
```

```sh
bulk=build/gcc-release/apps/utcp-bulk/utcp-bulk
"$bulk" --backend kernel --connect 127.0.0.1:5201 --send --bytes 1Mi --cc cubic
```

## Run the comparison testbed

The measured host uses Linux, Docker, a TUN device and the CPU layout in the
[environment description](docs/ENVIRONMENT.md). The runner starts the stack sender with
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
