# userspace-tcp-stack

A userspace TCP/IP stack with a sans-I/O core. Work in progress. The design
is in [docs/DESIGN.md](docs/DESIGN.md).

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
