# userspace-tcp-stack

A userspace TCP/IP stack with a sans-I/O core. Work in progress.

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
ci/docker-ci.sh                   # all six presets in a throwaway container
ci/docker-ci.sh clang-asan        # one preset
testbed/verify-env.sh             # TUN, netem/tbf and BBR checks
```

Inside the image, or anywhere with the same toolchain:

```sh
cmake --preset gcc-debug && cmake --build --preset gcc-debug && ctest --preset gcc-debug
cmake --workflow --preset clang-asan   # configure, build and test in one step
```

Presets: `gcc-debug`, `gcc-release`, `gcc-asan`, `clang-debug`,
`clang-release`, `clang-asan` (asan = ASan + UBSan, no recovery).
