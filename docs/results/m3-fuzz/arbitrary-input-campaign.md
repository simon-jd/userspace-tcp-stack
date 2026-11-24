# M3 arbitrary-input fuzz campaign

The four libFuzzer targets in `tests/fuzz/` each ran for four hours on Ubuntu
with the criteria fixed beforehand in the
[preregistration](campaign-preregistration.md). The campaign found nothing:
no crash, sanitizer report, `UTCP_CHECK` abort, timeout, out-of-memory or leak.
Every minimized corpus input replayed with exit 0.

## Build and run

- Source `c5b99d4935439becd406d40e9036fb535e931d44`. No file under `src/`,
  `include/`, `tests/fuzz/`, `tests/support/`, `cmake/`, `CMakeLists.txt` or
  `CMakePresets.json` changed between it and the merge that closed M3, so the
  result applies to that tree.
- Preset `clang-fuzz`: Ubuntu clang 21.1.8, RelWithDebInfo,
  `-fsanitize=fuzzer,address,undefined`, `UTCP_DCHECKS=ON`.
- Each target: `-fork=2 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1
  -max_total_time=14400 -timeout=10 -rss_limit_mb=2048`. The four targets ran
  at once (eight fuzzing processes) under `taskset -c 16-31 nice -n 10`, from
  2026-11-24T04:36:57Z to 08:37:34Z.
- Starting corpus: the corpus left by a five-minute single-process probe of
  each binary (no finding in any probe). `fuzz_ipv4` also started from 400
  distinct IPv4 datagrams taken from the ingress captures of 60 stock Gen6
  replay seeds.

| Target | Input | `-max_len` | Start files | Executions | Edges | Features | Final files | Minimized |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `fuzz_ipv4` | bytes parsed as IPv4, TCP, UDP and ICMP; anything that parses is written and parsed back and must match | 4096 | 530 | 4,756,405,601 | 191 | 489 | 582 | 151 |
| `fuzz_tcp_options` | a TCP option area, compared with a separate transcription of Linux `tcp_parse_options`, then written and parsed back in SYN and non-SYN layouts | 42 | 95 | 4,222,765,769 | 148 | 334 | 102 | 88 |
| `fuzz_reassembler` | insert, burst, read, FIN, renege, grow and limit operations applied to `RecvBuffer` and to the naive byte-map reference, with a full or deliberately short chunk pool | 1024 | 811 | 2,181,667 | 674 | 4,255 | 900 | 768 |
| `fuzz_stack_input` | raw datagrams, crafted segments placed relative to live sequence numbers, ICMP errors, SYNs, time steps, socket calls and transmit-queue holds against one Stack, with `debug_check()` after each step and a quiescent stack at the end | 2048 | 3,374 | 24,245,725 | 4,681 | 26,002 | 5,804 | 4,690 |

Executions, edges and features are libFuzzer's final status line for each
target. Edges and features count the whole instrumented binary, harness
included; they are not a source coverage report. `fuzz_reassembler` is slow
because its reference does work proportional to the window on every step, so
it ran about 151 inputs per second against hundreds of thousands for the
parser targets.

## Checks

- Every final status line reports `oom/timeout/crash: 0/0/0`; each target
  logged `INFO: exiting: 0` after 14,425 to 14,436 seconds and exited 0; the
  four artifact directories are empty.
- After the run, `-merge=1` with the campaign binaries (SHA-256 unchanged)
  reduced the final corpora to 151, 88, 768 and 4,690 inputs; the merge kept
  the same edge counts. Each minimized input was then passed to its binary
  once: all 5,697 ran, every invocation exited 0 and the replay logs contain
  no `ERROR` or `SUMMARY` line.

## Limits

- Inputs are arbitrary only inside each harness's model. `fuzz_stack_input`
  builds valid IPv4 headers and transport checksums for some operations, and
  its scripted peer always completes the two handshakes before the fuzz
  operations. `fuzz_tcp_options` covers an option area of at most 40 bytes.
- Only the clang build was fuzzed; there was no GCC fuzz build and no
  MemorySanitizer run.
- Four hours per target, two processes each. A clean run of this length
  shows no finding within that budget, not the absence of bugs.

## Raw artifacts

On Ubuntu under `~/Desktop/utcp-wt/m3-fuzz-campaign-n23-run/`:
`PREREGISTRATION.md`, `binaries.sha256`, `build.log`, the probe corpora,
`campaign.sh` (SHA-256 `79f1e0e9c107ac19647aea0ae17f4175e296d5a43f6237e6ad8512b35cadd96f`),
`minimize.sh` (SHA-256 `5f0080089ffc5f29e911e39f276df6a73b5020268ae7e1e09d47d5dc443374cd`),
`pcap_seeds.py`, and under `campaign/` the start and end times, the four logs
and exit codes, the final corpora, the merge and replay logs, and
`minimized-corpora.tar.gz`
(SHA-256 `39072e583017f9b3e69461911141967d0692ae27477d506e370e97950bd2ae41`).

| Binary | SHA-256 |
|---|---|
| `fuzz_ipv4` | `1e4429c346c7cc045dd247c8c62a73b2c2bcb4afaffaebb7532b443bbf151950` |
| `fuzz_tcp_options` | `bfa7abf941e1b95c5aad42a5fe4d4944efdf2d2350759458f42998d11da1fd82` |
| `fuzz_reassembler` | `66d9e01b8cb8e6db9d3882e4a17c0d4f79eef41936366d4861ebdfcfaa8fb8cd` |
| `fuzz_stack_input` | `b5dea3ad2fb25d58787e91506529239996579942e905110dea4e5571235c9bf4` |

To repeat a run, build the `clang-fuzz` preset and run one target with the
options above on an empty or copied corpus directory, for example
`build/clang-fuzz/tests/fuzz/fuzz_stack_input corpus/ -fork=2 -max_len=2048
-max_total_time=14400 -timeout=10 -rss_limit_mb=2048`.
