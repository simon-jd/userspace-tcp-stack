> Copied unchanged from the campaign run directory, where the file has SHA-256
> `5b9e9516996080f9de6d0b587db58fe669b12b020d341712d11fb48e0e3d6756`. It was written before
> `campaign/start.txt` (2026-11-24T04:36:57Z). Results: [arbitrary-input campaign](arbitrary-input-campaign.md).

# M3 arbitrary-input fuzz campaign: preregistration (2026-11-23)

Written before the campaign starts. Criteria below are not changed after the run.

## Source and build
- Source: private `main` at `c5b99d4935439becd406d40e9036fb535e931d44`, worktree branch `work/m3-fuzz-campaign-n23` (no source change).
- Preset `clang-fuzz`: Ubuntu clang 21.1.8, RelWithDebInfo, `-fsanitize=fuzzer,address,undefined`, `UTCP_DCHECKS=ON`.
- Binary SHA-256 values: `binaries.sha256` in this directory.

## Targets (tests/fuzz)
- `fuzz_ipv4`: arbitrary bytes parsed as IPv4, TCP, UDP and ICMP (and ICMP quotes); whatever parses is written and parsed back and must match.
- `fuzz_tcp_options`: arbitrary TCP option areas; `parse_tcp` must match a separate transcription of Linux `tcp_parse_options`, then write/parse round trips for SYN and non-SYN layouts.
- `fuzz_reassembler`: operation sequences applied to `RecvBuffer` and to the naive byte-map reference; results, read bytes, FIN state and SACK ranges must agree after every step.
- `fuzz_stack_input`: arbitrary datagrams, crafted segments, ICMP errors, time steps and socket calls into a Stack; `debug_check()` after every operation and a quiescent stack at the end.

## Run
- Each target: `-fork=2 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 -max_total_time=14400 -timeout=10 -rss_limit_mb=2048`, `-max_len` 4096 / 42 / 1024 / 2048 respectively. Four targets run at once: eight fuzzing processes, `taskset -c 16-31 nice -n 10`.
- Starting corpus: the corpus of a 5-minute single-process probe per target on the same binaries (all four probes ended with no finding); `fuzz_ipv4` also gets 400 distinct IPv4 datagrams taken from the ingress captures of 60 Gen6 replay seeds.
- Budget: 4 hours wall, 8 CPU-hours per target, 32 CPU-hours in total.

## Pass criteria
- Zero crash, sanitizer report, `UTCP_CHECK` abort, timeout, OOM or leak artifact across the four targets.
- After the run, each target's corpus is minimized with `-merge=1`, and every minimized input is replayed once by the campaign binary with exit 0.

## If something is found
The campaign keeps running. Each artifact is reproduced, minimized and root-caused; the fix gets a regression test that fails before and passes after; the affected target is run again for the full budget on the fixed source from the merged corpus. The results note reports both runs.

## Limits stated in advance
- Bytes are arbitrary only inside each harness's input model (e.g. `fuzz_stack_input` builds IPv4 headers with valid checksums for some operations; `fuzz_tcp_options` bounds the area at 40 bytes).
- Only the clang build is fuzzed; no gcc build, no MSan.
