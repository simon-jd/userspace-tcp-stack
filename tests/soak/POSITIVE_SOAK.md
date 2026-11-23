# Closed valid-protocol soak

`utcp_positive_protocol_soak` has four independent lanes: `ipv4` builds valid
TCP, UDP and ICMP IPv4 datagrams and checks the parsed headers and transport
checksums; `options` writes and parses legal TCP SYN and ACK options; `stream`
delivers four segments of one normal stream out of order, compares the receive
buffer against `NaiveReassembler`, checks every returned byte and reaches FIN;
`peers` exchanges TCP with FIN, UDP datagrams and ICMP echoes between two
ordinary stack peers and checks the returned content. All protocol bytes are
generated in the process. No file is used as a protocol input.

The runner logs a monotonic `steady_ns`, elapsed nanoseconds, completed cases,
the numeric seed and a rolling FNV-1a 64-bit digest. The digest absorbs each
validated case's canonical bytes and selected counters. `--cases N` with the
same lane and seed replays the first N cases, so a final `completed=N` can be
rechecked independently. The test exits on the first mismatch. `exit=0` on a
final record appears only after all case checks pass; the runner also saves
each process exit status separately.

## Build

From this checkout on `home-ubuntu`, with build output in a new
`~/Desktop/utcp-data` subdirectory:

```bash
root=$HOME/Desktop/utcp-wt/m3-positive-four-dev-n23
data=$HOME/Desktop/utcp-data/m3-positive-four-n23
taskset -c 22-25 nice -n 10 cmake -S "$root" -B "$data/build-clang21-debug" -G Ninja -DCMAKE_CXX_COMPILER=clang++-21 -DCMAKE_BUILD_TYPE=Debug -DUTCP_SANITIZE=ON -DUTCP_FUZZ=OFF
taskset -c 22-25 nice -n 10 cmake --build "$data/build-clang21-debug" --target utcp_positive_protocol_soak -j4
taskset -c 22-25 nice -n 10 cmake -S "$root" -B "$data/build-clang21-relwithdebinfo-2048" -G Ninja -DCMAKE_CXX_COMPILER=clang++-21 -DCMAKE_BUILD_TYPE=RelWithDebInfo -DUTCP_RING_CHUNK_BYTES=2048 -DUTCP_SANITIZE=ON -DUTCP_FUZZ=OFF
taskset -c 22-25 nice -n 10 cmake --build "$data/build-clang21-relwithdebinfo-2048" --target utcp_positive_protocol_soak -j4
```

Both configurations use Clang 21 ASan and UBSan. Ubuntu currently exposes
only `clang++-21`; the two builds use different optimization and chunk-size
settings. A requirement for two distinct Clang versions needs another
compiler installed by the independent verifier.

## Independent long run

Run one build at a time. `7210` seconds leaves ten seconds for process launch
skew while requiring every lane and their common overlap to reach 7200 seconds.
Each lane is pinned to one of CPUs 22–25 and runs at nice 10. The four lanes
run concurrently. The output directory must be new.

```bash
b=$data/build-clang21-debug/tests/soak/utcp_positive_protocol_soak
"$root/tests/soak/run_positive_protocol_soak.sh" "$b" "$data/accept-debug-01" 7210 7200 20261123
b=$data/build-clang21-relwithdebinfo-2048/tests/soak/utcp_positive_protocol_soak
"$root/tests/soak/run_positive_protocol_soak.sh" "$b" "$data/accept-rel-01" 7210 7200 20261123
```

For a one-minute progress smoke, replace the output directory and use `65 60`.
For a quick deterministic replay, run `--lane stream --seed 20261123 --cases
100` on either build and compare the final digest. The verification script
checks exit statuses, minute gaps, each lane's duration and the common
monotonic overlap; the raw logs and process statuses remain under `utcp-data`.
