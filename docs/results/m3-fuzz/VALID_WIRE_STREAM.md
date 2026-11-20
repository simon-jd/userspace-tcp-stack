# M3 valid wire and receive-stream properties

The four recorded seeds are `101`, `202`, `303` and `404`. With
`UTCP_VALID_PROPERTY_SCALE=1024`, they completed 1,572,864 IPv4 datagram
round-trips and 65,536 receive streams. All eight scaled test entries passed
under Clang 21.1.8 ASan and UBSan on Ubuntu in **106.05 seconds** of
wall time. The focused CTest command passed 83 entries in **57.03
seconds**, including eight default-scale property entries. The new test
translation unit also compiled with GCC 15.2.0 in the project's debug build.

[Per-seed counts](valid-wire-stream-counts.csv) come from GoogleTest XML.
The IPv4 total contains 524,288 each of TCP, UDP and ICMP datagrams. The
receive-buffer run compared 1,704,693 inserts and 1,685,150 reads against
`NaiveReassembler`, including 131,072 repeated inserts, 1,182,552
out-of-order first deliveries and 272,643 hole fills. All 671,059,730 bytes
read also matched the original generated streams.

## Coverage

- The wire tests serialize and parse unfragmented IPv4 datagrams with base
  headers and lengths up to 1,500 bytes. The TCP profiles exercise SYN,
  SYN-ACK, ACK and data-bearing ACK with PSH, all 16 SYN option subsets,
  and every supported ACK SACK block count with and without timestamps.
  UDP includes computed and omitted checksums. ICMP includes echo requests,
  echo replies and port-unreachable messages with valid UDP quotes. The
  decoded header fields, option values and payload bytes are checked with
  checksum verification enabled.
- Each receive-stream trial uses a 4,096–8,191-byte capacity and two
  complete windows. The sender divides each window into variable chunks,
  delivers the last chunk first, repeats it byte-for-byte and shuffles the
  rest. Each insert compares its outcome and buffer state with the
  existing byte-based reference. Each read compares its count and bytes
  with the reference and the original stream. The test drains both windows
  and checks chunk return to the pool.
- The stock suites already cover Linux wire fixtures, randomized IPv4/TCP
  header round-trips, directed option and error handling, ICMP
  fragmentation-needed, and checksums. The five stock receive-buffer
  differential tests cover one million insert, read and FIN operations in
  total, with additional grow and drop operations. Stock directed cases
  also cover advertised-window clipping, FIN and range or pool pressure.
  The scaled results apply to the valid in-memory cases described above.

## Reproduction on Ubuntu

The run used base `22b7cf30961cffb4b456c01aafb8c662f404212d`, Ubuntu
kernel `7.0.0-42-generic`, CMake 4.2.3 and Ninja 1.13.2. Run from the
repository root with the distro GoogleTest sources installed.

```bash
taskset -c 24-29 nice -n 10 cmake --preset clang-asan -DUTCP_FUZZ=OFF
taskset -c 24-29 nice -n 10 cmake --build --preset clang-asan -j 6 --target utcp_unit_tests
proof="$PWD/build/m3-wire-stream-rerun"
mkdir -p "$proof"
unset UTCP_VALID_PROPERTY_SCALE
regex='^unit\.((Wire(Ipv4|Tcp|Udp|Icmp)(DeathTest)?|RecvBuffer(DeathTest)?|NaiveReassembler)\.|Seeds/ValidWireStream\.)|^ci\.test_names$'
taskset -c 24-29 nice -n 10 ctest --preset clang-asan -j 6 -R "$regex" --output-junit "$proof/ctest.xml"

export UTCP_VALID_PROPERTY_SCALE=1024
export ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
binary=build/clang-asan/tests/unit/utcp_unit_tests
pids=()
for seed in 101 202 303 404; do
  taskset -c 24-29 nice -n 10 /usr/bin/time -o "$proof/seed-$seed.time" \
    -f 'elapsed_seconds=%e exit_status=%x' timeout 8m "$binary" \
    --gtest_filter="Seeds/ValidWireStream.*/$seed" --gtest_color=no \
    --gtest_output="xml:$proof/seed-$seed.xml" > "$proof/seed-$seed.log" 2>&1 &
  pids+=("$!")
done
status=0
for pid in "${pids[@]}"; do
  wait "$pid" || status=1
done
test "$status" = 0
```

The Ubuntu proof archive at
`~/Desktop/utcp-wt/m3-wire-reference/build/m3-wire-reference-proof.tar.gz`
includes the final build and test logs, CTest and GoogleTest XML, timings,
source and executable hashes, toolchain and CPU information, and the count
validator. Its SHA-256 is `aa75bd267460bc4c937ce64c5958270d02e13c1dc7d08ec6b4b8d0c7672418b0`.
