# Valid IPv4 datagrams and complete receive streams

## Acceptance registered before the run

Run two separate single-threaded workloads at Git revision recorded in each
receipt, with a fresh Clang 21 Debug ASan+UBSan build, abort on the first
sanitizer or reference check failure, and retain their raw receipts. For this
acceptance use run **20261121**, scale **16**, first batch **0** and **7200
seconds per lane**. A two-hour result requires both successful exits, one
completed GoogleTest per lane, valid counts and at least 7,200,000,000,000
verified monotonic nanoseconds in *each* lane. The lanes may run concurrently.
Building, launching, logging, hashing and time between batches earn no workload
credit. Each uninterrupted process advances to its next batch until its own
checked workload durations reach the threshold. Report wall time separately.

For each batch, bit 63 of its unsigned 64-bit seed is 1, bits 32–62 encode the
run number, bit 31 selects the lane (wire 0, stream 1), and bits 0–30 are the
sequential batch index. Use distinct run numbers for separate campaigns.
Reusing a run, lane, batch index and scale reproduces its generated data.
Counts describe completed generated cases, including intentional repeats within
a stream. Distinct seeds identify separate batches; bytewise uniqueness of
all generated packets is not measured. Historical tests retain seeds 101, 202,
303 and 404 and their original input sequence.

The wire lane exercises the existing legal IPv4/TCP, UDP and ICMP profiles.
Each trial checks three IPv4 envelopes, one per transport/message. A port
unreachable message quotes the previously generated UDP datagram. The oracles
compare decoded fields, options, quoted bytes and payload with the generation
specifications. Packet builders share project serialization and checksum
helpers. This is an in-memory consistency check with bounded legal profiles.

The stream lane constructs each stream from two windows of 4,097–8,191 bytes
each. Both use multiple segments. The first arrives in order. The second
receives its tail first, an exact repeat, and shuffled remaining segments.
Every insert and ordinary read checks state against the byte-level reference,
and each read checks bytes against the original. Both windows must fully drain
and pass an empty-read check. At receipt of the tail in the final window, the
receive buffer records its FIN offset. FIN must initially be pending and later
reached at the drained byte offset. This exercises the receive-buffer API;
TCP connection-state transitions, wire FIN exchange and external network I/O
are outside the workload.

## Run and independently read back

Use two CPUs within the project's 16–31 allocation at nice 10, an offline
testbed, and empty per-lane directories on the private project data volume.
Build from the clean checkout at the same absolute path that the runner will
see. The build needs local GoogleTest sources, Ninja and Python 3.11+. The
registered run uses CPUs 24 and 25. This example uses CPUs 16 and 17 inside
the testbed with the checkout at /src and a new private results directory
at /results.

~~~sh
cd /src
nice -n 10 taskset -c 16-23 cmake --preset clang-asan
nice -n 10 taskset -c 16-23 cmake --build --preset clang-asan --target utcp_unit_tests -j6
nice -n 10 taskset -c 16 python3 tools/valid_soak.py run wire --run 20261121 --output /results/wire &
wire_pid=$!
nice -n 10 taskset -c 17 python3 tools/valid_soak.py run stream --run 20261121 --output /results/stream &
stream_pid=$!
wait "$wire_pid"; wire_status=$?
wait "$stream_pid"; stream_status=$?
test "$wire_status" -eq 0 && test "$stream_status" -eq 0
python3 tools/valid_soak.py check /results/wire
python3 tools/valid_soak.py check /results/stream
~~~

For a short smoke run choose another run number, a new output path and
e.g. --seconds 2 --scale 1. The check command accepts --expected-batches N
for an external count cross-check. Both run commands need separate output
paths. A failed or interrupted run leaves its available logs for inspection.
For a stream smoke receipt with at least two batches,
`python3 tests/selftest/valid_soak_receipt.py /path/to/stream-smoke` exercises
the offline checker using temporary copies.

start.json records the Git commit, tree and archive digest, selected source
file digests, compilation database digest, test compile and link commands,
compiler identity and executable digest, measured binary digest, effective
affinity and sanitizer settings. These checkout records describe the source
snapshot. A fresh independent build establishes its correspondence with the
measured executable. test.log records per-batch steady-clock boundaries,
64-bit seed and work counts. test.xml carries the GoogleTest verdict and
last-batch properties. exit.json records the process exit, wall clock bounds
and executable digest rechecked after exit. summary.json totals passing batch
data and links the log and XML by SHA-256. The offline check requires this
saved summary. It matches the final log batch's seed and counters against the
test case's XML properties, then compares every summary field with its value
recomputed from the raw files. These checks establish internal consistency.
Authenticating the origin of a receipt requires separate evidence, such as a
signature verified with a trusted key. Retain the testbed image ID and fresh
build output alongside these receipts.
