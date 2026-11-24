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

## Independent run on 2026-11-21

Both lanes passed the registered 7,200-second threshold under Clang 21.1.8
Debug with ASan and UBSan. Each process completed one GoogleTest and exited
with status 0. The lanes ran concurrently at nice 10 on CPUs 24 and 25 in
an offline Ubuntu testbed. Active time sums the checked duration of each
batch. Elapsed time spans process start through exit.

| Measurement | Valid IPv4 datagrams | Receive-buffer streams |
| --- | ---: | ---: |
| Active seconds | 7,200.033542460 | 7,200.823695115 |
| Process elapsed seconds | 7,201.011741621 | 7,201.191206877 |
| Completed batches | 19,854 | 5,181 |
| First batch seed | `9310392888930074624` | `9310392891077558272` |
| Last batch seed | `9310392888930094477` | `9310392891077563452` |

At scale 16, the wire lane checked **121,982,976 valid IPv4
datagrams**. TCP, UDP and ICMP each accounted for 40,660,992.
The stream lane checked **1,326,336 complete streams**, each with an
ordered window and a reordered window. All 2,652,672 windows
drained and all 1,326,336 receive-buffer FIN offsets were reached.
Across 31,801,598 checked reads, **13,582,105,777 bytes** matched both
the byte-level reference and the original payload. The independent verifier
reconstructed every batch's seed and counts, including the stream operation
counts. These counts include the deliberate repeats described above.
[Machine-readable totals, timings and log hashes](results/m3-fuzz/valid-soak-20261121.json)

These are valid-input tests. The one-million-seed simulator campaign and the
four-hour arbitrary-input fuzz campaigns ran later and are reported
separately: [simulator campaign](RESULTS.md#one-million-seed-simulator-campaign) ·
[fuzz campaign](RESULTS.md#arbitrary-input-fuzzing). The fixed-seed suite has its
own [historical results](results/m3-fuzz/VALID_WIRE_STREAM.md).

### Evidence and reproduction

| Artifact | Identifier |
| --- | --- |
| Measured source commit | `ac8e2827e04184b00f9c4aea4488c627ede0b49c` |
| Measured source tree | `3d5282a7a5e0db0f42e39e37e03459eea504a2c6` |
| Measured Git archive, SHA-256 | `90674540d0ce7194ba244f53cae71d72ceb3c44add2fb6a3be9fbf9416296767` |
| Measured test executable, SHA-256 | `f10e34bacf6aa96f588be3f7e0b66ef48d2ca7ace7bb966be8607aeac46b1992` |
| Revised offline checker commit | `dd56f1a0b91b16d04ac7f9f8c8641a90d65a6434` |
| Revised checker source file, SHA-256 | `9d0c5bc9d3cb5786733caf265c7e67a7abd32c9258aba1ef53bbbf768a3983ba` |
| Independent report (`report.json`), SHA-256 | `35c5bb21668e109912f8a5b9218960f958c1b6e1a97a3785c2b212af07b1284b` |
| Independent report (`REPORT.md`), SHA-256 | `b558d6ac291fe5b964fd27dd368a220e2810788f90e0e1d15f322de0f78ca2f3` |
| Published summary (`valid-soak-20261121.json`), SHA-256 | `fbe6ca153ef254af4b0c54360f65c2e3ca8cb116e1ad82b2a1f4c08430b54941` |
| Original receipt file index (`volume-source.sha256`), SHA-256 | `f65a420a4a17d1abba9f9431f0a653c6b941ca9fa11491a6c96715b2e797920d` |

The formal receipts reside at `utcp-data:/valid-soak-independent-n21` in
the `wire` and `stream` directories. The Ubuntu audit directory is
`~/Desktop/utcp-wt/valid-soak-independent-n21/reviewer-takeover-20261121`.
It retains the independent report, per-file digest index, original receipt
copies and the revised checker's output. To check archived files from that
directory, run

~~~sh
sha256sum --strict -c report.sha256
(cd evidence && sha256sum --strict --quiet -c ../volume-source.sha256)
~~~

To read back both lanes, set `archive` to the absolute path of that audit
directory. From a checkout of the revised checker commit, run

~~~sh
python3 tools/valid_soak.py check "$archive/evidence/wire" --expected-batches 19854
python3 tools/valid_soak.py check "$archive/evidence/stream" --expected-batches 5181
~~~

For a new timed run, use the measured source commit, the image ID in the
machine-readable summary and the [build and run commands](#run-and-independently-read-back)
above with fresh output directories. CPUs 24 and 25 reproduce the recorded
affinity. A repeat with the same run and scale regenerates the same inputs
for each matching batch index. Machine speed determines the final batch
when the active-time threshold is reached. The original commands are saved in
`evidence/audit/inside.sh` and `evidence/audit/launch.sh`.
