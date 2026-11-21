# Upstream scripts for ordinary IPv4 TCP

At Google Packetdrill revision `15ab46aedd01a5e664ec5cfb2b1888328cdd3901`,
six unmodified upstream scripts parsed successfully. None of the six qualified
as a complete test for the current nonblocking IPv4 adapter. The closest case
covers an active handshake, a 1,000-byte write, its ACK and an orderly close.
A live invocation of this case loaded the adapter and exited 1 during Linux
initialization, before the handshake. The project's two ordinary scripts
passed twice each against the same binary, adapter and container settings.

## Selection

The shortlist covers the four named blocking socket operations, the plain
local-first orderly close, and a nonblocking client exchange with ordinary
data and ACKs. The table describes whole scripts as shipped, including their
preconditions. It makes no coverage claim for other upstream tests.
Every row runs the Linux defaults script before the first socket call.
That script sets kernel TCP parameters and configures the queue on `tun0`.
[Upstream TCP tree](https://github.com/google/packetdrill/tree/15ab46aedd01a5e664ec5cfb2b1888328cdd3901/gtests/net/tcp)
and [shared initialization](https://github.com/google/packetdrill/blob/15ab46aedd01a5e664ec5cfb2b1888328cdd3901/gtests/net/common/defaults.sh)

| Original under `gtests/net/tcp/` | Additional requirement in original (line numbers at the pin) | Parser exit | Live execution |
| --- | --- | ---: | --- |
| `blocking/blocking-accept.pkt` | Lines 6–17 require SO_REUSEADDR, an accept that waits for the handshake, window scale 8 and a single 2,000-byte output segment. | 0 | Not run |
| `blocking/blocking-connect.pkt` | Lines 6–12 require a timed, successful blocking connect and specific SYN options including timestamps, SACK and window scale 8. | 0 | Not run |
| `blocking/blocking-read.pkt` | Lines 7–23 require SO_REUSEADDR, window scale 8 and blocking reads that wake when the peer data arrives. | 0 | Not run |
| `blocking/blocking-write.pkt` | Lines 4–6 and 19–31 set a Linux TSO parameter and check Linux send-buffer doubling and the ACK that wakes a blocked writer. | 0 | Not run |
| `close/close-local-close-then-remote-fin.pkt` | Lines 7–11 require blocking connect to return success while the handshake runs. The adapter returns EOPNOTSUPP for this call. | 0 | Exit 1 in initialization |
| `nagle/https_client.pkt` | Lines 5–16 switch TUN offloads, set Linux timestamps, request O_RDWR with O_NONBLOCK, set TCP_NODELAY and assert SACK plus window scale 8. | 0 | Not run |

The adapter implements synchronous nonblocking connect, accept, read and
write. Its `fcntl(F_SETFL)` accepts only the O_NONBLOCK bit, its `setsockopt`
callback returns ENOSYS, and its configured SYN options enable only MSS.
The screen preserves each script's Linux setup, socket behavior and expected
wire segments. [Adapter implementation](../../../tests/packetdrill/adapter.cpp)

## Reproduce

Build the pinned upstream Packetdrill in the ignored `build/packetdrill/upstream`
directory using the [build instructions](README.md#run). On the Ubuntu testbed
use CPUs 16–23 for the configure and build commands as well. From the project
root run the following command.

```bash
UTCP_PACKETDRILL_CPUS=16-23 tests/packetdrill/run.sh --upstream-ordinary
```

The runner records each original's SHA-256 and feeds it to Packetdrill's
`--dry_run`. At this revision that option returns immediately after parsing.
It then invokes the local-first close script from its own directory with
`--so_filename` and the project's strict packet and timing checks. The
container uses the caller's UID, a read-only filesystem, a private network
namespace with networking disabled, no capabilities and no new privileges.
[Upstream parser entry point](https://github.com/google/packetdrill/blob/15ab46aedd01a5e664ec5cfb2b1888328cdd3901/gtests/net/packetdrill/packetdrill.c#L107-L126)

The developer run on Stack base `8e6bdfe6673a54d89bb9a1f01e50667f50900757`
reported a read-only sysctl filesystem, missing `tun0` and exit 1 from the
initialization command in the close script. Its TCP assertions were never
reached. Both repetitions of the project active case wrote 5 bytes, reached
TIME-WAIT and matched five outgoing packets. The passive case read 4 bytes,
fired the delayed ACK timer, observed EOF, reached LAST-ACK and matched four
outgoing packets. These four completed runs used project-authored scripts.

The run printed `build/packetdrill/receipts/run-880Roucy/`. That directory
contains `upstream.tsv` (phase, original, exit), `upstream.sha256`, the original
close invocation's log, the four project logs and `tools.txt` with tool and
image hashes. The project branch carries references and results. The original
scripts and their license are retained in the separate upstream checkout.
[Upstream license](https://github.com/google/packetdrill/blob/15ab46aedd01a5e664ec5cfb2b1888328cdd3901/LICENSE)
