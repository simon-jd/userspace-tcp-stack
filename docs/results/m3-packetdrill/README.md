# Packetdrill functional verification

The Packetdrill shared object loads a real `utcp::Stack` for the two
[nonblocking IPv4 cases](../../../tests/packetdrill/). Both scripts passed
twice with unmodified Google Packetdrill. The tests cover active and passive
open, transfer of a small payload, and orderly FIN exchange. The passive case
also checks the delayed ACK, an empty read before data arrives, and EOF after
the peer's FIN. [RFC 9293 §§3.5–3.8](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5)
[Verification receipt](verification.md)

[Screen of six upstream Linux TCP scripts](upstream-ordinary.md)

| Case | Packetdrill checked | Stack and adapter observed |
| --- | --- | --- |
| Active open | `EINPROGRESS`, handshake, successful 5-byte write, data sequence and peer ACK, both FINs and the last ACK | ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, TIME-WAIT. Four inbound datagrams delivered and five outbound packets matched. One TIME-WAIT entry remained, with zero live TCP slots and zero queued output. |
| Passive open | `EAGAIN` before connection and before data, accepted socket, 4-byte read, cumulative ACK at 195–205 ms, EOF, and both FINs acknowledged | SYN-RECEIVED and ESTABLISHED. The read buffer held four zero bytes supplied by the script. The Stack fired its delayed ACK timer 200 ms after data arrival. CLOSE-WAIT and LAST-ACK led to CLOSED. Six inbound datagrams reached TCP, including Packetdrill's cleanup packet. Four outbound packets matched. Zero live TCP slots, TIME-WAIT entries, and queued output. |
| Wrong expected ACK | Exit 1 after the handshake with `tcp_ack_seq: expected: 2 (0x2) vs actual: 1 (0x1)` | The input and Stack were identical to the positive active case. Only a script expectation changed. |
| Missing expected egress | Exit 1 after the normal FIN exchange with the `packet of 0 bytes` diagnostic | An additional expected ACK had no corresponding output. The adapter stopped waiting after its virtual bound. |

## Run

Use the project testbed image and GCC 15 on Ubuntu. Build Packetdrill in this
checkout's ignored build directory. The Ubuntu commands below unpack build
dependencies locally, using the existing APT package index.

```bash
work="$PWD/build/packetdrill"
mkdir -p "$work/deps/downloads" "$work/deps/root"
git init -q "$work/upstream"
git -C "$work/upstream" remote add origin https://github.com/google/packetdrill.git
git -C "$work/upstream" fetch --depth=1 origin 15ab46aedd01a5e664ec5cfb2b1888328cdd3901
git -C "$work/upstream" switch --detach FETCH_HEAD

(
  cd "$work/deps/downloads"
  apt-get download bison flex
  for pkg in *.deb; do
    dpkg-deb -f "$pkg" Package Version
    sha256sum "$pkg"
    dpkg-deb -x "$pkg" ../root
  done
)
(
  export PATH="$work/deps/root/usr/bin:$PATH"
  export BISON_PKGDATADIR="$work/deps/root/usr/share/bison"
  cd "$work/upstream/gtests/net/packetdrill"
  taskset -c 30,31 nice -n 10 ./configure
  taskset -c 30,31 nice -n 10 make -j2
)
tests/packetdrill/run.sh
```

`run.sh` builds the position-independent `utcp_core` archive and the adapter,
then runs each case twice and both control scripts once. It checks the positive
exits, independent Stack trace markers, byte count and read content, and the
specific negative diagnostics. Its logs and hashes are in
`build/packetdrill/receipts/`. The Docker process runs as the invoking user with
all capabilities dropped, `--network none`, a read-only checkout mount, an
8-second process timeout, and a 64 MiB process memlock limit for the upstream
`mlockall`. Packetdrill uses a namespace-local kernel socket to reserve an
ephemeral port. Script traffic passes through the adapter as IPv4 bytes.
The default affinity is CPUs 30–31 at nice 10 with up to two build jobs.
`UTCP_PACKETDRILL_CPUS` and `UTCP_PACKETDRILL_IMAGE` select the runner's CPU
and image settings.

## ABI and coverage

The adapter compiles against the upstream header and exports
`packetdrill_interface_init`. It uses Stack handles for the scripted system
calls and reserves descriptors with `eventfd` for Packetdrill's descriptor
bookkeeping. Peer addresses for `accept` come from the Stack connection trace.
Ingress calls `Stack::receive`, and egress drains `Stack::pop_transmit` with
the Stack's transmit timestamp. Packetdrill verifies relative sequence
numbers, TCP flags, MSS, payload length, and packet times.
[Upstream ABI header](https://github.com/google/packetdrill/blob/15ab46aedd01a5e664ec5cfb2b1888328cdd3901/gtests/net/packetdrill/packetdrill.h)

Each clock read ticks virtual time by 1 µs to let Packetdrill's final busy
wait finish. Sleep callbacks move virtual time forward through Stack
deadlines. An empty egress queue advances to the earlier of a new packet
or 500 ms of virtual time. At the pinned revision the shared-object reader
retries a nonzero callback status and ignores its own receive timeout
parameter. The adapter reports zero bytes on timeout, so the upstream
packet parser rejects the expectation immediately. Packetdrill still
does its process startup using the host's `times(2)`.
[Upstream reader](https://github.com/google/packetdrill/blob/15ab46aedd01a5e664ec5cfb2b1888328cdd3901/gtests/net/packetdrill/so_testing.c)
[Upstream clock integration](https://github.com/google/packetdrill/blob/15ab46aedd01a5e664ec5cfb2b1888328cdd3901/gtests/net/packetdrill/run.c)

Coverage is limited to one connection per script and synchronous,
nonblocking TCP callbacks. The adapter uses the RFC profile, 1500-byte MTU,
and seed 1. The scripts negotiate MSS and leave timestamps, window scaling,
and SACK disabled. The 200 ms delayed ACK reflects the selected profile's
configuration. Blocking callbacks, IPv6, other socket options, Linux-specific
tests, TIME-WAIT expiration, and performance measurements are outside these
cases. The revision's header carries the GPL-2.0-or-later notice. Upstream
source and build products stay in the separate ignored checkout.
[Upstream license](https://github.com/google/packetdrill/blob/15ab46aedd01a5e664ec5cfb2b1888328cdd3901/LICENSE)
