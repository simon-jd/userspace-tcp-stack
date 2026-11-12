# userspace-tcp-stack: design

This document fixes the architecture for M1 and the interfaces that M2 to M4 build on. Section numbers are
referenced from the M1 task list. "M1" marks what the first milestone ships; "M2a/M2b/M2c/M3/M4" marks later
work whose hooks exist from M1. RFC references are to sections (RFC 9293 is the base specification).

## 1. Goals, non-goals and scope

### 1.1 Goals

- An IPv4 TCP/UDP/ICMP endpoint stack in C++23 whose protocol logic is a deterministic, sans-I/O library
  (`utcp_core`). Inputs: IPv4 datagrams, the current time, a seed. Outputs: IPv4 datagrams, socket readiness
  events, the next deadline. Same inputs give byte-identical outputs.
- The same core runs on a Linux TUN device (`utcp_backend`) and inside a discrete-event simulator (`utcp_sim`).
- Interoperates with Linux 7.0 TCP in every combination of SACK, timestamps and window scaling, under loss,
  reordering and duplication, and across a 1400-byte path MTU.
- M1 implements RFC 9293 with RFC 7323, 2018, 2883, 5961, 6298, 6528, 6056, 1191, 5927, 5681 and 6582.
  M2 adds RFC 6675, 9937 (PRR; obsoletes RFC 6937), 8985, 9438, 9406 and BBRv1 as in Linux `tcp_bbr.c`.
- Two parameter profiles, `rfc` and `linux_compat` (§3.9), so that M2 differences against Linux can be attributed to
  named knobs.
- Per-connection statistics that map onto `ss -ti` / `TCP_INFO`, an event trace, and pcap output.

### 1.2 Non-goals

Stated in the README as well:

- IPv6, TLS, QUIC, MPTCP (MP_CAPABLE is ignored, so peers fall back to plain TCP, RFC 8684 §3.1).
- IP fragmentation and reassembly. Every datagram is sent with DF set and is never larger than the path MTU.
  Received fragments (MF set or non-zero offset) are dropped and counted.
- ECN. The SYN never carries ECE/CWR; a SYN with ECE+CWR (RFC 3168) or AE+CWR+ECE (AccECN, Linux `tcp_ecn` 3-5)
  is answered with AE = CWR = ECE = 0, so ECN is not negotiated (RFC 3168 §6.1.1). Data is sent Not-ECT; CE marks
  on received datagrams are ignored.
- TCP Fast Open. Data on a SYN is not acknowledged (the peer retransmits it after the handshake); the TFO
  option is ignored.
- Urgent data (URG never sent; on receipt the pointer is ignored and data delivered inline, RFC 6093 §5) and IP
  options (skipped on receipt, never sent).
- SYN cookies, PLPMTUD (RFC 4821/8899), keepalive in M1. F-RTO (RFC 5682) and DSACK/timestamp undo are not
  modelled in any milestone; M2 results list them as named Linux behaviours (`tcp_frto = 2`, `tcp_try_undo_*`)
  that the stack lacks, and the CC hooks keep `prior_cwnd`/`undo_cwnd` so they can be added later.
- Running unmodified applications (no socket shim, no LD_PRELOAD); forwarding or routing (one endpoint, one
  interface, one address); a multi-threaded core (parallelism, if any, is one `Stack` per thread, §8.4).

### 1.3 Scope per milestone

| Area | M1 | Later |
|---|---|---|
| IPv4 | validate, demux, DF on send, PMTU cache | M4 checksum offload, GSO/GRO via `IFF_VNET_HDR` |
| ICMP, UDP | echo reply and API, unreachable in/out, frag-needed lowers MSS; unconnected UDP sockets | |
| TCP | full state machine, options, SACK/DSACK generation, RTO, delayed ACK, Nagle, SWS, ZWP, half-close, TIME_WAIT, RFC 5961, PAWS, RFC 6528/6056, NewReno | M2a RFC 6675, RACK-TLP, PRR; M2b CC interface users (CUBIC, HyStart/HyStart++), rate sampling, pacing; M2c BBRv1 |
| Simulator, apps | full simulator (§7), 1e5-seed sweeps; bulk, echo, httpd, http-get | M3 1e6 seeds |
| Backend | TUN (`IFF_TUN` + `IFF_NO_PI`), `epoll_pwait2` | M4 `IFF_VNET_HDR`, multi-queue; optional io_uring |

## 2. Structure

```
  apps (utcp-bulk, utcp-echo, utcp-httpd, utcp-http-get, utcp-sim)
        |  Transport interface (apps/common/transport.hpp): kernel sockets | utcp
        v
  +------------------------- utcp_core (sans-I/O) --------------------------+
  | Stack: socket API, events | IPv4 | ICMP | UDP | TCP engine | timers      |
  |   receive(now, datagram)  advance(now)  pop_transmit()  next_deadline() |
  +------------------^-------------------------------------|----------------+
                     | datagrams in                        | datagrams out
         utcp_backend (TUN + epoll_pwait2)      or      utcp_sim (virtual links, clock)
```

### 2.1 Repository layout and targets

| Path | Content | Target |
|---|---|---|
| `include/utcp/` | public headers: core (`checksum.hpp` from M0, `time.hpp`, `types.hpp`, `error.hpp`, `random.hpp`, `config.hpp`, `packet.hpp`, `stack.hpp`, `stats.hpp`, `trace.hpp`, `pcap.hpp`, `retry_model.hpp`; `defs/*.def` and the per-owner `defs/config_*_types.hpp`); backend (`tun_device.hpp` from M0, `event_loop.hpp`) | |
| `include/utcp/sim/` | public headers of the simulator | |
| `src/core/` | `checksum.cpp` (M0), `util/`, `buffer/`, `timer/`, `wire/`, IP/ICMP/UDP files, `tcp/` | `utcp_core` (static) |
| `src/sim/` | simulator | `utcp_sim` (static, depends on core) |
| `src/backend/` | `tun_device.cpp` (M0), event loop, monotonic clock | `utcp_backend` (static, depends on core) |
| `apps/common/` | `Transport` interface and its two implementations, SHA-256, JSONL writer, CLI parsing | `utcp_appkit` (static; addition to the M0 target list) |
| `apps/<name>/` | one program per directory; logic that is unit-tested sits in a static library registered with `utcp_app_logic()`, its tests in `apps/<name>/*_test.cpp` go into `utcp_unit_tests` | `tun_probe` (M0), `utcp-bulk`, `utcp-echo`, `utcp-httpd`, `utcp-http-get`, `utcp-sim` |
| `tests/unit/`, `tests/sim/` | GoogleTest files `*_test.cpp`, globbed into `utcp_unit_tests` and `utcp_sim_tests` | |
| `tests/support/`, `tests/interop/`, `tests/fuzz/` | shared test code (naive reassembler, loopback harness); container interop scripts and helper programs (one executable per `tests/interop/*.cpp`, linked with `utcp_appkit`); libFuzzer targets (clang, `-DUTCP_FUZZ=ON`) | |
| `testbed/`, `ci/`, `docs/`, `tools/` | Dockerfiles and testbed scripts; CI; documents; analysis and plot scripts | |

GoogleTest 1.17 is built from `/usr/src/googletest` in each build tree (M0). There are no other dependencies:
SHA-256, SipHash, pcap and JSONL writers are in-repo. Configuration and scenario files use flat `key=value`
lines (no JSON parser needed); JSONL is output only.

M0 lists sources explicitly. The CMake files that several M1 tasks touch (`src/core`, `src/sim`, `src/backend`,
`tests/unit`, `tests/sim`, `tests/fuzz`, `tests/support` (static `utcp_test_support`), `apps`) switch to
`file(GLOB_RECURSE ... CONFIGURE_DEPENDS)` in the foundation task, so parallel branches never edit the same CMake
file. Because all test files link into two binaries, test helpers live in anonymous namespaces and suite names
start with the file stem (`ci/check-test-names.sh`). `CMAKE_CXX_EXTENSIONS` stays OFF (M0): in
`gnu++23` mode the identifier `linux` is a predefined macro.

### 2.2 Core purity, enforced

M0's ctest `core.forbidden_symbols` (`cmake/CheckCoreSymbols.cmake`) runs `nm -C -u` on `libutcp_core.a` and
fails on system-call wrappers, clocks (C and C++), random sources, threads, stdio and iostreams, and on any
symbol that `libutcp_backend.a` or `libutcp_appkit.a` defines (such as `utcp::mono_now()`, reachable through the
backend headers); a self-test proves it catches planted calls. M1 adds `core.no_float` (`ci/check-no-float.sh`):
`float` or `double` in the comment-stripped source (`g++ -fpreprocessed -dD -E -P`) of `src/core`, the core
headers, and every simulator source fails the build (§13.1); simulator files outside the generator and link
pipeline (pcap writer, results output) may opt out with a `// utcp-no-float: exempt (reason)` line.

## 3. Core API

### 3.1 Time

```cpp
namespace utcp {
using Duration = std::chrono::nanoseconds;        // signed 64-bit
struct Time {                                      // nanoseconds since an epoch chosen by the host
  std::int64_t ns = 0;
  static constexpr Time never() { return {std::numeric_limits<std::int64_t>::max()}; }
  constexpr auto operator<=>(const Time&) const = default;
  friend constexpr Time operator+(Time t, Duration d);   // saturates at never()
  friend constexpr Duration operator-(Time a, Time b);
};
}  // namespace utcp
```

The backend uses `CLOCK_MONOTONIC` nanoseconds; the simulator's virtual time starts at a seeded offset of at least
1 s (10 % of seeds start just below 2^32 ms, so 32-bit millisecond stamps wrap). Ported Linux code that uses 0 as
"unset" (`delivered_mstamp`, `epoch_start`, `retrans_stamp`) gets an explicit flag or `std::optional`. Protocol clocks
derive from `Time`: the TCP timestamp clock is `ns / 1'000'000` (1 ms ticks, as Linux `TCP_TS_HZ = 1000`) plus a
per-connection offset; the ISN clock M is `ns / 4000` (4 µs, RFC 6528 §3).

### 3.2 Addresses, sequence numbers, handles

```cpp
struct Ipv4Addr { std::uint32_t v; /* host order */ auto operator<=>(const Ipv4Addr&) const = default; };
struct Endpoint { Ipv4Addr addr; std::uint16_t port; auto operator<=>(const Endpoint&) const = default; };
struct FourTuple { Endpoint local, remote; auto operator<=>(const FourTuple&) const = default; };
struct Range { std::uint64_t begin, end; };       // half-open, stream offsets
class Seq32 {        // RFC 9293 §3.4 modular arithmetic; no operator<, so it cannot key an ordered container
 public:
  constexpr explicit Seq32(std::uint32_t v); constexpr std::uint32_t raw() const;
  constexpr Seq32 operator+(std::uint32_t d) const; constexpr std::uint32_t operator-(Seq32 o) const;
  friend constexpr bool before(Seq32 a, Seq32 b) { return std::int32_t(a.v_ - b.v_) < 0; }
  friend constexpr bool after(Seq32 a, Seq32 b) { return before(b, a); }
 private: std::uint32_t v_;
};
enum class Proto : std::uint8_t { tcp, udp };
struct Handle { std::uint32_t slot; std::uint32_t gen; Proto proto; auto operator<=>(const Handle&) const = default; };
```

Wire-facing TCB fields use `Seq32`. Buffers use 64-bit stream offsets (offset 0 is the byte at ISN+1), converted
at one place (`unwrap(Seq32, Seq32 base, std::uint64_t ref)` in `include/utcp/seq.hpp`, signed so that a
SYN at ISN unwraps to −1). SYN and FIN occupy
sequence space but have no offset: the engine boundary clips received ACK and SACK ranges to `[una, end()]` of the
send queue (Linux acks and SACKs include the FIN), records an ACK of our FIN as `fin_acked`, and passes only payload
ranges to `RecvBuffer`/`SackGenerator`. Handles index a slot
vector; `gen` increments when a slot is reused, so a stale handle returns `Error::bad_handle`.

### 3.3 Packet buffers and ownership

```cpp
class PacketPool {     // fixed-size buffers (2 KiB in M1, plus a 64 KiB class in M4), LIFO free list, preallocated
 public:
  PacketPool(std::uint32_t count, std::uint32_t buf_size);
  std::optional<PacketBuf> alloc(std::uint32_t min_size, std::uint32_t headroom);  // one size class in M1
  std::uint32_t available() const;
};
class PacketBuf {      // move-only; the destructor returns the buffer to its pool
 public:
  std::span<std::byte> bytes();                     // [head, tail)
  std::byte* prepend(std::size_t n);                // into headroom: headers are built back to front
  std::byte* append(std::size_t n); std::size_t size() const;
 private: PacketPool* pool_; std::uint32_t index_, head_, tail_;  // 32-bit: the M4 64 KiB class + vnet header
};
struct TxPacket { PacketBuf buf;                    // one complete IPv4 datagram
  std::uint16_t gso_size = 0;                       // M4: >0 means a TCP super-segment split by the kernel
  bool csum_partial = false; };                     // M4: TCP checksum left to the kernel
struct RxMeta { bool csum_verified = false;         // M4: VIRTIO_NET_HDR_F_DATA_VALID
                bool csum_partial = false;          // M4: NEEDS_CSUM (field holds the pseudo-header sum); verified
                std::uint16_t gso_size = 0; };      // M4: GRO super-segment; rcv_mss uses it (tcp_measure_rcv_mss)
```

Ownership rules:

- Input datagrams are borrowed: `receive()` parses in place and copies payload into the destination socket's
  buffer before returning. The host may reuse its buffer immediately.
- Output datagrams are built into `PacketPool` buffers owned by the `Stack` and handed to the host as
  `TxPacket` by value; the host writes them and drops them, which returns the buffer.
- Socket data lives in per-connection `ByteRing`s: offset-addressed storage (`write_at`, `read_at`, `consume`,
  `bytes_held`) whose capacity is a limit, not an allocation. Storage is 4 KiB chunks from a per-`Stack`
  `ChunkPool` (grows on demand up to `StackConfig::chunk_limit`, LIFO reuse), taken when first written and
  returned when consumed, so idle connections hold no data memory. `tcp_send` copies application bytes in,
  `tcp_recv` copies them out; segments are built by copying from the send ring into a `PacketBuf`.

Allocation policy: steady-state per-packet work allocates nothing from the heap. Pools, the transmit queue, timer
heap and event queue are preallocated at `Stack` construction; the heap is used only on connection creation and
on chunk-pool or retransmission-queue growth, amortised (M1 also allows a map node per connection and vector
growth). M4 adds an `operator new` counter and requires zero allocations per packet in steady bulk and echo runs.

### 3.4 Stack: inputs and outputs

```cpp
class Stack {
 public:
  explicit Stack(const StackConfig& cfg);           // cfg.seed is the only source of randomness
  ~Stack(); Stack(const Stack&) = delete; Stack& operator=(const Stack&) = delete;
  // Host interface. `now` must be non-decreasing across calls.
  void receive(Time now, std::span<const std::byte> ipv4, RxMeta meta = {});
  void advance(Time now);                           // fire timers and pacing gates due at or before now
  std::optional<TxPacket> pop_transmit();           // FIFO; empty when nothing is queued
  [[nodiscard]] Time next_deadline() const;         // earliest timer or pacing gate; Time::never() if none
  [[nodiscard]] Time now() const;                   // time of the last receive/advance
  std::optional<SocketEvent> poll_event();          // §3.5
  // TCP, UDP, ICMP APIs: §3.5-3.7
  void set_trace_sink(TraceSink* sink);             // §10.2; nullptr disables
  const StackStats& stats() const;
  void debug_check() const;                         // verify internal invariants; aborts on failure
  StackUsage debug_usage() const;  // live slots, TIME_WAIT entries, free buffers/chunks, queued packets/events, armed timers
 private:
  std::unique_ptr<StackImpl> impl_;                 // one allocation at construction
};
```

Output model: all protocol work happens inside `receive`, `advance` and socket calls, as in Linux, where an
incoming ACK leads to data transmission in the same softirq (`tcp_rcv_established` calls `tcp_data_snd_check`
then `tcp_ack_snd_check`). Packets produced by a call go into a bounded transmit queue (`tx_queue_packets`,
default 1024) in production order, and the host drains them with `pop_transmit`. Host batching therefore does
not change protocol decisions such as ACK frequency, only their timing. When the queue or the pool is full,
connections stop producing data segments and join a FIFO of blocked connections that `advance` resumes; control
packets (RST, ICMP) that do not fit are dropped and counted. A pure ACK that does not fit stays pending (delayed-ACK
state is kept, as Linux `__tcp_send_ack` reschedules on allocation failure). Once `pop_transmit` or a buffer release
frees space, `next_deadline()` returns `now()` (no heap timer), and the next `advance` first resumes the blocked
connections in FIFO order.

Host contract:

1. Before blocking, the host drains `pop_transmit()` and `poll_event()` and re-reads `next_deadline()`.
2. When `now >= next_deadline()` the host calls `advance(now)`. Waking late is allowed (it is measured, §8.3).
3. Socket calls use `now()`, the time of the last `receive`/`advance`; an iteration starts with `advance(clock())`.
4. A `now` earlier than `now()` is a contract violation: clamped and counted in `stats().time_regressions`;
   `StackConfig::assert_time_monotonic` (off by default, on in the simulator) turns it into an assertion.

### 3.5 TCP socket API and events

The calls below, and those of §3.6-3.7, are members of `Stack`.

```cpp
enum class Shutdown : std::uint8_t { read, write, both };
struct TcpSocketOptions {                           // per socket; defaults come from TcpConfig
  std::optional<bool> nodelay;
  std::optional<std::uint32_t> snd_buf, rcv_buf;    // payload bytes; disables autotuning for that side
  std::optional<CcAlgo> cc;                         // M1: newreno only
  std::optional<std::uint16_t> mss_clamp;           // like TCP_MAXSEG
};
std::expected<Handle, Error> tcp_listen(Endpoint local, std::uint32_t backlog, const TcpSocketOptions& = {});
std::expected<Handle, Error> tcp_accept(Handle listener);                        // would_block if queue empty
std::expected<Handle, Error> tcp_connect(Endpoint remote, const TcpSocketOptions& = {},
                                         std::uint16_t local_port = 0);         // 0 = RFC 6056 ephemeral
std::expected<std::size_t, Error> tcp_send(Handle, std::span<const std::byte>);  // bytes accepted, may be short
std::expected<std::size_t, Error> tcp_recv(Handle, std::span<std::byte>);        // 0 = end of stream
std::expected<void, Error> tcp_shutdown(Handle, Shutdown);
std::expected<void, Error> tcp_close(Handle);                                    // handle invalid on return
std::expected<void, Error> tcp_abort(Handle);                                    // RST, handle invalid on return
Readiness tcp_readiness(Handle) const;                                           // level-triggered state
std::expected<TcpInfo, Error> tcp_info(Handle) const;                            // §10.1
std::expected<void, Error> tcp_set_options(Handle, const TcpSocketOptions&);
std::optional<Error> take_error(Handle);                                         // like SO_ERROR
```

| Call | Behaviour |
|---|---|
| `tcp_listen` | binds `local` (addr must be the stack address or 0); `addr_in_use` if another listener has the port. `backlog` bounds established-but-not-accepted children; SYNs beyond it (counting SYN-RECEIVED children) are dropped, as Linux does when the accept queue is full. |
| `tcp_accept` | pops the oldest established child. Children inherit the listener's options. |
| `tcp_connect` | allocates a port (§4.6), sends SYN; result via `connected` or `error` events. `addr_not_available` when no port is free. |
| `tcp_send` | copies up to the free send-buffer space; `would_block` if none; `shut_down` after `shutdown(write)`; the pending connection error otherwise. Allowed in SYN-SENT (data is queued). |
| `tcp_recv` | returns in-order data; then 0 after the peer's FIN; then the connection error if any. Buffered data is returned before an error (after RST, data already received is still readable). |
| `tcp_shutdown(write)` | queues FIN after buffered data (half-close, RFC 9293 §3.6). `shutdown(read)`: `tcp_recv` returns 0; later data is acknowledged and discarded. |
| `tcp_close` | if unread data remains, sends RST (RFC 1122 §4.2.2.13) and frees; otherwise behaves as shutdown(both) and the connection lives on as an orphan until CLOSED/TIME_WAIT. Data arriving after close also triggers RST. On a listener: closes it and RSTs non-accepted children. |
| `tcp_abort` | sends RST `<SEQ=SND.NXT>` if synchronized, frees immediately. |

Events are edge-triggered and coalesced. Each socket has a pending bitmask and sits at most once in a FIFO of
sockets with pending events; `poll_event()` returns the next one. The FIFO order is the order in which sockets
first became pending, which depends only on inputs. `ev_writable` fires when free send space rises to at least half
the queued bytes (Linux `sk_stream_min_wspace`); `ev_closed` fires once when the connection reaches CLOSED.

```cpp
enum Ev : std::uint16_t { ev_readable = 1, ev_writable = 2, ev_acceptable = 4, ev_connected = 8,
  ev_read_closed = 16 /* peer FIN */, ev_closed = 32 /* fully closed */, ev_error = 64 };
struct SocketEvent { Handle h; std::uint16_t events; };
struct Readiness { bool readable, writable, acceptable, read_closed, write_closed, has_error; };
```

```cpp
enum class Error : std::uint8_t {
  would_block, bad_handle, invalid_state, invalid_argument, addr_in_use, addr_not_available,
  not_connected, already_connected, connection_refused, connection_reset, connection_aborted,
  timed_out, host_unreachable, network_unreachable, message_too_big, no_buffers, shut_down };
std::string_view to_string(Error);
int to_errno(Error);                                // EAGAIN, EBADF, ... (used by apps and packetdrill shim)
```

### 3.6 UDP

```cpp
std::expected<Handle, Error> udp_open(Endpoint local);                         // port 0 = ephemeral
std::expected<void, Error> udp_send_to(Handle, Endpoint remote, std::span<const std::byte>);
struct UdpRecv { std::size_t len; Endpoint from; bool truncated; };
std::expected<UdpRecv, Error> udp_recv_from(Handle, std::span<std::byte>);     // would_block if empty
std::expected<void, Error> udp_close(Handle);
```

Unconnected sockets only. A datagram larger than `pmtu(dst) - 28` fails with `message_too_big` (no
fragmentation). Received datagrams are stored length-prefixed in a per-socket `ByteRing` of `udp.rcv_buf`
bytes (default 256 KiB); when full the datagram is dropped and counted. Checksums are always sent, a computed 0
as 0xFFFF; a received 0 means none (RFC 768). A datagram for an unbound port gets ICMP port unreachable
(rate-limited, §3.7). ICMP errors for UDP are counted, not reported to sockets. A UDP handle raises only
`ev_readable` (through `poll_event`, coalesced) when a datagram is queued on it, and no `ev_writable`: there is no
send buffer. `udp_send_to` queues the datagram at once or fails; with the transmit queue or pool full it returns
`no_buffers` (counted `UdpSndbufErrors`) and the caller retries after the host has drained `pop_transmit`. UDP
never joins the blocked-connection FIFO.

### 3.7 ICMP

- Echo requests to the stack address are answered (`icmp.echo_reply`, default on).
- Echo API: `std::expected<void, Error> icmp_echo(Ipv4Addr dst, std::uint16_t id, std::uint16_t seq,
  std::span<const std::byte> payload)` and `std::optional<EchoReply> poll_echo_reply()` (id, seq, from, len,
  receive time), bounded queue of 64.
- Generated errors: port unreachable for UDP, protocol unreachable for unknown protocols. Global token bucket of
  `icmp.rate_per_s = 1000` with burst 50 (Linux `icmp_msgs_per_sec`/`icmp_msgs_burst`).
- Received errors: the quoted IPv4 header plus at least 8 bytes of the transport header are required. Type 3
  code 4 goes to PMTU handling (§4.13); other unreachables go to TCP error handling (§4.7); source quench is
  ignored (RFC 6633); redirects are ignored; time exceeded is a soft error.

### 3.8 Randomness

```cpp
struct Seed { std::array<std::uint64_t, 4> w; };
class Rng {                                         // xoshiro256**, seeded via splitmix64; not cryptographic
 public:
  explicit Rng(const Seed&); std::uint64_t next(); std::uint32_t below(std::uint32_t n);  // unbiased (Lemire)
  static Rng derive(const Seed& master, std::string_view label);     // independent named stream
  static Seed derive_seed(const Seed& master, std::string_view label);
};
struct SipKey { std::uint64_t k0, k1; };
std::uint64_t siphash24(const SipKey&, std::span<const std::byte>);
```

The host injects `StackConfig::seed`: the backend fills it from `getrandom(2)`, the simulator derives it from the
scenario seed. At construction the stack derives keys with SipHash used as a PRF over the seed: `isn_key`,
`ts_offset_key`, `port_offset_key`, `port_table_key`, `hash_key` (connection-table hashing), and a runtime `Rng`
(test knobs such as `test_renege_ppm`; M2c: BBR's random initial PROBE_BW phase, `get_random_u32_below
(bbr_cycle_rand)` in Linux). Nothing else in the core is random.

### 3.9 Configuration and profiles

`StackConfig` holds stack-wide settings and a `TcpConfig` of per-connection defaults. `tcp_config(ProfileId)`
returns one of two profiles; any field can then be overridden (the M2 ablation flips one field at a time).

```cpp
enum class ProfileId : std::uint8_t { rfc, linux_compat };
TcpConfig tcp_config(ProfileId);
struct StackConfig {
  Ipv4Addr local_addr; std::uint16_t mtu = 1500; std::uint8_t ip_ttl = 64; Seed seed;   // mtu: interface MTU
  TcpConfig tcp = tcp_config(ProfileId::linux_compat); UdpConfig udp; IcmpConfig icmp;
  std::uint32_t pool_buffers = 4096, tx_queue_packets = 1024, max_connections = 65536, chunk_limit = 1u << 20;
  std::uint32_t trace_mask = 0;                     // §10.2
  std::uint16_t tx_headroom = 0;                    // M4: the backend reserves room for virtio_net_hdr
  bool assert_time_monotonic = false;               // §3.4 item 4; on in the simulator
};
```

`TcpConfig` fields (names as in the code). "Same" means both profiles use the value. Sizes are payload bytes;
Linux limits count `skb->truesize`, so a Linux buffer of nominal size N holds less than N bytes of payload.

| Field | `rfc` | `linux_compat` | Basis |
|---|---|---|---|
| `rto_min` | 1 s | 200 ms | RFC 6298 §2.4; Linux `TCP_RTO_MIN` |
| `rto_initial` | 1 s | 1 s | RFC 6298 §2.1; `TCP_TIMEOUT_INIT` |
| `rto_max` | 60 s | 120 s | RFC 6298 §2.5 (≥ 60 s); `TCP_RTO_MAX` |
| `rto_after_syn_rexmit` | 3 s | 3 s | RFC 6298 §5.7; `TCP_TIMEOUT_FALLBACK` |
| `rtt_estimator` | `rfc6298` (α 1/8, β 1/4, K 4, G 1 ms; RTO = max(SRTT + max(G, 4·RTTVAR), rto_min)) | `linux` (`tcp_rtt_estimator`: RTO = SRTT + rttvar, rttvar ≥ rto_min, decays by ¼ of its excess per RTT) | §4.8. The `rto_min` ablation flips both rows. |
| `rtt_sample_rule` | same: Linux `tcp_clean_rtx_queue` (seq_rtt for SRTT/RTO, ca_rtt for min_rtt and CC), TSecr fallback | | `tcp_ack_update_rtt`; RFC 6298 §3; RFC 7323 §4 |
| `initial_cwnd` | RFC 5681 §3.1 (3 segments at SMSS 1095..2190) | 10 | RFC 6928; `TCP_INIT_CWND` |
| `iw_after_syn_loss` | 1 after any SYN/SYN-ACK retransmission | 1 after more than one | RFC 5681 §3.1; RFC 6928 §2; `tcp_init_transfer` |
| `initial_ssthresh` | ∞ | ∞ | RFC 5681 §3.1 |
| `idle_restart` | `rfc5681` (cwnd = min(IW, cwnd) after idle > RTO) | `linux` (`tcp_cwnd_restart`: halve per RTO idle, floor IW) | RFC 5681 §4.1 |
| `cwnd_growth_needs_cwnd_limited` | same: yes | | Linux `tcp_is_cwnd_limited`; RFC 7661 |
| `recovery_reduction` (M2a) | `rfc6675` (cwnd = ssthresh on entry) | `prr` (SafeACK, as Linux 7.0) | RFC 6675 §5; RFC 9937; `tcp_cwnd_reduction` |
| `frto`, `undo` | same: not modelled | | Linux `tcp_frto = 2` and `tcp_try_undo_*` are on; named in M2 results (§1.2) |
| `rack_tlp` (M2a) | same: on | | RFC 8985; Linux `tcp_recovery=1`, `tcp_early_retrans=3` |
| `dupthresh` / adaptive reordering | 3 / fixed | 3 / adaptive up to 300 | RFC 5681; `tcp_reordering`, `tcp_max_reordering` |
| `cc` | same: `newreno` in M1; `cubic` from M2b | | |
| `hystart` (M2b) | `hystart_pp` | `hystart_classic` (ACK train + delay, low window 16, ack delta 2 ms) | RFC 9406; `tcp_cubic.c` |
| `pacing`, `pacing_ss_ratio`/`_ca_ratio` | same: rate always computed (§5.5), applied only if the CC requests it (BBR); 200 % / 120 % | | the 2d sender has no fq qdisc, so Linux CUBIC is unpaced; `tcp_update_pacing_rate` |
| `gso_max_size` (M2b) | same: testbed veth `gso_ipv4_max_size` − `MAX_TCP_HEADER` − 1, recorded | | `sk_setup_caps` (TCP always has GSO); pacing quantum, HyStart ACK delay |
| `delack_max` | 200 ms | 200 ms (`TCP_DELACK_MAX`) | RFC 9293 §3.8.6.3 (< 500 ms) |
| `delack_ato` | fixed 200 ms | adaptive 40..200 ms (`TCP_ATO_MIN`, inter-arrival estimate) | |
| `ack_every_full_segments` | same: 2 | | RFC 5681 §4.2; Linux `__tcp_ack_snd_check` |
| `quickack` | out-of-order and hole-filling segments only | also the first min(16, rcv_wnd/(2·rcv_mss)) segments and after an idle gap > RTO | RFC 5681 §4.2; `TCP_MAX_QUICKACKS`, `tcp_incr_quickack` |
| `nagle` | `rfc896` (hold small segment while any data unacked) | `minshall` (hold while a small segment is unacked) | RFC 9293 §3.7.4; `tcp_minshall_check` |
| `sack`, `timestamps`, `window_scaling`, `dsack`, `ts_offset_random` | same: on | | server sysctls; RFC 7323 §5.4 |
| `paws_disordered_ack` | `strict` (RFC 7323 §5.3 R1) | `linux` (old-TSval pure dup ACKs kept, `tcp_disordered_ack`, `TCP_PAWS_WINDOW` 1) | reordered ACKs keep their SACK blocks |
| `rcv_wscale` | same: smallest s with 65535·2^s ≥ `rcv_buf_max`, ≤ 14 | | RFC 7323 §2.3 (gives 10 for 32 MiB, as Linux) |
| `snd_buf_init` / `snd_buf_max` | 4 MiB fixed | 16 KiB, autotune to 4 MiB | `tcp_wmem`; `tcp_sndbuf_expand` (2 · cwnd · MSS) |
| `rcv_buf_init` / `rcv_buf_max` | 4 MiB fixed | 128 KiB, autotune to 32 MiB | `tcp_rmem`; `tcp_rcv_space_adjust` |
| `rcv_window_growth` | `free_space` (window = free buffer, receiver SWS rule) | `linux` (`rcv_ssthresh` clamp from the initial window, +2·rcv_mss per in-order segment, `tcp_grow_window`) | RFC 9293 §3.8.6.2.2 |
| `syn_window` | min(rcv_buf, 65535) | 65535 rounded down to a multiple of MSS (64240 at MSS 1460) | `tcp_select_initial_window` |
| `window_update_after_read` | when the right edge can move by ≥ min(rcv_buf/2, MSS) | when the new window ≥ 2 · current window | RFC 9293 §3.8.6.2.2; `tcp_cleanup_rbuf` |
| `sender_sws` | same: RFC 9293 §3.8.6.2.1, Fs = 1/2, override via the persist timer | | |
| `zero_window_probe` | same: zero-length `<SEQ=SND.UNA−1>`, interval RTO with backoff (§4.9) | | Linux `tcp_xmit_probe_skb`; RFC 9293 §3.8.6.1 asks for one octet of new data |
| `syn_retries` / `syn_linear_timeouts` | 7 / 0 (183 s ≥ 3 min) | 6 / 4 (10 retransmissions, 131 s) | RFC 1122 §4.2.3.5; `tcp_syn_retries`, `tcp_syn_linear_timeouts` (SYN-SENT only); count-based, §4.8 |
| `synack_retries` | 5 | 5 | `tcp_synack_retries`; count-based |
| `data_retries` | 15 (bound 663 s) | 15 (bound 924.6 s) | RFC 1122 R2 ≥ 100 s; `tcp_retries2`; abort at the first RTO expiry past the bound, §4.8 |
| `time_wait` | 240 s (2·MSL, MSL 2 min) | 60 s (`TCP_TIMEWAIT_LEN`) | RFC 9293 §3.4.2 |
| `rst_in_time_wait` | `ignore` | `accept` | RFC 1337; `tcp_rfc1337 = 0` |
| `orphan_fin_wait2_timeout` | 240 s (implementation choice) | 60 s (`tcp_fin_timeout`) | not specified by RFC 9293 |
| `oow_ack_interval` | same: 500 ms per connection, shared by challenge ACKs and ACKs to out-of-window segments with SEG.LEN = 0 or SYN; segments with payload or FIN are exempt; no global limit | | RFC 5961 §7; `tcp_oow_rate_limited`, `tcp_invalid_ratelimit`, `tcp_challenge_ack_limit = INT_MAX` |
| `ephemeral_ports` | 1024..65535 | 32768..60999 | RFC 6056 §3.2; `ip_local_port_range`; both use Algorithm 4 (§4.6) |
| `default_snd_mss`, `min_snd_mss`, `min_pmtu`, `pmtu_expiry` | same: 536, 48, 552, 10 min | | RFC 9293 §3.7.1; `tcp_min_snd_mss`, `ip_rt_min_pmtu`, `mtu_expires`; RFC 1191 §6.3 |

`UdpConfig`: `rcv_buf` 256 KiB, `ephemeral_ports` as TCP (unset follows `StackConfig::tcp.ephemeral_ports`, whichever profile; `udp_ephemeral_ports()`). `IcmpConfig`: `echo_reply` on, `rate_per_s` 1000, burst 50.

### 3.10 Wire formats

`src/core/wire/` uses explicit big-endian loads/stores; parsers return views into the input. Output is built back
to front in a `PacketBuf`: payload copied in, TCP header prepended, checksum set, IPv4 header prepended.

```cpp
namespace utcp::wire {
enum class ParseError : std::uint8_t { truncated, bad_version, bad_ihl, bad_length, bad_checksum, fragment,
                                       bad_data_offset };
struct Ipv4Header { std::uint8_t tos, ttl, proto; std::uint16_t total_len, id, frag_off; bool df, mf;
                    Ipv4Addr src, dst; };                   // IP options are skipped
struct Ipv4View { Ipv4Header h; std::span<const std::byte> payload; };
std::expected<Ipv4View, ParseError> parse_ipv4(std::span<const std::byte>);
void write_ipv4(std::span<std::byte> out20, const Ipv4Header&);          // sets the header checksum
struct Timestamps { std::uint32_t val, ecr; };
struct TcpOptions { std::optional<std::uint16_t> mss; std::optional<std::uint8_t> wscale; bool sack_permitted;
                    std::optional<Timestamps> ts; std::array<std::pair<Seq32, Seq32>, 4> sack;
                    std::uint8_t sack_count; bool malformed; };     // malformed: parsing stopped (§4.4)
struct TcpHeader { std::uint16_t sport, dport; Seq32 seq, ack; std::uint16_t window, urg;
                   std::uint16_t flags; };  // FIN..CWR bits 0-7, AE bit 8, reserved 9-11: zero on send, ignored on receive
struct TcpView { TcpHeader h; TcpOptions opt; std::span<const std::byte> payload; };
std::expected<TcpView, ParseError> parse_tcp(std::span<const std::byte>, Ipv4Addr src, Ipv4Addr dst,
                                             bool verify_csum);
std::size_t tcp_header_len(const TcpOptions&, bool syn);                  // layout of §4.5
void write_tcp_header(std::span<std::byte> out, const TcpHeader&, const TcpOptions&, bool syn);
void set_l4_checksum(std::span<std::byte> l4, Ipv4Addr src, Ipv4Addr dst, std::uint8_t proto);
// parse_udp/write_udp_header; parse_icmp/write_icmp (echo, unreachable with quoted datagram) likewise
}  // namespace utcp::wire
// Checksums: M0's include/utcp/checksum.hpp (ChecksumAccumulator, ipv4_transport_checksum, RFC 1624 updates).
```

## 4. TCP

### 4.1 Module map

`src/core/tcp/`: engine (`tcb.hpp`, `conn_table.*`, `time_wait.*`, `tcp_input.cpp`, `tcp_output.cpp`,
`tcp_timers.cpp`, `tcp_api.cpp`, `tcp_icmp.cpp`, `tcp_engine.*`); receive side (`recv_buffer.*`, `sack_gen.*`,
`ack_policy.*`, `rcv_window.*`, §4.10); send side (`send_queue.*`, `rtt.*`, `tx_policy.*`, `rate.*`, `cc.hpp`,
`cc_newreno.*`, `recovery.*`, `ack_pipeline.*`, §4.8-4.11, §5). Shared with UDP: `identifiers.*`, `ports.*` (§4.6).
The IP layer calls the engine through `TcpEngine` (`tcp_engine.hpp`); the engine reaches the rest of the stack only
through `StackCore` (`src/core/stack_impl.hpp`: packets, transmit queue, timers, ports, events, PMTU, stats, RNG).

### 4.2 TCB

```cpp
enum class TcpState : std::uint8_t { closed, listen, syn_sent, syn_received, established,
  fin_wait_1, fin_wait_2, close_wait, closing, last_ack, time_wait };
enum class CaState : std::uint8_t { open, disorder, cwr, recovery, loss };   // Linux tcp_ca_state

struct Tcb {
  FourTuple tuple; Handle self, listener; std::uint32_t conn_id;  // conn_id: monotonic, for traces
  TcpState state; bool passive, orphan, app_read_shut, app_write_shut;
  // send sequence space, RFC 9293 §3.3.1
  Seq32 iss, snd_una, snd_nxt, snd_wl1, snd_wl2;  // snd_nxt never moves back: retransmissions use lost marks (Linux)
  std::uint32_t snd_wnd, max_snd_wnd;                         // scaled, bytes
  // receive sequence space
  Seq32 irs, rcv_nxt, rcv_adv;                  // rcv_adv: highest right edge ever advertised (RFC 7323 §2.4 rule 2)
  std::uint32_t rcv_wnd;                                      // last advertised, bytes
  // options
  bool ws_ok, ts_ok, sack_ok; std::uint8_t snd_wscale, rcv_wscale;
  std::uint16_t peer_mss, adv_mss, mss_cache, pmtu, rcv_mss;  // mss_cache: payload of a full segment
  std::uint32_t ts_recent, ts_offset; Time ts_recent_stamp; Seq32 last_ack_sent;
  // RTT and retransmission; retrans_stamp = time of the first retransmission (abort rule, §4.8)
  // rto_count: RTO expiries since SND.UNA last advanced (Linux icsk_retransmits); probes_out: unanswered probes
  RttEstimator rtt; std::uint8_t backoff, rto_count, probes_out, syn_tries; Time retrans_stamp, syn_first_tx;
  SendQueue sndq; TxPolicy txp; bool fin_queued, fin_sent, fin_acked; Time pacing_next;  // send side
  RecvBuffer rcvq; SackGenerator sackgen; AckPolicy ackp; RcvWindow rwin;               // receive side
  CcConn cc_conn; CcStorage cc; LossRecovery recovery; RateState rate;                 // §5
  TimerSlots timers; Time last_oow_ack; std::optional<Error> error, soft_error;        // §6, §4.7
  std::uint16_t pending_events; TcpCounters ctr; Chrono chrono;                        // §3.5, §10.1
  void check_invariants() const;                              // snd_una <= snd_nxt, counters vs a recount
};
```

Buffers inside `SendQueue` and `RecvBuffer` are allocated on first use, not at SYN time, which keeps
SYN-RECEIVED children and idle connections small (§12, item 4).

### 4.3 Demultiplexing

- `ConnTable`: `FourTuple -> slot` hash map with SipHash-1-3 keyed by `hash_key` (resists hash flooding). It is
  only looked up, never iterated. Iteration over connections, when needed, walks the slot vector in index
  order.
- `TimeWaitTable`: compact entries `{FourTuple, snd_nxt, rcv_nxt, rcv_wnd, rcv_wscale, ts_recent, ts_recent_stamp,
  ts_offset, ts_ok, expiry}` (about 56 bytes; TIME_WAIT ACKs carry a scaled window and a TSval); the TCB is freed on
  entry to TIME_WAIT. Same keyed hash.
- `Listeners`: sorted `std::vector<{port, slot}>`. Lookup order: connection, TIME_WAIT, listener, else CLOSED.
  `TcpEngine::tuple_in_use(const FourTuple&)` and `port_has_listener(port)` serve the port allocator (§4.6).
- Slot allocation takes the lowest free index (a min-heap of free indices), so it depends only on input history.

### 4.4 Segment arrival processing

`Stack::receive` validates IPv4 (version 4, IHL ≥ 5, total length within the buffer, header checksum, destination
is the stack address, not a fragment) and TCP (length ≥ 20, data offset in range, checksum over the
pseudo-header unless `meta.csum_verified`). Options are then parsed; a malformed option length stops option
parsing and the remaining options are treated as absent (Linux behaviour; RFC 9293 MUST-7 asks only that it be
handled, and resetting on bad options would let an off-path packet with a valid checksum kill connections).

Processing then follows RFC 9293 §3.10.7, with RFC 7323 and RFC 5961 inserted where they say:

**CLOSED (no TCB, no TIME_WAIT, no listener)** (§3.10.7.1): drop if RST. If ACK set send `<SEQ=SEG.ACK><CTL=RST>`,
else `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`.

**LISTEN** (§3.10.7.2): RST: drop. ACK: send `<SEQ=SEG.ACK><CTL=RST>`. SYN: if backlog is exhausted drop;
else create a child in SYN-RECEIVED, choose ISS (§4.6), record peer options, reply SYN-ACK with only the options
the peer offered (WS only if the SYN had WS, RFC 7323 §2.2; TS only if the SYN had TS, §3.2; SACK-permitted only
if offered). SYN data is not acknowledged (no TFO). Anything else: drop.

**SYN-SENT** (§3.10.7.3):
1. ACK check: if `SEG.ACK ≤ ISS` or `SEG.ACK > SND.NXT`, send RST unless RST is set, drop.
2. RST: acceptable only with an acceptable ACK (RFC 5961 §3 applies RFC 9293's rule); then fail the connect
   with `connection_refused`.
3. SYN: record IRS, options, peer window (unscaled in a SYN, RFC 7323 §2.2). With an ACK, go to ESTABLISHED,
   send ACK, raise `ev_connected`. Without ACK (simultaneous open), go to SYN-RECEIVED and send SYN-ACK.
4. Otherwise drop.

**Synchronized states and SYN-RECEIVED** (§3.10.7.4), in this order:
0. SYN-RECEIVED, before PAWS and the sequence check. Passive child: SYN without ACK, `SEG.SEQ == IRS`, passing
   PAWS → re-send the SYN-ACK (oow rate limit) and drop (Linux `tcp_check_req`), so a lost SYN-ACK recovers at the
   client's next SYN retransmission. Active open (simultaneous): a SYN-ACK with `SEG.SEQ == IRS` and `SEG.ACK ==
   SND.NXT` skips steps 2 and 5 and completes the handshake in step 6 (the `pass` case of Linux
   `tcp_validate_incoming`); it never triggers a SYN-ACK.
1. PAWS (RFC 7323 §5.3 R1): if timestamps are in use, the segment carries TSval, RST is clear and
   `TSval < TS.Recent`: if TS.Recent is older than 24 days invalidate it (§5.5) and continue; with
   `paws_disordered_ack = linux` a pure duplicate ACK at RCV.NXT that leaves the window unchanged and whose TSval is
   within one RTO of TS.Recent continues (`tcp_disordered_ack`); else send an ACK and drop; count `paws_drops`.
2. Sequence acceptability: the four-case table with the right edge `rcv_adv`, the highest edge ever advertised
   (RFC 7323 §2.4 rule 1). At zero window (`rcv_adv == RCV.NXT`) a segment with `SEG.SEQ == RCV.NXT` passes for its
   ACK, RST and window fields; its payload is dropped (counted) and ACKed, and a bare FIN is accepted (RFC 9293
   §3.10.7.4 "special allowance"; Linux `tcp_data_queue`). An unacceptable segment without RST gets an ACK and is
   dropped; that ACK is rate-limited (§4.7) only if SEG.LEN = 0 or SYN is set. If it carries payload below RCV.NXT,
   the ACK has a D-SACK for those payload bytes (RFC 2883 §4); SYN/FIN sequence space and zero-length segments
   never produce a D-SACK (Linux `tcp_send_dupack`). Acceptable segments are trimmed to `rcv_adv`; data above
   RCV.NXT is kept (out-of-order queue). R3 (RFC 7323 §4.3, §5.3): if acceptable, `SEG.TSval ≥ TS.Recent` and
   `SEG.SEQ ≤ Last.ACK.sent`, update TS.Recent and its stamp.
3. RST (RFC 5961 §3.2): `SEG.SEQ == RCV.NXT`: reset. In SYN-RECEIVED of a passive open, free the child (back to
   LISTEN), of an active open fail with `connection_refused` (RFC 9293 §3.10.7.4); otherwise CLOSED with
   `connection_reset` (CLOSING/LAST-ACK/TIME-WAIT: close without error). In window but not exact: challenge ACK.
   TIME-WAIT follows `rst_in_time_wait`.
4. Security/compartment: not implemented (no IPsec, no labels).
5. SYN (RFC 5961 §4): challenge ACK and drop (SYN-RECEIVED retransmissions are handled in step 0).
6. ACK. No ACK bit: drop. RFC 5961 §5: acceptable when `SND.UNA − MAX.SND.WND ≤ SEG.ACK ≤ SND.NXT`;
   `SEG.ACK > SND.NXT`: ACK (challenge, rate-limited) and drop; older than the lower bound: challenge ACK, drop.
   SND.NXT never moves back, so an ACK for data sent before an RTO is always in range.
   - SYN-RECEIVED: if `SND.UNA < SEG.ACK ≤ SND.NXT`, go to ESTABLISHED, take the window, queue on the listener
     (`ev_acceptable`) or raise `ev_connected` (simultaneous open). Else send `<SEQ=SEG.ACK><CTL=RST>`.
   - Otherwise the ACK pipeline of §5.1 runs in Linux order: SACK blocks (validated; D-SACK detected per RFC 2883
     §4: first block below SEG.ACK or contained in the second block), then the cumulative ACK, RTT samples (§4.8),
     loss recovery, rate sample, CC. Window update if `SND.WL1 < SEG.SEQ` or
     (`SND.WL1 == SEG.SEQ` and `SND.WL2 ≤ SEG.ACK`) (MUST-20). Duplicate ACK as RFC 5681 §2 (same ACK, no data,
     no SYN/FIN, same window, data outstanding) or, with SACK, an ACK whose SACK blocks cover new data
     (RFC 6675 §2).
   - FIN-WAIT-1: our FIN acked → FIN-WAIT-2 (orphans arm `fin_wait2`). CLOSING: FIN acked → TIME-WAIT.
     LAST-ACK: FIN acked → CLOSED, free. TIME-WAIT: a retransmitted FIN is ACKed and the 2·MSL timer restarts.
7. URG: ignored (§1.2).
8. Text, in ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2: if the app has closed its read side by `tcp_close`, new data
   triggers RST (RFC 1122 §4.2.2.13). Otherwise `RecvBuffer::insert`, SACK/D-SACK bookkeeping, `AckPolicy`
   decides immediate or delayed ACK (§4.10). Text in other states is ignored.
9. FIN: processed when its sequence number equals RCV.NXT after inserting data (an out-of-order FIN is remembered
   in the reassembler). RCV.NXT advances by 1, `ev_read_closed`, ACK sent immediately. ESTABLISHED → CLOSE-WAIT;
   FIN-WAIT-1 → CLOSING, or TIME-WAIT if this segment also acked our FIN; FIN-WAIT-2 → TIME-WAIT.

After input processing the engine runs the output path for the connection (§4.9), so ACKs and data are produced
within the same call.

TIME-WAIT receiving a SYN without ACK (RFC 6191, RFC 9293 §3.6.1; Linux `tcp_timewait_state_process`): if PAWS
passes and `SEG.SEQ > RCV.NXT` or `TSval > TS.Recent` (so an equal TSval with a higher SEG.SEQ is accepted, as RFC
6191), and a listener holds the port, the entry is freed and the listener takes the SYN with ISS = `old SND.NXT +
65537`. Otherwise, also when no listener exists, ACK (oow rate limit) and drop: RFC 6191 says drop silently; the
ACK is the Linux choice, used in both profiles.

### 4.5 Options

Wire layout matches Linux so captures read the same: SYN `MSS, SACK_PERM, TS, NOP, WS` (20 bytes), without TS
`MSS, NOP, NOP, SACK_PERM, NOP, WS`; other segments `NOP, NOP, TS` then `NOP, NOP, SACK(n)`. With TS at most 3
SACK blocks fit, otherwise 4.

- **MSS** (RFC 9293 §3.7.1, RFC 6691): advertised `adv_mss = mtu − 40`. Without the option, or with value 0
  (Linux ignores it), the peer MSS is 536; smaller values are floored by `min_snd_mss` (§4.13).
- **Window scale** (RFC 7323 §2): used only if both SYNs carry it; shift capped at 14 (larger values are treated
  as 14, §2.3). Windows in SYN and SYN-ACK are never scaled.
- **Timestamps** (RFC 7323 §3-5): only if both SYNs carry TS; then every non-RST segment carries TSval =
  `now_ms + ts_offset`, TSecr = TS.Recent. A segment without TS is accepted (Linux; RFC 7323 §3.2 allows dropping).
- **SACK-permitted / SACK / D-SACK** (RFC 2018, 2883): blocks are sent while out-of-order data is held or a D-SACK
  is pending. Received blocks are validated (inside `[SND.UNA − MAX.SND.WND, SND.NXT]`, begin < end); a received
  D-SACK increments `dsack_dups` and, from M2a, adapts RACK's reorder window.

### 4.6 Identifiers

- **ISN** (RFC 6528 §3): `ISN = M + F(local addr, local port, remote addr, remote port, isn_key)`, M = `now.ns /
  4000`, F = low 32 bits of SipHash-2-4. Tests can set `TcpConfig::test_isn` to force sequence wrap (e.g.
  `0xFFFF0000`).
- **TS offset**: SipHash of the 4-tuple with `ts_offset_key` (RFC 7323 §5.4).
- **Ephemeral ports** (RFC 6056 §3.3.4, Algorithm 4): `offset = F(local addr, remote addr, remote port,
  port_offset_key)`, `index = G(..., port_table_key) mod 256`, candidate = `min + (offset + table[index]) mod n`,
  `table[index]` increments per attempt; a candidate is rejected if the 4-tuple is in the connection or TIME_WAIT
  table or a TCP listener holds the port (`TcpEngine` queries, §4.3). UDP uses the allocator with its own check.
- **IP ID**: atomic datagrams may carry any ID (RFC 6864 §4.1); each connection counts up from a hash-derived
  start, which keeps captures readable.

### 4.7 RST rules, challenge ACKs, ICMP errors

- Never send RST in reply to RST. RSTs are sent for: CLOSED processing, unacceptable ACK in LISTEN/SYN-SENT/
  SYN-RECEIVED, `tcp_abort`, close with unread data, data after close, retry exhaustion in synchronized states.
- Challenge ACKs (RFC 5961 §3.2, §4, §5) and ACKs to out-of-window segments with SEG.LEN = 0 or SYN share one
  per-connection 500 ms limiter (`last_oow_ack`), as Linux `tcp_oow_rate_limited`. Segments with payload or FIN
  always get their duplicate ACK (with D-SACK), so a resent TLP or flight is answered at once (RFC 5681 §4.2).
  There is no stack-wide limit: a global counter is the side channel of CVE-2016-5696.
- ICMP errors for TCP (validated against in-flight sequence numbers as in §4.13): in SYN-SENT, protocol and port
  unreachable fail the connect (`connection_refused`), other unreachables are stored as a soft error. In
  synchronized states all unreachables are soft errors (RFC 5461 §4): stored and reported only if the connection
  later times out (RFC 1122 §4.2.3.9).

### 4.8 RTT and RTO

```cpp
class RttEstimator {
 public:
  explicit RttEstimator(const TcpConfig&); bool has_sample() const;
  void on_srtt_sample(Duration seq_rtt, std::uint64_t snd_una, std::uint64_t snd_nxt);  // SRTT/RTO; keeps rtt_seq
  void on_min_rtt_sample(Duration ca_rtt, bool maybe_delayed, Time now);   // minmax_running_min, 300 s window;
                                                    // a maybe-delayed sample above min_rtt is skipped (tcp_update_rtt_min)
  Duration srtt() const, rttvar() const, min_rtt() const;   // min_rtt: windowed min over 300 s
  Duration rto() const;                             // without backoff, bounded by rto_min/rto_max
  Duration rto_backed_off(std::uint8_t backoff) const;      // min(rto << backoff, rto_max)
};
// include/utcp/retry_model.hpp (shared with the simulator's ProgressChecker, §7.3):
Duration retry_abort_time(std::uint8_t retries, Duration rto_base, Duration rto_max);  // Linux tcp_model_timeout
```

- `rfc6298`: §2.2-2.3 updates, RTO = max(SRTT + max(G, 4·RTTVAR), rto_min), G = 1 ms.
- `linux`: `tcp_rtt_estimator` line for line, in fixed point. First sample m: srtt = m, mdev = 2m, rttvar =
  mdev_max = max(2m, rto_min). Later: srtt += err/8; mdev += (|err| − mdev/4), with the gain cut by 8 when the
  sample is below SRTT; a new round maximum `mdev_max` raises rttvar at once; at each round end (SND.UNA passed
  rtt_seq, which the estimator stores: SND.NXT at the first sample and at each round end) rttvar −=
  (rttvar − mdev_max)/4 if mdev_max < rttvar, then mdev_max = rto_min. RTO = SRTT + rttvar, so
  after a delay spike the RTO decays by a quarter of the excess per RTT, and Linux's minimum bounds the variance.
- Samples (both profiles, Linux `tcp_clean_rtx_queue`/`tcp_ack_update_rtt`): `seq_rtt` from the first newly
  cumulatively acked segment, only if no retransmitted segment is newly acked (Karn, RFC 6298 §3), else from the
  first newly SACKed never-retransmitted one; `ca_rtt` from the last newly acked, or the last newly SACKed if any.
  If neither exists and new data is acked, TSecr gives both when TSecr ≠ 0 and 0 ≤ now_ts − TSecr < 2^31/1000
  (RFC 7323 §4; Linux `tcp_rtt_tsopt_us`). seq_rtt feeds SRTT/RTO, ca_rtt feeds min_rtt and the CC. The handshake
  gives one sample per side (SYN → SYN-ACK, SYN-ACK → ACK; only if `syn_tries == 1`, else from TSecr).
- Timer management (RFC 6298 §5) through the connection's one `xmit` timer (§6): armed when data is sent with none
  outstanding, restarted when new data is acked (when re-armed from kind `reo` or `pto`, at the head's last_tx +
  RTO, Linux `tcp_rearm_rto`), stopped when all is acked. On expiry: retransmit the earliest unacked segment,
  `backoff++`, `rto_count++`, enter Loss (§5.3). `backoff` resets on a valid RTT sample, `rto_count` when SND.UNA
  advances.
- SYN/SYN-ACK use `rto_initial` with backoff; SYN-SENT does not double the RTO for its first
  `syn_linear_timeouts` + 1 expiries (Linux: 1, 1, 1, 1, 1, 2, 4, … s). After a SYN retransmission and no RTT
  sample the RTO is reset to `rto_after_syn_rexmit` (RFC 6298 §5.7).
- Abort. SYN states count retransmissions (Linux `tcp_write_timeout`): SYN-SENT fails with `timed_out` when
  `rto_count` reaches `syn_retries + syn_linear_timeouts`; a passive child is freed silently after
  `synack_retries`. Synchronized states (Linux `retransmits_timed_out`): at an RTO expiry with `now − retrans_stamp
  ≥ retry_abort_time(data_retries, rto_min, rto_max)`; the bound is a model value, so the abort lands at the first
  expiry past it (`rfc` at a 1 s RTO: 722 s after the first retransmission). Send RST and fail with `timed_out` (or
  the stored soft error). Unanswered zero-window probes count `probes_out` against `data_retries`.

### 4.9 Output: segmentation, Nagle, sender SWS, probes, pacing gate

`tcp_output.cpp` has one entry, `transmit(Tcb&, Time now)`, called after input, timer and API events. Order:

1. Lost-and-not-yet-retransmitted segments from `SendQueue` in sequence order (M1: what recovery marks lost; M2a:
   RFC 6675 NextSeg rules 1-4) while `packets_in_flight < cwnd`. Only three transmissions skip the cwnd gate: the
   `fast_rexmit` on entering recovery when cwnd is set to ssthresh (M1, `rfc6675`; RFC 6675 §5 (4.3)), the head
   `rto_rexmit` (Linux `tcp_retransmit_timer`) and `tlp` (RFC 8985 §7.3). PMTU retransmissions are ordinary lost
   segments.
2. New data while all gates pass:
   - congestion: `packets_in_flight < cwnd`, the only congestion gate (PRR writes cwnd, §5.1);
   - receive window: segment end ≤ SND.UNA + SND.WND;
   - sender SWS (RFC 9293 §3.8.6.2.1): send if a full `mss_cache` segment fits, or the usable window is
     ≥ max_snd_wnd/2, or all queued data fits and nothing is unacked (or Nagle is off);
   - Nagle (§3.9 variants) unless `nodelay`; FIN-bearing segments are exempt;
   - pacing (§5.5): `now ≥ pacing_next`, else arm the `pace` timer;
   - transmit queue and pool space (§3.4).
3. FIN when the queue is empty and `fin_queued`; it rides on the last data segment when possible.
4. A pure ACK if `AckPolicy` wants one and nothing above carried it.

Payload size is `mss_cache − sack_option_bytes` when SACK blocks are being sent (Linux `tcp_current_mss`).
Every data segment carries the current ACK and window, so a pending delayed ACK is cancelled by it. Every data
(re)transmission calls `LossRecovery::on_transmit`, and the end of `transmit` calls `on_burst_end` (§5.1).

Zero-window probing (RFC 9293 §3.8.6.1): with data queued, nothing in flight and SND.WND = 0, the `xmit` timer runs
as kind `persist` at `rto_backed_off`. On expiry send a zero-length `<SEQ=SND.UNA−1><ACK=RCV.NXT>` (Linux
`tcp_xmit_probe_skb`; `TxKind::zwp`), `probes_out++`, and back off up to `rto_max`. The probe carries no data, so
it never enters the send queue, in-flight count, RTO or recovery and causes no CC reaction; any acceptable ACK
resets `probes_out` (Linux `icsk_probes_out = 0`), so answered probes never abort. With a window above zero but
below the sender SWS threshold, the same timer is the SWS override and sends min(D, U) bytes inside the window as
ordinary data (RFC 9293 §3.8.6.2.1).

### 4.10 Receive side

```cpp
struct InsertResult { std::uint64_t contiguous_end; bool advanced, out_of_order, filled_hole;
                      std::optional<Range> duplicate; Range stored; };
class RecvBuffer {                                  // ByteRing of `capacity` bytes, out-of-order data in place
 public:
  RecvBuffer(std::uint32_t capacity, ChunkPool&);
  InsertResult insert(std::uint64_t off, std::span<const std::byte> data);   // clips to rcv_adv; no chunk: drop, count
  void drop_out_of_order();                         // reneging: test knob (§7.2) and a future memory-pressure prune
  void set_fin(std::uint64_t off); bool fin_reached() const;                 // FIN at stream offset `off`
  std::size_t read(std::span<std::byte> out);
  std::uint64_t read_offset() const, contiguous_end() const;  // first unread byte; RCV.NXT as an offset
  std::uint64_t right_edge() const;                 // read_offset + capacity
  std::span<const Range> ooo_ranges() const;        // sorted, disjoint, above contiguous_end; ≤ 64 ranges
  void grow(std::uint32_t new_capacity);            // autotuning; never shrinks
};
class SackGenerator {                               // RFC 2018 §4, RFC 2883 §4
 public:
  void on_arrival(Range seg, const RecvBuffer&);    // remembers the block containing the newest segment
  void on_duplicate(Range dup, const RecvBuffer&);  // D-SACK for the next ACK
  std::size_t fill(const RecvBuffer&, std::span<Range> out, std::size_t max_blocks) const;
  void on_ack_sent();                               // D-SACK is reported once
};
```

- Out-of-order data is written at its final position in the ring; the interval set tracks filled ranges. A
  segment that would create a 65th range is dropped (counted) rather than stored. Every byte below `rcv_adv` fits:
  each advertised edge was ≤ `right_edge()` when sent, and `right_edge()` never decreases.
- SACK block order (RFC 2018 §4): first the D-SACK block if pending (RFC 2883 §4.1; followed by the out-of-order
  block containing it, if any), then the block containing the most recently received segment, then the other
  blocks in order of most recent report. Blocks are recomputed against the current interval set (merged,
  clipped above RCV.NXT) and truncated to `max_blocks`.
- `AckPolicy` (RFC 9293 §3.8.6.3, RFC 5681 §4.2; Linux `__tcp_ack_snd_check`, `tcp_event_data_recv`): ACK
  immediately for out-of-order data, a hole-filling segment, a D-SACK, FIN, quick-ack mode (Linux profile), or
  when ≥ `ack_every_full_segments` full segments (judged against `rcv_mss`, Linux `tcp_measure_rcv_mss`, which
  takes `meta.gso_size` when set) are
  unacknowledged; else arm `delack` at `now + ato`.
- `RcvWindow::select(...)`: window = `right_edge − RCV.NXT` subject to the receiver SWS rule (advance the edge only
  by ≥ min(rcv_buf/2, rcv_mss), RFC 9293 §3.8.6.2.2) and, in the Linux profile, the `rcv_ssthresh` clamp.
  The value is rounded down to a multiple of `2^rcv_wscale`. RCV.NXT moves by arbitrary amounts, so the previous
  edge is often not encodable; rounding down lets the edge retract by less than 2^rcv_wscale (RFC 7323 §2.4), and
  acceptance and storage use `rcv_adv` (rule 1), so nothing sent into an earlier window is lost. Linux rounds the
  kept window up (`tcp_select_window`), which can move the edge past a fixed buffer by up to 2^s − 1 per ACK; its
  buffer limits are soft, ours are not.
- Linux-profile autotuning (`tcp_rcv_space_adjust`): once per receiver RTT estimate (from TS echo or per window,
  `tcp_rcv_rtt_update`) the buffer grows to 2 × bytes read in that RTT, up to `rcv_buf_max`. Window-update ACKs
  after reads follow `window_update_after_read`.

### 4.11 Send buffer and retransmission queue

```cpp
struct TxSeg {                                      // one wire packet for its whole life: len ≤ mss_cache at send
  std::uint64_t id, off; std::uint32_t len; bool fin;   // id: stable, monotonic; stream offsets; FIN is a flag
  bool sacked, lost, retrans_inflight, ever_retrans;
  std::uint16_t tx_count;                           // transmissions so far (RACK, RFC 8985 §6.1)
  Time first_tx, last_tx;                           // RACK uses last_tx (xmit_ts)
  // delivery-rate snapshot at last_tx (tcp_rate_skb_sent); rate_used: consumed by a SACK (tcp_rate_skb_delivered)
  std::uint64_t delivered; Time delivered_time, first_tx_time; bool app_limited, rate_used;
};
struct Counters { std::uint32_t packets_out, sacked_out, lost_out, retrans_out;   // packets = TxSegs
                  std::uint64_t bytes_sent, bytes_retrans, bytes_acked; };
struct AckedSummary { std::uint32_t pkts; bool retrans_acked, stopped_at_sacked; };  // FLAG_RETRANS_DATA_ACKED,
struct SackedSummary { std::uint32_t newly_sacked; std::uint64_t high_sacked; };    // FLAG_SACK_RENEGING
using DeliveredFn = FunctionRef<void(const TxSeg&, bool via_sack)>;  // util/function_ref.hpp; non-owning
class SendQueue {
 public:
  std::size_t write(std::span<const std::byte>);    // app bytes into the ring
  std::uint64_t una() const, nxt() const, end() const; std::uint32_t free_space() const;  // stream offsets
  void copy_out(std::uint64_t off, std::span<std::byte> dst) const;
  TxSeg& on_transmit(std::uint64_t off, std::uint32_t len, bool fin, Time now, const RateState&);
  // both call `fn` once per newly delivered segment, in sequence order, before it is popped
  AckedSummary on_cumulative_ack(std::uint64_t new_una, Time now, DeliveredFn fn);  // pops/trims
  SackedSummary on_sack(std::span<const Range> blocks, Time now, DeliveredFn fn);    // whole segments only
  void mark_lost(std::uint64_t off); void clear_all_sacked();  // by offset; clear: reneging at RTO (§5.3)
  void reno_dupack(); void split_to_mss(std::uint16_t mss);    // non-SACK dupack; PMTU decrease
  const Counters& counters() const;
  std::span<const TxSeg> segs() const;              // in sequence order (ring view)
};
std::uint32_t packets_in_flight(const Counters& c) {          // Linux tcp_packets_in_flight
  return c.packets_out - (c.sacked_out + c.lost_out) + c.retrans_out; }
```

TxSeg entries live in a ring that grows by doubling (amortised). A TxSeg is one wire packet for its whole life,
so the counters count packets (Linux pcount 1); M4 GSO packs consecutive TxSegs into one super-segment (§12.3). A
cumulative ACK inside a segment trims it (`tcp_trim_head`). A SACK block marks a segment only if it covers it
entirely and never splits it (Linux `tcp_match_skb_to_sack` for single-packet skbs); only `split_to_mss` splits.
Without SACK, a duplicate ACK adds to `sacked_out`, capped so that `sacked_out + max(lost_out, 1) ≤ packets_out`
(`tcp_add_reno_sack`, `tcp_limit_reno_sacked`), and a cumulative ACK of n packets removes min(n − 1, sacked_out)
(`tcp_remove_reno_sacks`), so the in-flight formula is the same in all option combinations. M2a adds a send-time
FIFO of (id, last_tx), pushed on every transmission, stale entries skipped, so RACK walks from the oldest send and
stops early (Linux `tsorted_sent_queue`). `RateState` holds `delivered`, `delivered_time`, `first_tx_time` and the
`app_limited` marker (§5.4).

### 4.12 Closing

`shutdown(write)`/`close` send FIN after queued data (ESTABLISHED → FIN-WAIT-1, CLOSE-WAIT → LAST-ACK). FIN-WAIT-2
waits indefinitely for a non-orphan; an orphan is freed silently after `orphan_fin_wait2_timeout` (as Linux).
TIME-WAIT lasts `time_wait`; retransmitted FINs are ACKed and restart it. After the peer's FIN (CLOSE-WAIT) the app
sees EOF and may keep sending (half-close).

### 4.13 MSS and PMTU

- `mss_cache = max(min(peer_mss, pmtu − 40, mss_clamp), min_snd_mss) − (ts_ok ? 12 : 0)` in 32-bit arithmetic,
  recomputed on PMTU change (Linux `tcp_mtu_to_mss`); at least 8 payload bytes remain after TS and SACK options.
- PMTU cache: sorted vector keyed by destination (256 entries, deterministic eviction by oldest update), initial
  value `mtu`, entries expire after `pmtu_expiry` (RFC 1191 §6.3), checked lazily and by a stack timer.
- ICMP type 3 code 4 (RFC 1191 §6): find the connection from the quoted 4-tuple; require the quoted sequence
  number in `[SND.UNA, SND.NXT)` (RFC 5927 §4.1; Linux `tcp_v4_err`), otherwise ignore and count
  `icmp_seq_invalid`. New PMTU = the next-hop MTU field, or the RFC 1191 §7 plateau below the quoted total length
  when the field is 0; clamped to `[min_pmtu, current)`. Update the cache and `mss_cache`, split queued segments,
  mark in-flight segments larger than the new MSS lost and, unless already in Loss, enter Loss with `recover =
  SND.NXT` and ssthresh = max(ssthresh, ¾·cwnd) but no cwnd cut; `transmit` resends them under cwnd (Linux
  `tcp_simple_retransmit`; traced as `TxKind::pmtu_rexmit`).
- The same sequence check applies to other ICMP errors quoted for TCP.

## 5. Extension points for M2

### 5.1 Loss-recovery boundary

The per-ACK pipeline is one function, `process_ack` (`src/core/tcp/ack_pipeline.{hpp,cpp}`, owned with the send
side), which the engine calls. It runs Linux `tcp_ack` order: `SendQueue::on_sack` (`tcp_sacktag_write_queue`),
`on_cumulative_ack` (`tcp_clean_rtx_queue`), whose per-segment callbacks feed `LossRecovery::on_delivered` (RACK
advance, reordering detection) and the rate sampler (`tcp_rate_skb_delivered`); RTT samples (§4.8) and
`pkts_acked`; `LossRecovery::on_ack` (`tcp_fastretrans_alert`); delivered and lost counts; the rate sample
(`tcp_rate_gen`); then `cong_control`, or `cong_avoid` outside cwnd reduction, and the pacing rate
(`tcp_cong_control`). `delivered` = newly cumulatively acked packets not already SACKed + newly SACKed ones; it is
`cong_avoid`'s count and PRR's DeliveredData (Linux `tcp_newly_delivered`).

```cpp
struct AckInput { Time now; std::uint64_t prior_una, new_una; std::optional<std::uint32_t> tsecr;  // to recovery
                  std::span<const Range> sack; std::optional<Range> dsack; bool window_update, dupack; };
struct AckOutcome {                                 // after tagging, cleanup and loss marking; to CC and PRR
  std::uint32_t delivered, acked_pkts, newly_sacked, newly_lost, prior_in_flight, in_flight;   // packets
  std::uint32_t flags;   // AckFlag bits: una_advanced, retrans_data_acked, orig_sack_acked, sack_reneging, maybe_delayed
  Duration seq_rtt, ca_rtt;  const RateSample* rs;  // Duration{-1}: none; rs: M2b, nullptr in M1
};
struct AckSample { std::uint32_t pkts_acked; Duration rtt; std::uint32_t in_flight; };    // Linux ack_sample (ca_rtt)
struct RecoveryCtx { SendQueue& q; CcConn& cc; CongestionControl& algo; const RttEstimator& rtt;
                     const TcpConfig& cfg; Time now; std::uint32_t snd_wnd; };
enum class XmitTimer : std::uint8_t { none, rto, persist, reo, pto };   // one timer, RFC 8985 §8, Linux icsk_pending
class LossRecovery {                                // M1: NewReno; M2a: RFC 6675 scoreboard + RACK-TLP + PRR
 public:
  void on_delivered(RecoveryCtx&, const TxSeg&, bool via_sack);   // from the SendQueue callbacks
  void on_ack(RecoveryCtx&, const AckInput&, AckOutcome&);        // marks lost, moves CaState; PRR writes cwnd
  void on_transmit(RecoveryCtx&, const TxSeg&, TxKind);           // every (re)transmission: prr_out, HighRxt, TLP
  void on_burst_end(RecoveryCtx&);                                // end of transmit(): schedule the PTO
  void on_rto(RecoveryCtx&); void on_pmtu_drop(RecoveryCtx&);     // enter Loss and mark (§5.3); simple retransmit
  std::pair<XmitTimer, Time> xmit_timer(const RecoveryCtx&) const;  // M1: RFC 6298 rto, or persist (§4.9)
  void on_xmit_timer(RecoveryCtx&, XmitTimer);                    // M2a: reo, pto; the engine handles rto/persist
  CaState state() const;
};
```

M2a replaces the internals: an RFC 6675 scoreboard over `TxSeg.sacked/lost` (IsLost by DupThresh segments or
(DupThresh−1)·SMSS bytes SACKed above, NextSeg rules 1-4 with rescue retransmission, pipe = `packets_in_flight`);
RACK-TLP (RFC 8985) with the send-time FIFO, `reo_wnd = min(reo_wnd_mult · min_rtt/4, srtt)` where
`reo_wnd_mult` grows on D-SACK and resets after 16 recoveries (RFC 8985 §6.2 step 4; Linux
`tcp_rack_update_reo_wnd`), and reo_wnd = 0 while no reordering has been seen and the connection is in recovery or
`sacked_out ≥ dupthresh` (`tcp_rack_reo_wnd`); TLP PTO per RFC 8985 §7.2; PRR (RFC 9937, SafeACK: +1 only when
SND.UNA advanced and no new loss, as Linux `tcp_cwnd_reduction`) writes cwnd = in_flight + sndcnt, so the only
send gate stays cwnd − in_flight. None of this changes `TxSeg`, `SendQueue` or the engine.

### 5.2 Congestion-control interface

Hooks mirror Linux `struct tcp_congestion_ops` so `tcp_cubic.c` and `tcp_bbr.c` port with little change. cwnd and
ssthresh are in packets, as in Linux and RFC 9438.

```cpp
enum class CaEvent : std::uint8_t { tx_start, cwnd_restart, complete_cwr, loss };
struct CcConn {                                     // the part of the TCB a CC may read and write
  std::uint32_t cwnd, ssthresh, cwnd_cnt, cwnd_clamp, prior_cwnd, prior_ssthresh;
  std::uint64_t pacing_rate, max_pacing_rate;       // bytes/s; always computed (§5.5)
  bool pacing_needed;                               // Linux sk_pacing_status; BBR sets it
  std::uint64_t app_limited;                        // tcp_rate marker (§5.4); BBR writes it entering PROBE_RTT
  // read-only views refreshed before each hook
  CaState ca_state; std::uint32_t mss, in_flight, max_packets_out, gso_max_size; bool cwnd_limited;
  std::uint64_t snd_una, snd_nxt, delivered, lost;  // offsets (HyStart rounds, RFC 9406 windowEnd); packets
  Time now, lsndtime, delivered_time, wstamp;       // last data send; tcp_rate delivered_mstamp; EDT pacing_next
  Duration srtt, min_rtt; Rng* rng;
};
class CongestionControl {
 public:
  virtual ~CongestionControl() = default; virtual std::string_view name() const = 0;
  virtual void init(CcConn&) {}
  virtual std::uint32_t ssthresh(const CcConn&) = 0;                    // on loss
  virtual void cong_avoid(CcConn&, const AckOutcome&) = 0;              // grows by `delivered`; skipped if cong_control
  virtual void pkts_acked(CcConn&, const AckSample&) {}                 // before recovery, as Linux (HyStart)
  virtual void set_state(CcConn&, CaState) {}
  virtual void cwnd_event(CcConn&, CaEvent) {}
  virtual std::uint32_t undo_cwnd(const CcConn& c) { return std::max(c.cwnd, c.prior_cwnd); }
  virtual bool has_cong_control() const { return false; }               // BBR owns cwnd and pacing
  virtual void cong_control(CcConn&, const AckOutcome&, const RateSample&) {}
  virtual std::uint32_t sndbuf_expand() const { return 2; } virtual std::uint32_t min_tso_segs() const { return 2; }
};
using CcStorage = std::variant<NewReno /*, Cubic (M2b), Bbr (M2c) */>;  // in the TCB, no heap
CongestionControl& cc_of(CcStorage&);               // std::visit to the base reference
```

When `has_cong_control()` is true the engine skips `cong_avoid` and PRR and calls `cong_control` after rate
sampling (Linux `tcp_cong_control`). CUBIC (M2b) uses integer cube root and the fixed-point constants of
`tcp_cubic.c`; HyStart++ follows RFC 9406 §4 with its constants (MIN_RTT_THRESH 4 ms, MAX_RTT_THRESH 16 ms,
N_RTT_SAMPLE 8, CSS_GROWTH_DIVISOR 4, CSS_ROUNDS 5). BBRv1 (M2c) follows `tcp_bbr.c` of the server kernel,
including `lt_bw` sampling and ACK aggregation (`extra_acked`).

### 5.3 What M1 ships

Enough to move 1 GB under netem loss, with the interface above in place:

- `NewReno` CC: RFC 5681 slow start (`cwnd += acked`, capped at ssthresh, Linux `tcp_slow_start`), congestion
  avoidance with `cwnd_cnt` (`tcp_cong_avoid_ai`), growth only when cwnd-limited, ssthresh = max(FlightSize/2, 2)
  (RFC 5681 eq. 4; Linux reno uses cwnd/2).
- `LossRecovery` M1: RFC 6582 NewReno. Open → Disorder on the first dupack or SACK; Recovery when dupacks (or
  SACKed segments above SND.UNA) reach `dupthresh`: `recover = SND.NXT`, ssthresh from the CC, cwnd = ssthresh,
  the SND.UNA segment marked lost and retransmitted (`TxKind::fast_rexmit`). In-flight uses the Linux formula,
  so transmission resumes once enough dupacks/SACKs have drained the pipe (RFC 6675-like pacing of the
  recovery, no cwnd inflation). Each partial ACK marks the new SND.UNA segment lost (RFC 6582 §3.2 step 5).
  A full ACK returns to Open. RTO (`on_rto`, Linux `tcp_enter_loss`/`tcp_timeout_mark_lost`): a SACKed head means
  the receiver reneged, so all SACK marks are cleared, `TCPSACKReneging` counted and rate samples invalid until
  recovery ends; then every non-SACKed segment is marked lost (M2a: RFC 8985 §6.3), so the head is always resent
  (RFC 2018 §8). ssthresh comes from the CC (saving prior_ssthresh/prior_cwnd) only if ca_state ≤ disorder, SND.UNA
  ≥ `recover`, or in Loss with no earlier RTO since SND.UNA advanced; a repeated RTO keeps it (RFC 5681 §3.1). cwnd
  = 1, Loss, resend in order under slow start, exit when SND.UNA passes `recover`. An ACK that stops at a SACKed
  segment re-arms the RTO at max(srtt/2, 10 ms) (`tcp_check_sack_reneging`).
- RFC 5681 §4.1 / Linux idle restart; IW after SYN loss per `iw_after_syn_loss`; RFC 3042 limited transmit falls
  out of the in-flight formula.
- Rate-state snapshots in every `TxSeg`; `delivered` counted. Rate samples are computed from M2b.
- The pacing gate and `pace` timer, driven in M1 only by the test knob `TcpConfig::test_fixed_pacing_rate`.

### 5.4 Delivery-rate sampling (M2b)

As Linux `tcp_rate.c`. On send (`tcp_rate_skb_sent`): if `packets_out == 0` (not in-flight, which is 0 after an
RTO marks all lost and would give an inflated sample), `first_tx_time = delivered_time = now`; snapshot into the
`TxSeg`. On each newly delivered segment (`tcp_rate_skb_delivered`): keep the snapshot of the most recently sent
one (ties by end offset), `send_elapsed = last_tx − first_tx_time`, `ack_elapsed = delivered_time_now −
snapshot.delivered_time`, advance `first_tx_time`; a SACKed segment sets `rate_used`. `tcp_rate_gen`: `interval =
max(send_elapsed, ack_elapsed)`, `delivered = now_delivered − prior_delivered`; the sample is invalid without a
prior snapshot, while `is_sack_reneg`, or when interval < min_rtt. `RateState::app_limited` is a delivered-count
marker (`delivered + in_flight`, or 1), cleared once `delivered` passes it; `tcp_send` sets it
(`tcp_rate_check_app_limited`) when less than one MSS is unsent, no packet of the connection waits in the stack
transmit queue (`StackCore::queued_for(slot)`, counted from `send_ipv4`'s owner slot), in flight < cwnd and
lost_out ≤ retrans_out.

```cpp
struct RateSample { std::uint64_t prior_delivered, delivered; Duration interval, rtt; bool valid;
                    std::uint32_t acked_sacked, losses, prior_in_flight; bool is_app_limited, is_retrans, is_ack_delayed; };
```

### 5.5 Pacing

Each connection has an earliest departure time `pacing_next` (Linux EDT, `tcp_wstamp_ns`). `pacing_rate` is set by
`cong_control` (BBR) or after every ACK as `tcp_update_pacing_rate` (mss·max(cwnd, packets_out)/srtt × 200 % if
cwnd < ssthresh/2, else 120 %), and the gate applies only when `pacing_needed` (or a test knob) is set. An open gate
allows one burst of `max(min((rate >> 10) + (gso_max_size >> (min_rtt_us >> 9)), gso_max_size) / mss,
min_tso_segs())` segments (Linux `tcp_tso_autosize`; BBR's `min_tso_segs` is 1 below 1.2 Mbit/s, else 2). After a
burst of `len` payload bytes, with `len_ns = len·10^9/rate`: `pacing_next = max(pacing_next, now) + len_ns −
min(len_ns/2, max(0, now − pacing_next))` (Linux `tcp_update_skb_after_send`): lateness is credited up to half of
this burst's own interval. The first 10 data segments are not paced (`data_segs_out ≥ 10`). A closed gate arms
the `pace` timer at `pacing_next`, which reaches the host through `next_deadline()`.

## 6. Timers

One structure, `TimerHeap` (`src/core/timer/`), serves the whole stack: an indexed 4-ary min-heap of entries
`{deadline, arm_seq, owner, kind}` ordered by `(deadline, arm_seq)`. `arm_seq` is a stack-wide counter assigned at
each (re)arm, so timers with equal deadlines fire in arming order, a total order that depends only on inputs.
Each owner keeps one `TimerId` per timer kind and the heap maps ids to heap positions, so cancel and re-arm are
O(log n) with no stale entries. Frequent pushes to a later deadline (the RTO on every ACK) use lazy re-arm: the slot stores the wanted
deadline and the `arm_seq` of that arm call, the effective key is (wanted deadline, that arm_seq), and a stale
entry is repaired when it reaches the top: every heap operation (arm, cancel, destroy, pop) leaves the top exact,
so `next_deadline()` is exact at all times.

`advance(now)` first resumes blocked connections (§3.4; not a timer), then pops entries with `deadline ≤ now` in
order and runs their handlers with `now` (not the deadline). A handler may not arm a timer at or before `now`
(assertion). Rate limiters (challenge/out-of-window ACKs, ICMP) are timestamps and token buckets, not timers.

| Owner | Kind | Armed when | On expiry |
|---|---|---|---|
| connection | `xmit` | one timer whose kind and deadline come from `LossRecovery::xmit_timer` (RFC 8985 §8, Linux `icsk_pending`): `rto` with data/FIN outstanding (§4.8; while SYN/SYN-ACK is unacknowledged the engine arms `rto` itself with the SYN schedule), `persist` at zero window or for the SWS override (§4.9), `reo`/`pto` in M2a | retransmit, back off, maybe abort; probe; RACK detect / TLP |
| connection | `delack` | `AckPolicy` delays an ACK | send ACK |
| connection | `pace` | pacing gate closed with data sendable (§5.5) | run `transmit` |
| connection | `fin_wait2` | orphan enters FIN-WAIT-2 | free connection |
| connection | `keepalive` | reserved, never armed in M1 | |
| TIME_WAIT entry | `time_wait` | entry created or FIN retransmission seen | free entry |
| stack | `pmtu_expiry` | earliest PMTU cache expiry | restore MTU for that destination |

## 7. Simulator

### 7.1 Model

```cpp
namespace utcp::sim {
class Node {                                        // a host: a Stack plus scripted applications
 public: virtual ~Node() = default;
  virtual void receive(Time, std::span<const std::byte>) = 0; virtual void advance(Time) = 0;
  virtual std::optional<TxPacket> pop_transmit() = 0; virtual Time next_deadline() const = 0;
};
struct LinkParams {
  Duration delay; Duration jitter; bool allow_reorder;     // without reorder, delivery = max(prev, t)
  std::uint32_t loss_ppm; GilbertElliott burst;             // Bernoulli plus optional burst state
  std::uint32_t dup_ppm; Duration dup_extra_delay;
  std::uint32_t bitflip_ppm;                                // exactly one bit flipped; checksums catch it
  std::uint32_t garbage_ppm;                                // mutate fields, then fix checksums
  std::uint64_t rate_bps; std::uint32_t queue_bytes;        // 0 = unlimited; drop-tail
  std::uint16_t mtu; bool send_frag_needed;                 // emulated router: ICMP 3/4 for DF > mtu
  std::uint32_t icmp_spoof_ppm;                             // forged frag-needed with random sequence
};
class World { public: explicit World(const Scenario&); RunResult run(); };   // until done or a checker fires
}  // namespace utcp::sim
```

- Clock and queue: a min-heap of events `(time, seq)` with a global insertion counter for ties. Event types:
  packet arrival at a node, node wake-up (one per node, re-keyed whenever its `next_deadline()` changes; stale
  wake-ups carry an old generation and are skipped), application actions. Virtual time jumps from event to event,
  so idle periods cost nothing.
- The world calls `advance(t)` before every application action. After every node call it drains `pop_transmit()`,
  copying the bytes into link storage so pool buffers return at once (knob `host_drain_max`: at most K per wake-up,
  the rest after `host_delay`), runs `debug_check()`, feeds traces to the checkers, and calls `advance(now)` again
  while `next_deadline() ≤ now`. `stuck`: an `advance` that fires nothing leaves `next_deadline() ≤ now`;
  `livelock`: over 10^6 events at one instant or 2·10^8 in a run.
- Link pipeline per packet: queue/rate admission → loss → duplication → corruption (bitflip or garbage, chosen per
  packet) → delay + jitter → delivery. MTU check before admission; too-big DF packets are dropped and, if
  `send_frag_needed`, answered with ICMP 3/4 quoting the first 28 bytes plus as much as fits in 576 bytes.
- Garbage mutations: random seq/ack/window/flags/option bytes/length fields, truncation, valid-checksum
  re-injection of old segments. Runs with `garbage_ppm > 0` use the relaxed checks of §7.3.

### 7.2 Seeds, scenarios, replay

- Every random consumer has its own `Rng::derive(master, label)` stream, for example `"link/a>b/loss"`,
  `"node/b/stack"`, `"wl/conn3/writes"`. Adding a consumer does not shift the others.
- `Scenario` is generated from one 64-bit seed and serialises to `key=value` lines with a `gen_version`;
  `utcp-sim --scenario file` runs an explicit scenario and `utcp-sim --seed N` regenerates it. Generation and the
  link pipeline use integers only (fixed-point log-uniform table, ppm probabilities, `Rng::below`, no `<random>`).
- Generated ranges: 2 nodes (a third "router" link segment when MTU < 1500); delay 0.1-100 ms log-uniform, jitter
  0-50 % of delay, reorder on in 30 %; loss 0 in 20 % of seeds, else up to 10 %, rarely 30 % (forces aborts); dup
  up to 5 %; bitflip up to 2 %; garbage in 5 % of seeds; rate 1 Mbit/s-10 Gbit/s or unlimited; queue 2-2000
  packets; MTU 576-1500; per side: profile, SACK/TS/WS on/off independently, buffers 4 KiB-8 MiB, nodelay,
  `test_isn` near 2^32 in 10 %, a reneging receiver (`test_renege_ppm`) in 5 %; `tx_queue_packets`/`pool_buffers`
  down to 8/16 and a host drain limit in 5 %. Workloads: 1-8 connections, bytes per direction 0-4 MiB
  log-uniform, write sizes 1 B-64 KiB, readers that pause (zero windows), close modes {both close, half-close then reverse transfer,
  client abort at a random point, connect to a closed port, simultaneous open}, backlog limits.
- Data bytes are a function of `(seed, conn, direction, offset)`; receivers check every byte without storing it.
- Exact replay: same binary + scenario gives the same run. Each run reports a digest (SipHash over every
  transmitted datagram and its time, socket events, errors and checker verdicts) and an event count; a SIGABRT
  handler in `utcp-sim` prints both, so crashing seeds compare too. CI runs a seed twice and on both compilers and
  compares digests, and replays `tests/sim/corpus/` (the dumped scenario of every SIM-BUGS entry).

### 7.3 Invariant checkers

| Checker | Rule | Relaxed for garbage runs |
|---|---|---|
| `StreamChecker` | each received byte equals the expected byte at its offset; at EOF the length equals the bytes written | off |
| `TerminationChecker` | every connection ends in CLOSED after a FIN exchange in both directions (TIME_WAIT expired or LAST-ACK acked), or with `timed_out` after retry exhaustion (RST sent if synchronized), or as the scenario designed (abort, refused). Also legal: an RST received in FIN-WAIT-1/2, CLOSING or LAST-ACK after the peer's TIME_WAIT or orphan FIN-WAIT-2 entry ended (checked in the peer's trace); an orphan freed by `orphan_fin_wait2_timeout` after our FIN was ACKed; a SYN-RECEIVED child freed after `synack_retries` | any end state |
| `InFlightChecker` | from the wire, not the sender's own numbers: the world learns each side's wscale from the SYNs and keeps, per direction, the highest right edge `ack + (win << wscale)` (SYN windows unscaled) over ACKs delivered to the sender; each new-data segment must end at or before it (retransmissions exempt). Self-reported: after any data transmission `packets_in_flight ≤ cwnd` except `fast_rexmit` (cwnd = ssthresh reductions, RFC 6675 §5 (4.3)), the head `rto_rexmit` and `tlp` (RFC 8985 §7.3); in Open with no loss marks, wire bytes in flight (highest sent − highest delivered ACK − wire-SACKed) ≤ cwnd·mss. The knob `TcpConfig::test_fault = unscaled_peer_window` (a planted bug) must make it fire. | on |
| `ProgressChecker` | while any connection is unfinished, some progress event (bytes delivered, state change, connection end) occurs within `B = retry_abort_time(data_retries) + time_wait + 120 s` of virtual time (wall-clock hangs: `stuck`, `livelock`, §7.1, and the sweep timeout, §7.4) | on |
| `QuiescenceChecker` | after all workload connections end, run until `next_deadline()` is never or only `pmtu_expiry`; then `debug_usage()` must show no live slots, TIME_WAIT entries, queued packets or events, or armed connection timers, and every buffer and chunk free; else `leak` | on |
| `SelfCheck` | `Stack::debug_check()` after every call; ASan/UBSan in sweep builds | on |

A survivor whose peer has failed with `timed_out` would wait forever if the peer's RST was lost (no keepalive
in M1). Workload applications therefore close after an application idle timeout set by the scenario, and the
survivor must then terminate by its own retry rules.

### 7.4 Output and sweeps

- `RunResult` is one JSONL line: seed, verdict, violations, virtual end time, packets, bytes, digest, wall time.
- pcap: one file per node interface (egress before impairment, ingress after), `LINKTYPE_RAW` (101), nanosecond
  magic `0xa1b23c4d`, optional snaplen. Header serialisation lives in core (`include/utcp/pcap.hpp`, bytes only),
  file I/O in `src/sim/pcap_writer.cpp` and the backend.
- `tools/sim_sweep.py --seeds A:B --jobs 8 --out DIR` splits the range across worker processes (`utcp-sim
  --seed-range a:b`, run under `taskset -c 16-31 nice -n 10`), restarts a worker that crashed at the next seed,
  kills a seed after a wall-clock limit (default 120 s) and records it as `timeout`, re-runs every failing seed
  twice to confirm identical digests, and writes pcap + trace for failures and for a deterministic sample (`seed %
  500 == 0`). `tools/tshark_expert.sh` runs `tshark -q -z expert` on the egress pcaps of sampled seeds, and on
  ingress pcaps only for seeds without bit flips or garbage (impairment produces malformed frames by design); it
  fails on Error-severity items, tallies warnings. Sweeps use a release build with assertions; failing seeds are
  replayed under ASan/UBSan.

## 8. Backends

### 8.1 TUN

M0's `utcp::TunDevice::open(name, nonblocking)` opens `/dev/net/tun` with `IFF_TUN|IFF_NO_PI`; `read`/`write`
return `std::expected<std::size_t, std::error_code>`. Addresses, MTU and routes are set by testbed scripts with
`ip` (no netlink code). `StackConfig::mtu` must equal the TUN MTU. One datagram per read or write.

M4: `IFF_VNET_HDR` with `TUNSETOFFLOAD(TUN_F_CSUM|TUN_F_TSO4)`; each read/write is prefixed by `struct
virtio_net_hdr`. Received datagrams carry `DATA_VALID` or, for CHECKSUM_PARTIAL skbs (local or forwarded from a
TSO veth), `NEEDS_CSUM`, mapped to `RxMeta::csum_verified`/`csum_partial`, plus GRO `gso_size`; `TxPacket` fields
map to `VIRTIO_NET_HDR_GSO_TCPV4` and `NEEDS_CSUM`. The core API carries these fields now; M1 leaves them zero.

### 8.2 Event loop

```cpp
class EventLoop {                                   // M1 foundation ships it with the lateness histogram; the backend task adds --spin-us
 public:
  EventLoop();                                      // epoll_create1; prctl(PR_SET_TIMERSLACK, 1000 ns)
  void watch(int fd, std::uint32_t events, std::function<void(std::uint32_t)> cb);
  void set_deadline_source(std::function<Time()> f);     // usually stack.next_deadline() and app timers
  void run_once();                                  // one iteration
  const LoopStats& stats() const;                   // counters and the wake-up lateness histogram (log2 buckets)
};
Time mono_now();                                    // clock_gettime(CLOCK_MONOTONIC)
```

Iteration: `stack.advance(mono_now())`; read up to 64 datagrams from TUN, each `stack.receive(mono_now(), ...)`
(vDSO clock, per packet for RTT precision); deliver `poll_event()` to the app, which calls socket APIs; drain
`pop_transmit()` with `write(2)` (on `EAGAIN` keep the packet and wait for `EPOLLOUT`); compute
`deadline = min(stack.next_deadline(), app timers)`; sleep with `epoll_pwait2(epfd, ev, n, &timeout, &sigmask)`,
where `timeout` is `deadline − mono_now()` as a `timespec` (zero if past, NULL if never). Signals arrive through a
`signalfd`.

### 8.3 Pacing deadlines

`epoll_pwait2` takes nanosecond timeouts on `CLOCK_MONOTONIC`; with timer slack at 1 µs the expected lateness is
tens of microseconds, small against the 1 ms quantum. The loop records lateness (`now − deadline` at wake) in a
log2 histogram reported by `utcp-bulk`, so M2 can state pacing accuracy. An optional `--spin-us N` busy-polls the
last N µs before a deadline; it is off by default and its CPU cost is reported when used. Lateness is absorbed by
the credit rule of §5.5.

### 8.4 Later backends

- Multi-queue TUN (`IFF_MULTI_QUEUE`) is not shared-nothing: tun keeps a flow on the queue that last wrote it only
  while its flow entry lives (`TUN_FLOW_EXPIRE`, 3 s), then uses a keyed hash the stack cannot compute, so an idle
  connection can land on another thread's `Stack` (no TCB, RST). It needs one dispatcher reading all queues and
  steering by 4-tuple (partitioned ephemeral ranges), or `TUNSETSTEERINGEBPF` (CAP_BPF, not approved). M4's
  10k-connection test runs single-queue.
- io_uring (optional, PLAN §7): multishot reads into `PacketPool`-backed buffer rings, batched writes, and
  `IORING_OP_TIMEOUT` with `IORING_TIMEOUT_ABS` for the deadline, under the same `run_once` contract (liburing2
  runtime is installed on the server, headers are not).

## 9. Applications

All apps use `apps/common/transport.hpp`, an interface with two implementations: `KernelTransport` (non-blocking
Linux sockets on the shared `EventLoop`) and `UtcpTransport` (Stack + TUN + EventLoop). The app logic is written
once; the foundation task ships the full interface with a fake implementation for tests.

```cpp
class Transport {
 public:
  virtual ~Transport() = default;
  virtual std::expected<ConnId, Error> connect(Endpoint) = 0;
  virtual std::expected<ConnId, Error> listen(Endpoint, std::uint32_t backlog) = 0;
  virtual std::expected<std::size_t, Error> send(ConnId, std::span<const std::byte>) = 0;
  virtual std::expected<std::size_t, Error> recv(ConnId, std::span<std::byte>) = 0;
  virtual void shutdown_write(ConnId) = 0; virtual void close(ConnId) = 0;
  virtual ConnSample sample(ConnId) = 0;            // TcpInfo (utcp) or TCP_INFO (kernel), same struct
  virtual std::expected<ConnId, Error> udp_open(Endpoint) = 0;   // send_to/recv_from likewise
  virtual void add_timer(Duration period, std::function<void()>) = 0;
  virtual void run(Handler&) = 0;                   // events: accept, connected, readable, writable, closed, error
  virtual const LoopStats* loop_stats() const;      // the EventLoop's statistics (lateness, §8.3); nullptr in the fake
};
```

- **utcp-bulk**: `--backend utcp|kernel`, `--listen PORT | --connect IP:PORT`, `--send|--recv`, `--bytes N |
  --duration S`, `--cc`, `--profile rfc|linux`, `--snd-buf/--rcv-buf`, `--recv-pause MS:BYTES` (stop reading for
  MS after every BYTES, so the peer sees a zero window), `--sample-ms 10`, `--jsonl FILE`. Data is
  a seeded pattern; both sides compute SHA-256 of the stream and print it. Every 10 ms a JSONL line with the
  fields of §10.1 (kernel mode maps `TCP_INFO` by the table there; inflight = `unacked − sacked − lost +
  retrans`). A final summary line has bytes, duration,
  goodput, SHA-256, retransmissions, the three limited times and loop lateness percentiles. Kernel mode sets
  `TCP_CONGESTION` and leaves buffer sizes to sysctls (setting `SO_SNDBUF` would disable autotuning).
- **utcp-echo**: TCP server and client (`--size`, `--count`, `--concurrency`, `--rate`; latency p50/p99/p999 from
  a log-linear histogram) and a UDP echo mode for `nc -u`. M4 uses it for 10k connections.
- **utcp-httpd**: HTTP/1.1 GET and HEAD for files under `--root`, `Content-Length`, persistent connections with
  `Connection: close` honoured, sequential pipelining, 400/404/405/414/505, rejects paths that escape the root,
  small MIME table. Files are read in 64 KiB chunks as the socket becomes writable.
- **utcp-http-get**: `utcp-http-get URL [-o FILE] [--resolve host:ip] [--dns IP]`. Plain `http://` only; sends
  GET with Host, `Connection: close`; parses status and headers; body by `Content-Length`, `chunked` (with
  trailers), or read-to-close; no redirects (3xx is an error); prints the SHA-256 and length of the body. Name
  resolution: `--resolve`, otherwise a stub A-record query over the transport's UDP to `--dns`, which must be
  reachable through the DUT's NAT (Docker's 127.0.0.11 is loopback, unreachable via `utcp0`): the host's upstream
  resolver, recorded, with `--resolve` as the recorded fallback.

## 10. Observability

### 10.1 Per-connection statistics

`TcpInfo` (from `tcp_info()`), field names follow `ss -ti` so tables line up:

| `TcpInfo` field | `ss -ti` | `TCP_INFO` |
|---|---|---|
| `cc_name`, `state`, `ca_state`, `snd_wscale`, `rcv_wscale` | `cubic`, state, `wscale:s,r` | `tcpi_state`, `tcpi_ca_state`, `tcpi_*_wscale` |
| `rto`, `ato`, `srtt`, `rttvar`, `min_rtt`, `cwnd`, `ssthresh` | `rto:`, `ato:`, `rtt:s/v`, `minrtt:`, `cwnd:`, `ssthresh:` | `tcpi_rto`, `tcpi_ato`, `tcpi_rtt`, `tcpi_rttvar`, `tcpi_min_rtt`, `tcpi_snd_cwnd`, `tcpi_snd_ssthresh` |
| `snd_mss`, `rcv_mss`, `adv_mss`, `pmtu` | `mss:`, `rcvmss:`, `advmss:`, `pmtu:` | `tcpi_snd_mss`, `tcpi_rcv_mss`, `tcpi_advmss`, `tcpi_pmtu` |
| `bytes_sent`, `bytes_retrans`, `bytes_acked`, `bytes_received`, `segs_out`, `segs_in`, `data_segs_out`, `data_segs_in` | same names | `tcpi_bytes_*`, `tcpi_segs_*`, `tcpi_data_segs_*` |
| `pacing_rate`, `delivery_rate`, `delivered`, `app_limited` | same names | `tcpi_pacing_rate`, `tcpi_delivery_rate`, `tcpi_delivered` |
| `busy_time`, `rwnd_limited`, `sndbuf_limited` | `busy:`, `rwnd_limited:`, `sndbuf_limited:` | `tcpi_busy_time`, `tcpi_rwnd_limited`, `tcpi_sndbuf_limited` |
| `unacked`, `sacked`, `lost`, `retrans`, `total_retrans` | `unacked:`, `sacked:`, `lost:`, `retrans:c/t` | `tcpi_unacked`, ... |
| `dsack_dups`, `reordering`, `reord_seen`, `rcv_rtt`, `rcv_space`, `rcv_ssthresh`, `snd_wnd`, `rcv_wnd`, `notsent_bytes` | same names | `tcpi_dsack_dups`, `tcpi_reordering`, ... |
| `last_data_sent`, `last_data_recv`, `last_ack_recv` | `lastsnd:`, `lastrcv:`, `lastack:` | `tcpi_last_*` |
| `conn_id` (links a Handle to its `TraceEvent`s, §10.2) | | none (0 for kernel sockets) |

Limited-time accounting follows Linux `tcp_chrono_start/stop`: exactly one of `busy`, `rwnd_limited`,
`sndbuf_limited` runs while unsent or unacked data exists; `rwnd_limited` when transmission stopped at the
receive window, `sndbuf_limited` when the app was refused by a full send buffer, `busy` otherwise.
`StackStats` holds stack counters named after Linux MIB entries (`InSegs`, `OutSegs`, `RetransSegs`, `InCsumErrors`,
`OutRsts`, `TCPChallengeACK`, `PAWSEstab`, `TCPSACKReneging`, `TCPZeroWindowDrop`, `frag_dropped`, ...), declared in
X-macro lists split by owning task (M1 task list).

### 10.2 Event trace

```cpp
enum class TraceKind : std::uint8_t { state, tx, rx, ack, rtt, rto, cwnd, recovery, timer, icmp, drop };
enum class TxKind : std::uint8_t { syn, synack, data, fin, ack, rst, fast_rexmit, rexmit, rto_rexmit,
                                   pmtu_rexmit, zwp, tlp, challenge_ack };
enum class CloseCause : std::uint8_t { none, last_ack, time_wait_expired, time_wait_reused, time_wait_rst,
  rst_received, refused, child_reset, aborted, timed_out, synack_timed_out, fin_wait2_timeout, listener_closed };
enum class TraceTimer : std::uint8_t { none, rto, persist, reo, pto, delack, pace, fin_wait2, keepalive,
                                       time_wait, pmtu_expiry };
enum class TimerOp : std::uint8_t { none, armed, cancelled, fired };
struct TraceEvent {                                 // POD; no strings
  Time t; std::uint32_t conn_id; FourTuple tuple;   // tuple: local = this stack; TIME_WAIT events too
  TraceKind kind; TxKind tx; TcpState state; CaState ca;
  CloseCause cause;                                 // state events to closed
  TraceTimer timer; TimerOp timer_op;               // timer events
  std::uint16_t flags, mss;                         // tx/rx/drop: TCP flags; mss_cache
  std::uint32_t seq, ack, len, wnd; std::uint32_t cwnd, ssthresh, in_flight, snd_wnd;
  std::uint32_t sacked_out, lost_out, retrans_out;  // packets
  std::int64_t srtt_ns, rttvar_ns, rto_ns; std::uint64_t delivered, pacing_rate, delivery_rate;
  std::uint64_t snd_una_off, snd_nxt_off;
};
class TraceSink { public: virtual ~TraceSink() = default; virtual void on_event(const TraceEvent&) = 0; };
```

`StackConfig::trace_mask` selects kinds; with no sink the cost is one branch. The JSONL writer (sim, apps) emits
one line per event with fixed keys (`{"t":1234567,"node":"a","conn":3,"ev":"ack","cwnd":42,"srtt_us":20113,...}`);
`tools/` scripts plot cwnd, RTT and in-flight from traces and `utcp-bulk` JSONL on one axis with Linux data.
pcap: per-node files from the simulator (§7.4); `UtcpTransport --pcap FILE` writes what crosses the TUN with
`CLOCK_REALTIME` timestamps to line up with `tcpdump` on the peer.

## 11. Testing

- **Unit** (`tests/unit/`): every module, with RFC examples where they exist: RFC 1071 checksum, SipHash-2-4
  reference vectors, FIPS 180-4 SHA-256 vectors, RFC 6298 worked sequences, RFC 2883 §4 D-SACK examples, RFC 7323
  PAWS cases, a captured Linux SYN parsed byte for byte, malformed headers and options. TCP behaviour is tested
  with a two-stack loopback harness (`tests/support/tcp_harness`) that passes packets directly and lets a test
  drop, reorder or rewrite them.
- **Simulator** (`tests/sim/`): directed scenarios (handshake in all 8×8 option combinations, simultaneous open,
  zero window and probes, half-close both ways, TIME_WAIT, every RST/SYN/ACK case of RFC 5961, PAWS, PMTU with
  valid and forged ICMP, Nagle, delayed-ACK timing per profile, SYN and data retry exhaustion, sequence wrap),
  plus random sweeps (§7): 1e4 seeds in CI-sized runs, 1e5 for M1 acceptance, 1e6 in M3.
- **Interop** (`tests/interop/`, `testbed/`): containers named `utcp-*`, run with `--cap-add NET_ADMIN --device
  /dev/net/tun` and `--cpuset-cpus 16-31` (functional) or `8-15` (timing). `utcp-m1-dut` runs the stack on `utcp0`
  (kernel side 198.18.0.1, stack 198.18.0.2) with IP forwarding; `utcp-m1-peer` is plain Linux on `utcp-m1-net`
  (198.19.1.0/24) with a route to 198.18.0.0/24 via the DUT. `utcp0` gets txqueuelen 10000 and a pfifo root (limit
  10000; netem replaces it); each run records `ip -s link show utcp0` drops and `tc -s qdisc`. Linux peers here
  and in the 2d testbed run with `--sysctl net.ipv4.tcp_no_metrics_save=1` (the server has 0; ssthresh caching is
  already off by `tcp_no_ssthresh_metrics_save = 1`, but cached RTT and reordering would seed later runs), checked
  with `ip tcp_metrics show`. netem goes on the DUT's `eth0` egress (stack→Linux) and `utcp0` egress
  (Linux→stack), so the peer's own egress has no qdisc. Cases: 1 GB each way under clean, loss 1 %, reorder
  (delay 5 ms, `reorder 10% 50%`), duplicate 2 %, and a combination, with `nstat -az` deltas from the peer; paused
  readers each way; the 8 Linux SACK/TS/WS combinations (`docker run --sysctl` per peer); peers at `tcp_ecn` 1
  and 3; a PMTU chain DUT —`utcp-m1-net1400` (MTU 1400)— router `utcp-m1-r` —`utcp-m1-netb` (1500)— peer (the
  DUT kernel answers the stack's 1500-byte DF packets with frag-needed into the TUN, the router does the same for
  Linux); public sites through NAT in the DUT (`nftables`); curl against `utcp-httpd`; `utcp-http-get` against
  nginx and the public sites (kernel curl in the same container for the reference hash); `nc -u`; ping.
- **Fuzz** (`tests/fuzz/`, clang, `-fsanitize=fuzzer,address,undefined`): `fuzz_ipv4` (parse; parse → serialise →
  parse round trip), `fuzz_tcp_options`, `fuzz_reassembler` (input decoded as insert/read/fin operations applied
  to `RecvBuffer` and to the naive reference in `tests/support/naive_reassembler.hpp`, a byte map; contiguous
  output, FIN state and SACK-able ranges must agree after every step), `fuzz_stack_input` (arbitrary datagrams
  into a stack with a listener and an established connection; checks `debug_check()`). M1 runs each for 60 s in
  CI; M3 runs them for hours.
- **packetdrill** (M3, one day): `--so_filename` loads a shared object implementing its socket, packet and time
  interface (check `so_testing.h` at M3 start); virtual time, `receive`/`pop_transmit` and loops over `advance`
  map onto it, plus `to_errno` and blocking `accept`/`connect` emulation. Only scripts for RFC behaviour are kept.

## 12. Performance notes for M4

1. **Buffer pools**: a 64 KiB packet class for GSO next to the 2 KiB class (`alloc` already takes a size); data
   rings are chunked from M1 (§3.3), M4 tunes the chunk size.
2. **Batching**: read up to 64 datagrams per wake-up, one `advance` per batch, write all queued packets before
   sleeping. Delayed-ACK decisions stay per segment, as in §3.4.
3. **GSO**: the output path packs k consecutive new-data TxSegs sent at the same instant into one super-segment
   (`gso_size = mss_cache`, partial checksum); retransmissions stay single packets, so scoreboard code is unchanged;
   `min_tso_segs` and the quantum bound k. A GRO super-segment is one insert with ACK accounting by `gso_segs`.
4. **Memory target for 10k connections**: TCB ≤ 1 KiB (a `static_assert` once M4 starts), TIME_WAIT entry ≤ 64
   bytes, buffers allocated on first use. Target: an idle established connection ≤ 2 KiB, an echo connection with
   small messages ≤ 12 KiB, so 10k echo connections ≤ 128 MiB RSS. Measured against Linux for the same load
   (`/proc/net/sockstat` mem, TCP slab usage).
5. **Hot path**: no allocation per packet (§3.3); a single copy each way between rings and packet buffers; flat
   open-addressing connection table; checksum offload via `NEEDS_CSUM`.
6. Each optimisation is reported with before/after numbers measured on CPUs 8-15.

## 13. Rules

### 13.1 Determinism

- The core has no global mutable state, no threads, no clock other than `now`, no randomness other than the seed.
- No container ordered or hashed by pointer value; no iteration over hash maps; sorts use total-order keys (or
  `std::stable_sort`).
- Integer arithmetic only in the core (CUBIC and BBR use Linux's fixed-point forms) and in the simulator's
  generator and link pipeline; this also removes compiler-dependent floating-point contraction.
- No unspecified evaluation order involving the RNG or state mutation: at most one `rng.next()` per full
  expression, no side effects in function arguments.
- Ties are broken explicitly: timers by `(deadline, arm_seq)`, simulator events by `(time, seq)`, event FIFO by
  first-pending order, slots by lowest free index.
- CI checks: the same seed twice gives the same digest; the g++ and clang builds give the same digest.

### 13.2 Error handling

No exceptions; `utcp_core` is compiled with `-fno-exceptions`. Malformed packets are routine and are dropped and
counted; API errors are `std::expected<T, Error>`; failures are deterministic aborts the simulator and fuzzers
see; allocation failure aborts. Invariants use `UTCP_CHECK` (always on) and `UTCP_DCHECK` (debug, simulator, fuzz
builds); both call glibc `__assert_fail(expr, __FILE__, __LINE__, __func__)`, which `core.forbidden_symbols`
allows, so the core links no stdio. Backend and apps use `std::expected<T, std::error_code>` (like M0's
`TunDevice`); apps exit non-zero on fatal errors.

### 13.3 Coding conventions

- Flags from M0's `cmake/Warnings.cmake` (`utcp_core`: STRICT set with `-Wconversion -Wsign-conversion
  -Wold-style-cast -Wcast-qual`, plus `-fno-exceptions`). Presets: M0's `{gcc,clang}-{debug,release,asan}`,
  `gcc-sweep` (Release with `UTCP_DCHECK`) and `clang-fuzz`. Naming as in M0 (`snake_case` files, functions and
  constants, `PascalCase` types, `snake_case_` members); namespaces `utcp`, `utcp::wire`, `utcp::sim`,
  `utcp::backend`, `utcp::app`.
- Fixed-width integers for wire and protocol quantities, `std::span`/`std::byte` for bytes, no `reinterpret_cast`
  of packet bytes (explicit big-endian loads and stores). Comments cite RFC sections (`// RFC 9293 §3.10.7.4:`)
  and Linux functions when copying Linux (`// as Linux tcp_cwnd_restart()`). Failing tests are fixed, never weakened.
