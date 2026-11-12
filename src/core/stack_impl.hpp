// The stack's implementation: StackCore, the services the IP layer gives TCP,
// and StackImpl, the object behind Stack (DESIGN §3.4, §4.1). Interface
// declared by m1-found; implemented by m1-ip (stack.cpp replaces the link
// stub, plus ip, icmp, udp, pmtu_cache, ports, identifiers, events and
// tx_queue), which may restructure StackImpl and the private members.
//
// The TCP engine reaches the rest of the stack only through StackCore:
// packets, the transmit queue, the blocked-connection FIFO, timers, slots,
// ports, identifiers, events, PMTU, chunk pool, stats, trace, RNG and
// configuration.
#pragma once

#include <cstdint>
#include <expected>
#include <optional>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/tcp_engine.hpp"
#include "core/timer/timer_heap.hpp"
#include "utcp/config.hpp"
#include "utcp/error.hpp"
#include "utcp/packet.hpp"
#include "utcp/random.hpp"
#include "utcp/seq.hpp"
#include "utcp/stack.hpp"
#include "utcp/stats.hpp"
#include "utcp/time.hpp"
#include "utcp/trace.hpp"
#include "utcp/types.hpp"

namespace utcp {

// Size of every PacketPool buffer in M1 (§3.3).
inline constexpr std::uint32_t packet_buf_size = 2048;

class StackCore {
public:
  explicit StackCore(const StackConfig& cfg);
  ~StackCore();
  StackCore(const StackCore&) = delete;
  StackCore& operator=(const StackCore&) = delete;

  // --- Configuration, clock, randomness (§3.4, §3.8).
  [[nodiscard]] const StackConfig& config() const noexcept { return cfg_; }
  [[nodiscard]] Ipv4Addr local_addr() const noexcept { return cfg_.local_addr; }
  // Time of the current (or last) entry point; entry points set it after the
  // monotonicity check (§3.4 item 4).
  [[nodiscard]] Time now() const noexcept { return now_; }
  void set_now(Time now) noexcept { now_ = now; }
  // The runtime stream (test knobs such as test_renege_ppm; BBR in M2c).
  [[nodiscard]] Rng& rng() noexcept { return rng_; }
  // Key of the connection and TIME_WAIT tables (SipHash-1-3, §4.3).
  [[nodiscard]] const SipKey& hash_key() const noexcept;

  // --- Statistics and trace (§10).
  [[nodiscard]] StackStats& stats() noexcept { return stats_; }
  [[nodiscard]] const StackStats& stats() const noexcept { return stats_; }
  void set_trace_sink(TraceSink* sink) noexcept { sink_ = sink; }
  // A sink is set and StackConfig::trace_mask selects `k` (one branch, §10.2).
  [[nodiscard]] bool tracing(TraceKind k) const noexcept {
    return sink_ != nullptr && (cfg_.trace_mask & trace_bit(k)) != 0;
  }
  void trace(const TraceEvent& e) {
    if (sink_ != nullptr && (cfg_.trace_mask & trace_bit(e.kind)) != 0) {
      sink_->on_event(e);
    }
  }

  // --- Packets and the transmit queue (§3.3, §3.4).
  // A pool buffer with headroom for StackConfig::tx_headroom, the IPv4 header
  // and `l4_header` transport-header bytes, and room for `payload` bytes after
  // it; nullopt if the pool is empty.
  [[nodiscard]] std::optional<PacketBuf> alloc_packet(std::uint32_t l4_header,
                                                      std::uint32_t payload);
  // One more datagram fits in the transmit queue and the pool.
  [[nodiscard]] bool can_transmit() const;
  // Prepends the IPv4 header (DF set, TTL, `ip_id`, `proto`, from the stack
  // address to `dst`) to the transport packet `l4` (checksum already set) and
  // queues the datagram for pop_transmit. False if the queue is full: the
  // datagram is dropped (control packets count IpOutDiscards, §3.4).
  bool send_ipv4(Ipv4Addr dst, std::uint8_t proto, std::uint16_t ip_id, PacketBuf&& l4);
  // Joins the FIFO of connections blocked on transmit or pool space (at most
  // once per slot); advance() resumes them in FIFO order through
  // TcpEngine::on_tx_space, and next_deadline() is now() while space is free
  // and the FIFO is not empty (§3.4).
  void block_tx(std::uint32_t slot);
  [[nodiscard]] const PacketPool& pool() const noexcept { return pool_; }

  // --- Timers (§6). Owners create their TimerIds; the Stack dispatches
  // connection and TIME_WAIT kinds to TcpEngine::on_timer.
  [[nodiscard]] TimerHeap& timers() noexcept { return timers_; }
  [[nodiscard]] const TimerHeap& timers() const noexcept { return timers_; }

  // --- Slots, ports and identifiers (§4.3, §4.6).
  // TCP and UDP sockets share StackConfig::max_connections; false when none
  // is left.
  [[nodiscard]] bool reserve_slot();
  void release_slot();
  // RFC 6056 §3.3.4 Algorithm 4 over TcpConfig::ephemeral_ports for a
  // connection from the stack address to `remote`; candidates are rejected by
  // TcpEngine::tuple_in_use and port_has_listener; addr_not_available after
  // the whole range.
  [[nodiscard]] std::expected<std::uint16_t, Error> tcp_ephemeral_port(Endpoint remote);
  // RFC 6528 §3: M + F(tuple, isn_key), M = now().ns / 4000. TcpConfig::
  // test_isn is applied by the engine.
  [[nodiscard]] Seq32 isn(const FourTuple& tuple) const;
  // RFC 7323 §5.4: SipHash of the tuple with ts_offset_key.
  [[nodiscard]] std::uint32_t ts_offset(const FourTuple& tuple) const;
  // RFC 6864 §4.1: the first IP ID of a connection, hash-derived; it counts up.
  [[nodiscard]] std::uint16_t ip_id_start(const FourTuple& tuple) const;

  // --- Events (§3.5). Pending bits and the FIFO are kept here.
  // ORs `ev` (Ev bits) into the handle's pending bits and queues the handle if
  // it had none.
  void raise_event(Handle h, std::uint16_t ev);
  // Forgets the pending events of a handle that became invalid.
  void drop_events(Handle h);

  // --- PMTU (§4.13).
  // Cached path MTU to `dst` (expired entries dropped lazily), else the
  // interface MTU.
  [[nodiscard]] std::uint16_t pmtu(Ipv4Addr dst);
  // Lowers the cached path MTU to `dst`; never raises it, never below
  // min_pmtu.
  void pmtu_lower(Ipv4Addr dst, std::uint16_t mtu);

  // --- Socket data storage (§3.3).
  [[nodiscard]] ChunkPool& chunks() noexcept { return chunks_; }
  [[nodiscard]] const ChunkPool& chunks() const noexcept { return chunks_; }

  // The engine, for the port allocator's queries (StackImpl sets it).
  void set_tcp(TcpEngine* tcp) noexcept { tcp_ = tcp; }

private:
  StackConfig cfg_;
  StackStats stats_;
  Time now_;
  Rng rng_;
  TimerHeap timers_;
  ChunkPool chunks_;
  PacketPool pool_;
  TraceSink* sink_ = nullptr;
  TcpEngine* tcp_ = nullptr;
  // The rest is m1-ip's (keys, transmit queue, blocked FIFO, events, PMTU
  // cache, port table).
};

// The object behind Stack (Stack::impl_): the core services and the protocol
// modules. m1-ip adds IP, ICMP and UDP.
class StackImpl {
public:
  explicit StackImpl(const StackConfig& cfg);
  ~StackImpl();
  StackImpl(const StackImpl&) = delete;
  StackImpl& operator=(const StackImpl&) = delete;

  StackCore core;
  TcpEngine tcp;
};

}  // namespace utcp
