// Stack, StackImpl and the StackCore services (DESIGN §3.4-3.7, §4.1, §6).
#include "utcp/stack.hpp"

#include <algorithm>
#include <memory>
#include <optional>

#include "core/ip.hpp"
#include "core/stack_impl.hpp"
#include "core/wire/ipv4.hpp"
#include "utcp/check.hpp"

namespace utcp {

// --- StackCore

StackCore::StackCore(const StackConfig& cfg)
    : cfg_(cfg),
      rng_(Rng::derive(cfg.seed, "stack/runtime")),
      chunks_(cfg.chunk_limit),
      pool_(cfg.pool_buffers, packet_buf_size),
      keys_(StackKeys::derive(cfg.seed)),
      txq_(cfg.tx_queue_packets),
      pmtu_(cfg.mtu, cfg.tcp.min_pmtu, cfg.tcp.pmtu_expiry),
      // RFC 6056 §3.3.4: table[] starts with random values.
      ports_(keys_.port_offset, keys_.port_table, Rng::derive(cfg.seed, "stack/port_table")) {
  // RFC 791: every host accepts 68-byte datagrams; the ICMP quote room and
  // the PMTU clamp assume it.
  UTCP_CHECK(cfg.mtu >= 68);
  UTCP_CHECK(cfg.tcp.min_pmtu >= 68);
  UTCP_CHECK(std::uint32_t{cfg.mtu} + cfg.tx_headroom <= packet_buf_size);
  pmtu_timer_ = timers_.create(0, TimerKind::pmtu_expiry);
}

StackCore::~StackCore() = default;

const SipKey& StackCore::hash_key() const noexcept { return keys_.hash; }

std::optional<PacketBuf> StackCore::alloc_packet(std::uint32_t l4_header, std::uint32_t payload) {
  const std::uint64_t head =
      std::uint64_t{cfg_.tx_headroom} + wire::ipv4_header_len + std::uint64_t{l4_header};
  if (head + payload > pool_.buf_size()) {
    return std::nullopt;
  }
  return pool_.alloc(payload, static_cast<std::uint32_t>(head));
}

std::uint32_t StackCore::max_l4_size() const noexcept {
  return pool_.buf_size() - std::uint32_t{cfg_.tx_headroom} -
         static_cast<std::uint32_t>(wire::ipv4_header_len);
}

bool StackCore::can_transmit() const { return !txq_.full() && pool_.available() > 0; }

std::uint32_t StackCore::queued_for(std::uint32_t slot) const { return txq_.queued_for(slot); }

void StackCore::release_tx_owner(std::uint32_t slot) { txq_.disown(slot); }

void StackCore::block_tx(std::uint32_t slot) { blocked_.push(slot); }

void StackCore::unblock_tx(std::uint32_t slot) { blocked_.erase(slot); }

bool StackCore::resumable() const { return !blocked_.empty() && can_transmit(); }

void StackCore::resume_blocked(Time now) {
  // §3.4: FIFO order. Only producers queued before `mark` are resumed, each
  // once: one that blocks again during the call joins the back with a later
  // push number and waits for the next call, and one that a resumed
  // producer removed (unblock_tx) is gone from the FIFO.
  const std::uint64_t mark = blocked_.pushes();
  while (can_transmit()) {
    const auto slot = blocked_.pop_before(mark);
    if (!slot) {
      break;
    }
    UTCP_CHECK(tx_listener_ != nullptr);
    tx_listener_->on_tx_space(now, *slot);
  }
}

bool StackCore::reserve_slot() {
  if (slots_used_ >= cfg_.max_connections) {
    return false;
  }
  ++slots_used_;
  return true;
}

void StackCore::release_slot() {
  UTCP_CHECK(slots_used_ > 0);
  --slots_used_;
}

std::expected<std::uint16_t, Error> StackCore::tcp_ephemeral_port(Endpoint remote) {
  UTCP_CHECK(tcp_ != nullptr);
  const Ipv4Addr local = cfg_.local_addr;
  // §4.6: a candidate is rejected if the 4-tuple is in the connection or
  // TIME_WAIT table or a listener holds the port.
  return ports_.pick(cfg_.tcp.ephemeral_ports, local, remote, [&](std::uint16_t p) {
    return tcp_->port_has_listener(p) || tcp_->tuple_in_use(FourTuple{Endpoint{local, p}, remote});
  });
}

std::expected<std::uint16_t, Error> StackCore::udp_ephemeral_port(
    FunctionRef<bool(std::uint16_t)> in_use) {
  return ports_.pick(udp_ephemeral_ports(cfg_), cfg_.local_addr, Endpoint{}, in_use);
}

Seq32 StackCore::isn(const FourTuple& tuple) const { return isn_for(keys_.isn, tuple, now_); }

std::uint32_t StackCore::ts_offset(const FourTuple& tuple) const {
  return cfg_.tcp.ts_offset_random ? ts_offset_for(keys_.ts_offset, tuple) : 0;
}

std::uint16_t StackCore::ip_id_start(const FourTuple& tuple) const {
  return ip_id_start_for(keys_.ip_id, tuple);
}

void StackCore::raise_event(Handle h, std::uint16_t ev) { events_.raise(h, ev); }

void StackCore::drop_events(Handle h) { events_.drop(h); }

std::uint16_t StackCore::pmtu(Ipv4Addr dst) {
  const std::size_t before = pmtu_.size();
  const std::uint16_t v = pmtu_.lookup(dst, now_);
  if (pmtu_.size() != before) {
    sync_pmtu_timer();
  }
  return v;
}

void StackCore::pmtu_lower(Ipv4Addr dst, std::uint16_t mtu) {
  if (pmtu_.lower(dst, mtu, now_)) {
    sync_pmtu_timer();
  }
}

void StackCore::trace_pmtu_timer(TimerOp op, Time t) {
  if (tracing(TraceKind::timer)) {
    TraceEvent e;
    e.t = t;
    e.kind = TraceKind::timer;
    e.timer = TraceTimer::pmtu_expiry;
    e.timer_op = op;
    trace(e);
  }
}

void StackCore::on_pmtu_expiry(Time now) {
  trace_pmtu_timer(TimerOp::fired, now);
  // RFC 1191 §6.3: expired estimates return to the interface MTU.
  pmtu_.expire(now);
  sync_pmtu_timer();
}

void StackCore::sync_pmtu_timer() {
  // §10.2: every arm (or re-arm to another deadline) and every cancel of an
  // armed timer is traced. TraceEvent has no deadline field.
  const Time t = pmtu_.next_expiry();
  if (t.is_never()) {
    if (timers_.armed(pmtu_timer_)) {
      timers_.cancel(pmtu_timer_);
      trace_pmtu_timer(TimerOp::cancelled, now_);
    }
  } else if (!timers_.armed(pmtu_timer_) || timers_.deadline(pmtu_timer_) != t) {
    timers_.arm(pmtu_timer_, t);
    trace_pmtu_timer(TimerOp::armed, now_);
  }
}

void StackCore::check_invariants() const {
  timers_.check_invariants();
  txq_.check_invariants();
  blocked_.check_invariants();
  events_.check_invariants();
  pmtu_.check_invariants();
  // The pmtu_expiry timer runs exactly while the cache has entries, at the
  // earliest expiry.
  UTCP_CHECK(timers_.armed(pmtu_timer_) == (pmtu_.size() > 0));
  UTCP_CHECK(pmtu_.size() == 0 || timers_.deadline(pmtu_timer_) == pmtu_.next_expiry());
  UTCP_CHECK(slots_used_ <= cfg_.max_connections);
  // Every queued datagram holds a pool buffer.
  UTCP_CHECK(txq_.size() + pool_.available() <= pool_.count());
}

// --- StackImpl

StackImpl::StackImpl(const StackConfig& cfg) : core(cfg), tcp(core), udp(core), icmp(core, udp) {
  core.set_tcp(&tcp);
  core.set_tx_listener(&tx_space_);
  icmp.set_tcp_sink(&tcp_icmp_);
}

StackImpl::~StackImpl() = default;

void StackImpl::enter(Time now) {
  // §3.4 item 4: `now` never goes backwards; a host that breaks the contract
  // is clamped and counted, or stopped with assert_time_monotonic.
  UTCP_CHECK(!core.config().assert_time_monotonic || now >= core.now());
  if (now < core.now()) {
    ++core.stats().time_regressions;
    return;
  }
  core.set_now(now);
}

void StackImpl::receive(Time now, std::span<const std::byte> ipv4, RxMeta meta) {
  enter(now);
  ip_input(*this, ipv4, meta);
}

void DueTimerRunner::run(TimerHeap& heap, Time now, FunctionRef<void(const FiredTimer&)> fire) {
  ++runs_;
  const std::uint64_t mark = heap.next_arm_seq();
  std::optional<TimerKey> last;
  while (const auto f = heap.pop_due(now)) {
    UTCP_CHECK(f->key.arm_seq < mark);  // armed by a handler of this run at or before now
    // §6: a handler may not arm a timer at or before now (see the class
    // comment for what these two checks cover).
    if (f->id >= fired_in_.size()) {
      fired_in_.resize(std::size_t{f->id} + 1, 0);
    }
    UTCP_CHECK(fired_in_[f->id] != runs_);
    UTCP_CHECK(!last.has_value() || *last < f->key);
    fired_in_[f->id] = runs_;
    last = f->key;
    fire(*f);
  }
}

void StackImpl::advance(Time now) {
  enter(now);
  core.next_host_batch();
  const Time t = core.now();
  // §6: blocked producers first (not a timer), then every timer due at t in
  // (deadline, arm_seq) order, each handler run with t.
  core.resume_blocked(t);
  timer_runner_.run(core.timers(), t, [&](const FiredTimer& f) {
    if (f.kind == TimerKind::pmtu_expiry) {
      core.on_pmtu_expiry(t);
    } else {
      tcp.on_timer(t, f.owner, f.kind);
    }
  });
}

std::optional<TxPacket> StackImpl::pop_transmit() { return core.tx_queue().pop(); }

Time StackImpl::next_deadline() const {
  Time t = core.timers().next_deadline();
  // §3.4: once space is free, blocked producers resume at the next advance.
  if (core.resumable()) {
    t = std::min(t, core.now());
  }
  return t;
}

std::optional<SocketEvent> StackImpl::poll_event() { return core.events().poll(); }

void StackImpl::debug_check() const {
  core.check_invariants();
  tcp.check_invariants();
  udp.check_invariants();
  icmp.check_invariants();
  UTCP_CHECK(core.slots_in_use() >= udp.open_count());
}

StackUsage StackImpl::debug_usage() const {
  const TcpUsage t = tcp.usage();
  StackUsage u;
  u.tcp_slots = t.slots;
  u.udp_slots = udp.open_count();
  u.time_wait_entries = t.time_wait_entries;
  u.pool_buffers = core.pool().count();
  u.pool_buffers_free = core.pool().available();
  u.chunks = core.chunks().allocated();
  u.chunks_free = core.chunks().free_count();
  u.tx_queued = core.tx_queue().size();
  u.events_queued = core.events().queued();
  u.echo_replies_queued = icmp.echo_replies_queued();
  u.blocked_conns = core.blocked().size();
  u.conn_timers_armed = t.timers_armed;
  u.stack_timers_armed = core.pmtu_timer_armed() ? 1u : 0u;
  return u;
}

// --- Stack

Stack::Stack(const StackConfig& cfg) : impl_(std::make_unique<StackImpl>(cfg)) {}

Stack::~Stack() = default;

void Stack::receive(Time now, std::span<const std::byte> ipv4, RxMeta meta) {
  impl_->receive(now, ipv4, meta);
}

void Stack::advance(Time now) { impl_->advance(now); }

std::optional<TxPacket> Stack::pop_transmit() { return impl_->pop_transmit(); }

Time Stack::next_deadline() const { return impl_->next_deadline(); }

Time Stack::now() const { return impl_->core.now(); }

std::optional<SocketEvent> Stack::poll_event() { return impl_->poll_event(); }

std::expected<Handle, Error> Stack::tcp_listen(Endpoint local, std::uint32_t backlog,
                                               const TcpSocketOptions& opts) {
  return impl_->tcp.tcp_listen(local, backlog, opts);
}

std::expected<Handle, Error> Stack::tcp_accept(Handle listener) {
  return impl_->tcp.tcp_accept(listener);
}

std::expected<Handle, Error> Stack::tcp_connect(Endpoint remote, const TcpSocketOptions& opts,
                                                std::uint16_t local_port) {
  return impl_->tcp.tcp_connect(remote, opts, local_port);
}

std::expected<std::size_t, Error> Stack::tcp_send(Handle h, std::span<const std::byte> data) {
  return impl_->tcp.tcp_send(h, data);
}

std::expected<std::size_t, Error> Stack::tcp_recv(Handle h, std::span<std::byte> out) {
  return impl_->tcp.tcp_recv(h, out);
}

std::expected<void, Error> Stack::tcp_shutdown(Handle h, Shutdown how) {
  return impl_->tcp.tcp_shutdown(h, how);
}

std::expected<void, Error> Stack::tcp_close(Handle h) { return impl_->tcp.tcp_close(h); }

std::expected<void, Error> Stack::tcp_abort(Handle h) { return impl_->tcp.tcp_abort(h); }

Readiness Stack::tcp_readiness(Handle h) const { return impl_->tcp.tcp_readiness(h); }

std::expected<TcpInfo, Error> Stack::tcp_info(Handle h) const { return impl_->tcp.tcp_info(h); }

std::expected<void, Error> Stack::tcp_set_options(Handle h, const TcpSocketOptions& opts) {
  return impl_->tcp.tcp_set_options(h, opts);
}

std::optional<Error> Stack::take_error(Handle h) { return impl_->tcp.take_error(h); }

std::expected<Handle, Error> Stack::udp_open(Endpoint local) { return impl_->udp.open(local); }

std::expected<void, Error> Stack::udp_send_to(Handle h, Endpoint remote,
                                              std::span<const std::byte> data) {
  return impl_->udp.send_to(h, remote, data);
}

std::expected<UdpRecv, Error> Stack::udp_recv_from(Handle h, std::span<std::byte> out) {
  return impl_->udp.recv_from(h, out);
}

std::expected<void, Error> Stack::udp_close(Handle h) { return impl_->udp.close(h); }

std::expected<void, Error> Stack::icmp_echo(Ipv4Addr dst, std::uint16_t id, std::uint16_t seq,
                                            std::span<const std::byte> payload) {
  return impl_->icmp.echo(dst, id, seq, payload);
}

std::optional<EchoReply> Stack::poll_echo_reply() { return impl_->icmp.poll_echo_reply(); }

void Stack::set_trace_sink(TraceSink* sink) { impl_->core.set_trace_sink(sink); }

const StackStats& Stack::stats() const { return impl_->core.stats(); }

const StackConfig& Stack::config() const { return impl_->core.config(); }

void Stack::debug_check() const { impl_->debug_check(); }

StackUsage Stack::debug_usage() const { return impl_->debug_usage(); }

}  // namespace utcp
