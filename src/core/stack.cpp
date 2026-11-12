// Link stub (m1-found): every Stack method returns Error::invalid_state or
// does nothing, so that the simulator, the backend and the apps build against
// the full API before the stack exists. m1-ip replaces this file. The TCP
// calls go to the TcpEngine link stub (tcp/tcp_engine_stub.cpp).
#include "utcp/stack.hpp"

#include <algorithm>
#include <memory>

#include "core/stack_impl.hpp"

namespace utcp {

StackCore::StackCore(const StackConfig& cfg)
    : cfg_(cfg),
      rng_(Rng::derive(cfg.seed, "stack/runtime")),
      chunks_(cfg.chunk_limit),
      pool_(cfg.pool_buffers, packet_buf_size) {}

StackCore::~StackCore() = default;

StackImpl::StackImpl(const StackConfig& cfg) : core(cfg), tcp(core) { core.set_tcp(&tcp); }

StackImpl::~StackImpl() = default;

Stack::Stack(const StackConfig& cfg) : impl_(std::make_unique<StackImpl>(cfg)) {}

Stack::~Stack() = default;

void Stack::receive(Time now, std::span<const std::byte>, RxMeta) {
  impl_->core.set_now(std::max(now, impl_->core.now()));
}

void Stack::advance(Time now) { impl_->core.set_now(std::max(now, impl_->core.now())); }

std::optional<TxPacket> Stack::pop_transmit() { return std::nullopt; }

Time Stack::next_deadline() const { return Time::never(); }

Time Stack::now() const { return impl_->core.now(); }

std::optional<SocketEvent> Stack::poll_event() { return std::nullopt; }

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

std::expected<Handle, Error> Stack::udp_open(Endpoint) {
  return std::unexpected(Error::invalid_state);
}

std::expected<void, Error> Stack::udp_send_to(Handle, Endpoint, std::span<const std::byte>) {
  return std::unexpected(Error::invalid_state);
}

std::expected<UdpRecv, Error> Stack::udp_recv_from(Handle, std::span<std::byte>) {
  return std::unexpected(Error::invalid_state);
}

std::expected<void, Error> Stack::udp_close(Handle) {
  return std::unexpected(Error::invalid_state);
}

std::expected<void, Error> Stack::icmp_echo(Ipv4Addr, std::uint16_t, std::uint16_t,
                                            std::span<const std::byte>) {
  return std::unexpected(Error::invalid_state);
}

std::optional<EchoReply> Stack::poll_echo_reply() { return std::nullopt; }

void Stack::set_trace_sink(TraceSink* sink) { impl_->core.set_trace_sink(sink); }

const StackStats& Stack::stats() const { return impl_->core.stats(); }

const StackConfig& Stack::config() const { return impl_->core.config(); }

void Stack::debug_check() const {
  impl_->core.timers().check_invariants();
  impl_->tcp.check_invariants();
}

StackUsage Stack::debug_usage() const {
  const StackCore& c = impl_->core;
  const TcpUsage tcp = impl_->tcp.usage();
  StackUsage u;
  u.tcp_slots = tcp.slots;
  u.time_wait_entries = tcp.time_wait_entries;
  u.pool_buffers = c.pool().count();
  u.pool_buffers_free = c.pool().available();
  u.chunks = c.chunks().allocated();
  u.chunks_free = c.chunks().free_count();
  u.conn_timers_armed = tcp.timers_armed;
  u.stack_timers_armed = static_cast<std::uint32_t>(c.timers().armed_count()) - tcp.timers_armed;
  return u;
}

}  // namespace utcp
