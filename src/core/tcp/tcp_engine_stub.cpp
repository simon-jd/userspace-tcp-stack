// Link stub (m1-found): an engine that drops every segment, answers the port
// allocator's queries with false and refuses every socket call with
// Error::invalid_state. m1-tcp-core deletes this file.
#include "core/stack_impl.hpp"
#include "core/tcp/tcp_engine.hpp"

namespace utcp {

TcpEngine::TcpEngine(StackCore& core) : core_(core) {}

TcpEngine::~TcpEngine() = default;

void TcpEngine::on_segment(Time, const wire::Ipv4Header&, const wire::TcpView&, RxMeta) {
  static_cast<void>(core_);  // dropped
}

void TcpEngine::on_icmp_error(Time, const TcpIcmpError&) {}

void TcpEngine::on_timer(Time, std::uint32_t, TimerKind) {}

void TcpEngine::on_tx_space(Time, std::uint32_t) {}

bool TcpEngine::tuple_in_use(const FourTuple&) const { return false; }

bool TcpEngine::port_has_listener(std::uint16_t) const { return false; }

std::expected<Handle, Error> TcpEngine::tcp_listen(Endpoint, std::uint32_t,
                                                   const TcpSocketOptions&) {
  return std::unexpected(Error::invalid_state);
}

std::expected<Handle, Error> TcpEngine::tcp_accept(Handle) {
  return std::unexpected(Error::invalid_state);
}

std::expected<Handle, Error> TcpEngine::tcp_connect(Endpoint, const TcpSocketOptions&,
                                                    std::uint16_t) {
  return std::unexpected(Error::invalid_state);
}

std::expected<std::size_t, Error> TcpEngine::tcp_send(Handle, std::span<const std::byte>) {
  return std::unexpected(Error::invalid_state);
}

std::expected<std::size_t, Error> TcpEngine::tcp_recv(Handle, std::span<std::byte>) {
  return std::unexpected(Error::invalid_state);
}

std::expected<void, Error> TcpEngine::tcp_shutdown(Handle, Shutdown) {
  return std::unexpected(Error::invalid_state);
}

std::expected<void, Error> TcpEngine::tcp_close(Handle) {
  return std::unexpected(Error::invalid_state);
}

std::expected<void, Error> TcpEngine::tcp_abort(Handle) {
  return std::unexpected(Error::invalid_state);
}

Readiness TcpEngine::tcp_readiness(Handle) const { return Readiness{}; }

std::expected<TcpInfo, Error> TcpEngine::tcp_info(Handle) const {
  return std::unexpected(Error::invalid_state);
}

std::expected<void, Error> TcpEngine::tcp_set_options(Handle, const TcpSocketOptions&) {
  return std::unexpected(Error::invalid_state);
}

std::optional<Error> TcpEngine::take_error(Handle) { return std::nullopt; }

TcpUsage TcpEngine::usage() const { return TcpUsage{}; }

void TcpEngine::check_invariants() const {}

}  // namespace utcp
