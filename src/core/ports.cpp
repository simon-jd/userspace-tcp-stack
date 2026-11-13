#include "core/ports.hpp"

#include "core/util/siphash.hpp"

namespace utcp {
namespace {

std::uint64_t port_hash(const SipKey& key, Ipv4Addr local, Endpoint remote) noexcept {
  // RFC 6056 §3.3.4: F(local_IP, remote_IP, remote_port, secret_key).
  SipHasher24 h(key);
  h.update_u32(local.v);
  h.update_u32(remote.addr.v);
  h.update_u16(remote.port);
  return h.finish();
}

}  // namespace

PortAllocator::PortAllocator(const SipKey& offset_key, const SipKey& table_key,
                             Rng table_init) noexcept
    : offset_key_(offset_key), table_key_(table_key) {
  for (auto& v : table_) {
    v = static_cast<std::uint32_t>(table_init.next() & 0xffffu);
  }
}

std::uint32_t PortAllocator::offset(Ipv4Addr local, Endpoint remote) const noexcept {
  return static_cast<std::uint32_t>(port_hash(offset_key_, local, remote));
}

std::size_t PortAllocator::index(Ipv4Addr local, Endpoint remote) const noexcept {
  return static_cast<std::size_t>(port_hash(table_key_, local, remote) % table_size);
}

std::expected<std::uint16_t, Error> PortAllocator::pick(
    PortRange range, Ipv4Addr local, Endpoint remote,
    FunctionRef<bool(std::uint16_t)> unusable) noexcept {
  const std::uint64_t n = range.size();
  const std::uint64_t off = offset(local, remote);
  std::uint32_t& counter = table_[index(local, remote)];
  for (std::uint64_t count = n; count > 0; --count) {
    const auto port = static_cast<std::uint16_t>(std::uint64_t{range.lo} + (off + counter) % n);
    ++counter;
    if (!unusable(port)) {
      return port;
    }
  }
  return std::unexpected(Error::addr_not_available);
}

}  // namespace utcp
