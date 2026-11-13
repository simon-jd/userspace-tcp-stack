#include "utcp/sim/digest.hpp"

namespace utcp::sim {
namespace {

// A fixed key: the digest identifies a run, it is not a secret.
constexpr SipKey digest_key{0x7574'6370'2d73'696dULL, 0x6469'6765'7374'0001ULL};

void put_text(SipHasher24& h, std::string_view s) noexcept {
  h.update_u32(static_cast<std::uint32_t>(s.size()));
  h.update(std::as_bytes(std::span<const char>(s.data(), s.size())));
}

}  // namespace

RunDigest::RunDigest() noexcept : h_(digest_key) {}

void RunDigest::packet(std::uint32_t node, Time t, std::span<const std::byte> datagram) noexcept {
  h_.update_u8('P');
  h_.update_u32(node);
  h_.update_u64(static_cast<std::uint64_t>(t.ns));
  h_.update_u32(static_cast<std::uint32_t>(datagram.size()));
  h_.update(datagram);
}

void RunDigest::delivery(std::uint32_t node, Time t, std::span<const std::byte> datagram) noexcept {
  h_.update_u8('D');
  h_.update_u32(node);
  h_.update_u64(static_cast<std::uint64_t>(t.ns));
  h_.update_u32(static_cast<std::uint32_t>(datagram.size()));
  h_.update(datagram);
}

void RunDigest::socket_event(std::uint32_t node, Time t, std::uint32_t slot, std::uint32_t gen,
                             std::uint8_t proto, std::uint16_t events) noexcept {
  h_.update_u8('E');
  h_.update_u32(node);
  h_.update_u64(static_cast<std::uint64_t>(t.ns));
  h_.update_u32(slot);
  h_.update_u32(gen);
  h_.update_u8(proto);
  h_.update_u16(events);
}

void RunDigest::text(std::uint32_t node, Time t, std::string_view tag,
                     std::string_view what) noexcept {
  h_.update_u8('T');
  h_.update_u32(node);
  h_.update_u64(static_cast<std::uint64_t>(t.ns));
  put_text(h_, tag);
  put_text(h_, what);
}

std::array<char, 16> RunDigest::hex(std::uint64_t v) noexcept {
  constexpr char digits[] = "0123456789abcdef";
  std::array<char, 16> out{};
  for (int i = 15; i >= 0; --i) {
    out[static_cast<std::size_t>(i)] = digits[v & 0xf];
    v >>= 4;
  }
  return out;
}

}  // namespace utcp::sim
