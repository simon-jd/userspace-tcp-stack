// UDP: unconnected sockets (RFC 768; DESIGN §3.6).
//
// A socket is bound to one local port (address 0 or the stack address). It
// sends datagrams with DF set, never larger than the path MTU (no
// fragmentation), and stores received datagrams length-prefixed in a ByteRing
// of UdpConfig::rcv_buf bytes; a datagram that does not fit is dropped and
// counted. Checksums are always sent (a computed 0 as 0xFFFF); a received 0
// means none. ICMP errors quoting UDP are counted, not reported to sockets;
// frag-needed for a bound port lowers the PMTU cache (Linux __udp4_lib_err).
//
// Sockets share StackConfig::max_connections with TCP (StackCore slots).
// Slots of the UDP slot vector are reused lowest-first; the handle's gen
// increments on reuse.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "core/buffer/byte_ring.hpp"
#include "core/wire/ipv4.hpp"
#include "utcp/error.hpp"
#include "utcp/packet.hpp"
#include "utcp/stack.hpp"
#include "utcp/types.hpp"

namespace utcp {

class StackCore;

class UdpLayer {
public:
  // Bytes in front of each stored datagram: source address (4), source port
  // (2), payload length (2).
  static constexpr std::uint32_t record_header_len = 8;
  // Largest payload of one datagram: 65535 - 20 - 8.
  static constexpr std::uint32_t max_payload = 65507;

  explicit UdpLayer(StackCore& core);
  ~UdpLayer();
  UdpLayer(const UdpLayer&) = delete;
  UdpLayer& operator=(const UdpLayer&) = delete;

  // --- Socket API (Stack::udp_*, §3.6).
  // addr_not_available if local.addr is neither 0 nor the stack address, or
  // port 0 and no ephemeral port is free; addr_in_use if a UDP socket has the
  // port; no_buffers if no slot is left (max_connections).
  std::expected<Handle, Error> open(Endpoint local);
  // invalid_argument for remote address or port 0; message_too_big above
  // pmtu(remote) - 28 bytes; no_buffers when the transmit queue or the pool
  // is full (UdpSndbufErrors).
  std::expected<void, Error> send_to(Handle h, Endpoint remote, std::span<const std::byte> data);
  // would_block if nothing is queued.
  std::expected<UdpRecv, Error> recv_from(Handle h, std::span<std::byte> out);
  std::expected<void, Error> close(Handle h);

  // --- From the IP layer.
  enum class Input : std::uint8_t {
    delivered,  // queued on a socket
    dropped,    // malformed, bad checksum or receive buffer full (counted)
    no_port,    // valid, but no socket has the port: the caller sends ICMP 3/3
  };
  // `ip` is a validated datagram for the stack address with protocol UDP.
  Input on_datagram(const wire::Ipv4View& ip, RxMeta meta);
  // An ICMP error (type, code) whose quote is a UDP datagram we sent from
  // `local_port` to `remote`. Counts udp_icmp_errors; for type 3 code 4 with
  // a bound port, lowers the path MTU to remote.addr to `frag_mtu`.
  void on_icmp_error(std::uint8_t type, std::uint8_t code, std::uint16_t local_port,
                     Endpoint remote, std::uint16_t frag_mtu);

  // A socket has the port.
  [[nodiscard]] bool port_bound(std::uint16_t port) const noexcept;
  [[nodiscard]] std::uint32_t open_count() const noexcept { return open_; }
  // Datagrams queued on `h` (0 for a bad handle).
  [[nodiscard]] std::uint32_t queued(Handle h) const noexcept;

  // Slots, bindings and receive rings consistent; aborts on failure.
  void check_invariants() const;

private:
  struct Socket {
    std::uint32_t gen = 0;
    bool open = false;
    std::uint16_t port = 0;
    std::optional<ByteRing> rcv;  // [head, tail): records
    std::uint64_t head = 0, tail = 0;
    std::uint32_t datagrams = 0;
  };

  Socket* find(Handle h) noexcept;
  [[nodiscard]] const Socket* find(Handle h) const noexcept;
  [[nodiscard]] std::optional<std::uint32_t> bound_slot(std::uint16_t port) const noexcept;
  void bind(std::uint16_t port, std::uint32_t slot);
  void unbind(std::uint16_t port);
  bool enqueue(Socket& s, Endpoint from, std::span<const std::byte> payload);

  StackCore& core_;
  std::vector<Socket> slots_;
  std::vector<std::uint32_t> free_;                          // min-heap of free slot indices
  std::vector<std::pair<std::uint16_t, std::uint32_t>> bound_;  // (port, slot), sorted by port
  std::uint32_t open_ = 0;
};

}  // namespace utcp
