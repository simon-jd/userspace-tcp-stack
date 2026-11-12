// Socket API errors (DESIGN §3.5). API calls return std::expected<T, Error>.
#pragma once

#include <cstdint>
#include <string_view>

namespace utcp {

enum class Error : std::uint8_t {
  would_block,          // EAGAIN: nothing to read, no send space, no child to accept
  bad_handle,           // EBADF: unknown or stale handle, or wrong protocol
  invalid_state,        // EINVAL: call not allowed in the socket's state
  invalid_argument,     // EINVAL
  addr_in_use,          // EADDRINUSE
  addr_not_available,   // EADDRNOTAVAIL: bad local address, or no ephemeral port free
  not_connected,        // ENOTCONN
  already_connected,    // EISCONN
  connection_refused,   // ECONNREFUSED: RST or ICMP unreachable during connect
  connection_reset,     // ECONNRESET
  connection_aborted,   // ECONNABORTED
  timed_out,            // ETIMEDOUT: retransmissions exhausted
  host_unreachable,     // EHOSTUNREACH
  network_unreachable,  // ENETUNREACH
  message_too_big,      // EMSGSIZE: UDP datagram above pmtu - 28
  no_buffers,           // ENOBUFS
  shut_down,            // EPIPE: send after shutdown(write)
};
inline constexpr int error_count = 17;

// Enumerator name, e.g. "would_block".
[[nodiscard]] std::string_view to_string(Error e) noexcept;
// Linux errno value, as in the comments above (for apps and the packetdrill shim).
[[nodiscard]] int to_errno(Error e) noexcept;

}  // namespace utcp
