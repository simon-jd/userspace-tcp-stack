// Link stub for the utcp backend; m1-backend replaces this file with
// UtcpTransport (Stack + TUN + EventLoop, DESIGN §8, §9).
#include <expected>
#include <memory>
#include <string>

#include "common/transport.hpp"

namespace utcp::app {

std::expected<std::unique_ptr<Transport>, std::string> make_utcp_transport(
    const UtcpTransportOptions& /*opts*/) {
  return std::unexpected(std::string("utcp transport not implemented yet (m1-backend)"));
}

}  // namespace utcp::app
