#include "utcp/error.hpp"

#include <cerrno>

namespace utcp {

std::string_view to_string(Error e) noexcept {
  switch (e) {
    case Error::would_block: return "would_block";
    case Error::bad_handle: return "bad_handle";
    case Error::invalid_state: return "invalid_state";
    case Error::invalid_argument: return "invalid_argument";
    case Error::addr_in_use: return "addr_in_use";
    case Error::addr_not_available: return "addr_not_available";
    case Error::not_connected: return "not_connected";
    case Error::already_connected: return "already_connected";
    case Error::connection_refused: return "connection_refused";
    case Error::connection_reset: return "connection_reset";
    case Error::connection_aborted: return "connection_aborted";
    case Error::timed_out: return "timed_out";
    case Error::host_unreachable: return "host_unreachable";
    case Error::network_unreachable: return "network_unreachable";
    case Error::message_too_big: return "message_too_big";
    case Error::no_buffers: return "no_buffers";
    case Error::shut_down: return "shut_down";
  }
  return "?";
}

int to_errno(Error e) noexcept {
  switch (e) {
    case Error::would_block: return EAGAIN;
    case Error::bad_handle: return EBADF;
    case Error::invalid_state: return EINVAL;
    case Error::invalid_argument: return EINVAL;
    case Error::addr_in_use: return EADDRINUSE;
    case Error::addr_not_available: return EADDRNOTAVAIL;
    case Error::not_connected: return ENOTCONN;
    case Error::already_connected: return EISCONN;
    case Error::connection_refused: return ECONNREFUSED;
    case Error::connection_reset: return ECONNRESET;
    case Error::connection_aborted: return ECONNABORTED;
    case Error::timed_out: return ETIMEDOUT;
    case Error::host_unreachable: return EHOSTUNREACH;
    case Error::network_unreachable: return ENETUNREACH;
    case Error::message_too_big: return EMSGSIZE;
    case Error::no_buffers: return ENOBUFS;
    case Error::shut_down: return EPIPE;
  }
  return EINVAL;
}

}  // namespace utcp
