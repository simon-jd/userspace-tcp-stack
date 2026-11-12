#include "utcp/error.hpp"

#include <gtest/gtest.h>

#include <cerrno>
#include <set>
#include <string_view>

namespace {

using utcp::Error;

TEST(Error, NamesAreDistinct) {
  std::set<std::string_view> names;
  for (int i = 0; i < utcp::error_count; ++i) {
    const auto name = to_string(static_cast<Error>(i));
    EXPECT_NE(name, "?") << i;
    names.insert(name);
  }
  EXPECT_EQ(names.size(), static_cast<std::size_t>(utcp::error_count));
  EXPECT_EQ(to_string(Error::would_block), "would_block");
  EXPECT_EQ(to_string(Error::shut_down), "shut_down");
}

TEST(Error, Errno) {
  EXPECT_EQ(to_errno(Error::would_block), EAGAIN);
  EXPECT_EQ(to_errno(Error::bad_handle), EBADF);
  EXPECT_EQ(to_errno(Error::addr_in_use), EADDRINUSE);
  EXPECT_EQ(to_errno(Error::addr_not_available), EADDRNOTAVAIL);
  EXPECT_EQ(to_errno(Error::not_connected), ENOTCONN);
  EXPECT_EQ(to_errno(Error::already_connected), EISCONN);
  EXPECT_EQ(to_errno(Error::connection_refused), ECONNREFUSED);
  EXPECT_EQ(to_errno(Error::connection_reset), ECONNRESET);
  EXPECT_EQ(to_errno(Error::connection_aborted), ECONNABORTED);
  EXPECT_EQ(to_errno(Error::timed_out), ETIMEDOUT);
  EXPECT_EQ(to_errno(Error::host_unreachable), EHOSTUNREACH);
  EXPECT_EQ(to_errno(Error::network_unreachable), ENETUNREACH);
  EXPECT_EQ(to_errno(Error::message_too_big), EMSGSIZE);
  EXPECT_EQ(to_errno(Error::no_buffers), ENOBUFS);
  EXPECT_EQ(to_errno(Error::shut_down), EPIPE);
  for (int i = 0; i < utcp::error_count; ++i) {
    EXPECT_GT(to_errno(static_cast<Error>(i)), 0);
  }
}

}  // namespace
