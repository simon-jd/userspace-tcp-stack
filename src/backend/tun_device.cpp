#include "utcp/tun_device.hpp"

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <utility>

namespace utcp {
namespace {

std::error_code last_error() { return {errno, std::system_category()}; }

}  // namespace

std::expected<TunDevice, std::error_code> TunDevice::open(std::string_view name,
                                                          bool nonblocking) {
  if (name.size() >= IFNAMSIZ) {
    return std::unexpected(std::make_error_code(std::errc::invalid_argument));
  }
  int flags = O_RDWR | O_CLOEXEC;
  if (nonblocking) {
    flags |= O_NONBLOCK;
  }
  const int fd = ::open("/dev/net/tun", flags);
  if (fd < 0) {
    return std::unexpected(last_error());
  }

  ifreq ifr{};
  ifr.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI);
  std::memcpy(ifr.ifr_name, name.data(), name.size());
  if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
    const std::error_code ec = last_error();
    ::close(fd);
    return std::unexpected(ec);
  }
  return TunDevice(fd, std::string(ifr.ifr_name, ::strnlen(ifr.ifr_name, IFNAMSIZ)));
}

TunDevice::TunDevice(TunDevice&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)), name_(std::move(other.name_)) {}

TunDevice& TunDevice::operator=(TunDevice&& other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) {
      ::close(fd_);
    }
    fd_ = std::exchange(other.fd_, -1);
    name_ = std::move(other.name_);
  }
  return *this;
}

TunDevice::~TunDevice() {
  if (fd_ >= 0) {
    ::close(fd_);
  }
}

std::expected<std::size_t, std::error_code> TunDevice::read(std::span<std::byte> buf) const {
  const ssize_t n = ::read(fd_, buf.data(), buf.size());
  if (n < 0) {
    return std::unexpected(last_error());
  }
  return static_cast<std::size_t>(n);
}

std::expected<std::size_t, std::error_code> TunDevice::write(
    std::span<const std::byte> packet) const {
  const ssize_t n = ::write(fd_, packet.data(), packet.size());
  if (n < 0) {
    return std::unexpected(last_error());
  }
  return static_cast<std::size_t>(n);
}

}  // namespace utcp
