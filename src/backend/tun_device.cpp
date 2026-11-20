#include "utcp/tun_device.hpp"

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <thread>
#include <utility>

namespace utcp {
namespace {

std::error_code last_error() { return {errno, std::system_category()}; }

}  // namespace

std::expected<TunDevice, std::error_code> TunDevice::open(std::string_view name,
                                                          bool nonblocking, TunOffload offload) {
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

  const auto fail = [fd](std::error_code ec) -> std::expected<TunDevice, std::error_code> {
    ::close(fd);
    return std::unexpected(ec);
  };
  const bool vnet = offload != TunOffload::legacy;
  const auto framing = static_cast<short>(IFF_TUN | IFF_NO_PI | (vnet ? IFF_VNET_HDR : 0));
  ifreq ifr{};
  ifr.ifr_flags = framing;
  std::memcpy(ifr.ifr_name, name.data(), name.size());
  if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
    return fail(last_error());
  }
  if (::ioctl(fd, TUNGETIFF, &ifr) < 0) {
    return fail(last_error());
  }
  constexpr short mask = IFF_TUN | IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
  if ((ifr.ifr_flags & mask) != framing) {
    return fail(std::make_error_code(std::errc::protocol_not_supported));
  }
  int header_size = 0;
  if (vnet) {
    const int desired_size = static_cast<int>(tun_vnet_header_size);
    const int little = 1;
    if (::ioctl(fd, TUNSETVNETHDRSZ, &desired_size) < 0 ||
        ::ioctl(fd, TUNGETVNETHDRSZ, &header_size) < 0 ||
        ::ioctl(fd, TUNSETVNETLE, &little) < 0) {
      return fail(last_error());
    }
    if (header_size != desired_size) {
      return fail(std::make_error_code(std::errc::protocol_not_supported));
    }
  }
  const unsigned long features =
      vnet ? static_cast<unsigned long>(TUN_F_CSUM | (offload == TunOffload::tcpv4 ? TUN_F_TSO4 : 0))
           : 0;
  // TUNSETOFFLOAD takes the feature bitmask by value, despite its _IOW encoding.
  if (::ioctl(fd, TUNSETOFFLOAD, features) < 0) {
    return fail(last_error());
  }
  return TunDevice(fd, std::string(ifr.ifr_name, ::strnlen(ifr.ifr_name, IFNAMSIZ)),
                   static_cast<std::size_t>(header_size));
}

TunDevice::TunDevice(TunDevice&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)), name_(std::move(other.name_)),
      vnet_header_size_(std::exchange(other.vnet_header_size_, 0)) {}

TunDevice& TunDevice::operator=(TunDevice&& other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) {
      ::close(fd_);
    }
    fd_ = std::exchange(other.fd_, -1);
    name_ = std::move(other.name_);
    vnet_header_size_ = std::exchange(other.vnet_header_size_, 0);
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

std::string TunDevice::operstate() const {
  const std::string path = "/sys/class/net/" + name_ + "/operstate";
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return {};
  }
  char buf[32] = {};
  const ssize_t n = ::read(fd, buf, sizeof buf - 1);
  ::close(fd);
  if (n <= 0) {
    return {};
  }
  std::string s(buf, static_cast<std::size_t>(n));
  while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) {
    s.pop_back();
  }
  return s;
}

bool TunDevice::wait_running(std::chrono::nanoseconds max) const {
  using clock = std::chrono::steady_clock;
  const auto end = clock::now() + max;
  for (;;) {
    if (operstate() == "up") {
      // linkwatch_do_dev sets operstate (rfc2863_policy) just before
      // dev_activate; give the activation time to finish.
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
      return true;
    }
    if (clock::now() >= end) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::microseconds{100});
  }
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
