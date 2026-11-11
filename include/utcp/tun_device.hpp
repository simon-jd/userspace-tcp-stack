// Linux TUN interface opened with IFF_TUN | IFF_NO_PI: each read returns one
// IP packet and each write sends one, with no extra header in front.
#pragma once

#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace utcp {

class TunDevice {
public:
  // Opens /dev/net/tun and attaches to interface `name`, creating it if it
  // does not exist (creating needs CAP_NET_ADMIN). An empty name lets the
  // kernel pick one (tun0, tun1, ...). The interface is left down and without
  // an address.
  static std::expected<TunDevice, std::error_code> open(std::string_view name, bool nonblocking);

  TunDevice(TunDevice&& other) noexcept;
  TunDevice& operator=(TunDevice&& other) noexcept;
  TunDevice(const TunDevice&) = delete;
  TunDevice& operator=(const TunDevice&) = delete;
  ~TunDevice();

  [[nodiscard]] int fd() const noexcept { return fd_; }
  // Name the kernel assigned.
  [[nodiscard]] const std::string& name() const noexcept { return name_; }

  // Reads one packet. A buffer shorter than the packet truncates it.
  std::expected<std::size_t, std::error_code> read(std::span<std::byte> buf) const;
  // Writes one packet.
  std::expected<std::size_t, std::error_code> write(std::span<const std::byte> packet) const;

private:
  TunDevice(int fd, std::string name) noexcept : fd_(fd), name_(std::move(name)) {}

  int fd_ = -1;
  std::string name_;
};

}  // namespace utcp
