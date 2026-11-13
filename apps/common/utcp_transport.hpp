// UtcpTransport: the Transport of DESIGN §9 over a Stack, a TUN device and an
// EventLoop (§8). make_utcp_transport (declared in transport.hpp) returns one
// of these; programs that need more than the Transport interface (the stack's
// counters, the device counters) use this header.
//
// One iteration of run() (§8.2):
// 1. EventLoop::run_once with deadline min(stack.next_deadline(), app timers):
//    a. the wait (epoll_pwait2, nanosecond timeout, optional --spin-us);
//    b. the device is readable: stack.advance(mono_now()), then up to 64
//       datagrams, each stack.receive(mono_now(), ...) (per-packet clock for
//       RTT precision);
//    c. the deadline has passed: stack.advance(now) and the app timers due.
// 2. Socket events (Stack::poll_event) go to the Handler, whose callbacks
//    call the Transport, until no event is left.
// 3. pop_transmit() is drained with write(2); on EAGAIN the packet is kept
//    and the device is watched for EPOLLOUT until it has been written.
// Host contract (§3.4): drained before every wait, advance when the deadline
// has passed, now non-decreasing (CLOCK_MONOTONIC). Calls made outside run()
// (setup before the first run, or after it returned) first advance the stack
// to mono_now() and drain its output, so their packets leave at once.
//
// Events, per Stack event mask, in this order (the id is re-checked after
// each callback, as a callback may close it): ev_connected -> on_connected;
// ev_acceptable on a listener -> tcp_accept until would_block, on_accept for
// each child, then on_readable/on_error if the child already has data or an
// error (its events may have been raised before it had an id);
// ev_readable or ev_read_closed -> on_readable; ev_writable -> on_writable;
// ev_error -> on_error(take_error()); ev_closed -> on_closed, unless the
// connection reported an error.
//
// --pcap FILE (§10.2): every datagram read from or written to the device, as
// LINKTYPE_RAW records with CLOCK_REALTIME nanosecond timestamps (so they
// line up with tcpdump on the peer), snaplen 65535. Written through a 1 MiB
// stdio buffer, flushed when the transport is destroyed.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "common/transport.hpp"

namespace utcp::app {

// Counters of the device side.
struct DeviceStats {
  std::uint64_t rx_datagrams = 0, rx_bytes = 0;  // read from the device, passed to receive()
  std::uint64_t rx_errors = 0;                   // read errors other than EAGAIN/EINTR
  std::uint64_t tx_datagrams = 0, tx_bytes = 0;  // written to the device
  std::uint64_t tx_eagain = 0;                   // writes that returned EAGAIN (packet kept)
  std::uint64_t tx_errors = 0;                   // write errors: the packet was dropped
  int last_tx_errno = 0;
  std::uint64_t rx_batches = 0;                  // readable callbacks
  std::uint64_t rx_batch_limit = 0;              // batches that stopped at 64 datagrams
  std::uint64_t pcap_records = 0;
  bool pcap_failed = false;                      // a pcap write failed; recording stopped
  bool device_failed = false;                    // the device reported an error (EPOLLERR/HUP)
};

class UtcpTransport final : public Transport {
public:
  // Opens the TUN interface opts.tun (IFF_TUN | IFF_NO_PI, non-blocking; it is
  // created if missing, which needs CAP_NET_ADMIN; addresses and routes are
  // the testbed's job, §8.1), checks that opts.stack.mtu equals its MTU, waits
  // up to 1 s until the interface is running (TunDevice::wait_running; an
  // error if it is down), fills the seed from getrandom(2) if asked, and opens
  // the pcap file.
  static std::expected<std::unique_ptr<UtcpTransport>, std::string> open(
      const UtcpTransportOptions& opts);
  // The same over an already open datagram fd (one IPv4 datagram per read
  // and write: a TUN fd, or one end of a SOCK_SEQPACKET socketpair in tests).
  // Takes ownership of `fd` and makes it non-blocking; opts.tun is ignored
  // and the MTU is not checked.
  static std::expected<std::unique_ptr<UtcpTransport>, std::string> attach(
      int fd, const UtcpTransportOptions& opts);

  ~UtcpTransport() override;
  UtcpTransport(const UtcpTransport&) = delete;
  UtcpTransport& operator=(const UtcpTransport&) = delete;

  // Transport.
  std::expected<ConnId, Error> connect(Endpoint remote, const TcpSocketOptions& opts) override;
  std::expected<ConnId, Error> listen(Endpoint local, std::uint32_t backlog,
                                      const TcpSocketOptions& opts) override;
  std::expected<std::size_t, Error> send(ConnId id, std::span<const std::byte> data) override;
  std::expected<std::size_t, Error> recv(ConnId id, std::span<std::byte> out) override;
  void shutdown_write(ConnId id) override;
  void close(ConnId id) override;
  ConnSample sample(ConnId id) override;
  std::expected<ConnId, Error> udp_open(Endpoint local) override;
  // Stack::udp_send_to; on no_buffers the transmit queue is written to the
  // device and the send is tried once more.
  std::expected<void, Error> send_to(ConnId id, Endpoint remote,
                                     std::span<const std::byte> data) override;
  std::expected<UdpRecv, Error> recv_from(ConnId id, std::span<std::byte> out) override;
  // Periodic timers are drift-free (next = previous deadline + period) but
  // never fire twice for one wake-up: a timer that fell behind by a whole
  // period is rescheduled to now + period.
  TimerToken add_timer(Duration period, std::function<void()> cb) override;
  TimerToken add_oneshot(Duration delay, std::function<void()> cb) override;
  void cancel_timer(TimerToken t) override;
  // Until stop(), a stop signal (SIGINT, SIGTERM: the EventLoop's signalfd)
  // or a device error. stop() takes effect after the current callback; run()
  // can be called again after stop(), not after a signal.
  void run(Handler& h) override;
  void stop() override { stop_requested_ = true; }
  [[nodiscard]] Time now() const override;
  [[nodiscard]] const LoopStats* loop_stats() const override { return &loop_.stats(); }

  // Beyond Transport.
  [[nodiscard]] Stack& stack() noexcept { return stack_; }
  [[nodiscard]] const Stack& stack() const noexcept { return stack_; }
  [[nodiscard]] const DeviceStats& device_stats() const noexcept { return dev_; }
  // The signal that ended run(), 0 if none.
  [[nodiscard]] int stop_signal() const noexcept { return loop_.stop_signal(); }
  // Writes the pcap buffer to the file now.
  void flush_pcap();

private:
  struct PcapWriter;
  enum class Kind : std::uint8_t { listener, tcp, udp };
  struct Sock {
    Kind kind = Kind::tcp;
    Handle h{};
    bool errored = false;  // on_error was delivered: no on_closed
  };
  struct Timer {
    Time deadline{};
    Duration period{};  // 0: one-shot
    std::shared_ptr<std::function<void()>> cb{};  // shared: survives a cancel inside the call
  };

  UtcpTransport(int fd, const UtcpTransportOptions& opts);

  // A call from outside run(): advance to mono_now() first.
  void outside_run_enter();
  // A call from outside run() that may have produced output: drain it.
  void outside_run_leave();
  void on_device(std::uint32_t events);
  void read_batch();
  void device_failed();
  void drain_tx();
  void deliver_events();
  void deliver(ConnId id, std::uint16_t ev);
  void accept_all(ConnId listener);
  void fire_timers(Time now);
  [[nodiscard]] Time timer_deadline() const;
  ConnId add_sock(Kind kind, Handle h);
  Sock* find(ConnId id);
  Sock* find(ConnId id, Kind kind);
  void record_pcap(std::span<const std::byte> datagram);

  UtcpTransportOptions opt_;
  int fd_ = -1;
  bool watched_ = false;       // fd_ is registered with loop_
  bool watching_out_ = false;  // ... for EPOLLOUT as well
  EventLoop loop_;
  Stack stack_;
  std::unique_ptr<PcapWriter> pcap_;
  std::vector<std::byte> rxbuf_;
  std::optional<TxPacket> pending_tx_;  // EAGAIN: written when EPOLLOUT arrives
  std::map<ConnId, Sock> socks_;
  std::map<Handle, ConnId> by_handle_;
  ConnId next_id_ = 1;
  std::map<TimerToken, Timer> timers_;
  TimerToken next_timer_ = 1;
  Handler* handler_ = nullptr;  // non-null inside run()
  bool in_run_ = false;
  bool stop_requested_ = false;
  DeviceStats dev_;
};

}  // namespace utcp::app
