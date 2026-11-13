// KernelTransport: the Transport interface (common/transport.hpp) on
// non-blocking Linux sockets and the backend's EventLoop (DESIGN §9).
//
// Every socket is registered edge-triggered (EPOLLET), which gives the
// interface's edge-triggered events directly: on_readable after the kernel
// reports new data, the end of stream or an error; on_writable only after a
// send was refused or short (the kernel reports write space again once
// SOCK_NOSPACE was set). on_closed follows EPOLLHUP without an error: Linux
// tcp_poll sets it once both directions are shut down (our shutdown and the
// peer's FIN), as in the interface. Errors come from SO_ERROR on EPOLLERR.
// Events that a call produces directly (a connect that completes at once)
// are queued and delivered from an eventfd, so they never run inside the
// call.
//
// sample() maps TCP_INFO by the table of DESIGN §10.1. Socket options:
// nodelay -> TCP_NODELAY, snd_buf/rcv_buf -> SO_SNDBUF/SO_RCVBUF (only when
// set: setting them turns off the kernel's autotuning), cc ->
// TCP_CONGESTION ("reno" for newreno), mss_clamp -> TCP_MAXSEG. A listener
// sets them before listen(), so accepted connections inherit them.
//
// The backend selection shared by the programs (--backend kernel|utcp and the
// utcp backend's options) is at the end of this file.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

#include "common/cli.hpp"
#include "common/transport.hpp"
#include "utcp/event_loop.hpp"

namespace utcp::app {

class KernelTransport final : public Transport {
public:
  explicit KernelTransport(const EventLoopOptions& loop_options = {});
  ~KernelTransport() override;
  KernelTransport(const KernelTransport&) = delete;
  KernelTransport& operator=(const KernelTransport&) = delete;

  std::expected<ConnId, Error> connect(Endpoint remote, const TcpSocketOptions& opts) override;
  std::expected<ConnId, Error> listen(Endpoint local, std::uint32_t backlog,
                                      const TcpSocketOptions& opts) override;
  std::expected<std::size_t, Error> send(ConnId id, std::span<const std::byte> data) override;
  std::expected<std::size_t, Error> recv(ConnId id, std::span<std::byte> out) override;
  void shutdown_write(ConnId id) override;
  void close(ConnId id) override;
  ConnSample sample(ConnId id) override;

  std::expected<ConnId, Error> udp_open(Endpoint local) override;
  std::expected<void, Error> send_to(ConnId id, Endpoint remote,
                                     std::span<const std::byte> data) override;
  std::expected<UdpRecv, Error> recv_from(ConnId id, std::span<std::byte> out) override;

  TimerToken add_timer(Duration period, std::function<void()> cb) override;
  TimerToken add_oneshot(Duration delay, std::function<void()> cb) override;
  void cancel_timer(TimerToken t) override;

  // Runs the EventLoop until stop() or one of the loop's stop signals
  // (SIGINT, SIGTERM). After a signal the loop stays stopped and run()
  // returns at once.
  void run(Handler& h) override;
  void stop() override;
  [[nodiscard]] Time now() const override { return mono_now(); }
  [[nodiscard]] const LoopStats* loop_stats() const override { return &loop_.stats(); }

  // --- Kernel-specific.
  // getsockname / getpeername of a socket.
  [[nodiscard]] std::expected<Endpoint, Error> local_endpoint(ConnId id) const;
  [[nodiscard]] std::expected<Endpoint, Error> remote_endpoint(ConnId id) const;
  // The signal that ended run(), 0 if none.
  [[nodiscard]] int stop_signal() const { return loop_.stop_signal(); }
  // The system call and errno text behind the last error a call returned
  // (e.g. "setsockopt(TCP_CONGESTION, bbr): No such file or directory").
  [[nodiscard]] const std::string& last_error_detail() const { return detail_; }
  [[nodiscard]] std::size_t open_count() const { return socks_.size(); }

private:
  enum class Kind : std::uint8_t { listener, tcp, udp };
  struct Sock {
    Kind kind = Kind::tcp;
    int fd = -1;
    TcpSocketOptions opts{};        // listener: inherited by accepted connections
    bool connecting = false;        // connect() in progress
    bool want_writable = false;     // a send was refused or short
    bool fin_sent = false;          // shutdown_write() was called
    bool closed_delivered = false;  // on_closed was delivered
    std::optional<Error> error{};   // the connection failed (from SO_ERROR or a call)
  };
  enum class EvType : std::uint8_t { connected, error };
  struct Pending {
    EvType type = EvType::connected;
    ConnId id = no_conn;
    Error err = Error::would_block;
  };
  struct Timer {
    Time deadline{};
    std::uint64_t seq = 0;
    Duration period{};  // 0: one-shot
    std::shared_ptr<std::function<void()>> cb;
  };

  Sock* find(ConnId id, Kind kind);
  const Sock* find_any(ConnId id) const;
  ConnId add(Sock s);
  Error fail(const char* what, int err);
  std::expected<void, Error> apply_options(int fd, const TcpSocketOptions& opts);
  void watch(ConnId id, int fd);
  void queue(Pending p);
  void on_io(ConnId id, std::uint32_t events);
  void on_listener(ConnId id);
  void on_pending();
  void on_deadline(Time now);
  [[nodiscard]] Time next_deadline() const;
  TimerToken add_timer_(Time deadline, Duration period, std::function<void()> cb);

  EventLoop loop_;
  int event_fd_ = -1;
  Handler* handler_ = nullptr;
  bool stopped_ = false;
  std::map<ConnId, Sock> socks_;
  ConnId next_id_ = 1;
  std::deque<Pending> pending_;
  std::map<TimerToken, Timer> timers_;
  std::map<std::pair<Time, std::uint64_t>, TimerToken> timer_order_;
  TimerToken next_timer_ = 1;
  std::uint64_t next_timer_seq_ = 0;
  std::string detail_;
};

// Linux errno -> Error (the inverse of to_errno; unknown values give
// invalid_state).
[[nodiscard]] Error error_from_errno(int err) noexcept;
// The TCP_CONGESTION name of an algorithm: "reno", "cubic", "bbr".
[[nodiscard]] std::string_view kernel_cc_name(CcAlgo cc) noexcept;
// "newreno" or "reno", "cubic", "bbr".
[[nodiscard]] std::expected<CcAlgo, std::string> parse_cc(std::string_view s);

// --- Backend selection (DESIGN §9), shared by the programs.
//
// Declares --backend kernel|utcp (default utcp), --profile rfc|linux
// (default linux; utcp only) and the utcp backend's options: --tun IFNAME
// (utcp0), --addr IP (198.18.0.2), --mtu N (1500), --pcap FILE, --spin-us N
// (0), --seed N (default: getrandom).
void add_backend_options(CliParser& p);

struct BackendSelection {
  bool kernel = false;
  UtcpTransportOptions utcp;  // filled for the utcp backend
};
[[nodiscard]] std::expected<BackendSelection, std::string> parse_backend_options(const CliArgs& a);

// KernelTransport or make_utcp_transport(), as selected.
[[nodiscard]] std::expected<std::unique_ptr<Transport>, std::string> make_transport(
    const BackendSelection& b);

// The error's name and errno text, e.g. "connection_refused (Connection
// refused)": for messages.
[[nodiscard]] std::string describe(Error e);

}  // namespace utcp::app
