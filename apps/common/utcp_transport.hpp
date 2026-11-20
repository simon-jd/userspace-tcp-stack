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
//    When next_deadline() is the stack's now() (blocked connections can
//    resume, §3.4), the loop gets it as pending work instead: a zero-timeout
//    wait and stack.advance(now), without a lateness sample (§8.3).
// 2. Socket events (Stack::poll_event) go to the Handler, whose callbacks
//    call the Transport, until no event is left.
// 3. pop_transmit() is drained with write(2); on EAGAIN the packet is kept
//    and the device is watched for EPOLLOUT until it has been written.
// 4. The --pcap buffer is written to the file.
// Host contract (§3.4): drained before every wait, advance when the deadline
// has passed, now non-decreasing (CLOCK_MONOTONIC). connect, listen, send,
// recv, shutdown_write, close, udp_open and send_to, called outside run()
// (setup before the first run, or after it returned), first advance the
// stack to mono_now() and drain its output (and the pcap buffer) when they
// return, also when they fail, so packets of timers that fired in that
// advance leave at once as well as their own.
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
// line up with tcpdump on the peer), snaplen 65535. The file header is
// written when the file is opened; records go through a 1 MiB stdio buffer
// that is written out before every wait of run() and after calls made
// outside run(), so a process that aborts or is killed keeps everything up
// to its last wait.
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
#include "utcp/trace.hpp"

namespace utcp::app {

// The stack's event trace for utcp-bulk --trace (DESIGN §14.6): events are
// kept as TraceEvent structs in memory (the first block holds 64 MiB; when
// it is full another block of the same size is added, nothing is dropped)
// and written as JSONL (add_fields) only by write(), so a run pays no
// formatting and no file I/O per event and nothing per loop wait.
// Which kinds reach the sink is StackConfig::trace_mask; with
// `tx_retransmissions_only`, tx events other than retransmissions
// (fast_rexmit, rexmit, rto_rexmit, pmtu_rexmit, tlp) are not kept.
class TraceRecorder final : public TraceSink {
public:
  static constexpr std::size_t block_bytes = std::size_t{64} << 20;
  explicit TraceRecorder(bool tx_retransmissions_only);
  void on_event(const TraceEvent& e) override;
  [[nodiscard]] std::uint64_t events() const noexcept { return events_; }
  [[nodiscard]] std::uint64_t blocks() const noexcept { return blocks_.size(); }
  // Every kept event as one JSON line, in arrival order; an error message
  // if the file cannot be written.
  [[nodiscard]] std::expected<void, std::string> write(const std::string& path) const;

  [[nodiscard]] static bool is_retransmission(TxKind k) noexcept;

private:
  static constexpr std::size_t block_events = block_bytes / sizeof(TraceEvent);
  bool rexmit_only_;
  std::vector<std::vector<TraceEvent>> blocks_;
  std::uint64_t events_ = 0;
};

// Counters of the device side.
struct DeviceStats {
  std::uint64_t rx_read_calls = 0, tx_write_calls = 0;  // attempts, including errors and retries
  std::uint64_t rx_csum_valid = 0, rx_csum_partial = 0;
  std::uint64_t rx_gro_datagrams = 0, rx_gro_segments = 0;
  std::uint64_t rx_vnet_drops = 0;
  std::uint64_t tx_csum_partial = 0;
  std::uint64_t tx_gso_datagrams = 0, tx_gso_segments = 0;
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
  std::uint64_t tx_batch_max = 0;                // most datagrams written by one drain of the stack
};

class UtcpTransport final : public Transport {
public:
  // Opens the existing TUN interface opts.tun (IFF_TUN | IFF_NO_PI,
  // non-blocking; creating it, its addresses and routes are the testbed's job,
  // §8.1: a missing interface is an error at once, as TUNSETIFF would create
  // one that never comes up), checks that opts.stack.mtu equals its MTU, waits
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
  // Runs the loop without a Handler until the stack holds no TCP connection
  // the program has closed (Stack::debug_usage().tcp_slots equals the
  // listeners and connections still open) and no TIME-WAIT entry, and
  // nothing waits for the device; or until `max` passed, or a signal or
  // device error stopped the loop.
  void finish_closing(Duration max) override;
  [[nodiscard]] Time now() const override;
  [[nodiscard]] const LoopStats* loop_stats() const override { return &loop_.stats(); }

  // Beyond Transport.
  [[nodiscard]] Stack& stack() noexcept { return stack_; }
  [[nodiscard]] const Stack& stack() const noexcept { return stack_; }
  [[nodiscard]] const DeviceStats& device_stats() const noexcept { return dev_; }
  // The signal that ended run(), 0 if none.
  [[nodiscard]] int stop_signal() const noexcept { return loop_.stop_signal(); }
  // Writes the pcap buffer to the file now (run() does it before every wait).
  void flush_pcap();
  // One JSON object: "ev":"stack_stats", every StackStats field under its
  // name (for_each_stat order), then every DeviceStats field with the prefix
  // "dev_", then the EventLoop's statistics with the prefix "loop_"
  // (loop_pending_calls counts the iterations in which connections blocked
  // on transmit-queue or pool space resumed, §3.4; the lateness histogram as
  // loop_lateness_count, loop_lateness_max_ns and one key
  // loop_lateness_bucket_I per non-empty log2 bucket I, LatenessHistogram's
  // layout), and with a trace, trace_events and trace_blocks. The
  // destructor writes it, with a newline, to opts.stats_file if that is set
  // (failures go to stderr), so a program that ends normally or by
  // SIGINT/SIGTERM leaves the counters of the whole run.
  [[nodiscard]] std::string stats_json() const;
  // Records the stack's trace events (the kinds of StackConfig::trace_mask)
  // in memory; the destructor writes them to `path` as JSONL, after the
  // --stats file. Call before run().
  void enable_trace(std::string path, bool tx_retransmissions_only);
  [[nodiscard]] const TraceRecorder* trace() const noexcept { return trace_.get(); }

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

  UtcpTransport(int fd, const UtcpTransportOptions& opts, std::size_t vnet_header_size);
  static std::expected<std::unique_ptr<UtcpTransport>, std::string> attach_configured(
      int fd, const UtcpTransportOptions& opts, std::size_t vnet_header_size);

  // Scope of a Transport call (utcp_transport.cpp): outside run(), advances
  // the stack to mono_now() on entry and drains its output on every return.
  class OutsideRun;
  void outside_run_enter();
  void outside_run_leave();
  void on_device(std::uint32_t events);
  void read_batch();
  void device_failed();
  void drain_tx();
  void deliver_events();
  [[nodiscard]] bool closing_done() const;
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
  std::size_t vnet_header_size_ = 0;
  bool watched_ = false;       // fd_ is registered with loop_
  bool watching_out_ = false;  // ... for EPOLLOUT as well
  EventLoop loop_;
  Stack stack_;
  std::unique_ptr<PcapWriter> pcap_;
  std::unique_ptr<TraceRecorder> trace_;
  std::string trace_file_;
  std::vector<std::byte> rxbuf_;
  std::optional<TxPacket> pending_tx_;  // EAGAIN: written when EPOLLOUT arrives
  std::uint32_t pending_tx_segments_ = 1;
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
