// utcp-bulk (DESIGN §9): one TCP connection, one side sends a seeded byte
// pattern, the other reads it; both hash the stream with SHA-256 and print
// the digest. Either end may listen or connect, and either may send.
//
// The sender sends --bytes N or for --duration S, then shuts down its write
// side and waits for the receiver's FIN. The receiver reads to the end of
// stream, then sends its FIN and closes. The duration is measured from the
// connection's establishment to the end of stream (receiver) or the
// receiver's FIN (sender). A receiver FIN that arrives before the sender has
// sent everything is an error (ok = false, exit status 1).
//
// Every --sample-ms a JSONL line has the connection's statistics (every
// TcpInfo field, §10.1) and inflight = unacked - sacked - lost + retrans. The
// summary line has bytes, duration, goodput, SHA-256, retransmissions, the
// three limited times and the event loop's lateness percentiles.
//
// Lateness is what the EventLoop records (§8.3): now - deadline when it runs
// the timers, after the I/O callbacks of the same iteration. Those callbacks
// include this program's send and receive loops, so the figures contain its
// own work: a loop runs for at most one slice (100 us) plus one --chunk call
// before it yields to the event loop, and a loop that has yielded does not
// run again from an I/O callback until its continuation timer fires.
//
// --recv-pause MS:BYTES stops reading for MS after every BYTES read, so the
// sender sees a zero window.
//
// The JSONL file starts with one clock line, {"ev":"clock","monotonic_ns":M,
// "realtime_ns":R}: R is CLOCK_REALTIME at the moment CLOCK_MONOTONIC read M
// (the mean of two realtime reads around it), so CLOCK_REALTIME times from
// other tools (ping -D, tcpdump) convert to the samples' clock: t = rt - R + M
// (DESIGN §14). When the connection is established (accepted or connected)
// a start line {"t":...,"ev":"start","role":...} follows; its t is the start
// of the duration and of the testbed's measurement window.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "common/cli.hpp"
#include "common/jsonl.hpp"
#include "common/kernel_transport.hpp"
#include "common/sha256.hpp"
#include "common/transport.hpp"

namespace utcp::app::bulk {

// The byte at stream offset o is byte (o % 8) (little-endian) of
// splitmix64(seed + (o / 8) * golden), so any range can be produced on its own.
void pattern_fill(std::uint64_t seed, std::uint64_t offset, std::span<std::byte> out) noexcept;

struct Options {
  bool listen = false;
  Endpoint endpoint{};  // listen: local address and port; connect: remote
  bool sender = false;
  std::optional<std::uint64_t> bytes;  // sender: amount; receiver: expected amount (checked)
  std::optional<Duration> duration;    // sender only
  TcpSocketOptions sock{};
  std::optional<Duration> pause;      // --recv-pause MS
  std::uint64_t pause_every = 0;      // --recv-pause :BYTES
  Duration sample_interval = std::chrono::milliseconds(10);  // 0: no samples
  std::uint64_t seed = 1;             // pattern seed
  std::size_t chunk = 256 * 1024;     // bytes per send/recv call
  std::string backend = "utcp";       // for the summary
};

// Declares the program's options (without the backend options).
void add_options(CliParser& p);
[[nodiscard]] std::expected<Options, std::string> parse_options(const CliArgs& a);

struct Result {
  bool ok = false;
  std::string error;
  std::uint64_t bytes = 0;
  Duration duration{};
  std::string sha256;
  ConnSample last{};  // the last sample of the connection
  std::uint64_t samples = 0;
};

class BulkApp final : public Handler {
public:
  // `jsonl` may be null (no samples written).
  BulkApp(Transport& t, const Options& o, JsonlWriter* jsonl);

  // Listens or connects. Then run the transport; it is stopped when done.
  [[nodiscard]] std::expected<void, std::string> start();

  void on_accept(ConnId listener, ConnId conn) override;
  void on_connected(ConnId conn) override;
  void on_readable(ConnId id) override;
  void on_writable(ConnId id) override;
  void on_closed(ConnId id) override;
  void on_error(ConnId id, Error e) override;

  [[nodiscard]] bool done() const { return done_; }
  [[nodiscard]] const Result& result() const { return result_; }
  // The summary line (also written to the JSONL file at the end).
  [[nodiscard]] JsonLine summary() const;
  // Ends the run early (a signal): summary with ok = false.
  void abort(const std::string& why);

private:
  void begin(ConnId conn);
  void pump();
  void drain();
  bool yield(bool sending);
  void take_sample();
  void finish();
  void fail(const std::string& why);
  [[nodiscard]] const char* role() const { return o_.sender ? "sender" : "receiver"; }

  Transport& t_;
  Options o_;
  JsonlWriter* jsonl_;
  ConnId listener_ = no_conn;
  ConnId conn_ = no_conn;
  Time start_{};
  Sha256 hash_;
  std::vector<std::byte> buf_;
  std::size_t buf_off_ = 0, buf_len_ = 0;  // sender: unsent part of buf_
  std::uint64_t offset_ = 0;               // bytes sent or received
  bool sending_done_ = false;              // FIN queued (sender)
  bool stop_sending_ = false;              // --duration elapsed
  bool paused_ = false;
  // Longest run of a send or receive loop before it yields (see the top).
  static constexpr Duration slice = std::chrono::microseconds(100);
  Time slice_start_{};
  bool pump_scheduled_ = false, drain_scheduled_ = false;  // a continuation timer is armed
  std::uint64_t since_pause_ = 0;
  TimerToken sample_timer_ = 0;
  bool sample_timer_on_ = false;
  bool done_ = false;
  Result result_;
};

// The clock line described at the top, from the system clocks.
[[nodiscard]] JsonLine clock_line();

// The whole program: options, transport, run, finish_closing, summary.
// Returns the exit status (0 = success). `make` creates the transport (tests
// pass a fake).
int main_(int argc, const char* const* argv,
          const TransportFactory& make = make_transport);

}  // namespace utcp::app::bulk
