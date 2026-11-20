// utcp-bulk's logic against the fake Transport (DESIGN §9).
#include "utcp-bulk/bulk.hpp"

#include <gtest/gtest.h>

#include <linux/tcp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <cstdint>
#include <expected>
#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "common/fake_transport.hpp"
#include "common/utcp_transport.hpp"
#include "utcp/config.hpp"

namespace utcp::app::bulk {
namespace {

// Routes the events of one transport to two apps; runs until both are done.
class Pair final : public Handler {
public:
  Pair(BulkApp& a, BulkApp& b) : a_(a), b_(b) {}
  void on_accept(ConnId l, ConnId c) override { a_.on_accept(l, c), b_.on_accept(l, c); }
  void on_connected(ConnId c) override { a_.on_connected(c), b_.on_connected(c); }
  void on_readable(ConnId c) override { a_.on_readable(c), b_.on_readable(c); }
  void on_writable(ConnId c) override { a_.on_writable(c), b_.on_writable(c); }
  void on_closed(ConnId c) override { a_.on_closed(c), b_.on_closed(c); }
  void on_error(ConnId c, Error e) override { a_.on_error(c, e), b_.on_error(c, e); }

private:
  BulkApp& a_;
  BulkApp& b_;
};

void run_both(FakeTransport& t, BulkApp& a, BulkApp& b) {
  Pair p(a, b);
  for (int i = 0; i < 10 && !(a.done() && b.done()); ++i) {
    t.run(p);  // each app stops the run when it is done
  }
}

std::string pattern_sha(std::uint64_t seed, std::uint64_t n) {
  std::vector<std::byte> buf(n);
  pattern_fill(seed, 0, buf);
  return sha256_hex(buf);
}

Options listener(std::uint16_t port, bool sender) {
  Options o;
  o.listen = true;
  o.endpoint = Endpoint{Ipv4Addr{}, port};
  o.sender = sender;
  o.chunk = 7000;  // not a divisor of the buffer sizes, so sends are short
  return o;
}

Options connector(std::uint16_t port, bool sender) {
  Options o = listener(port, sender);
  o.listen = false;
  o.endpoint = Endpoint{Ipv4Addr::from_octets(10, 0, 0, 1), port};
  o.chunk = 5000;
  return o;
}

TEST(BulkPattern, AnyRangeEqualsTheWholeStream) {
  std::vector<std::byte> whole(1000);
  pattern_fill(9, 0, whole);
  for (std::size_t off : {0u, 1u, 7u, 8u, 9u, 100u, 993u}) {
    for (std::size_t len : {0u, 1u, 5u, 8u, 17u}) {
      if (off + len > whole.size()) continue;
      std::vector<std::byte> part(len);
      pattern_fill(9, off, part);
      EXPECT_TRUE(std::equal(part.begin(), part.end(), whole.begin() + static_cast<std::ptrdiff_t>(off)))
          << off << "+" << len;
    }
  }
  std::vector<std::byte> other(1000);
  pattern_fill(10, 0, other);
  EXPECT_NE(whole, other);
}

TEST(BulkTransfer, ConnectorSendsListenerReceives) {
  FakeTransport t({.rcv_buf = 16 * 1024});
  Options so = connector(5001, true);
  so.bytes = 1'000'003;
  Options ro = listener(5001, false);
  ro.bytes = 1'000'003;  // checked by the receiver
  BulkApp recv(t, ro, nullptr), send(t, so, nullptr);
  ASSERT_TRUE(recv.start());
  ASSERT_TRUE(send.start());
  run_both(t, recv, send);
  ASSERT_TRUE(send.done() && recv.done());
  EXPECT_TRUE(send.result().ok) << send.result().error;
  EXPECT_TRUE(recv.result().ok) << recv.result().error;
  EXPECT_EQ(send.result().bytes, 1'000'003u);
  EXPECT_EQ(recv.result().bytes, 1'000'003u);
  EXPECT_EQ(send.result().sha256, pattern_sha(1, 1'000'003));
  EXPECT_EQ(recv.result().sha256, send.result().sha256);
  EXPECT_EQ(t.open_count(), 0u);  // both ends and the listener closed
}

TEST(BulkTransfer, ListenerSendsConnectorReceives) {
  FakeTransport t({.rcv_buf = 4096});
  Options so = listener(80, true);
  so.bytes = 100'000;
  so.seed = 77;
  BulkApp send(t, so, nullptr), recv(t, connector(80, false), nullptr);
  ASSERT_TRUE(send.start());
  ASSERT_TRUE(recv.start());
  run_both(t, send, recv);
  EXPECT_TRUE(send.result().ok) << send.result().error;
  EXPECT_TRUE(recv.result().ok) << recv.result().error;
  EXPECT_EQ(recv.result().sha256, pattern_sha(77, 100'000));
}

TEST(BulkTransfer, ReceiverChecksTheExpectedLength) {
  FakeTransport t;
  Options so = connector(5001, true);
  so.bytes = 1000;
  Options ro = listener(5001, false);
  ro.bytes = 999;
  BulkApp recv(t, ro, nullptr), send(t, so, nullptr);
  ASSERT_TRUE(recv.start());
  ASSERT_TRUE(send.start());
  run_both(t, recv, send);
  EXPECT_FALSE(recv.result().ok);
  EXPECT_NE(recv.result().error.find("expected 999"), std::string::npos);
}

TEST(BulkTransfer, RecvPauseWaitsBetweenBlocks) {
  FakeTransport t({.rcv_buf = 8192});
  Options so = connector(5001, true);
  so.bytes = 64 * 1024;
  Options ro = listener(5001, false);
  ro.pause = std::chrono::milliseconds(10);
  ro.pause_every = 4096;
  ro.sample_interval = Duration::zero();
  so.sample_interval = Duration::zero();
  BulkApp recv(t, ro, nullptr), send(t, so, nullptr);
  ASSERT_TRUE(recv.start());
  ASSERT_TRUE(send.start());
  const Time t0 = t.now();
  run_both(t, recv, send);
  EXPECT_TRUE(recv.result().ok) << recv.result().error;
  EXPECT_EQ(recv.result().sha256, send.result().sha256);
  // 16 blocks of 4096 bytes: a pause after each, the last one before the end
  // of stream is read, so at least 16 pauses of 10 ms of virtual time.
  EXPECT_GE(t.now() - t0, std::chrono::milliseconds(160));
}

TEST(BulkTransfer, DurationStopsTheSender) {
  // The receiver reads slowly (a pause after every 1000 bytes), so the queue
  // empties and virtual time moves; the sender stops after 50 ms.
  FakeTransport t({.rcv_buf = 2048});
  Options so = connector(5001, true);
  so.duration = std::chrono::milliseconds(50);
  so.sample_interval = Duration::zero();
  Options ro = listener(5001, false);
  ro.pause = std::chrono::milliseconds(1);
  ro.pause_every = 1000;
  ro.sample_interval = Duration::zero();
  BulkApp recv(t, ro, nullptr), send(t, so, nullptr);
  ASSERT_TRUE(recv.start());
  ASSERT_TRUE(send.start());
  run_both(t, recv, send);
  EXPECT_TRUE(send.result().ok) << send.result().error;
  EXPECT_TRUE(recv.result().ok) << recv.result().error;
  EXPECT_GT(send.result().bytes, 10'000u);
  EXPECT_EQ(recv.result().bytes, send.result().bytes);
  EXPECT_EQ(recv.result().sha256, pattern_sha(1, send.result().bytes));
  EXPECT_GE(send.result().duration, std::chrono::milliseconds(50));
}

TEST(BulkJsonl, SamplesAndSummaryHaveTheFields) {
  const std::string path = testing::TempDir() + "/bulk_test_samples.jsonl";
  {
    auto w = JsonlWriter::open(path);
    ASSERT_TRUE(w) << w.error();
    FakeTransport t({.rcv_buf = 2048});
    Options so = connector(5001, true);
    so.duration = std::chrono::milliseconds(100);
    Options ro = listener(5001, false);
    ro.pause = std::chrono::milliseconds(2);
    ro.pause_every = 1000;
    ro.sample_interval = Duration::zero();
    BulkApp recv(t, ro, nullptr), send(t, so, &*w);
    ASSERT_TRUE(recv.start());
    ASSERT_TRUE(send.start());
    run_both(t, recv, send);
    ASSERT_TRUE(send.result().ok) << send.result().error;
    EXPECT_GE(send.result().samples, 9u);
    w->write(send.summary());
  }
  std::ifstream in(path);
  std::vector<std::string> lines;
  for (std::string l; std::getline(in, l);) {
    lines.push_back(l);
  }
  ASSERT_GE(lines.size(), 11u);
  // The start line first: the connection's establishment on the transport's
  // clock (the fake starts at 0 and connects without delay).
  EXPECT_EQ(lines[0], "{\"t\":0,\"ev\":\"start\",\"role\":\"sender\"}");
  for (std::size_t i = 1; i + 1 < lines.size(); ++i) {
    for (const char* key : {"\"t\":", "\"ev\":\"sample\"", "\"cc_name\":", "\"srtt_us\":", "\"cwnd\":",
                            "\"bytes_acked\":", "\"busy_time_us\":", "\"rwnd_limited_us\":",
                            "\"sndbuf_limited_us\":", "\"notsent_bytes\":", "\"last_ack_recv_us\":",
                            "\"inflight\":"}) {
      EXPECT_NE(lines[i].find(key), std::string::npos) << key << " in " << lines[i];
    }
  }
  for (const char* key : {"\"ev\":\"summary\"", "\"ok\":true", "\"goodput_bps\":", "\"sha256\":",
                          "\"total_retrans\":", "\"busy_us\":", "\"rwnd_limited_us\":",
                          "\"sndbuf_limited_us\":", "\"duration_us\":"}) {
    EXPECT_NE(lines.back().find(key), std::string::npos) << key << " in " << lines.back();
  }
}

TEST(BulkErrors, RefusedConnectionFails) {
  FakeTransport t;
  Options so = connector(9, true);
  so.bytes = 10;
  BulkApp send(t, so, nullptr);
  ASSERT_TRUE(send.start());
  t.run(send);
  ASSERT_TRUE(send.done());
  EXPECT_FALSE(send.result().ok);
  EXPECT_NE(send.result().error.find("connection_refused"), std::string::npos);
  EXPECT_NE(send.summary().str().find("\"ok\":false"), std::string::npos);
}

TEST(BulkErrors, ResetDuringTransferFails) {
  FakeTransport t({.rcv_buf = 1024});
  Options so = connector(5001, true);
  so.bytes = 1'000'000;
  Options ro = listener(5001, false);
  ro.pause = std::chrono::seconds(10);  // stops reading after 2000 bytes
  ro.pause_every = 2000;
  BulkApp recv(t, ro, nullptr), send(t, so, nullptr);
  ASSERT_TRUE(recv.start());
  ASSERT_TRUE(send.start());
  // Reset the sender's connection (id 2: the listener is 1, the server end 3)
  // once the transfer is under way.
  t.add_oneshot(std::chrono::milliseconds(5), [&] { t.inject_error(2, Error::connection_reset); });
  run_both(t, recv, send);
  EXPECT_TRUE(send.done());
  EXPECT_FALSE(send.result().ok);
  EXPECT_NE(send.result().error.find("connection_reset"), std::string::npos) << send.result().error;
}

// A receiver that sends its FIN after `limit` bytes and keeps reading (a
// peer that ends the transfer early); forwards the sender's events.
class EarlyCloser final : public Handler {
public:
  EarlyCloser(Transport& t, BulkApp& sender, std::uint64_t limit) : t_(t), s_(sender), limit_(limit) {}
  void listen(std::uint16_t port) { l_ = *t_.listen(Endpoint{Ipv4Addr{}, port}, 1, {}); }
  void on_accept(ConnId l, ConnId c) override {
    if (l != l_) return s_.on_accept(l, c);
    c_ = c;
    read();
  }
  void on_connected(ConnId c) override { s_.on_connected(c); }
  void on_readable(ConnId c) override { c == c_ ? read() : s_.on_readable(c); }
  void on_writable(ConnId c) override { s_.on_writable(c); }
  void on_closed(ConnId c) override { c == c_ ? void() : s_.on_closed(c); }
  void on_error(ConnId c, Error e) override { c == c_ ? void() : s_.on_error(c, e); }
  std::uint64_t got = 0;

private:
  void read() {
    std::vector<std::byte> b(3000);
    while (true) {
      auto r = t_.recv(c_, b);
      if (!r || *r == 0) return;
      got += *r;
      if (got >= limit_ && !shut_) {
        shut_ = true;
        t_.shutdown_write(c_);
      }
    }
  }
  Transport& t_;
  BulkApp& s_;
  std::uint64_t limit_;
  ConnId l_ = no_conn, c_ = no_conn;
  bool shut_ = false;
};

TEST(BulkErrors, ReceiverFinBeforeTheEndFailsTheSender) {
  for (const bool by_duration : {false, true}) {
    FakeTransport t({.rcv_buf = 4096});
    Options so = connector(5001, true);
    if (by_duration) {
      so.duration = std::chrono::seconds(10);
    } else {
      so.bytes = 1'000'000;
    }
    so.sample_interval = Duration::zero();
    BulkApp send(t, so, nullptr);
    EarlyCloser recv(t, send, 20'000);
    recv.listen(5001);
    ASSERT_TRUE(send.start());
    for (int i = 0; i < 10 && !send.done(); ++i) {
      t.run(recv);
    }
    ASSERT_TRUE(send.done()) << by_duration;
    EXPECT_FALSE(send.result().ok) << by_duration;
    EXPECT_NE(send.result().error.find("the receiver closed after"), std::string::npos)
        << send.result().error;
    EXPECT_LT(send.result().bytes, 1'000'000u);
    EXPECT_GE(recv.got, 20'000u);
    EXPECT_NE(send.summary().str().find("\"ok\":false"), std::string::npos);
  }
}

TEST(BulkOptions, Parse) {
  CliParser cli("utcp-bulk", "");
  add_options(cli);
  const auto parse = [&](std::vector<std::string_view> words) -> std::expected<Options, std::string> {
    auto a = cli.parse(words);
    if (!a) return std::unexpected(a.error());
    return parse_options(*a);
  };
  auto o = parse({"--connect", "10.1.2.3:99", "--send", "--bytes", "1Gi", "--cc", "cubic",
                  "--snd-buf", "64Ki", "--sample-ms", "5"});
  ASSERT_TRUE(o) << o.error();
  EXPECT_FALSE(o->listen);
  EXPECT_TRUE(o->sender);
  EXPECT_EQ(*o->bytes, std::uint64_t{1} << 30);
  EXPECT_EQ(o->sock.cc, CcAlgo::cubic);
  EXPECT_EQ(o->sock.snd_buf, 65536u);
  EXPECT_FALSE(o->sock.rcv_buf);
  EXPECT_EQ(o->sample_interval, std::chrono::milliseconds(5));
  o = parse({"--listen", "5001", "--recv-pause", "200:1048576"});
  ASSERT_TRUE(o) << o.error();
  EXPECT_EQ(*o->pause, std::chrono::milliseconds(200));
  EXPECT_EQ(o->pause_every, 1048576u);
  EXPECT_EQ(o->endpoint.port, 5001);
  EXPECT_FALSE(parse({"--listen", "1", "--connect", "1.2.3.4:5"}));
  EXPECT_FALSE(parse({"--connect", "1.2.3.4:5", "--send"}));  // no amount
  EXPECT_FALSE(parse({"--connect", "1.2.3.4:5", "--send", "--bytes", "1", "--duration", "1"}));
  EXPECT_FALSE(parse({"--listen", "1", "--recv-pause", "200"}));
  EXPECT_FALSE(parse({"--listen", "1", "--cc", "vegas"}));
}

// main_ writes the clock line first (DESIGN §14: ping -D and tcpdump times
// convert to the samples' clock with it), also when the connection fails.
TEST(BulkMain, JsonlStartsWithTheClockPair) {
  const std::string path = testing::TempDir() + "/bulk_test_clock.jsonl";
  const TransportFactory make = [](const BackendSelection&)
      -> std::expected<std::unique_ptr<Transport>, std::string> {
    return std::make_unique<FakeTransport>();
  };
  timespec before{};
  clock_gettime(CLOCK_REALTIME, &before);
  const char* const argv[] = {"utcp-bulk", "--connect", "10.0.0.1:9", "--send", "--bytes", "10",
                              "--jsonl", path.c_str()};
  EXPECT_EQ(main_(static_cast<int>(std::size(argv)), argv, make), 1);
  std::ifstream in(path);
  std::string first;
  ASSERT_TRUE(std::getline(in, first));
  ASSERT_TRUE(first.starts_with("{\"ev\":\"clock\",\"monotonic_ns\":")) << first;
  const auto rt_at = first.find("\"realtime_ns\":");
  ASSERT_NE(rt_at, std::string::npos) << first;
  const std::int64_t rt = std::stoll(first.substr(rt_at + 14));
  const std::int64_t before_ns = std::int64_t{before.tv_sec} * 1'000'000'000 + before.tv_nsec;
  EXPECT_GE(rt, before_ns);
  EXPECT_LT(rt, before_ns + 60'000'000'000);
  const std::int64_t mono = std::stoll(first.substr(first.find("\"monotonic_ns\":") + 15));
  EXPECT_GT(mono, 0);
}

// --- The utcp backend's --set, --trace and --stats (DESIGN §14.6).

std::expected<BackendSelection, std::string> parse_backend(std::vector<std::string_view> words) {
  CliParser cli("utcp-bulk", "");
  add_options(cli);
  add_backend_options(cli);
  auto a = cli.parse(words);
  if (!a) return std::unexpected(a.error());
  return parse_backend_options(*a);
}

std::vector<std::string> lines_of(const std::string& path) {
  std::ifstream in(path);
  std::vector<std::string> out;
  for (std::string l; std::getline(in, l);) {
    out.push_back(l);
  }
  return out;
}

TEST(BulkBackendOptions, SetAppliesFieldsInOrder) {
  auto b = parse_backend({"--connect", "1.2.3.4:5", "--set", "snd_buf_max=64Mi", "--set=rcv_buf_max=32Mi",
                          "--set", "test_fixed_pacing_rate=50Mbit", "--set", "initial_cwnd=4",
                          "--set", "initial_cwnd=10"});
  ASSERT_TRUE(b) << b.error();
  const TcpConfig& c = b->utcp.stack.tcp;
  EXPECT_EQ(c.snd_buf_max, 64u << 20);
  EXPECT_EQ(c.rcv_buf_max, 32u << 20);
  ASSERT_TRUE(c.test_fixed_pacing_rate.has_value());
  EXPECT_EQ(*c.test_fixed_pacing_rate, 6'250'000u);  // 50 Mbit/s of payload in bytes/s
  EXPECT_EQ(c.initial_cwnd, 10u);                    // the last --set of a field wins
  ASSERT_EQ(b->sets.size(), 5u);
  EXPECT_EQ(b->sets[1], (std::pair<std::string, std::string>{"rcv_buf_max", "32Mi"}));
  // Fields not set keep the profile's values.
  TcpConfig rfc = tcp_config(ProfileId::rfc);
  b = parse_backend({"--connect", "1.2.3.4:5", "--profile", "rfc", "--set", "rto_min=200ms"});
  ASSERT_TRUE(b) << b.error();
  rfc.rto_min = std::chrono::milliseconds(200);
  EXPECT_EQ(b->utcp.stack.tcp, rfc);

  EXPECT_FALSE(parse_backend({"--connect", "1.2.3.4:5", "--set", "no_such_field=1"}));
  EXPECT_FALSE(parse_backend({"--connect", "1.2.3.4:5", "--set", "snd_buf_max"}));
  EXPECT_FALSE(parse_backend({"--connect", "1.2.3.4:5", "--set", "=1"}));
  EXPECT_FALSE(parse_backend({"--connect", "1.2.3.4:5", "--set", "test_fixed_pacing_rate=50Mbitx"}));
  // 3 bit/s is not a whole number of bytes.
  EXPECT_FALSE(parse_backend({"--connect", "1.2.3.4:5", "--set", "test_fixed_pacing_rate=3bit"}));
  // RFC 8985 §9.2: RACK-TLP with RFC 6675 recovery is refused (check_tcp_config).
  auto bad = parse_backend({"--connect", "1.2.3.4:5", "--set", "rack_tlp=true", "--set",
                            "recovery_reduction=rfc6675"});
  ASSERT_FALSE(bad);
  EXPECT_NE(bad.error().find("--set"), std::string::npos) << bad.error();
  auto kernel = parse_backend({"--connect", "1.2.3.4:5", "--backend", "kernel", "--set", "initial_cwnd=10"});
  ASSERT_FALSE(kernel);
  EXPECT_NE(kernel.error().find("utcp backend"), std::string::npos) << kernel.error();
}

TEST(BulkBackendOptions, TunQueuesAreOptIn) {
  auto b = parse_backend({"--connect", "1.2.3.4:5"});
  ASSERT_TRUE(b) << b.error();
  EXPECT_FALSE(b->utcp.tun_queues);
  for (const auto count : {1u, 2u, 64u}) {
    const auto text = std::to_string(count);
    b = parse_backend({"--connect", "1.2.3.4:5", "--tun-queues", text});
    ASSERT_TRUE(b) << b.error();
    EXPECT_EQ(b->utcp.tun_queues, count);
  }
  for (const char* value : {"0", "65", "invalid"}) {
    EXPECT_FALSE(parse_backend({"--connect", "1.2.3.4:5", "--tun-queues", value}));
  }
  EXPECT_FALSE(parse_backend({"--connect", "1.2.3.4:5", "--backend", "kernel",
                              "--tun-queues", "1"}));
}

TEST(BulkBackendOptions, TraceKinds) {
  auto b = parse_backend({"--connect", "1.2.3.4:5"});
  ASSERT_TRUE(b) << b.error();
  EXPECT_TRUE(b->trace_file.empty());
  EXPECT_EQ(b->utcp.stack.trace_mask, 0u);
  b = parse_backend({"--connect", "1.2.3.4:5", "--trace", "/x/trace.jsonl"});
  ASSERT_TRUE(b) << b.error();
  EXPECT_EQ(b->trace_file, "/x/trace.jsonl");
  // M2 design §5.6: cwnd, recovery, rto and the retransmissions; no timer events.
  EXPECT_EQ(b->utcp.stack.trace_mask, trace_bit(TraceKind::cwnd) | trace_bit(TraceKind::recovery) |
                                          trace_bit(TraceKind::rto) | trace_bit(TraceKind::tx));
  EXPECT_TRUE(b->trace_rexmit_only);
  b = parse_backend({"--connect", "1.2.3.4:5", "--trace", "t", "--trace-kinds", "tx,rexmit,state"});
  ASSERT_TRUE(b) << b.error();
  EXPECT_EQ(b->utcp.stack.trace_mask, trace_bit(TraceKind::tx) | trace_bit(TraceKind::state));
  EXPECT_FALSE(b->trace_rexmit_only);  // "tx" keeps every transmission
  EXPECT_FALSE(parse_backend({"--connect", "1.2.3.4:5", "--trace", "t", "--trace-kinds", "cwnd,pace"}));
  EXPECT_FALSE(parse_backend({"--connect", "1.2.3.4:5", "--trace", "t", "--trace-kinds", ""}));
  EXPECT_FALSE(parse_backend({"--connect", "1.2.3.4:5", "--trace-kinds", "cwnd"}));
  EXPECT_FALSE(parse_backend({"--connect", "1.2.3.4:5", "--backend", "kernel", "--trace", "t"}));
}

TEST(BulkTrace, RecorderKeepsRetransmissionsAndWritesOnlyOnRequest) {
  TraceRecorder r(true);
  TraceEvent e;
  e.t = Time{1'000'000};
  e.kind = TraceKind::tx;
  e.tx = TxKind::data;
  r.on_event(e);  // not kept: a first transmission
  e.tx = TxKind::rto_rexmit;
  e.seq = 77;
  r.on_event(e);
  e.kind = TraceKind::cwnd;
  e.cwnd = 12;
  r.on_event(e);
  EXPECT_EQ(r.events(), 2u);
  EXPECT_EQ(r.blocks(), 1u);
  const std::string path = testing::TempDir() + "/bulk_test_recorder.jsonl";
  std::filesystem::remove(path);
  ASSERT_TRUE(r.write(path));
  const auto lines = lines_of(path);
  ASSERT_EQ(lines.size(), 2u);
  EXPECT_TRUE(lines[0].starts_with("{\"t\":1000000,")) << lines[0];
  EXPECT_NE(lines[0].find("\"ev\":\"tx\""), std::string::npos) << lines[0];
  EXPECT_NE(lines[0].find("\"tx\":\"rto_rexmit\""), std::string::npos) << lines[0];
  EXPECT_NE(lines[0].find("\"seq\":77"), std::string::npos) << lines[0];
  EXPECT_NE(lines[1].find("\"ev\":\"cwnd\""), std::string::npos) << lines[1];
  EXPECT_NE(lines[1].find("\"cwnd\":12"), std::string::npos) << lines[1];
  for (const TxKind k : {TxKind::fast_rexmit, TxKind::rexmit, TxKind::rto_rexmit, TxKind::pmtu_rexmit,
                         TxKind::tlp}) {
    EXPECT_TRUE(TraceRecorder::is_retransmission(k)) << to_string(k);
  }
  for (const TxKind k : {TxKind::syn, TxKind::data, TxKind::fin, TxKind::ack, TxKind::zwp}) {
    EXPECT_FALSE(TraceRecorder::is_retransmission(k)) << to_string(k);
  }
  EXPECT_GE(TraceRecorder::block_bytes, std::size_t{64} << 20);  // §5.6: at least 64 MiB
}

// UtcpTransport over a socketpair: the trace stays in memory while the
// program runs and is written, with the --stats line, when the transport
// is destroyed.
TEST(BulkTrace, TransportWritesTraceAndStatsAtTheEnd) {
  int fds[2];
  ASSERT_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds), 0);
  const std::string trace = testing::TempDir() + "/bulk_test_trace.jsonl";
  const std::string stats = testing::TempDir() + "/bulk_test_stats.json";
  std::filesystem::remove(trace);
  std::filesystem::remove(stats);
  UtcpTransportOptions o;
  o.stack.local_addr = Ipv4Addr::from_octets(198, 18, 0, 2);
  o.stack.tcp = tcp_config(ProfileId::linux_compat);
  o.stack.trace_mask = trace_bit(TraceKind::tx) | trace_bit(TraceKind::state);
  o.seed_from_getrandom = false;
  o.stats_file = stats;
  {
    auto t = UtcpTransport::attach(fds[0], o);
    ASSERT_TRUE(t) << t.error();
    (*t)->enable_trace(trace, false);
    ASSERT_TRUE((*t)->connect(Endpoint{Ipv4Addr::from_octets(198, 19, 12, 5), 9}, {}));
    std::array<std::byte, 2048> syn{};
    EXPECT_GT(::read(fds[1], syn.data(), syn.size()), 40);  // the SYN went out
    ASSERT_NE((*t)->trace(), nullptr);
    EXPECT_GE((*t)->trace()->events(), 1u);  // the SYN (and the state change)
    EXPECT_FALSE(std::filesystem::exists(trace));  // nothing written during the run
    const std::string sj = (*t)->stats_json();
    for (const char* key : {"\"loop_iterations\":", "\"loop_pending_calls\":", "\"loop_lateness_count\":",
                            "\"loop_lateness_max_ns\":", "\"dev_tx_errors\":0", "\"dev_rx_errors\":0",
                            "\"dev_device_failed\":false", "\"dev_tx_batch_max\":1", "\"trace_events\":",
                            "\"trace_blocks\":1"}) {
      EXPECT_NE(sj.find(key), std::string::npos) << key << " in " << sj;
    }
  }
  ::close(fds[1]);
  const auto tl = lines_of(trace);
  ASSERT_GE(tl.size(), 2u);
  bool syn_seen = false;
  for (const auto& l : tl) {
    syn_seen = syn_seen || (l.find("\"ev\":\"tx\"") != std::string::npos &&
                            l.find("\"tx\":\"syn\"") != std::string::npos);
  }
  EXPECT_TRUE(syn_seen) << tl[0];
  const auto sl = lines_of(stats);
  ASSERT_EQ(sl.size(), 1u);
  EXPECT_TRUE(sl[0].starts_with("{\"ev\":\"stack_stats\",")) << sl[0];
  EXPECT_NE(sl[0].find("\"trace_events\":" + std::to_string(tl.size())), std::string::npos) << sl[0];
}

// The analysis reads the same keys from both senders' samples (M2 design
// §5.9): both are TcpInfo, written by add_fields.
TEST(BulkJsonl, StackAndKernelSamplesHaveTheSameKeys) {
  const auto keys = [](const TcpInfo& info) {
    JsonLine line;
    add_fields(line, info);
    std::set<std::string> out;
    const std::string s = line.str();
    for (std::size_t i = s.find('"'); i != std::string::npos; i = s.find(",\"", i)) {
      const std::size_t start = s[i] == '"' ? i + 1 : i + 2;
      const std::size_t end = s.find('"', start);
      out.insert(s.substr(start, end - start));
      i = end;
    }
    return out;
  };
  const ::tcp_info ti{};
  const auto kernel = keys(sample_from_tcp_info(ti, "cubic"));
  TcpInfo stack;
  stack.total_retrans = 3;
  EXPECT_EQ(keys(stack), kernel);
  for (const char* k : {"sndbuf_limited_us", "rwnd_limited_us", "total_retrans", "data_segs_out",
                        "dsack_dups", "bytes_received", "cwnd", "pacing_rate", "delivery_rate"}) {
    EXPECT_TRUE(kernel.contains(k)) << k;
  }
}

// With the utcp backend, the line after the clock pair is the effective
// configuration with the --set options.
TEST(BulkMain, ConfigLineFollowsTheClockLine) {
  const std::string path = testing::TempDir() + "/bulk_test_config.jsonl";
  const TransportFactory make = [](const BackendSelection&)
      -> std::expected<std::unique_ptr<Transport>, std::string> {
    return std::make_unique<FakeTransport>();
  };
  const char* const argv[] = {"utcp-bulk", "--connect", "10.0.0.1:9", "--send", "--bytes", "10",
                              "--set", "snd_buf_max=64Mi", "--set", "gso_max_size=65215",
                              "--jsonl", path.c_str()};
  EXPECT_EQ(main_(static_cast<int>(std::size(argv)), argv, make), 1);
  const auto lines = lines_of(path);
  ASSERT_GE(lines.size(), 2u);
  EXPECT_TRUE(lines[0].starts_with("{\"ev\":\"clock\",")) << lines[0];
  EXPECT_TRUE(lines[1].starts_with("{\"ev\":\"config\",\"set\":\"snd_buf_max=64Mi gso_max_size=65215\","))
      << lines[1];
  EXPECT_NE(lines[1].find("\"snd_buf_max\":\"67108864\""), std::string::npos) << lines[1];
  EXPECT_NE(lines[1].find("\"gso_max_size\":\"65215\""), std::string::npos) << lines[1];
  EXPECT_NE(lines[1].find("\"cc\":\"newreno\""), std::string::npos) << lines[1];
  // The kernel backend has no stack configuration.
  const char* const kargv[] = {"utcp-bulk", "--backend", "kernel", "--connect", "10.0.0.1:9", "--send",
                               "--bytes", "10", "--jsonl", path.c_str()};
  EXPECT_EQ(main_(static_cast<int>(std::size(kargv)), kargv, make), 1);
  const auto kl = lines_of(path);
  ASSERT_GE(kl.size(), 2u);
  EXPECT_FALSE(kl[1].starts_with("{\"ev\":\"config\"")) << kl[1];
}

}  // namespace

// main_ calls finish_closing(finish_closing_max) once, after run() returned
// (interop case E-chunked: without the call the server's FIN that follows
// the program's close is never ACKed). Nothing listens on the fake, so the
// connection is refused and the program fails, but the exit path is the same.
TEST(BulkMain, MainFinishesClosingAfterRun) {
  std::vector<std::pair<Duration, std::uint64_t>> calls;
  const TransportFactory make = [&](const BackendSelection&)
      -> std::expected<std::unique_ptr<Transport>, std::string> {
    FakeTransportOptions o;
    o.on_finish_closing = [&](Duration max, std::uint64_t runs_returned) {
      calls.emplace_back(max, runs_returned);
    };
    return std::make_unique<FakeTransport>(o);
  };
  const char* const argv[] = {"utcp-bulk", "--connect", "10.0.0.1:9", "--send", "--bytes", "10", "--jsonl", "/dev/null"};
  EXPECT_EQ(main_(static_cast<int>(std::size(argv)), argv, make), 1);
  ASSERT_EQ(calls.size(), 1u);
  EXPECT_EQ(calls[0].first, finish_closing_max);
  EXPECT_EQ(calls[0].second, 1u);
}

}  // namespace utcp::app::bulk
