// m1-tcp-core acceptance test 7: determinism (DESIGN §13.1). The same
// harness run twice gives the same digest over every datagram (time, sender,
// fate, bytes), every trace event and the final TcpInfo of each socket. The
// digest is printed as "TcpDeterminism digest <scenario> <hex>";
// ci/check-digests.sh compares those lines between the g++ and clang builds.
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "common/jsonl.hpp"
#include "common/sha256.hpp"
#include "tcp_test_util.hpp"
#include "utcp/trace.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Endpoint;
using utcp::Handle;
using utcp::ProfileId;
using utcp::StackConfig;
namespace t = utcp::test;
using t::Side;
using namespace utcp::test::tcpt;

class HashSink : public utcp::TraceSink {
public:
  HashSink(utcp::app::Sha256& h, char node) : h_(h), node_(node) {}
  void on_event(const utcp::TraceEvent& e) override {
    utcp::app::JsonLine line;
    line.add("node", std::string(1, node_));
    utcp::app::add_fields(line, e);
    h_.update(line.str());
    h_.update("\n");
    ++events;
  }
  std::size_t events = 0;

private:
  utcp::app::Sha256& h_;
  char node_;
};

struct Result {
  std::string digest;
  std::size_t datagrams = 0, events = 0;
  bool data_ok = false;
};

// Three connections moving data both ways at once over links with delays,
// deterministic losses and reordering, then closing; run to quiescence.
Result run(ProfileId profile) {
  utcp::app::Sha256 hash(utcp::app::Sha256::Impl::portable);
  HashSink sa(hash, 'a'), sb(hash, 'b');
  StackConfig ca = config(Side::a, profile), cb = config(Side::b, profile);
  ca.trace_mask = cb.trace_mask = utcp::trace_mask_all;
  ca.tcp.rcv_buf_init = cb.tcp.rcv_buf_init = 64 * 1024;  // window-limited at times
  t::TcpHarness h(ca, cb);
  h.a().set_trace_sink(&sa);
  h.b().set_trace_sink(&sb);
  h.set_delay(Side::a, 7ms);
  h.set_delay(Side::b, 3ms);
  std::size_t from_a = 0, from_b = 0;
  h.set_hook([&](Side from, t::Bytes&) {
    const std::size_t n = from == Side::a ? ++from_a : ++from_b;
    if (n % 23 == 0) {
      return t::Verdict::drop;
    }
    if (n % 31 == 0) {
      return t::Verdict::hold;
    }
    return t::Verdict::deliver;
  });
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 16, {});
  std::vector<Handle> cl, sv;
  for (int i = 0; i < 3; ++i) {
    const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
    if (c) {
      cl.push_back(*c);
    }
  }
  h.run_for(3s);
  while (const auto s = h.b().tcp_accept(*l)) {
    sv.push_back(*s);
  }
  Result r;
  if (cl.size() != 3 || sv.size() != 3) {
    return r;
  }
  struct Flow {
    utcp::Stack* tx;
    Handle txh;
    utcp::Stack* rx;
    Handle rxh;
    t::Bytes data;
    std::size_t sent = 0;
    t::Bytes got;
    bool shut = false;
  };
  std::vector<Flow> flows;
  for (std::size_t i = 0; i < 3; ++i) {
    flows.push_back(Flow{&h.a(), cl[i], &h.b(), sv[i],
                         t::pattern(200'000 + 1000 * i, static_cast<std::uint8_t>(i)), 0, {},
                         false});
    flows.push_back(Flow{&h.b(), sv[i], &h.a(), cl[i],
                         t::pattern(100'000 + 333 * i, static_cast<std::uint8_t>(i + 50)), 0, {},
                         false});
  }
  for (int round = 0; round < 6000; ++round) {
    bool done = true;
    for (Flow& f : flows) {
      if (f.sent < f.data.size()) {
        const auto n = f.tx->tcp_send(f.txh, std::span(f.data).subspan(f.sent));
        if (n) {
          f.sent += *n;
        }
      } else if (!f.shut) {
        f.shut = f.tx->tcp_shutdown(f.txh, utcp::Shutdown::write).has_value();
      }
      const t::Bytes part = drain(*f.rx, f.rxh);
      f.got.insert(f.got.end(), part.begin(), part.end());
      done = done && f.got.size() == f.data.size() && f.shut;
    }
    if (h.held_count() > 0 && round % 5 == 0) {
      h.release_held(0);  // the held datagram arrives behind later ones
    }
    if (done) {
      break;
    }
    h.run_for(5ms);
  }
  h.release_all_held();
  h.run_for(1s);
  r.data_ok = true;
  for (Flow& f : flows) {
    r.data_ok = r.data_ok && f.got == f.data;
  }
  for (std::size_t i = 0; i < 3; ++i) {
    for (const auto& [s, hd] : {std::pair{&h.a(), cl[i]}, std::pair{&h.b(), sv[i]}}) {
      if (const auto info = s->tcp_info(hd)) {
        utcp::app::JsonLine line;
        utcp::app::add_fields(line, *info);
        hash.update(line.str());
      }
      (void)s->tcp_close(hd);
    }
  }
  h.run_for(300s);
  for (const t::Sent& s : h.log()) {
    hash.update(std::to_string(s.t.ns) + (s.from == Side::a ? " a " : " b ") +
                std::to_string(static_cast<int>(s.verdict)) + "\n");
    hash.update(std::span<const std::byte>(s.bytes));
  }
  for (utcp::Stack* s : {&h.a(), &h.b()}) {
    const utcp::StackUsage u = s->debug_usage();
    hash.update(std::to_string(u.tcp_slots) + " " + std::to_string(u.time_wait_entries) + "\n");
  }
  r.datagrams = h.log().size();
  r.events = sa.events + sb.events;
  h.a().set_trace_sink(nullptr);
  h.b().set_trace_sink(nullptr);
  const auto d = hash.finish();
  r.digest = utcp::app::to_hex(d);
  return r;
}

TEST(TcpDeterminism, SameRunTwiceGivesTheSameDigest) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    const std::string name = profile == ProfileId::rfc ? "rfc" : "linux_compat";
    SCOPED_TRACE(name);
    const Result r1 = run(profile);
    const Result r2 = run(profile);
    EXPECT_TRUE(r1.data_ok);
    EXPECT_GT(r1.datagrams, 1000u);
    EXPECT_GT(r1.events, r1.datagrams);
    EXPECT_EQ(r1.datagrams, r2.datagrams);
    EXPECT_EQ(r1.events, r2.events);
    EXPECT_EQ(r1.digest, r2.digest);
    // Read by ci/check-digests.sh (g++ against clang).
    std::cout << "TcpDeterminism digest " << name << " " << r1.digest << "\n";
  }
}

}  // namespace
