#include "support/tcp_harness.hpp"

#include <algorithm>
#include <utility>

#include "utcp/check.hpp"

namespace utcp::test {

namespace {

// Steps at one instant before the harness gives up (two stacks answering
// each other forever without the clock moving).
constexpr std::size_t max_steps_per_instant = 1'000'000;

}  // namespace

StackConfig TcpHarness::default_config(Side s) {
  StackConfig c;
  c.local_addr = s == Side::a ? Ipv4Addr::from_octets(10, 0, 0, 1) : Ipv4Addr::from_octets(10, 0, 0, 2);
  c.seed = Seed::from_u64(s == Side::a ? 1 : 2);
  c.assert_time_monotonic = true;
  return c;
}

TcpHarness::TcpHarness() : TcpHarness(default_config(Side::a), default_config(Side::b)) {}

TcpHarness::TcpHarness(const StackConfig& a, const StackConfig& b, Time start)
    : a_(a), b_(b), now_(start) {
  a_.advance(now_);
  b_.advance(now_);
}

void TcpHarness::sync_clock() noexcept { now_ = std::max({now_, a_.now(), b_.now()}); }

void TcpHarness::send(Side from, Bytes bytes) {
  InFlight f{now_ + delay_[index(from)], next_seq_++, other(from), std::move(bytes)};
  const auto pos = std::upper_bound(flight_.begin(), flight_.end(), f, [](const InFlight& x,
                                                                         const InFlight& y) {
    return x.at != y.at ? x.at < y.at : x.seq < y.seq;
  });
  flight_.insert(pos, std::move(f));
}

std::size_t TcpHarness::settle() {
  sync_clock();
  std::size_t delivered = 0;
  for (std::size_t steps = 0;; ++steps) {
    UTCP_CHECK(steps < max_steps_per_instant);
    bool moved = false;
    for (const Side s : {Side::a, Side::b}) {
      while (auto p = stack(s).pop_transmit()) {
        const auto view = p->buf.bytes();
        Bytes bytes(view.begin(), view.end());
        p.reset();  // the buffer goes back to the stack's pool
        // The log keeps the bytes as the stack sent them; the hook may edit
        // its copy.
        const std::size_t entry = log_.size();
        log_.push_back(Sent{now_, s, bytes, Verdict::deliver});
        const Verdict v = hook_ ? hook_(s, bytes) : Verdict::deliver;
        log_[entry].verdict = v;
        switch (v) {
          case Verdict::deliver:
            send(s, std::move(bytes));
            break;
          case Verdict::drop:
            ++dropped_;
            break;
          case Verdict::hold:
            held_.push_back(Held{s, std::move(bytes)});
            break;
        }
        moved = true;
      }
    }
    while (!flight_.empty() && flight_.front().at <= now_) {
      InFlight f = std::move(flight_.front());
      flight_.erase(flight_.begin());
      stack(f.to).receive(now_, f.bytes);
      ++delivered;
      ++delivered_;
      moved = true;
    }
    if (!moved) {
      return delivered;
    }
  }
}

Time TcpHarness::next_event() const {
  Time t = std::min(a_.next_deadline(), b_.next_deadline());
  if (!flight_.empty()) {
    t = std::min(t, flight_.front().at);
  }
  return t;
}

void TcpHarness::run_until(Time end) {
  settle();
  Time instant = now_;
  std::size_t steps = 0;
  for (;;) {
    const Time next = next_event();
    if (next > end) {
      break;
    }
    now_ = std::max(now_, next);
    if (now_ != instant) {
      instant = now_;
      steps = 0;
    }
    UTCP_CHECK(++steps < max_steps_per_instant);
    for (const Side s : {Side::a, Side::b}) {
      if (stack(s).next_deadline() <= now_) {
        stack(s).advance(now_);
      }
    }
    settle();
  }
  now_ = std::max(now_, end);
  a_.advance(now_);
  b_.advance(now_);
  settle();
}

void TcpHarness::release_held(std::size_t i) {
  UTCP_CHECK(i < held_.size());
  Held h = std::move(held_[i]);
  held_.erase(held_.begin() + static_cast<std::ptrdiff_t>(i));
  send(h.from, std::move(h.bytes));
}

void TcpHarness::release_all_held() {
  while (!held_.empty()) {
    release_held(0);
  }
}

}  // namespace utcp::test
