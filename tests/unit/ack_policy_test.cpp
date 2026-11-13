// AckPolicy (src/core/tcp/ack_policy.hpp, DESIGN §4.10): delayed ACKs and
// quick ACKs in both profiles, and a hand trace of Linux 7.0
// tcp_event_data_recv's ato estimate.
#include "core/tcp/ack_policy.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/recv_buffer.hpp"
#include "utcp/config.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::AckNeed;
using utcp::AckPolicy;
using utcp::ChunkPool;
using utcp::Duration;
using utcp::InsertResult;
using utcp::ProfileId;
using utcp::RecvBuffer;
using utcp::TcpConfig;
using utcp::Time;

Time at(Duration d) { return Time{} + d; }

utcp::TcpConfig linux_cfg() { return utcp::tcp_config(ProfileId::linux_compat); }
utcp::TcpConfig rfc_cfg() { return utcp::tcp_config(ProfileId::rfc); }
// Linux's adaptive ato without quick-ack mode, to trace ato alone.
utcp::TcpConfig ato_only_cfg() {
  TcpConfig c = linux_cfg();
  c.quickack = utcp::Quickack::rfc;
  return c;
}

// A receiver: segments go through a RecvBuffer, then AckPolicy::on_data.
class Rx {
public:
  explicit Rx(const TcpConfig& c, std::uint32_t wnd = 64240)
      : cfg_(c), ap(cfg_), rcv_wnd(wnd) {
    ap.init(1460, 1448, rcv_wnd);
  }

  InsertResult data(Duration t, std::uint64_t off, std::uint32_t len, std::uint16_t gso = 0) {
    const std::vector<std::byte> payload(len);
    const InsertResult r = rb.insert(off, payload, rb.right_edge());
    ap.on_data(at(t), len, gso, r, rcv_wnd, rto);
    return r;
  }
  // In-order data of `len` bytes at the current end.
  InsertResult next(Duration t, std::uint32_t len, std::uint16_t gso = 0) {
    return data(t, rb.contiguous_end(), len, gso);
  }
  // Sends the ACK if one is owed now.
  bool ack_if_now(Duration t) {
    if (ap.need() != AckNeed::now) {
      return false;
    }
    ap.on_ack_sent(at(t));
    return true;
  }

private:
  TcpConfig cfg_;

public:
  ChunkPool pool{8192};
  RecvBuffer rb{1u << 24, pool};
  AckPolicy ap;
  std::uint32_t rcv_wnd;
  Duration rto = 1s;
};

TEST(AckPolicy, InitialRcvMss) {
  // tcp_initialize_rcv_mss: min(adv_mss, mss_cache, rcv_wnd / 2, 536) >= 88.
  AckPolicy a(linux_cfg());
  a.init(1460, 1448, 64240);
  EXPECT_EQ(a.rcv_mss(), 536);
  a.init(1460, 400, 64240);
  EXPECT_EQ(a.rcv_mss(), 400);
  a.init(1460, 1448, 500);
  EXPECT_EQ(a.rcv_mss(), 250);
  a.init(1460, 1448, 100);
  EXPECT_EQ(a.rcv_mss(), 88);
  EXPECT_EQ(a.need(), AckNeed::none);
  EXPECT_EQ(a.delack_deadline(), Time::never());
  EXPECT_EQ(a.ato(), Duration::zero());  // before the first data
  EXPECT_EQ(AckPolicy(rfc_cfg()).ato(), 200ms);
}

TEST(AckPolicy, RfcTwoFullSegmentsAckedAtOnceOneDelayed200ms) {
  Rx x(rfc_cfg(), 65535);
  x.next(0ms, 1460);
  EXPECT_EQ(x.ap.rcv_mss(), 1460);
  EXPECT_FALSE(x.ap.in_quickack_mode());
  EXPECT_EQ(x.ap.need(), AckNeed::delayed);
  EXPECT_EQ(x.ap.delack_deadline(), at(200ms));
  x.next(10ms, 1460);  // the second full segment
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  x.ap.on_ack_sent(at(10ms));
  EXPECT_EQ(x.ap.need(), AckNeed::none);
  EXPECT_EQ(x.ap.delack_deadline(), Time::never());

  x.next(20ms, 100);
  EXPECT_EQ(x.ap.need(), AckNeed::delayed);
  EXPECT_EQ(x.ap.delack_deadline(), at(220ms));
  x.next(100ms, 100);  // a second one keeps the first deadline
  EXPECT_EQ(x.ap.need(), AckNeed::delayed);
  EXPECT_EQ(x.ap.delack_deadline(), at(220ms));
  x.ap.on_delack_timer(at(219ms));  // early: nothing
  EXPECT_EQ(x.ap.need(), AckNeed::delayed);
  x.ap.on_delack_timer(at(220ms));
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  x.ap.on_ack_sent(at(220ms));
  EXPECT_EQ(x.ap.ato(), 200ms);  // fixed in the rfc profile
}

TEST(AckPolicy, OutOfOrderAndHoleFillingAreAckedAtOnce) {
  for (const TcpConfig& c : {rfc_cfg(), ato_only_cfg()}) {
    Rx x(c);
    x.next(0ms, 1000);
    ASSERT_EQ(x.ap.need(), AckNeed::delayed);
    InsertResult r = x.data(1ms, 3000, 1000);  // out of order
    ASSERT_TRUE(r.out_of_order);
    EXPECT_EQ(x.ap.need(), AckNeed::now);
    x.ap.on_ack_sent(at(1ms));
    r = x.data(2ms, 2000, 1000);  // out of order, below the first range
    EXPECT_EQ(x.ap.need(), AckNeed::now);
    x.ap.on_ack_sent(at(2ms));
    r = x.data(3ms, 1000, 500);  // fills part of the gap: RFC 5681 §4.2
    ASSERT_TRUE(r.advanced);
    ASSERT_FALSE(r.filled_hole);
    EXPECT_EQ(x.ap.need(), AckNeed::now);
    x.ap.on_ack_sent(at(3ms));
    r = x.data(4ms, 1500, 500);  // fills the gap
    ASSERT_TRUE(r.filled_hole);
    EXPECT_EQ(x.ap.need(), AckNeed::now);
    x.ap.on_ack_sent(at(4ms));
    x.next(5ms, 100);  // in order again: delayed
    EXPECT_EQ(x.ap.need(), AckNeed::delayed);
  }
}

TEST(AckPolicy, LinuxFirstSixteenSegmentsAckedAtOnce) {
  Rx x(linux_cfg(), 64240);
  // rcv_mss becomes 1448 with the first segment: 64240 / (2 * 1448) = 22,
  // capped at TCP_MAX_QUICKACKS = 16.
  for (int i = 0; i < 16; ++i) {
    x.next(Duration{i * 1ms}, 1448);
    ASSERT_EQ(x.ap.need(), AckNeed::now) << i;
    ASSERT_TRUE(x.ap.in_quickack_mode()) << i;
    x.ap.on_ack_sent(at(Duration{i * 1ms}));
  }
  EXPECT_FALSE(x.ap.in_quickack_mode());
  EXPECT_EQ(x.ap.ato(), 40ms);  // leaving quick-ack mode deflates ato
  x.next(16ms, 1448);
  EXPECT_EQ(x.ap.need(), AckNeed::delayed);
  EXPECT_EQ(x.ap.delack_deadline(), at(56ms));
  x.next(17ms, 1448);  // more than one full segment unacknowledged
  EXPECT_EQ(x.ap.need(), AckNeed::now);
}

TEST(AckPolicy, LinuxQuickAckCountFollowsTheWindow) {
  // rcv_wnd / (2 * rcv_mss), 2 if that is 0, at most 16.
  struct Case {
    std::uint32_t rcv_wnd;
    int quick;
  };
  for (const Case c : {Case{8000, 2}, Case{20'000, 6}, Case{2000, 2}, Case{1u << 20, 16}}) {
    Rx x(linux_cfg(), c.rcv_wnd);
    int quick = 0;
    for (int i = 0; i < 20; ++i) {
      x.next(Duration{i * 1ms}, 1448);
      if (x.ap.in_quickack_mode()) {
        ++quick;
      }
      x.ack_if_now(Duration{i * 1ms});
      if (x.ap.need() == AckNeed::delayed) {
        break;
      }
    }
    EXPECT_EQ(quick, c.quick) << c.rcv_wnd;
  }
}

// Hand trace of tcp_event_data_recv (TCP_ATO_MIN 40 ms, rto 1 s), with
// small segments so that only ato decides:
//   m <= 20 ms:  ato = ato / 2 + 20 ms
//   m < ato:     ato = min(ato / 2 + m, rto), here also at most 200 ms
//   m > rto:     quick-ack mode again
// and tcp_delack_timer_handler: ato = min(2 * ato, rto).
TEST(AckPolicy, LinuxAtoFollowsTheArrivalPattern) {
  Rx x(ato_only_cfg());
  struct Step {
    Duration t;
    Duration ato;
  };
  const Step steps[] = {
      {0ms, 40ms},                  // first data: TCP_ATO_MIN
      {10ms, 40ms},                 // m = 10: 20 + 20
      {40ms, 50ms},                 // m = 30 < 40: 20 + 30
      {85ms, 70ms},                 // m = 45 < 50: 25 + 45
      {150ms, 100ms},               // m = 65 < 70: 35 + 65
      {245ms, 145ms},               // m = 95 < 100: 50 + 95
      {385ms, 200ms},               // m = 140 < 145: 72.5 + 140 = 212.5, capped at 200
      {585ms, 200ms},               // m = 200, not below ato: unchanged
      {600ms, 120ms},               // m = 15: 100 + 20
  };
  for (const Step& s : steps) {
    x.next(s.t, 100);
    EXPECT_EQ(x.ap.ato(), s.ato) << s.t.count();
    if (s.t != 600ms) {
      x.ap.on_ack_sent(at(s.t));  // no effect on ato without quick-ack mode
    }
  }
  // The last segment is not acknowledged: delayed by ato.
  EXPECT_EQ(x.ap.need(), AckNeed::delayed);
  EXPECT_EQ(x.ap.delack_deadline(), at(720ms));
  x.ap.on_delack_timer(at(720ms));  // missed: ato doubles, capped
  EXPECT_EQ(x.ap.ato(), 200ms);
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  x.ap.on_ack_sent(at(720ms));
  // m = 150 < 200: 100 + 150 = 250, capped by the rto of 150 ms.
  x.rto = 150ms;
  x.next(750ms, 100);
  EXPECT_EQ(x.ap.ato(), 150ms);
}

TEST(AckPolicy, LinuxAtoNeverAbove200ms) {
  std::mt19937_64 gen(5681);
  Rx x(linux_cfg(), 1u << 20);
  Duration t{0};
  for (int i = 0; i < 5000; ++i) {
    t += Duration{static_cast<std::int64_t>(gen() % 400'000'000)};  // 0..400 ms
    if (gen() % 3 == 0) {
      x.ap.on_delack_timer(at(t));
    }
    x.next(t, static_cast<std::uint32_t>(1 + gen() % 2000));
    ASSERT_LE(x.ap.ato(), 200ms) << i;
    ASSERT_GE(x.ap.ato(), 40ms) << i;
    if (x.ap.need() == AckNeed::delayed) {
      ASSERT_LE(x.ap.delack_deadline() - at(t), 200ms) << i;
      ASSERT_GE(x.ap.delack_deadline(), at(t)) << i;
    }
    if (gen() % 2 == 0) {
      x.ack_if_now(t);
    }
  }
}

TEST(AckPolicy, DelayedAckIsBoundedBySrtt) {
  // tcp_send_delayed_ack: once ato > 40 ms, the delay is at most
  // max(srtt, 40 ms).
  for (const auto& [srtt, deadline] :
       {std::pair{Duration{0}, 80ms}, std::pair{Duration{10ms}, 70ms}, std::pair{Duration{45ms}, 75ms}}) {
    Rx x(ato_only_cfg());
    x.ap.set_srtt(srtt);
    x.next(0ms, 100);
    x.ap.on_ack_sent(at(0ms));
    x.next(30ms, 100);  // m = 30 < 40: ato = 50 ms
    ASSERT_EQ(x.ap.ato(), 50ms);
    ASSERT_EQ(x.ap.need(), AckNeed::delayed);
    EXPECT_EQ(x.ap.delack_deadline(), at(deadline)) << srtt.count();
  }
}

TEST(AckPolicy, TimerAboutToExpireSendsNow) {
  // tcp_send_delayed_ack: a pending timer that expires within ato / 4 sends
  // the ACK at once; otherwise the earlier deadline stays.
  Rx x(ato_only_cfg());
  x.next(0ms, 100);
  ASSERT_EQ(x.ap.delack_deadline(), at(40ms));
  x.next(10ms, 100);  // ato 40: 40 > 10 + 10
  EXPECT_EQ(x.ap.need(), AckNeed::delayed);
  EXPECT_EQ(x.ap.delack_deadline(), at(40ms));
  x.next(35ms, 100);  // m = 25 < 40: ato = 45; 40 <= 35 + 11.25
  EXPECT_EQ(x.ap.need(), AckNeed::now);
}

TEST(AckPolicy, IdleLongerThanRtoReentersQuickAck) {
  Rx x(linux_cfg(), 1u << 20);
  for (int i = 0; i < 20; ++i) {
    x.next(Duration{i * 1ms}, 1448);
    x.ack_if_now(Duration{i * 1ms});
  }
  x.ap.on_ack_sent(at(20ms));
  ASSERT_FALSE(x.ap.in_quickack_mode());
  x.next(500ms, 100);  // idle 480 ms < rto 1 s
  EXPECT_FALSE(x.ap.in_quickack_mode());
  x.ap.on_ack_sent(at(500ms));
  x.next(1600ms, 100);  // idle 1.1 s > rto
  EXPECT_TRUE(x.ap.in_quickack_mode());
  EXPECT_EQ(x.ap.need(), AckNeed::now);

  Rx y(rfc_cfg());  // the rfc profile has no quick-ack mode
  y.next(0ms, 100);
  y.ap.on_ack_sent(at(0ms));
  y.next(5s, 100);
  EXPECT_FALSE(y.ap.in_quickack_mode());
  EXPECT_EQ(y.ap.need(), AckNeed::delayed);
}

TEST(AckPolicy, RcvMssTakesGsoSize) {
  // tcp_measure_rcv_mss: len = gso_size ?: skb->len, capped at adv_mss.
  Rx x(linux_cfg());
  x.next(0ms, 64'000, 1448);
  EXPECT_EQ(x.ap.rcv_mss(), 1448);
  Rx y(linux_cfg());
  y.next(0ms, 64'000);
  EXPECT_EQ(y.ap.rcv_mss(), 1460);
  // Smaller segments lower it once two equal ones of >= 536 bytes arrive.
  y.next(1ms, 1000);
  EXPECT_EQ(y.ap.rcv_mss(), 1460);
  y.next(2ms, 1000);
  EXPECT_EQ(y.ap.rcv_mss(), 1000);
  y.next(3ms, 400);  // below 536: kept
  y.next(4ms, 400);
  EXPECT_EQ(y.ap.rcv_mss(), 1000);
  // Out-of-order segments are measured too (Linux 7.0 tcp_data_queue_ofo).
  Rx z(linux_cfg());
  z.data(0ms, 5000, 1448);
  EXPECT_EQ(z.ap.rcv_mss(), 1448);
}

TEST(AckPolicy, DuplicateAloneDoesNotForceAnAck) {
  // A partly duplicate in-order segment goes the normal way (Linux
  // tcp_data_queue: queue_and_out). Only a D-SACK the engine actually
  // records makes it call ack_now(); without SACK there is none.
  for (const bool dsack : {true, false}) {
    TcpConfig c = ato_only_cfg();
    c.dsack = dsack;
    Rx x(c);
    x.next(0ms, 1000);
    x.ap.on_ack_sent(at(0ms));
    const InsertResult r = x.data(5ms, 500, 1000);  // [500, 1000) duplicate
    ASSERT_TRUE(r.duplicate);
    ASSERT_TRUE(r.advanced);
    EXPECT_EQ(x.ap.need(), AckNeed::delayed) << dsack;
    x.ap.ack_now();  // the engine recorded a D-SACK (SACK negotiated)
    EXPECT_EQ(x.ap.need(), AckNeed::now);
  }
}

TEST(AckPolicy, InOrderDataDroppedForMemoryIsAckedAtOnceWithoutQuickAck) {
  // Linux tcp_data_queue: tcp_try_rmem_schedule failed for in-order data:
  // ICSK_ACK_NOMEM | ICSK_ACK_NOW, no tcp_enter_quickack_mode.
  Rx x(linux_cfg(), 1u << 20);
  for (int i = 0; i < 20; ++i) {
    x.next(Duration{i * 1ms}, 1448);
    x.ack_if_now(Duration{i * 1ms});
  }
  x.ap.on_ack_sent(at(20ms));
  ASSERT_FALSE(x.ap.in_quickack_mode());
  const Duration ato = x.ap.ato();
  InsertResult r;
  r.contiguous_end = x.rb.contiguous_end();
  r.dropped = 1448;
  x.ap.on_data(at(21ms), 1448, 0, r, x.rcv_wnd, x.rto);
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  EXPECT_FALSE(x.ap.in_quickack_mode());
  EXPECT_EQ(x.ap.ato(), ato);
}

// Linux __tcp_ack_snd_check: more than one full frame is ACKed at once only
// if the right edge advances far enough or nothing is unread; otherwise
// tcp_cleanup_rbuf sends it when the application reads.
TEST(AckPolicy, LinuxFullSegmentsWaitWhileTheWindowShrinks) {
  Rx x(linux_cfg(), 1u << 20);
  for (int i = 0; i < 20; ++i) {
    x.next(Duration{i * 1ms}, 1448);
    x.ack_if_now(Duration{i * 1ms});
  }
  x.ap.on_ack_sent(at(20ms));
  ASSERT_FALSE(x.ap.in_quickack_mode());
  const utcp::RcvWindowView shrinking{.unread = true, .not_shrinking = false, .low_space = false};

  x.next(30ms, 1448);
  x.ap.on_window(at(30ms), shrinking);
  EXPECT_EQ(x.ap.need(), AckNeed::delayed);
  EXPECT_EQ(x.ap.delack_deadline(), at(70ms));
  x.next(31ms, 1448);  // more than one full segment unacknowledged
  x.ap.on_window(at(31ms), shrinking);
  EXPECT_EQ(x.ap.need(), AckNeed::delayed);
  EXPECT_EQ(x.ap.delack_deadline(), at(70ms));
  // The application reads part of the data: tcp_cleanup_rbuf ACKs.
  x.ap.on_read(shrinking);
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  x.ap.on_ack_sent(at(32ms));

  // Not shrinking, or nothing unread: at once, as without a view.
  x.next(40ms, 1448);
  x.ap.on_window(at(40ms), shrinking);
  x.next(41ms, 1448);
  x.ap.on_window(at(41ms), {.unread = true, .not_shrinking = true, .low_space = false});
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  x.ap.on_ack_sent(at(41ms));
  x.next(50ms, 1448);
  x.ap.on_window(at(50ms), shrinking);
  x.next(51ms, 1448);
  x.ap.on_window(at(51ms), {.unread = false, .not_shrinking = false, .low_space = false});
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  x.ap.on_ack_sent(at(51ms));

  // One segment and a read: nothing more than one full segment, no ACK.
  x.next(60ms, 1448);
  x.ap.on_window(at(60ms), shrinking);
  x.ap.on_read(shrinking);
  EXPECT_EQ(x.ap.need(), AckNeed::delayed);

  // The rfc model ACKs every second full segment whatever the window.
  Rx y(rfc_cfg(), 65535);
  y.next(0ms, 1460);
  y.ap.on_window(at(0ms), shrinking);
  y.next(1ms, 1460);
  y.ap.on_window(at(1ms), shrinking);
  EXPECT_EQ(y.ap.need(), AckNeed::now);
}

// Linux __tcp_select_window clears icsk_ack.quick below half the buffer
// free, when an ACK is sent and when __tcp_ack_snd_check evaluates it.
TEST(AckPolicy, LinuxLowSpaceEndsQuickAckMode) {
  const utcp::RcvWindowView low{.unread = true, .not_shrinking = false, .low_space = true};
  Rx x(linux_cfg(), 1u << 20);
  x.next(0ms, 1448);
  x.ap.on_window(at(0ms), low);  // one segment: __tcp_select_window not evaluated
  ASSERT_TRUE(x.ap.in_quickack_mode());
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  x.ap.on_ack_sent(at(0ms));  // tcp_select_window while low: quick = 0
  EXPECT_FALSE(x.ap.in_quickack_mode());
  x.next(1ms, 1448);
  x.ap.on_window(at(1ms), low);
  EXPECT_EQ(x.ap.need(), AckNeed::delayed);

  // Two segments before an ACK went out: the check itself clears quick.
  Rx y(linux_cfg(), 1u << 20);
  y.next(0ms, 1448);
  ASSERT_TRUE(y.ap.in_quickack_mode());
  y.next(1ms, 1448);
  y.ap.on_window(at(1ms), low);
  EXPECT_FALSE(y.ap.in_quickack_mode());
  EXPECT_EQ(y.ap.need(), AckNeed::delayed);

  // With room in the buffer quick-ack mode goes on.
  Rx z(linux_cfg(), 1u << 20);
  z.next(0ms, 1448);
  z.next(1ms, 1448);
  z.ap.on_window(at(1ms), {.unread = true, .not_shrinking = false, .low_space = false});
  EXPECT_TRUE(z.ap.in_quickack_mode());
  EXPECT_EQ(z.ap.need(), AckNeed::now);
  z.ap.on_ack_sent(at(1ms));
  EXPECT_TRUE(z.ap.in_quickack_mode());
}

TEST(AckPolicy, NothingNewEntersQuickAck) {
  // Linux tcp_data_queue: data below RCV.NXT or at a zero window.
  Rx x(linux_cfg(), 1u << 20);
  for (int i = 0; i < 20; ++i) {
    x.next(Duration{i * 1ms}, 1448);
    x.ack_if_now(Duration{i * 1ms});
  }
  x.ap.on_ack_sent(at(20ms));
  ASSERT_FALSE(x.ap.in_quickack_mode());
  const InsertResult r = x.data(21ms, 0, 1448);  // wholly below RCV.NXT
  ASSERT_FALSE(r.advanced);
  ASSERT_FALSE(r.out_of_order);
  EXPECT_TRUE(x.ap.in_quickack_mode());
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  EXPECT_EQ(x.ap.ato(), 40ms);

  Rx y(rfc_cfg());
  y.next(0ms, 100);
  y.ap.on_ack_sent(at(0ms));
  y.data(1ms, 0, 100);
  EXPECT_FALSE(y.ap.in_quickack_mode());
  EXPECT_EQ(y.ap.need(), AckNeed::now);
}

TEST(AckPolicy, AckNowEnterQuickAckAndWindowGrowth) {
  Rx x(linux_cfg(), 1u << 20);
  for (int i = 0; i < 20; ++i) {
    x.next(Duration{i * 1ms}, 1448);
    x.ack_if_now(Duration{i * 1ms});
  }
  x.ap.on_ack_sent(at(20ms));
  ASSERT_FALSE(x.ap.in_quickack_mode());

  x.ap.ack_now();  // e.g. FIN or a window update
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  x.ap.on_ack_sent(at(21ms));
  EXPECT_EQ(x.ap.need(), AckNeed::none);

  x.next(22ms, 1448);
  ASSERT_EQ(x.ap.need(), AckNeed::delayed);
  x.ap.on_rcv_ssthresh_grew();  // tcp_grow_window: quick |= 1
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  x.ap.on_ack_sent(at(22ms));
  EXPECT_FALSE(x.ap.in_quickack_mode());  // one quick ACK, used up

  x.ap.enter_quickack(1u << 20);
  EXPECT_TRUE(x.ap.in_quickack_mode());
  EXPECT_EQ(x.ap.need(), AckNeed::now);
  x.ap.on_ack_sent(at(23ms));
  EXPECT_TRUE(x.ap.in_quickack_mode());  // 16 - 1 left
  x.next(24ms, 100);
  EXPECT_EQ(x.ap.need(), AckNeed::now);

  Rx y(rfc_cfg());
  y.next(0ms, 100);
  y.ap.on_rcv_ssthresh_grew();  // no quick-ack mode in the rfc profile
  EXPECT_EQ(y.ap.need(), AckNeed::delayed);
}

TEST(AckPolicy, ZeroLengthSegmentChangesNothing) {
  Rx x(linux_cfg());
  x.ap.on_data(at(0ms), 0, 0, InsertResult{}, 64240, 1s);
  EXPECT_EQ(x.ap.need(), AckNeed::none);
  EXPECT_EQ(x.ap.ato(), Duration::zero());
}

}  // namespace
