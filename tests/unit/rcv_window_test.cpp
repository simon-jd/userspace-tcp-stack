// RcvWindow (src/core/tcp/rcv_window.hpp, DESIGN §4.10): window rounding and
// rcv_adv (RFC 7323 §2.4), receiver SWS avoidance (RFC 9293 §3.8.6.2.2), SYN
// windows, Linux 7.0 rcv_ssthresh growth (tcp_grow_window), the receiver RTT
// (tcp_rcv_rtt_update) and autotuning (tcp_rcv_space_adjust,
// tcp_rcvbuf_grow).
#include "core/tcp/rcv_window.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/recv_buffer.hpp"
#include "utcp/config.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::ChunkPool;
using utcp::Duration;
using utcp::InsertResult;
using utcp::ProfileId;
using utcp::RcvWindow;
using utcp::RcvWindowGrowth;
using utcp::RecvBuffer;
using utcp::SelectedWindow;
using utcp::TcpConfig;
using utcp::Time;
using utcp::WindowUpdateAfterRead;

Time at(Duration d) { return Time{} + d; }

TcpConfig linux_cfg() { return utcp::tcp_config(ProfileId::linux_compat); }
TcpConfig rfc_cfg() { return utcp::tcp_config(ProfileId::rfc); }

// A receive side: a RecvBuffer and its RcvWindow after the handshake, with
// the SYN window as the first rcv_adv.
class Rx {
public:
  Rx(const TcpConfig& c, std::uint32_t rcv_buf, std::uint8_t wscale, std::uint16_t adv_mss = 1460,
     bool autotune = false)
      : pool_(rcv_buf / 4096 + 8), rb(rcv_buf, pool_), rw(c, rcv_buf, autotune), mss(adv_mss) {
    syn = rw.syn_window(mss);
    rw.on_established(wscale, mss, syn);
  }

  // In-order data of `len` bytes, accepted up to rcv_adv; tells RcvWindow.
  InsertResult next(std::uint32_t len) { return put(rb.contiguous_end(), len); }
  InsertResult put(std::uint64_t off, std::uint32_t len) {
    const std::vector<std::byte> payload(len);
    const InsertResult r = rb.insert(off, payload, rw.rcv_adv());
    if (r.advanced) {
      rw.on_in_order_data(len, mss, rb);
    }
    return r;
  }
  void read(std::size_t n) {
    std::vector<std::byte> out(n);
    ASSERT_EQ(rb.read(out), n);
  }
  SelectedWindow select() { return rw.select(rb, mss); }

private:
  ChunkPool pool_;

public:
  RecvBuffer rb;
  RcvWindow rw;
  std::uint16_t mss;
  std::uint16_t syn = 0;
};

TEST(RcvWindow, SynWindows) {
  // RFC: min(rcv_buf, 65535); Linux: rounded down to the MSS
  // (tcp_select_initial_window).
  EXPECT_EQ(RcvWindow(rfc_cfg(), 131072, true).syn_window(1460), 65535);
  EXPECT_EQ(RcvWindow(linux_cfg(), 131072, true).syn_window(1460), 64240);
  // The SYN-ACK to a SYN with timestamps (tcp_openreq_init_rwin: mss - 12).
  EXPECT_EQ(RcvWindow(linux_cfg(), 131072, true).syn_window(1448), 65160);
  // A buffer below 64 KiB.
  EXPECT_EQ(RcvWindow(rfc_cfg(), 3000, false).syn_window(1460), 3000);
  EXPECT_EQ(RcvWindow(linux_cfg(), 3000, false).syn_window(1460), 2920);
  // "if (space > mss)": a buffer below one MSS is not rounded to 0.
  EXPECT_EQ(RcvWindow(linux_cfg(), 1000, false).syn_window(1460), 1000);
}

TEST(RcvWindow, EstablishedStartsFromTheSynWindow) {
  Rx x(linux_cfg(), 131072, 7);
  EXPECT_EQ(x.rw.rcv_adv(), 64240u);
  EXPECT_EQ(x.rw.last_window(), 64240u);
  EXPECT_EQ(x.rw.rcv_ssthresh(), 64240u);
  // tcp_init_buffer_space: min(rcv_wnd, 10 * advmss).
  EXPECT_EQ(x.rw.rcv_space(), 14600u);
  EXPECT_EQ(x.rw.rcv_rtt(), Duration::zero());

  Rx r(rfc_cfg(), 131072, 7);
  EXPECT_EQ(r.rw.rcv_adv(), 65535u);
  // free_space growth has no clamp: rcv_ssthresh() is the buffer.
  EXPECT_EQ(r.rw.rcv_ssthresh(), 131072u);
}

TEST(RcvWindow, WindowsAreMultiplesOfTheScaleUnit) {
  TcpConfig c = rfc_cfg();
  Rx x(c, 1 << 20, 10);  // 2^10 = 1024
  x.next(1000);
  const SelectedWindow w = x.select();
  // free = 1 MiB - 1000; rounded down to 1023 * 1024.
  EXPECT_EQ(w.window, 1023u * 1024);
  EXPECT_EQ(w.field, 1023);
  EXPECT_EQ(x.rw.rcv_adv(), 1000u + 1023 * 1024);
  EXPECT_LE(x.rw.rcv_adv(), x.rb.right_edge());
}

TEST(RcvWindow, RoundingRetractsTheEdgeByLessThanTheScaleUnitAndKeepsRcvAdv) {
  // The SYN window (unscaled) ends at 65535; after 1000 bytes the window
  // 64535 rounds down to 64512, an edge 23 bytes below rcv_adv.
  Rx x(rfc_cfg(), 65536, 10);
  ASSERT_EQ(x.rw.rcv_adv(), 65535u);
  x.next(1000);
  const SelectedWindow w = x.select();
  EXPECT_EQ(w.window, 64512u);
  EXPECT_EQ(x.rw.rcv_adv(), 65535u);  // never lowered
  // Bytes the peer sent into the earlier window are stored, not clipped.
  const InsertResult r = x.put(65000, 535);
  EXPECT_EQ(r.stored, (utcp::Range{65000, 65535}));
  EXPECT_EQ(r.dropped, 0u);
}

TEST(RcvWindow, WindowBelowTheScaleUnitIsZero) {
  Rx x(rfc_cfg(), 65536, 10);
  for (int i = 0; i < 44; ++i) {
    x.next(1460);
  }
  x.next(65535 - 44 * 1460);
  ASSERT_EQ(x.rb.contiguous_end(), 65535u);
  SelectedWindow w = x.select();  // 1 byte free
  EXPECT_EQ(w.window, 0u);
  EXPECT_EQ(w.field, 0);
  EXPECT_TRUE(x.rw.went_to_zero());
  x.read(1000);  // 1001 free: below 1024
  w = x.select();
  EXPECT_EQ(w.window, 0u);
  EXPECT_FALSE(x.rw.went_to_zero());  // was already zero
  x.read(1000);  // 2001 free: 1024 after rounding, below the SWS step 1460
  EXPECT_FALSE(x.rw.update_after_read(x.rb, x.mss));
  w = x.select();
  EXPECT_EQ(w.window, 0u);
  x.read(500);  // 2501 free: 2048 >= 1460
  EXPECT_TRUE(x.rw.update_after_read(x.rb, x.mss));
  w = x.select();
  EXPECT_EQ(w.window, 2048u);
  EXPECT_EQ(w.field, 2);
  EXPECT_TRUE(x.rw.went_from_zero());
}

TEST(RcvWindow, ReceiverSwsHoldsTheEdgeUntilItCanMoveByOneMss) {
  // RFC 9293 §3.8.6.2.2 with Fr = 1/2: the step is min(rcv_buf / 2, MSS).
  Rx x(rfc_cfg(), 65535, 0);
  x.next(1000);
  x.read(1000);
  // The edge could move by 1000 only: the window stays rcv_adv - RCV.NXT.
  SelectedWindow w = x.select();
  EXPECT_EQ(w.window, 64535u);
  EXPECT_EQ(x.rw.rcv_adv(), 65535u);
  x.next(500);
  x.read(500);
  w = x.select();  // the edge can move by 1500 >= 1460
  EXPECT_EQ(w.window, 65535u);
  EXPECT_EQ(x.rw.rcv_adv(), 1500u + 65535);

  // A small buffer: the step is rcv_buf / 2.
  Rx s(rfc_cfg(), 1000, 0);
  ASSERT_EQ(s.rw.rcv_adv(), 1000u);
  s.next(400);
  s.read(400);
  w = s.select();  // the edge can move by 400 < 500
  EXPECT_EQ(w.window, 600u);
  s.next(100);
  s.read(100);
  w = s.select();  // by 500
  EXPECT_EQ(w.window, 1000u);
}

TEST(RcvWindow, UnscaledWindowIsAtMost65535) {
  Rx x(rfc_cfg(), 1 << 20, 0);
  x.next(1460);
  x.read(1460);
  EXPECT_EQ(x.select().window, 65535u);
  // With a scale of 14 the field still fits in 16 bits.
  Rx s(rfc_cfg(), 1 << 20, 14);
  s.next(1460);
  const SelectedWindow w = s.select();
  EXPECT_EQ(w.window, ((1u << 20) - 16384));
  EXPECT_EQ(w.field, 63);
}

TEST(RcvWindow, LinuxClampGrowsByTwoMssPerFullSegment) {
  Rx x(linux_cfg(), 1 << 20, 7);
  ASSERT_EQ(x.rw.rcv_ssthresh(), 64240u);
  for (std::uint32_t i = 1; i <= 10; ++i) {
    x.next(1460);
    EXPECT_EQ(x.rw.rcv_ssthresh(), 64240u + i * 2920) << i;
  }
  // The advertised window follows the clamp (rounded down to 128).
  const SelectedWindow w = x.select();
  EXPECT_EQ(w.window, (64240u + 10 * 2920) / 128 * 128);
}

TEST(RcvWindow, LinuxClampStepIsTwiceTheLargerOfAdvMssAndTheSegment) {
  // Linux 7.0 tcp_grow_window: incr = max(2 * advmss, 2 * len). With
  // timestamps (1448-byte segments) the step stays 2 * 1460.
  Rx x(linux_cfg(), 1 << 20, 7);
  x.next(1448);
  EXPECT_EQ(x.rw.rcv_ssthresh(), 64240u + 2920);
  // A GRO segment of 4 * 1460 bytes grows by twice its length.
  x.next(5840);
  EXPECT_EQ(x.rw.rcv_ssthresh(), 64240u + 2920 + 11680);
}

TEST(RcvWindow, LinuxClampIgnoresSegmentsBelow128Bytes) {
  Rx x(linux_cfg(), 1 << 20, 7);
  x.next(127);
  EXPECT_EQ(x.rw.rcv_ssthresh(), 64240u);
  x.next(128);
  EXPECT_EQ(x.rw.rcv_ssthresh(), 64240u + 2920);
}

TEST(RcvWindow, LinuxClampIsLimitedByTheFreeSpace) {
  // An 80000-byte buffer, nothing read: the clamp stops at the free space
  // (tcp_grow_window: room = min(window_clamp, tcp_space) - rcv_ssthresh).
  Rx x(linux_cfg(), 80000, 7);
  ASSERT_EQ(x.rw.rcv_ssthresh(), 64240u);
  for (std::uint32_t i = 1; i <= 3; ++i) {
    x.next(1460);
    EXPECT_EQ(x.rw.rcv_ssthresh(), 64240u + i * 2920) << i;
  }
  x.next(1460);  // free 74160: room 1160
  EXPECT_EQ(x.rw.rcv_ssthresh(), 74160u);
  x.next(1460);  // free 72700, below the clamp: unchanged
  EXPECT_EQ(x.rw.rcv_ssthresh(), 74160u);
}

TEST(RcvWindow, FreeSpaceGrowthHasNoClamp) {
  Rx x(rfc_cfg(), 1 << 20, 7);
  x.next(1460);
  EXPECT_EQ(x.rw.rcv_ssthresh(), 1u << 20);
  EXPECT_EQ(x.select().window, ((1u << 20) - 1460) / 128 * 128);
}

TEST(RcvWindow, LinuxWindowIsZeroWhenLittleOfTheBufferIsFree) {
  // __tcp_select_window: below half the buffer free, a free space under
  // rcv_buf / 16 gives 0.
  TcpConfig c = linux_cfg();
  Rx x(c, 65536, 7);
  for (int i = 0; i < 44; ++i) {
    x.next(1460);
  }
  ASSERT_EQ(x.rb.contiguous_end(), 64240u);
  EXPECT_EQ(x.select().window, 0u);  // 1296 free < 4096
  x.read(3000);  // 4296 free: rounds to 4224 >= 4096
  EXPECT_EQ(x.select().window, 4224u);
}

TEST(RcvWindow, UpdateAfterReadLinuxNeedsTheWindowToDouble) {
  // tcp_cleanup_rbuf: ACK when the new window is >= 2 * the current one and
  // the current one is at most half the buffer. RFC 9293: when the edge can
  // move by >= min(rcv_buf / 2, MSS).
  TcpConfig lc = linux_cfg();
  TcpConfig rc = linux_cfg();
  rc.window_update_after_read = WindowUpdateAfterRead::rfc;
  Rx l(lc, 65536, 7);
  Rx r(rc, 65536, 7);
  for (Rx* x : {&l, &r}) {
    for (int i = 0; i < 44; ++i) {
      x->next(1460);
    }
    ASSERT_EQ(x->select().window, 0u);
    x->read(30000);  // 31296 free: 31232 after rounding; the current window is 0
  }
  EXPECT_TRUE(l.rw.update_after_read(l.rb, l.mss));
  EXPECT_TRUE(r.rw.update_after_read(r.rb, r.mss));
  for (Rx* x : {&l, &r}) {
    ASSERT_EQ(x->select().window, 31232u);
    x->read(5000);  // 36296 free: 36224 after rounding
  }
  // The edge can move by 4992 (RFC: yes); 36224 < 2 * 31232 (Linux: no).
  EXPECT_FALSE(l.rw.update_after_read(l.rb, l.mss));
  EXPECT_TRUE(r.rw.update_after_read(r.rb, r.mss));
}

TEST(RcvWindow, ReceiverRttFollowsLinux) {
  Rx x(linux_cfg(), 1 << 20, 7);
  // tcp_rcv_rtt_measure_ts: the first sample is taken as is.
  x.next(1448);
  x.rw.on_data_rtt(at(1ms), x.rb.contiguous_end(), 10ms);
  EXPECT_EQ(x.rw.rcv_rtt(), 10ms);
  // The queue was empty before the next segment: a 1/8 EWMA.
  x.read(1448);
  ASSERT_EQ(x.rw.on_read(at(2ms), x.rb.read_offset()), std::nullopt);
  x.next(1448);
  x.rw.on_data_rtt(at(3ms), x.rb.contiguous_end(), 20ms);
  EXPECT_EQ(x.rw.rcv_rtt(), 11'250us);
  // Unread data queued: only the minimum filter applies.
  x.next(1448);
  x.rw.on_data_rtt(at(4ms), x.rb.contiguous_end(), 30ms);
  EXPECT_EQ(x.rw.rcv_rtt(), 11'250us);
  x.next(1448);
  x.rw.on_data_rtt(at(5ms), x.rb.contiguous_end(), 5ms);
  EXPECT_EQ(x.rw.rcv_rtt(), 5ms);
}

TEST(RcvWindow, ReceiverRttFromOneWindowOfData) {
  // tcp_rcv_rtt_measure: the time to receive the last advertised window.
  Rx x(linux_cfg(), 1 << 20, 7);
  x.rw.on_data_rtt(at(0ms), 0, std::nullopt);  // starts: one window = 64240
  x.rw.on_data_rtt(at(5ms), 64239, std::nullopt);
  EXPECT_EQ(x.rw.rcv_rtt(), Duration::zero());
  x.rw.on_data_rtt(at(30ms), 64240, std::nullopt);
  EXPECT_EQ(x.rw.rcv_rtt(), 30ms);
}

// The application reads a sender's doubling flight every RTT; returns the
// buffer sizes on_read reports, one per RTT (0 when it did not grow).
std::vector<std::uint32_t> autotune_run(RcvWindow& rw, Duration rtt, std::uint32_t first,
                                        int rtts) {
  rw.on_data_rtt(at(0ms), 0, rtt);
  std::vector<std::uint32_t> out;
  std::uint64_t read = 0;
  std::uint64_t flight = first;
  for (int i = 1; i <= rtts; ++i) {
    // Half the flight read half-way through the RTT: too early to adjust.
    read += flight / 2;
    EXPECT_EQ(rw.on_read(at(rtt * i - rtt / 2), read), std::nullopt);
    read += flight - flight / 2;
    out.push_back(rw.on_read(at(rtt * i), read).value_or(0));
    flight *= 2;
  }
  return out;
}

TEST(RcvWindow, AutotuningDoublesPerReceiverRttUpToTheMaximum) {
  // rcv_space starts at 10 * 1460 = 14600; reads of 29200, 58400, ...
  // grow the buffer to 2 * copied + 4 * copied * (copied - old) / old
  // = 6 * copied (tcp_rcvbuf_grow, RTT >= 1 ms).
  TcpConfig c = linux_cfg();
  ASSERT_EQ(c.rcv_buf_max, 32u << 20);
  RcvWindow rw(c, 131072, true);
  rw.on_established(10, 1460, 64240);
  const std::vector<std::uint32_t> got = autotune_run(rw, 10ms, 29200, 10);
  const std::vector<std::uint32_t> want = {175200,   350400,   700800,  1401600, 2803200,
                                           5606400,  11212800, 22425600, 32u << 20, 0};
  EXPECT_EQ(got, want);
  EXPECT_EQ(rw.rcv_buf(), 32u << 20);
  EXPECT_EQ(rw.rcv_space(), 29200u << 9);
}

TEST(RcvWindow, AutotuningBelowOneMillisecondGrowsWithTheRtt) {
  // tcp_rcvbuf_grow: below tcp_rcvbuf_low_rtt (1 ms) the extra room is
  // rcvwin * rtt / 1 ms: 500 us gives 1.5 * rcvwin = 3 * copied.
  RcvWindow rw(linux_cfg(), 65536, true);
  rw.on_established(7, 1460, 64240);
  const std::vector<std::uint32_t> got = autotune_run(rw, 500us, 50000, 2);
  EXPECT_EQ(got, (std::vector<std::uint32_t>{150000, 300000}));
}

TEST(RcvWindow, NoAutotuningWhenDisabled) {
  RcvWindow rw(linux_cfg(), 131072, false);
  rw.on_established(7, 1460, 64240);
  const std::vector<std::uint32_t> got = autotune_run(rw, 10ms, 29200, 3);
  EXPECT_EQ(got, (std::vector<std::uint32_t>{0, 0, 0}));
  EXPECT_EQ(rw.rcv_buf(), 131072u);
  EXPECT_EQ(rw.rcv_space(), 116800u);  // still measured
}

TEST(RcvWindow, NoAutotuningWithoutAnRttOrBeforeOneRtt) {
  RcvWindow rw(linux_cfg(), 16384, true);
  rw.on_established(7, 1460, 16384);
  ASSERT_EQ(rw.rcv_space(), 14600u);
  // No receiver RTT yet: the interval that started at 0 stays open.
  rw.on_data_rtt(at(0ms), 0, std::nullopt);
  EXPECT_EQ(rw.on_read(at(100ms), 20000), std::nullopt);
  // An RTT of 10 ms: 20000 read since 0 gives 2 * 20000 + 4 * 20000 * 5400
  // / 14600 = 69589.
  rw.on_data_rtt(at(100ms), 20000, 10ms);
  EXPECT_EQ(rw.on_read(at(100ms), 20000), 69589u);
  // Less than one RTT after that adjustment: nothing.
  EXPECT_EQ(rw.on_read(at(109ms), 60000), std::nullopt);
  EXPECT_EQ(rw.on_read(at(110ms), 60000), 240000u);
}

TEST(RcvWindow, AutotuningCountsOnlyTheBytesReadLessThoseStillQueued) {
  RcvWindow rw(linux_cfg(), 131072, true);
  rw.on_established(7, 1460, 64240);
  rw.on_data_rtt(at(0ms), 0, 10ms);
  // 40000 read but 20000 still queued: copied = 20000 (Linux 7.0
  // tcp_rcv_space_adjust: copied -= inq).
  rw.on_data_rtt(at(5ms), 60000, std::nullopt);
  EXPECT_EQ(rw.on_read(at(10ms), 40000), std::nullopt);  // 69589 < 131072
  EXPECT_EQ(rw.rcv_space(), 20000u);
}

// What a property run exercised, so that a run that checks nothing fails.
struct PropertyCounts {
  int advances = 0;       // windows that moved the edge above rcv_adv
  int held = 0;           // windows that kept rcv_adv (SWS or rounding)
  int zero = 0;           // zero windows
  int stored_checks = 0;  // segments checked against rcv_adv
  int grows = 0;          // autotuning grew the buffer
};

struct PropertyCase {
  bool linux_profile;
  std::uint8_t wscale;
  std::uint32_t rcv_buf;
  bool autotune;
};

// Random arrivals (in order, out of order, duplicate, beyond the window),
// reads, ACKs and autotuning; every advertised window is checked. The reader
// alternates between keeping up and falling behind every 500 steps, so the
// buffer fills and windows close.
void property_run(const PropertyCase& pc, std::uint32_t seed, int steps, PropertyCounts& count) {
  TcpConfig c = pc.linux_profile ? linux_cfg() : rfc_cfg();
  c.rcv_buf_max = 4u << 20;
  const std::uint16_t mss = 1460;
  const std::uint64_t unit = std::uint64_t{1} << pc.wscale;
  ChunkPool pool((4u << 20) / 4096 + 8);
  RecvBuffer rb(pc.rcv_buf, pool);
  RcvWindow rw(c, pc.rcv_buf, pc.autotune);
  rw.on_established(pc.wscale, mss, rw.syn_window(mss));
  std::mt19937 rng(seed);
  const auto pick = [&rng](std::uint64_t lo, std::uint64_t hi) {  // [lo, hi]
    return std::uniform_int_distribution<std::uint64_t>(lo, hi)(rng);
  };
  Duration now{0};
  const std::uint64_t rtt_us = pick(1000, 4000);  // timestamp RTT samples: rtt_us .. 1.25 rtt_us
  std::vector<std::byte> buf(1 << 16);

  const auto check_select = [&] {
    const std::uint64_t adv_before = rw.rcv_adv();
    const std::uint64_t rcv_nxt = rb.contiguous_end();
    const SelectedWindow w = rw.select(rb, mss);
    const std::uint64_t edge = rcv_nxt + w.window;
    ASSERT_EQ(w.window % unit, 0u);
    ASSERT_EQ(w.field, w.window >> pc.wscale);
    ASSERT_LE(w.window, std::uint64_t{65535} << pc.wscale);
    ASSERT_LE(edge, rb.right_edge());
    ASSERT_GT(edge + unit, adv_before);  // never retracts by >= 2^s
    ASSERT_EQ(rw.rcv_adv(), std::max(adv_before, edge));
    ASSERT_LE(rw.rcv_adv(), rb.right_edge());
    count.zero += w.window == 0 ? 1 : 0;
    count.held += edge <= adv_before ? 1 : 0;
    if (edge > adv_before) {
      ++count.advances;
      // Receiver SWS: no update smaller than min(rcv_buf / 2, rcv_mss).
      ASSERT_GE(edge - adv_before, std::min<std::uint64_t>(rb.capacity() / 2, mss));
      if (pc.linux_profile) {
        ASSERT_LE(w.window, rw.rcv_ssthresh());
      }
    }
    ASSERT_EQ(rw.last_window(), w.window);
  };

  for (int i = 0; i < steps; ++i) {
    now += std::chrono::microseconds{static_cast<std::int64_t>(pick(1, 300))};
    const std::uint64_t rcv_nxt = rb.contiguous_end();
    const std::uint64_t adv = rw.rcv_adv();
    const std::uint64_t op = pick(0, 99);
    const std::uint64_t read_pct = (i / 500) % 2 == 0 ? 25 : 3;
    if (op < 70) {
      // A segment: mostly in order, some ahead, some old, some past rcv_adv.
      const auto len = static_cast<std::uint32_t>(pick(1, 2u * mss));
      std::uint64_t off = rcv_nxt;
      const std::uint64_t kind = pick(0, 9);
      if (kind == 0) {
        off = rcv_nxt - std::min<std::uint64_t>(rcv_nxt, pick(0, 3000));
      } else if (kind <= 2) {
        off = rcv_nxt + pick(0, adv - rcv_nxt + mss);
      }
      const InsertResult r = rb.insert(off, std::span(buf.data(), len), rw.rcv_adv());
      // Bytes below rcv_adv are stored, not clipped.
      const std::uint64_t lo = std::max(off, rb.read_offset());
      const std::uint64_t hi = std::min(off + len, adv);
      if (lo < hi && !r.range_limit) {
        ASSERT_EQ(r.stored, (utcp::Range{lo, hi})) << "step " << i;
        ++count.stored_checks;
        ASSERT_EQ(r.dropped, 0u);
      }
      if (r.advanced) {
        rw.on_in_order_data(len, mss, rb);
      }
      std::optional<Duration> ts;
      if (pick(0, 3) == 0) {
        ts = std::chrono::microseconds{static_cast<std::int64_t>(rtt_us + pick(0, rtt_us / 4))};
      }
      rw.on_data_rtt(Time{} + now, rb.contiguous_end(), ts);
      if (pick(0, 1) == 0) {
        check_select();
      }
    } else if (op < 70 + read_pct) {
      const std::size_t n = static_cast<std::size_t>(
          std::min<std::uint64_t>(rb.readable(), pick(0, buf.size())));
      ASSERT_EQ(rb.read(std::span(buf.data(), n)), n);
      if (const auto grown = rw.on_read(Time{} + now, rb.read_offset())) {
        ASSERT_GT(*grown, rb.capacity());
        ASSERT_LE(*grown, c.rcv_buf_max);
        rb.grow(*grown);
        ++count.grows;
      }
      if (rw.update_after_read(rb, mss)) {
        check_select();
      }
    } else {
      check_select();
    }
    if (::testing::Test::HasFatalFailure()) {
      return;
    }
    rb.check_invariants();
  }
}

TEST(RcvWindow, PropertyEveryWindowFollowsTheRules) {
  for (const int s : {0, 7, 10, 14}) {
    for (const bool linux_profile : {false, true}) {
      for (const std::uint32_t rcv_buf : {3000u, 65535u, 131072u, 1u << 20}) {
        for (const bool autotune : {false, true}) {
          SCOPED_TRACE(::testing::Message() << "wscale " << s << " linux " << linux_profile
                                            << " rcv_buf " << rcv_buf << " autotune " << autotune);
          PropertyCounts n;
          property_run(
              PropertyCase{linux_profile, static_cast<std::uint8_t>(s), rcv_buf, autotune},
              1000u + static_cast<std::uint32_t>(s) + rcv_buf, 4000, n);
          if (HasFatalFailure()) {
            return;
          }
          // The run exercised what it checks.
          if (rcv_buf >= (4u << s)) {
            EXPECT_GT(n.advances, 100);
            EXPECT_GT(n.held, 100);
            EXPECT_GT(n.stored_checks, 1000);
          }
          if (rcv_buf <= 131072 && !autotune) {
            EXPECT_GT(n.zero, 0);
          }
          if (rcv_buf <= 131072 && autotune && rcv_buf >= (1u << s)) {
            EXPECT_GT(n.grows, 0);
          }
        }
      }
    }
  }
}

}  // namespace
