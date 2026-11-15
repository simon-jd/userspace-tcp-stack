// Receive window selection, rcv_adv and autotuning (RFC 9293 §3.8.6.2.2, RFC
// 7323 §2.4; Linux 7.0 tcp_select_window, __tcp_select_window,
// tcp_grow_window, tcp_rcv_rtt_update, tcp_rcv_space_adjust,
// tcp_rcvbuf_grow; DESIGN §4.10).
//
// Buffers here are payload bytes with a hard limit (RecvBuffer::right_edge),
// where Linux counts skb->truesize against soft limits, so Linux's
// space/window conversions (tcp_win_from_space, scaling_ratio) are the
// identity. Not modelled: memory pressure (tcp_adjust_rcv_ssthresh,
// tcp_clamp_window) and the tcp_app_win one-segment reservation of the
// window clamp. The ACK-side effects of __tcp_select_window go to AckPolicy
// through ack_view.
#include "core/tcp/rcv_window.hpp"

#include <algorithm>
#include <limits>

#include "utcp/check.hpp"

namespace utcp {
namespace {

constexpr std::uint64_t max_unscaled_window = 65535;
// net.ipv4.tcp_rcvbuf_low_rtt, Linux 7.0 default (USEC_PER_MSEC).
constexpr Duration rcvbuf_low_rtt = std::chrono::milliseconds{1};
constexpr std::uint64_t tcp_init_cwnd = 10;  // TCP_INIT_CWND, first rcvq_space.space
constexpr std::uint32_t grow_window_min_len = 128;  // tcp_event_data_recv: skb->len >= 128

constexpr std::uint64_t round_down(std::uint64_t v, std::uint8_t s) { return v >> s << s; }

}  // namespace

RcvWindow::RcvWindow(const TcpConfig& cfg, std::uint32_t rcv_buf, bool autotune)
    : linux_growth_(cfg.rcv_window_growth == RcvWindowGrowth::linux),
      linux_syn_window_(cfg.syn_window == SynWindow::linux),
      linux_update_after_read_(cfg.window_update_after_read == WindowUpdateAfterRead::linux),
      autotune_(autotune),
      rcv_buf_max_(cfg.rcv_buf_max),
      rcv_buf_(rcv_buf),
      rcv_ssthresh_(rcv_buf) {}

std::uint16_t RcvWindow::syn_window(std::uint16_t adv_mss) const {
  // tcp_select_initial_window: "quantize space offering to a multiple of mss".
  auto w = static_cast<std::uint32_t>(std::min<std::uint64_t>(rcv_buf_, max_unscaled_window));
  if (linux_syn_window_ && adv_mss > 0 && w > adv_mss) {
    w -= w % adv_mss;
  }
  return static_cast<std::uint16_t>(w);
}

void RcvWindow::on_established(std::uint8_t rcv_wscale, std::uint16_t adv_mss,
                               std::uint64_t syn_edge) {
  wscale_ = std::min(rcv_wscale, max_wscale);
  // Windows round down to 2^wscale and the edge never moves past the buffer:
  // a smaller buffer could never advertise a window again (see the header).
  UTCP_CHECK(rcv_buf_ >= min_rcv_buf(wscale_));
  adv_mss_ = adv_mss;
  rcv_adv_ = syn_edge;
  const auto init_wnd =
      static_cast<std::uint32_t>(std::min<std::uint64_t>(syn_edge - std::min(syn_edge, rcv_nxt_),
                                                         max_unscaled_window));
  last_window_ = init_wnd;
  wup_ = rcv_nxt_;
  if (linux_growth_) {
    // tcp_connect_init / tcp_openreq_init_rwin: rcv_ssthresh = rcv_wnd;
    // tcp_init_buffer_space: at most the window clamp.
    rcv_ssthresh_ = std::min(init_wnd, rcv_buf_);
  }
  // tcp_init_buffer_space: min3(rcv_ssthresh, rcv_wnd, TCP_INIT_CWND * advmss).
  space_ = static_cast<std::uint32_t>(
      std::min<std::uint64_t>(std::min(init_wnd, rcv_buf_), tcp_init_cwnd * adv_mss));
}

std::uint64_t RcvWindow::target(const RecvBuffer& rb, std::uint16_t rcv_mss) const {
  return target_of(rb.right_edge() - rb.contiguous_end(), rb.capacity(), rcv_mss);
}

std::uint64_t RcvWindow::target_of(std::uint64_t free, std::uint64_t full,
                                   std::uint16_t rcv_mss) const {
  if (!linux_growth_) {
    return free;  // RFC 9293 §3.8.6.2.2: RCV.BUFF - RCV.USER
  }
  // __tcp_select_window without the final ALIGN up.
  const std::uint64_t mss = std::min<std::uint64_t>(rcv_mss, full);
  std::uint64_t f = free;
  if (f < full / 2) {
    f = round_down(f, wscale_);
    if (f < full / 16 || f < mss) {
      return 0;
    }
  }
  f = std::min<std::uint64_t>(f, rcv_ssthresh_);
  if (wscale_ == 0 && mss > 0) {
    // Without window scaling: a multiple of the MSS, or the current window if
    // it is within one MSS of the free space.
    std::uint64_t w = last_window_;
    if (w + mss <= f || w > f) {
      w = f - f % mss;
    } else if (mss == full && f > w + full / 2) {
      w = f;
    }
    f = w;
  }
  return f;
}

std::uint32_t RcvWindow::compute(const RecvBuffer& rb, std::uint16_t rcv_mss) const {
  const std::uint64_t rcv_nxt = rb.contiguous_end();
  const std::uint64_t max_win = max_unscaled_window << wscale_;
  const std::uint64_t win_new = std::min(round_down(target(rb, rcv_mss), wscale_), max_win);
  const std::uint64_t edge_new = rcv_nxt + win_new;
  // Receiver SWS avoidance (RFC 9293 §3.8.6.2.2, Fr = 1/2): the edge moves
  // only by at least min(RCV.BUFF / 2, Eff.snd.MSS); otherwise it stays at
  // rcv_adv, which rounding down may pull back by less than 2^rcv_wscale
  // (RFC 7323 §2.4).
  const std::uint64_t sws = std::min<std::uint64_t>(rb.capacity() / 2, rcv_mss);
  // The window that keeps the edge at rcv_adv.
  const std::uint64_t kept =
      rcv_adv_ > rcv_nxt ? std::min(round_down(rcv_adv_ - rcv_nxt, wscale_), max_win) : 0;
  std::uint64_t win = kept;
  if (edge_new > rcv_adv_ && edge_new - rcv_adv_ >= sws) {
    win = win_new;
  } else if (kept == 0 && win_new > 0 && (win_new >= sws || rb.readable() == 0)) {
    // Keeping the edge would advertise a zero window (less than 2^wscale
    // left below rcv_adv). The edge then moves if the new window is not
    // small (>= the SWS step), or if everything was read: no read can free
    // more space, so waiting for a larger step would keep the window closed
    // for good.
    win = win_new;
  }
  return static_cast<std::uint32_t>(win);
}

SelectedWindow RcvWindow::select(const RecvBuffer& rb, std::uint16_t rcv_mss) {
  rcv_nxt_ = rb.contiguous_end();
  UTCP_DCHECK(rcv_adv_ <= rb.right_edge());
  const std::uint32_t win = compute(rb, rcv_mss);
  rcv_adv_ = std::max(rcv_adv_, rcv_nxt_ + win);
  wup_ = rcv_nxt_;
  to_zero_ = last_window_ != 0 && win == 0;
  from_zero_ = last_window_ == 0 && win != 0;
  last_window_ = win;
  return SelectedWindow{win, static_cast<std::uint16_t>(win >> wscale_)};
}

std::uint64_t RcvWindow::rcv_adv() const { return rcv_adv_; }

std::uint32_t RcvWindow::last_window() const { return last_window_; }

bool RcvWindow::went_to_zero() const { return to_zero_; }

bool RcvWindow::went_from_zero() const { return from_zero_; }

void RcvWindow::on_in_order_data(std::uint32_t len, std::uint16_t /*rcv_mss*/,
                                 const RecvBuffer& rb, std::uint64_t read_upto) {
  // tcp_grow_window, reached from tcp_event_data_recv for len >= 128.
  rcv_nxt_ = rb.contiguous_end();
  if (!linux_growth_ || len < grow_window_min_len) {
    return;
  }
  // tcp_space with the data below read_upto taken by the reader.
  const std::uint64_t edge =
      std::max(rb.right_edge(), std::min(read_upto, rcv_nxt_) + rb.capacity());
  const std::uint64_t free = edge - rcv_nxt_;
  const std::uint64_t clamp = std::min<std::uint64_t>(rb.capacity(), free);
  if (clamp <= rcv_ssthresh_) {
    return;
  }
  const std::uint64_t room = clamp - rcv_ssthresh_;
  const std::uint64_t incr = std::max(std::uint64_t{2} * adv_mss_, std::uint64_t{2} * len);
  rcv_ssthresh_ += static_cast<std::uint32_t>(std::min(room, incr));
}

bool RcvWindow::update_after_read(const RecvBuffer& rb, std::uint16_t rcv_mss) const {
  const std::uint64_t rcv_nxt = rb.contiguous_end();
  const std::uint32_t win = compute(rb, rcv_mss);
  if (!linux_update_after_read_) {
    // RFC 9293 §3.8.6.2.2: the edge can move by at least min(RCV.BUFF / 2,
    // MSS), which is when compute() advances it.
    return rcv_nxt + win > rcv_adv_;
  }
  // tcp_cleanup_rbuf: ACK if the window can at least double. The current
  // window is the one the peer was last told, less the data received since
  // (tcp_receive_window: rcv_wup + rcv_wnd - rcv_nxt).
  const std::uint64_t told = wup_ + last_window_;
  const std::uint64_t cur = told > rcv_nxt ? told - rcv_nxt : 0;
  if (2 * cur > rb.capacity()) {
    return false;
  }
  return win != 0 && win >= 2 * cur;
}

RcvWindowView RcvWindow::ack_view(const RecvBuffer& rb, std::uint16_t rcv_mss,
                                  std::uint64_t read_upto) const {
  const std::uint64_t max_win = max_unscaled_window << wscale_;
  const std::uint64_t rcv_nxt = rb.contiguous_end();
  // The free space with the data below read_upto read (see the header).
  const std::uint64_t edge = std::max(rb.right_edge(), std::min(read_upto, rcv_nxt) + rb.capacity());
  const std::uint64_t free = edge - rcv_nxt;
  RcvWindowView v;
  v.unread = rb.readable() > 0;
  v.ooo_held = !rb.ooo_ranges().empty();
  // __tcp_select_window(sk) >= tp->rcv_wnd, both rounded down here (the
  // unscaled SYN window too).
  v.not_shrinking = std::min(round_down(target_of(free, rb.capacity(), rcv_mss), wscale_),
                             max_win) >= round_down(last_window_, wscale_);
  v.low_space = free < std::uint64_t{rb.capacity()} / 2;
  return v;
}

void RcvWindow::rtt_update(Duration sample, bool win_dep, bool queue_empty) {
  // tcp_rcv_rtt_update: a minimum filter for window samples, an 1/8 EWMA for
  // timestamp samples taken while the receive queue is empty.
  const Duration m = sample * 8;
  if (rtt8_ == Duration::zero() || m < rtt8_) {
    rtt8_ = m;
    return;
  }
  if (win_dep || !queue_empty) {
    return;
  }
  rtt8_ = rtt8_ - rtt8_ / 8 + sample;
}

void RcvWindow::on_data_rtt(Time now, std::uint64_t rcv_nxt, std::optional<Duration> ts_rtt) {
  // Linux takes the timestamp sample before the segment is queued, so the
  // queue-empty test uses RCV.NXT before this segment: the value of the
  // previous call.
  const std::uint64_t before = data_rcv_nxt_;
  data_rcv_nxt_ = rcv_nxt;
  rcv_nxt_ = std::max(rcv_nxt_, rcv_nxt);
  if (!space_time_) {
    space_time_ = now;
    space_seq_ = read_off_;
  }
  // tcp_rcv_rtt_measure_ts.
  if (ts_rtt && *ts_rtt > Duration::zero()) {
    rtt_update(*ts_rtt, false, before == read_off_);
  }
  // tcp_rcv_rtt_measure: the time to receive one window of data.
  if (rtt_time_) {
    if (rcv_nxt < rtt_seq_) {
      return;
    }
    Duration d = now - *rtt_time_;
    if (d <= Duration::zero()) {
      d = Duration{1};
    }
    rtt_update(d, true, false);
  }
  rtt_seq_ = rcv_nxt + last_window_;
  rtt_time_ = now;
}

std::optional<std::uint32_t> RcvWindow::rcvbuf_grow(std::uint32_t copied) {
  // tcp_rcvbuf_grow.
  const std::uint32_t old = space_;
  space_ = copied;
  if (!autotune_) {
    return std::nullopt;
  }
  std::uint64_t rcvwin = std::uint64_t{copied} << 1;  // "DRS is always one RTT late"
  const Duration rtt = rcv_rtt();
  std::uint64_t grow = 0;
  if (rtt < rcvbuf_low_rtt) {
    // Small RTT: grow by rcvwin * rtt / tcp_rcvbuf_low_rtt.
    grow = rcvwin * static_cast<std::uint64_t>(rtt.count()) /
           static_cast<std::uint64_t>(rcvbuf_low_rtt.count());
  } else if (old > 0 && copied > old) {
    // Slow start: room for the sender to double its rate.
    std::uint64_t prod = 0;
    if (__builtin_mul_overflow(rcvwin << 1, std::uint64_t{copied - old}, &prod)) {
      grow = std::numeric_limits<std::uint32_t>::max();
    } else {
      grow = prod / old;
    }
  }
  rcvwin += grow;
  const auto rcvbuf = static_cast<std::uint32_t>(std::min<std::uint64_t>(rcvwin, rcv_buf_max_));
  if (rcvbuf > rcv_buf_) {
    rcv_buf_ = rcvbuf;
    return rcvbuf;
  }
  return std::nullopt;
}

std::optional<std::uint32_t> RcvWindow::on_read(Time now, std::uint64_t read_offset) {
  // tcp_rcv_space_adjust.
  read_off_ = read_offset;
  if (rtt8_ == Duration::zero()) {
    return std::nullopt;
  }
  if (!space_time_) {
    space_time_ = now;
    space_seq_ = read_offset;
    return std::nullopt;
  }
  if (now - *space_time_ < rcv_rtt()) {
    return std::nullopt;
  }
  // Bytes read in the last RTT, less the bytes still queued.
  const std::uint64_t got = read_offset - space_seq_;
  const std::uint64_t inq = rcv_nxt_ > read_offset ? rcv_nxt_ - read_offset : 0;
  std::optional<std::uint32_t> grown;
  if (got > inq && got - inq > space_) {
    grown = rcvbuf_grow(static_cast<std::uint32_t>(
        std::min<std::uint64_t>(got - inq, std::numeric_limits<std::uint32_t>::max())));
  }
  space_seq_ = read_offset;
  space_time_ = now;
  return grown;
}

Duration RcvWindow::rcv_rtt() const { return rtt8_ / 8; }

std::uint32_t RcvWindow::rcv_space() const { return space_; }

std::uint32_t RcvWindow::rcv_ssthresh() const { return linux_growth_ ? rcv_ssthresh_ : rcv_buf_; }

std::uint32_t RcvWindow::rcv_buf() const { return rcv_buf_; }

}  // namespace utcp
