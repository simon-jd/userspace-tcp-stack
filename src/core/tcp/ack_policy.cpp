// When to acknowledge received data (RFC 9293 §3.8.6.3, RFC 5681 §4.2; Linux
// 7.0 tcp_event_data_recv, __tcp_ack_snd_check, tcp_send_delayed_ack,
// tcp_dec_quickack_mode, tcp_delack_timer_handler; DESIGN §4.10).
//
// Not modelled: pingpong (interactive) mode, the PSH-based ICSK_ACK_PUSHED
// flags, SACK compression (tcp_comp_sack_*), and the "right edge advances far
// enough" condition of __tcp_ack_snd_check.
#include "core/tcp/ack_policy.hpp"

#include <algorithm>

namespace utcp {
namespace {

constexpr std::uint32_t tcp_mss_default = 536;  // TCP_MSS_DEFAULT
constexpr std::uint32_t tcp_min_mss = 88;       // TCP_MIN_MSS
// tcp_send_delayed_ack: max_ato = HZ / 2 outside pingpong mode.
constexpr Duration max_ato_default = std::chrono::milliseconds{500};

}  // namespace

AckPolicy::AckPolicy(const TcpConfig& cfg)
    : delack_max_(cfg.delack_max),
      ato_min_(cfg.delack_ato_min),
      ack_every_(cfg.ack_every_full_segments),
      quickack_max_(cfg.quickack_max),
      adaptive_ato_(cfg.delack_ato == DelackAto::adaptive),
      linux_quickack_(cfg.quickack == Quickack::linux),
      dsack_(cfg.dsack) {
  if (!adaptive_ato_) {
    ato_ = delack_max_;
  }
}

void AckPolicy::init(std::uint16_t adv_mss, std::uint16_t mss_cache, std::uint32_t rcv_wnd) {
  // tcp_initialize_rcv_mss.
  adv_mss_ = adv_mss;
  std::uint32_t hint = std::min<std::uint32_t>(adv_mss, mss_cache);
  hint = std::min(hint, rcv_wnd / 2);
  hint = std::min(hint, tcp_mss_default);
  hint = std::max(hint, tcp_min_mss);
  rcv_mss_ = static_cast<std::uint16_t>(hint);
}

void AckPolicy::measure_rcv_mss(std::uint32_t len, std::uint16_t gso_size) {
  // tcp_measure_rcv_mss. The second branch of Linux adds the TCP header
  // length and compares with TCP_MSS_DEFAULT + 20, and also accepts segments
  // of TCP_MIN_MSS + 20 without PSH, FIN, SYN or URG; the policy sees payload
  // lengths only, so it takes payload >= TCP_MSS_DEFAULT.
  const std::uint32_t lss = last_seg_size_;
  last_seg_size_ = 0;
  const std::uint32_t l = gso_size != 0 ? gso_size : len;
  if (l >= rcv_mss_) {
    rcv_mss_ = static_cast<std::uint16_t>(std::min<std::uint32_t>(l, adv_mss_));
  } else if (l >= tcp_mss_default) {
    last_seg_size_ = l;
    if (l == lss) {
      rcv_mss_ = static_cast<std::uint16_t>(l);
    }
  }
}

void AckPolicy::incr_quickack(std::uint32_t rcv_wnd) {
  // tcp_incr_quickack.
  if (!linux_quickack_) {
    return;
  }
  std::uint32_t q = rcv_wnd / (2u * std::max<std::uint32_t>(rcv_mss_, 1));
  if (q == 0) {
    q = 2;
  }
  q = std::min(q, quickack_max_);
  quick_ = std::max(quick_, q);
}

void AckPolicy::on_data(Time now, std::uint32_t len, std::uint16_t gso_size,
                        const InsertResult& r, std::uint32_t rcv_wnd, Duration rto) {
  rto_ = rto;
  if (len == 0) {
    return;
  }
  rcv_nxt_ = r.contiguous_end;
  pending_ = true;  // inet_csk_schedule_ack
  if (r.out_of_order) {
    // RFC 5681 §4.2: an immediate duplicate ACK for out-of-order data.
    measure_rcv_mss(len, gso_size);
    now_ = true;
  } else if (r.advanced) {
    // tcp_event_data_recv.
    measure_rcv_mss(len, gso_size);
    if (!seen_data_) {
      // The first data segment starts the delayed-ACK engine in quick-ack
      // mode.
      seen_data_ = true;
      incr_quickack(rcv_wnd);
      if (adaptive_ato_) {
        ato_ = ato_min_;
      }
    } else {
      const Duration m = now - lrcvtime_;
      if (adaptive_ato_ && m <= ato_min_ / 2) {
        ato_ = ato_ / 2 + ato_min_ / 2;
      } else if (adaptive_ato_ && m < ato_) {
        ato_ = std::min({ato_ / 2 + m, rto, delack_max_});
      } else if (m > rto) {
        // A gap above the RTO: the sender restarts, ACK quickly again.
        incr_quickack(rcv_wnd);
      }
    }
    lrcvtime_ = now;
    // RFC 5681 §4.2: ACK at once when the segment fills all or part of a gap.
    if (r.filled_hole || r.ooo_held) {
      now_ = true;
    }
  } else {
    // Nothing new (data below RCV.NXT, or dropped at a zero window): Linux
    // tcp_data_queue enters quick-ack mode and ACKs.
    enter_quickack(rcv_wnd);
  }
  if (r.duplicate && dsack_) {
    now_ = true;  // the D-SACK goes out in the next ACK (RFC 2883 §4)
  }
  if (need() == AckNeed::delayed) {
    schedule_delayed(now);
  }
}

void AckPolicy::schedule_delayed(Time now) {
  // tcp_send_delayed_ack.
  Duration d = ato_;
  if (adaptive_ato_ && d > ato_min_) {
    Duration max_ato = max_ato_default;
    if (srtt_ > Duration::zero()) {
      max_ato = std::min(max_ato, std::max(srtt_, ato_min_));
    }
    d = std::min(d, max_ato);
  }
  d = std::min(d, delack_max_);
  Time deadline = now + d;
  if (timer_) {
    // A timer about to expire sends the ACK now; otherwise the earlier
    // deadline stays.
    if (adaptive_ato_ && deadline_ <= now + d / 4) {
      now_ = true;
      return;
    }
    deadline = std::min(deadline, deadline_);
  }
  timer_ = true;
  deadline_ = deadline;
}

void AckPolicy::ack_now() { now_ = true; }

void AckPolicy::enter_quickack(std::uint32_t rcv_wnd) {
  // tcp_enter_quickack_mode; the call sites schedule an ACK.
  incr_quickack(rcv_wnd);
  if (adaptive_ato_) {
    ato_ = ato_min_;
  }
  pending_ = true;
  now_ = true;
}

void AckPolicy::on_rcv_ssthresh_grew() {
  if (linux_quickack_) {
    quick_ |= 1u;
  }
}

void AckPolicy::set_srtt(Duration srtt) { srtt_ = srtt; }

AckNeed AckPolicy::need() const {
  if (now_) {
    return AckNeed::now;
  }
  if (!pending_) {
    return AckNeed::none;
  }
  if (in_quickack_mode()) {
    return AckNeed::now;
  }
  // __tcp_ack_snd_check: more than (ack_every_full_segments - 1) full
  // segments unacknowledged ("more than one full frame" for 2).
  const std::uint64_t full = ack_every_ > 1 ? std::uint64_t{ack_every_ - 1} * rcv_mss_ : 0;
  if (rcv_nxt_ - rcv_wup_ > full) {
    return AckNeed::now;
  }
  return AckNeed::delayed;
}

Time AckPolicy::delack_deadline() const { return deadline_; }

void AckPolicy::on_ack_sent(Time /*now*/) {
  // tcp_event_ack_sent: tcp_dec_quickack_mode, then the delack timer stops.
  if (linux_quickack_ && quick_ > 0) {
    const std::uint32_t pkts = pending_ ? 1 : 0;
    if (pkts >= quick_) {
      quick_ = 0;
      if (adaptive_ato_) {
        ato_ = ato_min_;  // leaving quick-ack mode deflates ato
      }
    } else {
      quick_ -= pkts;
    }
  }
  pending_ = false;
  now_ = false;
  timer_ = false;
  deadline_ = Time::never();
  rcv_wup_ = rcv_nxt_;
}

void AckPolicy::on_delack_timer(Time now) {
  // tcp_delack_timer_handler (no pingpong mode).
  if (!timer_ || now < deadline_) {
    return;
  }
  timer_ = false;
  deadline_ = Time::never();
  if (pending_) {
    if (adaptive_ato_) {
      ato_ = std::min({ato_ * 2, rto_, delack_max_});  // delayed ACK missed: inflate ato
    }
    now_ = true;
  }
}

std::uint16_t AckPolicy::rcv_mss() const { return rcv_mss_; }

Duration AckPolicy::ato() const { return ato_; }

bool AckPolicy::in_quickack_mode() const { return linux_quickack_ && quick_ > 0; }

}  // namespace utcp
