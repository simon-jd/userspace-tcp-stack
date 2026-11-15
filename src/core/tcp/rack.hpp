// RACK loss detection (RFC 8985 §6; Linux 7.0 tcp_recovery.c and
// tcp_rack_advance in tcp_input.c) and the send-time FIFO it walks
// (M2-DESIGN §1.5, §1.6). Used by LossRecovery (recovery.cpp) when rack_tlp
// is on.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

#include "core/tcp/send_queue.hpp"
#include "utcp/time.hpp"

namespace utcp {

// Segments in order of their last transmission (RFC 8985 §6.1; Linux
// tsorted_sent_queue, moved to the tail on every transmission,
// tcp_update_skb_after_send). One entry per transmission: the TxSegs it
// covered then ([off, off + len), a bare FIN as one unit) with that
// transmission's tx_count. A TxSeg is live in the FIFO while it is neither
// SACKed nor lost-awaiting-retransmission (lost without a retransmission in
// flight; Linux skips those, tcp_recovery.c:71-73, and drops the ones RACK
// marks, :87); it belongs to the entry whose range holds its offset and
// whose tx_count equals its own. A split part (retransmit_seg's split,
// tcp_fragment, which inserts the tail right after the head) or a trimmed
// head (tcp_trim_head) stays in its entry. Entries without a live TxSeg are
// dead: popped at the front and skipped elsewhere; when an append leaves more
// than 2 * packets_out + 64 entries they are filtered out, so memory is
// bounded by the transmissions in flight.
class SentFifo {
public:
  struct Entry {
    std::uint64_t off = 0;
    std::uint32_t len = 0;  // payload bytes at the transmission; 0 for a bare FIN
    std::uint16_t tx_count = 0;
    Time t;  // the transmission's time (TxSeg::last_tx then)
  };

  // `seg` was just transmitted (SendQueue::on_transmit). Entries are kept in
  // (time, offset) order with the entries of one instant disjoint: an append
  // at the tail's time but a lower offset goes before those above it, and a
  // part of a transmission of the same instant resent at once splits that
  // entry around it (RACK compares transmissions by time, then end offset,
  // tcp_skb_sent_after).
  void on_transmit(const SendQueue& q, const TxSeg& seg);
  // Rebuilt from the live TxSegs sorted by (last_tx, off) (after a PMTU split).
  void rebuild(const SendQueue& q);
  void clear() { fifo_.clear(); }

  [[nodiscard]] static bool live(const TxSeg& s) {
    return !s.sacked && !(s.lost && !s.retrans_inflight);
  }

  // Calls fn(const TxSeg&) for every live TxSeg in FIFO order until fn returns
  // false. Pops dead entries at the front first. fn may mark the TxSeg lost.
  template <class Fn>
  void walk(const SendQueue& q, Fn&& fn) {
    pop_dead_front(q);
    for (const Entry& e : fifo_) {
      const std::span<const TxSeg> segs = q.segs();
      for (std::size_t i = first_in(segs, e.off); i < segs.size() && in_range(e, segs[i]); ++i) {
        if (segs[i].tx_count == e.tx_count && live(segs[i]) && !fn(segs[i])) {
          return;
        }
      }
    }
  }

  // The offsets of the live TxSegs in FIFO order (tests).
  [[nodiscard]] std::vector<std::uint64_t> live_offsets(const SendQueue& q) const;
  [[nodiscard]] std::size_t size() const { return fifo_.size(); }

private:
  static std::size_t first_in(std::span<const TxSeg> segs, std::uint64_t off);
  static bool in_range(const Entry& e, const TxSeg& s) {
    return s.off >= e.off && s.off < e.off + (e.len == 0 ? 1u : e.len);
  }
  [[nodiscard]] static bool entry_live(const SendQueue& q, const Entry& e);
  void pop_dead_front(const SendQueue& q);
  void filter(const SendQueue& q);

  std::deque<Entry> fifo_;
};

struct RackState {  // Linux tp->rack (RFC 8985 §6.1 names in comments)
  Time xmit_ts;            // RACK.xmit_ts: last transmission of the most recently sent delivered TxSeg
  std::uint64_t end = 0;   // RACK.end_seq: its end offset
  Duration rtt{-1};        // RACK.rtt: from that delivery; -1 before any
  bool advanced = false;   // RACK.xmit_ts moved since the last detection
  std::uint8_t reo_wnd_steps = 1;    // RACK.reo_wnd_mult
  std::uint8_t reo_wnd_persist = 0;  // RACK.reo_wnd_persist
  bool dsack_seen = false;
  std::uint64_t last_delivered = 0;
};

// Linux tcp_skb_sent_after: (t1, end1) sent after (t2, end2): later time,
// or the same time and a higher end offset.
[[nodiscard]] constexpr bool sent_after(Time t1, Time t2, std::uint64_t end1, std::uint64_t end2) {
  return t1 > t2 || (t1 == t2 && end1 > end2);
}

// tcp_rack_advance: TxSeg `seg` was newly delivered at `now`. A retransmitted
// TxSeg delivered within min_rtt of its last transmission is ambiguous (the
// original may have arrived) and skipped. The caller skips a cumulatively
// acknowledged one whose ACK's TSecr predates its last transmission
// (tcp_skb_spurious_retrans).
void rack_advance(RackState& r, const TxSeg& seg, Time now, Duration min_rtt);

// tcp_rack_reo_wnd: 0 if no reordering was seen and either the state is
// Recovery or Loss (`in_recovery`) or sacked_out >= reordering; else
// min(min_rtt / 4 * reo_wnd_steps, srtt). RFC 8985 §6.2 step 4.
[[nodiscard]] Duration rack_reo_wnd(const RackState& r, std::uint32_t reord_seen, bool in_recovery,
                                    std::uint32_t sacked_out, std::uint32_t reordering,
                                    Duration min_rtt, Duration srtt);

// tcp_rack_detect_loss: walks the FIFO while the TxSeg was sent before
// RACK.xmit_ts; remaining = rack.rtt + reo_wnd - (now - last_tx); <= 0 marks it
// lost. Returns the largest positive remaining time (0: none).
Duration rack_detect_loss(RackState& r, SentFifo& fifo, SendQueue& q, Time now, Duration reo_wnd);

// tcp_rack_mark_lost's REO deadline for a remaining time `timeout` > 0: now +
// timeout + 2 ms (TCP_TIMEOUT_MIN_US) rounded up to whole milliseconds
// (usecs_to_jiffies at HZ 1000), at most now + `rto` (the max_when of
// inet_csk_reset_xmit_timer, icsk_rto). No pacing delay.
[[nodiscard]] Time rack_reo_deadline(Time now, Duration timeout, Duration rto);

}  // namespace utcp
