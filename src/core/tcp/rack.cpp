#include "core/tcp/rack.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>

namespace utcp {

std::size_t SentFifo::first_in(std::span<const TxSeg> segs, std::uint64_t off) {
  const auto it = std::lower_bound(segs.begin(), segs.end(), off,
                                   [](const TxSeg& s, std::uint64_t o) { return s.off < o; });
  return static_cast<std::size_t>(it - segs.begin());
}

bool SentFifo::entry_live(const SendQueue& q, const Entry& e) {
  const std::span<const TxSeg> segs = q.segs();
  for (std::size_t i = first_in(segs, e.off); i < segs.size() && in_range(e, segs[i]); ++i) {
    if (segs[i].tx_count == e.tx_count && live(segs[i])) {
      return true;
    }
  }
  return false;
}

void SentFifo::pop_dead_front(const SendQueue& q) {
  while (head_ < fifo_.size() && !entry_live(q, fifo_[head_])) {
    ++head_;
  }
  if (head_ && head_ >= size()) {
    fifo_.erase(fifo_.begin(), fifo_.begin() + static_cast<std::ptrdiff_t>(head_));
    head_ = 0;
  }
}

void SentFifo::filter(const SendQueue& q) {
  auto keep = fifo_.begin();
  for (const Entry& e : entries()) {
    if (entry_live(q, e)) *keep++ = e;
  }
  fifo_.erase(keep, fifo_.end());
  head_ = 0;
}

void SentFifo::on_transmit(const SendQueue& q, const TxSeg& seg) {
  // ACK processing need not walk RACK when all data has drained. Before
  // growing, reclaim stale transmissions left by those ACKs.
  if (fifo_.size() == fifo_.capacity()) pop_dead_front(q);
  const Entry e{seg.off, seg.len, seg.tx_count, seg.last_tx};
  const auto span_of = [](const Entry& x) -> std::uint64_t { return x.len == 0 ? 1u : x.len; };
  // Times only grow, so the entries of this instant are at the tail; they are
  // kept sorted by offset with disjoint ranges (RACK orders transmissions by
  // time, then end offset, tcp_skb_sent_after). Usually the new entry goes
  // last; a retransmission in the same instant at a lower offset goes before.
  std::size_t pos = fifo_.size();
  while (pos > head_ && fifo_[pos - 1].t == e.t && fifo_[pos - 1].off > e.off) {
    --pos;
  }
  if (pos > head_ && fifo_[pos - 1].t == e.t) {
    // A part of a transmission of this same instant is resent: that entry's
    // range holds e's; split it around e.
    const Entry prev = fifo_[pos - 1];
    const std::uint64_t prev_end = prev.off + span_of(prev);
    const std::uint64_t e_end = e.off + span_of(e);
    if (e.off < prev_end) {
      const auto at = fifo_.begin() + static_cast<std::ptrdiff_t>(pos - 1);
      if (prev.off == e.off) {
        fifo_.erase(at);
        --pos;
      } else {
        at->len = static_cast<std::uint32_t>(e.off - prev.off);
      }
      if (e_end < prev_end) {
        Entry rest = prev;
        rest.off = e_end;
        rest.len = static_cast<std::uint32_t>(prev_end - e_end);
        fifo_.insert(fifo_.begin() + static_cast<std::ptrdiff_t>(pos), rest);
      }
    }
  }
  fifo_.insert(fifo_.begin() + static_cast<std::ptrdiff_t>(pos), e);
  // M2-DESIGN §1.5: at most 2 * packets_out + 64 entries after each append.
  const std::size_t bound = 2 * std::size_t{q.counters().packets_out} + 64;
  if (size() > bound) {
    filter(q);
  }
}

void SentFifo::rebuild(const SendQueue& q) {
  clear();
  for (const TxSeg& s : q.segs()) {
    if (live(s)) {
      fifo_.push_back(Entry{s.off, s.len, s.tx_count, s.last_tx});
    }
  }
  // The live TxSeg offsets are unique, including a bare FIN at end().
  std::sort(fifo_.begin(), fifo_.end(), [](const Entry& a, const Entry& b) {
    return a.t < b.t || (a.t == b.t && a.off < b.off);
  });
}

std::vector<std::uint64_t> SentFifo::live_offsets(const SendQueue& q) const {
  std::vector<std::uint64_t> out;
  const std::span<const TxSeg> segs = q.segs();
  for (const Entry& e : entries()) {
    for (std::size_t i = first_in(segs, e.off); i < segs.size() && in_range(e, segs[i]); ++i) {
      if (segs[i].tx_count == e.tx_count && live(segs[i])) {
        out.push_back(segs[i].off);
      }
    }
  }
  return out;
}

void rack_advance(RackState& r, const TxSeg& seg, Time now, Duration min_rtt) {
  const Duration rtt = now - seg.last_tx;
  if (seg.ever_retrans && rtt < min_rtt) {
    // Ambiguous: the original or an earlier retransmission may be the one
    // delivered; the original can be delayed up to aRTT + min_rtt.
    return;
  }
  r.advanced = true;
  r.rtt = rtt;
  if (sent_after(seg.last_tx, r.xmit_ts, seg.end(), r.end)) {
    r.xmit_ts = seg.last_tx;
    r.end = seg.end();
  }
}

Duration rack_reo_wnd(const RackState& r, std::uint32_t reord_seen, bool in_recovery,
                      std::uint32_t sacked_out, std::uint32_t reordering, Duration min_rtt,
                      Duration srtt) {
  if (reord_seen == 0) {
    // No reordering seen: as aggressive as the DupThresh rule in recovery
    // or once DupThresh packets are SACKed.
    if (in_recovery || sacked_out >= reordering) {
      return Duration{0};
    }
  }
  // min_rtt / 4 per step, up to srtt (min_rtt is Duration::max() before any
  // sample: then srtt).
  const Duration quarter = min_rtt / 4;
  const auto steps = static_cast<Duration::rep>(r.reo_wnd_steps);
  if (steps == 0 || quarter > srtt / steps) {
    return std::max(srtt, Duration{0});
  }
  return std::min(quarter * steps, srtt);
}

Duration rack_detect_loss(RackState& r, SentFifo& fifo, SendQueue& q, Time now, Duration reo_wnd) {
  Duration timeout{0};
  fifo.walk(q, [&](const TxSeg& s) {
    if (!sent_after(r.xmit_ts, s.last_tx, r.end, s.end())) {
      return false;  // sent at or after the most recently delivered one
    }
    // tcp_rack_skb_timeout: not (S)ACKed within RACK.rtt + reo_wnd.
    const Duration remaining = r.rtt + reo_wnd - (now - s.last_tx);
    if (remaining <= Duration{0}) {
      q.mark_lost(s.off);
    } else {
      timeout = std::max(timeout, remaining);
    }
    return true;
  });
  return timeout;
}

Time rack_reo_deadline(Time now, Duration timeout, Duration rto) {
  constexpr Duration jiffy = std::chrono::milliseconds{1};
  constexpr Duration min_slack = std::chrono::milliseconds{2};  // TCP_TIMEOUT_MIN_US
  Duration d = timeout + min_slack;
  d = (d + jiffy - Duration{1}) / jiffy * jiffy;  // usecs_to_jiffies rounds up
  return now + std::min(d, rto);
}

}  // namespace utcp
