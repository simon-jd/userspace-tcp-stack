#include "core/tcp/sack_scoreboard.hpp"

#include <algorithm>
#include <cstddef>
#include <span>

namespace utcp {
namespace {

// Index of the first TxSeg with off >= `off`.
std::size_t first_at_or_above(std::span<const TxSeg> segs, std::uint64_t off) {
  const auto it = std::lower_bound(segs.begin(), segs.end(), off,
                                   [](const TxSeg& s, std::uint64_t o) { return s.off < o; });
  return static_cast<std::size_t>(it - segs.begin());
}

// RFC 6675 §4 IsLost threshold: DupThresh SACKed segments, or more than
// (DupThresh - 1) * SMSS SACKed bytes.
bool threshold_reached(std::uint32_t count, std::uint64_t bytes, std::uint32_t dupthresh,
                       std::uint32_t smss) {
  return count >= dupthresh ||
         bytes > std::uint64_t{dupthresh > 0 ? dupthresh - 1 : 0} * std::uint64_t{smss};
}

}  // namespace

void Rfc6675Scoreboard::reset_recovery() {
  dupacks_ = 0;
  high_rxt_ = 0;
  rescue_rxt_.reset();
  rescue_named_.reset();
}

void Rfc6675Scoreboard::on_ack(bool una_advanced, std::uint32_t newly_sacked, bool counting) {
  if (una_advanced) {
    dupacks_ = 0;  // RFC 6675 §5: a cumulative ACK resets DupAcks
  }
  if (counting && newly_sacked > 0 && dupacks_ < 0xffff'ffffu) {
    ++dupacks_;  // §2 DupAck, counted after the reset (§5)
  }
}

std::uint32_t Rfc6675Scoreboard::mark_lost(SendQueue& q, std::uint32_t dupthresh,
                                           std::uint32_t smss) {
  const std::span<const TxSeg> segs = q.segs();
  if (segs.empty()) {
    return 0;
  }
  const std::size_t start = first_at_or_above(segs, std::max(lost_below_, q.una()));
  std::uint32_t count = 0;
  std::uint64_t bytes = 0;
  for (std::size_t i = segs.size(); i > start; --i) {
    const TxSeg& s = segs[i - 1];
    if (!s.sacked) {
      continue;
    }
    ++count;
    bytes += s.len;
    if (!threshold_reached(count, bytes, dupthresh, smss)) {
      continue;
    }
    // Every segment below segs[i - 1] has the threshold above it.
    const std::uint64_t point = s.off;
    std::uint32_t marked = 0;
    for (std::size_t j = start; j + 1 < i; ++j) {
      const TxSeg& t = q.segs()[j];
      if (!t.sacked && !t.lost) {
        q.mark_lost(t.off);
        ++marked;
      }
    }
    lost_below_ = point;
    return marked;
  }
  return 0;
}

bool Rfc6675Scoreboard::is_lost(const SendQueue& q, std::uint64_t off, std::uint32_t dupthresh,
                                std::uint32_t smss) {
  const std::span<const TxSeg> segs = q.segs();
  std::uint32_t count = 0;
  std::uint64_t bytes = 0;
  for (std::size_t i = first_at_or_above(segs, off) + 1; i < segs.size(); ++i) {
    if (segs[i].sacked) {
      ++count;
      bytes += segs[i].len;
    }
  }
  return threshold_reached(count, bytes, dupthresh, smss);
}

void Rfc6675Scoreboard::on_enter_recovery(std::uint64_t head_end) {
  dupacks_ = 0;
  high_rxt_ = head_end;
  rescue_rxt_ = head_end;
  rescue_named_.reset();
}

std::optional<std::uint64_t> Rfc6675Scoreboard::next_seg(const SendQueue& q, std::uint64_t una,
                                                         std::uint64_t wnd_end) {
  rescue_named_.reset();
  const std::span<const TxSeg> segs = q.segs();
  if (segs.empty()) {
    return std::nullopt;
  }
  const auto in_window = [&](const TxSeg& s) { return s.off == q.una() || s.off < wnd_end; };
  // The highest SACKed segment.
  std::size_t top = segs.size();
  while (top > 0 && !segs[top - 1].sacked) {
    --top;
  }
  // Rule 3: unSACKed, above HighRxt (rule 1.a) and below the highest SACK
  // (rule 1.b), IsLost not required.
  if (top > 0) {
    const std::uint64_t high_sack = segs[top - 1].end();
    for (std::size_t i = first_at_or_above(segs, high_rxt_); i < top; ++i) {
      const TxSeg& s = segs[i];
      if (s.end() > high_sack) {
        break;
      }
      if (!s.sacked && !s.retrans_inflight && s.len > 0) {
        if (!in_window(s)) {
          return std::nullopt;
        }
        return s.off;
      }
    }
  }
  // Rule 4: the rescue retransmission, once per recovery (RFC 6675 (4.a)).
  if (rescue_rxt_ && una <= *rescue_rxt_) {
    return std::nullopt;
  }
  for (std::size_t i = segs.size(); i > 0; --i) {
    const TxSeg& s = segs[i - 1];
    if (s.sacked) {
      continue;
    }
    // The highest unSACKed segment; nothing to rescue if it already has a
    // retransmission in flight.
    if (s.retrans_inflight || !in_window(s)) {
      return std::nullopt;
    }
    rescue_named_ = s.off;
    return s.off;
  }
  return std::nullopt;
}

void Rfc6675Scoreboard::on_retransmit(const TxSeg& seg, std::uint64_t recover) {
  if (rescue_named_ && *rescue_named_ == seg.off) {
    rescue_rxt_ = recover;  // (C.4): RescueRxt = RecoveryPoint; HighRxt unchanged
    rescue_named_.reset();
    return;
  }
  high_rxt_ = std::max(high_rxt_, seg.end());  // (C.3)
}

}  // namespace utcp
