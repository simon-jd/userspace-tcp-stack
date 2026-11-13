#include "core/tcp/send_queue.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include "utcp/check.hpp"

namespace utcp {

SendQueue::SendQueue(ChunkPool& pool, std::uint32_t capacity)
    : ring_(pool, capacity, 0), capacity_(capacity) {}

std::size_t SendQueue::write(std::span<const std::byte> data) {
  const std::size_t n = std::min<std::size_t>(data.size(), free_space());
  if (n == 0) {
    return 0;
  }
  const std::size_t written = ring_.write_at(end_, data.first(n));
  end_ += written;
  return written;
}

std::uint64_t SendQueue::una() const { return ring_.begin(); }
std::uint64_t SendQueue::nxt() const { return nxt_; }
std::uint64_t SendQueue::end() const { return end_; }

std::uint32_t SendQueue::free_space() const {
  const std::uint64_t held = end_ - una();
  return held >= capacity_ ? 0u : static_cast<std::uint32_t>(capacity_ - held);
}

std::uint32_t SendQueue::capacity() const { return capacity_; }

void SendQueue::set_capacity(std::uint32_t capacity) {
  capacity_ = capacity;
  // Bytes already written above the new limit stay readable (ByteRing);
  // free_space() stops further writes.
  ring_.set_capacity(capacity);
}

void SendQueue::copy_out(std::uint64_t off, std::span<std::byte> dst) const {
  UTCP_CHECK(una() <= off && off + dst.size() <= end_);
  ring_.read_at(off, dst);
}

std::size_t SendQueue::index_of(std::uint64_t off) const {
  const auto first = segs_.begin() + static_cast<std::ptrdiff_t>(head_);
  const auto it = std::lower_bound(first, segs_.end(), off,
                                   [](const TxSeg& s, std::uint64_t o) { return s.off < o; });
  return static_cast<std::size_t>(it - segs_.begin());
}

TxSeg* SendQueue::find_mut(std::uint64_t off) {
  const std::size_t i = index_of(off);
  if (i < segs_.size() && segs_[i].off == off) {
    // A bare FIN shares its offset with nothing else: every other TxSeg
    // ending at end() carries payload and starts below it.
    return &segs_[i];
  }
  return nullptr;
}

const TxSeg* SendQueue::find(std::uint64_t off) const {
  const std::size_t i = index_of(off);
  return i < segs_.size() && segs_[i].off == off ? &segs_[i] : nullptr;
}

// Linux tcp_rate_skb_sent, part 2: the snapshot the segment carries. Without
// a prior rate_on_send there is no snapshot (rate_used stands for Linux's
// delivered_mstamp == 0).
void SendQueue::snapshot(TxSeg& seg, const RateState& rate) const {
  seg.delivered = rate.delivered;
  seg.delivered_time = rate.delivered_time;
  seg.first_tx_time = rate.first_tx_time;
  seg.app_limited = rate.app_limited != 0;
  seg.rate_used = !rate.has_sent;
}

TxSeg& SendQueue::on_transmit(std::uint64_t off, std::uint32_t len, bool fin, Time now,
                              const RateState& rate) {
  const bool new_data = off == nxt_ && (len > 0 || !fin_sent_);
  if (new_data) {
    UTCP_CHECK(len > 0 || fin);
    UTCP_CHECK(!fin_sent_);
    UTCP_CHECK(off + len <= end_);
    UTCP_CHECK(!fin || off + len == end_);  // the FIN follows the last byte
    TxSeg seg;
    seg.id = next_id_++;
    seg.off = off;
    seg.len = len;
    seg.fin = fin;
    seg.tx_count = 1;
    seg.first_tx = now;
    seg.last_tx = now;
    snapshot(seg, rate);
    segs_.push_back(seg);
    nxt_ += len;
    fin_sent_ = fin;
    ++ctr_.packets_out;
    ctr_.bytes_sent += len;
    return segs_.back();
  }
  // Retransmission of an existing TxSeg (Linux tcp_retransmit_skb: TCPCB_RETRANS).
  TxSeg* seg = find_mut(off);
  UTCP_CHECK(seg != nullptr);
  UTCP_CHECK(seg->len == len && seg->fin == fin);
  UTCP_CHECK(!seg->sacked);
  if (seg->tx_count < 0xffff) {
    ++seg->tx_count;
  }
  seg->last_tx = now;
  seg->ever_retrans = true;
  if (!seg->retrans_inflight) {
    seg->retrans_inflight = true;
    ++ctr_.retrans_out;
  }
  ctr_.bytes_sent += len;
  ctr_.bytes_retrans += len;
  snapshot(*seg, rate);
  return *seg;
}

AckedSummary SendQueue::on_cumulative_ack(std::uint64_t new_una, Time now, DeliveredFn fn) {
  return on_cumulative_ack(new_una, false, now, fn);
}

AckedSummary SendQueue::on_cumulative_ack(std::uint64_t new_una, bool fin_acked, Time now,
                                          DeliveredFn fn) {
  static_cast<void>(now);
  const std::uint64_t old_una = una();
  UTCP_CHECK(new_una <= nxt_);
  UTCP_CHECK(!fin_acked || (fin_sent_ && new_una == end_));
  if (new_una < old_una) {
    new_una = old_una;  // an old ACK acknowledges nothing new
  }
  AckedSummary s;
  // Linux tcp_clean_rtx_queue: pop fully acknowledged TxSegs in order.
  while (head_ < segs_.size()) {
    TxSeg& seg = segs_[head_];
    const bool fully = seg.end() <= new_una && (!seg.fin || fin_acked);
    if (!fully) {
      break;
    }
    ++s.pkts;
    if (seg.ever_retrans) {
      s.retrans_acked = true;  // FLAG_RETRANS_DATA_ACKED (TCPCB_RETRANS)
    }
    if (!seg.sacked) {
      fn(seg, false);  // a segment SACKed earlier was delivered then
    }
    --ctr_.packets_out;
    if (seg.retrans_inflight) {
      --ctr_.retrans_out;
    }
    if (seg.sacked) {
      --ctr_.sacked_out;
    }
    if (seg.lost) {
      --ctr_.lost_out;
    }
    if (seg.fin) {
      fin_acked_ = true;
    }
    ++head_;
  }
  // A cumulative ACK inside a TxSeg trims its head (tcp_trim_head); the
  // TxSeg stays one packet.
  if (head_ < segs_.size() && segs_[head_].off < new_una) {
    TxSeg& seg = segs_[head_];
    const auto delta = static_cast<std::uint32_t>(new_una - seg.off);
    seg.off = new_una;
    seg.len -= delta;
  }
  ctr_.bytes_acked += new_una - old_una;
  ring_.consume(new_una - old_una);
  if (!sack_ok_ && s.pkts > 0) {
    // tcp_remove_reno_sacks: one ACK filled the hole, the rest ate duplicate ACKs.
    ctr_.sacked_out -= std::min(s.pkts - 1, ctr_.sacked_out);
  }
  if (!sack_ok_) {
    limit_reno_sacked();
  }
  s.stopped_at_sacked = head_ < segs_.size() && segs_[head_].sacked;  // FLAG_SACK_RENEGING
  compact();
  return s;
}

SackedSummary SendQueue::on_sack(std::span<const Range> blocks, Time now, DeliveredFn fn) {
  static_cast<void>(now);
  SackedSummary s;
  if (!sack_ok_) {
    return s;
  }
  // Receivers send the newest block first (RFC 2018 §4); walk them in
  // sequence order so that `fn` sees segments in sequence order (Linux
  // tcp_sacktag_write_queue sorts by start_seq). Insertion sort on (begin,
  // end): a total order, so equal blocks need no tie rule.
  UTCP_CHECK(blocks.size() <= max_sack_ranges);
  std::array<Range, max_sack_ranges> sorted{};
  std::size_t n = 0;
  for (const Range& b : blocks) {
    std::size_t j = n++;
    for (; j > 0 && (sorted[j - 1].begin > b.begin ||
                     (sorted[j - 1].begin == b.begin && sorted[j - 1].end > b.end));
         --j) {
      sorted[j] = sorted[j - 1];
    }
    sorted[j] = b;
  }
  // Blocks sorted by begin deliver in sequence order: a segment SACKed by a
  // later block that starts below the end of an earlier one is not covered
  // by the earlier block, so it ends above every segment that block SACKed.
  for (const Range& b : std::span<const Range>(sorted.data(), n)) {
    if (b.empty()) {
      continue;
    }
    // Segments are sorted and contiguous: walk those that start inside b.
    for (std::size_t i = index_of(b.begin); i < segs_.size(); ++i) {
      TxSeg& seg = segs_[i];
      if (seg.end() > b.end || seg.off >= b.end) {
        break;
      }
      if (seg.sacked || seg.len == 0) {
        continue;
      }
      // Linux tcp_sacktag_one.
      if (seg.retrans_inflight) {
        // A retransmission of a segment not marked lost is believed to be
        // still in flight and stays counted.
        if (seg.lost) {
          seg.lost = false;
          --ctr_.lost_out;
          seg.retrans_inflight = false;
          --ctr_.retrans_out;
        }
      } else if (seg.lost) {
        seg.lost = false;
        --ctr_.lost_out;
      }
      seg.sacked = true;
      ++ctr_.sacked_out;
      ++s.newly_sacked;
      high_sacked_ = std::max(high_sacked_, seg.end());
      fn(seg, true);
      seg.rate_used = true;  // tcp_rate_skb_delivered: delivered_mstamp = 0
    }
  }
  s.high_sacked = high_sacked_ > una() ? high_sacked_ : 0;
  return s;
}

void SendQueue::mark_lost(std::uint64_t off) {
  TxSeg* seg = find_mut(off);
  UTCP_CHECK(seg != nullptr);
  if (seg->sacked) {
    return;
  }
  if (seg->lost) {
    if (seg->retrans_inflight) {
      // The retransmission is lost again.
      seg->retrans_inflight = false;
      --ctr_.retrans_out;
      ++lost_total_;
    }
    return;
  }
  seg->lost = true;
  ++ctr_.lost_out;
  ++lost_total_;
  if (!sack_ok_) {
    limit_reno_sacked();
  }
}

void SendQueue::clear_all_sacked() {
  for (std::size_t i = head_; i < segs_.size(); ++i) {
    segs_[i].sacked = false;
  }
  ctr_.sacked_out = 0;
  high_sacked_ = 0;
}

// tcp_limit_reno_sacked: sacked_out + max(lost_out, 1) <= packets_out.
void SendQueue::limit_reno_sacked() {
  const std::uint32_t holes = std::min(std::max(ctr_.lost_out, 1u), ctr_.packets_out);
  if (ctr_.sacked_out + holes > ctr_.packets_out) {
    ctr_.sacked_out = ctr_.packets_out - holes;
  }
}

void SendQueue::reno_dupack() {
  if (sack_ok_) {
    return;
  }
  // tcp_add_reno_sack, then tcp_check_reno_reordering's limit.
  ++ctr_.sacked_out;
  limit_reno_sacked();
}

void SendQueue::set_sack_ok(bool sack_ok) { sack_ok_ = sack_ok; }

void SendQueue::split_to_mss(std::uint16_t mss) {
  UTCP_CHECK(mss > 0);
  bool any = false;
  for (std::size_t i = head_; i < segs_.size(); ++i) {
    any = any || segs_[i].len > mss;
  }
  if (!any) {
    return;
  }
  std::vector<TxSeg> out;
  out.reserve(segs_.size() - head_ + 16);
  for (std::size_t i = head_; i < segs_.size(); ++i) {
    const TxSeg& seg = segs_[i];
    if (seg.len <= mss) {
      out.push_back(seg);
      continue;
    }
    std::uint32_t done = 0;
    bool first = true;
    while (done < seg.len) {
      TxSeg part = seg;
      part.off = seg.off + done;
      part.len = std::min<std::uint32_t>(mss, seg.len - done);
      done += part.len;
      part.fin = seg.fin && done == seg.len;
      if (!first) {
        part.id = next_id_++;
        ++ctr_.packets_out;
        ctr_.sacked_out += part.sacked ? 1u : 0u;
        ctr_.lost_out += part.lost ? 1u : 0u;
        ctr_.retrans_out += part.retrans_inflight ? 1u : 0u;
      }
      first = false;
      out.push_back(part);
    }
  }
  segs_ = std::move(out);
  head_ = 0;
}

void SendQueue::split(std::uint64_t off, std::uint32_t len) {
  const std::size_t i = index_of(off);
  UTCP_CHECK(i < segs_.size() && segs_[i].off == off);
  UTCP_CHECK(len > 0 && len < segs_[i].len);
  TxSeg tail = segs_[i];
  tail.id = next_id_++;
  tail.off = off + len;
  tail.len = segs_[i].len - len;
  segs_[i].len = len;
  segs_[i].fin = false;
  ++ctr_.packets_out;
  ctr_.sacked_out += tail.sacked ? 1u : 0u;
  ctr_.lost_out += tail.lost ? 1u : 0u;
  ctr_.retrans_out += tail.retrans_inflight ? 1u : 0u;
  segs_.insert(segs_.begin() + static_cast<std::ptrdiff_t>(i + 1), tail);
}

const Counters& SendQueue::counters() const { return ctr_; }
std::uint64_t SendQueue::lost_total() const { return lost_total_; }
bool SendQueue::sack_ok() const { return sack_ok_; }
bool SendQueue::fin_sent() const { return fin_sent_; }
bool SendQueue::fin_acked() const { return fin_acked_; }
std::uint64_t SendQueue::una_with_fin() const { return una() + (fin_acked_ ? 1u : 0u); }
std::uint64_t SendQueue::nxt_with_fin() const { return nxt_ + (fin_sent_ ? 1u : 0u); }

std::span<const TxSeg> SendQueue::segs() const {
  return std::span<const TxSeg>(segs_).subspan(head_);
}

void SendQueue::compact() {
  if (head_ == segs_.size()) {
    segs_.clear();
    head_ = 0;
  } else if (head_ >= 64 && head_ * 2 >= segs_.size()) {
    segs_.erase(segs_.begin(), segs_.begin() + static_cast<std::ptrdiff_t>(head_));
    head_ = 0;
  }
}

void SendQueue::check_invariants() const {
  Counters recount;
  std::uint64_t expect = una();
  const auto live = segs();
  for (std::size_t i = 0; i < live.size(); ++i) {
    const TxSeg& seg = live[i];
    UTCP_CHECK(seg.off == expect);  // TxSegs cover [una(), nxt()) exactly
    UTCP_CHECK(seg.len > 0 || seg.fin);
    UTCP_CHECK(!seg.fin || i + 1 == live.size());
    UTCP_CHECK(!(seg.sacked && seg.lost));
    UTCP_CHECK(!seg.retrans_inflight || seg.ever_retrans);
    UTCP_CHECK(sack_ok_ || !seg.sacked);
    UTCP_CHECK(seg.tx_count >= 1);
    expect = seg.end();
    ++recount.packets_out;
    recount.sacked_out += seg.sacked ? 1u : 0u;
    recount.lost_out += seg.lost ? 1u : 0u;
    recount.retrans_out += seg.retrans_inflight ? 1u : 0u;
  }
  UTCP_CHECK(expect == nxt_);
  UTCP_CHECK(nxt_ <= end_);
  UTCP_CHECK(!fin_sent_ || nxt_ == end_);
  UTCP_CHECK(!fin_acked_ || (fin_sent_ && live.empty()));
  UTCP_CHECK(recount.packets_out == ctr_.packets_out);
  UTCP_CHECK(recount.lost_out == ctr_.lost_out);
  UTCP_CHECK(recount.retrans_out == ctr_.retrans_out);
  if (sack_ok_) {
    UTCP_CHECK(recount.sacked_out == ctr_.sacked_out);
  } else {
    UTCP_CHECK(ctr_.sacked_out + std::min(std::max(ctr_.lost_out, 1u), ctr_.packets_out) <=
                   ctr_.packets_out ||
               ctr_.sacked_out == 0);
  }
  UTCP_CHECK(ctr_.sacked_out + ctr_.lost_out <= ctr_.packets_out);  // in-flight cannot underflow
}

}  // namespace utcp
