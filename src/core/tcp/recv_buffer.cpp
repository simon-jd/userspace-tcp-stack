// Receive buffer: in-place reassembly over a ByteRing (DESIGN §4.10).
#include "core/tcp/recv_buffer.hpp"

#include <algorithm>

#include "utcp/check.hpp"

namespace utcp {
namespace {

// Index of the first range whose end is above `off`.
std::size_t first_ending_after(const std::vector<Range>& r, std::uint64_t off) {
  const auto it = std::ranges::upper_bound(r, off, {}, &Range::end);
  return static_cast<std::size_t>(it - r.begin());
}

// Index of the first range whose end is at or above `off`.
std::size_t first_ending_at_or_after(const std::vector<Range>& r, std::uint64_t off) {
  const auto it = std::ranges::lower_bound(r, off, {}, &Range::end);
  return static_cast<std::size_t>(it - r.begin());
}

// Index of the first range that begins above `off`.
std::size_t first_beginning_after(const std::vector<Range>& r, std::uint64_t off) {
  const auto it = std::ranges::upper_bound(r, off, {}, &Range::begin);
  return static_cast<std::size_t>(it - r.begin());
}

}  // namespace

RecvBuffer::RecvBuffer(std::uint32_t capacity, ChunkPool& pool)
    : pool_(&pool), ring_(pool, capacity), capacity_(capacity) {}

std::size_t RecvBuffer::range_count_with(std::uint64_t lo, std::uint64_t hi) const {
  if (lo <= rcv_end_) {
    // [lo, hi) joins the in-order data together with every range it reaches;
    // ranges do not touch, so the ones beginning above hi stay apart.
    return ooo_.size() - first_beginning_after(ooo_, hi);
  }
  // Ranges overlapping or touching [lo, hi) merge with it into one.
  const std::size_t i = first_ending_at_or_after(ooo_, lo);
  const std::size_t j = first_beginning_after(ooo_, hi);
  return ooo_.size() - (j - i) + 1;
}

std::uint64_t RecvBuffer::unheld_bytes(std::uint64_t lo, std::uint64_t hi) const {
  lo = std::max(lo, rcv_end_);  // [read_offset, rcv_end_) is held
  if (lo >= hi) {
    return 0;
  }
  std::uint64_t n = hi - lo;
  for (std::size_t i = first_ending_after(ooo_, lo); i < ooo_.size() && ooo_[i].begin < hi; ++i) {
    n -= std::min(hi, ooo_[i].end) - std::max(lo, ooo_[i].begin);
  }
  return n;
}

std::uint32_t RecvBuffer::chunks_needed(std::uint64_t lo, std::uint64_t hi) const {
  // Every held byte has a chunk, so a chunk the ring lacks holds no byte yet
  // and every byte of [lo, hi) in it is new.
  constexpr std::uint64_t cs = ChunkPool::chunk_size;
  std::uint32_t n = 0;
  for (std::uint64_t c = lo / cs; c <= (hi - 1) / cs; ++c) {
    if (!ring_.has_chunk(std::max(c * cs, lo))) {
      ++n;
    }
  }
  return n;
}

bool RecvBuffer::chunks_fit(std::uint64_t lo, std::uint64_t hi) const {
  return chunks_needed(lo, hi) <= pool_->limit() - pool_->in_use();
}

std::uint64_t RecvBuffer::prune_last_range() {
  const Range g = ooo_.back();
  ooo_.pop_back();
  // Nothing is held between the next lower range (or the in-order data) and
  // g, so every chunk wholly above that point goes back to the pool.
  ring_.release_from(ooo_.empty() ? rcv_end_ : ooo_.back().end);
  return g.end - g.begin;
}

InsertResult RecvBuffer::insert(std::uint64_t off, std::span<const std::byte> data,
                                std::uint64_t limit) {
  UTCP_CHECK(limit <= right_edge());
  const std::uint64_t old_end = rcv_end_;
  const std::uint64_t seg_end = off + data.size();

  InsertResult r;
  r.out_of_order = off > old_end;

  // The lowest run of segment bytes already received: below the old
  // contiguous end, or inside one held range (ranges do not touch, so the run
  // ends where the range ends). RFC 2883 §4.2: only the first duplicate run is
  // reported.
  if (off < seg_end) {
    if (off < old_end) {
      r.duplicate = Range{off, std::min(old_end, seg_end)};
    } else if (const std::size_t i = first_ending_after(ooo_, off);
               i < ooo_.size() && ooo_[i].begin < seg_end) {
      r.duplicate = Range{std::max(off, ooo_[i].begin), std::min(ooo_[i].end, seg_end)};
    }
  }

  // The part that may be stored: [read_offset, min(limit, FIN)).
  std::uint64_t hi = std::min(seg_end, limit);
  if (fin_) {
    hi = std::min(hi, *fin_);
  }
  const std::uint64_t lo = std::max(off, read_offset());
  bool absorbed = false;
  if (lo < hi) {
    if (range_count_with(lo, hi) <= max_ooo_ranges) {
      // Short of chunks: Linux tcp_try_rmem_schedule prunes the out-of-order
      // queue from the top (tcp_prune_ofo_queue) before it drops the segment,
      // but stops where the incoming segment would land last. Pruning only
      // lowers the range count.
      while (!chunks_fit(lo, hi) && !ooo_.empty() && ooo_.back().begin >= off) {
        r.pruned += prune_last_range();
      }
      // A duplicate of pruned data is no duplicate any more: Linux inserts
      // the segment into what is left of the queue and sets a D-SACK only
      // for overlaps found there. Pruned ranges are the highest ones, so if
      // the range holding the lowest duplicate run went, every higher one
      // went too.
      if (r.pruned > 0 && r.duplicate && r.duplicate->begin >= old_end) {
        const std::size_t i = first_ending_after(ooo_, r.duplicate->begin);
        if (i == ooo_.size() || ooo_[i].begin > r.duplicate->begin) {
          r.duplicate.reset();
        }
      }
    }
    if (range_count_with(lo, hi) > max_ooo_ranges) {
      r.range_limit = true;
      r.dropped = unheld_bytes(lo, hi);
    } else if (!chunks_fit(lo, hi)) {
      r.dropped = unheld_bytes(lo, hi);
    } else {
      // Write the gaps only: bytes already held keep their first copy.
      std::uint64_t pos = std::max(lo, rcv_end_);
      std::size_t i = first_ending_after(ooo_, pos);
      while (pos < hi) {
        if (i < ooo_.size() && ooo_[i].begin <= pos) {
          pos = ooo_[i].end;
          ++i;
          continue;
        }
        const std::uint64_t gap_end = i < ooo_.size() ? std::min(ooo_[i].begin, hi) : hi;
        const auto n = static_cast<std::size_t>(gap_end - pos);
        const std::size_t written =
            ring_.write_at(pos, data.subspan(static_cast<std::size_t>(pos - off), n));
        UTCP_CHECK(written == n);  // chunks_needed() reserved them
        pos = gap_end;
      }

      if (lo <= rcv_end_) {
        rcv_end_ = std::max(rcv_end_, hi);
        std::size_t k = 0;
        while (k < ooo_.size() && ooo_[k].begin <= rcv_end_) {
          rcv_end_ = std::max(rcv_end_, ooo_[k].end);
          ++k;
        }
        if (k > 0) {
          ooo_.erase(ooo_.begin(), ooo_.begin() + static_cast<std::ptrdiff_t>(k));
          absorbed = true;
        }
      } else {
        const std::size_t first = first_ending_at_or_after(ooo_, lo);
        const std::size_t last = first_beginning_after(ooo_, hi);
        Range merged{lo, hi};
        if (first < last) {
          merged.begin = std::min(lo, ooo_[first].begin);
          merged.end = std::max(hi, ooo_[last - 1].end);
          ooo_.erase(ooo_.begin() + static_cast<std::ptrdiff_t>(first),
                     ooo_.begin() + static_cast<std::ptrdiff_t>(last));
        }
        ooo_.insert(ooo_.begin() + static_cast<std::ptrdiff_t>(first), merged);
      }
      r.stored = Range{lo, hi};
    }
  }
  // A segment dropped whole reports no duplicate unless it began below the
  // old contiguous end: Linux tcp_data_queue_ofo returns on a failed
  // tcp_try_rmem_schedule before tcp_dsack_set, and in-order data at
  // RCV.NXT is dropped before tcp_ofo_queue looks for overlaps, but a
  // partial packet (seq < RCV.NXT) has its D-SACK set first. (A segment
  // dropped at the range limit overlaps nothing held.)
  if (r.dropped > 0 && off >= old_end) {
    r.duplicate.reset();
  }

  r.contiguous_end = rcv_end_;
  r.advanced = rcv_end_ != old_end;
  r.filled_hole = absorbed;
  r.ooo_held = !ooo_.empty();
  return r;
}

void RecvBuffer::drop_out_of_order() {
  if (!ooo_.empty()) {
    ring_.release_from(rcv_end_);
    ooo_.clear();
  }
}

void RecvBuffer::set_fin(std::uint64_t off) {
  if (fin_ || off < rcv_end_ || (!ooo_.empty() && ooo_.back().end > off)) {
    return;
  }
  fin_ = off;
}

std::optional<std::uint64_t> RecvBuffer::fin_offset() const { return fin_; }

bool RecvBuffer::fin_reached() const { return fin_ && rcv_end_ >= *fin_; }

std::size_t RecvBuffer::read(std::span<std::byte> out) {
  const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), readable()));
  if (n == 0) {
    return 0;
  }
  ring_.read_at(ring_.begin(), out.first(n));
  ring_.consume(n);
  return n;
}

std::uint64_t RecvBuffer::readable() const { return rcv_end_ - ring_.begin(); }

std::uint64_t RecvBuffer::read_offset() const { return ring_.begin(); }

std::uint64_t RecvBuffer::contiguous_end() const { return rcv_end_; }

std::uint64_t RecvBuffer::right_edge() const { return ring_.begin() + capacity_; }

std::uint32_t RecvBuffer::capacity() const { return capacity_; }

std::span<const Range> RecvBuffer::ooo_ranges() const { return ooo_; }

void RecvBuffer::grow(std::uint32_t new_capacity) {
  UTCP_CHECK(new_capacity >= capacity_);
  capacity_ = new_capacity;
  ring_.set_capacity(new_capacity);
}

std::uint32_t RecvBuffer::chunks_held() const { return ring_.chunks_held(); }

void RecvBuffer::check_invariants() const {
  UTCP_CHECK(ring_.begin() <= rcv_end_);
  UTCP_CHECK(ooo_.size() <= max_ooo_ranges);
  std::uint64_t prev_end = rcv_end_;
  for (const Range& g : ooo_) {
    UTCP_CHECK(g.begin > prev_end && g.end > g.begin);
    prev_end = g.end;
  }
  UTCP_CHECK(prev_end <= right_edge());
  if (fin_) {
    UTCP_CHECK(*fin_ >= prev_end);
  }
  constexpr std::uint64_t cs = ChunkPool::chunk_size;
  const auto check_held = [this](std::uint64_t lo, std::uint64_t hi) {
    for (std::uint64_t o = lo; o < hi; o = (o / cs + 1) * cs) {
      UTCP_CHECK(ring_.has_chunk(o));
    }
  };
  check_held(ring_.begin(), rcv_end_);
  for (const Range& g : ooo_) {
    check_held(g.begin, g.end);
  }
}

}  // namespace utcp
