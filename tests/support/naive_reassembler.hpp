// Reference model of RecvBuffer (src/core/tcp/recv_buffer.hpp, DESIGN §4.10):
// one flag and one byte per stream offset of the window, with every rule
// written out directly. m1-rx's differential test and fuzz_reassembler apply
// the same operations to both and compare readable bytes, contiguous_end, FIN
// state and ooo_ranges after every step.
//
// Runs of held bytes are found with memchr over the flags, so a query costs
// O(ranges) plus a libc scan of the window, and an insert O(segment length)
// on top; nothing copies the window. 1e6 random insert/read/FIN steps, each
// followed by contiguous_end, ooo_ranges, readable and fin_offset, took 9.0 s
// at capacity 4 KiB and 10.9 s at 16 KiB (g++-15 -O0, ASan, UBSan,
// _GLIBCXX_ASSERTIONS, home-ubuntu E-cores), well inside the 300 s ctest
// timeout.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

#include "core/tcp/recv_buffer.hpp"
#include "utcp/check.hpp"
#include "utcp/types.hpp"

namespace utcp::test {

class NaiveReassembler {
public:
  explicit NaiveReassembler(std::uint32_t capacity) : capacity_(capacity) {}

  // RecvBuffer::insert without a chunk pool (nothing is dropped for memory).
  InsertResult insert(std::uint64_t off, std::span<const std::byte> data, std::uint64_t limit) {
    UTCP_CHECK(limit <= right_edge());
    const std::uint64_t old_end = contiguous_end();
    const std::vector<Range> old_ranges = ooo_ranges();
    const std::uint64_t seg_end = off + data.size();

    InsertResult r;
    r.out_of_order = off > old_end;

    // The lowest run of bytes already received (below old_end, or held).
    const auto received = [&](std::uint64_t o) { return o < old_end || held(o); };
    for (std::uint64_t o = off; o < seg_end; ++o) {
      if (received(o)) {
        std::uint64_t e = o;
        while (e < seg_end && received(e)) {
          ++e;
        }
        r.duplicate = Range{o, e};
        break;
      }
    }

    // Clip to the window [read_offset, min(limit, FIN)).
    std::uint64_t hi = std::min(seg_end, limit);
    if (fin_) {
      hi = std::min(hi, *fin_);
    }
    const std::uint64_t lo = std::max(off, read_off_);
    if (lo < hi) {
      // Range limit: would the held bytes plus [lo, hi) form more than
      // max_ooo_ranges ranges above their in-order end?
      if (ooo_range_count_with(lo, hi) > max_ooo_ranges) {
        r.range_limit = true;
        for (std::uint64_t o = lo; o < hi; ++o) {
          r.dropped += held(o) ? 0 : 1;
        }
      } else {
        for (std::uint64_t o = lo; o < hi; ++o) {
          if (!held(o)) {  // first copy wins
            put(o, data[static_cast<std::size_t>(o - off)]);
          }
        }
        r.stored = Range{lo, hi};
      }
    }

    r.contiguous_end = contiguous_end();
    r.advanced = r.contiguous_end != old_end;
    r.filled_hole = r.advanced && std::ranges::any_of(old_ranges, [&](const Range& g) {
                      return g.begin <= r.contiguous_end;
                    });
    r.ooo_held = !ooo_ranges().empty();
    return r;
  }

  void drop_out_of_order() {
    const std::uint64_t end = contiguous_end();
    if (end < stored_end()) {
      std::fill(held_.begin() + static_cast<std::ptrdiff_t>(index(end)), held_.end(), std::uint8_t{0});
    }
  }

  // The first FIN wins. An offset below contiguous_end() (in-order data,
  // read or not, lies beyond it) or below a held out-of-order byte is ignored:
  // the peer's data contradicts it.
  void set_fin(std::uint64_t off) {
    if (fin_) {
      return;
    }
    if (off < contiguous_end()) {
      return;
    }
    if (const std::vector<Range> ooo = ooo_ranges(); !ooo.empty() && ooo.back().end > off) {
      return;  // the highest held byte, ooo.back().end - 1, is at or above off
    }
    fin_ = off;
  }
  [[nodiscard]] std::optional<std::uint64_t> fin_offset() const { return fin_; }
  [[nodiscard]] bool fin_reached() const { return fin_ && contiguous_end() >= *fin_; }

  std::size_t read(std::span<std::byte> out) {
    std::size_t n = 0;
    while (n < out.size() && held(read_off_)) {
      out[n++] = data_[index(read_off_)];
      held_[index(read_off_)] = 0;
      ++read_off_;
    }
    compact();
    return n;
  }
  [[nodiscard]] std::uint64_t readable() const { return contiguous_end() - read_off_; }

  [[nodiscard]] std::uint64_t read_offset() const { return read_off_; }
  [[nodiscard]] std::uint64_t contiguous_end() const { return next_with(read_off_, 0); }
  [[nodiscard]] std::uint64_t right_edge() const { return read_off_ + capacity_; }
  [[nodiscard]] std::uint32_t capacity() const { return capacity_; }
  // Maximal runs of held bytes above contiguous_end(), in order.
  [[nodiscard]] std::vector<Range> ooo_ranges() const { return runs_from(contiguous_end()); }

  void grow(std::uint32_t new_capacity) {
    UTCP_CHECK(new_capacity >= capacity_);
    capacity_ = new_capacity;
  }

private:
  // held_[i] and data_[i] describe stream offset base_ + i; base_ <= read_off_.
  [[nodiscard]] std::size_t index(std::uint64_t o) const { return static_cast<std::size_t>(o - base_); }
  [[nodiscard]] std::uint64_t stored_end() const { return base_ + held_.size(); }
  [[nodiscard]] bool held(std::uint64_t o) const {
    return o >= base_ && o < stored_end() && held_[index(o)] != 0;
  }
  void put(std::uint64_t o, std::byte b) {
    UTCP_CHECK(o >= read_off_ && o < right_edge());
    if (o >= stored_end()) {
      held_.resize(index(o) + 1, 0);
      data_.resize(index(o) + 1);
    }
    held_[index(o)] = 1;
    data_[index(o)] = b;
  }
  // The first offset >= o whose flag equals `flag` (1 held, 0 not held);
  // every offset at or past stored_end() is not held.
  [[nodiscard]] std::uint64_t next_with(std::uint64_t o, std::uint8_t flag) const {
    if (o < base_) {  // nothing below base_ is held
      return flag == 0 ? o : next_with(base_, 1);
    }
    if (o >= stored_end()) {
      return flag == 0 ? o : stored_end();
    }
    const std::size_t i = index(o);
    const void* hit = std::memchr(held_.data() + i, flag, held_.size() - i);
    if (hit == nullptr) {
      return stored_end();
    }
    return base_ + static_cast<std::uint64_t>(static_cast<const std::uint8_t*>(hit) - held_.data());
  }
  // Maximal runs of held bytes at or above `from`, in order.
  [[nodiscard]] std::vector<Range> runs_from(std::uint64_t from) const {
    std::vector<Range> out;
    for (std::uint64_t o = next_with(from, 1); o < stored_end(); o = next_with(o, 1)) {
      const std::uint64_t e = next_with(o, 0);
      out.push_back(Range{o, e});
      o = e;
    }
    return out;
  }
  // Number of ranges above the in-order end if [lo, hi) (lo >= read_off_)
  // were held as well: the held runs plus [lo, hi), sorted and merged where
  // they overlap or touch, without the run that starts at read_off_.
  [[nodiscard]] std::size_t ooo_range_count_with(std::uint64_t lo, std::uint64_t hi) const {
    std::vector<Range> runs = runs_from(read_off_);
    runs.push_back(Range{lo, hi});
    std::ranges::sort(runs, {}, &Range::begin);
    std::vector<Range> merged;
    for (const Range& r : runs) {
      if (!merged.empty() && r.begin <= merged.back().end) {
        merged.back().end = std::max(merged.back().end, r.end);
      } else {
        merged.push_back(r);
      }
    }
    const bool in_order_run = !merged.empty() && merged.front().begin == read_off_;
    return merged.size() - (in_order_run ? 1 : 0);
  }
  // Drops the read part of the window once it is large.
  void compact() {
    const std::uint64_t dead = read_off_ - base_;
    if (dead < 4096 || dead < held_.size() / 2) {
      return;
    }
    const auto n = static_cast<std::ptrdiff_t>(std::min<std::uint64_t>(dead, held_.size()));
    held_.erase(held_.begin(), held_.begin() + n);
    data_.erase(data_.begin(), data_.begin() + n);
    base_ += static_cast<std::uint64_t>(n);
    if (base_ < read_off_) {  // nothing was held up to read_off_
      base_ = read_off_;
      held_.clear();
      data_.clear();
    }
  }

  std::uint32_t capacity_;
  std::uint64_t read_off_ = 0;
  std::uint64_t base_ = 0;
  std::vector<std::uint8_t> held_;  // 1: byte held (readable or out of order)
  std::vector<std::byte> data_;
  std::optional<std::uint64_t> fin_;
};

}  // namespace utcp::test
