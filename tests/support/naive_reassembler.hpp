// Reference model of RecvBuffer (src/core/tcp/recv_buffer.hpp, DESIGN §4.10):
// a map from stream offset to byte, with every rule written out directly.
// m1-rx's differential test and fuzz_reassembler apply the same operations to
// both and compare readable bytes, contiguous_end, FIN state and ooo_ranges
// after every step.
//
// Queries walk the map: O(bytes held) per call, so use small capacities.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
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
    const auto received = [&](std::uint64_t o) { return o < old_end || bytes_.contains(o); };
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
      // Range limit: would the union hold more than max_ooo_ranges ranges?
      std::map<std::uint64_t, std::byte> trial = bytes_;
      for (std::uint64_t o = lo; o < hi; ++o) {
        trial.try_emplace(o, std::byte{});
      }
      if (ranges_of(trial, end_of(trial)).size() > max_ooo_ranges) {
        r.range_limit = true;
        for (std::uint64_t o = lo; o < hi; ++o) {
          r.dropped += bytes_.contains(o) ? 0 : 1;
        }
      } else {
        for (std::uint64_t o = lo; o < hi; ++o) {
          bytes_.try_emplace(o, data[static_cast<std::size_t>(o - off)]);  // first copy wins
        }
        r.stored = Range{lo, hi};
      }
    }

    r.contiguous_end = contiguous_end();
    r.advanced = r.contiguous_end != old_end;
    r.filled_hole = r.advanced && std::ranges::any_of(old_ranges, [&](const Range& g) {
                      return g.begin <= r.contiguous_end;
                    });
    return r;
  }

  void drop_out_of_order() {
    const std::uint64_t end = contiguous_end();
    bytes_.erase(bytes_.lower_bound(end), bytes_.end());
  }

  void set_fin(std::uint64_t off) {
    if (fin_) {
      return;  // the first FIN wins
    }
    if (!bytes_.empty() && bytes_.rbegin()->first >= off) {
      return;  // a byte at or above `off` is held
    }
    fin_ = off;
  }
  [[nodiscard]] std::optional<std::uint64_t> fin_offset() const { return fin_; }
  [[nodiscard]] bool fin_reached() const { return fin_ && contiguous_end() >= *fin_; }

  std::size_t read(std::span<std::byte> out) {
    std::size_t n = 0;
    while (n < out.size()) {
      const auto it = bytes_.find(read_off_);
      if (it == bytes_.end()) {
        break;
      }
      out[n++] = it->second;
      bytes_.erase(it);
      ++read_off_;
    }
    return n;
  }
  [[nodiscard]] std::uint64_t readable() const { return contiguous_end() - read_off_; }

  [[nodiscard]] std::uint64_t read_offset() const { return read_off_; }
  [[nodiscard]] std::uint64_t contiguous_end() const {
    std::uint64_t e = read_off_;
    while (bytes_.contains(e)) {
      ++e;
    }
    return e;
  }
  [[nodiscard]] std::uint64_t right_edge() const { return read_off_ + capacity_; }
  [[nodiscard]] std::uint32_t capacity() const { return capacity_; }
  // Maximal runs of held bytes above contiguous_end(), in order.
  [[nodiscard]] std::vector<Range> ooo_ranges() const { return ranges_of(bytes_, contiguous_end()); }

  void grow(std::uint32_t new_capacity) {
    UTCP_CHECK(new_capacity >= capacity_);
    capacity_ = new_capacity;
  }

private:
  [[nodiscard]] std::uint64_t end_of(const std::map<std::uint64_t, std::byte>& m) const {
    std::uint64_t e = read_off_;
    while (m.contains(e)) {
      ++e;
    }
    return e;
  }
  static std::vector<Range> ranges_of(const std::map<std::uint64_t, std::byte>& m,
                                      std::uint64_t from) {
    std::vector<Range> out;
    for (auto it = m.lower_bound(from); it != m.end(); ++it) {
      if (!out.empty() && out.back().end == it->first) {
        ++out.back().end;
      } else {
        out.push_back(Range{it->first, it->first + 1});
      }
    }
    return out;
  }

  std::uint32_t capacity_;
  std::uint64_t read_off_ = 0;
  std::map<std::uint64_t, std::byte> bytes_;  // held bytes: readable and out of order
  std::optional<std::uint64_t> fin_;
};

}  // namespace utcp::test
