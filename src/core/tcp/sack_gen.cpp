// SACK and D-SACK block generation (RFC 2018 §4, RFC 2883 §4; DESIGN §4.10).
#include "core/tcp/sack_gen.hpp"

#include <algorithm>
#include <array>
#include <bitset>

namespace utcp {
namespace {

// Index of the first range of `ooo` that overlaps `r`, or ooo.size().
std::size_t overlapping(std::span<const Range> ooo, Range r) {
  if (r.empty()) {
    return ooo.size();
  }
  const auto it = std::ranges::upper_bound(ooo, r.begin, {}, &Range::end);
  if (it != ooo.end() && it->begin < r.end) {
    return static_cast<std::size_t>(it - ooo.begin());
  }
  return ooo.size();
}

}  // namespace

void SackGenerator::on_arrival(Range seg, const RecvBuffer& rb) {
  if (dsack_ && !(seg.begin <= dsack_->begin && dsack_->end <= seg.end)) {
    dsack_.reset();
  }
  // Rebuild the recency list against the current ranges: the block holding
  // this segment first, then the others in their previous order, without
  // entries whose data is gone and without two entries for one block.
  const std::span<const Range> ooo = rb.ooo_ranges();
  std::array<std::uint8_t, max_ooo_ranges> order{};
  std::bitset<max_ooo_ranges> used;
  std::size_t n = 0;
  const auto add = [&](std::size_t i) {
    if (i < ooo.size() && !used[i]) {
      used.set(i);
      order[n++] = static_cast<std::uint8_t>(i);
    }
  };
  add(overlapping(ooo, seg));
  for (const Range& e : recent_) {
    add(overlapping(ooo, e));
  }
  recent_.clear();
  for (std::size_t k = 0; k < n; ++k) {
    recent_.push_back(ooo[order[k]]);
  }
}

void SackGenerator::on_duplicate(Range dup, const RecvBuffer& /*rb*/) {
  if (!dup.empty()) {
    dsack_ = dup;
  }
}

std::size_t SackGenerator::fill(const RecvBuffer& rb, std::span<Range> out,
                                std::size_t max_blocks) const {
  const std::size_t cap = std::min(out.size(), max_blocks);
  const std::span<const Range> ooo = rb.ooo_ranges();
  std::bitset<max_ooo_ranges> used;
  std::size_t n = 0;
  const auto add = [&](std::size_t i) {
    if (n < cap && i < ooo.size() && !used[i]) {
      used.set(i);
      out[n++] = ooo[i];
    }
  };
  if (dsack_ && n < cap) {
    // RFC 2883 §4: the D-SACK block first, then (rule 4) the block above
    // RCV.NXT that holds the duplicate. The sender recognises the D-SACK by
    // the first block lying below the ACK or inside the second (§5).
    out[n++] = *dsack_;
    add(overlapping(ooo, *dsack_));
  }
  // RFC 2018 §4: the block of the newest segment, then the most recently
  // reported ones.
  for (const Range& e : recent_) {
    add(overlapping(ooo, e));
  }
  // Blocks never reported (not expected when the engine calls on_arrival for
  // every out-of-order segment), lowest first.
  for (std::size_t i = 0; i < ooo.size(); ++i) {
    add(i);
  }
  return n;
}

void SackGenerator::on_ack_sent() { dsack_.reset(); }

bool SackGenerator::dsack_pending() const { return dsack_.has_value(); }

}  // namespace utcp
