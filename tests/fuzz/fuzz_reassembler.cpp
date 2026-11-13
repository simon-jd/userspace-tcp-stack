// libFuzzer target for RecvBuffer (DESIGN §4.10, §11 Fuzz). The input is a
// sequence of insert, read, FIN, reneging, grow and limit operations applied
// to a RecvBuffer and to the naive reference
// (tests/support/naive_reassembler.hpp); every InsertResult, the bytes read
// and the state after each step must match, and check_invariants must hold.
// A burst operation inserts up to 121 short segments with gaps, so inputs
// reach the 64-range limit in a few bytes. The first byte picks the capacity
// and whether the chunk pool is short of chunks. With a short pool the
// RecvBuffer may prune its highest out-of-order ranges or drop a segment for
// lack of chunks, which the pool-less reference cannot decide: the harness
// checks that only whole ranges at or above the segment's offset were
// pruned, from the top, and applies the same pruning to the reference; a
// dropped segment must change nothing else. A mismatch aborts through
// UTCP_CHECK.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <span>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/recv_buffer.hpp"
#include "support/naive_reassembler.hpp"
#include "utcp/check.hpp"

namespace {

using utcp::ChunkPool;
using utcp::InsertResult;
using utcp::Range;
using utcp::RecvBuffer;
using utcp::test::NaiveReassembler;

constexpr std::uint64_t cs = ChunkPool::chunk_size;
constexpr std::uint32_t capacities[] = {1, 100, 3000, 4096, 3 * 4096 + 17, 16384, 65535, 200000};

class Input {
public:
  Input(const std::uint8_t* data, std::size_t size) : p_(data), end_(data + size) {}
  [[nodiscard]] bool empty() const { return p_ == end_; }
  std::uint8_t u8() { return p_ == end_ ? std::uint8_t{0} : *p_++; }
  std::uint16_t u16() {
    const std::uint8_t hi = u8();
    return static_cast<std::uint16_t>((hi << 8) | u8());
  }

private:
  const std::uint8_t* p_;
  const std::uint8_t* end_;
};

// Bytes that differ per offset and per copy, so that "the first copy wins"
// is visible in what is read back.
std::vector<std::byte> payload(std::uint64_t off, std::size_t len, std::uint8_t copy) {
  std::vector<std::byte> v(len);
  for (std::size_t i = 0; i < len; ++i) {
    const std::uint64_t o = off + i;
    v[i] = static_cast<std::byte>(((o ^ (o >> 8)) * 31 + copy) & 0xff);
  }
  return v;
}

void check_same(const RecvBuffer& rb, const NaiveReassembler& ref) {
  rb.check_invariants();
  UTCP_CHECK(rb.contiguous_end() == ref.contiguous_end());
  UTCP_CHECK(rb.read_offset() == ref.read_offset());
  UTCP_CHECK(rb.readable() == ref.readable());
  UTCP_CHECK(rb.right_edge() == ref.right_edge());
  UTCP_CHECK(rb.capacity() == ref.capacity());
  UTCP_CHECK(rb.fin_offset() == ref.fin_offset());
  UTCP_CHECK(rb.fin_reached() == ref.fin_reached());
  const std::vector<Range> want = ref.ooo_ranges();
  UTCP_CHECK(std::ranges::equal(rb.ooo_ranges(), want));
  // Chunks for the window only.
  UTCP_CHECK(rb.chunks_held() <= rb.capacity() / cs + 2);
}

void insert(RecvBuffer& rb, NaiveReassembler& ref, std::uint64_t off,
            std::span<const std::byte> data, std::uint64_t limit, bool short_pool) {
  const std::vector<Range> before(rb.ooo_ranges().begin(), rb.ooo_ranges().end());
  const InsertResult x = rb.insert(off, data, limit);
  if (x.pruned > 0 || (x.dropped > 0 && !x.range_limit)) {
    // Short of chunks: only with a short pool, and never at the range limit.
    UTCP_CHECK(short_pool);
    UTCP_CHECK(!x.range_limit);
    // What insert decides before pruning, against the unpruned reference.
    NaiveReassembler probe = ref;
    const InsertResult y = probe.insert(off, data, limit);
    UTCP_CHECK(!y.range_limit);
    UTCP_CHECK(x.out_of_order == y.out_of_order);
    UTCP_CHECK(x.duplicate == y.duplicate);
    if (x.pruned > 0) {
      // Whole ranges from the top, each beginning at or above `off`.
      std::uint64_t sum = 0;
      std::size_t k = before.size();
      while (sum < x.pruned) {
        UTCP_CHECK(k > 0);
        --k;
        UTCP_CHECK(before[k].begin >= off);
        sum += before[k].end - before[k].begin;
      }
      UTCP_CHECK(sum == x.pruned);
      ref.drop_from(before[k].begin);
    }
    if (x.dropped > 0) {
      // The whole segment, nothing else changed.
      UTCP_CHECK(x.stored == Range{});
      UTCP_CHECK(!x.advanced && !x.filled_hole);
      UTCP_CHECK(x.contiguous_end == ref.contiguous_end());
      UTCP_CHECK(x.dropped <= y.stored.end - y.stored.begin);
      return;
    }
    // Stored after pruning: the reference, pruned the same way, agrees.
    const InsertResult z = ref.insert(off, data, limit);
    UTCP_CHECK(x.contiguous_end == z.contiguous_end);
    UTCP_CHECK(x.advanced == z.advanced);
    UTCP_CHECK(x.filled_hole == z.filled_hole);
    UTCP_CHECK(x.ooo_held == z.ooo_held);
    UTCP_CHECK(x.stored == z.stored);
    UTCP_CHECK(z.dropped == 0 && !z.range_limit);
    return;
  }
  const InsertResult y = ref.insert(off, data, limit);
  UTCP_CHECK(x.contiguous_end == y.contiguous_end);
  UTCP_CHECK(x.advanced == y.advanced);
  UTCP_CHECK(x.out_of_order == y.out_of_order);
  UTCP_CHECK(x.filled_hole == y.filled_hole);
  UTCP_CHECK(x.ooo_held == y.ooo_held);
  UTCP_CHECK(x.duplicate == y.duplicate);
  UTCP_CHECK(x.stored == y.stored);
  UTCP_CHECK(x.dropped == y.dropped);
  UTCP_CHECK(x.range_limit == y.range_limit);
}

void read(RecvBuffer& rb, NaiveReassembler& ref, std::size_t n) {
  std::vector<std::byte> a(n);
  std::vector<std::byte> b(n);
  const std::size_t got = rb.read(a);
  UTCP_CHECK(got == ref.read(b));
  UTCP_CHECK(a == b);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  Input in(data, size);
  const std::uint8_t mode = in.u8();
  const std::uint32_t cap0 = capacities[mode % std::size(capacities)];
  const std::uint32_t max_cap = 4 * cap0;
  // A short pool holds 1 to 4 chunks; a full one enough for max_cap.
  const bool short_pool = (mode & 0x80) != 0;
  const auto chunks =
      static_cast<std::uint32_t>(short_pool ? 1 + (mode >> 4) % 4 : max_cap / cs + 4);
  ChunkPool pool(chunks);
  RecvBuffer rb(cap0, pool);
  NaiveReassembler ref(cap0);
  std::uint64_t limit = rb.right_edge();  // like rcv_adv: never decreases

  while (!in.empty()) {
    const std::uint8_t op = in.u8();
    const std::uint64_t cap = rb.capacity();
    switch (op & 7) {
      case 0:
      case 1:
      case 2:
      case 3: {
        // A segment near contiguous_end or the read offset, from a little
        // below it to past the right edge.
        const std::uint64_t base = (op & 8) != 0 ? rb.read_offset() : rb.contiguous_end();
        const std::uint16_t d = in.u16();
        std::uint64_t off = 0;
        if ((op & 16) != 0) {
          const std::uint64_t back = d % 600;
          off = base >= back ? base - back : 0;
        } else {
          off = base + d % (cap + 600);
        }
        const std::size_t len = in.u16() % (std::min<std::uint64_t>(cap, 5000) + 1);
        const auto copy = static_cast<std::uint8_t>(op >> 5);
        insert(rb, ref, off, payload(off, len, copy), limit, short_pool);
        break;
      }
      case 4:
        read(rb, ref, in.u16() % (cap + 1));
        break;
      case 5: {
        const std::uint64_t base = (op & 8) != 0 ? rb.read_offset() : rb.contiguous_end();
        const std::uint64_t at = base + in.u16() % (cap + 1);
        rb.set_fin(at);
        ref.set_fin(at);
        break;
      }
      case 6:
        if ((op & 8) != 0) {
          rb.drop_out_of_order();
          ref.drop_out_of_order();
        } else {
          limit = std::max(limit, rb.right_edge() - in.u16() % (cap + 1));
        }
        break;
      default:
        if ((op & 8) != 0) {
          // A burst of 1 + 8 * (op >> 4) short segments, 1 to 8 bytes long
          // with gaps of 1 to 8 bytes, from just above contiguous_end or the
          // read offset.
          const std::uint64_t base =
              ((op & 16) != 0 ? rb.read_offset() : rb.contiguous_end() + 1) + in.u16() % (cap + 1);
          const std::uint8_t shape = in.u8();
          const std::uint64_t len = 1 + shape % 8;
          const std::uint64_t stride = len + 1 + (shape >> 3) % 8;
          const auto copy = static_cast<std::uint8_t>(shape >> 6);
          const unsigned count = 1 + 8 * (op >> 4);
          for (unsigned k = 0; k < count; ++k) {
            const std::uint64_t off = base + k * stride;
            insert(rb, ref, off, payload(off, static_cast<std::size_t>(len), copy), limit,
                   short_pool);
          }
        } else if (cap < max_cap) {
          const auto grown = static_cast<std::uint32_t>(
              std::min<std::uint64_t>(cap + in.u16() % (cap / 2 + 2), max_cap));
          rb.grow(grown);
          ref.grow(grown);
        }
        break;
    }
    UTCP_CHECK(limit <= rb.right_edge());
    check_same(rb, ref);
  }
  // The rest of the stream reads back the same.
  read(rb, ref, static_cast<std::size_t>(rb.readable()));
  check_same(rb, ref);
  return 0;
}
