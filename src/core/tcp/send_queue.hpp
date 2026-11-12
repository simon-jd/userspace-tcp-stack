// Send buffer and retransmission queue (DESIGN §4.11).
// Interface declared by m1-found; implemented by m1-tx (send_queue.cpp).
//
// Application bytes live in a ByteRing addressed by stream offset (offset 0
// is the byte at ISS + 1). Every transmitted wire packet is one TxSeg for its
// whole life (Linux pcount 1); the counters count TxSegs. FIN is a flag on the
// last TxSeg and has no offset (§3.2): an ACK covering it is end() + 1 at the
// engine boundary and is clipped to end() by process_ack.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "core/buffer/byte_ring.hpp"
#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/rate.hpp"
#include "core/util/function_ref.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {

struct TxSeg {  // one wire packet for its whole life: len <= mss_cache at send
  std::uint64_t id = 0;    // stable, monotonic per connection (survives pops and split_to_mss)
  std::uint64_t off = 0;   // stream offset of the first payload byte
  std::uint32_t len = 0;   // payload bytes; 0 only for a bare FIN
  bool fin = false;        // carries our FIN after its payload
  bool sacked = false;     // TCPCB_SACKED_ACKED
  bool lost = false;       // TCPCB_LOST
  bool retrans_inflight = false;  // TCPCB_SACKED_RETRANS: a retransmission is in flight
  bool ever_retrans = false;      // TCPCB_EVER_RETRANS
  std::uint16_t tx_count = 0;     // transmissions so far (RACK, RFC 8985 §6.1)
  Time first_tx, last_tx;         // RACK uses last_tx (xmit_ts)
  // Delivery-rate snapshot at last_tx (tcp_rate_skb_sent); rate_used: the
  // snapshot was consumed by a SACK (tcp_rate_skb_delivered).
  std::uint64_t delivered = 0;
  Time delivered_time, first_tx_time;
  bool app_limited = false;
  bool rate_used = false;

  [[nodiscard]] constexpr std::uint64_t end() const noexcept { return off + len; }

  bool operator==(const TxSeg&) const = default;
};

struct Counters {  // packets = TxSegs (Linux tcp_sock packets_out, sacked_out, ...)
  std::uint32_t packets_out = 0, sacked_out = 0, lost_out = 0, retrans_out = 0;
  std::uint64_t bytes_sent = 0;     // tcpi_bytes_sent, retransmissions included
  std::uint64_t bytes_retrans = 0;  // tcpi_bytes_retrans
  std::uint64_t bytes_acked = 0;    // tcpi_bytes_acked

  bool operator==(const Counters&) const = default;
};

// Linux tcp_packets_in_flight (§4.11).
[[nodiscard]] constexpr std::uint32_t packets_in_flight(const Counters& c) noexcept {
  return c.packets_out - (c.sacked_out + c.lost_out) + c.retrans_out;
}

struct AckedSummary {  // from on_cumulative_ack
  std::uint32_t pkts = 0;          // TxSegs fully acked and popped
  bool retrans_acked = false;      // FLAG_RETRANS_DATA_ACKED
  bool stopped_at_sacked = false;  // the new head is SACKed (tcp_check_sack_reneging)

  bool operator==(const AckedSummary&) const = default;
};

struct SackedSummary {  // from on_sack (FLAG_SACK_RENEGING is the engine's)
  std::uint32_t newly_sacked = 0;
  std::uint64_t high_sacked = 0;  // end offset of the highest SACKed TxSeg

  bool operator==(const SackedSummary&) const = default;
};

// Called once per newly delivered TxSeg, in sequence order, before it is
// popped (cumulative ACK) or after it is marked (SACK). Non-owning.
using DeliveredFn = FunctionRef<void(const TxSeg&, bool via_sack)>;

// Most blocks SendQueue::on_sack takes in one call (an option carries at most
// 4, wire::max_sack_blocks; process_ack passes at most this many).
inline constexpr std::size_t max_sack_ranges = 8;

class SendQueue {
public:
  // `capacity`: send buffer size in payload bytes (snd_buf); chunks come from
  // `pool` when bytes are first written.
  SendQueue(ChunkPool& pool, std::uint32_t capacity);

  // Copies application bytes in, up to free_space(); returns the count (0 if
  // full or if the chunk pool is exhausted).
  std::size_t write(std::span<const std::byte> data);

  [[nodiscard]] std::uint64_t una() const;  // first unacknowledged byte (SND.UNA as an offset)
  [[nodiscard]] std::uint64_t nxt() const;  // first byte never sent (SND.NXT as an offset); never moves back
  [[nodiscard]] std::uint64_t end() const;  // one past the last byte written
  [[nodiscard]] std::uint32_t free_space() const;  // capacity() - (end() - una())
  [[nodiscard]] std::uint32_t capacity() const;
  // Autotuning (tcp_sndbuf_expand) or TcpSocketOptions::snd_buf. A capacity
  // below the bytes held only stops further writes.
  void set_capacity(std::uint32_t capacity);

  // Copies stream bytes [off, off + dst.size()) out of the ring for a segment.
  // Precondition (checked): una() <= off and off + dst.size() <= end().
  void copy_out(std::uint64_t off, std::span<std::byte> dst) const;

  // Records a transmission. New data: off == nxt(), appends a TxSeg (with
  // `fin` for a FIN riding on it, or len == 0 for a bare FIN at end()) and
  // advances nxt(). Retransmission: off and len are those of an existing
  // TxSeg; tx_count, last_tx, retrans flags and counters are updated. The rate
  // snapshot is taken from `rate` (call rate_on_send first).
  TxSeg& on_transmit(std::uint64_t off, std::uint32_t len, bool fin, Time now,
                     const RateState& rate);

  // Both call `fn` once per newly delivered segment, in sequence order, before
  // it is popped. `new_una` is clipped to end() by the caller. A TxSeg is
  // popped once its payload is acknowledged and, if it carries our FIN, the
  // FIN too; a cumulative ACK inside a TxSeg trims its head (tcp_trim_head),
  // so a FIN-bearing TxSeg whose payload is acknowledged but whose FIN is not
  // stays as a bare FIN. Without SACK, a cumulative ACK of n TxSegs removes
  // min(n - 1, sacked_out) (tcp_remove_reno_sacks).
  AckedSummary on_cumulative_ack(std::uint64_t new_una, Time now, DeliveredFn fn);  // pops/trims
  // The same with `fin_acked`: the ACK covered our FIN (SEG.ACK = end() + 1
  // at the engine boundary, clipped to end(); process_ack passes it).
  AckedSummary on_cumulative_ack(std::uint64_t new_una, bool fin_acked, Time now,
                                 DeliveredFn fn);
  // Blocks are offset ranges, validated and clipped by the caller, at most
  // max_sack_ranges (checked), in any order: they are walked sorted by start
  // (Linux tcp_sacktag_write_queue), so `fn` runs in sequence order. Only
  // whole TxSegs are SACKed; a block covering a TxSeg partly never splits it.
  // A bare FIN is never SACKed. As Linux tcp_sacktag_one: a lost segment loses
  // its lost mark, and a retransmission in flight of a lost segment is no
  // longer counted. `fn` runs after the segment is marked; its rate snapshot
  // is then marked used (rate_used). Ignored without SACK (set_sack_ok).
  SackedSummary on_sack(std::span<const Range> blocks, Time now, DeliveredFn fn);

  // Marks the TxSeg starting at `off` lost (by offset, stable across pops), as
  // Linux tcp_mark_skb_lost: no effect on a SACKed TxSeg; a TxSeg already
  // lost whose retransmission is in flight counts that retransmission as lost
  // (retrans_inflight cleared). Precondition (checked): a TxSeg starts at off.
  void mark_lost(std::uint64_t off);
  // Clears every SACK mark: reneging detected at RTO (§5.3). Without SACK it
  // resets the duplicate-ACK count sacked_out (tcp_reset_reno_sack).
  void clear_all_sacked();
  // Without SACK, a duplicate ACK counts as one SACKed packet, capped so that
  // sacked_out + max(lost_out, 1) <= packets_out (tcp_add_reno_sack,
  // tcp_limit_reno_sacked); a cumulative ACK of n packets then removes
  // min(n - 1, sacked_out) (tcp_remove_reno_sacks).
  void reno_dupack();
  // Whether SACK was negotiated (selects the reno accounting above).
  void set_sack_ok(bool sack_ok);
  // PMTU decrease (§4.13): splits queued TxSegs longer than `mss` into
  // several, keeping ids of the first parts. The parts inherit the flags,
  // times and rate snapshot (Linux tcp_fragment); new parts get new ids.
  void split_to_mss(std::uint16_t mss);

  [[nodiscard]] const Counters& counters() const;
  // Packets marked lost so far (Linux tp->lost): mark_lost calls that set a
  // lost mark or found a lost retransmission. AckOutcome::newly_lost is its
  // change over one ACK.
  [[nodiscard]] std::uint64_t lost_total() const;
  [[nodiscard]] bool sack_ok() const;
  // A TxSeg carrying our FIN was transmitted; that TxSeg was acknowledged.
  [[nodiscard]] bool fin_sent() const;
  [[nodiscard]] bool fin_acked() const;
  // SND.UNA and SND.NXT as offsets in which our FIN counts one unit past
  // end(), as in sequence space (loss recovery's `recover`, RTT rounds).
  [[nodiscard]] std::uint64_t una_with_fin() const;
  [[nodiscard]] std::uint64_t nxt_with_fin() const;
  // In sequence order.
  [[nodiscard]] std::span<const TxSeg> segs() const;
  // The TxSeg starting at `off`, or nullptr.
  [[nodiscard]] const TxSeg* find(std::uint64_t off) const;

  // Counters equal a recount of segs(); aborts on failure (Tcb::check_invariants).
  void check_invariants() const;

private:
  [[nodiscard]] TxSeg* find_mut(std::uint64_t off);
  [[nodiscard]] std::size_t index_of(std::uint64_t off) const;  // first TxSeg with seg.off >= off
  void snapshot(TxSeg& seg, const RateState& rate) const;
  void limit_reno_sacked();
  void compact();

  ByteRing ring_;  // begin() is una()
  std::uint32_t capacity_;
  std::uint64_t nxt_ = 0, end_ = 0;
  // TxSegs in sequence order: segs_[head_, size()); popped entries below
  // head_ are dropped by compact() (amortised O(1) per pop).
  std::vector<TxSeg> segs_;
  std::size_t head_ = 0;
  std::uint64_t next_id_ = 0;
  Counters ctr_;
  std::uint64_t lost_total_ = 0;
  std::uint64_t high_sacked_ = 0;  // highest end of a TxSeg SACKed since the last clear
  bool sack_ok_ = true;
  bool fin_sent_ = false, fin_acked_ = false;
};

}  // namespace utcp
