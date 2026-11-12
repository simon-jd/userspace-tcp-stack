// When to acknowledge received data (RFC 9293 §3.8.6.3, RFC 5681 §4.2; Linux
// __tcp_ack_snd_check, tcp_event_data_recv; DESIGN §4.10). Interface declared
// by m1-found; implemented by m1-rx (ack_policy.cpp).
//
// ACK immediately for out-of-order data, a hole-filling segment, a D-SACK,
// FIN, quick-ack mode (linux_compat), or when ack_every_full_segments full
// segments (judged against rcv_mss) are unacknowledged; otherwise a delayed
// ACK at now + ato. Profiles differ in delack_ato (fixed 200 ms or Linux's
// adaptive 40..200 ms) and quickack (§3.9).
#pragma once

#include <cstdint>

#include "core/tcp/recv_buffer.hpp"
#include "utcp/config.hpp"
#include "utcp/time.hpp"

namespace utcp {

// What the connection owes the peer after input processing.
enum class AckNeed : std::uint8_t { none, delayed, now };

class AckPolicy {
public:
  explicit AckPolicy(const TcpConfig& cfg);

  // The connection is synchronized: the first rcv_mss estimate (Linux
  // tcp_initialize_rcv_mss: min(adv_mss, mss_cache, rcv_wnd / 2, 536), at
  // least 88).
  void init(std::uint16_t adv_mss, std::uint16_t mss_cache, std::uint32_t rcv_wnd);

  // An acceptable segment with `len` payload bytes went through
  // RecvBuffer::insert with result `r`. `gso_size` is RxMeta::gso_size
  // (rcv_mss takes it when set, tcp_measure_rcv_mss); `rcv_wnd` is the window
  // last advertised (quick-ack count min(quickack_max, rcv_wnd / (2 *
  // rcv_mss))); `rto` caps ato, and an idle gap above it re-enters quick-ack
  // mode (linux_compat).
  //
  // ACK now: out-of-order data, data that filled all or part of a gap
  // (r.filled_hole, or r.advanced with r.ooo_held; RFC 5681 §4.2), a
  // duplicate when D-SACK is on, and a segment that brought nothing new
  // (Linux tcp_data_queue: data below RCV.NXT or at a zero window enters
  // quick-ack mode). Only in-order data updates ato and the inter-arrival
  // clock (tcp_event_data_recv); rcv_mss is measured on in-order and
  // out-of-order data (Linux 7.0 also measures in tcp_data_queue_ofo).
  void on_data(Time now, std::uint32_t len, std::uint16_t gso_size, const InsertResult& r,
               std::uint32_t rcv_wnd, Duration rto);
  // An event that needs an immediate ACK (Linux ICSK_ACK_NOW): FIN, a
  // D-SACK, a zero-window drop, a window update after a read. It does not
  // count as received data, so the ACK it causes uses up no quick ACK.
  void ack_now();
  // Linux tcp_enter_quickack_mode (e.g. data below RCV.NXT): an ACK is owed
  // now; linux_compat also refills the quick-ack count and resets ato.
  void enter_quickack(std::uint32_t rcv_wnd);
  // RcvWindow::on_in_order_data raised rcv_ssthresh: the next ACK goes out at
  // once (Linux 7.0 tcp_grow_window: icsk_ack.quick |= 1). quickack = linux
  // only.
  void on_rcv_ssthresh_grew();
  // The smoothed RTT of the connection (0: no sample yet). With adaptive ato,
  // a delayed ACK waits at most max(srtt, delack_ato_min) once ato exceeds
  // delack_ato_min (Linux tcp_send_delayed_ack).
  void set_srtt(Duration srtt);

  // After input processing: nothing owed, a delayed ACK at delack_deadline(),
  // or an ACK now.
  [[nodiscard]] AckNeed need() const;
  // When need() == delayed: the delack timer's deadline.
  [[nodiscard]] Time delack_deadline() const;

  // A segment carrying ACK = RCV.NXT was sent (data, FIN or a pure ACK):
  // clears what was owed and uses up one quick ACK.
  void on_ack_sent(Time now);
  // The delack timer fired (the engine counts TcpExtDelayedACKs); need()
  // becomes now.
  void on_delack_timer(Time now);

  [[nodiscard]] std::uint16_t rcv_mss() const;  // tcpi_rcv_mss
  // tcpi_ato; 0 before the first data with adaptive ato. Linux lets ato reach
  // the RTO; here it stays at most delack_max, the longest delay used.
  [[nodiscard]] Duration ato() const;
  [[nodiscard]] bool in_quickack_mode() const;

private:
  void measure_rcv_mss(std::uint32_t len, std::uint16_t gso_size);
  void incr_quickack(std::uint32_t rcv_wnd);
  void schedule_delayed(Time now);

  // Configuration (copied: the Tcb may move).
  Duration delack_max_;
  Duration ato_min_;
  std::uint32_t ack_every_;
  std::uint32_t quickack_max_;
  bool adaptive_ato_;
  bool linux_quickack_;
  bool dsack_;

  std::uint16_t adv_mss_ = 536;
  std::uint16_t rcv_mss_ = 536;      // TCP_MSS_DEFAULT until init()
  std::uint32_t last_seg_size_ = 0;  // icsk_ack.last_seg_size
  Duration ato_{0};
  Duration rto_{0};
  Duration srtt_{0};
  Time lrcvtime_;                    // last in-order data arrival
  bool seen_data_ = false;
  std::uint32_t quick_ = 0;          // icsk_ack.quick
  bool pending_ = false;             // data arrived since the last ACK (ICSK_ACK_SCHED)
  bool now_ = false;                 // ICSK_ACK_NOW
  bool timer_ = false;               // delack timer armed (ICSK_ACK_TIMER)
  Time deadline_ = Time::never();
  std::uint64_t rcv_nxt_ = 0;        // offsets, from InsertResult::contiguous_end
  std::uint64_t rcv_wup_ = 0;        // RCV.NXT when the last ACK was sent
};

}  // namespace utcp
