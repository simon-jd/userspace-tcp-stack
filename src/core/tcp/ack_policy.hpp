// When to acknowledge received data (RFC 9293 §3.8.6.3, RFC 5681 §4.2; Linux
// __tcp_ack_snd_check, tcp_event_data_recv; DESIGN §4.10). Interface declared
// by m1-found; implemented by m1-rx (ack_policy.cpp).
//
// ACK immediately for out-of-order data, a hole-filling segment, a D-SACK,
// FIN, quick-ack mode (linux_compat), or when ack_every_full_segments full
// segments (judged against rcv_mss) are unacknowledged (linux_compat: and
// the window is not shrinking or nothing is unread, see on_window);
// otherwise a delayed ACK at now + ato. Profiles differ in delack_ato (fixed
// 200 ms or Linux's adaptive 40..200 ms) and quickack (§3.9).
#pragma once

#include <cstdint>

#include "core/tcp/recv_buffer.hpp"
#include "utcp/config.hpp"
#include "utcp/time.hpp"

namespace utcp {

// What the connection owes the peer after input processing.
enum class AckNeed : std::uint8_t { none, delayed, now };

// The receive window as Linux's ACK decisions see it (linux_compat);
// RcvWindow::ack_view computes it from the RecvBuffer. The defaults leave
// the decisions as without a view.
struct RcvWindowView {
  // In-order data not read yet (RCV.NXT - copied_seq >= SO_RCVLOWAT = 1).
  bool unread = false;
  // The window computed now is at least the last advertised one (Linux
  // __tcp_select_window(sk) >= tp->rcv_wnd): the right edge would move by at
  // least the data received since.
  bool not_shrinking = true;
  // Less than half the buffer is free (Linux __tcp_select_window then clears
  // icsk_ack.quick).
  bool low_space = false;
  // Out-of-order data is held (with `unread`: Linux sk_rmem_alloc != 0).
  bool ooo_held = false;
};

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
  // (r.filled_hole, or r.advanced with r.ooo_held; RFC 5681 §4.2), in-order
  // data dropped for lack of chunks (Linux ICSK_ACK_NOW without quick-ack
  // mode; Linux also advertises a zero window then, which rcv_adv rules out
  // here), and a segment that brought nothing new (Linux tcp_data_queue:
  // data below RCV.NXT or at a zero window enters quick-ack mode). A
  // duplicate alone does not force an ACK: the engine calls ack_now() when it
  // records a D-SACK (SACK negotiated and cfg.dsack). Only in-order data
  // updates ato and the inter-arrival clock (tcp_event_data_recv); rcv_mss is
  // measured on in-order and out-of-order data (Linux 7.0 also measures in
  // tcp_data_queue_ofo). quickack = linux: an out-of-order segment dropped
  // whole (r.dropped, for lack of chunks or at the range limit) changes
  // nothing and owes no ACK, as Linux tcp_data_queue_ofo returns on a failed
  // tcp_try_rmem_schedule before tcp_measure_rcv_mss and
  // inet_csk_schedule_ack; quickack = rfc sends the duplicate ACK (RFC 5681
  // §4.2).
  void on_data(Time now, std::uint32_t len, std::uint16_t gso_size, const InsertResult& r,
               std::uint32_t rcv_wnd, Duration rto);
  // An event that needs an immediate ACK (Linux ICSK_ACK_NOW): FIN, a
  // D-SACK, a zero-window drop, a window update after a read. It does not
  // count as received data, so the ACK it causes uses up no quick ACK
  // (tcp_dec_quickack_mode counts only a scheduled ACK; Linux schedules one
  // for a FIN, but no data follows a FIN).
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

  // The receive window after a data segment (call after on_data and
  // RcvWindow::on_in_order_data, before need(); `v` from RcvWindow::ack_view).
  // quickack = linux: more than ack_every_full_segments - 1 full segments
  // unacknowledged send an ACK at once only if nothing is unread or the
  // window is not shrinking (__tcp_ack_snd_check: "right edge of window
  // advances far enough", else tcp_recvmsg sends it, see on_read); checking
  // that with less than half the buffer free ends quick-ack mode
  // (__tcp_select_window). An ACK that is then delayed arms the timer.
  void on_window(Time now, const RcvWindowView& v);
  // The application read data (call after a RecvBuffer::read that returned
  // bytes, with the new view). quickack = linux: with an ACK owed, ACK now if
  // more than one full segment is unacknowledged (tcp_cleanup_rbuf:
  // "once-per-two-segments ACK was not sent by tcp_input.c") or if a segment
  // shorter than rcv_mss arrived since the last ACK and the read left nothing
  // unread and no out-of-order data (ICSK_ACK_PUSHED and !sk_rmem_alloc:
  // "user drained receive buffer and there was a small segment in queue").
  // The window update after a read is RcvWindow::update_after_read's.
  void on_read(const RcvWindowView& v);

  // After input processing: nothing owed, a delayed ACK at delack_deadline(),
  // or an ACK now.
  [[nodiscard]] AckNeed need() const;
  // When need() == delayed: the delack timer's deadline.
  [[nodiscard]] Time delack_deadline() const;

  // A segment carrying ACK = RCV.NXT was sent (data, FIN or a pure ACK):
  // clears what was owed and uses up one quick ACK. quickack = linux: sent
  // with less than half the buffer free (the last view's low_space), it ends
  // quick-ack mode (tcp_select_window -> __tcp_select_window).
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
  // __tcp_ack_snd_check: more than ack_every_full_segments - 1 full
  // segments unacknowledged.
  [[nodiscard]] bool full_segments_owed() const;

  // Configuration (copied: the Tcb may move).
  Duration delack_max_;
  Duration ato_min_;
  std::uint32_t ack_every_;
  std::uint32_t quickack_max_;
  bool adaptive_ato_;
  bool linux_quickack_;
  bool pushed_ = false;
  bool seen_data_ = false;
  bool pending_ = false;             // data arrived since the last ACK (ICSK_ACK_SCHED)
  bool now_ = false;                 // ICSK_ACK_NOW
  bool timer_ = false;               // delack timer armed (ICSK_ACK_TIMER)

  std::uint16_t adv_mss_ = 536;
  std::uint16_t rcv_mss_ = 536;      // TCP_MSS_DEFAULT until init()
  std::uint32_t last_seg_size_ = 0;  // icsk_ack.last_seg_size
  // A segment below rcv_mss arrived since the last ACK (ICSK_ACK_PUSHED).
  Duration ato_{0};
  Duration rto_{0};
  Duration srtt_{0};
  Time lrcvtime_;                    // last in-order data arrival
  std::uint32_t quick_ = 0;          // icsk_ack.quick
  Time deadline_ = Time::never();
  std::uint64_t rcv_nxt_ = 0;        // offsets, from InsertResult::contiguous_end
  std::uint64_t rcv_wup_ = 0;        // RCV.NXT when the last ACK was sent
  RcvWindowView view_;               // the last on_window or on_read view
};

}  // namespace utcp
