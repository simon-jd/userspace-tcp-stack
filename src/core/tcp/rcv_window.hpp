// Receive window selection, rcv_adv and autotuning (RFC 9293 §3.8.6.2.2, RFC
// 7323 §2.4; Linux tcp_select_window, tcp_grow_window, tcp_rcv_space_adjust;
// DESIGN §4.10). Interface declared by m1-found; implemented by m1-rx
// (rcv_window.cpp).
//
// Windows are rounded down to a multiple of 2^rcv_wscale, so the right edge
// may retract by less than 2^rcv_wscale (RFC 7323 §2.4); acceptance and
// storage use rcv_adv(), the highest edge ever advertised, so nothing sent
// into an earlier window is lost.
#pragma once

#include <cstdint>
#include <optional>

#include "core/tcp/ack_policy.hpp"
#include "core/tcp/recv_buffer.hpp"
#include "utcp/config.hpp"
#include "utcp/time.hpp"

namespace utcp {

// The smallest receive buffer RcvWindow accepts with window scale
// `rcv_wscale`: 2^(rcv_wscale + 1) bytes (1 without scaling). Windows round
// down to 2^rcv_wscale and never reach past the buffer, so with less than
// 2^rcv_wscale of buffer the window is 0 for good; from 2^(rcv_wscale + 1)
// on, the rcv_ssthresh clamp and a drained buffer still leave at least
// 2^rcv_wscale. A socket's own rcv_buf (TcpSocketOptions) therefore needs a
// shift that fits it, e.g. default_rcv_wscale(rcv_buf); Linux instead
// rounds the window up past its soft buffer limit (__tcp_select_window).
[[nodiscard]] constexpr std::uint32_t min_rcv_buf(std::uint8_t rcv_wscale) noexcept {
  return rcv_wscale == 0 ? 1u : std::uint32_t{2} << rcv_wscale;
}

// The largest window scale a receive buffer of `rcv_buf` bytes (>= 1)
// supports: the largest s <= max_wscale with min_rcv_buf(s) <= rcv_buf. An
// engine that offers a shift from the configuration (effective_rcv_wscale)
// for a smaller socket buffer can offer min(that shift, max_rcv_wscale(rcv_buf)).
[[nodiscard]] constexpr std::uint8_t max_rcv_wscale(std::uint32_t rcv_buf) noexcept {
  std::uint8_t s = 0;
  while (s < max_wscale && min_rcv_buf(static_cast<std::uint8_t>(s + 1)) <= rcv_buf) {
    ++s;
  }
  return s;
}

struct SelectedWindow {
  std::uint32_t window = 0;  // bytes advertised (a multiple of 2^rcv_wscale)
  std::uint16_t field = 0;   // the header value, window >> rcv_wscale
};

class RcvWindow {
public:
  // rcv_buf: the buffer size in use; autotune: grow toward cfg.rcv_buf_max
  // (false when TcpSocketOptions::rcv_buf is set).
  RcvWindow(const TcpConfig& cfg, std::uint32_t rcv_buf, bool autotune);

  // Window field of our SYN or SYN-ACK, never scaled (RFC 7323 §2.2):
  // syn_window rfc = min(rcv_buf, 65535); linux = min(rcv_buf, 65535) rounded
  // down to a multiple of adv_mss (64240 at MSS 1460). Linux rounds to the
  // MSS it will receive: the SYN uses advmss (64240), the SYN-ACK to a SYN
  // with timestamps advmss - 12 (tcp_openreq_init_rwin: 65160 at 1448), so
  // the passive side passes adv_mss - 12 then.
  [[nodiscard]] std::uint16_t syn_window(std::uint16_t adv_mss) const;
  // The handshake completed. rcv_wscale: our shift (0 without window
  // scaling); `syn_edge`: RCV.NXT + the SYN window, as an offset (the first
  // rcv_adv). Starts rcv_ssthresh (linux) from the initial window.
  // Precondition (checked): rcv_buf >= min_rcv_buf(rcv_wscale).
  void on_established(std::uint8_t rcv_wscale, std::uint16_t adv_mss, std::uint64_t syn_edge);

  // The window for an outgoing segment: right_edge - RCV.NXT subject to the
  // receiver SWS rule (the edge moves only by >= min(rcv_buf / 2, rcv_mss))
  // and, with rcv_window_growth = linux, the rcv_ssthresh clamp; rounded down
  // to a multiple of 2^rcv_wscale (a window below that is 0). Raises
  // rcv_adv() when the advertised edge is higher.
  //
  // The SWS rule is applied to the rounded edge: a new edge is advertised
  // only if it lies at least min(rcv_buf / 2, rcv_mss) above rcv_adv();
  // otherwise the window is rcv_adv() - RCV.NXT rounded down. When that
  // rounds to 0, the new edge is advertised anyway if its window is at least
  // min(rcv_buf / 2, rcv_mss) or nothing is left to read (no read can free
  // more space), so a window closed by rounding always reopens. The linux
  // target is __tcp_select_window's: below half the buffer free, a free
  // space under rcv_buf / 16 or rcv_mss gives 0; then min(free, rcv_ssthresh);
  // without window scaling the MSS-multiple rule. Linux rounds the scaled
  // window up (ALIGN); this rounds it down (DESIGN §4.10).
  SelectedWindow select(const RecvBuffer& rb, std::uint16_t rcv_mss);
  // The highest right edge ever advertised, as an offset (RFC 7323 §2.4).
  [[nodiscard]] std::uint64_t rcv_adv() const;
  // The last advertised window in bytes (Tcb::rcv_wnd, tcpi_rcv_wnd).
  [[nodiscard]] std::uint32_t last_window() const;
  // The last select() went from a non-zero to a zero window or back
  // (TcpExtTCPToZeroWindowAdv, TcpExtTCPFromZeroWindowAdv).
  [[nodiscard]] bool went_to_zero() const;
  [[nodiscard]] bool went_from_zero() const;

  // An in-order segment of `len` bytes was stored (Linux tcp_grow_window:
  // rcv_ssthresh += 2 * rcv_mss up to the buffer's window).
  //
  // As Linux 7.0: segments of >= 128 bytes only (tcp_event_data_recv); the
  // step is max(2 * adv_mss, 2 * len) (the "check #2" branch, taken whenever
  // the skb's overhead fits, which always holds for payload-byte buffers),
  // limited by the room min(rcv_buf, right_edge - RCV.NXT) - rcv_ssthresh.
  // Linux 7.0 also calls it for out-of-order segments when SACK is on
  // (tcp_data_queue_ofo); the engine may do the same. A rise is visible
  // through rcv_ssthresh() (AckPolicy::on_rcv_ssthresh_grew). rcv_mss is
  // unused (kept for the interface).
  void on_in_order_data(std::uint32_t len, std::uint16_t rcv_mss, const RecvBuffer& rb);
  // The window state AckPolicy::on_window and on_read take (Linux
  // __tcp_select_window as __tcp_ack_snd_check and tcp_select_window see
  // it): data unread, the window before the SWS rule (rounded down) at least
  // last_window(), less than half the buffer free, and out-of-order data
  // held.
  [[nodiscard]] RcvWindowView ack_view(const RecvBuffer& rb, std::uint16_t rcv_mss) const;

  // After the application read: whether a window update should be sent now
  // (window_update_after_read: rfc when the edge can move by >= min(rcv_buf /
  // 2, MSS); linux when the new window is >= 2 * the current one, which is
  // the window last advertised less the data received since,
  // tcp_cleanup_rbuf and tcp_receive_window).
  [[nodiscard]] bool update_after_read(const RecvBuffer& rb, std::uint16_t rcv_mss) const;

  // Receiver RTT estimate (Linux tcp_rcv_rtt_measure, tcp_rcv_rtt_measure_ts),
  // called for each data segment: `rcv_nxt` after it; `ts_rtt` = now_ts -
  // TSecr when the segment echoes a new TSecr and carries >= rcv_mss bytes.
  // The first call also starts the first autotuning interval (Linux starts
  // it at tcp_init_buffer_space).
  void on_data_rtt(Time now, std::uint64_t rcv_nxt, std::optional<Duration> ts_rtt);
  // Linux tcp_rcv_space_adjust, after reads: once per receiver RTT the buffer
  // grows to 2 * the bytes read in that RTT, up to rcv_buf_max. Returns the
  // new buffer size when it grew (the engine calls RecvBuffer::grow).
  //
  // As Linux 7.0 (tcp_rcv_space_adjust, tcp_rcvbuf_grow): copied = bytes read
  // in the interval minus the bytes still unread; if copied > rcv_space():
  // window = 2 * copied plus, at a receiver RTT >= 1 ms
  // (tcp_rcvbuf_low_rtt), 2 * 2 * copied * (copied - rcv_space) / rcv_space
  // (room for a doubling sender), below it 2 * copied * rtt / 1 ms. Linux
  // also adds the span of out-of-order data; here that data does not use up
  // window (it sits at its offset below right_edge()), so it is not added.
  [[nodiscard]] std::optional<std::uint32_t> on_read(Time now, std::uint64_t read_offset);

  [[nodiscard]] Duration rcv_rtt() const;          // tcpi_rcv_rtt; 0 before a sample
  [[nodiscard]] std::uint32_t rcv_space() const;   // tcpi_rcv_space
  [[nodiscard]] std::uint32_t rcv_ssthresh() const;  // tcpi_rcv_ssthresh
  [[nodiscard]] std::uint32_t rcv_buf() const;     // the buffer size in use

private:
  // The window select() would advertise, without changing state.
  [[nodiscard]] std::uint32_t compute(const RecvBuffer& rb, std::uint16_t rcv_mss) const;
  // The window before the SWS rule: free space, or Linux's target.
  [[nodiscard]] std::uint64_t target(const RecvBuffer& rb, std::uint16_t rcv_mss) const;
  void rtt_update(Duration sample, bool win_dep, bool queue_empty);
  [[nodiscard]] std::optional<std::uint32_t> rcvbuf_grow(std::uint32_t copied);

  // Configuration (copied: the Tcb may move).
  bool linux_growth_;
  bool linux_syn_window_;
  bool linux_update_after_read_;
  bool autotune_;
  std::uint32_t rcv_buf_max_;

  std::uint32_t rcv_buf_;
  std::uint8_t wscale_ = 0;
  std::uint16_t adv_mss_ = 536;
  std::uint64_t rcv_adv_ = 0;        // offset
  std::uint32_t last_window_ = 0;    // bytes
  std::uint64_t wup_ = 0;            // RCV.NXT when last_window_ was chosen (rcv_wup)
  bool to_zero_ = false;
  bool from_zero_ = false;
  std::uint32_t rcv_ssthresh_;

  // Receiver RTT (rcv_rtt_est): 8 * the estimate, as Linux keeps it.
  Duration rtt8_{0};
  std::uint64_t rtt_seq_ = 0;        // rcv_rtt_est.seq
  std::optional<Time> rtt_time_;     // rcv_rtt_est.time
  // Autotuning (rcvq_space).
  std::uint32_t space_ = 0;
  std::uint64_t space_seq_ = 0;
  std::optional<Time> space_time_;
  std::uint64_t rcv_nxt_ = 0;        // the latest RCV.NXT seen, as an offset
  std::uint64_t data_rcv_nxt_ = 0;   // RCV.NXT at the last on_data_rtt
  std::uint64_t read_off_ = 0;       // copied_seq
};

}  // namespace utcp
