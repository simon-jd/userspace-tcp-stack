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

#include "core/tcp/recv_buffer.hpp"
#include "utcp/config.hpp"
#include "utcp/time.hpp"

namespace utcp {

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
  // syn_window rfc = min(rcv_buf, 65535); linux = 65535 rounded down to a
  // multiple of adv_mss (64240 at MSS 1460).
  [[nodiscard]] std::uint16_t syn_window(std::uint16_t adv_mss) const;
  // The handshake completed. rcv_wscale: our shift (0 without window
  // scaling); `syn_edge`: RCV.NXT + the SYN window, as an offset (the first
  // rcv_adv). Starts rcv_ssthresh (linux) from the initial window.
  void on_established(std::uint8_t rcv_wscale, std::uint16_t adv_mss, std::uint64_t syn_edge);

  // The window for an outgoing segment: right_edge - RCV.NXT subject to the
  // receiver SWS rule (the edge moves only by >= min(rcv_buf / 2, rcv_mss))
  // and, with rcv_window_growth = linux, the rcv_ssthresh clamp; rounded down
  // to a multiple of 2^rcv_wscale (a window below that is 0). Raises
  // rcv_adv() when the advertised edge is higher.
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
  void on_in_order_data(std::uint32_t len, std::uint16_t rcv_mss, const RecvBuffer& rb);
  // After the application read: whether a window update should be sent now
  // (window_update_after_read: rfc when the edge can move by >= min(rcv_buf /
  // 2, MSS); linux when the new window is >= 2 * the current one,
  // tcp_cleanup_rbuf).
  [[nodiscard]] bool update_after_read(const RecvBuffer& rb, std::uint16_t rcv_mss) const;

  // Receiver RTT estimate (Linux tcp_rcv_rtt_measure, tcp_rcv_rtt_measure_ts),
  // called for each data segment: `rcv_nxt` after it; `ts_rtt` = now_ts -
  // TSecr when the segment echoes a new TSecr and carries >= rcv_mss bytes.
  void on_data_rtt(Time now, std::uint64_t rcv_nxt, std::optional<Duration> ts_rtt);
  // Linux tcp_rcv_space_adjust, after reads: once per receiver RTT the buffer
  // grows to 2 * the bytes read in that RTT, up to rcv_buf_max. Returns the
  // new buffer size when it grew (the engine calls RecvBuffer::grow).
  [[nodiscard]] std::optional<std::uint32_t> on_read(Time now, std::uint64_t read_offset);

  [[nodiscard]] Duration rcv_rtt() const;          // tcpi_rcv_rtt; 0 before a sample
  [[nodiscard]] std::uint32_t rcv_space() const;   // tcpi_rcv_space
  [[nodiscard]] std::uint32_t rcv_ssthresh() const;  // tcpi_rcv_ssthresh
  [[nodiscard]] std::uint32_t rcv_buf() const;     // the buffer size in use

private:
  // Implementation state is m1-rx's.
};

}  // namespace utcp
