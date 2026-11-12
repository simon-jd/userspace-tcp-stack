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
  void on_data(Time now, std::uint32_t len, std::uint16_t gso_size, const InsertResult& r,
               std::uint32_t rcv_wnd, Duration rto);
  // An event that needs an immediate ACK (Linux ICSK_ACK_NOW): FIN, a
  // D-SACK, a zero-window drop, a window update after a read.
  void ack_now();
  // Linux tcp_enter_quickack_mode (e.g. data below RCV.NXT).
  void enter_quickack(std::uint32_t rcv_wnd);

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
  [[nodiscard]] Duration ato() const;           // tcpi_ato
  [[nodiscard]] bool in_quickack_mode() const;

private:
  // Implementation state is m1-rx's.
};

}  // namespace utcp
