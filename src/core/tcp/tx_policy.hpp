// Output decisions: Nagle, sender SWS avoidance and the pacing gate (DESIGN
// §4.9, §5.5). Interface declared by m1-found; implemented by m1-tx
// (tx_policy.cpp). The engine's transmit() asks these questions; it builds
// and sends the segments itself.
#pragma once

#include <cstdint>
#include <optional>

#include "core/tcp/cc.hpp"
#include "utcp/config.hpp"
#include "utcp/time.hpp"

namespace utcp {

// The send-side view for one candidate new-data segment.
struct SendCheck {
  std::uint32_t seg_len = 0;         // payload bytes this segment would carry
  std::uint32_t mss = 0;             // mss_cache minus SACK option bytes (tcp_current_mss)
  std::uint32_t usable_window = 0;   // U = SND.UNA + SND.WND - SND.NXT, bytes
  std::uint32_t max_snd_wnd = 0;     // largest window the peer offered
  std::uint64_t unsent = 0;          // D: queued bytes not yet sent
  std::uint64_t snd_una = 0, snd_nxt = 0;  // stream offsets
  bool fin = false;                  // the segment carries FIN (Nagle-exempt)
  bool nodelay = false;
};

class TxPolicy {
public:
  explicit TxPolicy(const TcpConfig& cfg);

  // Sender SWS avoidance (RFC 9293 §3.8.6.2.1, Fs = 1/2). With D = unsent and
  // U = usable_window, send if (1) min(D, U) >= mss, or (2) D <= U (all
  // queued data fits; every send is pushed) and the Nagle condition holds, or
  // (3) min(D, U) >= max_snd_wnd / 2 and the Nagle condition holds. The
  // bracketed "[SND.NXT = SND.UNA]" of rules (2) and (3) is the Nagle
  // algorithm's, so it is nagle_allows() with the configured variant (rfc896
  // is the RFC's literal condition). A bare FIN (D = 0) is allowed; D = 0
  // without FIN is not. TcpConfig::sender_sws = false allows any segment.
  [[nodiscard]] bool sws_allows(const SendCheck& c) const;
  // Nagle (RFC 9293 §3.7.4) for a segment shorter than mss: rfc896 holds it
  // while any data is unacknowledged, minshall while a small segment is
  // unacknowledged (tcp_minshall_check). Always true for full segments, FIN
  // and nodelay.
  [[nodiscard]] bool nagle_allows(const SendCheck& c) const;
  // A new-data segment [off, off + len) was sent (tcp_minshall_update:
  // remembers the end of the last segment shorter than mss).
  void on_data_sent(std::uint64_t off, std::uint32_t len, std::uint32_t mss);

  // §5.5: the pacing gate applies when the CC asks for it (pacing_needed,
  // Pacing::cc_requested), always or never per TcpConfig::pacing, or when
  // test_fixed_pacing_rate is set; never for the first 10 data segments
  // (data_segs_out < 10).
  [[nodiscard]] bool pacing_applies(const CcConn& cc, std::uint64_t data_segs_out) const;
  // The rate the gate uses: test_fixed_pacing_rate if set, else cc.pacing_rate.
  [[nodiscard]] std::uint64_t gate_rate(const CcConn& cc) const;

private:
  Nagle nagle_;
  Pacing pacing_;
  bool sender_sws_;
  std::optional<std::uint64_t> fixed_rate_;
  std::uint64_t snd_sml_ = 0;  // Linux tp->snd_sml as a stream offset
};

// Segments one open gate allows (Linux tcp_tso_autosize):
// max(min((rate >> 10) + (gso_max_size >> (min_rtt_us >> 9)), gso_max_size) / mss,
//     min_tso_segs).
[[nodiscard]] std::uint32_t pacing_burst_segments(std::uint64_t rate, Duration min_rtt,
                                                  std::uint32_t gso_max_size, std::uint32_t mss,
                                                  std::uint32_t min_tso_segs);

// Earliest departure after a burst of `len` payload bytes sent at `now`
// (Linux tcp_update_skb_after_send), len_ns = len * 1e9 / rate:
// max(pacing_next, now) + len_ns - min(len_ns / 2, max(0, now - pacing_next)).
// rate 0 (no rate yet) adds nothing: max(pacing_next, now).
[[nodiscard]] Time pacing_next_after_send(Time pacing_next, Time now, std::uint64_t len,
                                          std::uint64_t rate);

// Linux tcp_update_pacing_rate: mss * max(cwnd, packets_out) / srtt, times
// pacing_ss_ratio % if cwnd < ssthresh / 2, else pacing_ca_ratio %, capped by
// max_pacing_rate (0 = no cap). Bytes per second; 0 without an RTT sample
// (srtt 0), saturating at 2^64 - 1.
[[nodiscard]] std::uint64_t pacing_rate_for(const CcConn& cc, std::uint32_t packets_out,
                                            const TcpConfig& cfg);

}  // namespace utcp
