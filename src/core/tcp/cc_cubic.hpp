// Integer CUBIC (RFC 9438 and Linux v7.0 net/ipv4/tcp_cubic.c).
#pragma once

#include <cstdint>
#include <optional>

#include "core/tcp/cc.hpp"
#include "core/tcp/hystart.hpp"

namespace utcp {

// Shared packet-counted primitives for Reno and CUBIC. Slow start returns
// only the packets left after crossing ssthresh on this ACK.
std::uint32_t slow_start(CcConn& c, std::uint32_t acked, std::uint32_t limit);
void cong_avoid_ai(CcConn& c, std::uint32_t window, std::uint32_t acked);

inline constexpr std::uint32_t cubic_beta = 717;
inline constexpr std::uint32_t cubic_beta_scale = 8 * (1024 + cubic_beta) / 3 / (1024 - cubic_beta);
inline constexpr std::uint32_t cube_rtt_scale = 41 * 10;
inline constexpr std::uint64_t cube_factor = (std::uint64_t{1} << 40) / cube_rtt_scale;
[[nodiscard]] std::uint32_t cubic_root(std::uint64_t value);

class Cubic final : public CongestionControl {
public:
  [[nodiscard]] std::string_view name() const override;
  void init(CcConn& c) override;
  std::uint32_t ssthresh(const CcConn& c) override;
  void cong_avoid(CcConn& c, const AckOutcome& out) override;
  void pkts_acked(CcConn& c, const AckSample& sample) override;
  void set_state(CcConn& c, CaState state) override;
  void cwnd_event(CcConn& c, CaEvent event) override;

private:
  friend struct CubicTestView;
  void begin_epoch(const CcConn& c);
  void linux_update(CcConn& c, std::uint32_t acked);
  void rfc_update(CcConn& c, std::uint32_t acked);
  void shift_epoch(std::uint32_t now, std::uint32_t idle);

  ClassicHyStart classic_;
  HyStartPlusPlus plus_;
  std::optional<std::uint32_t> epoch_, pause_;
  std::uint32_t last_max_ = 0, prior_ = 0, origin_ = 0, k_ = 0;
  std::uint32_t last_cwnd_ = 0, last_time_ = 0, cnt_ = 0, tcp_cwnd_ = 0;
  std::uint64_t ack_cnt_ = 0;
  std::uint32_t delay_min_us_ = 0;
  // RFC 9438 uses fractional window increments; both values use Q32 packets.
  std::uint64_t estimate_ = 0, fraction_ = 0;
};

void emplace_cubic(CcStorage& s);

}  // namespace utcp
