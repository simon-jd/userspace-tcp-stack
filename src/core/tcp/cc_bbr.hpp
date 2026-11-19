// Per-connection BBRv1 model, following Linux v7.0 net/ipv4/tcp_bbr.c.
#pragma once

#include <array>
#include <cstdint>

#include "core/tcp/cc.hpp"
#include "core/tcp/minmax.hpp"

namespace utcp {

class Bbr final : public CongestionControl {
 public:
  enum class Mode : std::uint8_t { startup, drain, probe_bw, probe_rtt };
  struct Info {
    Mode mode;
    bool lt_use_bw;
    std::uint32_t bandwidth_q24;  // packets per microsecond, scaled by 2^24
    std::uint32_t min_rtt_us;     // UINT32_MAX until measured
    std::uint32_t pacing_gain_q8, cwnd_gain_q8;
  };

  [[nodiscard]] Info info() const;
  [[nodiscard]] std::string_view name() const override { return "bbr"; }
  void init(CcConn& c) override;
  std::uint32_t ssthresh(const CcConn& c) override;
  std::uint32_t undo_cwnd(const CcConn& c) override;
  void cong_avoid(CcConn&, const AckOutcome&) override {}
  [[nodiscard]] bool has_cong_control() const override { return true; }
  void cong_control(CcConn& c, const AckOutcome&, const RateSample& rs) override;
  void set_state(CcConn& c, CaState state) override;
  void cwnd_event(CcConn& c, CaEvent event) override;
  [[nodiscard]] std::uint32_t sndbuf_expand() const override { return 3; }
  [[nodiscard]] std::uint32_t min_tso_segs(const CcConn& c) const override;

 private:
  std::uint32_t bandwidth() const;
  void init_rate(CcConn& c);
  void pace(CcConn& c, std::uint32_t gain);
  std::uint32_t tso_goal(const CcConn& c) const;
  std::uint32_t flight_target(const CcConn& c, std::uint32_t bw, std::uint32_t gain,
                              std::uint32_t bonus = 0) const;
  std::uint32_t flight_at_edt(const CcConn& c, std::uint32_t flight) const;
  void save_window(const CcConn& c);
  void update_window(CcConn& c, const RateSample& rs);
  void start_lt_interval(const CcConn& c);
  void reset_lt(const CcConn& c);
  void sample_lt(const CcConn& c, const RateSample& rs);
  void sample_bw(const CcConn& c, const RateSample& rs);
  void sample_aggregation(const CcConn& c, const RateSample& rs);
  void check_plateau(const RateSample& rs);
  void start_probe_bw(const CcConn& c);
  void cycle(const CcConn& c, const RateSample& rs);
  void check_drain(CcConn& c);
  void finish_probe_rtt(CcConn& c);
  void probe_rtt(CcConn& c, const RateSample& rs);
  void update_gains();

  Mode mode_ = Mode::startup;
  // bbr_init uses high_gain directly. Stored gains are set by the first ACK.
  std::uint32_t pacing_gain_ = 0, cwnd_gain_ = 0;
  WindowMax max_bw_;
  std::uint32_t min_rtt_us_ = UINT32_MAX, min_stamp_ = 0;
  std::uint64_t next_round_ = 0;
  std::uint32_t rounds_ = 0, plateau_bw_ = 0, plateau_rounds_ = 0;
  bool round_start_ = false, full_pipe_ = false, seen_srtt_ = false, idle_ = false;

  std::uint32_t phase_ = 0;
  Time phase_start_;
  std::uint32_t probe_deadline_ = 0;  // Linux uses zero as the unarmed jiffies32 value.
  bool probe_round_ = false;
  CaState previous_ca_ = CaState::open;
  std::uint32_t saved_cwnd_ = 0;
  bool conserve_ = false;

  bool lt_sampling_ = false, lt_active_ = false;
  std::uint32_t lt_rounds_ = 0, lt_bw_ = 0;
  std::uint64_t lt_delivered_ = 0, lt_lost_ = 0;
  Time lt_start_;

  Time epoch_;
  std::uint32_t epoch_acked_ = 0, bucket_rounds_ = 0;
  std::size_t bucket_ = 0;
  std::array<std::uint16_t, 2> extra_{};
};

void emplace_bbr(CcStorage& s);
}  // namespace utcp
