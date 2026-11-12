// The per-ACK structures shared by the ACK pipeline, loss recovery and
// congestion control (DESIGN §5.1), and the congestion-control interface
// (§5.2). Interface declared by m1-found; owned by m1-tx.
//
// Hooks mirror Linux struct tcp_congestion_ops so that tcp_cubic.c and
// tcp_bbr.c port with little change. cwnd and ssthresh are in packets, as in
// Linux and RFC 9438. Algorithms live in the TCB (CcStorage, cc_newreno.hpp),
// not on the heap.
#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include "core/tcp/rate.hpp"
#include "utcp/random.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {

// What the engine knows about one acceptable ACK, after converting it to
// stream offsets at the engine boundary (§3.2). Input to process_ack and
// LossRecovery::on_ack.
struct AckInput {
  Time now;
  std::uint64_t prior_una = 0;  // SND.UNA before this ACK
  // SEG.ACK as an offset; end() + 1 when it covers our FIN (process_ack
  // clips it to end() and reports ack_fin_acked).
  std::uint64_t new_una = 0;
  std::optional<std::uint32_t> tsecr;  // the TSecr of a timestamped ACK (to recovery)
  std::uint32_t now_ts = 0;            // our TS clock now (TSval we would send): TSecr check, §4.8
  // Validated SACK blocks other than a D-SACK (§4.5), offsets, unclipped
  // above end(); process_ack clips them.
  std::span<const Range> sack;
  std::optional<Range> dsack;  // a D-SACK block (RFC 2883 §4), if the ACK had one
  bool window_update = false;  // the ACK changed SND.WND
  bool dupack = false;         // RFC 5681 §2 duplicate ACK (or SACK of new data, RFC 6675 §2)
};

// AckOutcome::flags bits (Linux FLAG_*).
enum AckFlag : std::uint32_t {
  ack_una_advanced = 1u << 0,       // SND.UNA moved (FLAG_SND_UNA_ADVANCED)
  ack_retrans_data_acked = 1u << 1, // FLAG_RETRANS_DATA_ACKED
  ack_orig_sack_acked = 1u << 2,    // a never-retransmitted segment was SACKed (FLAG_ORIG_SACK_ACKED)
  ack_sack_reneging = 1u << 3,      // the ACK stopped at a SACKed head (FLAG_SACK_RENEGING)
  ack_maybe_delayed = 1u << 4,      // the RTT sample may include a delayed ACK (tcp_clean_rtx_queue)
  ack_fin_acked = 1u << 5,          // the ACK covered our FIN (§3.2, fin_acked)
  ack_dsack = 1u << 6,              // the ACK carried a D-SACK (FLAG_DSACKING_ACK)
};

// After SACK tagging, cumulative cleanup and loss marking; input to the CC and
// PRR (§5.1).
struct AckOutcome {
  // Packets. delivered = newly cumulatively ACKed packets not already SACKed
  // + newly SACKed ones (Linux tcp_newly_delivered): cong_avoid's count and
  // PRR's DeliveredData.
  std::uint32_t delivered = 0, acked_pkts = 0, newly_sacked = 0, newly_lost = 0;
  std::uint32_t prior_in_flight = 0, in_flight = 0;
  std::uint32_t flags = 0;    // AckFlag bits
  Duration seq_rtt{-1};       // SRTT/RTO sample; -1 = none
  Duration ca_rtt{-1};        // min_rtt and CC sample; -1 = none
  const RateSample* rs = nullptr;  // M2b; nullptr in M1
};

// Linux struct ack_sample (pkts_acked hook).
struct AckSample {
  std::uint32_t pkts_acked = 0;
  Duration rtt{-1};  // ca_rtt; -1 = none
  std::uint32_t in_flight = 0;
};

enum class CaEvent : std::uint8_t { tx_start, cwnd_restart, complete_cwr, loss };  // CA_EVENT_*

struct CcConn {  // the part of the TCB a CC may read and write
  std::uint32_t cwnd = 0, ssthresh = 0, cwnd_cnt = 0, cwnd_clamp = 0;
  std::uint32_t prior_cwnd = 0, prior_ssthresh = 0;  // for undo (§1.2) and repeated RTOs
  std::uint64_t pacing_rate = 0, max_pacing_rate = 0;  // bytes/s; always computed (§5.5)
  bool pacing_needed = false;                          // Linux sk_pacing_status; BBR sets it
  std::uint64_t app_limited = 0;  // tcp_rate marker (§5.4); BBR writes it entering PROBE_RTT
  // Read-only views, refreshed before each hook.
  CaState ca_state = CaState::open;
  std::uint32_t mss = 0, in_flight = 0, max_packets_out = 0, gso_max_size = 0;
  bool cwnd_limited = false;  // Linux tcp_is_cwnd_limited
  // Offsets (HyStart rounds, RFC 9406 windowEnd) and packet counts.
  std::uint64_t snd_una = 0, snd_nxt = 0, delivered = 0, lost = 0;
  // Last data send; tcp_rate delivered_mstamp; EDT pacing_next.
  Time now, lsndtime, delivered_time, wstamp;
  Duration srtt{}, min_rtt{};
  Rng* rng = nullptr;  // the stack's runtime stream (BBR's random PROBE_BW phase)
};

class CongestionControl {
public:
  virtual ~CongestionControl() = default;
  [[nodiscard]] virtual std::string_view name() const = 0;
  virtual void init(CcConn&) {}
  // On loss: the new ssthresh.
  virtual std::uint32_t ssthresh(const CcConn& c) = 0;
  // Grows cwnd by `delivered`; skipped while cwnd is being reduced and when
  // has_cong_control().
  virtual void cong_avoid(CcConn& c, const AckOutcome& out) = 0;
  // Before loss recovery runs, as Linux (HyStart).
  virtual void pkts_acked(CcConn&, const AckSample&) {}
  virtual void set_state(CcConn&, CaState) {}
  virtual void cwnd_event(CcConn&, CaEvent) {}
  virtual std::uint32_t undo_cwnd(const CcConn& c) { return std::max(c.cwnd, c.prior_cwnd); }
  // BBR owns cwnd and pacing: the engine then skips cong_avoid and PRR and
  // calls cong_control after rate sampling (Linux tcp_cong_control).
  [[nodiscard]] virtual bool has_cong_control() const { return false; }
  virtual void cong_control(CcConn&, const AckOutcome&, const RateSample&) {}
  [[nodiscard]] virtual std::uint32_t sndbuf_expand() const { return 2; }
  [[nodiscard]] virtual std::uint32_t min_tso_segs() const { return 2; }

protected:
  CongestionControl() = default;
  CongestionControl(const CongestionControl&) = default;
  CongestionControl& operator=(const CongestionControl&) = default;
};

}  // namespace utcp
