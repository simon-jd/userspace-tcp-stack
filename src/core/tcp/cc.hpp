// The per-ACK structures shared by the ACK pipeline, loss recovery and
// congestion control (DESIGN §5.1), and the congestion-control interface
// (§5.2). Interface declared by m1-found, extended by m2-found (M2-DESIGN
// §2.1); a contract from M2 on (M2-TASKS "Rules for all M2 tasks").
//
// Hooks mirror Linux struct tcp_congestion_ops so that tcp_cubic.c and
// tcp_bbr.c port with little change. cwnd and ssthresh are in packets, as in
// Linux and RFC 9438. Algorithms live in the TCB (CcStorage), not on the heap.
#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <variant>

#include "core/tcp/rate.hpp"
#include "utcp/config.hpp"
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
  // SEG.ACK below SND.UNA (new_una = prior_una): only the SACK and D-SACK
  // blocks and loss recovery run, without RTT samples or CC (Linux tcp_ack,
  // old_ack).
  bool old_ack = false;
};

// AckOutcome::flags bits (Linux FLAG_*).
enum AckFlag : std::uint32_t {
  ack_una_advanced = 1u << 0,       // SND.UNA moved (FLAG_SND_UNA_ADVANCED)
  ack_retrans_data_acked = 1u << 1, // FLAG_RETRANS_DATA_ACKED
  ack_orig_sack_acked = 1u << 2,    // a never-retransmitted segment was (S)ACKed, at or below recover
                                    // in Recovery/Loss (FLAG_ORIG_SACK_ACKED)
  ack_sack_reneging = 1u << 3,      // the ACK stopped at a SACKed head (FLAG_SACK_RENEGING)
  ack_maybe_delayed = 1u << 4,      // the RTT sample may include a delayed ACK (tcp_clean_rtx_queue)
  ack_fin_acked = 1u << 5,          // the ACK newly covered our FIN (§3.2, fin_acked); not
                                    // set again by later ACKs (SendQueue::fin_acked is the state)
  ack_dsack = 1u << 6,              // the ACK carried a valid D-SACK (FLAG_DSACKING_ACK,
                                    // tcp_dsack_seen; M2-DESIGN §1.6)
  ack_dsack_tlp = 1u << 7,          // the D-SACK covers at most one MSS ending at tlp_high_seq
                                    // (FLAG_DSACK_TLP): a TLP's duplicate, not reordering
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
  // The ACK's rate sample (tcp_rate_gen), set by process_ack before the CC
  // step; it lives in the AckContext (AckContext::sample), so it is valid
  // while that lives. nullptr for an old ACK (no sample, Linux old_ack).
  const RateSample* rs = nullptr;
};

// Linux struct ack_sample (pkts_acked hook).
struct AckSample {
  std::uint32_t pkts_acked = 0;
  Duration rtt{-1};  // ca_rtt; -1 = none
  std::uint32_t in_flight = 0;
};

enum class CaEvent : std::uint8_t { tx_start, cwnd_restart, complete_cwr, loss };  // CA_EVENT_*

struct StackStats;

struct CcConn {  // the part of the TCB a CC may read and write
  std::uint32_t cwnd = 0, ssthresh = 0, cwnd_cnt = 0, cwnd_clamp = 0;
  std::uint32_t prior_cwnd = 0, prior_ssthresh = 0;  // for undo (§1.2) and repeated RTOs
  std::uint64_t pacing_rate = 0, max_pacing_rate = 0;  // bytes/s; always computed (§5.5)
  bool pacing_needed = false;                          // Linux sk_pacing_status; BBR sets it
  // tcp_rate marker (§5.4), one value with RateState::app_limited: copied in
  // before every hook and back after cong_control (M2-DESIGN §2.1 item 7);
  // BBR writes it entering PROBE_RTT.
  std::uint64_t app_limited = 0;
  // Read-only views, refreshed before each hook. LossRecovery refreshes
  // ca_state, in_flight, packets_out, snd_una, snd_nxt, lost, now, srtt and
  // min_rtt; process_ack also delivered and delivered_time (from RateState);
  // the engine keeps the others (mss = mss_cache, max_packets_out,
  // gso_max_size, cwnd_limited, lsndtime, wstamp, rng, paced, flavor) current.
  CaState ca_state = CaState::open;
  // max_packets_out: Linux tp->max_packets_out, the most packets out in the
  // current cwnd-usage window, as tcp_cwnd_validate keeps it.
  std::uint32_t mss = 0, in_flight = 0, max_packets_out = 0, gso_max_size = 0;
  // TxSegs sent and not cumulatively acknowledged: FlightSize in packets
  // (RFC 5681 §3.1, SND.NXT - SND.UNA), unchanged by SACK and loss marks.
  std::uint32_t packets_out = 0;
  // Linux tp->is_cwnd_limited: the transmit path was stopped by cwnd in the
  // current cwnd-usage window (tcp_cwnd_validate). The CC tests
  // is_cwnd_limited(), which adds the slow-start rule.
  bool cwnd_limited = false;
  // Offsets (HyStart rounds, RFC 9406 windowEnd) and packet counts.
  std::uint64_t snd_una = 0, snd_nxt = 0, delivered = 0, lost = 0;
  // Last data send; tcp_rate delivered_mstamp; EDT pacing_next.
  Time now, lsndtime, delivered_time, wstamp;
  Duration srtt{}, min_rtt{};
  Rng* rng = nullptr;  // the stack's runtime stream (BBR's random PROBE_BW phase)
  // The pacing gate applies (Linux sk_pacing_status != SK_PACING_NONE;
  // HyStart reads it, tcp_cubic.c hystart_update).
  bool paced = false;
  Hystart hystart = Hystart::hystart_classic;
  std::uint32_t hystart_low_window = 16;
  Duration hystart_ack_delta = std::chrono::milliseconds{2};
  StackStats* stats = nullptr;  // stack-wide classic HyStart event counters
  CcFlavor flavor = CcFlavor::linux;  // TcpConfig::cc_flavor (M2-DESIGN §2.1 item 5)
};

// Linux tcp_jiffies32 at HZ = 1000 (the server's CONFIG_HZ): whole
// milliseconds of `t`, wrapping. tcp_cubic.c and tcp_bbr.c time several
// rules in jiffies; the ports use this so the once-per-jiffy rules match.
[[nodiscard]] constexpr std::uint32_t jiffies(Time t) noexcept {
  return static_cast<std::uint32_t>(static_cast<std::uint64_t>(t.ns) / 1'000'000u);
}

// The algorithms (cc_newreno.hpp, cc_cubic.hpp, cc_bbr.hpp) and the storage
// of one connection's algorithm, in the TCB (no heap). Declared here so that
// cc_cubic.hpp and cc_bbr.hpp need only this header; include cc_newreno.hpp,
// which includes the other two, to use the variant.
class NewReno;
class Cubic;
class Bbr;
using CcStorage = std::variant<NewReno, Cubic, Bbr>;

// cwnd_clamp 0 means no clamp (Linux snd_cwnd_clamp defaults to ~0).
[[nodiscard]] constexpr std::uint32_t effective_cwnd_clamp(const CcConn& c) noexcept {
  return c.cwnd_clamp == 0 ? 0xffff'ffffu : c.cwnd_clamp;
}

// Linux tcp_is_cwnd_limited (RFC 7661): cwnd may grow if it limited sending
// in the current window, or in slow start while cwnd < 2 * max_packets_out,
// so that slow start reaches twice what was in flight.
[[nodiscard]] constexpr bool is_cwnd_limited(const CcConn& c) noexcept {
  return c.cwnd_limited ||
         (c.cwnd < c.ssthresh && std::uint64_t{c.cwnd} < 2 * std::uint64_t{c.max_packets_out});
}

// Linux tcp_current_ssthresh: ssthresh during a cwnd reduction (CWR,
// Recovery), else max(ssthresh, 3/4 cwnd).
[[nodiscard]] std::uint32_t current_ssthresh(const CcConn& c);

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
  // Linux min_tso_segs: the floor of a paced burst in packets (tcp_min_tso_segs
  // = 2; BBR's depends on the pacing rate, bbr_min_tso_segs).
  [[nodiscard]] virtual std::uint32_t min_tso_segs(const CcConn&) const { return 2; }

protected:
  CongestionControl() = default;
  CongestionControl(const CongestionControl&) = default;
  CongestionControl& operator=(const CongestionControl&) = default;
};

// Restart after an idle period (RFC 5681 §4.1; DESIGN §3.9 idle_restart).
// The engine calls it when new data is queued, or the window opens with data
// queued, while no TxSeg is outstanding (packets_out == 0; Linux
// tcp_slow_start_after_idle_check, with lsndtime set when the handshake
// completes). `idle` is the time since data was last sent (now - lsndtime), `rto`
// the current RTO (rto_backed_off(backoff), Linux icsk_rto), `iw` the initial
// window without the SYN-loss reduction (Linux tcp_init_cwnd). Acts only if
// idle > rto and the CC has no cong_control: sends CaEvent::cwnd_restart,
// then rfc5681 sets cwnd = min(iw, cwnd); linux (tcp_cwnd_restart) sets
// ssthresh = tcp_current_ssthresh and halves cwnd for each RTO, whole or
// partial, of idle time beyond the first, not below min(iw, cwnd). Returns
// whether it acted.
bool cwnd_restart(CcConn& c, CongestionControl& algo, IdleRestart mode, Duration idle,
                  Duration rto, std::uint32_t iw);

}  // namespace utcp
