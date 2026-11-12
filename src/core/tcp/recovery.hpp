// Loss recovery (DESIGN §5.1, §5.3). Interface declared by m1-found;
// implemented by m1-tx (recovery.cpp).
//
// M1: RFC 6582 NewReno over the Linux in-flight formula, RTO handling as Linux
// tcp_enter_loss/tcp_timeout_mark_lost with the reneging check, and the
// choice of the connection's one `xmit` timer. M2a replaces the internals
// (RFC 6675 scoreboard, RACK-TLP, PRR) without changing TxSeg, SendQueue or
// the engine.
#pragma once

#include <cstdint>
#include <optional>
#include <utility>

#include "core/tcp/cc.hpp"
#include "core/tcp/rtt.hpp"
#include "core/tcp/send_queue.hpp"
#include "utcp/config.hpp"
#include "utcp/stats.hpp"
#include "utcp/time.hpp"
#include "utcp/trace.hpp"
#include "utcp/types.hpp"

namespace utcp {

// What recovery works on, built by the engine for each call.
struct RecoveryCtx {
  SendQueue& q;
  CcConn& cc;
  CongestionControl& algo;
  const RttEstimator& rtt;
  const TcpConfig& cfg;
  Time now;
  std::uint32_t snd_wnd;  // bytes, scaled
  StackStats& stats;      // TcpExtTCPSACKReneging, TcpExtTCPSackRecovery, ...
  bool sack_ok;           // SACK negotiated (else reno dupack accounting)
  std::uint8_t backoff;   // RTO backoff exponent (rto_backed_off)
  std::uint8_t rto_count; // RTO expiries since SND.UNA last advanced, this one excluded
};

// The connection's one transmission timer (RFC 8985 §8, Linux icsk_pending).
enum class XmitTimer : std::uint8_t { none, rto, persist, reo, pto };

class LossRecovery {  // M1: NewReno; M2a: RFC 6675 scoreboard + RACK-TLP + PRR
public:
  LossRecovery() = default;

  // From the SendQueue DeliveredFn callbacks (RACK advance and reordering
  // detection in M2a).
  void on_delivered(RecoveryCtx& c, const TxSeg& seg, bool via_sack);
  // Linux tcp_fastretrans_alert: marks lost, moves the CaState; on entering
  // Recovery sets recover = SND.NXT, ssthresh from the CC, cwnd = ssthresh,
  // marks the SND.UNA segment lost and flags it for fast_rexmit; a partial
  // ACK marks the new SND.UNA segment lost (RFC 6582 §3.2 step 5); a full ACK
  // returns to Open. PRR (M2a) writes cwnd here.
  void on_ack(RecoveryCtx& c, const AckInput& in, AckOutcome& out);
  // Every data (re)transmission: prr_out, HighRxt, TLP state (M2a); clears
  // the fast_rexmit flag.
  void on_transmit(RecoveryCtx& c, const TxSeg& seg, TxKind kind);
  // End of the engine's transmit(): schedules the PTO (M2a).
  void on_burst_end(RecoveryCtx& c);
  // RTO expiry (§5.3): reneging check (a SACKed head clears every SACK mark,
  // counts TcpExtTCPSACKReneging, and makes rate samples invalid until
  // recovery ends), every non-SACKed segment marked lost, ssthresh per RFC
  // 5681 §3.1, cwnd = 1, Loss with recover = SND.NXT.
  void on_rto(RecoveryCtx& c);
  // PMTU decrease (§4.13, Linux tcp_simple_retransmit): segments longer than
  // the new MSS were marked lost; enter Loss without a cwnd cut, ssthresh =
  // max(ssthresh, 3/4 cwnd).
  void on_pmtu_drop(RecoveryCtx& c);
  // Kind and deadline of the xmit timer. M1: rto with data, SYN or FIN
  // outstanding (RFC 6298 §5), persist at zero window with data queued and
  // nothing in flight (§4.9), else none.
  [[nodiscard]] std::pair<XmitTimer, Time> xmit_timer(const RecoveryCtx& c) const;
  // reo and pto expiries (M2a); the engine handles rto and persist itself.
  void on_xmit_timer(RecoveryCtx& c, XmitTimer kind);

  [[nodiscard]] CaState state() const;
  // The head segment must be resent as TxKind::fast_rexmit (exempt from the
  // cwnd gate, RFC 6675 §5 (4.3)).
  [[nodiscard]] bool fast_rexmit_pending() const;
  // recover (RFC 6582) as an offset, while in Recovery or Loss.
  [[nodiscard]] std::optional<std::uint64_t> recover() const;
  // Rate samples are invalid (reneging seen at RTO, until recovery ends).
  [[nodiscard]] bool sack_reneg() const;

private:
  // Implementation state is m1-tx's.
};

}  // namespace utcp
