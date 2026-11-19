// CUBIC slow-start detectors, Linux v7.0 tcp_cubic.c and RFC 9406.
#pragma once

#include <cstdint>
#include <limits>

#include "core/tcp/cc.hpp"

namespace utcp {

class ClassicHyStart {
public:
  void reset_round(const CcConn& c);
  void sample(CcConn& c, std::uint32_t delay_us, std::uint32_t min_us);

private:
  std::uint64_t end_ = 0;
  Time start_{}, last_ack_{};
  std::uint32_t round_min_ = 0, samples_ = 0;
  bool found_ = false;
};

class HyStartPlusPlus {
public:
  void sample(CcConn& c, Duration rtt);
  std::uint32_t growth(const CcConn& c, std::uint32_t delivered);
  void end() { done_ = true; }
  bool active(const CcConn& c) const { return !done_ && c.ssthresh == cwnd_infinite; }

private:
  std::uint64_t end_ = 0;
  Duration previous_ = Duration::max(), current_ = Duration::max(), baseline_ = Duration::max();
  std::uint32_t samples_ = 0, rounds_ = 0, carry_ = 0;
  bool waiting_for_flight_ = true, css_ack_ = false, done_ = false;
};

}  // namespace utcp
