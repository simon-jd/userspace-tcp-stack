// The model time of a run of RTO expiries (DESIGN §4.8), shared by the TCP
// engine's abort rule and the simulator's ProgressChecker bound (§7.3), so
// both use one definition.
#pragma once

#include <cstdint>

#include "utcp/time.hpp"

namespace utcp {

// Linux tcp_model_timeout: the time `retries` RTO expiries take when the RTO
// starts at `rto_base` and doubles up to `rto_max`. With t = ilog2(rto_max /
// rto_base): (2^(retries+1) - 1) * rto_base for retries <= t, else
// (2^(t+1) - 1) * rto_base + (retries - t) * rto_max. Saturates at
// Duration::max(). Preconditions (checked): 0 < rto_base, 0 < rto_max.
// (15, 200 ms, 120 s) = 924.6 s; (6, 1 s, 120 s) = 127 s; (7, 1 s, 60 s) =
// 183 s; (15, 1 s, 60 s) = 663 s.
[[nodiscard]] Duration retry_abort_time(std::uint8_t retries, Duration rto_base,
                                        Duration rto_max) noexcept;

}  // namespace utcp
