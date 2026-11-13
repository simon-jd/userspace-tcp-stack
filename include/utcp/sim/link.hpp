// One simulated link segment (DESIGN §7.1). Integer arithmetic only: ppm
// probabilities, nanosecond times, Rng::below (§7.2, §13.1).
//
// Pipeline per datagram, in this order:
//   MTU check (an emulated router at the segment's entrance: a DF datagram
//   above `mtu` is dropped and, with send_frag_needed, answered with ICMP 3/4)
//   -> rate and drop-tail queue admission -> loss (Bernoulli, plus the
//   Gilbert-Elliott burst state) -> duplication -> corruption (bit flip or
//   garbage, chosen per copy) -> delay + jitter -> delivery.
// Forged frag-needed messages (icmp_spoof_ppm) go back to the sender for
// admitted TCP datagrams, which still continue.
//
// Each random decision has its own stream, Rng::derive(master,
// "link/<name>/<what>"), so adding a decision does not shift the others.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "utcp/random.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp::sim {

// Two-state burst loss (Gilbert-Elliott). Per datagram the state moves good ->
// bad with p_ppm and bad -> good with r_ppm, then a datagram in the bad state
// is lost with loss_bad_ppm. The mean number of consecutive datagrams in the
// bad state is 1e6 / r_ppm. p_ppm = 0 disables it.
struct GilbertElliott {
  std::uint32_t p_ppm = 0;
  std::uint32_t r_ppm = 0;
  std::uint32_t loss_bad_ppm = 1'000'000;

  bool operator==(const GilbertElliott&) const = default;
};

struct LinkParams {
  Duration delay{};
  Duration jitter{};           // uniform in [0, jitter], added to the delay
  bool allow_reorder = false;  // false: delivery time = max(previous delivery, t)
  std::uint32_t loss_ppm = 0;  // Bernoulli
  GilbertElliott burst;
  std::uint32_t dup_ppm = 0;
  Duration dup_extra_delay{};  // the duplicate arrives this much later
  std::uint32_t bitflip_ppm = 0;  // exactly one bit flipped; the checksums catch it
  std::uint32_t garbage_ppm = 0;  // fields mutated, then the checksums fixed
  std::uint64_t rate_bps = 0;     // 0 = unlimited (no serialisation, no queue); at most 1e12
  std::uint32_t queue_bytes = 0;  // drop-tail limit with a rate; 0 = unlimited
  std::uint16_t mtu = 1500;
  bool send_frag_needed = false;      // answer too-big DF datagrams with ICMP 3/4
  std::uint32_t icmp_spoof_ppm = 0;   // forged frag-needed with a random sequence number
  Ipv4Addr router_addr = Ipv4Addr::from_octets(198, 18, 0, 254);  // source of ICMP from this segment

  bool operator==(const LinkParams&) const = default;
};

inline constexpr std::uint64_t max_rate_bps = 1'000'000'000'000;

enum class Corruption : std::uint8_t { none, bitflip, garbage };

struct DeliveryInfo {
  Corruption corruption = Corruption::none;
  bool duplicate = false;  // the second copy of a duplicated datagram
  bool replay = false;     // an old datagram re-injected by the garbage class
};

// Receives what a segment emits. Implementations copy the bytes; the span is
// valid only during the call.
class LinkSink {
public:
  virtual ~LinkSink() = default;
  // The datagram leaves the segment at `t` (after delay and jitter).
  virtual void deliver(Time t, std::span<const std::byte> datagram, const DeliveryInfo& info) = 0;
  // An ICMP error from the router at the segment's entrance, sent back
  // towards the datagram's source at `t`.
  virtual void reply(Time t, std::span<const std::byte> icmp) = 0;
};

struct LinkStats {
  std::uint64_t offered = 0;       // datagrams given to send()
  std::uint64_t mtu_drops = 0;     // above mtu (DF or not)
  std::uint64_t frag_needed = 0;   // ICMP 3/4 sent for them
  std::uint64_t queue_drops = 0;   // drop-tail
  std::uint64_t lost = 0;          // Bernoulli or burst loss
  std::uint64_t burst_lost = 0;    // of which in the bad state
  std::uint64_t duplicated = 0;
  std::uint64_t bitflips = 0;
  std::uint64_t garbage = 0;
  std::uint64_t replays = 0;
  std::uint64_t spoofed = 0;       // forged frag-needed sent
  std::uint64_t delivered = 0;     // datagrams handed to deliver(), duplicates and replays included
  std::uint64_t bytes_delivered = 0;

  bool operator==(const LinkStats&) const = default;
};

class Link {
public:
  // `name` labels the random streams ("a>b"), so it must be unique in a run.
  Link(const LinkParams& params, const Seed& master, std::string_view name);

  // Runs one datagram through the pipeline at `now`. Calls to send() must
  // have non-decreasing `now`.
  void send(Time now, std::span<const std::byte> datagram, LinkSink& sink);

  [[nodiscard]] const LinkParams& params() const noexcept { return p_; }
  [[nodiscard]] const LinkStats& stats() const noexcept { return stats_; }
  [[nodiscard]] std::string_view name() const noexcept { return name_; }
  // Bytes admitted and not yet serialised at `now` (rate-limited links).
  [[nodiscard]] std::uint32_t queued_bytes(Time now) const;

private:
  struct Queued {
    Time end;            // end of serialisation
    std::uint32_t size;
  };

  void emit(Time departure, Duration extra, std::span<const std::byte> d, bool duplicate,
            LinkSink& sink);
  void remember(std::span<const std::byte> d);
  void spoof(Time t, std::span<const std::byte> d, LinkSink& sink);

  LinkParams p_;
  std::string name_;
  Rng loss_rng_, burst_rng_, dup_rng_, corrupt_rng_, delay_rng_, spoof_rng_;
  bool bad_ = false;  // Gilbert-Elliott state
  Time busy_until_{std::numeric_limits<std::int64_t>::min()};
  std::uint64_t carry_ = 0;  // serialisation remainder, bit-ns
  std::deque<Queued> queue_;
  std::uint32_t queued_ = 0;
  Time last_delivery_{std::numeric_limits<std::int64_t>::min()};
  std::array<std::vector<std::byte>, 8> history_;  // recent datagrams for garbage replays
  std::size_t history_count_ = 0;
  std::vector<std::byte> scratch_;
  std::uint16_t icmp_id_ = 0;
  LinkStats stats_;
};

// --- Corruption, exposed for tests (DESIGN §7.1, m1-sim test 3).

// Flips exactly one bit of `datagram`, chosen with `rng`, so that the IPv4
// header checksum or the transport checksum detects it (RFC 1071 §2: a one-bit
// change always changes the one's-complement sum). The one undetectable flip,
// a UDP checksum field becoming 0 ("no checksum", RFC 768), is never chosen.
// Returns the bit index (byte * 8 + bit, bit 7 = most significant).
std::size_t flip_one_bit(std::span<std::byte> datagram, Rng& rng);

enum class GarbageKind : std::uint8_t {
  seq, ack, window, flags, options, data_offset, truncate, payload, ports, replay
};

// Mutates fields of an IPv4 datagram in `buf` (its first `len` bytes), then
// fixes the IPv4 total length and header checksum and the TCP, UDP or ICMP
// checksum, so the result passes every checksum check (DESIGN §7.1). Returns
// the new length (truncation shortens it) and the kind applied. Datagrams
// that do not parse as IPv4 get payload bytes mutated only.
// `replay` is never returned: replays are chosen by Link from its history.
std::size_t mutate_garbage(std::span<std::byte> buf, std::size_t len, Rng& rng, GarbageKind& kind);

}  // namespace utcp::sim
