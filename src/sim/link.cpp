#include "utcp/sim/link.hpp"

#include <algorithm>
#include <string>

#include "utcp/check.hpp"
#include "utcp/checksum.hpp"
#include "utcp/sim/datagram.hpp"

namespace utcp::sim {
namespace {

std::string stream_label(std::string_view name, std::string_view what) {
  std::string s = "link/";
  s += name;
  s += '/';
  s += what;
  return s;
}

// IPv4 header length of `d`, or 0 if it does not start with an IPv4 header.
std::size_t ipv4_ihl(std::span<const std::byte> d) noexcept {
  if (d.size() < wire::ipv4_header_len) {
    return 0;
  }
  const std::uint8_t vihl = wire::load_u8(d, 0);
  const std::size_t ihl = std::size_t{vihl & 0xfu} * 4;
  if ((vihl >> 4) != 4 || ihl < wire::ipv4_header_len || ihl > d.size()) {
    return 0;
  }
  return ihl;
}

}  // namespace

Link::Link(const LinkParams& params, const Seed& master, std::string_view name)
    : p_(params),
      name_(name),
      loss_rng_(Rng::derive(master, stream_label(name, "loss"))),
      burst_rng_(Rng::derive(master, stream_label(name, "burst"))),
      dup_rng_(Rng::derive(master, stream_label(name, "dup"))),
      corrupt_rng_(Rng::derive(master, stream_label(name, "corrupt"))),
      delay_rng_(Rng::derive(master, stream_label(name, "delay"))),
      spoof_rng_(Rng::derive(master, stream_label(name, "spoof"))) {
  UTCP_CHECK(p_.rate_bps <= max_rate_bps);
  UTCP_CHECK(p_.delay.count() >= 0 && p_.jitter.count() >= 0 && p_.dup_extra_delay.count() >= 0);
}

std::uint32_t Link::queued_bytes(Time now) const {
  std::uint32_t q = 0;
  for (const Queued& e : queue_) {
    if (e.end > now) {
      q += e.size;
    }
  }
  return q;
}

void Link::send(Time now, std::span<const std::byte> d, LinkSink& sink) {
  ++stats_.offered;
  const auto size = static_cast<std::uint32_t>(d.size());

  // MTU check at the entrance (an emulated router). DF datagrams above the
  // MTU are answered with ICMP 3/4 (RFC 1191 §4); fragmentation is not
  // modelled, so others are dropped too.
  if (size > p_.mtu) {
    ++stats_.mtu_drops;
    const bool df = ipv4_ihl(d) != 0 && (wire::load_u8(d, 6) & 0x40u) != 0;
    if (df && p_.send_frag_needed) {
      std::array<std::byte, 576> icmp{};
      const std::size_t n = write_frag_needed(icmp, p_.router_addr, d, p_.mtu, icmp_id_++);
      if (n > 0) {
        ++stats_.frag_needed;
        sink.reply(now, std::span<const std::byte>(icmp).first(n));
      }
    }
    return;
  }

  // Rate and drop-tail queue. The queue holds every admitted datagram whose
  // serialisation has not ended. Serialisation time is exact over a busy
  // period: the sub-nanosecond remainder carries to the next datagram.
  Time departure = now;
  if (p_.rate_bps > 0) {
    while (!queue_.empty() && queue_.front().end <= now) {
      queued_ -= queue_.front().size;
      queue_.pop_front();
    }
    if (p_.queue_bytes > 0 && std::uint64_t{queued_} + size > p_.queue_bytes) {
      ++stats_.queue_drops;
      return;
    }
    Time begin = busy_until_;
    if (now > busy_until_) {
      begin = now;
      carry_ = 0;
    }
    const std::uint64_t num = std::uint64_t{size} * 8 * 1'000'000'000 + carry_;
    carry_ = num % p_.rate_bps;
    busy_until_ = begin + Duration(static_cast<std::int64_t>(num / p_.rate_bps));
    queue_.push_back(Queued{busy_until_, size});
    queued_ += size;
    departure = busy_until_;
  }

  // Forged frag-needed for TCP datagrams (RFC 5927 §4.1 makes the receiver
  // check the quoted sequence number); the datagram itself continues.
  if (p_.icmp_spoof_ppm > 0 && spoof_rng_.chance_ppm(p_.icmp_spoof_ppm)) {
    spoof(departure, d, sink);
  }

  // Loss: Bernoulli, then the burst state.
  bool lost = p_.loss_ppm > 0 && loss_rng_.chance_ppm(p_.loss_ppm);
  if (p_.burst.p_ppm > 0) {
    if (bad_) {
      if (burst_rng_.chance_ppm(p_.burst.r_ppm)) {
        bad_ = false;
      }
    } else if (burst_rng_.chance_ppm(p_.burst.p_ppm)) {
      bad_ = true;
    }
    if (bad_ && burst_rng_.chance_ppm(p_.burst.loss_bad_ppm)) {
      if (!lost) {
        ++stats_.burst_lost;
      }
      lost = true;
    }
  }
  if (lost) {
    ++stats_.lost;
    return;
  }

  const bool dup = p_.dup_ppm > 0 && dup_rng_.chance_ppm(p_.dup_ppm);
  emit(departure, Duration{0}, d, false, sink);
  if (dup) {
    ++stats_.duplicated;
    emit(departure, p_.dup_extra_delay, d, true, sink);
  }
  if (p_.garbage_ppm > 0) {
    remember(d);
  }
}

void Link::emit(Time departure, Duration extra, std::span<const std::byte> d, bool duplicate,
                LinkSink& sink) {
  DeliveryInfo info;
  info.duplicate = duplicate;
  std::span<const std::byte> out = d;
  bool replay = false;
  if (p_.bitflip_ppm > 0 || p_.garbage_ppm > 0) {
    const std::uint32_t r = corrupt_rng_.below(1'000'000);
    if (r < p_.bitflip_ppm) {
      ++stats_.bitflips;
      info.corruption = Corruption::bitflip;
      scratch_.assign(d.begin(), d.end());
      if (!scratch_.empty()) {
        flip_one_bit(scratch_, corrupt_rng_);
      }
      out = scratch_;
    } else if (r - p_.bitflip_ppm < p_.garbage_ppm) {
      ++stats_.garbage;
      info.corruption = Corruption::garbage;
      // One in ten garbage events re-injects an old datagram (valid
      // checksums) after this one; the others mutate this one.
      if (history_count_ > 0 && corrupt_rng_.below(10) == 0) {
        replay = true;
      } else {
        scratch_.assign(d.begin(), d.end());
        GarbageKind kind = GarbageKind::payload;
        const std::size_t len = mutate_garbage(scratch_, scratch_.size(), corrupt_rng_, kind);
        out = std::span<const std::byte>(scratch_).first(len);
      }
    }
  }

  Time t = departure + p_.delay + extra;
  if (p_.jitter.count() > 0) {
    t += Duration(static_cast<std::int64_t>(
        delay_rng_.below64(static_cast<std::uint64_t>(p_.jitter.count()) + 1)));
  }
  if (!p_.allow_reorder) {
    t = std::max(t, last_delivery_);
    last_delivery_ = t;
  }
  ++stats_.delivered;
  stats_.bytes_delivered += out.size();
  sink.deliver(t, out, info);

  if (replay) {
    const std::size_t n = std::min<std::size_t>(history_count_, history_.size());
    const std::vector<std::byte>& old = history_[corrupt_rng_.below(static_cast<std::uint32_t>(n))];
    DeliveryInfo ri;
    ri.corruption = Corruption::garbage;
    ri.replay = true;
    ++stats_.replays;
    ++stats_.delivered;
    stats_.bytes_delivered += old.size();
    sink.deliver(t, old, ri);
  }
}

void Link::remember(std::span<const std::byte> d) {
  history_[history_count_ % history_.size()].assign(d.begin(), d.end());
  ++history_count_;
}

void Link::spoof(Time t, std::span<const std::byte> d, LinkSink& sink) {
  const std::size_t ihl = ipv4_ihl(d);
  if (ihl == 0 || wire::load_u8(d, 9) != ip_proto_tcp || d.size() < ihl + 8) {
    return;
  }
  scratch_.assign(d.begin(), d.end());
  wire::store_be32(scratch_, ihl + 4, static_cast<std::uint32_t>(spoof_rng_.next()));
  const auto mtu = static_cast<std::uint16_t>(68 + spoof_rng_.below(std::uint32_t{p_.mtu} - 67));
  std::array<std::byte, 576> icmp{};
  const std::size_t n = write_frag_needed(icmp, p_.router_addr, scratch_, mtu, icmp_id_++);
  if (n > 0) {
    ++stats_.spoofed;
    sink.reply(t, std::span<const std::byte>(icmp).first(n));
  }
}

std::size_t flip_one_bit(std::span<std::byte> d, Rng& rng) {
  UTCP_CHECK(!d.empty());
  // The UDP checksum field, if any: a flip that makes it 0 would turn the
  // check off (RFC 768), so such a flip is drawn again.
  std::size_t udp_csum = d.size();
  const std::size_t ihl = ipv4_ihl(d);
  if (ihl != 0 && wire::load_u8(d, 9) == ip_proto_udp && d.size() >= ihl + 8) {
    udp_csum = ihl + 6;
  }
  for (;;) {
    const std::uint64_t bit = rng.below64(std::uint64_t{d.size()} * 8);
    const auto byte = static_cast<std::size_t>(bit / 8);
    const auto mask = static_cast<std::uint8_t>(0x80u >> (bit % 8));
    if (byte == udp_csum || byte == udp_csum + 1) {
      std::uint16_t field = wire::load_be16(d, udp_csum);
      field ^= static_cast<std::uint16_t>(byte == udp_csum ? mask << 8 : mask);
      if (field == 0) {
        continue;
      }
    }
    d[byte] ^= std::byte{mask};
    return static_cast<std::size_t>(bit);
  }
}

std::size_t mutate_garbage(std::span<std::byte> buf, std::size_t len, Rng& rng, GarbageKind& kind) {
  UTCP_CHECK(len <= buf.size());
  const auto d = buf.first(len);
  const std::size_t ihl = ipv4_ihl(d);
  // One draw per statement, in a fixed order (§13.1: function arguments and
  // the operands of most operators are evaluated in an unspecified order, so
  // two draws in one expression can differ between g++ and clang).
  const auto random_byte = [&](std::size_t from) {
    if (from < len) {
      const std::size_t at = from + rng.below(static_cast<std::uint32_t>(len - from));
      const auto v = static_cast<std::byte>(rng.below(256));
      d[at] = v;
    }
  };
  // Sequence-like fields: half the time a value near the old one (so it can
  // land inside the window), otherwise anything.
  const auto near_or_random = [&](std::size_t at) {
    const std::uint32_t old = wire::load_be32(d, at);
    std::uint32_t v = 0;
    if (rng.below(2) == 0) {
      const std::uint32_t delta = rng.below(131072);
      v = old + delta - 65536;
    } else {
      v = static_cast<std::uint32_t>(rng.next());
    }
    wire::store_be32(d, at, v);
  };
  if (ihl == 0) {
    kind = GarbageKind::payload;
    random_byte(0);
    return len;
  }
  std::size_t n = len;
  const std::uint8_t proto = wire::load_u8(d, 9);
  if (proto == ip_proto_tcp && len >= ihl + wire::tcp_header_min_len) {
    const std::size_t t = ihl;
    const auto doff = static_cast<std::size_t>(wire::load_u8(d, t + 12) >> 4) * 4;
    kind = static_cast<GarbageKind>(rng.below(8));
    switch (kind) {
      case GarbageKind::seq: near_or_random(t + 4); break;
      case GarbageKind::ack: near_or_random(t + 8); break;
      case GarbageKind::window:
        wire::store_be16(d, t + 14, static_cast<std::uint16_t>(rng.below(65536)));
        break;
      case GarbageKind::flags:
        // Byte 13 (FIN..CWR) and the AE and reserved bits of byte 12.
        wire::store_u8(d, t + 13, static_cast<std::uint8_t>(rng.below(256)));
        wire::store_u8(d, t + 12, static_cast<std::uint8_t>((wire::load_u8(d, t + 12) & 0xf0u) |
                                                            rng.below(16)));
        break;
      case GarbageKind::options:
        if (doff > wire::tcp_header_min_len && t + doff <= len) {
          const std::size_t optlen = doff - wire::tcp_header_min_len;
          const std::size_t at =
              t + wire::tcp_header_min_len + rng.below(static_cast<std::uint32_t>(optlen));
          const auto v = static_cast<std::byte>(rng.below(256));
          d[at] = v;
        } else {
          kind = GarbageKind::window;
          wire::store_be16(d, t + 14, static_cast<std::uint16_t>(rng.below(65536)));
        }
        break;
      case GarbageKind::data_offset:
        wire::store_u8(d, t + 12, static_cast<std::uint8_t>((rng.below(16) << 4) |
                                                            (wire::load_u8(d, t + 12) & 0x0fu)));
        break;
      case GarbageKind::truncate:
        if (len > t + wire::tcp_header_min_len) {
          n = t + wire::tcp_header_min_len +
              rng.below(static_cast<std::uint32_t>(len - t - wire::tcp_header_min_len));
        } else {
          kind = GarbageKind::flags;
          wire::store_u8(d, t + 13, static_cast<std::uint8_t>(rng.below(256)));
        }
        break;
      case GarbageKind::payload:
      default:
        kind = GarbageKind::payload;
        if (t + doff < len && doff >= wire::tcp_header_min_len) {
          random_byte(t + doff);
        } else {
          kind = GarbageKind::seq;
          near_or_random(t + 4);
        }
        break;
    }
  } else if (proto == ip_proto_udp && len >= ihl + wire::udp_header_len) {
    switch (rng.below(3)) {
      case 0:
        kind = GarbageKind::ports;
        {
          const std::size_t at = ihl + 2 * std::size_t{rng.below(2)};  // source or destination
          const auto v = static_cast<std::uint16_t>(rng.below(65536));
          wire::store_be16(d, at, v);
        }
        break;
      case 1:
        kind = GarbageKind::truncate;
        n = ihl + wire::udp_header_len +
            rng.below(static_cast<std::uint32_t>(len - ihl - wire::udp_header_len) + 1);
        break;
      default:
        kind = GarbageKind::payload;
        if (len > ihl + wire::udp_header_len) {
          random_byte(ihl + wire::udp_header_len);
        } else {
          kind = GarbageKind::ports;
          wire::store_be16(d, ihl, static_cast<std::uint16_t>(rng.below(65536)));
        }
        break;
    }
  } else {
    // ICMP and anything else: the message bytes (type, code and body).
    kind = GarbageKind::payload;
    random_byte(ihl);
  }
  wire::store_be16(d, 2, static_cast<std::uint16_t>(n));
  fix_checksums(buf.first(n));
  return n;
}

}  // namespace utcp::sim
