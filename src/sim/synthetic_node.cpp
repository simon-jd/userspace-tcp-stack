#include "utcp/sim/synthetic_node.hpp"

#include <algorithm>
#include <string>
#include <vector>

#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/udp.hpp"
#include "utcp/check.hpp"
#include "utcp/checksum.hpp"
#include "utcp/sim/checkers.hpp"
#include "utcp/sim/datagram.hpp"

namespace utcp::sim {

namespace {

constexpr std::uint32_t buf_size = 2048;
constexpr std::uint16_t src_port_base = 38000;  // no Wireshark dissector on 38000-39999
constexpr std::uint16_t dst_port_base = 39000;
constexpr std::size_t udp_overhead = wire::ipv4_header_len + wire::udp_header_len;

// Copies `d` into a buffer of `pool`; nullopt if the pool is empty.
std::optional<TxPacket> to_packet(PacketPool& pool, std::span<const std::byte> d) {
  auto b = pool.alloc(static_cast<std::uint32_t>(d.size()), 0);
  if (!b) {
    return std::nullopt;
  }
  std::copy(d.begin(), d.end(), b->append(d.size()));
  TxPacket p;
  p.buf = std::move(*b);
  return p;
}

}  // namespace

// --- SyntheticNode.

class SyntheticNode::Impl {
public:
  struct Flow {
    std::uint32_t conn = 0;
    std::uint8_t dir = 0;
    Endpoint src, dst;
    std::uint64_t total = 0, sent = 0;
    std::uint32_t next_seq = 0;
    Time next = Time::never();
    std::uint16_t mtu = 1500;
    bool done = false;
  };

  Impl(const Scenario& s, std::uint32_t index)
      : index_(index), pool_(std::max<std::uint32_t>(s.node.at(index).pool_buffers, 1), buf_size) {
    for (std::uint32_t i = 0; i < s.conn.size(); ++i) {
      const ConnSpec& c = s.conn[i];
      const std::uint32_t server = 1 - c.client;
      for (std::uint8_t dir = 0; dir < 2; ++dir) {
        const std::uint32_t from = dir == 0 ? c.client : server;
        if (from != index_) {
          continue;
        }
        const std::uint32_t to = dir == 0 ? server : c.client;
        Flow f;
        f.conn = i;
        f.dir = dir;
        const auto port_off = static_cast<std::uint16_t>(2 * i + dir);
        f.src = Endpoint{node_addr(from), static_cast<std::uint16_t>(src_port_base + port_off)};
        f.dst = Endpoint{node_addr(to), static_cast<std::uint16_t>(dst_port_base + port_off)};
        f.total = std::min(dir == 0 ? c.bytes_c2s : c.bytes_s2c, synthetic_flow_cap);
        f.next = s.start + c.start;
        f.done = f.total == 0;
        flows_.push_back(f);
      }
    }
  }

  void send(Time now) {
    blocked_ = false;
    for (Flow& f : flows_) {
      while (!f.done && f.next <= now) {
        const std::size_t room = std::max<std::size_t>(f.mtu, udp_overhead + 4) - udp_overhead;
        const auto len = static_cast<std::size_t>(std::min<std::uint64_t>(room, f.total - f.sent));
        payload_.resize(len);
        ctx_->stream().udp_payload(f.conn, f.dir, f.next_seq, payload_);
        const auto d = build_udp(f.src, f.dst, payload_, ip_id_);
        auto p = to_packet(pool_, d);
        if (!p) {
          blocked_ = true;  // the host drains later and advances us again
          return;
        }
        ++ip_id_;
        out_.push_back(std::move(*p));
        ++activity_;
        f.sent += len;
        ++f.next_seq;
        f.next = f.next + synthetic_gap;
        if (f.sent >= f.total) {
          f.done = true;
          ctx_->on_progress();
        }
      }
    }
  }

  void receive(std::span<const std::byte> d) {
    ++activity_;
    if (!checksums_valid(d)) {
      ++bad_checksums_;
      return;
    }
    const auto ip = wire::parse_ipv4(d);
    if (!ip) {
      ++bad_checksums_;
      return;
    }
    if (ip->h.proto == ip_proto_udp) {
      const auto u = wire::parse_udp(ip->payload, ip->h.src, ip->h.dst, true);
      if (!u || u->h.dport < dst_port_base) {
        return;
      }
      const std::uint32_t off = u->h.dport - dst_port_base;
      ++datagrams_;
      bytes_ += u->payload.size();
      if (auto v = ctx_->stream().on_datagram(off / 2, static_cast<std::uint8_t>(off % 2),
                                              u->payload)) {
        ctx_->violation(Verdict::stream, std::move(*v));
        return;
      }
      ctx_->on_progress();
      return;
    }
    if (ip->h.proto != ip_proto_icmp) {
      return;
    }
    const auto m = wire::parse_icmp(ip->payload, true);
    if (!m) {
      return;
    }
    if (m->h.type == wire::icmp_dest_unreach && m->h.code == wire::icmp_frag_needed) {
      ++frag_needed_;
      const auto q = wire::parse_icmp_quote(m->body);
      if (!q || q->ip.proto != ip_proto_udp || q->ip.src != node_addr(index_)) {
        return;
      }
      const std::uint16_t sport = wire::load_be16(q->l4, 0);
      const std::uint16_t mtu = m->h.next_hop_mtu();
      for (Flow& f : flows_) {
        if (f.src.port == sport && mtu >= 68 && mtu < f.mtu) {
          f.mtu = mtu;  // RFC 1191: the next datagrams fit the next hop
        }
      }
      return;
    }
    if (m->h.type == wire::icmp_echo_request) {
      const auto r = build_icmp_echo(node_addr(index_), ip->h.src, wire::icmp_echo_reply,
                                     m->h.echo_id(), m->h.echo_seq(), m->body, ip_id_);
      if (auto p = to_packet(pool_, r)) {
        ++ip_id_;
        out_.push_back(std::move(*p));
      }
    }
  }

  Time next_deadline() const {
    if (blocked_) {
      return Time::never();
    }
    Time t = Time::never();
    for (const Flow& f : flows_) {
      if (!f.done) {
        t = std::min(t, f.next);
      }
    }
    return t;
  }

  bool finished() const {
    return std::ranges::all_of(flows_, [](const Flow& f) { return f.done; });
  }

  std::uint32_t index_;
  SimContext* ctx_ = nullptr;
  PacketPool pool_;
  std::vector<Flow> flows_;
  std::deque<TxPacket> out_;
  std::vector<std::byte> payload_;
  std::uint16_t ip_id_ = 1;
  bool blocked_ = false;
  std::uint64_t activity_ = 0, datagrams_ = 0, bytes_ = 0, frag_needed_ = 0, bad_checksums_ = 0;
};

SyntheticNode::SyntheticNode(const Scenario& s, std::uint32_t index)
    : impl_(std::make_unique<Impl>(s, index)) {}

SyntheticNode::~SyntheticNode() {
  impl_->out_.clear();  // return the buffers before the pool goes
}

void SyntheticNode::receive(Time now, std::span<const std::byte> datagram) {
  static_cast<void>(now);
  impl_->receive(datagram);
}

void SyntheticNode::advance(Time now) { impl_->send(now); }

std::optional<TxPacket> SyntheticNode::pop_transmit() {
  if (impl_->out_.empty()) {
    return std::nullopt;
  }
  TxPacket p = std::move(impl_->out_.front());
  impl_->out_.pop_front();
  return p;
}

Time SyntheticNode::next_deadline() const { return impl_->next_deadline(); }

void SyntheticNode::attach(SimContext& ctx, std::uint32_t index) {
  static_cast<void>(index);
  impl_->ctx_ = &ctx;
}

bool SyntheticNode::finished() const { return impl_->finished(); }

std::uint64_t SyntheticNode::activity() const { return impl_->activity_; }

std::uint64_t SyntheticNode::datagrams_received() const noexcept { return impl_->datagrams_; }

std::uint64_t SyntheticNode::bytes_received() const noexcept { return impl_->bytes_; }

std::uint64_t SyntheticNode::frag_needed_received() const noexcept { return impl_->frag_needed_; }

std::uint64_t SyntheticNode::bad_checksums() const noexcept { return impl_->bad_checksums_; }

// --- ScriptedNode.

ScriptedNode::ScriptedNode(std::uint32_t pool_buffers)
    : pool_(std::max<std::uint32_t>(pool_buffers, 1), buf_size) {}

ScriptedNode::~ScriptedNode() { out_.clear(); }

void ScriptedNode::attach(SimContext& ctx, std::uint32_t index) {
  ctx_ = &ctx;
  index_ = index;
}

void ScriptedNode::send_at(Time t, std::vector<std::byte> datagram) {
  const auto it = std::upper_bound(pending_.begin(), pending_.end(), t,
                                   [](Time x, const auto& p) { return x < p.first; });
  pending_.emplace(it, t, std::move(datagram));
}

void ScriptedNode::send_now(std::span<const std::byte> datagram) { enqueue(datagram); }

void ScriptedNode::app_at(Time t) {
  app_times_.insert(std::upper_bound(app_times_.begin(), app_times_.end(), t), t);
}

void ScriptedNode::enqueue(std::span<const std::byte> datagram) {
  auto p = to_packet(pool_, datagram);
  if (!p) {
    ++alloc_failures_;
    return;
  }
  out_.push_back(std::move(*p));
}

void ScriptedNode::receive(Time now, std::span<const std::byte> datagram) {
  calls_.emplace_back('r', now);
  ++activity_;
  received_.push_back(Received{now, std::vector<std::byte>(datagram.begin(), datagram.end())});
  if (on_receive) {
    on_receive(*this, now, datagram);
  }
}

void ScriptedNode::advance(Time now) {
  calls_.emplace_back('a', now);
  activity_ += activity_per_advance;
  std::size_t n = 0;
  while (n < pending_.size() && pending_[n].first <= now) {
    enqueue(pending_[n].second);
    ++n;
  }
  pending_.erase(pending_.begin(), pending_.begin() + static_cast<std::ptrdiff_t>(n));
}

std::optional<TxPacket> ScriptedNode::pop_transmit() {
  if (out_.empty()) {
    return std::nullopt;
  }
  TxPacket p = std::move(out_.front());
  out_.pop_front();
  ++activity_;
  return p;
}

Time ScriptedNode::next_deadline() const {
  if (fixed_deadline) {
    return *fixed_deadline;
  }
  return pending_.empty() ? Time::never() : pending_.front().first;
}

std::optional<StackUsage> ScriptedNode::debug_usage() const {
  if (!usage) {
    return std::nullopt;
  }
  StackUsage u = *usage;
  u.tx_queued += static_cast<std::uint32_t>(pending_.size() + out_.size());
  return u;
}

Time ScriptedNode::next_app_deadline() const {
  return app_times_.empty() ? Time::never() : app_times_.front();
}

void ScriptedNode::run_apps(Time now) {
  const bool due = !app_times_.empty() && app_times_.front() <= now;
  if (!due && !act_on_every_call) {
    return;
  }
  calls_.emplace_back('p', now);
  ++activity_;
  std::size_t n = 0;
  while (n < app_times_.size() && app_times_[n] <= now) {
    ++n;
  }
  app_times_.erase(app_times_.begin(), app_times_.begin() + static_cast<std::ptrdiff_t>(n));
  if (on_app) {
    on_app(*this, now);
  }
}

}  // namespace utcp::sim
