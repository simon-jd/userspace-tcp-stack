#include "common/dns.hpp"

#include <algorithm>

namespace utcp::app {

namespace {

constexpr std::size_t header_size = 12;
constexpr std::size_t max_name = 255;  // RFC 1035 §2.3.4, encoded
constexpr std::size_t max_label = 63;

char lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

std::string lower_name(std::string_view s) {
  if (s.ends_with('.')) {
    s.remove_suffix(1);
  }
  std::string out(s);
  std::ranges::transform(out, out.begin(), lower);
  return out;
}

void put16(std::vector<std::byte>& v, std::uint16_t x) {
  v.push_back(static_cast<std::byte>(x >> 8));
  v.push_back(static_cast<std::byte>(x & 0xff));
}

class Reader {
public:
  explicit Reader(std::span<const std::byte> m) : m_(m) {}

  [[nodiscard]] std::size_t pos() const { return pos_; }
  [[nodiscard]] bool has(std::size_t n) const { return m_.size() - pos_ >= n; }
  std::uint8_t u8(std::size_t at) const { return std::to_integer<std::uint8_t>(m_[at]); }
  std::uint16_t u16() {
    const auto v = static_cast<std::uint16_t>((u8(pos_) << 8) | u8(pos_ + 1));
    pos_ += 2;
    return v;
  }
  std::uint32_t u32() {
    const std::uint32_t hi = u16();
    return (hi << 16) | u16();
  }
  void skip(std::size_t n) { pos_ += n; }

  // RFC 1035 §4.1.4: a sequence of labels ending in a zero octet or a
  // pointer. Every pointer must point before the label that holds it, so a
  // chain of them always ends.
  std::expected<std::string, std::string> name() {
    std::string out;
    std::size_t at = pos_;
    std::size_t encoded = 0;
    bool jumped = false;
    while (true) {
      if (at >= m_.size()) {
        return std::unexpected(std::string("name runs past the message"));
      }
      const std::uint8_t len = u8(at);
      if ((len & 0xc0) == 0xc0) {
        if (at + 1 >= m_.size()) {
          return std::unexpected(std::string("truncated compression pointer"));
        }
        const std::size_t target = static_cast<std::size_t>(((len & 0x3f) << 8) | u8(at + 1));
        if (target >= at) {
          return std::unexpected(std::string("compression pointer does not point backwards"));
        }
        if (!jumped) {
          pos_ = at + 2;
          jumped = true;
        }
        at = target;
        continue;
      }
      if ((len & 0xc0) != 0) {
        return std::unexpected(std::string("reserved label type"));
      }
      encoded += 1u + len;
      if (encoded > max_name) {
        return std::unexpected(std::string("name longer than 255 octets"));
      }
      if (len == 0) {
        if (!jumped) {
          pos_ = at + 1;
        }
        return out;
      }
      if (at + 1 + len > m_.size()) {
        return std::unexpected(std::string("label runs past the message"));
      }
      if (!out.empty()) {
        out += '.';
      }
      for (std::size_t i = 0; i < len; ++i) {
        out += lower(static_cast<char>(u8(at + 1 + i)));
      }
      at += 1u + len;
    }
  }

  std::span<const std::byte> bytes(std::size_t n) {
    const auto s = m_.subspan(pos_, n);
    pos_ += n;
    return s;
  }

private:
  std::span<const std::byte> m_;
  std::size_t pos_ = 0;
};

}  // namespace

std::expected<std::vector<std::byte>, std::string> dns_encode_query(std::uint16_t id,
                                                                    std::string_view name,
                                                                    std::uint16_t qtype) {
  if (name.ends_with('.')) {
    name.remove_suffix(1);
  }
  if (name.empty()) {
    return std::unexpected(std::string("empty name"));
  }
  std::vector<std::byte> q;
  put16(q, id);
  put16(q, 0x0100);  // RFC 1035 §4.1.1: QR 0, opcode 0, RD 1
  put16(q, 1);       // QDCOUNT
  put16(q, 0);
  put16(q, 0);
  put16(q, 0);
  std::size_t encoded = 1;  // the root label
  std::string_view rest = name;
  while (true) {
    const std::size_t dot = rest.find('.');
    const std::string_view label = rest.substr(0, dot);
    if (label.empty() || label.size() > max_label) {
      return std::unexpected("bad label in '" + std::string(name) + "'");
    }
    encoded += 1 + label.size();
    if (encoded > max_name) {
      return std::unexpected("name too long: '" + std::string(name) + "'");
    }
    q.push_back(static_cast<std::byte>(label.size()));
    for (const char c : label) {
      q.push_back(static_cast<std::byte>(c));
    }
    if (dot == std::string_view::npos) {
      break;
    }
    rest.remove_prefix(dot + 1);
  }
  q.push_back(std::byte{0});
  put16(q, qtype);
  put16(q, dns_class_in);
  return q;
}

std::expected<DnsResponse, std::string> dns_parse_response(std::span<const std::byte> msg) {
  Reader r(msg);
  if (!r.has(header_size)) {
    return std::unexpected(std::string("message shorter than the header"));
  }
  DnsResponse out;
  out.id = r.u16();
  const std::uint16_t flags = r.u16();
  out.qr = (flags & 0x8000) != 0;
  out.truncated = (flags & 0x0200) != 0;
  out.rcode = static_cast<std::uint8_t>(flags & 0x000f);
  const std::uint16_t qdcount = r.u16();
  const std::uint16_t ancount = r.u16();
  r.skip(4);  // NSCOUNT, ARCOUNT: not read
  for (std::uint16_t i = 0; i < qdcount; ++i) {
    auto n = r.name();
    if (!n) {
      return std::unexpected("question: " + n.error());
    }
    if (!r.has(4)) {
      return std::unexpected(std::string("truncated question"));
    }
    r.skip(4);
    if (i == 0) {
      out.qname = std::move(*n);
    }
  }
  for (std::uint16_t i = 0; i < ancount; ++i) {
    DnsRecord rec;
    auto n = r.name();
    if (!n) {
      return std::unexpected("answer: " + n.error());
    }
    rec.name = std::move(*n);
    if (!r.has(10)) {
      return std::unexpected(std::string("truncated resource record"));
    }
    rec.type = r.u16();
    rec.klass = r.u16();
    rec.ttl = r.u32();
    const std::uint16_t rdlength = r.u16();
    if (!r.has(rdlength)) {
      return std::unexpected(std::string("RDATA runs past the message"));
    }
    const std::size_t rdata_start = r.pos();
    if (rec.type == dns_type_cname) {
      auto t = r.name();
      if (!t) {
        return std::unexpected("CNAME: " + t.error());
      }
      if (r.pos() != rdata_start + rdlength) {
        return std::unexpected(std::string("CNAME RDATA length mismatch"));
      }
      rec.target = std::move(*t);
      Reader copy(msg);
      copy.skip(rdata_start);
      const auto raw = copy.bytes(rdlength);
      rec.rdata.assign(raw.begin(), raw.end());
    } else {
      const auto raw = r.bytes(rdlength);
      rec.rdata.assign(raw.begin(), raw.end());
    }
    out.answers.push_back(std::move(rec));
  }
  return out;
}

std::expected<std::vector<Ipv4Addr>, std::string> dns_a_records(const DnsResponse& r,
                                                                std::uint16_t id,
                                                                std::string_view name) {
  const std::string want = lower_name(name);
  if (!r.qr) {
    return std::unexpected(std::string("not a response"));
  }
  if (r.id != id) {
    return std::unexpected(std::string("response id does not match the query"));
  }
  if (r.qname != want) {
    return std::unexpected("response is for '" + r.qname + "', not '" + want + "'");
  }
  if (r.rcode != 0) {
    return std::unexpected("server answered rcode " + std::to_string(r.rcode) +
                           (r.rcode == 3 ? " (NXDOMAIN)" : ""));
  }
  if (r.truncated) {
    return std::unexpected(std::string("response truncated (TC set)"));
  }
  // Follow the CNAME chain (at most as many steps as there are records).
  std::string cur = want;
  for (std::size_t step = 0; step <= r.answers.size(); ++step) {
    const auto cname = std::ranges::find_if(r.answers, [&cur](const DnsRecord& rec) {
      return rec.klass == dns_class_in && rec.type == dns_type_cname && rec.name == cur;
    });
    if (cname == r.answers.end()) {
      break;
    }
    cur = cname->target;
  }
  std::vector<Ipv4Addr> addrs;
  for (const DnsRecord& rec : r.answers) {
    if (rec.klass == dns_class_in && rec.type == dns_type_a && rec.name == cur &&
        rec.rdata.size() == 4) {
      addrs.push_back(Ipv4Addr::from_octets(
          std::to_integer<std::uint8_t>(rec.rdata[0]), std::to_integer<std::uint8_t>(rec.rdata[1]),
          std::to_integer<std::uint8_t>(rec.rdata[2]), std::to_integer<std::uint8_t>(rec.rdata[3])));
    }
  }
  if (addrs.empty()) {
    return std::unexpected("no A record for '" + want + "'");
  }
  return addrs;
}

}  // namespace utcp::app
