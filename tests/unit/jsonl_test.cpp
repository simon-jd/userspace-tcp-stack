#include "common/jsonl.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>

#include "support/field_count.hpp"

namespace utcp::app {
namespace {

using namespace std::chrono_literals;

// Number of top-level members of a flat object written by JsonLine (no
// nested objects; commas inside strings are skipped).
std::size_t member_count(const std::string& json) {
  std::size_t n = 0;
  bool in_string = false;
  for (std::size_t i = 0; i < json.size(); ++i) {
    const char c = json[i];
    if (in_string) {
      if (c == '\\') {
        ++i;
      } else if (c == '"') {
        in_string = false;
      }
    } else if (c == '"') {
      in_string = true;
    } else if (c == ':') {
      ++n;
    }
  }
  return n;
}

TEST(Jsonl, QuoteEscapes) {
  EXPECT_EQ(json_quote("plain"), "\"plain\"");
  EXPECT_EQ(json_quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
  EXPECT_EQ(json_quote("\n\t\r\b\f"), "\"\\n\\t\\r\\b\\f\"");
  EXPECT_EQ(json_quote(std::string_view("\x01\x1f\x7f", 3)), "\"\\u0001\\u001f\x7f\"");
  EXPECT_EQ(json_quote("caf\xc3\xa9"), "\"caf\xc3\xa9\"");  // UTF-8 copied
}

TEST(Jsonl, LineKeepsOrderAndTypes) {
  JsonLine l;
  EXPECT_EQ(l.str(), "{}");
  l.add("s", "x").add("b", true).add("u8", std::uint8_t{200}).add("i", std::int64_t{-5});
  l.add("max", std::numeric_limits<std::uint64_t>::max()).add("d", 0.1).add("n", std::numeric_limits<double>::infinity());
  l.add_null("z");
  EXPECT_EQ(l.str(),
            "{\"s\":\"x\",\"b\":true,\"u8\":200,\"i\":-5,\"max\":18446744073709551615,"
            "\"d\":0.1,\"n\":null,\"z\":null}");
  l.clear();
  EXPECT_TRUE(l.empty());
}

TEST(Jsonl, TcpInfoHasEveryField) {
  TcpInfo info;
  info.set_cc_name("newreno");
  info.state = TcpState::established;
  info.ca_state = CaState::recovery;
  info.srtt = 20'113'999ns;
  info.cwnd = 42;
  info.bytes_acked = 1'000'000'000'000;
  JsonLine l;
  add_fields(l, info);
  const std::string s = l.str();
  EXPECT_EQ(member_count(s), utcp::test::field_count<TcpInfo>());
  EXPECT_TRUE(s.starts_with("{\"cc_name\":\"newreno\",\"state\":\"established\","
                            "\"ca_state\":\"recovery\","))
      << s;
  EXPECT_NE(s.find("\"srtt_us\":20113,"), std::string::npos) << s;
  EXPECT_NE(s.find("\"cwnd\":42,"), std::string::npos) << s;
  EXPECT_NE(s.find("\"bytes_acked\":1000000000000,"), std::string::npos) << s;
  EXPECT_TRUE(s.ends_with("\"last_ack_recv_us\":0}")) << s;
}

TEST(Jsonl, TraceEventKeys) {
  TraceEvent e;
  e.t = Time{1'234'567};
  e.conn_id = 3;
  e.kind = TraceKind::ack;
  e.tx = TxKind::fast_rexmit;
  e.cwnd = 42;
  e.srtt_ns = 20'113'999;
  e.rto_ns = -1500;
  JsonLine l;
  l.add("node", "a");
  add_fields(l, e);
  const std::string s = l.str();
  EXPECT_EQ(member_count(s), utcp::test::field_count<TraceEvent>() + 1);
  EXPECT_TRUE(s.starts_with("{\"node\":\"a\",\"t\":1234567,\"conn\":3,\"ev\":\"ack\","
                            "\"tx\":\"fast_rexmit\",\"state\":\"closed\",\"ca\":\"open\","))
      << s;
  EXPECT_NE(s.find("\"cwnd\":42,"), std::string::npos) << s;
  EXPECT_NE(s.find("\"srtt_us\":20113,\"rttvar_us\":0,\"rto_us\":-1,"), std::string::npos) << s;
  EXPECT_TRUE(s.ends_with("\"snd_nxt_off\":0}")) << s;
}

TEST(Jsonl, WriterWritesOneLinePerCall) {
  const std::filesystem::path path =
      std::filesystem::path(testing::TempDir()) / "jsonl_test_writer.jsonl";
  {
    auto w = JsonlWriter::open(path.string());
    ASSERT_TRUE(w) << w.error();
    JsonLine l;
    l.add("a", 1);
    EXPECT_TRUE(w->write(l));
    l.clear();
    l.add("b", "two");
    EXPECT_TRUE(w->write(l));
    EXPECT_TRUE(w->flush());
    EXPECT_EQ(w->lines(), 2u);
    JsonlWriter moved = std::move(*w);
    EXPECT_FALSE(w->write(l));  // the moved-from writer has no file
    EXPECT_EQ(moved.lines(), 2u);
  }
  std::ifstream in(path);
  std::stringstream ss;
  ss << in.rdbuf();
  EXPECT_EQ(ss.str(), "{\"a\":1}\n{\"b\":\"two\"}\n");
  std::filesystem::remove(path);

  const auto bad = JsonlWriter::open("/nonexistent-dir/x.jsonl");
  ASSERT_FALSE(bad);
  EXPECT_NE(bad.error().find("/nonexistent-dir/x.jsonl: "), std::string::npos);
}

}  // namespace
}  // namespace utcp::app
