#include "common/cli.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

namespace utcp::app {
namespace {

using namespace std::chrono_literals;

CliParser bulk_parser() {
  CliParser p("utcp-bulk", "Bulk transfer.");
  p.flag("send", "send data")
      .option("connect", "IP:PORT", "connect to")
      .option("bytes", "N", "bytes to send", "1Gi")
      .option("sample-ms", "MS", "sample period")
      .positional("file", "output", false);
  return p;
}

std::expected<CliArgs, std::string> parse(const CliParser& p, std::vector<std::string_view> args) {
  return p.parse(std::span<const std::string_view>(args));
}

TEST(Cli, OptionsFlagsAndPositionals) {
  const CliParser p = bulk_parser();
  const auto a = parse(p, {"--send", "--connect", "1.2.3.4:5", "--bytes=10M", "out", "--sample-ms",
                           "10", "--bytes", "20M"});
  ASSERT_TRUE(a) << a.error();
  EXPECT_TRUE(a->flag("send"));
  EXPECT_FALSE(a->help());
  EXPECT_EQ(a->get("connect"), "1.2.3.4:5");
  EXPECT_EQ(a->get("bytes"), "20M");  // the last one wins
  EXPECT_EQ(a->get("sample-ms"), "10");
  EXPECT_EQ(a->positionals(), std::vector<std::string>{"out"});

  const auto d = parse(p, {});
  ASSERT_TRUE(d);
  EXPECT_FALSE(d->flag("send"));
  EXPECT_FALSE(d->given("bytes"));
  EXPECT_EQ(d->get("bytes"), "1Gi");  // the default
  EXPECT_EQ(d->get("connect"), std::nullopt);

  const auto dash = parse(p, {"--", "--send"});
  ASSERT_TRUE(dash);
  EXPECT_FALSE(dash->flag("send"));
  EXPECT_EQ(dash->positionals(), std::vector<std::string>{"--send"});
}

TEST(Cli, Errors) {
  const CliParser p = bulk_parser();
  EXPECT_EQ(parse(p, {"--nope"}).error(), "unknown option --nope");
  EXPECT_EQ(parse(p, {"-x"}).error(), "unknown option -x");
  EXPECT_EQ(parse(p, {"--send=1"}).error(), "option --send takes no value");
  EXPECT_EQ(parse(p, {"--bytes"}).error(), "option --bytes needs a value (N)");
  EXPECT_EQ(parse(p, {"a", "b"}).error(), "unexpected argument 'b'");

  CliParser q("prog", "x");
  q.positional("in", "input");
  EXPECT_EQ(parse(q, {}).error(), "missing argument in");
  const auto h = parse(q, {"-h"});
  ASSERT_TRUE(h);
  EXPECT_TRUE(h->help());
}

TEST(Cli, Usage) {
  EXPECT_EQ(bulk_parser().usage(),
            "usage: utcp-bulk [options] [file]\n"
            "Bulk transfer.\n"
            "  file               output\n"
            "  --send             send data\n"
            "  --connect IP:PORT  connect to\n"
            "  --bytes N          bytes to send (default 1Gi)\n"
            "  --sample-ms MS     sample period\n"
            "  -h, --help         print this help\n");
}

TEST(Cli, Numbers) {
  EXPECT_EQ(parse_u64("0").value(), 0u);
  EXPECT_EQ(parse_u64("18446744073709551615").value(), 18446744073709551615u);
  EXPECT_FALSE(parse_u64("18446744073709551616"));
  EXPECT_FALSE(parse_u64(""));
  EXPECT_FALSE(parse_u64("-1"));
  EXPECT_FALSE(parse_u64(" 1"));
  EXPECT_FALSE(parse_u64("1x"));

  EXPECT_EQ(parse_size("1500").value(), 1500u);
  EXPECT_EQ(parse_size("64Ki").value(), 65536u);
  EXPECT_EQ(parse_size("10M").value(), 10'000'000u);
  EXPECT_EQ(parse_size("1Gi").value(), 1'073'741'824u);
  EXPECT_EQ(parse_size("2K").value(), 2000u);
  EXPECT_FALSE(parse_size("Ki"));
  EXPECT_FALSE(parse_size("1k"));
  EXPECT_FALSE(parse_size("1.5M"));
  EXPECT_FALSE(parse_size("18446744073709551615K"));
}

TEST(Cli, Durations) {
  EXPECT_EQ(parse_duration("200ms").value(), 200ms);
  EXPECT_EQ(parse_duration("1.5s").value(), 1500ms);
  EXPECT_EQ(parse_duration("0.000000001s").value(), 1ns);
  EXPECT_EQ(parse_duration("7ns").value(), 7ns);
  EXPECT_EQ(parse_duration("3us").value(), 3us);
  EXPECT_EQ(parse_duration("10", 1ms).value(), 10ms);
  EXPECT_EQ(parse_duration("0.25", 1s).value(), 250ms);
  EXPECT_FALSE(parse_duration("10"));
  EXPECT_FALSE(parse_duration("1.5ns"));
  EXPECT_FALSE(parse_duration("1.s"));
  EXPECT_FALSE(parse_duration(".5s"));
  EXPECT_FALSE(parse_duration("1.0000000001s"));  // 10 decimals
  EXPECT_FALSE(parse_duration("-1s"));
  EXPECT_FALSE(parse_duration("10m"));
  EXPECT_FALSE(parse_duration("9223372037s"));  // above 2^63 ns
}

TEST(Cli, Addresses) {
  EXPECT_EQ(parse_ipv4("198.18.0.2").value(), Ipv4Addr::from_octets(198, 18, 0, 2));
  EXPECT_EQ(parse_ipv4("0.0.0.0").value(), Ipv4Addr{});
  EXPECT_EQ(parse_ipv4("255.255.255.255").value(), Ipv4Addr{0xffffffff});
  for (const char* bad : {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1..2.3", "1.2.3.4.",
                          "a.b.c.d", "1.2.3.-4", "0000.1.1.1"}) {
    EXPECT_FALSE(parse_ipv4(bad)) << bad;
  }
  EXPECT_EQ(parse_port("65535").value(), 65535);
  EXPECT_FALSE(parse_port("65536"));
  EXPECT_EQ(parse_endpoint("10.0.0.1:8080").value(),
            (Endpoint{Ipv4Addr::from_octets(10, 0, 0, 1), 8080}));
  EXPECT_FALSE(parse_endpoint("10.0.0.1"));
  EXPECT_FALSE(parse_endpoint("10.0.0.1:"));
  EXPECT_FALSE(parse_endpoint("host:80"));

  const auto pr = parse_pair("200:1048576").value();
  EXPECT_EQ(pr.first, "200");
  EXPECT_EQ(pr.second, "1048576");
  EXPECT_EQ(parse_pair("a=b:c", '=').value().second, "b:c");
  EXPECT_FALSE(parse_pair(":1"));
  EXPECT_FALSE(parse_pair("1:"));
  EXPECT_FALSE(parse_pair("1"));
}

}  // namespace
}  // namespace utcp::app
