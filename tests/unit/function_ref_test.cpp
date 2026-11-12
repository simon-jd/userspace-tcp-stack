#include "core/util/function_ref.hpp"

#include <gtest/gtest.h>

#include <vector>

namespace {

using utcp::FunctionRef;

int apply(FunctionRef<int(int)> f, int x) { return f(x); }

void each(const std::vector<int>& v, FunctionRef<void(const int&)> f) {
  for (const int& x : v) {
    f(x);
  }
}

TEST(FunctionRef, CallsLambdaWithState) {
  int sum = 0;
  each({1, 2, 3}, [&](const int& x) { sum += x; });
  EXPECT_EQ(sum, 6);
}

TEST(FunctionRef, TemporaryLambdaAsArgument) {
  EXPECT_EQ(apply([](int x) { return x * 2; }, 21), 42);
}

TEST(FunctionRef, MutableAndConstCallables) {
  int calls = 0;
  auto counter = [calls]() mutable { return ++calls; };
  FunctionRef<int()> f(counter);
  EXPECT_EQ(f(), 1);
  EXPECT_EQ(f(), 2);  // refers to `counter`, so its state advances

  const auto constant = [] { return 7; };
  FunctionRef<int()> g(constant);
  EXPECT_EQ(g(), 7);
  FunctionRef<int()> h = g;  // copies the reference
  EXPECT_EQ(h(), 7);
}

TEST(FunctionRef, ReturnConversion) {
  auto f = [](int x) -> short { return static_cast<short>(x + 1); };
  FunctionRef<long(int)> r(f);
  EXPECT_EQ(r(1), 2L);
}

}  // namespace
