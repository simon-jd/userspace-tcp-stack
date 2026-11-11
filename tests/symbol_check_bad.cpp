// Not part of any program: a library that makes the calls the core must not
// make, used to test cmake/CheckCoreSymbols.cmake.
#include <unistd.h>

#include <chrono>
#include <random>

long utcp_symbol_check_bad() {
  const long n = ::write(1, "x", 1);
  const auto t = std::chrono::steady_clock::now().time_since_epoch().count();
  std::random_device rd;
  return n + static_cast<long>(t) + static_cast<long>(rd());
}
