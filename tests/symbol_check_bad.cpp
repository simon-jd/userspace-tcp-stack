// Not part of any program: a library that makes the calls the core must not
// make, used to test cmake/CheckCoreSymbols.cmake: a system call, a C++ clock,
// a random device, the C clocks clock() and timespec_get(), and the backend's
// clock, which a core file could reach through include/utcp/event_loop.hpp.
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <random>

#include "utcp/event_loop.hpp"

long utcp_symbol_check_bad() {
  const long n = ::write(1, "x", 1);
  const auto t = std::chrono::steady_clock::now().time_since_epoch().count();
  std::random_device rd;
  timespec ts{};
  timespec_get(&ts, TIME_UTC);
  const std::clock_t c = std::clock();
  return n + static_cast<long>(t) + static_cast<long>(rd()) + static_cast<long>(ts.tv_nsec) +
         static_cast<long>(c) + static_cast<long>(utcp::mono_now().ns);
}
