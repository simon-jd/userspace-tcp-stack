#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <vector>
#include "core/tcp/send_queue.hpp"

int main() {
  constexpr unsigned reads = 5'000'000;
  for (unsigned n : {16u, 1024u, 16384u}) {
    utcp::ChunkPool pool(8192);
    utcp::SendQueue queue(pool, n * 100);
    std::vector<std::byte> data(100 * n);
    if (queue.write(data) != data.size()) return 2;
    for (unsigned i = 0; i < n; ++i) queue.on_transmit(i * 100, 100, false, {}, {});
    for (unsigned has_sack = 0; has_sack < 2; ++has_sack) {
      if (has_sack) {
        const utcp::Range block{200, 300};
        queue.on_sack(std::span(&block, 1), {}, [](const auto&, bool) {});
      }
      const auto want = static_cast<std::uint64_t>(n * 100 - has_sack * 100) * reads;
      std::array<double, 7> t{};
      for (double& ns : t) {
        const auto begin = std::chrono::steady_clock::now();
        std::uint64_t sum = 0;
        for (unsigned i = 0; i < reads; ++i) sum += queue.in_flight_bytes();
        const auto stop = std::chrono::steady_clock::now();
        if (sum != want) return 1;
        ns = std::chrono::duration<double, std::nano>(stop - begin).count() / reads;
      }
      std::sort(t.begin(), t.end());
      std::cout << n << " queue segments, SACK=" << has_sack << ": median " << t[3]
                << " ns/read, range " << t.front() << " .. " << t.back() << '\n';
    }
  }
}
