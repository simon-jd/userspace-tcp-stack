#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <new>

std::uint64_t calls() {
  std::uint64_t value = 0;
  auto* file = std::fopen(std::getenv("UTCP_NEW_COUNTER"), "rb");
  if (file == nullptr || std::fread(&value, sizeof(value), 1, file) != 1) {
    std::exit(2);
  }
  std::fclose(file);
  return value;
}

int main() {
  const auto before = calls();
  const auto a = std::align_val_t{64};
  auto* scalar = ::operator new(1);
  auto* array = ::operator new[](2);
  auto* aligned = ::operator new(3, a);
  auto* aligned_array = ::operator new[](4, a);
  auto* quiet = ::operator new(5, std::nothrow);
  auto* quiet_array = ::operator new[](6, std::nothrow);
  auto* quiet_aligned = ::operator new(7, a, std::nothrow);
  auto* quiet_aligned_array = ::operator new[](8, a, std::nothrow);
  const auto delta = calls() - before;
  ::operator delete(scalar);
  ::operator delete[](array);
  ::operator delete(aligned, a);
  ::operator delete[](aligned_array, a);
  ::operator delete(quiet);
  ::operator delete[](quiet_array);
  ::operator delete(quiet_aligned, a);
  ::operator delete[](quiet_aligned_array, a);
  std::printf("%llu counted allocation calls for eight explicit calls\n",
              static_cast<unsigned long long>(delta));
  return delta == 8 && calls() == before + delta ? 0 : 1;
}
