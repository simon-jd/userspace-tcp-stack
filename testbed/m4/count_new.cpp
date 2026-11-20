// Optional Linux allocation diagnostic. LD_PRELOAD only into the measured
// process, setting UTCP_NEW_COUNTER to a new, writable counter file.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <new>

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace {

using Counter = std::atomic<std::uint64_t>;
static_assert(Counter::is_always_lock_free && sizeof(Counter) == sizeof(std::uint64_t));
Counter* count = nullptr;

[[noreturn]] void fail(const char* operation) {
  std::perror(operation);
  std::_Exit(127);
}

__attribute__((constructor)) void open_counter() {
  const char* path = std::getenv("UTCP_NEW_COUNTER");
  if (path == nullptr) {
    return;
  }
  const int fd = ::open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  if (fd < 0) {
    fail("open C++ allocation counter");
  }
  if (::ftruncate(fd, sizeof(Counter)) != 0) {
    fail("size C++ allocation counter");
  }
  void* memory = ::mmap(nullptr, sizeof(Counter), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (memory == MAP_FAILED) {
    fail("map C++ allocation counter");
  }
  ::close(fd);
  count = ::new (memory) Counter{0};
}

void* allocate(std::size_t size, std::size_t alignment) {
  if (count != nullptr) {
    count->fetch_add(1, std::memory_order_relaxed);
  }
  size = size == 0 ? 1 : size;
  while (true) {
    void* p = nullptr;
    if (alignment == 0) {
      p = std::malloc(size);
    } else if (::posix_memalign(&p, alignment, size) != 0) {
      p = nullptr;
    }
    if (p != nullptr) {
      return p;
    }
    if (const std::new_handler handler = std::get_new_handler()) {
      handler();
    } else {
      throw std::bad_alloc{};
    }
  }
}

void* allocate_nothrow(std::size_t n, std::size_t alignment) noexcept {
  try {
    return allocate(n, alignment);
  } catch (...) {
    return nullptr;
  }
}

}  // namespace

void* operator new(std::size_t n) { return allocate(n, 0); }
void* operator new[](std::size_t n) { return allocate(n, 0); }
void* operator new(std::size_t n, std::align_val_t a) {
  return allocate(n, static_cast<std::size_t>(a));
}
void* operator new[](std::size_t n, std::align_val_t a) {
  return allocate(n, static_cast<std::size_t>(a));
}
void* operator new(std::size_t n, const std::nothrow_t&) noexcept {
  return allocate_nothrow(n, 0);
}
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept {
  return allocate_nothrow(n, 0);
}
void* operator new(std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return allocate_nothrow(n, static_cast<std::size_t>(a));
}
void* operator new[](std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return allocate_nothrow(n, static_cast<std::size_t>(a));
}

void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }
