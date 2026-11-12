// Invariant checks (DESIGN §13.2).
//
// UTCP_CHECK(expr) is always on. UTCP_DCHECK(expr) is on in debug builds
// (NDEBUG undefined) and in builds configured with UTCP_DCHECKS=ON (presets
// gcc-sweep and clang-fuzz); otherwise the expression is type-checked but not
// evaluated. A failed check calls glibc's __assert_fail, which prints the
// expression and location to stderr and aborts. The core therefore links no
// stdio itself, and core.forbidden_symbols allows __assert_fail.
#pragma once

// glibc declares __assert_fail in <assert.h> only when NDEBUG is undefined,
// so it is declared here for every build type. The declaration matches
// glibc's (C linkage, noexcept, noreturn).
extern "C" void __assert_fail(const char* assertion, const char* file, unsigned int line,
                              const char* function) noexcept __attribute__((__noreturn__));

#if !defined(NDEBUG) || (defined(UTCP_DCHECKS) && UTCP_DCHECKS)
#define UTCP_DCHECK_IS_ON 1
#else
#define UTCP_DCHECK_IS_ON 0
#endif

#define UTCP_CHECK(expr)                                                                   \
  (__builtin_expect(static_cast<bool>(expr), 1)                                            \
       ? static_cast<void>(0)                                                              \
       : __assert_fail("UTCP_CHECK(" #expr ")", __FILE__, __LINE__, __func__))

#if UTCP_DCHECK_IS_ON
#define UTCP_DCHECK(expr)                                                                  \
  (__builtin_expect(static_cast<bool>(expr), 1)                                            \
       ? static_cast<void>(0)                                                              \
       : __assert_fail("UTCP_DCHECK(" #expr ")", __FILE__, __LINE__, __func__))
#else
#define UTCP_DCHECK(expr) static_cast<void>(sizeof(static_cast<bool>(expr)))
#endif
