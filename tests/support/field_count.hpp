// Number of fields of an aggregate, so that tests can check that a list
// covers every field of a struct (the counting technique of Boost.PFR).
//
// field_count<T>() is the largest N for which T{a1, ..., aN} is well formed
// with arguments that convert to any field type. std::optional fields are
// built through optional's converting constructor; a conversion to
// std::optional itself would compete with it and make the initialisation
// ambiguous, so Any does not offer one.
#pragma once

#include <cstddef>
#include <optional>
#include <utility>

namespace utcp::test {
namespace field_count_detail {

template <class T>
inline constexpr bool is_optional = false;
template <class T>
inline constexpr bool is_optional<std::optional<T>> = true;

struct Any {
  // Declared only: used in unevaluated operands.
  template <class T>
    requires(!is_optional<T>)
  operator T() const noexcept;
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
template <class T, std::size_t... I>
consteval bool brace_initializable(std::index_sequence<I...>) {
  return requires { T{(static_cast<void>(I), Any{})...}; };
}
#pragma GCC diagnostic pop

}  // namespace field_count_detail

template <class T, std::size_t N = 0>
consteval std::size_t field_count() {
  if constexpr (field_count_detail::brace_initializable<T>(std::make_index_sequence<N + 1>{})) {
    return field_count<T, N + 1>();
  } else {
    return N;
  }
}

}  // namespace utcp::test
