// Non-owning reference to a callable (like std::function_ref of C++26).
//
// Holds a pointer to the callable and a call thunk; it never allocates. The
// referenced callable must outlive every call. Passing a lambda directly as a
// function argument is safe; storing a FunctionRef to a temporary is not.
// Function pointers are not accepted: wrap them in a lambda.
#pragma once

#include <functional>
#include <memory>
#include <type_traits>
#include <utility>

namespace utcp {

template <class Signature>
class FunctionRef;

template <class R, class... Args>
class FunctionRef<R(Args...)> {
public:
  template <class F>
    requires(!std::is_same_v<std::remove_cvref_t<F>, FunctionRef> &&
             !std::is_pointer_v<std::remove_cvref_t<F>> &&
             !std::is_function_v<std::remove_reference_t<F>> &&
             std::is_invocable_r_v<R, std::remove_reference_t<F>&, Args...>)
  constexpr FunctionRef(F&& f) noexcept  // implicit, so lambdas convert at call sites
      : obj_(const_cast<void*>(static_cast<const void*>(std::addressof(f)))),
        call_(&invoke<std::remove_reference_t<F>>) {}

  constexpr FunctionRef(const FunctionRef&) noexcept = default;
  constexpr FunctionRef& operator=(const FunctionRef&) noexcept = default;

  R operator()(Args... args) const { return call_(obj_, std::forward<Args>(args)...); }

private:
  template <class T>
  static R invoke(void* obj, Args... args) {
    return std::invoke(*static_cast<T*>(obj), std::forward<Args>(args)...);
  }

  void* obj_;
  R (*call_)(void*, Args...);
};

}  // namespace utcp
