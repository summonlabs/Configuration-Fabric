// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Checked arithmetic. Every size, count, offset or capacity derived from
// external input (wire frames, persisted records, plan files, CLI arguments)
// must pass through these helpers before it is used to allocate, index, or
// accumulate.

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>

namespace cf {

template <class T>
[[nodiscard]] constexpr std::optional<T> checkedAdd(T a, T b) noexcept {
  static_assert(std::is_unsigned_v<T>, "checkedAdd requires an unsigned type");
  if (a > std::numeric_limits<T>::max() - b) {
    return std::nullopt;
  }
  return static_cast<T>(a + b);
}

template <class T>
[[nodiscard]] constexpr std::optional<T> checkedSub(T a, T b) noexcept {
  static_assert(std::is_unsigned_v<T>, "checkedSub requires an unsigned type");
  if (b > a) {
    return std::nullopt;
  }
  return static_cast<T>(a - b);
}

template <class T>
[[nodiscard]] constexpr std::optional<T> checkedMul(T a, T b) noexcept {
  static_assert(std::is_unsigned_v<T>, "checkedMul requires an unsigned type");
  if (a != 0 && b > std::numeric_limits<T>::max() / a) {
    return std::nullopt;
  }
  return static_cast<T>(a * b);
}

/// Narrowing conversion that fails instead of truncating.
template <class To, class From>
[[nodiscard]] constexpr std::optional<To> checkedCast(From value) noexcept {
  static_assert(std::is_integral_v<To> && std::is_integral_v<From>,
                "checkedCast requires integral types");
  if constexpr (std::is_signed_v<From> == std::is_signed_v<To>) {
    if (value < static_cast<From>(std::numeric_limits<To>::min()) ||
        value > static_cast<From>(std::numeric_limits<To>::max())) {
      return std::nullopt;
    }
  } else if constexpr (std::is_signed_v<From>) {
    if (value < 0) {
      return std::nullopt;
    }
    using UFrom = std::make_unsigned_t<From>;
    if (static_cast<UFrom>(value) > static_cast<UFrom>(std::numeric_limits<To>::max())) {
      return std::nullopt;
    }
  } else {
    using UTo = std::make_unsigned_t<To>;
    if (value > static_cast<UTo>(std::numeric_limits<To>::max())) {
      return std::nullopt;
    }
  }
  return static_cast<To>(value);
}

/// Saturating decrement used for bounded retry counters.
template <class T>
[[nodiscard]] constexpr T saturatingSub(T a, T b) noexcept {
  return (b > a) ? static_cast<T>(0) : static_cast<T>(a - b);
}

}  // namespace cf
