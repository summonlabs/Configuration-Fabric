// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Strongly typed identifiers. Domain objects (targets, generations, epochs,
// incumbents, artifacts, deployments) are never interchangeable strings or
// integers: each carries a distinct C++ type, and crossing between them
// requires an explicit, reviewable conversion.

#pragma once

#include <compare>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

#include "cf/result.hpp"

namespace cf {

/// Strongly typed unsigned integer with a tag type.
template <class Tag, class T = std::uint64_t>
class StrongUint {
 public:
  using value_type = T;

  constexpr StrongUint() noexcept = default;
  constexpr explicit StrongUint(T value) noexcept : value_(value) {}

  [[nodiscard]] static constexpr StrongUint fromValue(T value) noexcept {
    return StrongUint(value);
  }

  [[nodiscard]] constexpr T value() const noexcept { return value_; }
  /// A default-constructed identity is unset; boundaries must reject it.
  [[nodiscard]] constexpr bool isSet() const noexcept { return value_ != 0; }

  friend constexpr bool operator==(const StrongUint&, const StrongUint&) noexcept = default;
  friend constexpr std::strong_ordering operator<=>(const StrongUint& lhs,
                                                    const StrongUint& rhs) noexcept {
    return lhs.value_ <=> rhs.value_;
  }

 private:
  T value_{0};
};

/// Strongly typed string identifier with an explicit validity predicate.
template <class Tag>
class StrongString {
 public:
  using value_type = std::string;

  StrongString() = default;
  explicit StrongString(std::string value) : value_(std::move(value)) {}

  template <class Validator>
  [[nodiscard]] static Result<StrongString> parse(std::string_view text, std::string_view what,
                                                  Validator&& validator) {
    if (text.empty()) {
      return Result<StrongString>::fail(ErrorCode::MissingField,
                                        std::string(what) + " must not be empty");
    }
    if (!validator(text)) {
      return Result<StrongString>::fail(ErrorCode::InvalidArgument,
                                        std::string(what) + " is not a valid identifier",
                                        std::string(text));
    }
    return Result<StrongString>::ok(StrongString(std::string(text)));
  }

  [[nodiscard]] const std::string& str() const noexcept { return value_; }
  [[nodiscard]] std::string_view view() const noexcept { return value_; }
  [[nodiscard]] bool empty() const noexcept { return value_.empty(); }
  [[nodiscard]] bool isSet() const noexcept { return !value_.empty(); }

  friend bool operator==(const StrongString&, const StrongString&) noexcept = default;
  friend std::strong_ordering operator<=>(const StrongString& lhs,
                                          const StrongString& rhs) noexcept {
    return lhs.value_ <=> rhs.value_;
  }

 private:
  std::string value_;
};

}  // namespace cf

namespace std {

template <class Tag, class T>
struct hash<::cf::StrongUint<Tag, T>> {
  [[nodiscard]] size_t operator()(const ::cf::StrongUint<Tag, T>& id) const noexcept {
    return std::hash<T>{}(id.value());
  }
};

template <class Tag>
struct hash<::cf::StrongString<Tag>> {
  [[nodiscard]] size_t operator()(const ::cf::StrongString<Tag>& id) const noexcept {
    return std::hash<std::string>{}(id.str());
  }
};

}  // namespace std
