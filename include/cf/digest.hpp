// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Configuration content digest. A digest is a value object: two artifacts with
// the same digest have the same bytes. Every activation path compares digests
// before it mutates target state, and a mismatch is a hard stop, never a
// warning.

#pragma once

#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>

#include "cf/hash.hpp"
#include "cf/result.hpp"

namespace cf {

class Digest final {
 public:
  constexpr Digest() noexcept = default;

  [[nodiscard]] static constexpr Digest fromBytes(const Sha256Digest& bytes) noexcept {
    Digest digest;
    digest.bytes_ = bytes;
    return digest;
  }

  /// Strict hex parsing: exactly 64 lowercase-or-uppercase hex characters.
  [[nodiscard]] static Result<Digest> parse(std::string_view hex);
  [[nodiscard]] static Digest ofContent(std::span<const std::uint8_t> content) noexcept;
  [[nodiscard]] static Digest ofText(std::string_view text) noexcept;

  [[nodiscard]] const Sha256Digest& bytes() const noexcept { return bytes_; }
  [[nodiscard]] std::span<const std::uint8_t> span() const noexcept {
    return std::span<const std::uint8_t>(bytes_.data(), bytes_.size());
  }
  [[nodiscard]] std::string hex() const { return toHex(span()); }
  /// True when the digest is not the all-zero "unset" value. The all-zero digest
  /// is never produced by hashing (it is not a reachable SHA-256 output in this
  /// runtime's threat model) and is reserved as the "no content" sentinel.
  [[nodiscard]] bool isSet() const noexcept;

  friend bool operator==(const Digest&, const Digest&) noexcept = default;
  friend std::strong_ordering operator<=>(const Digest& lhs, const Digest& rhs) noexcept {
    return lhs.bytes_ <=> rhs.bytes_;
  }

 private:
  Sha256Digest bytes_{};
};

/// Short form used in human-facing reports: first 12 hex characters.
[[nodiscard]] std::string shortDigest(const Digest& digest);

}  // namespace cf

namespace std {
template <>
struct hash<::cf::Digest> {
  [[nodiscard]] size_t operator()(const ::cf::Digest& digest) const noexcept {
    size_t seed = 1469598103934665603ULL;
    for (const std::uint8_t byte : digest.bytes()) {
      seed = (seed ^ byte) * 1099511628211ULL;
    }
    return seed;
  }
};
}  // namespace std
