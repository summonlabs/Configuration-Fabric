// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Randomness.
//
//  * Rng        - deterministic, explicitly seeded xoshiro256** generator. All
//                 randomized and property tests use this so that a failing run
//                 is reproducible from its printed seed.
//  * ChaCha20   - stream cipher used to expand a small amount of OS entropy
//                 into session nonces and incarnation identities. Validated
//                 against the RFC 8439 keystream vector.
//  * secureRandomBytes - OS entropy (std::random_device) expanded through
//                 ChaCha20. This is used for unguessable identities, not for
//                 bulk data confidentiality.

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>

#include "cf/hash.hpp"

namespace cf {

/// Deterministic xoshiro256** generator. Not for secrets.
class Rng final {
 public:
  explicit Rng(std::uint64_t seed) noexcept;

  [[nodiscard]] std::uint64_t next() noexcept;
  /// Uniform in [0, boundExclusive) via rejection sampling; returns 0 for a zero
  /// bound rather than dividing by zero.
  [[nodiscard]] std::uint64_t bounded(std::uint64_t boundExclusive) noexcept;
  [[nodiscard]] std::int64_t boundedSigned(std::int64_t lowInclusive,
                                           std::int64_t highExclusive) noexcept;
  [[nodiscard]] bool chance(std::uint64_t numerator, std::uint64_t denominator) noexcept;
  void fillBytes(std::span<std::uint8_t> out) noexcept;
  [[nodiscard]] std::uint64_t seed() const noexcept { return seed_; }

 private:
  std::array<std::uint64_t, 4> state_{};
  std::uint64_t seed_{0};
};

/// ChaCha20 keystream generator (RFC 8439). Deterministic given key and nonce.
class ChaCha20 final {
 public:
  ChaCha20(const HmacKey& key, const std::array<std::uint8_t, 12>& nonce,
           std::uint32_t initialCounter = 0) noexcept;

  /// Fills out with keystream bytes and advances the counter.
  void keystream(std::span<std::uint8_t> out) noexcept;

 private:
  void block(std::array<std::uint8_t, 64>& out) noexcept;

  std::array<std::uint32_t, 16> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffered_{64};
};

/// Fills out with OS-derived random bytes expanded through ChaCha20.
void secureRandomBytes(std::span<std::uint8_t> out);

/// Convenience: a fresh 16-byte opaque value as raw bytes.
[[nodiscard]] std::array<std::uint8_t, 16> secureRandom128();

}  // namespace cf
