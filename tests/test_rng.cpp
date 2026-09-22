// Unit and property tests: deterministic and secret-bearing randomness.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <set>
#include <string>

#include "cf/rng.hpp"
#include "testing.hpp"

CF_TEST(unit, seeded_generator_is_reproducible) {
  cf::Rng first(12345);
  cf::Rng second(12345);
  for (int i = 0; i < 64; ++i) {
    CF_EXPECT_EQ(first.next(), second.next());
  }
  cf::Rng different(12346);
  CF_EXPECT(first.next() != different.next());
}

CF_TEST(unit, zero_seed_is_usable) {
  cf::Rng rng(0);
  std::set<std::uint64_t> values;
  for (int i = 0; i < 32; ++i) {
    values.insert(rng.next());
  }
  CF_EXPECT_EQ(values.size(), std::size_t{32});
}

CF_TEST(unit, bounded_respects_its_range) {
  cf::Rng rng(cftest::runSeed());
  for (int bound = 1; bound <= 64; ++bound) {
    for (int i = 0; i < 64; ++i) {
      const std::uint64_t value = rng.bounded(static_cast<std::uint64_t>(bound));
      CF_EXPECT(value < static_cast<std::uint64_t>(bound));
    }
  }
  CF_EXPECT_EQ(rng.bounded(0), std::uint64_t{0});
  const std::int64_t signedValue = rng.boundedSigned(-5, 5);
  CF_EXPECT(signedValue >= -5 && signedValue < 5);
}

CF_TEST(property, bounded_is_approximately_uniform) {
  cf::Rng rng(cftest::runSeed() ^ 0xABCDu);
  constexpr int kBuckets = 8;
  std::array<int, kBuckets> counts{};
  constexpr int kSamples = 80000;
  for (int i = 0; i < kSamples; ++i) {
    counts[rng.bounded(kBuckets)] += 1;
  }
  const int expected = kSamples / kBuckets;
  for (const int count : counts) {
    // Generous bounds: this is a smoke test for a badly broken generator, not a
    // statistical certification.
    CF_EXPECT(count > expected / 2 && count < (expected * 3) / 2);
  }
}

CF_TEST(unit, fill_bytes_covers_the_buffer) {
  cf::Rng rng(7);
  for (std::size_t size = 1; size <= 40; ++size) {
    std::vector<std::uint8_t> buffer(size, 0);
    rng.fillBytes(std::span<std::uint8_t>(buffer.data(), buffer.size()));
    bool anyNonZero = false;
    for (const std::uint8_t byte : buffer) {
      if (byte != 0) {
        anyNonZero = true;
      }
    }
    CF_EXPECT(anyNonZero);
  }
  std::vector<std::uint8_t> empty;
  rng.fillBytes(std::span<std::uint8_t>(empty.data(), empty.size()));
  CF_EXPECT(empty.empty());
}

CF_TEST(unit, secure_random_expands_beyond_the_seed) {
  std::vector<std::uint8_t> buffer(4096, 0);
  cf::secureRandomBytes(std::span<std::uint8_t>(buffer.data(), buffer.size()));
  std::set<std::uint8_t> distinct(buffer.begin(), buffer.end());
  // ChaCha20 output over 4 KiB must not collapse to a handful of values.
  CF_EXPECT(distinct.size() > 100);
  std::vector<std::uint8_t> again(4096, 0);
  cf::secureRandomBytes(std::span<std::uint8_t>(again.data(), again.size()));
  CF_EXPECT(!(buffer == again));
  std::vector<std::uint8_t> none;
  cf::secureRandomBytes(std::span<std::uint8_t>(none.data(), none.size()));
  CF_EXPECT(none.empty());
}
