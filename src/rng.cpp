// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/rng.hpp"

#include <chrono>
#include <cstring>
#include <random>
#include <thread>

#include "cf/contract.hpp"

namespace cf {
namespace {

[[nodiscard]] constexpr std::uint64_t rotl64(std::uint64_t value, unsigned count) noexcept {
  return (value << count) | (value >> (64u - count));
}

[[nodiscard]] constexpr std::uint32_t rotl32(std::uint32_t value, unsigned count) noexcept {
  return (value << count) | (value >> (32u - count));
}

[[nodiscard]] constexpr std::uint64_t splitMix64(std::uint64_t& state) noexcept {
  state += 0x9E3779B97F4A7C15ULL;
  std::uint64_t z = state;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

[[nodiscard]] constexpr std::uint32_t littleEndian32(const std::uint8_t* p) noexcept {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

void storeLittleEndian32(std::uint8_t* p, std::uint32_t value) noexcept {
  p[0] = static_cast<std::uint8_t>(value & 0xFFu);
  p[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  p[2] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  p[3] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
}

}  // namespace

Rng::Rng(std::uint64_t seed) noexcept : seed_(seed) {
  std::uint64_t state = seed;
  for (std::size_t i = 0; i < state_.size(); ++i) {
    state_[i] = splitMix64(state);
  }
  // Guard against the all-zero state, which xoshiro cannot leave.
  if ((state_[0] | state_[1] | state_[2] | state_[3]) == 0) {
    state_[0] = 0x9E3779B97F4A7C15ULL;
  }
}

std::uint64_t Rng::next() noexcept {
  const std::uint64_t result = rotl64(state_[1] * 5u, 7) * 9u;
  const std::uint64_t t = state_[1] << 17;
  state_[2] ^= state_[0];
  state_[3] ^= state_[1];
  state_[1] ^= state_[2];
  state_[0] ^= state_[3];
  state_[2] ^= t;
  state_[3] = rotl64(state_[3], 45);
  return result;
}

std::uint64_t Rng::bounded(std::uint64_t boundExclusive) noexcept {
  if (boundExclusive == 0) {
    return 0;
  }
  const std::uint64_t threshold = (0u - boundExclusive) % boundExclusive;
  for (;;) {
    const std::uint64_t draw = next();
    if (draw >= threshold) {
      return draw % boundExclusive;
    }
  }
}

std::int64_t Rng::boundedSigned(std::int64_t lowInclusive, std::int64_t highExclusive) noexcept {
  if (highExclusive <= lowInclusive) {
    return lowInclusive;
  }
  const auto span = static_cast<std::uint64_t>(highExclusive - lowInclusive);
  return lowInclusive + static_cast<std::int64_t>(bounded(span));
}

bool Rng::chance(std::uint64_t numerator, std::uint64_t denominator) noexcept {
  if (denominator == 0) {
    return false;
  }
  return bounded(denominator) < numerator;
}

void Rng::fillBytes(std::span<std::uint8_t> out) noexcept {
  std::size_t offset = 0;
  while (offset < out.size()) {
    const std::uint64_t draw = next();
    for (unsigned i = 0; i < 8 && offset < out.size(); ++i) {
      out[offset++] = static_cast<std::uint8_t>((draw >> (i * 8)) & 0xFFu);
    }
  }
}

ChaCha20::ChaCha20(const HmacKey& key, const std::array<std::uint8_t, 12>& nonce,
                   std::uint32_t initialCounter) noexcept {
  state_[0] = 0x61707865u;
  state_[1] = 0x3320646eu;
  state_[2] = 0x79622d32u;
  state_[3] = 0x6b206574u;
  for (std::size_t i = 0; i < 8; ++i) {
    state_[4 + i] = littleEndian32(key.data() + (i * 4));
  }
  state_[12] = initialCounter;
  state_[13] = littleEndian32(nonce.data());
  state_[14] = littleEndian32(nonce.data() + 4);
  state_[15] = littleEndian32(nonce.data() + 8);
}

void ChaCha20::block(std::array<std::uint8_t, 64>& out) noexcept {
  std::array<std::uint32_t, 16> working = state_;
  const auto quarterRound = [](std::uint32_t& a, std::uint32_t& b, std::uint32_t& c,
                               std::uint32_t& d) {
    a += b;
    d ^= a;
    d = rotl32(d, 16);
    c += d;
    b ^= c;
    b = rotl32(b, 12);
    a += b;
    d ^= a;
    d = rotl32(d, 8);
    c += d;
    b ^= c;
    b = rotl32(b, 7);
  };

  for (int round = 0; round < 10; ++round) {
    quarterRound(working[0], working[4], working[8], working[12]);
    quarterRound(working[1], working[5], working[9], working[13]);
    quarterRound(working[2], working[6], working[10], working[14]);
    quarterRound(working[3], working[7], working[11], working[15]);
    quarterRound(working[0], working[5], working[10], working[15]);
    quarterRound(working[1], working[6], working[11], working[12]);
    quarterRound(working[2], working[7], working[8], working[13]);
    quarterRound(working[3], working[4], working[9], working[14]);
  }

  for (std::size_t i = 0; i < 16; ++i) {
    storeLittleEndian32(out.data() + (i * 4), working[i] + state_[i]);
  }
  state_[12] += 1;
}

void ChaCha20::keystream(std::span<std::uint8_t> out) noexcept {
  std::size_t offset = 0;
  while (offset < out.size()) {
    if (buffered_ == buffer_.size()) {
      block(buffer_);
      buffered_ = 0;
    }
    const std::size_t available = buffer_.size() - buffered_;
    const std::size_t remaining = out.size() - offset;
    const std::size_t take = (available < remaining) ? available : remaining;
    std::memcpy(out.data() + offset, buffer_.data() + buffered_, take);
    buffered_ += take;
    offset += take;
  }
}

void secureRandomBytes(std::span<std::uint8_t> out) {
  if (out.empty()) {
    return;
  }
  // Seed material comes from the operating system entropy source. ChaCha20 then
  // expands it, so a caller that asks for a large buffer does not depend on the
  // entropy source's throughput or per-call quality.
  std::random_device device;
  HmacKey key{};
  std::array<std::uint8_t, 12> nonce{};
  for (std::size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<std::uint8_t>(device() & 0xFFu);
  }
  for (std::size_t i = 0; i < nonce.size(); ++i) {
    nonce[i] = static_cast<std::uint8_t>(device() & 0xFFu);
  }
  ChaCha20 stream(key, nonce);
  stream.keystream(out);
}

std::array<std::uint8_t, 16> secureRandom128() {
  std::array<std::uint8_t, 16> bytes{};
  secureRandomBytes(std::span<std::uint8_t>(bytes.data(), bytes.size()));
  return bytes;
}

}  // namespace cf
