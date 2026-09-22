// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/hash.hpp"

#include <cstring>

#include "cf/contract.hpp"

namespace cf {
namespace {

// --- SHA-256 ---------------------------------------------------------------

constexpr std::array<std::uint32_t, 64> kSha256K = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

[[nodiscard]] constexpr std::uint32_t rotr32(std::uint32_t value, unsigned count) noexcept {
  return (value >> count) | (value << (32u - count));
}

[[nodiscard]] constexpr std::uint32_t bigEndian32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

// --- CRC32C ----------------------------------------------------------------

[[nodiscard]] consteval std::array<std::uint32_t, 256> makeCrc32cTable() noexcept {
  std::array<std::uint32_t, 256> table{};
  constexpr std::uint32_t kPoly = 0x82F63B78u;  // reflected Castagnoli polynomial
  for (std::uint32_t i = 0; i < 256; ++i) {
    std::uint32_t crc = i;
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc & 1u) != 0u ? (crc >> 1) ^ kPoly : (crc >> 1);
    }
    table[i] = crc;
  }
  return table;
}

constexpr auto kCrc32cTable = makeCrc32cTable();

[[nodiscard]] std::uint32_t crc32cUpdate(std::uint32_t state,
                                         std::span<const std::uint8_t> data) noexcept {
  std::uint32_t crc = state;
  for (const std::uint8_t byte : data) {
    crc = kCrc32cTable[(crc ^ byte) & 0xFFu] ^ (crc >> 8);
  }
  return crc;
}

}  // namespace

Sha256Digest sha256(std::span<const std::uint8_t> data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

Sha256Digest sha256(std::string_view data) noexcept {
  return sha256(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()),
                                              data.size()));
}

Sha256::Sha256() noexcept {
  state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::array<std::uint32_t, 64> w{};
  for (std::size_t i = 0; i < 16; ++i) {
    w[i] = bigEndian32(block + (i * 4));
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 =
        rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::span<const std::uint8_t> data) noexcept {
  totalBytes_ += static_cast<std::uint64_t>(data.size());
  std::size_t offset = 0;
  if (buffered_ > 0) {
    while (buffered_ < buffer_.size() && offset < data.size()) {
      buffer_[buffered_++] = data[offset++];
    }
    if (buffered_ == buffer_.size()) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }
  while (data.size() - offset >= buffer_.size()) {
    compress(data.data() + offset);
    offset += buffer_.size();
  }
  while (offset < data.size()) {
    buffer_[buffered_++] = data[offset++];
  }
}

void Sha256::update(std::string_view data) noexcept {
  update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()),
                                       data.size()));
}

Sha256Digest Sha256::finish() noexcept {
  const std::uint64_t bitLength = totalBytes_ * 8u;
  // The tail holds 0x80, the zero padding, and the 64-bit big-endian bit count.
  // Worst case (buffered_ == 56) needs 72 bytes, but compress() always consumes
  // whole 64-byte blocks, so the buffer must cover the final rounded-up block.
  std::array<std::uint8_t, 128> tail{};
  tail[0] = 0x80u;
  const std::size_t afterMarker = (buffered_ + 1) % 64;
  const std::size_t padZeros = (afterMarker <= 56) ? (56 - afterMarker) : (120 - afterMarker);
  const std::size_t lengthOffset = 1 + padZeros;
  const std::size_t tailLength = lengthOffset + 8;
  for (std::size_t i = 0; i < 8; ++i) {
    tail[lengthOffset + i] = static_cast<std::uint8_t>((bitLength >> (56 - (i * 8))) & 0xFFu);
  }
  CF_CONTRACT((buffered_ + tailLength) % 64 == 0, "sha256 padding must be block aligned");
  for (std::size_t offset = 0; offset < tailLength; offset += 64) {
    compress(tail.data() + offset);
  }

  Sha256Digest digest{};
  for (std::size_t i = 0; i < 8; ++i) {
    digest[i * 4] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFFu);
    digest[(i * 4) + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFFu);
    digest[(i * 4) + 2] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFFu);
    digest[(i * 4) + 3] = static_cast<std::uint8_t>(state_[i] & 0xFFu);
  }
  return digest;
}

Sha256Digest hmacSha256(const HmacKey& key, std::span<const std::uint8_t> message) noexcept {
  constexpr std::size_t kBlock = 64;
  std::array<std::uint8_t, kBlock> inner{};
  std::array<std::uint8_t, kBlock> outer{};
  for (std::size_t i = 0; i < kBlock; ++i) {
    const std::uint8_t byte = (i < key.size()) ? key[i] : 0u;
    inner[i] = static_cast<std::uint8_t>(byte ^ 0x36u);
    outer[i] = static_cast<std::uint8_t>(byte ^ 0x5cu);
  }

  Sha256 hasher;
  hasher.update(std::span<const std::uint8_t>(inner.data(), inner.size()));
  hasher.update(message);
  const Sha256Digest innerDigest = hasher.finish();

  Sha256 outerHasher;
  outerHasher.update(std::span<const std::uint8_t>(outer.data(), outer.size()));
  outerHasher.update(std::span<const std::uint8_t>(innerDigest.data(), innerDigest.size()));
  return outerHasher.finish();
}

Sha256Digest hmacSha256(const HmacKey& key, std::string_view message) noexcept {
  return hmacSha256(key, std::span<const std::uint8_t>(
                             reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
}

bool constantTimeEquals(std::span<const std::uint8_t> a,
                        std::span<const std::uint8_t> b) noexcept {
  if (a.size() != b.size()) {
    return false;
  }
  std::uint8_t accumulator = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    accumulator = static_cast<std::uint8_t>(accumulator | (a[i] ^ b[i]));
  }
  return accumulator == 0;
}

std::uint32_t crc32c(std::span<const std::uint8_t> data) noexcept {
  return crc32cUpdate(0xFFFFFFFFu, data) ^ 0xFFFFFFFFu;
}

std::uint32_t crc32c(std::string_view data) noexcept {
  return crc32c(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()),
                                              data.size()));
}

void Crc32c::update(std::span<const std::uint8_t> data) noexcept {
  state_ = crc32cUpdate(state_, data);
}

std::string toHex(std::span<const std::uint8_t> bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    out[i * 2] = kDigits[(bytes[i] >> 4) & 0x0Fu];
    out[(i * 2) + 1] = kDigits[bytes[i] & 0x0Fu];
  }
  return out;
}

bool fromHex(std::string_view text, std::span<std::uint8_t> out) noexcept {
  if (text.size() != out.size() * 2) {
    return false;
  }
  const auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return (c - 'a') + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return (c - 'A') + 10;
    }
    return -1;
  };
  for (std::size_t i = 0; i < out.size(); ++i) {
    const int high = nibble(text[i * 2]);
    const int low = nibble(text[(i * 2) + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    out[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

}  // namespace cf
