// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Content and transport integrity primitives.
//
//  * SHA-256      - content digest of immutable configuration artifacts, and the
//                   building block for HMAC-SHA256 peer authentication.
//  * HMAC-SHA256  - peer identity proof (see cf/protocol.hpp handshake).
//  * CRC32C       - cheap corruption detection for wire frames and durable
//                   journal records. CRC32C is NOT a security primitive: it is a
//                   corruption detector only, and the code never treats it as
//                   authentication.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace cf {

inline constexpr std::size_t kSha256Bytes = 32;   ///< raw digest size
inline constexpr std::size_t kSha256HexChars = 64; ///< lowercase hex digest size

using Sha256Digest = std::array<std::uint8_t, kSha256Bytes>;
using HmacKey = std::array<std::uint8_t, kSha256Bytes>; ///< shared secret (256-bit)

// --- SHA-256 ---------------------------------------------------------------

[[nodiscard]] Sha256Digest sha256(std::span<const std::uint8_t> data) noexcept;
[[nodiscard]] Sha256Digest sha256(std::string_view data) noexcept;

/// Incremental SHA-256. Used for streaming artifact ingestion so that a
/// multi-megabyte artifact is never held in memory twice.
class Sha256 final {
 public:
  Sha256() noexcept;
  void update(std::span<const std::uint8_t> data) noexcept;
  void update(std::string_view data) noexcept;
  /// Finalizes. The object must not be updated afterwards.
  [[nodiscard]] Sha256Digest finish() noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffered_{0};
  std::uint64_t totalBytes_{0};
};

// --- HMAC-SHA256 -----------------------------------------------------------

[[nodiscard]] Sha256Digest hmacSha256(const HmacKey& key,
                                      std::span<const std::uint8_t> message) noexcept;
/// Domain-separated HMAC over a text transcript (see protocol handshake).
[[nodiscard]] Sha256Digest hmacSha256(const HmacKey& key, std::string_view message) noexcept;
/// HMAC over a key of any length, per RFC 2104: keys longer than the block size
/// are hashed first, shorter keys are zero padded. Sessions always use the
/// fixed-width HmacKey; this general form exists so the primitive can be checked
/// against the published test vectors.
[[nodiscard]] Sha256Digest hmacSha256(std::span<const std::uint8_t> key,
                                      std::span<const std::uint8_t> message) noexcept;
[[nodiscard]] Sha256Digest hmacSha256(std::span<const std::uint8_t> key,
                                      std::string_view message) noexcept;

/// Constant-time equality. Authentication decisions must never branch on
/// secret-derived bytes in a way that leaks timing.
[[nodiscard]] bool constantTimeEquals(std::span<const std::uint8_t> a,
                                      std::span<const std::uint8_t> b) noexcept;

// --- CRC32C (Castagnoli) ---------------------------------------------------

[[nodiscard]] std::uint32_t crc32c(std::span<const std::uint8_t> data) noexcept;
[[nodiscard]] std::uint32_t crc32c(std::string_view data) noexcept;

class Crc32c final {
 public:
  Crc32c() noexcept = default;
  void update(std::span<const std::uint8_t> data) noexcept;
  [[nodiscard]] std::uint32_t value() const noexcept { return state_; }

 private:
  std::uint32_t state_{0xFFFFFFFFu};
};

// --- Hex -------------------------------------------------------------------

[[nodiscard]] std::string toHex(std::span<const std::uint8_t> bytes);
/// Strict: rejects odd lengths, non-hex characters and wrong output sizes.
[[nodiscard]] bool fromHex(std::string_view text, std::span<std::uint8_t> out) noexcept;

}  // namespace cf
