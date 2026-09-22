// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Bounded binary codec.
//
// Every byte that crosses a trust boundary (wire frames, journal records,
// snapshot files, deployment plan files) is written and read through these two
// classes. Both are bounded by construction:
//
//  * writes never grow past an explicit limit;
//  * reads never allocate based on an unvalidated length, and a declared length
//    that exceeds the caller's bound fails with OversizePayload rather than
//    attempting the allocation.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "cf/digest.hpp"
#include "cf/result.hpp"

namespace cf {

/// Absolute ceiling for any single length-prefixed field read from an untrusted
/// source. Individual call sites pass tighter bounds; this is the backstop.
inline constexpr std::size_t kAbsoluteMaxFieldBytes = 1u << 20;

class ByteWriter final {
 public:
  explicit ByteWriter(std::size_t reserveBytes = 256) { buffer_.reserve(reserveBytes); }

  void u8(std::uint8_t value) { buffer_.push_back(value); }
  void boolean(bool value) { buffer_.push_back(value ? 1u : 0u); }
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void i64(std::int64_t value);
  void bytes(std::span<const std::uint8_t> value);
  /// Length-prefixed (u32) string. Fails nothing: the caller controls the bound.
  void string(std::string_view value, std::size_t maxBytes = kAbsoluteMaxFieldBytes);
  void digest(const Digest& value) { bytes(value.span()); }
  void sha256(const Sha256Digest& value) {
    bytes(std::span<const std::uint8_t>(value.data(), value.size()));
  }
  void opaque128(const std::array<std::uint8_t, 16>& value) {
    bytes(std::span<const std::uint8_t>(value.data(), value.size()));
  }

  [[nodiscard]] const std::vector<std::uint8_t>& data() const noexcept { return buffer_; }
  [[nodiscard]] std::vector<std::uint8_t> take() noexcept { return std::move(buffer_); }
  [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
  [[nodiscard]] std::span<const std::uint8_t> span() const noexcept {
    return std::span<const std::uint8_t>(buffer_.data(), buffer_.size());
  }

 private:
  std::vector<std::uint8_t> buffer_;
};

class ByteReader final {
 public:
  explicit ByteReader(std::span<const std::uint8_t> data) noexcept : data_(data) {}

  [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }
  [[nodiscard]] bool atEnd() const noexcept { return offset_ == data_.size(); }
  [[nodiscard]] std::size_t consumed() const noexcept { return offset_; }

  [[nodiscard]] Result<std::uint8_t> u8();
  [[nodiscard]] Result<bool> boolean();
  [[nodiscard]] Result<std::uint16_t> u16();
  [[nodiscard]] Result<std::uint32_t> u32();
  [[nodiscard]] Result<std::uint64_t> u64();
  [[nodiscard]] Result<std::int64_t> i64();
  [[nodiscard]] Result<std::string> string(std::size_t maxBytes);
  [[nodiscard]] Result<Digest> digest();
  [[nodiscard]] Result<Sha256Digest> sha256();
  [[nodiscard]] Result<std::array<std::uint8_t, 16>> opaque128();
  [[nodiscard]] Result<std::span<const std::uint8_t>> fixed(std::size_t count);

  /// Fails with ProtocolViolation when unconsumed bytes remain. Every decoder
  /// calls this so that a frame carrying trailing garbage is rejected instead of
  /// silently accepted.
  [[nodiscard]] Status requireEnd() const;

 private:
  [[nodiscard]] Status need(std::size_t count) const;

  std::span<const std::uint8_t> data_;
  std::size_t offset_{0};
};

/// Reads a whole file into memory with a hard byte ceiling. Used for snapshot,
/// metadata and plan loading; never for artifact payloads (those stream).
[[nodiscard]] Result<std::vector<std::uint8_t>> readFileBounded(const std::string& path,
                                                                std::uint64_t maxBytes);
/// Atomic whole-file write: temporary file, durable flush, then rename over the
/// target. The rename is the commit point: a reader observes either the previous
/// complete file or the new complete file.
[[nodiscard]] Status writeFileAtomic(const std::string& path,
                                     std::span<const std::uint8_t> content);

/// Flushes a stdio stream all the way to the storage device (fflush + fsync /
/// _commit). Every durable record in this runtime passes through here before it
/// is considered recorded.
[[nodiscard]] Status flushFileToDisk(std::FILE* file);

}  // namespace cf
