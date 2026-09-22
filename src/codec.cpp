// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/codec.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#include "cf/checked.hpp"
#include "cf/contract.hpp"
#include "cf/rng.hpp"

namespace cf {
namespace {

[[nodiscard]] std::string tempSiblingPath(const std::string& path) {
  const std::array<std::uint8_t, 16> suffix = secureRandom128();
  return path + ".part-" + toHex(std::span<const std::uint8_t>(suffix.data(), suffix.size()));
}

}  // namespace

void ByteWriter::u16(std::uint16_t value) {
  buffer_.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  buffer_.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void ByteWriter::u32(std::uint32_t value) {
  for (unsigned i = 0; i < 4; ++i) {
    buffer_.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void ByteWriter::u64(std::uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) {
    buffer_.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
  }
}

void ByteWriter::i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }

void ByteWriter::bytes(std::span<const std::uint8_t> value) {
  buffer_.insert(buffer_.end(), value.begin(), value.end());
}

void ByteWriter::string(std::string_view value, std::size_t maxBytes) {
  // Truncation here would corrupt the record silently, so it is a contract
  // violation: callers must bound their inputs before encoding.
  CF_CONTRACT(value.size() <= maxBytes, "encoded string exceeds its declared bound");
  CF_CONTRACT(value.size() <= kAbsoluteMaxFieldBytes, "encoded string exceeds the absolute bound");
  u32(static_cast<std::uint32_t>(value.size()));
  bytes(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(value.data()),
                                      value.size()));
}

Status ByteReader::need(std::size_t count) const {
  if (count > remaining()) {
    return Status::fail(ErrorCode::TruncatedFrame, "record ended before the declared field count");
  }
  return Status::ok();
}

Result<std::uint8_t> ByteReader::u8() {
  CF_TRY(need(1));
  return Result<std::uint8_t>::ok(data_[offset_++]);
}

Result<bool> ByteReader::boolean() {
  CF_TRY_ASSIGN(const std::uint8_t raw, u8());
  if (raw > 1u) {
    return Result<bool>::fail(ErrorCode::MalformedInput, "boolean field is not 0 or 1");
  }
  return Result<bool>::ok(raw == 1u);
}

Result<std::uint16_t> ByteReader::u16() {
  CF_TRY(need(2));
  const std::uint16_t value = static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(data_[offset_]) |
      static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[offset_ + 1]) << 8));
  offset_ += 2;
  return Result<std::uint16_t>::ok(value);
}

Result<std::uint32_t> ByteReader::u32() {
  CF_TRY(need(4));
  std::uint32_t value = 0;
  for (unsigned i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(data_[offset_ + i]) << (i * 8);
  }
  offset_ += 4;
  return Result<std::uint32_t>::ok(value);
}

Result<std::uint64_t> ByteReader::u64() {
  CF_TRY(need(8));
  std::uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data_[offset_ + i]) << (i * 8);
  }
  offset_ += 8;
  return Result<std::uint64_t>::ok(value);
}

Result<std::int64_t> ByteReader::i64() {
  CF_TRY_ASSIGN(const std::uint64_t raw, u64());
  return Result<std::int64_t>::ok(static_cast<std::int64_t>(raw));
}

Result<std::span<const std::uint8_t>> ByteReader::fixed(std::size_t count) {
  CF_TRY(need(count));
  const std::span<const std::uint8_t> view(data_.data() + offset_, count);
  offset_ += count;
  return Result<std::span<const std::uint8_t>>::ok(view);
}

Result<std::string> ByteReader::string(std::size_t maxBytes) {
  CF_TRY_ASSIGN(const std::uint32_t declared, u32());
  const std::size_t length = declared;
  if (length > maxBytes || length > kAbsoluteMaxFieldBytes) {
    return Result<std::string>::fail(ErrorCode::OversizePayload,
                                     "declared string length exceeds the accepted bound",
                                     std::to_string(length));
  }
  CF_TRY_ASSIGN(const std::span<const std::uint8_t> view, fixed(length));
  return Result<std::string>::ok(
      std::string(reinterpret_cast<const char*>(view.data()), view.size()));
}

Result<Digest> ByteReader::digest() {
  CF_TRY_ASSIGN(const std::span<const std::uint8_t> view, fixed(kSha256Bytes));
  Sha256Digest bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = view[i];
  }
  return Result<Digest>::ok(Digest::fromBytes(bytes));
}

Result<Sha256Digest> ByteReader::sha256() {
  CF_TRY_ASSIGN(const std::span<const std::uint8_t> view, fixed(kSha256Bytes));
  Sha256Digest bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = view[i];
  }
  return Result<Sha256Digest>::ok(bytes);
}

Result<std::array<std::uint8_t, 16>> ByteReader::opaque128() {
  CF_TRY_ASSIGN(const std::span<const std::uint8_t> view, fixed(16));
  std::array<std::uint8_t, 16> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = view[i];
  }
  return Result<std::array<std::uint8_t, 16>>::ok(bytes);
}

Status ByteReader::requireEnd() const {
  if (!atEnd()) {
    return Status::fail(ErrorCode::ProtocolViolation,
                        "record carries trailing bytes after the last declared field",
                        std::to_string(remaining()));
  }
  return Status::ok();
}

Result<std::vector<std::uint8_t>> readFileBounded(const std::string& path,
                                                  std::uint64_t maxBytes) {
  std::error_code ec;
  const std::uintmax_t size = std::filesystem::file_size(path, ec);
  if (ec) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::NotFound, "cannot stat file", path);
  }
  if (size > maxBytes) {
    return Result<std::vector<std::uint8_t>>::fail(
        ErrorCode::OversizePayload, "file exceeds the accepted bound", path);
  }
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::OpenFailed, "cannot open file", path);
  }
  std::vector<std::uint8_t> content(static_cast<std::size_t>(size));
  std::size_t read = 0;
  if (size > 0) {
    read = std::fread(content.data(), 1, content.size(), file);
  }
  const bool shortRead = read != content.size();
  const bool extra = !shortRead && std::fgetc(file) != EOF;
  std::fclose(file);
  if (shortRead) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::IoFailure,
                                                   "short read while loading file", path);
  }
  if (extra) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::IoFailure,
                                                   "file grew while it was being read", path);
  }
  return Result<std::vector<std::uint8_t>>::ok(std::move(content));
}

Status flushFileToDisk(std::FILE* file) {
  if (file == nullptr) {
    return Status::fail(ErrorCode::InvalidArgument, "cannot flush a null stream");
  }
  if (std::fflush(file) != 0) {
    return Status::fail(ErrorCode::IoFailure, "failed to flush stream buffers");
  }
#if defined(_WIN32)
  if (_commit(_fileno(file)) != 0) {
    return Status::fail(ErrorCode::IoFailure, "failed to commit stream to disk");
  }
#else
  if (::fsync(fileno(file)) != 0) {
    return Status::fail(ErrorCode::IoFailure, "failed to sync stream to disk");
  }
#endif
  return Status::ok();
}

Status writeFileAtomic(const std::string& path, std::span<const std::uint8_t> content) {
  const std::string temporary = tempSiblingPath(path);
  std::FILE* file = std::fopen(temporary.c_str(), "wb");
  if (file == nullptr) {
    return Status::fail(ErrorCode::OpenFailed, "cannot create temporary file", temporary);
  }
  std::size_t written = 0;
  if (!content.empty()) {
    written = std::fwrite(content.data(), 1, content.size(), file);
  }
  const bool shortWrite = written != content.size();
  const bool flushFailed = shortWrite || !flushFileToDisk(file);
  if (shortWrite || flushFailed) {
    std::fclose(file);
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    return Status::fail(ErrorCode::IoFailure, "failed to write complete file", temporary);
  }
  std::fclose(file);

  std::error_code ec;
  std::filesystem::rename(temporary, path, ec);
  if (ec) {
    // Rename over an existing file is not universally permitted; fall back to a
    // remove-then-rename, which is still crash-safe because the temporary file
    // is complete before the target name is touched.
    std::filesystem::remove(path, ec);
    ec.clear();
    std::filesystem::rename(temporary, path, ec);
    if (ec) {
      std::error_code ignored;
      std::filesystem::remove(temporary, ignored);
      return Status::fail(ErrorCode::IoFailure, "cannot rename temporary file into place", path);
    }
  }
  return Status::ok();
}

}  // namespace cf
