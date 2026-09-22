// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Immutable configuration artifacts.
//
// An artifact is the bytes produced by an upstream intent system for one
// configuration identity at one revision. Configuration Fabric never edits,
// merges or interprets those bytes: it stores them, proves their digest, and
// distributes them.
//
// Storage is content addressed and append-only. Publishing an artifact whose
// digest already exists in the store is an idempotent success after the existing
// bytes are re-verified; the store never overwrites a published artifact.

#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "cf/digest.hpp"
#include "cf/ids.hpp"
#include "cf/result.hpp"

namespace cf {

inline constexpr std::uint16_t kArtifactMetadataFormatVersion = 1;

/// Everything Configuration Fabric knows about one artifact besides its bytes.
struct ArtifactMetadata {
  ArtifactId id;
  Revision revision;
  SchemaId schema;
  SchemaVersion schemaVersion;
  Digest digest;
  std::uint64_t sizeBytes{0};
  std::string mediaType;
  std::string producer;
  std::int64_t producedAtMillis{0};
  std::int64_t storedAtMillis{0};

  friend bool operator==(const ArtifactMetadata&, const ArtifactMetadata&) noexcept = default;
};

/// Stable, human-readable one-line rendering used by reports and the CLI.
[[nodiscard]] std::string renderArtifactMetadata(const ArtifactMetadata& metadata);

class ArtifactStore;

/// Sequential chunked reader over one stored artifact. The reader verifies the
/// whole-artifact digest when the last byte has been handed out; a caller that
/// abandons the reader gets no verification claim.
class ArtifactReader final {
 public:
  ArtifactReader(const ArtifactReader&) = delete;
  ArtifactReader& operator=(const ArtifactReader&) = delete;
  ~ArtifactReader();

  [[nodiscard]] static Result<std::unique_ptr<ArtifactReader>> open(const ArtifactStore& store,
                                                                   const Digest& digest);

  /// Reads up to length bytes at offset. Returns fewer bytes only at the end.
  [[nodiscard]] Result<std::vector<std::uint8_t>> readAt(std::uint64_t offset,
                                                        std::size_t length);
  [[nodiscard]] std::uint64_t size() const noexcept { return size_; }
  [[nodiscard]] std::uint64_t bytesRead() const noexcept { return bytesRead_; }
  /// True once every byte has been delivered and the recomputed digest matched.
  [[nodiscard]] bool verified() const noexcept { return verified_; }

 private:
  ArtifactReader() = default;

  std::FILE* file_{nullptr};
  Sha256 hasher_;
  std::uint64_t size_{0};
  std::uint64_t bytesRead_{0};
  Digest expected_;
  bool verified_{false};
};

class ArtifactStore final {
 public:
  struct Options {
    /// Root directory; created when absent. All state lives below it.
    std::string root;
    /// Largest artifact this store will accept. Checked before allocation.
    std::uint64_t maxArtifactBytes = 64ull * 1024ull * 1024ull;
    /// Total on-disk artifact payload budget. Publishing beyond it fails with
    /// StoreFull rather than filling the volume.
    std::uint64_t maxTotalBytes = 4ull * 1024ull * 1024ull * 1024ull;
    /// Maximum number of distinct artifacts.
    std::size_t maxArtifacts = 4096;
    /// Chunk size used by readers.
    std::size_t readChunkBytes = 64u * 1024u;
  };

  struct RecoveryReport {
    std::size_t removedPartialFiles{0};
    std::size_t unreadableMetadataFiles{0};
    std::size_t artifactsIndexed{0};
    std::uint64_t indexedBytes{0};
  };

  ArtifactStore(const ArtifactStore&) = delete;
  ArtifactStore& operator=(const ArtifactStore&) = delete;
  ~ArtifactStore();

  [[nodiscard]] static Result<std::unique_ptr<ArtifactStore>> open(const Options& options,
                                                                  RecoveryReport& report);

  /// Streams sourcePath into the store while hashing. The declared digest and
  /// size must match the actual content exactly, otherwise the temporary file is
  /// discarded and the store is unchanged.
  [[nodiscard]] Status ingestFromFile(const std::string& sourcePath,
                                      const ArtifactMetadata& declared);

  /// Stores an in-memory artifact. Used by tests and by small control payloads.
  [[nodiscard]] Status ingestBytes(std::span<const std::uint8_t> content,
                                   const ArtifactMetadata& declared);

  [[nodiscard]] Result<ArtifactMetadata> metadata(const Digest& digest) const;
  [[nodiscard]] bool contains(const Digest& digest) const;
  /// Recomputes the digest of the stored bytes and compares it against the
  /// metadata. Returns DigestMismatch and quarantines the artifact on failure.
  [[nodiscard]] Status verify(const Digest& digest);
  /// Verifies every indexed artifact. Reports each failure individually.
  [[nodiscard]] std::vector<std::pair<Digest, Status>> verifyAll();
  /// Sorted by digest, so the rendering is deterministic.
  [[nodiscard]] Result<std::vector<ArtifactMetadata>> list() const;

  [[nodiscard]] std::uint64_t usedBytes() const;
  [[nodiscard]] std::size_t artifactCount() const;
  [[nodiscard]] std::uint64_t maxArtifactBytes() const noexcept { return options_.maxArtifactBytes; }
  [[nodiscard]] std::size_t readChunkBytes() const noexcept { return options_.readChunkBytes; }

  /// Removes artifacts whose digest is not in live. Bounded cleanup for stores
  /// that would otherwise grow without limit.
  [[nodiscard]] Status collectGarbage(const std::vector<Digest>& live, std::size_t* removed);

  [[nodiscard]] std::string payloadPath(const Digest& digest) const;
  [[nodiscard]] std::string metadataPath(const Digest& digest) const;

 private:
  ArtifactStore() = default;

  [[nodiscard]] Status publish(const ArtifactMetadata& metadata, const std::string& alreadyHashedPath,
                               const Digest& actualDigest, std::uint64_t actualSize);
  [[nodiscard]] Status loadIndex();
  void quarantine(const Digest& digest);

  Options options_;
  mutable std::mutex mutex_;
  std::vector<ArtifactMetadata> index_;  // sorted by digest
  std::uint64_t usedBytes_{0};
};

/// Encodes/decodes a metadata record. The encoding is versioned and covered by a
/// CRC32C, so a truncated or corrupted metadata file fails to load instead of
/// producing plausible-looking nonsense.
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeArtifactMetadata(
    const ArtifactMetadata& metadata);
[[nodiscard]] Result<ArtifactMetadata> decodeArtifactMetadata(
    std::span<const std::uint8_t> record);

}  // namespace cf
