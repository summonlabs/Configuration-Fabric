// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/artifact.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>

#include "cf/checked.hpp"
#include "cf/codec.hpp"
#include "cf/contract.hpp"
#include "cf/hash.hpp"
#include "cf/log.hpp"
#include "cf/rng.hpp"

namespace cf {
namespace {

constexpr std::uint32_t kMetadataMagic = 0x4D414643u;  // "CFAM" little endian
constexpr std::string_view kComponent = "artifact-store";

[[nodiscard]] std::string shardOf(const Digest& digest) {
  return digest.hex().substr(0, 2);
}

[[nodiscard]] bool isPartialFileName(const std::string& name) {
  return name.find(".part-") != std::string::npos;
}

}  // namespace

std::string renderArtifactMetadata(const ArtifactMetadata& metadata) {
  std::string out;
  out.reserve(256);
  out.append(metadata.id.str());
  out.append(" rev=");
  out.append(std::to_string(metadata.revision.value()));
  out.append(" gen-digest=");
  out.append(shortDigest(metadata.digest));
  out.append(" size=");
  out.append(std::to_string(metadata.sizeBytes));
  out.append(" schema=");
  out.append(metadata.schema.str());
  out.append(" schema-version=");
  out.append(std::to_string(metadata.schemaVersion.value()));
  out.append(" media-type=");
  out.append(metadata.mediaType.empty() ? "-" : metadata.mediaType);
  out.append(" producer=");
  out.append(metadata.producer.empty() ? "-" : metadata.producer);
  return out;
}

Result<std::vector<std::uint8_t>> encodeArtifactMetadata(const ArtifactMetadata& metadata) {
  if (metadata.id.str().size() > kMaxIdentifierLength ||
      metadata.schema.str().size() > kMaxIdentifierLength ||
      metadata.mediaType.size() > kMaxMediaTypeBytes ||
      metadata.producer.size() > kMaxProducerBytes) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::LimitExceeded,
                                                   "artifact metadata field exceeds its bound");
  }
  ByteWriter writer(512);
  writer.u32(kMetadataMagic);
  writer.u16(kArtifactMetadataFormatVersion);
  writer.string(metadata.id.str(), kMaxIdentifierLength);
  writer.u64(metadata.revision.value());
  writer.string(metadata.schema.str(), kMaxIdentifierLength);
  writer.u32(metadata.schemaVersion.value());
  writer.digest(metadata.digest);
  writer.u64(metadata.sizeBytes);
  writer.string(metadata.mediaType, kMaxMediaTypeBytes);
  writer.string(metadata.producer, kMaxProducerBytes);
  writer.i64(metadata.producedAtMillis);
  writer.i64(metadata.storedAtMillis);
  const std::uint32_t crc = crc32c(writer.span());
  writer.u32(crc);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ArtifactMetadata> decodeArtifactMetadata(std::span<const std::uint8_t> record) {
  if (record.size() < 6u) {
    return Result<ArtifactMetadata>::fail(ErrorCode::TruncatedFrame,
                                          "artifact metadata record is too short");
  }
  const std::span<const std::uint8_t> body = record.first(record.size() - 4);
  const std::span<const std::uint8_t> crcBytes = record.last(4);
  const std::uint32_t storedCrc = static_cast<std::uint32_t>(crcBytes[0]) |
                                  (static_cast<std::uint32_t>(crcBytes[1]) << 8) |
                                  (static_cast<std::uint32_t>(crcBytes[2]) << 16) |
                                  (static_cast<std::uint32_t>(crcBytes[3]) << 24);
  if (crc32c(body) != storedCrc) {
    return Result<ArtifactMetadata>::fail(ErrorCode::IntegrityFailure,
                                          "artifact metadata record failed its checksum");
  }

  ByteReader reader(body);
  CF_TRY_ASSIGN(const std::uint32_t magic, reader.u32());
  if (magic != kMetadataMagic) {
    return Result<ArtifactMetadata>::fail(ErrorCode::MalformedInput,
                                          "artifact metadata magic does not match");
  }
  CF_TRY_ASSIGN(const std::uint16_t version, reader.u16());
  if (version != kArtifactMetadataFormatVersion) {
    return Result<ArtifactMetadata>::fail(ErrorCode::UnsupportedVersion,
                                          "artifact metadata format version is not supported",
                                          std::to_string(version));
  }

  ArtifactMetadata metadata;
  CF_TRY_ASSIGN(const std::string id, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(const ArtifactId parsedId, parseArtifactId(id));
  metadata.id = parsedId;
  CF_TRY_ASSIGN(const std::uint64_t revision, reader.u64());
  metadata.revision = Revision::fromValue(revision);
  CF_TRY_ASSIGN(const std::string schema, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(const SchemaId parsedSchema, parseSchemaId(schema));
  metadata.schema = parsedSchema;
  CF_TRY_ASSIGN(const std::uint32_t schemaVersion, reader.u32());
  metadata.schemaVersion = SchemaVersion::fromValue(schemaVersion);
  CF_TRY_ASSIGN(const Digest digest, reader.digest());
  metadata.digest = digest;
  CF_TRY_ASSIGN(const std::uint64_t size, reader.u64());
  metadata.sizeBytes = size;
  CF_TRY_ASSIGN(metadata.mediaType, reader.string(kMaxMediaTypeBytes));
  CF_TRY_ASSIGN(metadata.producer, reader.string(kMaxProducerBytes));
  CF_TRY_ASSIGN(metadata.producedAtMillis, reader.i64());
  CF_TRY_ASSIGN(metadata.storedAtMillis, reader.i64());
  CF_TRY(reader.requireEnd());
  return Result<ArtifactMetadata>::ok(metadata);
}

ArtifactStore::~ArtifactStore() = default;

Result<std::unique_ptr<ArtifactStore>> ArtifactStore::open(const Options& options,
                                                           RecoveryReport& report) {
  if (options.root.empty()) {
    return Result<std::unique_ptr<ArtifactStore>>::fail(ErrorCode::InvalidArgument,
                                                        "artifact store root must not be empty");
  }
  if (options.maxArtifactBytes == 0 || options.readChunkBytes == 0) {
    return Result<std::unique_ptr<ArtifactStore>>::fail(ErrorCode::InvalidArgument,
                                                        "artifact store bounds must be non-zero");
  }
  std::error_code ec;
  std::filesystem::create_directories(options.root, ec);
  if (ec) {
    return Result<std::unique_ptr<ArtifactStore>>::fail(ErrorCode::OpenFailed,
                                                        "cannot create artifact store root",
                                                        options.root);
  }

  std::unique_ptr<ArtifactStore> store(new ArtifactStore());
  store->options_ = options;

  // Remove partial publishes. A .part file is never a valid artifact: it exists
  // only between the start of a publish and the atomic rename that completes it,
  // so a file still present at open time belongs to a crashed publish.
  for (const auto& entry : std::filesystem::recursive_directory_iterator(options.root, ec)) {
    if (ec) {
      break;
    }
    if (!entry.is_regular_file(ec)) {
      continue;
    }
    const std::string name = entry.path().filename().string();
    if (isPartialFileName(name)) {
      std::error_code removed;
      if (std::filesystem::remove(entry.path(), removed)) {
        report.removedPartialFiles += 1;
      }
    }
  }
  ec.clear();

  CF_TRY(store->loadIndex());
  report.artifactsIndexed = store->index_.size();
  report.indexedBytes = store->usedBytes_;
  if (report.removedPartialFiles > 0) {
    Logger::global().warn(kComponent,
                          "removed " + std::to_string(report.removedPartialFiles) +
                              " partial artifact publish(es) left by an interrupted store write");
  }
  return Result<std::unique_ptr<ArtifactStore>>::ok(std::move(store));
}

Status ArtifactStore::loadIndex() {
  std::error_code ec;
  std::vector<ArtifactMetadata> loaded;
  std::uint64_t total = 0;
  std::size_t unreadable = 0;
  std::filesystem::path root(options_.root);
  if (!std::filesystem::exists(root, ec)) {
    return Status::ok();
  }
  for (const auto& entry : std::filesystem::recursive_directory_iterator(root, ec)) {
    if (ec) {
      return Status::fail(ErrorCode::IoFailure, "cannot enumerate artifact store", options_.root);
    }
    if (!entry.is_regular_file(ec)) {
      continue;
    }
    if (entry.path().extension() != ".meta") {
      continue;
    }
    auto record = readFileBounded(entry.path().string(), kAbsoluteMaxFieldBytes);
    if (!record) {
      unreadable += 1;
      continue;
    }
    auto metadata = decodeArtifactMetadata(record.value());
    if (!metadata) {
      unreadable += 1;
      continue;
    }
    std::error_code sizeError;
    const std::uintmax_t payloadSize =
        std::filesystem::file_size(options_.root + "/" + "payload" + "/" +
                                       shardOf(metadata.value().digest) + "/" +
                                       metadata.value().digest.hex() + ".bin",
                                   sizeError);
    if (sizeError) {
      unreadable += 1;
      continue;
    }
    if (static_cast<std::uint64_t>(payloadSize) != metadata.value().sizeBytes) {
      // The metadata claims a size the payload does not have: the artifact is
      // not trustworthy. Index it anyway so that verify() can report it and an
      // operator can see the corruption rather than a silently missing entry.
      Logger::global().warn(kComponent,
                            "artifact payload size disagrees with metadata for " +
                                shortDigest(metadata.value().digest));
    }
    total += metadata.value().sizeBytes;
    loaded.push_back(std::move(metadata).value());
  }

  std::sort(loaded.begin(), loaded.end(),
            [](const ArtifactMetadata& lhs, const ArtifactMetadata& rhs) {
              return lhs.digest < rhs.digest;
            });
  loaded.erase(std::unique(loaded.begin(), loaded.end(),
                           [](const ArtifactMetadata& lhs, const ArtifactMetadata& rhs) {
                             return lhs.digest == rhs.digest;
                           }),
               loaded.end());

  std::lock_guard<std::mutex> guard(mutex_);
  index_ = std::move(loaded);
  usedBytes_ = total;
  if (unreadable > 0) {
    Logger::global().warn(kComponent, "ignored " + std::to_string(unreadable) +
                                          " unreadable artifact metadata record(s)");
  }
  return Status::ok();
}

std::string ArtifactStore::payloadPath(const Digest& digest) const {
  return options_.root + "/payload/" + shardOf(digest) + "/" + digest.hex() + ".bin";
}

std::string ArtifactStore::metadataPath(const Digest& digest) const {
  return options_.root + "/payload/" + shardOf(digest) + "/" + digest.hex() + ".meta";
}

Status ArtifactStore::publish(const ArtifactMetadata& metadata, const std::string& stagedPath,
                              const Digest& actualDigest, std::uint64_t actualSize) {
  const auto removeStaged = [&stagedPath] {
    std::error_code ignored;
    std::filesystem::remove(stagedPath, ignored);
  };

  const auto indexPositionOf = [this](const Digest& digest) {
    return std::lower_bound(index_.begin(), index_.end(), digest,
                            [](const ArtifactMetadata& entry, const Digest& key) {
                              return entry.digest < key;
                            });
  };

  // Budget is reserved before anything on disk changes, so a rejected publish
  // leaves the store exactly as it was.
  bool alreadyPresent = false;
  {
    std::lock_guard<std::mutex> guard(mutex_);
    const auto found = indexPositionOf(actualDigest);
    alreadyPresent = (found != index_.end() && found->digest == actualDigest);
    if (!alreadyPresent) {
      if (index_.size() >= options_.maxArtifacts) {
        removeStaged();
        return Status::fail(ErrorCode::StoreFull, "artifact count budget is exhausted",
                            std::to_string(options_.maxArtifacts));
      }
      if (actualSize > options_.maxTotalBytes ||
          usedBytes_ > options_.maxTotalBytes - actualSize) {
        removeStaged();
        return Status::fail(ErrorCode::StoreFull, "artifact byte budget is exhausted",
                            std::to_string(options_.maxTotalBytes));
      }
    }
  }

  std::error_code ec;
  const std::string directory = options_.root + "/payload/" + shardOf(actualDigest);
  std::filesystem::create_directories(directory, ec);
  if (ec) {
    removeStaged();
    return Status::fail(ErrorCode::OpenFailed, "cannot create artifact shard directory", directory);
  }

  const std::string finalPayload = payloadPath(actualDigest);
  const std::string finalMetadata = metadataPath(actualDigest);

  ArtifactMetadata stored = metadata;
  stored.digest = actualDigest;
  stored.sizeBytes = actualSize;

  auto encoded = encodeArtifactMetadata(stored);
  if (!encoded) {
    removeStaged();
    return encoded.error();
  }

  if (alreadyPresent) {
    // Content-addressed publish is idempotent, but only after the existing bytes
    // prove they still hash to the same digest.
    removeStaged();
    Status verified = verify(actualDigest);
    if (!verified) {
      return verified;
    }
    if (!std::filesystem::exists(finalMetadata, ec)) {
      // The payload survived but its metadata did not; restore it so the
      // artifact is describable again.
      Status written = writeFileAtomic(finalMetadata, encoded.value());
      if (!written) {
        return written;
      }
    }
    return Status::ok();
  }

  std::filesystem::rename(stagedPath, finalPayload, ec);
  if (ec) {
    removeStaged();
    return Status::fail(ErrorCode::IoFailure, "cannot publish artifact payload", finalPayload);
  }
  Status written = writeFileAtomic(finalMetadata, encoded.value());
  if (!written) {
    std::error_code removed;
    std::filesystem::remove(finalPayload, removed);
    return written;
  }

  std::lock_guard<std::mutex> guard(mutex_);
  const auto found = indexPositionOf(actualDigest);
  if (found != index_.end() && found->digest == actualDigest) {
    // A concurrent publish of the same content won the race; identical bytes, so
    // this is a success with no double accounting.
    return Status::ok();
  }
  index_.insert(found, stored);
  usedBytes_ += actualSize;
  return Status::ok();
}

Status ArtifactStore::ingestFromFile(const std::string& sourcePath,
                                     const ArtifactMetadata& declared) {
  std::error_code ec;
  const std::uintmax_t declaredSize = std::filesystem::file_size(sourcePath, ec);
  if (ec) {
    return Status::fail(ErrorCode::NotFound, "cannot stat artifact source", sourcePath);
  }
  if (declaredSize > options_.maxArtifactBytes) {
    return Status::fail(ErrorCode::OversizePayload, "artifact exceeds the configured maximum size",
                        std::to_string(declaredSize));
  }
  if (static_cast<std::uint64_t>(declaredSize) != declared.sizeBytes) {
    return Status::fail(ErrorCode::SizeMismatch,
                        "declared artifact size does not match the source file",
                        std::to_string(declaredSize) + " != " + std::to_string(declared.sizeBytes));
  }

  std::filesystem::create_directories(options_.root + "/payload", ec);

  std::array<std::uint8_t, 16> suffix = secureRandom128();
  const std::string temporary =
      options_.root + "/payload/.staging-" +
      toHex(std::span<const std::uint8_t>(suffix.data(), suffix.size())) + ".part";

  std::FILE* source = std::fopen(sourcePath.c_str(), "rb");
  if (source == nullptr) {
    return Status::fail(ErrorCode::OpenFailed, "cannot open artifact source", sourcePath);
  }
  std::FILE* sink = std::fopen(temporary.c_str(), "wb");
  if (sink == nullptr) {
    std::fclose(source);
    return Status::fail(ErrorCode::OpenFailed, "cannot create staging file", temporary);
  }

  Sha256 hasher;
  std::vector<std::uint8_t> buffer(static_cast<std::size_t>(options_.readChunkBytes));
  std::uint64_t total = 0;
  Status result = Status::ok();
  for (;;) {
    const std::size_t read = std::fread(buffer.data(), 1, buffer.size(), source);
    if (read == 0) {
      if (std::ferror(source) != 0) {
        result = Status::fail(ErrorCode::IoFailure, "read error while ingesting artifact",
                              sourcePath);
      }
      break;
    }
    const std::span<const std::uint8_t> chunk(buffer.data(), read);
    hasher.update(chunk);
    if (std::fwrite(chunk.data(), 1, chunk.size(), sink) != chunk.size()) {
      result = Status::fail(ErrorCode::IoFailure, "write error while staging artifact", temporary);
      break;
    }
    const auto next = checkedAdd<std::uint64_t>(total, static_cast<std::uint64_t>(read));
    if (!next) {
      result = Status::fail(ErrorCode::ArithmeticOverflow, "artifact size overflowed");
      break;
    }
    total = *next;
    if (total > options_.maxArtifactBytes) {
      result = Status::fail(ErrorCode::OversizePayload, "artifact exceeds the configured maximum",
                            std::to_string(options_.maxArtifactBytes));
      break;
    }
  }
  std::fclose(source);
  const bool flushFailed = std::fflush(sink) != 0;
  std::fclose(sink);
  if (!flushFailed && !result) {
    result = Status::fail(ErrorCode::IoFailure, "failed to flush staging file", temporary);
  }

  if (!result) {
    std::error_code removed;
    std::filesystem::remove(temporary, removed);
    return result;
  }
  if (total != declared.sizeBytes) {
    std::error_code removed;
    std::filesystem::remove(temporary, removed);
    return Status::fail(ErrorCode::SizeMismatch, "artifact byte count does not match the declaration",
                        std::to_string(total) + " != " + std::to_string(declared.sizeBytes));
  }
  const Digest actual = Digest::fromBytes(hasher.finish());
  if (actual != declared.digest) {
    std::error_code removed;
    std::filesystem::remove(temporary, removed);
    return Status::fail(ErrorCode::DigestMismatch,
                        "artifact content digest does not match the declaration",
                        actual.hex() + " != " + declared.digest.hex());
  }
  return publish(declared, temporary, actual, total);
}

Status ArtifactStore::ingestBytes(std::span<const std::uint8_t> content,
                                  const ArtifactMetadata& declared) {
  if (content.size() > options_.maxArtifactBytes) {
    return Status::fail(ErrorCode::OversizePayload, "artifact exceeds the configured maximum size");
  }
  if (content.size() != declared.sizeBytes) {
    return Status::fail(ErrorCode::SizeMismatch,
                        "declared artifact size does not match the supplied content");
  }
  const Digest actual = Digest::ofContent(content);
  if (actual != declared.digest) {
    return Status::fail(ErrorCode::DigestMismatch,
                        "artifact content digest does not match the declaration",
                        actual.hex() + " != " + declared.digest.hex());
  }
  std::error_code ec;
  std::filesystem::create_directories(options_.root + "/payload", ec);
  std::array<std::uint8_t, 16> suffix = secureRandom128();
  const std::string temporary =
      options_.root + "/payload/.staging-" +
      toHex(std::span<const std::uint8_t>(suffix.data(), suffix.size())) + ".part";
  std::FILE* file = std::fopen(temporary.c_str(), "wb");
  if (file == nullptr) {
    return Status::fail(ErrorCode::OpenFailed, "cannot create artifact staging file", temporary);
  }
  const std::size_t written =
      content.empty() ? 0 : std::fwrite(content.data(), 1, content.size(), file);
  const bool failed = written != content.size() || std::fflush(file) != 0;
  std::fclose(file);
  if (failed) {
    std::error_code removed;
    std::filesystem::remove(temporary, removed);
    return Status::fail(ErrorCode::IoFailure, "cannot stage artifact content", temporary);
  }
  return publish(declared, temporary, actual, content.size());
}

Result<ArtifactMetadata> ArtifactStore::metadata(const Digest& digest) const {
  if (!digest.isSet()) {
    return Result<ArtifactMetadata>::fail(ErrorCode::InvalidArgument,
                                          "the all-zero digest is not a valid artifact identity");
  }
  std::lock_guard<std::mutex> guard(mutex_);
  const auto found = std::lower_bound(index_.begin(), index_.end(), digest,
                                      [](const ArtifactMetadata& entry, const Digest& key) {
                                        return entry.digest < key;
                                      });
  if (found == index_.end() || !(found->digest == digest)) {
    return Result<ArtifactMetadata>::fail(ErrorCode::NotFound, "artifact is not present in the store",
                                          shortDigest(digest));
  }
  return Result<ArtifactMetadata>::ok(*found);
}

bool ArtifactStore::contains(const Digest& digest) const {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto found = std::lower_bound(index_.begin(), index_.end(), digest,
                                      [](const ArtifactMetadata& entry, const Digest& key) {
                                        return entry.digest < key;
                                      });
  return found != index_.end() && found->digest == digest;
}

void ArtifactStore::quarantine(const Digest& digest) {
  std::error_code ec;
  const std::string payload = payloadPath(digest);
  const std::string target = payload + ".corrupt";
  std::filesystem::remove(target, ec);
  ec.clear();
  std::filesystem::rename(payload, target, ec);
  if (ec) {
    Logger::global().error(kComponent, "failed to quarantine corrupt artifact " +
                                           shortDigest(digest) + ": " + ec.message());
    return;
  }
  std::lock_guard<std::mutex> guard(mutex_);
  const auto found = std::lower_bound(index_.begin(), index_.end(), digest,
                                      [](const ArtifactMetadata& entry, const Digest& key) {
                                        return entry.digest < key;
                                      });
  if (found != index_.end() && found->digest == digest) {
    usedBytes_ = (usedBytes_ > found->sizeBytes) ? (usedBytes_ - found->sizeBytes) : 0;
    index_.erase(found);
  }
}

Status ArtifactStore::verify(const Digest& digest) {
  auto opened = ArtifactReader::open(*this, digest);
  if (!opened) {
    return opened.error();
  }
  ArtifactReader& reader = *opened.value();
  std::uint64_t offset = 0;
  while (offset < reader.size()) {
    auto chunk = reader.readAt(offset, options_.readChunkBytes);
    if (!chunk) {
      return chunk.error();
    }
    if (chunk.value().empty()) {
      return Status::fail(ErrorCode::IntegrityFailure,
                          "artifact payload ended before its declared size");
    }
    offset += chunk.value().size();
  }
  if (!reader.verified()) {
    quarantine(digest);
    return Status::fail(ErrorCode::DigestMismatch,
                        "artifact content no longer matches its recorded digest",
                        shortDigest(digest));
  }
  return Status::ok();
}

std::vector<std::pair<Digest, Status>> ArtifactStore::verifyAll() {
  std::vector<ArtifactMetadata> snapshot;
  {
    std::lock_guard<std::mutex> guard(mutex_);
    snapshot = index_;
  }
  std::vector<std::pair<Digest, Status>> results;
  results.reserve(snapshot.size());
  for (const ArtifactMetadata& entry : snapshot) {
    results.emplace_back(entry.digest, verify(entry.digest));
  }
  return results;
}

Result<std::vector<ArtifactMetadata>> ArtifactStore::list() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return Result<std::vector<ArtifactMetadata>>::ok(index_);
}

std::uint64_t ArtifactStore::usedBytes() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return usedBytes_;
}

std::size_t ArtifactStore::artifactCount() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return index_.size();
}

Status ArtifactStore::collectGarbage(const std::vector<Digest>& live, std::size_t* removed) {
  std::vector<ArtifactMetadata> doomed;
  {
    std::lock_guard<std::mutex> guard(mutex_);
    for (const ArtifactMetadata& entry : index_) {
      if (std::find(live.begin(), live.end(), entry.digest) == live.end()) {
        doomed.push_back(entry);
      }
    }
  }
  for (const ArtifactMetadata& entry : doomed) {
    std::error_code ec;
    std::filesystem::remove(payloadPath(entry.digest), ec);
    ec.clear();
    std::filesystem::remove(metadataPath(entry.digest), ec);
    {
      std::lock_guard<std::mutex> guard(mutex_);
      const auto found = std::lower_bound(index_.begin(), index_.end(), entry.digest,
                                          [](const ArtifactMetadata& candidate, const Digest& key) {
                                            return candidate.digest < key;
                                          });
      if (found != index_.end() && found->digest == entry.digest) {
        usedBytes_ = (usedBytes_ > found->sizeBytes) ? (usedBytes_ - found->sizeBytes) : 0;
        index_.erase(found);
      }
    }
    if (removed != nullptr) {
      *removed += 1;
    }
  }
  return Status::ok();
}

// --- ArtifactReader --------------------------------------------------------

ArtifactReader::~ArtifactReader() {
  if (file_ != nullptr) {
    std::fclose(file_);
  }
}

Result<std::unique_ptr<ArtifactReader>> ArtifactReader::open(const ArtifactStore& store,
                                                             const Digest& digest) {
  auto metadata = store.metadata(digest);
  if (!metadata) {
    return Result<std::unique_ptr<ArtifactReader>>::fail(metadata.error());
  }
  const std::string path = store.payloadPath(digest);
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return Result<std::unique_ptr<ArtifactReader>>::fail(
        ErrorCode::ArtifactUnavailable, "artifact payload file is missing", path);
  }
  std::unique_ptr<ArtifactReader> reader(new ArtifactReader());
  reader->file_ = file;
  reader->size_ = metadata.value().sizeBytes;
  reader->expected_ = digest;
  return Result<std::unique_ptr<ArtifactReader>>::ok(std::move(reader));
}

Result<std::vector<std::uint8_t>> ArtifactReader::readAt(std::uint64_t offset, std::size_t length) {
  if (file_ == nullptr) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::Internal,
                                                   "artifact reader is not open");
  }
  if (offset > size_) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::OutOfRange,
                                                   "artifact read offset is past the end of the payload");
  }
  const std::uint64_t remaining = size_ - offset;
  const std::uint64_t wanted = std::min<std::uint64_t>(remaining, static_cast<std::uint64_t>(length));
#if defined(_WIN32)
  if (_fseeki64(file_, static_cast<__int64>(offset), SEEK_SET) != 0) {
#else
  if (fseeko(file_, static_cast<off_t>(offset), SEEK_SET) != 0) {
#endif
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::IoFailure,
                                                   "cannot seek within artifact payload");
  }
  std::vector<std::uint8_t> chunk(static_cast<std::size_t>(wanted));
  std::size_t read = 0;
  if (wanted > 0) {
    read = std::fread(chunk.data(), 1, chunk.size(), file_);
  }
  if (read != chunk.size()) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::IntegrityFailure,
                                                   "artifact payload is shorter than its metadata",
                                                   shortDigest(expected_));
  }
  chunk.resize(read);
  if (offset == bytesRead_) {
    // Sequential consumption is the only path that can verify the digest.
    hasher_.update(std::span<const std::uint8_t>(chunk.data(), chunk.size()));
    bytesRead_ += read;
    if (bytesRead_ == size_) {
      const Digest actual = Digest::fromBytes(hasher_.finish());
      if (!(actual == expected_)) {
        verified_ = false;
        return Result<std::vector<std::uint8_t>>::fail(
            ErrorCode::DigestMismatch, "artifact payload does not match its digest",
            actual.hex() + " != " + expected_.hex());
      }
      verified_ = true;
    }
  } else {
    // Random access invalidates the sequential hash: the caller must not claim
    // verification for a payload it did not read in order.
    bytesRead_ = offset + read;
    if (bytesRead_ != size_) {
      verified_ = false;
    }
  }
  return Result<std::vector<std::uint8_t>>::ok(std::move(chunk));
}

}  // namespace cf
