// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/journal.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>

#include "cf/checked.hpp"
#include "cf/codec.hpp"
#include "cf/contract.hpp"
#include "cf/hash.hpp"
#include "cf/log.hpp"

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace cf {
namespace {

constexpr std::string_view kComponent = "journal";

void storeLe16(std::uint8_t* out, std::uint16_t value) noexcept {
  out[0] = static_cast<std::uint8_t>(value & 0xFFu);
  out[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}

void storeLe32(std::uint8_t* out, std::uint32_t value) noexcept {
  for (unsigned i = 0; i < 4; ++i) {
    out[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu);
  }
}

void storeLe64(std::uint8_t* out, std::uint64_t value) noexcept {
  for (unsigned i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu);
  }
}

[[nodiscard]] std::uint16_t loadLe16(const std::uint8_t* in) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(in[0]) |
                                    static_cast<std::uint16_t>(static_cast<std::uint16_t>(in[1])
                                                               << 8));
}

[[nodiscard]] std::uint32_t loadLe32(const std::uint8_t* in) noexcept {
  return static_cast<std::uint32_t>(in[0]) | (static_cast<std::uint32_t>(in[1]) << 8) |
         (static_cast<std::uint32_t>(in[2]) << 16) | (static_cast<std::uint32_t>(in[3]) << 24);
}

[[nodiscard]] std::uint64_t loadLe64(const std::uint8_t* in) noexcept {
  std::uint64_t value = 0;
  for (unsigned i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(in[i]) << (i * 8);
  }
  return value;
}

/// Reads exactly count bytes. Returns false when the stream ends early.
[[nodiscard]] bool readExact(std::FILE* file, std::uint8_t* out, std::size_t count) {
  if (count == 0) {
    return true;
  }
  return std::fread(out, 1, count, file) == count;
}

[[nodiscard]] std::vector<std::uint8_t> journalHeaderBytes() {
  std::vector<std::uint8_t> header(kJournalHeaderBytes, 0);
  storeLe32(header.data(), kJournalMagic);
  storeLe16(header.data() + 4, kJournalFormatVersion);
  storeLe16(header.data() + 6, 0);
  const std::uint32_t crc = crc32c(std::span<const std::uint8_t>(header.data(), 8));
  storeLe32(header.data() + 8, crc);
  return header;
}

/// Validates a journal header. Returns the failure reason through the result.
[[nodiscard]] Status validateJournalHeader(std::span<const std::uint8_t> bytes) {
  if (bytes.size() < kJournalHeaderBytes) {
    return Status::fail(ErrorCode::TruncatedFrame, "journal header is incomplete");
  }
  if (loadLe32(bytes.data()) != kJournalMagic) {
    return Status::fail(ErrorCode::MalformedInput, "file is not a configuration-fabric journal");
  }
  if (crc32c(bytes.first(8)) != loadLe32(bytes.data() + 8)) {
    return Status::fail(ErrorCode::IntegrityFailure, "journal header checksum does not match");
  }
  const std::uint16_t version = loadLe16(bytes.data() + 4);
  if (version != kJournalFormatVersion) {
    return Status::fail(ErrorCode::UnsupportedVersion,
                        "journal format version is not supported", std::to_string(version));
  }
  if (loadLe16(bytes.data() + 6) != 0) {
    return Status::fail(ErrorCode::ProtocolViolation, "journal header reserved field is not zero");
  }
  return Status::ok();
}

[[nodiscard]] std::uint32_t recordChecksum(JournalRecordType type, Sequence sequence,
                                           std::span<const std::uint8_t> payload) {
  Crc32c crc;
  std::array<std::uint8_t, 12> prefix{};
  storeLe32(prefix.data(), static_cast<std::uint32_t>(type));
  storeLe64(prefix.data() + 4, sequence.value());
  crc.update(std::span<const std::uint8_t>(prefix.data(), prefix.size()));
  crc.update(payload);
  return crc.value();
}

[[nodiscard]] bool isKnownRecordType(std::uint32_t raw) noexcept {
  switch (static_cast<JournalRecordType>(raw)) {
    case JournalRecordType::SegmentStart:
    case JournalRecordType::ControllerIdentity:
    case JournalRecordType::ControllerEpoch:
    case JournalRecordType::TargetUpsert:
    case JournalRecordType::TargetRemove:
    case JournalRecordType::DeliveryUpsert:
    case JournalRecordType::DeliveryRemove:
    case JournalRecordType::ArtifactUpsert:
    case JournalRecordType::ArtifactRemove:
    case JournalRecordType::DeploymentSetNote:
    case JournalRecordType::AgentIdentity:
    case JournalRecordType::AgentTargetCommit:
    case JournalRecordType::AgentTransferUpsert:
    case JournalRecordType::AgentTransferRemove:
    case JournalRecordType::AgentFindingUpsert:
    case JournalRecordType::AgentApplyPrepared:
    case JournalRecordType::AgentApplyResolved:
    case JournalRecordType::AgentControllerFence:
    case JournalRecordType::AgentRollbackNote:
    case JournalRecordType::Note:
      return true;
    case JournalRecordType::Invalid:
      return false;
  }
  return false;
}

}  // namespace

std::string_view journalRecordTypeName(JournalRecordType type) noexcept {
  switch (type) {
    case JournalRecordType::Invalid:
      return "invalid";
    case JournalRecordType::SegmentStart:
      return "segment-start";
    case JournalRecordType::ControllerIdentity:
      return "controller-identity";
    case JournalRecordType::ControllerEpoch:
      return "controller-epoch";
    case JournalRecordType::TargetUpsert:
      return "target-upsert";
    case JournalRecordType::TargetRemove:
      return "target-remove";
    case JournalRecordType::DeliveryUpsert:
      return "delivery-upsert";
    case JournalRecordType::DeliveryRemove:
      return "delivery-remove";
    case JournalRecordType::ArtifactUpsert:
      return "artifact-upsert";
    case JournalRecordType::ArtifactRemove:
      return "artifact-remove";
    case JournalRecordType::DeploymentSetNote:
      return "deployment-set-note";
    case JournalRecordType::AgentIdentity:
      return "agent-identity";
    case JournalRecordType::AgentTargetCommit:
      return "agent-target-commit";
    case JournalRecordType::AgentTransferUpsert:
      return "agent-transfer-upsert";
    case JournalRecordType::AgentTransferRemove:
      return "agent-transfer-remove";
    case JournalRecordType::AgentFindingUpsert:
      return "agent-finding-upsert";
    case JournalRecordType::AgentApplyPrepared:
      return "agent-apply-prepared";
    case JournalRecordType::AgentApplyResolved:
      return "agent-apply-resolved";
    case JournalRecordType::AgentControllerFence:
      return "agent-controller-fence";
    case JournalRecordType::AgentRollbackNote:
      return "agent-rollback-note";
    case JournalRecordType::Note:
      return "note";
  }
  return "unknown";
}

bool parseJournalRecordType(std::string_view text, JournalRecordType& out) noexcept {
  for (std::uint32_t raw = 1; raw <= 90; ++raw) {
    const auto type = static_cast<JournalRecordType>(raw);
    if (!isKnownRecordType(raw)) {
      continue;
    }
    if (journalRecordTypeName(type) == text) {
      out = type;
      return true;
    }
  }
  return false;
}

std::string JournalRecovery::render() const {
  std::string out;
  out.reserve(160);
  switch (outcome) {
    case Outcome::Created:
      out.append("created");
      break;
    case Outcome::Clean:
      out.append("clean");
      break;
    case Outcome::TruncatedTail:
      out.append("truncated-tail");
      break;
    case Outcome::Corrupted:
      out.append("corrupted");
      break;
    case Outcome::NotAJournal:
      out.append("not-a-journal");
      break;
    case Outcome::UnsupportedVersion:
      out.append("unsupported-version");
      break;
  }
  out.append(" records=");
  out.append(std::to_string(recordsRecovered));
  out.append(" last-sequence=");
  out.append(std::to_string(lastSequence.value()));
  if (discardedBytes > 0) {
    out.append(" discarded-bytes=");
    out.append(std::to_string(discardedBytes));
  }
  if (!detail.empty()) {
    out.append(" detail=");
    out.append(detail);
  }
  return out;
}

Journal::~Journal() {
  if (file_ != nullptr) {
    std::fflush(file_);
    std::fclose(file_);
  }
}

Result<std::unique_ptr<Journal>> Journal::open(const Options& options, JournalRecovery& recovery) {
  if (options.path.empty()) {
    return Result<std::unique_ptr<Journal>>::fail(ErrorCode::InvalidArgument,
                                                  "journal path must not be empty");
  }
  if (options.maxRecordBytes == 0 || options.maxRecordBytes > kMaxJournalRecordBytes) {
    return Result<std::unique_ptr<Journal>>::fail(ErrorCode::InvalidArgument,
                                                  "journal record bound is outside the accepted range");
  }

  std::unique_ptr<Journal> journal(new Journal());
  journal->options_ = options;
  journal->durableFlush_ = options.durable;

  std::error_code ec;
  const bool existed = std::filesystem::exists(options.path, ec);
  if (!existed) {
    std::filesystem::path parent = std::filesystem::path(options.path).parent_path();
    if (!parent.empty()) {
      std::filesystem::create_directories(parent, ec);
      if (ec) {
        return Result<std::unique_ptr<Journal>>::fail(ErrorCode::OpenFailed,
                                                      "cannot create journal directory",
                                                      parent.string());
      }
    }
    journal->file_ = std::fopen(options.path.c_str(), "w+b");
    if (journal->file_ == nullptr) {
      return Result<std::unique_ptr<Journal>>::fail(ErrorCode::OpenFailed, "cannot create journal",
                                                    options.path);
    }
    const std::vector<std::uint8_t> header = journalHeaderBytes();
    if (std::fwrite(header.data(), 1, header.size(), journal->file_) != header.size()) {
      return Result<std::unique_ptr<Journal>>::fail(ErrorCode::IoFailure,
                                                    "cannot write journal header", options.path);
    }
    CF_TRY(flushFileToDisk(journal->file_));
    CF_TRY(journal->restartSegment(Sequence::fromValue(1)));
    recovery.outcome = JournalRecovery::Outcome::Created;
    recovery.lastSequence = Sequence::fromValue(1);
    recovery.recordsRecovered = 1;
    return Result<std::unique_ptr<Journal>>::ok(std::move(journal));
  }

  const Status scanned = journal->scanInto(nullptr, recovery, true);
  if (!scanned) {
    return Result<std::unique_ptr<Journal>>::fail(recovery.fatal() ? ErrorCode::IntegrityFailure
                                                                   : ErrorCode::IoFailure,
                                                  "journal recovery failed", recovery.render());
  }
  journal->file_ = std::fopen(options.path.c_str(), "r+b");
  if (journal->file_ == nullptr) {
    return Result<std::unique_ptr<Journal>>::fail(ErrorCode::OpenFailed, "cannot open journal",
                                                  options.path);
  }
  if (std::fseek(journal->file_, 0, SEEK_END) != 0) {
    return Result<std::unique_ptr<Journal>>::fail(ErrorCode::IoFailure,
                                                  "cannot seek to the end of the journal",
                                                  options.path);
  }
  return Result<std::unique_ptr<Journal>>::ok(std::move(journal));
}

Status Journal::scanInto(std::vector<JournalRecord>* records, JournalRecovery& recovery,
                         bool truncateTornTail) {
  recovery = JournalRecovery{};
  std::FILE* file = std::fopen(options_.path.c_str(), "r+b");
  if (file == nullptr) {
    recovery.outcome = JournalRecovery::Outcome::NotAJournal;
    recovery.detail = "cannot open journal file";
    return Status::fail(ErrorCode::OpenFailed, "cannot open journal file", options_.path);
  }

  std::error_code ec;
  const std::uintmax_t fileSize = std::filesystem::file_size(options_.path, ec);
  if (ec) {
    std::fclose(file);
    recovery.outcome = JournalRecovery::Outcome::NotAJournal;
    return Status::fail(ErrorCode::IoFailure, "cannot size journal file", options_.path);
  }

  std::array<std::uint8_t, kJournalHeaderBytes> header{};
  if (!readExact(file, header.data(), header.size())) {
    std::fclose(file);
    recovery.outcome = JournalRecovery::Outcome::NotAJournal;
    recovery.detail = "journal header is incomplete";
    return Status::fail(ErrorCode::TruncatedFrame, "journal header is incomplete");
  }
  const Status headerStatus = validateJournalHeader(header);
  if (!headerStatus) {
    std::fclose(file);
    recovery.outcome = headerStatus.code() == ErrorCode::UnsupportedVersion
                           ? JournalRecovery::Outcome::UnsupportedVersion
                           : JournalRecovery::Outcome::NotAJournal;
    recovery.detail = headerStatus.str();
    return headerStatus;
  }

  std::uint64_t offset = kJournalHeaderBytes;
  std::uint64_t lastGoodOffset = kJournalHeaderBytes;
  bool haveSequence = false;
  Sequence expected;

  std::array<std::uint8_t, kJournalRecordHeaderBytes> recordHeader{};
  std::vector<std::uint8_t> payload;
  for (;;) {
    if (!readExact(file, recordHeader.data(), recordHeader.size())) {
      // Clean end of file, or a torn record header: both are a discarded tail.
      if (offset != fileSize) {
        recovery.discardedBytes = fileSize - lastGoodOffset;
        recovery.outcome = JournalRecovery::Outcome::TruncatedTail;
        recovery.detail = "torn record header at the end of the journal was discarded";
        break;
      }
      if (recovery.outcome != JournalRecovery::Outcome::TruncatedTail) {
        recovery.outcome = JournalRecovery::Outcome::Clean;
      }
      break;
    }
    const std::uint32_t payloadLength = loadLe32(recordHeader.data());
    const std::uint32_t rawType = loadLe32(recordHeader.data() + 4);
    const std::uint32_t storedCrc = loadLe32(recordHeader.data() + 8);
    const std::uint64_t rawSequence = loadLe64(recordHeader.data() + 12);

    const bool headerPlausible =
        payloadLength <= options_.maxRecordBytes && isKnownRecordType(rawType) && rawSequence > 0;
    auto failMidFile = [&](std::string detail) -> Status {
      // Decide between a torn tail and mid-file corruption: a valid-looking
      // record header appearing after the damage proves the damage is not simply
      // the end of a partially written append.
      recovery.outcome = JournalRecovery::Outcome::Corrupted;
      recovery.detail = std::move(detail);
      return Status::fail(ErrorCode::IntegrityFailure, "journal is corrupted", recovery.detail);
    };

    if (!headerPlausible) {
      std::fclose(file);
      return failMidFile("record header at offset " + std::to_string(offset) +
                         " is not a valid record");
    }
    if (payloadLength > 0) {
      payload.assign(payloadLength, 0);
      if (!readExact(file, payload.data(), payload.size())) {
        std::fclose(file);
        recovery.discardedBytes = fileSize - lastGoodOffset;
        recovery.outcome = JournalRecovery::Outcome::TruncatedTail;
        recovery.detail = "torn record payload at the end of the journal was discarded";
        break;
      }
    } else {
      payload.clear();
    }

    const auto type = static_cast<JournalRecordType>(rawType);
    const Sequence sequence = Sequence::fromValue(rawSequence);
    if (recordChecksum(type, sequence, payload) != storedCrc) {
      std::fclose(file);
      return failMidFile("record at offset " + std::to_string(offset) +
                         " failed its checksum");
    }
    if (haveSequence) {
      const auto expectedNext = checkedAdd<std::uint64_t>(expected.value(), 1u);
      if (!expectedNext || sequence.value() != *expectedNext) {
        std::fclose(file);
        return failMidFile("record sequence " + std::to_string(sequence.value()) +
                           " does not follow " + std::to_string(expected.value()));
      }
    }
    haveSequence = true;
    expected = sequence;

    if (records != nullptr) {
      JournalRecord record;
      record.type = type;
      record.sequence = sequence;
      record.payload = payload;
      records->push_back(std::move(record));
    }
    recovery.recordsRecovered += 1;
    recovery.lastSequence = sequence;
    offset += kJournalRecordHeaderBytes + payloadLength;
    lastGoodOffset = offset;
  }

  // A container type that this build cannot interpret must not be skipped: the
  // remaining state would be silently misread.
  if (records != nullptr) {
    for (const JournalRecord& record : *records) {
      if (!isKnownRecordType(static_cast<std::uint32_t>(record.type))) {
        std::fclose(file);
        recovery.outcome = JournalRecovery::Outcome::UnsupportedVersion;
        recovery.detail = "journal contains a record type this build does not understand";
        return Status::fail(ErrorCode::UnsupportedVersion, recovery.detail);
      }
    }
  }

  if (truncateTornTail && recovery.outcome == JournalRecovery::Outcome::TruncatedTail) {
    std::fflush(file);
    ec.clear();
    std::filesystem::resize_file(options_.path, lastGoodOffset, ec);
    if (ec) {
      std::fclose(file);
      recovery.outcome = JournalRecovery::Outcome::Corrupted;
      recovery.detail = "cannot truncate a torn tail from the journal: " + ec.message();
      return Status::fail(ErrorCode::IoFailure, recovery.detail);
    }
    Logger::global().warn(kComponent,
                          "discarded " + std::to_string(recovery.discardedBytes) +
                              " byte(s) of torn tail from " + options_.path);
  }
  std::fclose(file);
  return Status::ok();
}

Result<std::vector<JournalRecord>> Journal::readFile(const std::string& path,
                                                     JournalRecovery& recovery) {
  Options options;
  options.path = path;
  Journal reader;
  reader.options_ = options;
  std::vector<JournalRecord> records;
  const Status status = reader.scanInto(&records, recovery, false);
  if (!status) {
    return Result<std::vector<JournalRecord>>::fail(status.error());
  }
  return Result<std::vector<JournalRecord>>::ok(std::move(records));
}

Status Journal::rewriteHeader() {
  if (std::fseek(file_, 0, SEEK_SET) != 0) {
    return Status::fail(ErrorCode::IoFailure, "cannot seek to the journal header");
  }
  const std::vector<std::uint8_t> header = journalHeaderBytes();
  if (std::fwrite(header.data(), 1, header.size(), file_) != header.size()) {
    return Status::fail(ErrorCode::IoFailure, "cannot rewrite the journal header");
  }
  return Status::ok();
}

Status Journal::writeRecord(JournalRecordType type, std::span<const std::uint8_t> payload,
                            Sequence sequence) {
  std::array<std::uint8_t, kJournalRecordHeaderBytes> header{};
  storeLe32(header.data(), static_cast<std::uint32_t>(payload.size()));
  storeLe32(header.data() + 4, static_cast<std::uint32_t>(type));
  storeLe32(header.data() + 8, recordChecksum(type, sequence, payload));
  storeLe64(header.data() + 12, sequence.value());
  if (std::fwrite(header.data(), 1, header.size(), file_) != header.size()) {
    return Status::fail(ErrorCode::IoFailure, "cannot append a journal record header");
  }
  if (!payload.empty() &&
      std::fwrite(payload.data(), 1, payload.size(), file_) != payload.size()) {
    return Status::fail(ErrorCode::IoFailure, "cannot append a journal record payload");
  }
  if (durableFlush_) {
    CF_TRY(flushFileToDisk(file_));
  } else if (std::fflush(file_) != 0) {
    return Status::fail(ErrorCode::IoFailure, "cannot flush the journal stream");
  }
  return Status::ok();
}

Status Journal::append(JournalRecordType type, std::span<const std::uint8_t> payload,
                       Sequence* assignedSequence) {
  if (!isKnownRecordType(static_cast<std::uint32_t>(type))) {
    return Status::fail(ErrorCode::InvalidArgument, "cannot append an undefined record type");
  }
  if (payload.size() > options_.maxRecordBytes) {
    return Status::fail(ErrorCode::OversizePayload, "record exceeds the journal record bound",
                        std::to_string(payload.size()));
  }
  const auto next = checkedAdd<std::uint64_t>(lastSequence_.value(), 1u);
  if (!next) {
    return Status::fail(ErrorCode::ArithmeticOverflow, "journal sequence exhausted");
  }
  const Sequence sequence = Sequence::fromValue(*next);
  CF_TRY(writeRecord(type, payload, sequence));
  lastSequence_ = sequence;
  recordCount_ += 1;
  if (assignedSequence != nullptr) {
    *assignedSequence = sequence;
  }
  return Status::ok();
}

Status Journal::restartSegment(Sequence baseSequence) {
  if (baseSequence.value() == 0) {
    return Status::fail(ErrorCode::InvalidArgument, "journal base sequence must be non-zero");
  }
  if (file_ == nullptr) {
    return Status::fail(ErrorCode::ConnectionClosed, "journal is not open");
  }
  if (std::fflush(file_) != 0) {
    return Status::fail(ErrorCode::IoFailure, "cannot flush the journal before restarting");
  }
  CF_TRY(rewriteHeader());
  // Truncate to the header: the previous segment is superseded by a snapshot.
  std::error_code ec;
  if (std::fseek(file_, static_cast<long>(kJournalHeaderBytes), SEEK_SET) != 0) {
    return Status::fail(ErrorCode::IoFailure, "cannot seek in the journal");
  }
  if (std::fflush(file_) != 0) {
    return Status::fail(ErrorCode::IoFailure, "cannot flush the journal stream");
  }
#if defined(_WIN32)
  if (_chsize_s(_fileno(file_), static_cast<long long>(kJournalHeaderBytes)) != 0) {
    return Status::fail(ErrorCode::IoFailure, "cannot truncate the journal");
  }
#else
  if (ftruncate(fileno(file_), static_cast<off_t>(kJournalHeaderBytes)) != 0) {
    return Status::fail(ErrorCode::IoFailure, "cannot truncate the journal");
  }
#endif
  if (std::fseek(file_, 0, SEEK_END) != 0) {
    return Status::fail(ErrorCode::IoFailure, "cannot seek to the end of the journal");
  }
  (void)ec;

  std::array<std::uint8_t, 8> base{};
  storeLe64(base.data(), baseSequence.value());
  const Sequence previous = lastSequence_;
  lastSequence_ = Sequence::fromValue(baseSequence.value() - 1);
  const Status appended =
      writeRecord(JournalRecordType::SegmentStart,
                  std::span<const std::uint8_t>(base.data(), base.size()), baseSequence);
  if (!appended) {
    lastSequence_ = previous;
    return appended;
  }
  lastSequence_ = baseSequence;
  recordCount_ = 1;
  return Status::ok();
}

std::uint64_t Journal::sizeBytes() const {
  if (file_ == nullptr) {
    return 0;
  }
  std::error_code ec;
  const std::uintmax_t size = std::filesystem::file_size(options_.path, ec);
  return ec ? 0 : static_cast<std::uint64_t>(size);
}

// --- SnapshotFile ----------------------------------------------------------

namespace {

[[nodiscard]] std::string slotPath(const SnapshotFile::Options& options, char slot) {
  return options.path + "." + std::string(1, slot);
}

}  // namespace

Status SnapshotFile::write(const Options& options, Sequence coveredSequence,
                           std::span<const std::uint8_t> payload, char* slotUsed) {
  if (options.path.empty()) {
    return Status::fail(ErrorCode::InvalidArgument, "snapshot path must not be empty");
  }
  if (payload.size() > options.maxBytes) {
    return Status::fail(ErrorCode::OversizePayload, "snapshot exceeds the configured maximum");
  }

  // Write into the slot that does not hold the newest valid snapshot, so a torn
  // write can never destroy the last good state.
  char target = 'a';
  std::string detail;
  auto current = SnapshotFile::load(options, &detail);
  if (current && current.value().slot == 'a') {
    target = 'b';
  }

  std::vector<std::uint8_t> record(kSnapshotHeaderBytes + payload.size(), 0);
  storeLe32(record.data(), kSnapshotMagic);
  storeLe16(record.data() + 4, kSnapshotFormatVersion);
  storeLe16(record.data() + 6, 0);
  storeLe64(record.data() + 8, coveredSequence.value());
  storeLe32(record.data() + 16, static_cast<std::uint32_t>(payload.size()));
  storeLe32(record.data() + 20, payload.empty() ? 0u : crc32c(payload));
  storeLe32(record.data() + 24,
            crc32c(std::span<const std::uint8_t>(record.data(), kSnapshotHeaderBytes - 4)));
  if (!payload.empty()) {
    std::memcpy(record.data() + kSnapshotHeaderBytes, payload.data(), payload.size());
  }

  const Status written = writeFileAtomic(slotPath(options, target), record);
  if (!written) {
    return written;
  }
  if (slotUsed != nullptr) {
    *slotUsed = target;
  }
  return Status::ok();
}

Result<SnapshotFile::Loaded> SnapshotFile::load(const Options& options, std::string* detail) {
  Loaded best;
  bool found = false;
  std::string notes;
  for (const char slot : {'a', 'b'}) {
    const std::string path = slotPath(options, slot);
    auto bytes = readFileBounded(path, options.maxBytes + kSnapshotHeaderBytes);
    if (!bytes) {
      continue;
    }
    const std::span<const std::uint8_t> record(bytes.value());
    if (record.size() < kSnapshotHeaderBytes) {
      notes.append(" slot ");
      notes.push_back(slot);
      notes.append("=short");
      continue;
    }
    if (loadLe32(record.data()) != kSnapshotMagic) {
      notes.append(" slot ");
      notes.push_back(slot);
      notes.append("=magic");
      continue;
    }
    if (loadLe16(record.data() + 4) != kSnapshotFormatVersion) {
      notes.append(" slot ");
      notes.push_back(slot);
      notes.append("=version");
      continue;
    }
    if (crc32c(record.first(kSnapshotHeaderBytes - 4)) !=
        loadLe32(record.data() + kSnapshotHeaderBytes - 4)) {
      notes.append(" slot ");
      notes.push_back(slot);
      notes.append("=header-crc");
      continue;
    }
    const std::uint32_t payloadLength = loadLe32(record.data() + 16);
    const std::uint32_t payloadCrc = loadLe32(record.data() + 20);
    if (payloadLength > options.maxBytes) {
      notes.append(" slot ");
      notes.push_back(slot);
      notes.append("=oversize");
      continue;
    }
    if (record.size() != kSnapshotHeaderBytes + payloadLength) {
      notes.append(" slot ");
      notes.push_back(slot);
      notes.append("=length");
      continue;
    }
    const std::span<const std::uint8_t> payload = record.subspan(kSnapshotHeaderBytes);
    if (crc32c(payload) != payloadCrc) {
      notes.append(" slot ");
      notes.push_back(slot);
      notes.append("=payload-crc");
      continue;
    }
    const Sequence covered = Sequence::fromValue(loadLe64(record.data() + 8));
    if (!found || covered > best.coveredSequence) {
      best.coveredSequence = covered;
      best.payload.assign(payload.begin(), payload.end());
      best.slot = slot;
      found = true;
    }
  }
  if (detail != nullptr) {
    *detail = notes;
  }
  if (!found) {
    return Result<Loaded>::fail(ErrorCode::NotFound, "no valid snapshot is present");
  }
  return Result<Loaded>::ok(std::move(best));
}

}  // namespace cf
