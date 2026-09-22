// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Versioned, integrity-checked durable log.
//
// Authoritative deployment state cannot be reconstructed from a target's memory:
// it must survive a controller kill. The journal is an append-only record stream
// in which every record carries a checksum, a monotonic sequence number and a
// type from a frozen enumeration. Recovery is conservative:
//
//   * a torn record at the very end of the file (the shape a crash during append
//     leaves behind) is discarded and reported, never guessed at;
//   * a record that fails its checksum with valid data after it is corruption and
//     stops the process rather than silently dropping state;
//   * a sequence gap is corruption and stops the process;
//   * a record type this build does not know is an unsupported-version error, and
//     the store refuses to open instead of skipping state it cannot interpret.
//
// Snapshots are alternated between two slots so that a corrupt or torf snapshot
// can fall back to the previous one; if the fallback would leave a gap in the
// journal, opening fails loudly. That is the difference between recovery and
// invention.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "cf/ids.hpp"
#include "cf/result.hpp"

namespace cf {

inline constexpr std::uint32_t kJournalMagic = 0x314A4643u;  // "CFJ1"
inline constexpr std::uint16_t kJournalFormatVersion = 1;
inline constexpr std::size_t kJournalHeaderBytes = 12;
inline constexpr std::size_t kJournalRecordHeaderBytes = 20;
inline constexpr std::size_t kMaxJournalRecordBytes = 1u * 1024u * 1024u;
/// Bound on a free-form diagnostic note record.
inline constexpr std::size_t kMaxNoteBytes = 256;

// Snapshot file layout:
//   magic(4) version(2) reserved(2) coveredSequence(8) payloadLength(4)
//   payloadCrc(4) headerCrc(4) payload(payloadLength)
// headerCrc covers the first 24 bytes, so the checksum never covers itself.
inline constexpr std::uint32_t kSnapshotMagic = 0x31534643u;  // "CFS1"
inline constexpr std::uint16_t kSnapshotFormatVersion = 1;
inline constexpr std::size_t kSnapshotHeaderBytes = 28;
inline constexpr std::uint64_t kMaxSnapshotBytes = 64ull * 1024ull * 1024ull;

/// Frozen record type enumeration. Values are never renumbered.
enum class JournalRecordType : std::uint32_t {
  Invalid = 0,
  /// First record of a journal segment. Payload: u64 base sequence.
  SegmentStart = 1,

  // Controller authority and identity (10-19)
  ControllerIdentity = 10,
  ControllerEpoch = 11,

  // Authoritative deployment state (20-49)
  TargetUpsert = 20,
  TargetRemove = 21,
  DeliveryUpsert = 30,
  DeliveryRemove = 31,
  ArtifactUpsert = 40,
  ArtifactRemove = 41,
  DeploymentSetNote = 42,

  // Target agent state (60-89)
  AgentIdentity = 60,
  AgentTargetCommit = 61,
  AgentTransferUpsert = 62,
  AgentTransferRemove = 63,
  AgentFindingUpsert = 64,
  AgentApplyPrepared = 65,
  AgentApplyResolved = 66,
  AgentControllerFence = 67,
  AgentRollbackNote = 68,

  /// Free-form diagnostic note recorded by an operator-facing command.
  Note = 90,
};

[[nodiscard]] std::string_view journalRecordTypeName(JournalRecordType type) noexcept;
[[nodiscard]] bool parseJournalRecordType(std::string_view text, JournalRecordType& out) noexcept;

struct JournalRecord {
  JournalRecordType type{JournalRecordType::Invalid};
  Sequence sequence;
  std::vector<std::uint8_t> payload;

  friend bool operator==(const JournalRecord&, const JournalRecord&) noexcept = default;
};

/// What recovery actually did. Reported by every open so that a restart is
/// inspectable rather than silent.
struct JournalRecovery {
  enum class Outcome : std::uint8_t {
    /// A new, empty journal was created.
    Created = 0,
    /// The journal was read end to end with no anomaly.
    Clean = 1,
    /// A torn tail record was discarded. Expected after a crash mid-append.
    TruncatedTail = 2,
    /// Damage in the middle of the file, a sequence gap, or unknown record types.
    Corrupted = 3,
    /// The file is not a journal produced by this runtime.
    NotAJournal = 4,
    /// The journal was produced by an incompatible format version.
    UnsupportedVersion = 5,
  };

  Outcome outcome{Outcome::Created};
  std::uint64_t discardedBytes{0};
  std::size_t recordsRecovered{0};
  Sequence lastSequence;
  std::string detail;

  [[nodiscard]] bool fatal() const noexcept {
    return outcome == Outcome::Corrupted || outcome == Outcome::NotAJournal ||
           outcome == Outcome::UnsupportedVersion;
  }
  [[nodiscard]] std::string render() const;
};

class Journal final {
 public:
  struct Options {
    std::string path;
    std::size_t maxRecordBytes{kMaxJournalRecordBytes};
    /// Flush each append to the storage device. Disabling this trades crash
    /// safety for throughput and is reported in the capability surface.
    bool durable{true};
  };

  Journal(const Journal&) = delete;
  Journal& operator=(const Journal&) = delete;
  ~Journal();

  /// Opens or creates the journal and performs recovery. A fatal recovery
  /// outcome is returned as an error and no handle is produced.
  [[nodiscard]] static Result<std::unique_ptr<Journal>> open(const Options& options,
                                                             JournalRecovery& recovery);
  /// Read-only scan used by the inspection CLI and by tests. Never mutates.
  [[nodiscard]] static Result<std::vector<JournalRecord>> readFile(const std::string& path,
                                                                   JournalRecovery& recovery);

  /// Appends a record and returns the sequence it was assigned. When durable is
  /// enabled the record is on stable storage before this returns.
  [[nodiscard]] Status append(JournalRecordType type, std::span<const std::uint8_t> payload,
                              Sequence* assignedSequence);

  /// Discards all records and restarts the segment at baseSequence. Only valid
  /// immediately after a snapshot that covers baseSequence - 1.
  [[nodiscard]] Status restartSegment(Sequence baseSequence);

  [[nodiscard]] std::uint64_t sizeBytes() const;
  [[nodiscard]] std::size_t maxRecordBytes() const noexcept { return options_.maxRecordBytes; }
  [[nodiscard]] Sequence lastSequence() const noexcept { return lastSequence_; }
  [[nodiscard]] std::size_t recordCount() const noexcept { return recordCount_; }
  [[nodiscard]] const std::string& path() const noexcept { return options_.path; }

 private:
  Journal() = default;

  [[nodiscard]] Status writeRecord(JournalRecordType type, std::span<const std::uint8_t> payload,
                                   Sequence sequence);
  [[nodiscard]] Status rewriteHeader();
  [[nodiscard]] Status scanInto(std::vector<JournalRecord>* records, JournalRecovery& recovery,
                                bool truncateTornTail);

  Options options_;
  std::FILE* file_{nullptr};
  Sequence lastSequence_;
  std::size_t recordCount_{0};
  bool durableFlush_{true};
};

/// Two-slot snapshot file used with the journal.
class SnapshotFile final {
 public:
  struct Options {
    /// Base path; the two slots are "<base>.a" and "<base>.b".
    std::string path;
    std::size_t maxBytes{static_cast<std::size_t>(kMaxSnapshotBytes)};
  };

  /// Writes payload into the older slot and returns the slot actually used.
  [[nodiscard]] static Status write(const Options& options, Sequence coveredSequence,
                                    std::span<const std::uint8_t> payload, char* slotUsed);

  struct Loaded {
    Sequence coveredSequence;
    std::vector<std::uint8_t> payload;
    char slot{'?'};
  };

  /// Loads the newest valid snapshot. A slot that fails its checksum is skipped
  /// and reported in detail; if neither slot is valid the result is a
  /// NotFound error, which callers treat as "no snapshot yet".
  [[nodiscard]] static Result<Loaded> load(const Options& options, std::string* detail);
};

}  // namespace cf
