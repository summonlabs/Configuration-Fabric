// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Durable state store: snapshot + journal, with conservative recovery.
//
// The store is deliberately strict about the difference between recording a
// state change and inventing one:
//
//   * a change is validated and applied to memory, then appended to the journal;
//   * if the append fails, the store enters a failed state and refuses further
//     commits, so a caller can never believe it recorded something it did not;
//   * on open, the snapshot is loaded and only journal records newer than the
//     snapshot's covered sequence are replayed;
//   * a gap between the snapshot and the journal base - which is what a fallback
//     to an older snapshot looks like - is a hard failure, not a silent reset.
//
// Compaction rewrites the snapshot and restarts the journal segment, which is
// what keeps durable growth bounded.

#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "cf/journal.hpp"
#include "cf/log.hpp"
#include "cf/result.hpp"

namespace cf {

template <class State, class Codec>
class DurableStore final {
 public:
  struct Options {
    /// Directory that holds the snapshot slots and the journal.
    std::string directory;
    /// Base name for the store files.
    std::string name{"state"};
    /// Compaction threshold for the journal file.
    std::uint64_t compactAfterBytes{4ull * 1024ull * 1024ull};
    /// Flush every append to the storage device.
    bool durable{true};
  };

  struct Recovery {
    JournalRecovery journal;
    bool snapshotLoaded{false};
    char snapshotSlot{'?'};
    Sequence snapshotCovered;
    std::string snapshotDetail;
    std::size_t recordsReplayed{0};
    bool compactedOnOpen{false};

    [[nodiscard]] std::string render() const {
      std::string out;
      out.append("snapshot=");
      out.append(snapshotLoaded ? "loaded" : "none");
      if (snapshotLoaded) {
        out.push_back('(');
        out.push_back(snapshotSlot);
        out.append(" covered=");
        out.append(std::to_string(snapshotCovered.value()));
        out.push_back(')');
      }
      out.append(" journal=");
      out.append(journal.render());
      out.append(" replayed=");
      out.append(std::to_string(recordsReplayed));
      if (!snapshotDetail.empty()) {
        out.append(" snapshot-notes=");
        out.append(snapshotDetail);
      }
      return out;
    }
  };

  DurableStore(const DurableStore&) = delete;
  DurableStore& operator=(const DurableStore&) = delete;
  ~DurableStore() = default;

  [[nodiscard]] static Result<std::unique_ptr<DurableStore>> open(const Options& options,
                                                                 Recovery& recovery) {
    if (options.directory.empty()) {
      return Result<std::unique_ptr<DurableStore>>::fail(ErrorCode::InvalidArgument,
                                                         "state store directory must not be empty");
    }
    std::unique_ptr<DurableStore> store(new DurableStore());
    store->options_ = options;

    SnapshotFile::Options snapshotOptions;
    snapshotOptions.path = options.directory + "/" + options.name + ".snapshot";

    std::string snapshotDetail;
    auto snapshot = SnapshotFile::load(snapshotOptions, &snapshotDetail);
    recovery.snapshotDetail = snapshotDetail;
    if (snapshot) {
      CF_TRY_ASSIGN(State decoded, Codec::decodeSnapshot(snapshot.value().payload));
      store->state_ = std::move(decoded);
      recovery.snapshotLoaded = true;
      recovery.snapshotSlot = snapshot.value().slot;
      recovery.snapshotCovered = snapshot.value().coveredSequence;
    } else if (snapshot.error().code() != ErrorCode::NotFound) {
      return Result<std::unique_ptr<DurableStore>>::fail(snapshot.error());
    }

    Journal::Options journalOptions;
    journalOptions.path = options.directory + "/" + options.name + ".journal";
    journalOptions.durable = options.durable;
    auto journal = Journal::open(journalOptions, recovery.journal);
    if (!journal) {
      return Result<std::unique_ptr<DurableStore>>::fail(journal.error());
    }
    store->journal_ = std::move(journal).value();
    const bool created = recovery.journal.outcome == JournalRecovery::Outcome::Created;

    auto records = Journal::readFile(journalOptions.path, recovery.journal);
    if (!records) {
      return Result<std::unique_ptr<DurableStore>>::fail(records.error());
    }
    if (created) {
      // Reading the journal back to replay it must not erase the fact that this
      // open created it; the distinction is what an operator uses to tell a
      // first start from a recovery.
      recovery.journal.outcome = JournalRecovery::Outcome::Created;
    }

    std::uint64_t baseSequence = 0;
    for (const JournalRecord& record : records.value()) {
      if (record.type == JournalRecordType::SegmentStart) {
        if (record.payload.size() != 8) {
          return Result<std::unique_ptr<DurableStore>>::fail(
              ErrorCode::IntegrityFailure, "journal segment-start record is malformed");
        }
        std::uint64_t base = 0;
        for (unsigned i = 0; i < 8; ++i) {
          base |= static_cast<std::uint64_t>(record.payload[i]) << (i * 8);
        }
        baseSequence = base;
        break;
      }
    }
    if (baseSequence == 0) {
      return Result<std::unique_ptr<DurableStore>>::fail(
          ErrorCode::IntegrityFailure, "journal does not begin with a segment-start record");
    }

    const std::uint64_t covered =
        recovery.snapshotLoaded ? recovery.snapshotCovered.value() : 0;
    if (baseSequence > covered + 1) {
      // The snapshot we could load is older than the point the journal was reset
      // at, so records between them are gone. Recovery stops here: refusing to
      // open is the only honest response.
      return Result<std::unique_ptr<DurableStore>>::fail(
          ErrorCode::IntegrityFailure,
          "durable state has a gap between the newest loadable snapshot and the journal base",
          "snapshot-covered=" + std::to_string(covered) +
              " journal-base=" + std::to_string(baseSequence));
    }

    for (const JournalRecord& record : records.value()) {
      if (record.type == JournalRecordType::SegmentStart) {
        continue;
      }
      if (record.sequence.value() <= covered) {
        continue;
      }
      CF_TRY(Codec::apply(store->state_, record.type, record.payload));
      recovery.recordsReplayed += 1;
    }
    return Result<std::unique_ptr<DurableStore>>::ok(std::move(store));
  }

  [[nodiscard]] State& state() noexcept { return state_; }
  [[nodiscard]] const State& state() const noexcept { return state_; }
  [[nodiscard]] bool failed() const noexcept { return failed_; }
  [[nodiscard]] Sequence lastSequence() const noexcept { return journal_->lastSequence(); }
  [[nodiscard]] std::uint64_t journalBytes() const { return journal_->sizeBytes(); }

  /// Validates, applies and durably records one change. A failure leaves the
  /// store marked failed: continuing would mean running on state that is not
  /// recorded anywhere.
  [[nodiscard]] Status commit(JournalRecordType type, std::span<const std::uint8_t> payload) {
    if (failed_) {
      return Status::fail(ErrorCode::Internal,
                          "durable state store is failed; no further commits are accepted");
    }
    if (payload.size() > journal_->maxRecordBytes()) {
      return Status::fail(ErrorCode::OversizePayload, "state record exceeds the journal bound");
    }
    CF_TRY(Codec::apply(state_, type, payload));
    CF_TRY(journal_->append(type, payload, nullptr));
    return Status::ok();
  }

  /// Writes a snapshot of the current state and restarts the journal segment.
  [[nodiscard]] Status compact() {
    if (failed_) {
      return Status::fail(ErrorCode::Internal, "durable state store is failed");
    }
    CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, Codec::encodeSnapshot(state_));
    SnapshotFile::Options snapshotOptions;
    snapshotOptions.path = options_.directory + "/" + options_.name + ".snapshot";
    const Sequence covered = journal_->lastSequence();
    char slot = '?';
    CF_TRY(SnapshotFile::write(snapshotOptions, covered, encoded, &slot));
    CF_TRY(journal_->restartSegment(Sequence::fromValue(covered.value() + 1)));
    return Status::ok();
  }

  /// Compacts when the journal has grown past the configured threshold.
  [[nodiscard]] Status compactIfNeeded() {
    if (journal_->sizeBytes() < options_.compactAfterBytes) {
      return Status::ok();
    }
    return compact();
  }

  void markFailed() noexcept { failed_ = true; }

 private:
  DurableStore() = default;

  Options options_;
  std::unique_ptr<Journal> journal_;
  State state_;
  bool failed_{false};
};

}  // namespace cf
