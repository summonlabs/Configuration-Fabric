// Unit and adversarial tests: the durable journal and snapshot slots.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <filesystem>
#include <string>
#include <vector>

#include "cf/codec.hpp"
#include "cf/journal.hpp"
#include "cf/rng.hpp"
#include "harness.hpp"
#include "testing.hpp"

namespace {

cf::Result<std::unique_ptr<cf::Journal>> openJournal(const std::string& path,
                                                     cf::JournalRecovery& recovery) {
  cf::Journal::Options options;
  options.path = path;
  return cf::Journal::open(options, recovery);
}

std::vector<std::uint8_t> payloadOf(std::string_view text) {
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

}  // namespace

CF_TEST(unit, journal_create_append_and_replay) {
  cf::test::TempDir directory("journal-basic");
  const std::string path = directory.child("state.journal");
  cf::JournalRecovery recovery;
  {
    auto journal = openJournal(path, recovery);
    CF_EXPECT_OK(journal);
    CF_EXPECT_EQ(recovery.outcome, cf::JournalRecovery::Outcome::Created);
    for (int i = 0; i < 5; ++i) {
      const std::vector<std::uint8_t> payload = payloadOf("note-" + std::to_string(i));
      CF_EXPECT_OK(journal.value()->append(cf::JournalRecordType::Note,
                                           std::span<const std::uint8_t>(payload.data(),
                                                                         payload.size()),
                                           nullptr));
    }
  }
  cf::JournalRecovery reopened;
  auto records = cf::Journal::readFile(path, reopened);
  CF_REQUIRE_OK(records);
  CF_EXPECT_EQ(reopened.outcome, cf::JournalRecovery::Outcome::Clean);
  // A segment-start record plus five notes.
  CF_EXPECT_EQ(records.value().size(), std::size_t{6});
  CF_EXPECT_EQ(records.value()[0].type, cf::JournalRecordType::SegmentStart);
  for (std::size_t i = 1; i < records.value().size(); ++i) {
    CF_EXPECT_EQ(records.value()[i].sequence.value(), i + 1);
    const std::string text(records.value()[i].payload.begin(), records.value()[i].payload.end());
    CF_EXPECT_EQ(text, std::string("note-") + std::to_string(i - 1));
  }
}

CF_TEST(adversarial, torn_tail_is_discarded_and_reported) {
  cf::test::TempDir directory("journal-torn");
  const std::string path = directory.child("state.journal");
  cf::JournalRecovery recovery;
  {
    auto journal = openJournal(path, recovery);
    CF_EXPECT_OK(journal);
    for (int i = 0; i < 3; ++i) {
      const std::vector<std::uint8_t> payload = payloadOf("record");
      CF_EXPECT_OK(journal.value()->append(cf::JournalRecordType::Note,
                                           std::span<const std::uint8_t>(payload.data(),
                                                                         payload.size()),
                                           nullptr));
    }
  }
  // Simulate a crash in the middle of an append: append a partial record.
  {
    std::FILE* file = std::fopen(path.c_str(), "ab");
    CF_EXPECT(file != nullptr);
    const std::uint8_t partial[6] = {0x40, 0x00, 0x00, 0x00, 0x5A, 0x00};
    CF_EXPECT(std::fwrite(partial, 1, sizeof(partial), file) == sizeof(partial));
    std::fclose(file);
  }

  cf::JournalRecovery torn;
  {
    auto journal = openJournal(path, torn);
    CF_EXPECT_OK(journal);
    CF_EXPECT_EQ(torn.outcome, cf::JournalRecovery::Outcome::TruncatedTail);
    CF_EXPECT_EQ(torn.discardedBytes, std::uint64_t{6});
    CF_EXPECT_EQ(torn.recordsRecovered, std::size_t{4});
    // The journal keeps working after recovery.
    const std::vector<std::uint8_t> payload = payloadOf("after repair");
    CF_EXPECT_OK(journal.value()->append(cf::JournalRecordType::Note,
                                         std::span<const std::uint8_t>(payload.data(),
                                                                       payload.size()),
                                         nullptr));
  }
  cf::JournalRecovery after;
  auto records = cf::Journal::readFile(path, after);
  CF_REQUIRE_OK(records);
  CF_EXPECT_EQ(after.outcome, cf::JournalRecovery::Outcome::Clean);
  CF_EXPECT_EQ(records.value().size(), std::size_t{5});
}

CF_TEST(adversarial, mid_file_corruption_is_fatal) {
  cf::test::TempDir directory("journal-corrupt");
  const std::string path = directory.child("state.journal");
  cf::JournalRecovery recovery;
  {
    auto journal = openJournal(path, recovery);
    CF_EXPECT_OK(journal);
    for (int i = 0; i < 4; ++i) {
      const std::vector<std::uint8_t> payload = payloadOf("record-" + std::to_string(i));
      CF_EXPECT_OK(journal.value()->append(cf::JournalRecordType::Note,
                                           std::span<const std::uint8_t>(payload.data(),
                                                                         payload.size()),
                                           nullptr));
    }
  }
  // Corrupt a byte in the middle of the file, leaving valid records after it.
  {
    std::FILE* file = std::fopen(path.c_str(), "r+b");
    CF_EXPECT(file != nullptr);
    CF_EXPECT(std::fseek(file, 60, SEEK_SET) == 0);
    const std::uint8_t hostile = 0x7F;
    CF_EXPECT(std::fwrite(&hostile, 1, 1, file) == 1);
    std::fclose(file);
  }

  cf::JournalRecovery damaged;
  auto journal = openJournal(path, damaged);
  CF_EXPECT(!journal.hasValue());
  CF_EXPECT(damaged.fatal());
  CF_EXPECT(damaged.outcome == cf::JournalRecovery::Outcome::Corrupted ||
           damaged.outcome == cf::JournalRecovery::Outcome::NotAJournal);
}

CF_TEST(adversarial, foreign_file_is_not_a_journal) {
  cf::test::TempDir directory("journal-foreign");
  const std::string path = directory.child("state.journal");
  cf::test::writeTextFile(path, "this is not a journal at all, but it is long enough");
  cf::JournalRecovery recovery;
  auto journal = openJournal(path, recovery);
  CF_EXPECT(!journal.hasValue());
  CF_EXPECT_EQ(recovery.outcome, cf::JournalRecovery::Outcome::NotAJournal);
}

CF_TEST(adversarial, record_bound_is_enforced) {
  cf::test::TempDir directory("journal-bound");
  cf::Journal::Options options;
  options.path = directory.child("state.journal");
  options.maxRecordBytes = 64;
  cf::JournalRecovery recovery;
  auto journal = cf::Journal::open(options, recovery);
  CF_EXPECT_OK(journal);
  const std::string payload(128, 'x');
  CF_EXPECT_CODE(journal.value()->append(cf::JournalRecordType::Note,
                                         std::span<const std::uint8_t>(
                                             reinterpret_cast<const std::uint8_t*>(payload.data()),
                                             payload.size()),
                                         nullptr),
                 cf::ErrorCode::OversizePayload);
}

CF_TEST(unit, segment_restart_resets_sequence) {
  cf::test::TempDir directory("journal-restart");
  const std::string path = directory.child("state.journal");
  cf::JournalRecovery recovery;
  auto journal = openJournal(path, recovery);
  CF_EXPECT_OK(journal);
  const std::vector<std::uint8_t> payload = payloadOf("x");
  CF_EXPECT_OK(journal.value()->append(cf::JournalRecordType::Note,
                                       std::span<const std::uint8_t>(payload.data(), payload.size()),
                                       nullptr));
  CF_EXPECT_EQ(journal.value()->lastSequence().value(), std::uint64_t{2});
  CF_EXPECT_OK(journal.value()->restartSegment(cf::Sequence::fromValue(100)));
  CF_EXPECT_EQ(journal.value()->lastSequence().value(), std::uint64_t{100});
  CF_EXPECT_EQ(journal.value()->sizeBytes() < 200, true);

  cf::JournalRecovery reopened;
  auto records = cf::Journal::readFile(path, reopened);
  CF_REQUIRE_OK(records);
  CF_EXPECT_EQ(records.value().size(), std::size_t{1});
  CF_EXPECT_EQ(records.value()[0].type, cf::JournalRecordType::SegmentStart);
  CF_EXPECT_EQ(records.value()[0].sequence.value(), std::uint64_t{100});
}

CF_TEST(unit, snapshot_slots_alternate_and_survive_one_bad_slot) {
  cf::test::TempDir directory("snapshot-slots");
  cf::SnapshotFile::Options options;
  options.path = directory.child("state.snapshot");
  const std::string first = "first payload";
  const std::string second = "second payload";
  char slot = '?';
  CF_EXPECT_OK(cf::SnapshotFile::write(
      options, cf::Sequence::fromValue(10),
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(first.data()),
                                    first.size()),
      &slot));
  CF_EXPECT_EQ(slot, 'a');
  CF_EXPECT_OK(cf::SnapshotFile::write(
      options, cf::Sequence::fromValue(20),
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(second.data()),
                                    second.size()),
      &slot));
  CF_EXPECT_EQ(slot, 'b');

  std::string detail;
  auto loaded = cf::SnapshotFile::load(options, &detail);
  CF_EXPECT_OK(loaded);
  CF_EXPECT_EQ(loaded.value().coveredSequence.value(), std::uint64_t{20});
  CF_EXPECT_EQ(std::string(loaded.value().payload.begin(), loaded.value().payload.end()), second);

  // Damage the newest slot: the loader must fall back to the older one.
  {
    std::FILE* file = std::fopen((options.path + ".b").c_str(), "r+b");
    CF_EXPECT(file != nullptr);
    CF_EXPECT(std::fseek(file, 30, SEEK_SET) == 0);
    const std::uint8_t hostile = 0x00;
    CF_EXPECT(std::fwrite(&hostile, 1, 1, file) == 1);
    std::fclose(file);
  }
  auto fallback = cf::SnapshotFile::load(options, &detail);
  CF_EXPECT_OK(fallback);
  CF_EXPECT_EQ(fallback.value().coveredSequence.value(), std::uint64_t{10});
  CF_EXPECT_EQ(std::string(fallback.value().payload.begin(), fallback.value().payload.end()), first);
  CF_EXPECT(detail.find("slot b") != std::string::npos);
}

CF_TEST(adversarial, snapshot_damage_in_both_slots_is_reported) {
  cf::test::TempDir directory("snapshot-both");
  cf::SnapshotFile::Options options;
  options.path = directory.child("state.snapshot");
  const std::string payload = "payload";
  char slot = '?';
  CF_EXPECT_OK(cf::SnapshotFile::write(
      options, cf::Sequence::fromValue(1),
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(payload.data()),
                                    payload.size()),
      &slot));
  CF_EXPECT_OK(cf::SnapshotFile::write(
      options, cf::Sequence::fromValue(2),
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(payload.data()),
                                    payload.size()),
      &slot));
  for (const char which : {'a', 'b'}) {
    std::FILE* file = std::fopen((options.path + "." + which).c_str(), "r+b");
    if (file != nullptr) {
      std::fseek(file, 10, SEEK_SET);
      const std::uint8_t hostile = 0xFF;
      (void)std::fwrite(&hostile, 1, 1, file);
      std::fclose(file);
    }
  }
  std::string detail;
  auto loaded = cf::SnapshotFile::load(options, &detail);
  CF_EXPECT_CODE(loaded, cf::ErrorCode::NotFound);
  CF_EXPECT(detail.find("=header-crc") != std::string::npos);
}

CF_TEST(property, journal_round_trip_random_records) {
  cf::test::TempDir directory("journal-random");
  const std::string path = directory.child("state.journal");
  cf::Rng rng(cftest::runSeed() ^ 0x1234u);
  cf::JournalRecovery recovery;
  auto journal = openJournal(path, recovery);
  CF_EXPECT_OK(journal);
  std::vector<std::string> expected;
  for (int i = 0; i < 200; ++i) {
    const std::size_t length = static_cast<std::size_t>(rng.bounded(300));
    std::string text;
    text.reserve(length);
    for (std::size_t j = 0; j < length; ++j) {
      text.push_back(static_cast<char>('a' + rng.bounded(26)));
    }
    expected.push_back(text);
    const std::span<const std::uint8_t> payload(
        reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
    CF_EXPECT_OK(journal.value()->append(cf::JournalRecordType::Note, payload, nullptr));
  }
  cf::JournalRecovery reopened;
  auto records = cf::Journal::readFile(path, reopened);
  CF_REQUIRE_OK(records);
  CF_EXPECT_EQ(reopened.outcome, cf::JournalRecovery::Outcome::Clean);
  CF_EXPECT_EQ(records.value().size(), expected.size() + 1);
  for (std::size_t i = 0; i < expected.size(); ++i) {
    const std::string text(records.value()[i + 1].payload.begin(),
                           records.value()[i + 1].payload.end());
    CF_EXPECT_EQ(text, expected[i]);
  }
}
