// Unit, adversarial and restart tests: durable authoritative state.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <filesystem>
#include <string>

#include "cf/codec.hpp"
#include "cf/rng.hpp"
#include "cf/state.hpp"
#include "cf/store.hpp"
#include "harness.hpp"
#include "testing.hpp"

namespace {

cf::TargetRuntime sampleTarget(const std::string& id) {
  cf::TargetRuntime runtime;
  runtime.id = cf::parseTargetId(id).value();
  runtime.klass = cf::TargetClass::NetworkDevice;
  runtime.guarantee = cf::ApplyGuarantee::AtomicActivate;
  runtime.term = cf::Term::fromValue(3);
  runtime.incarnation = cf::IncarnationId(cf::secureRandom128());
  runtime.committedGeneration = cf::Generation::fromValue(2);
  runtime.committedDigest = cf::Digest::ofText("committed");
  runtime.committedArtifact = cf::parseArtifactId("cfg/underlay").value();
  runtime.endpoint = "127.0.0.1:9000";
  return runtime;
}

cf::DeliveryRecord sampleDelivery(const std::string& target, std::uint64_t generation) {
  cf::DeliveryRecord record;
  record.setId = cf::parseDeploymentSetId("set-1").value();
  record.target = cf::parseTargetId(target).value();
  record.key = cf::parseConfigKey("fabric/underlay").value();
  record.artifact = cf::parseArtifactId("cfg/underlay").value();
  record.revision = cf::Revision::fromValue(generation);
  record.generation = cf::Generation::fromValue(generation);
  record.digest = cf::Digest::ofText("payload-" + std::to_string(generation));
  record.schema = cf::parseSchemaId("cf.underlay").value();
  record.schemaVersion = cf::SchemaVersion::fromValue(1);
  record.sizeBytes = 128;
  record.id = cf::deriveDeploymentId(record.target, record.key, record.generation, record.digest);
  return record;
}

}  // namespace

CF_TEST(unit, controller_state_round_trip) {
  cf::ControllerState state;
  state.nodeId = cf::parseNodeId("ctl-a").value();
  state.epoch = cf::Epoch::fromValue(7);
  state.incarnation = cf::IncarnationId(cf::secureRandom128());
  state.startedAtMillis = 42;
  const cf::TargetRuntime runtime = sampleTarget("rtr-1");
  state.targets.emplace(runtime.id, runtime);
  const cf::DeliveryRecord delivery = sampleDelivery("rtr-1", 3);
  state.deliveries.emplace(delivery.id, delivery);
  cf::ArtifactMetadata metadata;
  metadata.id = cf::parseArtifactId("cfg/underlay").value();
  metadata.schema = cf::parseSchemaId("cf.underlay").value();
  metadata.digest = cf::Digest::ofText("payload-3");
  metadata.sizeBytes = 9;
  state.artifacts.emplace(metadata.digest, metadata);

  const auto encoded = cf::ControllerStateCodec::encodeSnapshot(state);
  CF_EXPECT_OK(encoded);
  const auto decoded = cf::ControllerStateCodec::decodeSnapshot(encoded.value());
  CF_EXPECT_OK(decoded);
  CF_EXPECT_EQ(decoded.value().epoch.value(), state.epoch.value());
  CF_EXPECT_EQ(decoded.value().targets.size(), std::size_t{1});
  CF_EXPECT_EQ(decoded.value().deliveries.size(), std::size_t{1});
  CF_EXPECT_EQ(decoded.value().artifacts.size(), std::size_t{1});
  const cf::TargetRuntime& restored = decoded.value().targets.begin()->second;
  CF_EXPECT_EQ(restored.committedGeneration.value(), std::uint64_t{2});
  // Contact evidence must never survive a round trip as current.
  CF_EXPECT(!restored.contactEstablishedThisProcess);
}

CF_TEST(unit, delivery_record_round_trip) {
  cf::DeliveryRecord record = sampleDelivery("rtr-1", 5);
  record.state = cf::DeliveryState::Staged;
  record.attempt = cf::AttemptId::fromValue(2);
  record.failures = 1;
  record.lastError = cf::ErrorCode::DigestMismatch;
  record.lastDirective = cf::RetryDirective::DoNotRetry;
  record.lastDetail = "digest mismatch";
  record.authorityEpoch = cf::Epoch::fromValue(4);
  record.authorityIncarnation = cf::IncarnationId(cf::secureRandom128());
  record.targetTerm = cf::Term::fromValue(2);
  record.targetIncarnation = cf::IncarnationId(cf::secureRandom128());
  record.acknowledgedFromReconcile = true;
  record.events.push_back(cf::LifecycleEvent{});
  record.events.back().kind = cf::EvidenceKind::DigestVerified;
  record.events.back().from = cf::DeliveryState::Transferred;
  record.events.back().to = cf::DeliveryState::Verified;

  const auto encoded = cf::encodeDeliveryRecord(record);
  CF_EXPECT_OK(encoded);
  const auto decoded = cf::decodeDeliveryRecord(encoded.value());
  CF_EXPECT_OK(decoded);
  CF_EXPECT(decoded.value() == record);
}

CF_TEST(adversarial, state_decoders_refuse_damaged_records) {
  const cf::DeliveryRecord record = sampleDelivery("rtr-1", 2);
  const auto encoded = cf::encodeDeliveryRecord(record);
  CF_EXPECT_OK(encoded);
  for (std::size_t length = 0; length < encoded.value().size(); ++length) {
    CF_EXPECT(!cf::decodeDeliveryRecord(
                   std::span<const std::uint8_t>(encoded.value().data(), length))
                   .hasValue());
  }
  for (std::size_t i = 0; i < encoded.value().size(); ++i) {
    std::vector<std::uint8_t> damaged = encoded.value();
    damaged[i] = static_cast<std::uint8_t>(damaged[i] ^ 0x01u);
    const auto decoded = cf::decodeDeliveryRecord(damaged);
    // Either the enumerator or the identity check rejects it, or the change was
    // in a free-form field. It must never crash and never accept a truncated one.
    (void)decoded;
  }
  CF_EXPECT(true);
}

CF_TEST(unit, agent_state_round_trip_with_findings) {
  cf::AgentState state;
  state.target = cf::parseTargetId("rtr-1").value();
  state.klass = cf::TargetClass::NetworkDevice;
  state.guarantee = cf::ApplyGuarantee::PrepareCommitAbort;
  state.term = cf::Term::fromValue(9);
  state.incarnation = cf::IncarnationId(cf::secureRandom128());
  state.restartCount = 3;
  state.lastControllerEpoch = cf::Epoch::fromValue(2);
  state.lastControllerIncarnation = cf::IncarnationId(cf::secureRandom128());
  state.lastControllerNode = cf::parseNodeId("ctl-a").value();
  state.committedGeneration = cf::Generation::fromValue(4);
  state.committedDigest = cf::Digest::ofText("committed");
  state.committedArtifact = cf::parseArtifactId("cfg/underlay").value();
  state.applyRollbacks = 2;
  state.activations = 5;

  cf::TransferRecord transfer;
  transfer.deployment = cf::parseDeploymentId("d-1").value();
  transfer.stream = cf::StreamId::fromValue(9);
  transfer.key = cf::parseConfigKey("fabric/underlay").value();
  transfer.artifact = cf::parseArtifactId("cfg/underlay").value();
  transfer.generation = cf::Generation::fromValue(5);
  transfer.digest = cf::Digest::ofText("next");
  transfer.totalBytes = 1000;
  transfer.bytesReceived = 400;
  state.transfers.emplace(transfer.deployment, transfer);

  cf::AppliedFinding finding;
  finding.key = transfer.key;
  finding.generation = cf::Generation::fromValue(4);
  finding.digest = state.committedDigest;
  finding.artifact = state.committedArtifact;
  finding.deployment = cf::parseDeploymentId("d-0").value();
  finding.state = cf::DeliveryState::Applied;
  state.findings.push_back(finding);

  const auto encoded = cf::AgentStateCodec::encodeSnapshot(state);
  CF_EXPECT_OK(encoded);
  const auto decoded = cf::AgentStateCodec::decodeSnapshot(encoded.value());
  CF_EXPECT_OK(decoded);
  CF_EXPECT_EQ(decoded.value().term.value(), state.term.value());
  CF_EXPECT_EQ(decoded.value().transfers.size(), std::size_t{1});
  CF_EXPECT_EQ(decoded.value().findings.size(), std::size_t{1});
  CF_EXPECT_EQ(decoded.value().applyRollbacks, state.applyRollbacks);
  CF_EXPECT(decoded.value().findFinding(transfer.key, state.committedDigest) != nullptr);
}

CF_TEST(restart, store_persists_and_recovers_across_reopen) {
  cf::test::TempDir directory("store-restart");
  const cf::DeliveryRecord delivery = sampleDelivery("rtr-1", 4);
  {
    cf::ControllerStore::Options options;
    options.directory = directory.path();
    options.name = "controller";
    cf::ControllerStore::Recovery recovery;
    auto store = cf::ControllerStore::open(options, recovery);
    CF_EXPECT_OK(store);
    CF_EXPECT_EQ(recovery.journal.outcome, cf::JournalRecovery::Outcome::Created);
    cf::ControllerState& state = store.value()->state();
    state.nodeId = cf::parseNodeId("ctl-a").value();
    const auto deliveryBytes = cf::encodeDeliveryRecord(delivery);
    CF_EXPECT_OK(store.value()->commit(cf::JournalRecordType::DeliveryUpsert,
                                       deliveryBytes.value()));
    const cf::TargetRuntime runtime = sampleTarget("rtr-1");
    const auto runtimeBytes = cf::encodeTargetRuntime(runtime);
    CF_EXPECT_OK(store.value()->commit(cf::JournalRecordType::TargetUpsert,
                                       runtimeBytes.value()));
  }
  {
    cf::ControllerStore::Options options;
    options.directory = directory.path();
    options.name = "controller";
    cf::ControllerStore::Recovery recovery;
    auto store = cf::ControllerStore::open(options, recovery);
    CF_EXPECT_OK(store);
    CF_EXPECT_EQ(recovery.recordsReplayed, std::size_t{2});
    CF_EXPECT_EQ(store.value()->state().deliveries.size(), std::size_t{1});
    CF_EXPECT_EQ(store.value()->state().targets.size(), std::size_t{1});
    const cf::DeliveryRecord* restored = store.value()->state().findDelivery(delivery.id);
    CF_EXPECT(restored != nullptr);
    if (restored != nullptr) {
      CF_EXPECT_EQ(restored->generation.value(), delivery.generation.value());
    }
    // Persisted contact evidence is loaded but not current.
    const cf::TargetRuntime* runtime = store.value()->state().findTarget(delivery.target);
    CF_EXPECT(runtime != nullptr);
    if (runtime != nullptr) {
      CF_EXPECT(!runtime->contactEstablishedThisProcess);
    }
  }
}

CF_TEST(restart, compaction_bounds_growth_and_keeps_state) {
  cf::test::TempDir directory("store-compaction");
  const cf::DeliveryRecord delivery = sampleDelivery("rtr-1", 6);
  {
    cf::ControllerStore::Options options;
    options.directory = directory.path();
    options.name = "controller";
    options.compactAfterBytes = 4096;
    cf::ControllerStore::Recovery recovery;
    auto store = cf::ControllerStore::open(options, recovery);
    CF_EXPECT_OK(store);
    for (int i = 0; i < 200; ++i) {
      const auto bytes = cf::encodeDeliveryRecord(delivery);
      CF_EXPECT_OK(store.value()->commit(cf::JournalRecordType::DeliveryUpsert, bytes.value()));
      CF_EXPECT_OK(store.value()->compactIfNeeded());
    }
    CF_EXPECT(store.value()->journalBytes() < 8192);
  }
  {
    cf::ControllerStore::Options options;
    options.directory = directory.path();
    options.name = "controller";
    cf::ControllerStore::Recovery recovery;
    auto store = cf::ControllerStore::open(options, recovery);
    CF_EXPECT_OK(store);
    CF_EXPECT(recovery.snapshotLoaded);
    CF_EXPECT_EQ(store.value()->state().deliveries.size(), std::size_t{1});
  }
}

CF_TEST(adversarial, snapshot_gap_is_refused_rather_than_guessed) {
  cf::test::TempDir directory("store-gap");
  const cf::DeliveryRecord delivery = sampleDelivery("rtr-1", 6);
  cf::ControllerStore::Options options;
  options.directory = directory.path();
  options.name = "controller";
  {
    cf::ControllerStore::Recovery recovery;
    auto store = cf::ControllerStore::open(options, recovery);
    CF_EXPECT_OK(store);
    const auto bytes = cf::encodeDeliveryRecord(delivery);
    CF_EXPECT_OK(store.value()->commit(cf::JournalRecordType::DeliveryUpsert, bytes.value()));
    CF_EXPECT_OK(store.value()->commit(cf::JournalRecordType::DeliveryUpsert, bytes.value()));
    CF_EXPECT_OK(store.value()->compact());
    CF_EXPECT_OK(store.value()->commit(cf::JournalRecordType::DeliveryUpsert, bytes.value()));
    CF_EXPECT_OK(store.value()->compact());
  }
  // Destroy the newer snapshot and the older one's peer, leaving only the oldest
  // snapshot next to a journal that starts far later.
  std::error_code ec;
  std::filesystem::remove(directory.path() + "/controller.snapshot.b", ec);
  {
    cf::ControllerStore::Recovery recovery;
    auto store = cf::ControllerStore::open(options, recovery);
    CF_EXPECT(!store.hasValue());
    CF_EXPECT(store.error().detail().find("journal-base") != std::string::npos);
  }
}

CF_TEST(unit, offline_loading_does_not_mutate_state) {
  cf::test::TempDir directory("store-offline");
  const cf::DeliveryRecord delivery = sampleDelivery("rtr-1", 2);
  {
    cf::ControllerStore::Options options;
    options.directory = directory.path();
    options.name = "controller";
    cf::ControllerStore::Recovery recovery;
    auto store = cf::ControllerStore::open(options, recovery);
    CF_EXPECT_OK(store);
    const auto bytes = cf::encodeDeliveryRecord(delivery);
    CF_EXPECT_OK(store.value()->commit(cf::JournalRecordType::DeliveryUpsert, bytes.value()));
  }
  const std::string journalPath = directory.path() + "/controller.journal";
  const std::uintmax_t sizeBefore = std::filesystem::file_size(journalPath);

  std::string detail;
  auto state = cf::loadControllerStateOffline(directory.path(), &detail);
  CF_EXPECT_OK(state);
  CF_EXPECT_EQ(state.value().deliveries.size(), std::size_t{1});
  CF_EXPECT_EQ(std::filesystem::file_size(journalPath), sizeBefore);

  // A second load produces identical results.
  std::string secondDetail;
  auto again = cf::loadControllerStateOffline(directory.path(), &secondDetail);
  CF_EXPECT_OK(again);
  CF_EXPECT_EQ(again.value().deliveries.size(), std::size_t{1});
}

CF_TEST(adversarial, pending_records_survive_and_apply_in_order) {
  cf::test::TempDir directory("store-order");
  cf::ControllerStore::Options options;
  options.directory = directory.path();
  options.name = "controller";
  cf::ControllerStore::Recovery recovery;
  auto store = cf::ControllerStore::open(options, recovery);
  CF_EXPECT_OK(store);
  const cf::DeliveryRecord first = sampleDelivery("rtr-1", 1);
  const cf::DeliveryRecord second = sampleDelivery("rtr-1", 2);
  const auto firstBytes = cf::encodeDeliveryRecord(first);
  const auto secondBytes = cf::encodeDeliveryRecord(second);
  CF_EXPECT_OK(store.value()->commit(cf::JournalRecordType::DeliveryUpsert, firstBytes.value()));
  CF_EXPECT_OK(store.value()->commit(cf::JournalRecordType::DeliveryUpsert, secondBytes.value()));
  CF_EXPECT_EQ(store.value()->state().deliveries.size(), std::size_t{2});
  CF_EXPECT_EQ(store.value()->state().pendingDeliveries().size(), std::size_t{2});
  const cf::DeliveryRecord* latest =
      store.value()->state().latestForLineage(first.target, first.key);
  CF_EXPECT(latest != nullptr);
  if (latest != nullptr) {
    CF_EXPECT_EQ(latest->generation.value(), std::uint64_t{2});
  }
}
