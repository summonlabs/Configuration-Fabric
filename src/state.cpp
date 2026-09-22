// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/state.hpp"

#include <algorithm>
#include <array>
#include <string>

#include "cf/checked.hpp"
#include "cf/codec.hpp"
#include "cf/contract.hpp"
#include "cf/transport.hpp"

namespace cf {
namespace {

using OpaqueBytes = std::array<std::uint8_t, 16>;

void writeLifecycleEvent(ByteWriter& writer, const LifecycleEvent& event) {
  writer.u8(static_cast<std::uint8_t>(event.kind));
  writer.u8(static_cast<std::uint8_t>(event.from));
  writer.u8(static_cast<std::uint8_t>(event.to));
  writer.u64(event.generation.value());
  writer.digest(event.digest);
  writer.u16(static_cast<std::uint16_t>(event.code));
  writer.u8(static_cast<std::uint8_t>(event.directive));
  writer.u64(event.authorityEpoch.value());
  writer.opaque128(event.authorityIncarnation.bytes());
  writer.u64(event.targetTerm.value());
  writer.opaque128(event.targetIncarnation.bytes());
  writer.boolean(event.fromReconciliation);
  writer.i64(event.atMillis);
  writer.string(event.detail, kMaxEvidenceDetailBytes);
}

[[nodiscard]] Result<LifecycleEvent> readLifecycleEvent(ByteReader& reader) {
  LifecycleEvent event;
  CF_TRY_ASSIGN(const std::uint8_t kind, reader.u8());
  if (kind < 1 || kind > 13) {
    return Result<LifecycleEvent>::fail(ErrorCode::MalformedInput,
                                        "stored lifecycle event has an unknown evidence kind");
  }
  event.kind = static_cast<EvidenceKind>(kind);
  CF_TRY_ASSIGN(const std::uint8_t from, reader.u8());
  CF_TRY_ASSIGN(const std::uint8_t to, reader.u8());
  if (from < 1 || from > 10 || to < 1 || to > 10) {
    return Result<LifecycleEvent>::fail(ErrorCode::MalformedInput,
                                        "stored lifecycle event has an unknown state");
  }
  event.from = static_cast<DeliveryState>(from);
  event.to = static_cast<DeliveryState>(to);
  CF_TRY_ASSIGN(const std::uint64_t generation, reader.u64());
  event.generation = Generation::fromValue(generation);
  CF_TRY_ASSIGN(event.digest, reader.digest());
  CF_TRY_ASSIGN(const std::uint16_t code, reader.u16());
  if (errorCodeName(static_cast<ErrorCode>(code)) == "Unknown") {
    return Result<LifecycleEvent>::fail(ErrorCode::MalformedInput,
                                        "stored lifecycle event has an unknown error code");
  }
  event.code = static_cast<ErrorCode>(code);
  CF_TRY_ASSIGN(const std::uint8_t directive, reader.u8());
  if (directive > 5) {
    return Result<LifecycleEvent>::fail(ErrorCode::MalformedInput,
                                        "stored lifecycle event has an unknown retry directive");
  }
  event.directive = static_cast<RetryDirective>(directive);
  CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
  event.authorityEpoch = Epoch::fromValue(epoch);
  CF_TRY_ASSIGN(const OpaqueBytes authorityIncarnation, reader.opaque128());
  event.authorityIncarnation = IncarnationId(authorityIncarnation);
  CF_TRY_ASSIGN(const std::uint64_t term, reader.u64());
  event.targetTerm = Term::fromValue(term);
  CF_TRY_ASSIGN(const OpaqueBytes targetIncarnation, reader.opaque128());
  event.targetIncarnation = IncarnationId(targetIncarnation);
  CF_TRY_ASSIGN(event.fromReconciliation, reader.boolean());
  CF_TRY_ASSIGN(event.atMillis, reader.i64());
  CF_TRY_ASSIGN(event.detail, reader.string(kMaxEvidenceDetailBytes));
  return Result<LifecycleEvent>::ok(std::move(event));
}

[[nodiscard]] Status checkBounded(const std::string& text, std::size_t bound,
                                  const char* what) {
  if (text.size() > bound) {
    return Status::fail(ErrorCode::LimitExceeded, std::string(what) + " exceeds its bound");
  }
  return Status::ok();
}

void writeTargetRuntime(ByteWriter& writer, const TargetRuntime& runtime) {
  writer.string(runtime.id.str(), kMaxIdentifierLength);
  writer.u8(static_cast<std::uint8_t>(runtime.klass));
  writer.u8(static_cast<std::uint8_t>(runtime.guarantee));
  writer.u64(runtime.term.value());
  writer.opaque128(runtime.incarnation.bytes());
  writer.u64(runtime.committedGeneration.value());
  writer.digest(runtime.committedDigest);
  writer.string(runtime.committedArtifact.str(), kMaxIdentifierLength);
  writer.i64(runtime.lastContactMillis);
  writer.u64(runtime.sessionsEstablished);
  writer.u64(runtime.restartsObserved);
  writer.boolean(runtime.applyPrepared);
  writer.string(runtime.preparedDeployment.str(), kMaxIdentifierLength);
  writer.u64(runtime.preparedGeneration.value());
  writer.digest(runtime.preparedDigest);
  writer.string(runtime.endpoint, kMaxEndpointBytes);
}

[[nodiscard]] Result<TargetRuntime> readTargetRuntime(ByteReader& reader) {
  TargetRuntime runtime;
  CF_TRY_ASSIGN(const std::string id, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(runtime.id, parseTargetId(id));
  CF_TRY_ASSIGN(const std::uint8_t klass, reader.u8());
  if (klass > 2) {
    return Result<TargetRuntime>::fail(ErrorCode::MalformedInput,
                                       "stored target has an unknown class");
  }
  runtime.klass = static_cast<TargetClass>(klass);
  CF_TRY_ASSIGN(const std::uint8_t guarantee, reader.u8());
  if (guarantee < 1 || guarantee > 2) {
    return Result<TargetRuntime>::fail(ErrorCode::MalformedInput,
                                       "stored target has an unknown guarantee");
  }
  runtime.guarantee = static_cast<ApplyGuarantee>(guarantee);
  CF_TRY_ASSIGN(const std::uint64_t term, reader.u64());
  runtime.term = Term::fromValue(term);
  CF_TRY_ASSIGN(const OpaqueBytes incarnation, reader.opaque128());
  runtime.incarnation = IncarnationId(incarnation);
  CF_TRY_ASSIGN(const std::uint64_t committed, reader.u64());
  runtime.committedGeneration = Generation::fromValue(committed);
  CF_TRY_ASSIGN(runtime.committedDigest, reader.digest());
  CF_TRY_ASSIGN(const std::string artifact, reader.string(kMaxIdentifierLength));
  if (!artifact.empty()) {
    CF_TRY_ASSIGN(runtime.committedArtifact, parseArtifactId(artifact));
  }
  CF_TRY_ASSIGN(runtime.lastContactMillis, reader.i64());
  CF_TRY_ASSIGN(runtime.sessionsEstablished, reader.u64());
  CF_TRY_ASSIGN(runtime.restartsObserved, reader.u64());
  CF_TRY_ASSIGN(runtime.applyPrepared, reader.boolean());
  CF_TRY_ASSIGN(const std::string preparedDeployment, reader.string(kMaxIdentifierLength));
  if (!preparedDeployment.empty()) {
    CF_TRY_ASSIGN(runtime.preparedDeployment, parseDeploymentId(preparedDeployment));
  }
  CF_TRY_ASSIGN(const std::uint64_t preparedGeneration, reader.u64());
  runtime.preparedGeneration = Generation::fromValue(preparedGeneration);
  CF_TRY_ASSIGN(runtime.preparedDigest, reader.digest());
  CF_TRY_ASSIGN(runtime.endpoint, reader.string(kMaxEndpointBytes));
  if (!runtime.endpoint.empty()) {
    CF_TRY(parseEndpoint(runtime.endpoint));
  }
  // Contact evidence decoded from durable storage is historical by definition: it
  // may have been written by a previous process. It is never current until the
  // running process establishes a session and sets this itself.
  runtime.contactEstablishedThisProcess = false;
  return Result<TargetRuntime>::ok(std::move(runtime));
}

void writeDeliveryRecord(ByteWriter& writer, const DeliveryRecord& record) {
  writer.string(record.id.str(), kMaxIdentifierLength);
  writer.string(record.setId.str(), kMaxIdentifierLength);
  writer.string(record.rolloutSet.str(), kMaxIdentifierLength);
  writer.string(record.target.str(), kMaxIdentifierLength);
  writer.string(record.key.str(), kMaxIdentifierLength);
  writer.string(record.artifact.str(), kMaxIdentifierLength);
  writer.u64(record.revision.value());
  writer.u64(record.generation.value());
  writer.digest(record.digest);
  writer.string(record.schema.str(), kMaxIdentifierLength);
  writer.u32(record.schemaVersion.value());
  writer.u64(record.sizeBytes);
  writer.u8(static_cast<std::uint8_t>(record.requirement));
  writer.u8(static_cast<std::uint8_t>(record.effectiveGuarantee));
  writer.u8(static_cast<std::uint8_t>(record.state));
  writer.u64(record.attempt.value());
  writer.u32(record.failures);
  writer.u16(static_cast<std::uint16_t>(record.lastError));
  writer.u8(static_cast<std::uint8_t>(record.lastDirective));
  writer.string(record.lastDetail, kMaxDeliveryDetailBytes);
  writer.u32(static_cast<std::uint32_t>(record.events.size()));
  for (const LifecycleEvent& event : record.events) {
    writeLifecycleEvent(writer, event);
  }
  writer.u64(record.authorityEpoch.value());
  writer.opaque128(record.authorityIncarnation.bytes());
  writer.u64(record.targetTerm.value());
  writer.opaque128(record.targetIncarnation.bytes());
  writer.boolean(record.acknowledgedFromReconcile);
  writer.boolean(record.superseded);
  writer.i64(record.createdAtMillis);
  writer.i64(record.updatedAtMillis);
}

[[nodiscard]] Result<DeliveryRecord> readDeliveryRecord(ByteReader& reader) {
  DeliveryRecord record;
  CF_TRY_ASSIGN(const std::string id, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(record.id, parseDeploymentId(id));
  CF_TRY_ASSIGN(const std::string setId, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(record.setId, parseDeploymentSetId(setId));
  CF_TRY_ASSIGN(const std::string rolloutSet, reader.string(kMaxIdentifierLength));
  if (!rolloutSet.empty()) {
    CF_TRY_ASSIGN(record.rolloutSet, parseRolloutSetId(rolloutSet));
  }
  CF_TRY_ASSIGN(const std::string target, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(record.target, parseTargetId(target));
  CF_TRY_ASSIGN(const std::string key, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(record.key, parseConfigKey(key));
  CF_TRY_ASSIGN(const std::string artifact, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(record.artifact, parseArtifactId(artifact));
  CF_TRY_ASSIGN(const std::uint64_t revision, reader.u64());
  record.revision = Revision::fromValue(revision);
  CF_TRY_ASSIGN(const std::uint64_t generation, reader.u64());
  if (generation == 0) {
    return Result<DeliveryRecord>::fail(ErrorCode::MalformedInput,
                                        "stored delivery carries the unset generation 0");
  }
  record.generation = Generation::fromValue(generation);
  CF_TRY_ASSIGN(record.digest, reader.digest());
  CF_TRY_ASSIGN(const std::string schema, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(record.schema, parseSchemaId(schema));
  CF_TRY_ASSIGN(const std::uint32_t schemaVersion, reader.u32());
  record.schemaVersion = SchemaVersion::fromValue(schemaVersion);
  CF_TRY_ASSIGN(record.sizeBytes, reader.u64());
  CF_TRY_ASSIGN(const std::uint8_t requirement, reader.u8());
  if (requirement < 1 || requirement > 2) {
    return Result<DeliveryRecord>::fail(ErrorCode::MalformedInput,
                                        "stored delivery has an unknown guarantee requirement");
  }
  record.requirement = static_cast<GuaranteeRequirement>(requirement);
  CF_TRY_ASSIGN(const std::uint8_t guarantee, reader.u8());
  if (guarantee < 1 || guarantee > 2) {
    return Result<DeliveryRecord>::fail(ErrorCode::MalformedInput,
                                        "stored delivery has an unknown guarantee");
  }
  record.effectiveGuarantee = static_cast<ApplyGuarantee>(guarantee);
  CF_TRY_ASSIGN(const std::uint8_t state, reader.u8());
  if (state < 1 || state > 10) {
    return Result<DeliveryRecord>::fail(ErrorCode::MalformedInput,
                                        "stored delivery has an unknown lifecycle state");
  }
  record.state = static_cast<DeliveryState>(state);
  CF_TRY_ASSIGN(const std::uint64_t attempt, reader.u64());
  record.attempt = AttemptId::fromValue(attempt);
  CF_TRY_ASSIGN(record.failures, reader.u32());
  CF_TRY_ASSIGN(const std::uint16_t code, reader.u16());
  if (errorCodeName(static_cast<ErrorCode>(code)) == "Unknown") {
    return Result<DeliveryRecord>::fail(ErrorCode::MalformedInput,
                                        "stored delivery has an unknown error code");
  }
  record.lastError = static_cast<ErrorCode>(code);
  CF_TRY_ASSIGN(const std::uint8_t directive, reader.u8());
  if (directive > 5) {
    return Result<DeliveryRecord>::fail(ErrorCode::MalformedInput,
                                        "stored delivery has an unknown retry directive");
  }
  record.lastDirective = static_cast<RetryDirective>(directive);
  CF_TRY_ASSIGN(record.lastDetail, reader.string(kMaxDeliveryDetailBytes));
  CF_TRY_ASSIGN(const std::uint32_t eventCount, reader.u32());
  if (eventCount > kMaxEventsPerDelivery) {
    return Result<DeliveryRecord>::fail(ErrorCode::LimitExceeded,
                                        "stored delivery carries too many lifecycle events",
                                        std::to_string(eventCount));
  }
  record.events.reserve(eventCount);
  for (std::uint32_t i = 0; i < eventCount; ++i) {
    CF_TRY_ASSIGN(LifecycleEvent event, readLifecycleEvent(reader));
    record.events.push_back(std::move(event));
  }
  CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
  record.authorityEpoch = Epoch::fromValue(epoch);
  CF_TRY_ASSIGN(const OpaqueBytes authorityIncarnation, reader.opaque128());
  record.authorityIncarnation = IncarnationId(authorityIncarnation);
  CF_TRY_ASSIGN(const std::uint64_t term, reader.u64());
  record.targetTerm = Term::fromValue(term);
  CF_TRY_ASSIGN(const OpaqueBytes targetIncarnation, reader.opaque128());
  record.targetIncarnation = IncarnationId(targetIncarnation);
  CF_TRY_ASSIGN(record.acknowledgedFromReconcile, reader.boolean());
  CF_TRY_ASSIGN(record.superseded, reader.boolean());
  CF_TRY_ASSIGN(record.createdAtMillis, reader.i64());
  CF_TRY_ASSIGN(record.updatedAtMillis, reader.i64());
  return Result<DeliveryRecord>::ok(std::move(record));
}

void writeTransferRecord(ByteWriter& writer, const TransferRecord& record) {
  writer.string(record.deployment.str(), kMaxIdentifierLength);
  writer.u64(record.stream.value());
  writer.string(record.key.str(), kMaxIdentifierLength);
  writer.string(record.artifact.str(), kMaxIdentifierLength);
  writer.u64(record.generation.value());
  writer.digest(record.digest);
  writer.u64(record.totalBytes);
  writer.u64(record.bytesReceived);
  writer.boolean(record.verified);
  writer.boolean(record.staged);
  writer.i64(record.updatedAtMillis);
}

[[nodiscard]] Result<TransferRecord> readTransferRecord(ByteReader& reader) {
  TransferRecord record;
  CF_TRY_ASSIGN(const std::string deployment, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(record.deployment, parseDeploymentId(deployment));
  CF_TRY_ASSIGN(const std::uint64_t stream, reader.u64());
  record.stream = StreamId::fromValue(stream);
  CF_TRY_ASSIGN(const std::string key, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(record.key, parseConfigKey(key));
  CF_TRY_ASSIGN(const std::string artifact, reader.string(kMaxIdentifierLength));
  if (!artifact.empty()) {
    CF_TRY_ASSIGN(record.artifact, parseArtifactId(artifact));
  }
  CF_TRY_ASSIGN(const std::uint64_t generation, reader.u64());
  record.generation = Generation::fromValue(generation);
  CF_TRY_ASSIGN(record.digest, reader.digest());
  CF_TRY_ASSIGN(record.totalBytes, reader.u64());
  CF_TRY_ASSIGN(record.bytesReceived, reader.u64());
  if (record.bytesReceived > record.totalBytes) {
    return Result<TransferRecord>::fail(ErrorCode::MalformedInput,
                                        "stored transfer claims more bytes than its total");
  }
  CF_TRY_ASSIGN(record.verified, reader.boolean());
  CF_TRY_ASSIGN(record.staged, reader.boolean());
  CF_TRY_ASSIGN(record.updatedAtMillis, reader.i64());
  return Result<TransferRecord>::ok(std::move(record));
}

void writeAppliedFinding(ByteWriter& writer, const AppliedFinding& finding) {
  writer.string(finding.key.str(), kMaxIdentifierLength);
  writer.u64(finding.generation.value());
  writer.digest(finding.digest);
  writer.string(finding.artifact.str(), kMaxIdentifierLength);
  writer.string(finding.deployment.str(), kMaxIdentifierLength);
  writer.u8(static_cast<std::uint8_t>(finding.state));
  writer.i64(finding.recordedAtMillis);
}

[[nodiscard]] Result<AppliedFinding> readAppliedFinding(ByteReader& reader) {
  AppliedFinding finding;
  CF_TRY_ASSIGN(const std::string key, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(finding.key, parseConfigKey(key));
  CF_TRY_ASSIGN(const std::uint64_t generation, reader.u64());
  finding.generation = Generation::fromValue(generation);
  CF_TRY_ASSIGN(finding.digest, reader.digest());
  CF_TRY_ASSIGN(const std::string artifact, reader.string(kMaxIdentifierLength));
  if (!artifact.empty()) {
    CF_TRY_ASSIGN(finding.artifact, parseArtifactId(artifact));
  }
  CF_TRY_ASSIGN(const std::string deployment, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(finding.deployment, parseDeploymentId(deployment));
  CF_TRY_ASSIGN(const std::uint8_t state, reader.u8());
  if (state < 1 || state > 10) {
    return Result<AppliedFinding>::fail(ErrorCode::MalformedInput,
                                        "stored finding has an unknown lifecycle state");
  }
  finding.state = static_cast<DeliveryState>(state);
  CF_TRY_ASSIGN(finding.recordedAtMillis, reader.i64());
  return Result<AppliedFinding>::ok(std::move(finding));
}

}  // namespace

// --- ControllerState -------------------------------------------------------

std::vector<const DeliveryRecord*> ControllerState::pendingDeliveries() const {
  std::vector<const DeliveryRecord*> pending;
  for (const auto& entry : deliveries) {
    if (isPendingState(entry.second.state)) {
      pending.push_back(&entry.second);
    }
  }
  return pending;
}

const DeliveryRecord* ControllerState::findDelivery(const DeploymentId& id) const {
  const auto found = deliveries.find(id);
  return found == deliveries.end() ? nullptr : &found->second;
}

const TargetRuntime* ControllerState::findTarget(const TargetId& id) const {
  const auto found = targets.find(id);
  return found == targets.end() ? nullptr : &found->second;
}

const DeliveryRecord* ControllerState::latestForLineage(const TargetId& target,
                                                        const ConfigKey& key) const {
  const DeliveryRecord* newest = nullptr;
  for (const auto& entry : deliveries) {
    const DeliveryRecord& record = entry.second;
    if (!(record.target == target) || !(record.key == key)) {
      continue;
    }
    if (newest == nullptr || record.generation > newest->generation ||
        (record.generation == newest->generation && record.id.str() > newest->id.str())) {
      newest = &record;
    }
  }
  return newest;
}

Result<std::vector<std::uint8_t>> encodeTargetRuntime(const TargetRuntime& runtime) {
  CF_TRY(checkBounded(runtime.id.str(), kMaxIdentifierLength, "target id"));
  ByteWriter writer(256);
  writeTargetRuntime(writer, runtime);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<TargetRuntime> decodeTargetRuntime(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  CF_TRY_ASSIGN(TargetRuntime runtime, readTargetRuntime(reader));
  CF_TRY(reader.requireEnd());
  return Result<TargetRuntime>::ok(std::move(runtime));
}

Result<std::vector<std::uint8_t>> encodeDeliveryRecord(const DeliveryRecord& record) {
  CF_TRY(checkBounded(record.id.str(), kMaxIdentifierLength, "deployment id"));
  CF_TRY(checkBounded(record.lastDetail, kMaxDeliveryDetailBytes, "delivery detail"));
  if (record.events.size() > kMaxEventsPerDelivery) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::LimitExceeded,
                                                   "delivery carries too many lifecycle events");
  }
  ByteWriter writer(768);
  writeDeliveryRecord(writer, record);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<DeliveryRecord> decodeDeliveryRecord(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  CF_TRY_ASSIGN(DeliveryRecord record, readDeliveryRecord(reader));
  CF_TRY(reader.requireEnd());
  return Result<DeliveryRecord>::ok(std::move(record));
}

Result<std::vector<std::uint8_t>> ControllerStateCodec::encodeSnapshot(
    const ControllerState& state) {
  if (state.targets.size() > 100000u || state.deliveries.size() > 100000u) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::LimitExceeded,
                                                   "controller state exceeds the snapshot bound");
  }
  ByteWriter writer(4096);
  writer.u16(kStateFormatVersion);
  writer.string(state.nodeId.str(), kMaxIdentifierLength);
  writer.u64(state.epoch.value());
  writer.opaque128(state.incarnation.bytes());
  writer.i64(state.startedAtMillis);
  writer.u32(static_cast<std::uint32_t>(state.targets.size()));
  for (const auto& entry : state.targets) {
    writeTargetRuntime(writer, entry.second);
  }
  writer.u32(static_cast<std::uint32_t>(state.deliveries.size()));
  for (const auto& entry : state.deliveries) {
    writeDeliveryRecord(writer, entry.second);
  }
  writer.u32(static_cast<std::uint32_t>(state.artifacts.size()));
  for (const auto& entry : state.artifacts) {
    CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeArtifactMetadata(entry.second));
    writer.string(std::string_view(reinterpret_cast<const char*>(encoded.data()), encoded.size()),
                  kAbsoluteMaxFieldBytes);
  }
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ControllerState> ControllerStateCodec::decodeSnapshot(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ControllerState state;
  CF_TRY_ASSIGN(const std::uint16_t version, reader.u16());
  if (version != kStateFormatVersion) {
    return Result<ControllerState>::fail(ErrorCode::UnsupportedVersion,
                                         "controller state snapshot version is not supported",
                                         std::to_string(version));
  }
  CF_TRY_ASSIGN(const std::string nodeId, reader.string(kMaxIdentifierLength));
  if (!nodeId.empty()) {
    CF_TRY_ASSIGN(state.nodeId, parseNodeId(nodeId));
  }
  CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
  state.epoch = Epoch::fromValue(epoch);
  CF_TRY_ASSIGN(const OpaqueBytes incarnation, reader.opaque128());
  state.incarnation = IncarnationId(incarnation);
  CF_TRY_ASSIGN(state.startedAtMillis, reader.i64());
  CF_TRY_ASSIGN(const std::uint32_t targetCount, reader.u32());
  if (targetCount > 100000u) {
    return Result<ControllerState>::fail(ErrorCode::OversizePayload,
                                         "controller state snapshot declares too many targets");
  }
  for (std::uint32_t i = 0; i < targetCount; ++i) {
    CF_TRY_ASSIGN(TargetRuntime runtime, readTargetRuntime(reader));
    state.targets.emplace(runtime.id, std::move(runtime));
  }
  CF_TRY_ASSIGN(const std::uint32_t deliveryCount, reader.u32());
  if (deliveryCount > 100000u) {
    return Result<ControllerState>::fail(ErrorCode::OversizePayload,
                                         "controller state snapshot declares too many deliveries");
  }
  for (std::uint32_t i = 0; i < deliveryCount; ++i) {
    CF_TRY_ASSIGN(DeliveryRecord record, readDeliveryRecord(reader));
    state.deliveries.emplace(record.id, std::move(record));
  }
  CF_TRY_ASSIGN(const std::uint32_t artifactCount, reader.u32());
  if (artifactCount > 100000u) {
    return Result<ControllerState>::fail(ErrorCode::OversizePayload,
                                         "controller state snapshot declares too many artifacts");
  }
  for (std::uint32_t i = 0; i < artifactCount; ++i) {
    CF_TRY_ASSIGN(const std::string encoded, reader.string(kAbsoluteMaxFieldBytes));
    CF_TRY_ASSIGN(ArtifactMetadata metadata,
                  decodeArtifactMetadata(std::span<const std::uint8_t>(
                      reinterpret_cast<const std::uint8_t*>(encoded.data()), encoded.size())));
    state.artifacts.emplace(metadata.digest, std::move(metadata));
  }
  CF_TRY(reader.requireEnd());
  return Result<ControllerState>::ok(std::move(state));
}

Status ControllerStateCodec::apply(ControllerState& state, JournalRecordType type,
                                   std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  switch (type) {
    case JournalRecordType::ControllerIdentity: {
      CF_TRY_ASSIGN(const std::string nodeId, reader.string(kMaxIdentifierLength));
      CF_TRY_ASSIGN(state.nodeId, parseNodeId(nodeId));
      CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
      state.epoch = Epoch::fromValue(epoch);
      CF_TRY_ASSIGN(const OpaqueBytes incarnation, reader.opaque128());
      state.incarnation = IncarnationId(incarnation);
      CF_TRY_ASSIGN(state.startedAtMillis, reader.i64());
      break;
    }
    case JournalRecordType::ControllerEpoch: {
      CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
      if (!Epoch::fromValue(epoch).isSet()) {
        return Status::fail(ErrorCode::MalformedInput, "recorded epoch 0 is not a valid authority");
      }
      state.epoch = Epoch::fromValue(epoch);
      break;
    }
    case JournalRecordType::TargetUpsert: {
      CF_TRY_ASSIGN(TargetRuntime runtime, readTargetRuntime(reader));
      // contactEstablishedThisProcess is process-local evidence, not durable
      // evidence. Decoding deliberately clears it (so a restart never inherits
      // it), but applying a record inside a live process must not clear the
      // value the current process has already established - otherwise every
      // durable write would silently discard the only proof of a live session.
      const auto existing = state.targets.find(runtime.id);
      if (existing != state.targets.end()) {
        runtime.contactEstablishedThisProcess = existing->second.contactEstablishedThisProcess;
      }
      state.targets[runtime.id] = std::move(runtime);
      break;
    }
    case JournalRecordType::TargetRemove: {
      CF_TRY_ASSIGN(const std::string id, reader.string(kMaxIdentifierLength));
      CF_TRY_ASSIGN(const TargetId target, parseTargetId(id));
      state.targets.erase(target);
      break;
    }
    case JournalRecordType::DeliveryUpsert: {
      CF_TRY_ASSIGN(DeliveryRecord record, readDeliveryRecord(reader));
      state.deliveries[record.id] = std::move(record);
      break;
    }
    case JournalRecordType::DeliveryRemove: {
      CF_TRY_ASSIGN(const std::string id, reader.string(kMaxIdentifierLength));
      CF_TRY_ASSIGN(const DeploymentId deployment, parseDeploymentId(id));
      state.deliveries.erase(deployment);
      break;
    }
    case JournalRecordType::ArtifactUpsert: {
      CF_TRY_ASSIGN(const std::string encoded, reader.string(kAbsoluteMaxFieldBytes));
      CF_TRY_ASSIGN(ArtifactMetadata metadata,
                    decodeArtifactMetadata(std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(encoded.data()), encoded.size())));
      state.artifacts[metadata.digest] = std::move(metadata);
      break;
    }
    case JournalRecordType::ArtifactRemove: {
      CF_TRY_ASSIGN(const Digest digest, reader.digest());
      state.artifacts.erase(digest);
      break;
    }
    case JournalRecordType::Note: {
      CF_TRY_ASSIGN(const std::string text, reader.string(kMaxNoteBytes));
      (void)text;
      break;
    }
    default:
      return Status::fail(ErrorCode::UnexpectedMessage,
                          "record type is not valid for controller state",
                          std::string(journalRecordTypeName(type)));
  }
  CF_TRY(reader.requireEnd());
  return Status::ok();
}

// --- Offline loading -------------------------------------------------------

namespace {

/// Shared shape of an offline load: newest valid snapshot plus journal records
/// with a higher sequence number, replayed through the codec.
template <class State, class Codec>
[[nodiscard]] Result<State> loadOffline(const std::string& directory, std::string* detail) {
  SnapshotFile::Options snapshotOptions;
  snapshotOptions.path = directory + "/controller.snapshot";
  State state;
  std::uint64_t covered = 0;
  std::string notes;
  auto snapshot = SnapshotFile::load(snapshotOptions, &notes);
  if (snapshot) {
    CF_TRY_ASSIGN(State decoded, Codec::decodeSnapshot(snapshot.value().payload));
    state = std::move(decoded);
    covered = snapshot.value().coveredSequence.value();
    notes.append(" snapshot-slot=");
    notes.push_back(snapshot.value().slot);
  }
  JournalRecovery recovery;
  auto records = Journal::readFile(directory + "/controller.journal", recovery);
  if (!records) {
    if (detail != nullptr) {
      *detail = notes + " journal=" + recovery.render();
    }
    return Result<State>::fail(records.error());
  }
  std::uint64_t base = 0;
  for (const JournalRecord& record : records.value()) {
    if (record.type == JournalRecordType::SegmentStart && record.payload.size() == 8) {
      for (unsigned i = 0; i < 8; ++i) {
        base |= static_cast<std::uint64_t>(record.payload[i]) << (i * 8);
      }
      break;
    }
  }
  if (base > covered + 1) {
    return Result<State>::fail(
        ErrorCode::IntegrityFailure,
        "durable state has a gap between the newest loadable snapshot and the journal base",
        "snapshot-covered=" + std::to_string(covered) + " journal-base=" + std::to_string(base));
  }
  for (const JournalRecord& record : records.value()) {
    if (record.type == JournalRecordType::SegmentStart) {
      continue;
    }
    if (record.sequence.value() <= covered) {
      continue;
    }
    CF_TRY(Codec::apply(state, record.type, record.payload));
  }
  if (detail != nullptr) {
    *detail = notes + " journal=" + recovery.render();
  }
  return Result<State>::ok(std::move(state));
}

}  // namespace

Result<ControllerState> loadControllerStateOffline(const std::string& directory,
                                                   std::string* detail) {
  return loadOffline<ControllerState, ControllerStateCodec>(directory, detail);
}

Result<AgentState> loadAgentStateOffline(const std::string& directory, std::string* detail) {
  // The agent store uses the same file layout with a different base name.
  SnapshotFile::Options snapshotOptions;
  snapshotOptions.path = directory + "/agent.snapshot";
  AgentState state;
  std::uint64_t covered = 0;
  std::string notes;
  auto snapshot = SnapshotFile::load(snapshotOptions, &notes);
  if (snapshot) {
    CF_TRY_ASSIGN(AgentState decoded, AgentStateCodec::decodeSnapshot(snapshot.value().payload));
    state = std::move(decoded);
    covered = snapshot.value().coveredSequence.value();
    notes.append(" snapshot-slot=");
    notes.push_back(snapshot.value().slot);
  }
  JournalRecovery recovery;
  auto records = Journal::readFile(directory + "/agent.journal", recovery);
  if (!records) {
    if (detail != nullptr) {
      *detail = notes + " journal=" + recovery.render();
    }
    return Result<AgentState>::fail(records.error());
  }
  std::uint64_t base = 0;
  for (const JournalRecord& record : records.value()) {
    if (record.type == JournalRecordType::SegmentStart && record.payload.size() == 8) {
      for (unsigned i = 0; i < 8; ++i) {
        base |= static_cast<std::uint64_t>(record.payload[i]) << (i * 8);
      }
      break;
    }
  }
  if (base > covered + 1) {
    return Result<AgentState>::fail(
        ErrorCode::IntegrityFailure,
        "agent state has a gap between the newest loadable snapshot and the journal base",
        "snapshot-covered=" + std::to_string(covered) + " journal-base=" + std::to_string(base));
  }
  for (const JournalRecord& record : records.value()) {
    if (record.type == JournalRecordType::SegmentStart) {
      continue;
    }
    if (record.sequence.value() <= covered) {
      continue;
    }
    CF_TRY(AgentStateCodec::apply(state, record.type, record.payload));
  }
  if (detail != nullptr) {
    *detail = notes + " journal=" + recovery.render();
  }
  return Result<AgentState>::ok(std::move(state));
}

// --- AgentState ------------------------------------------------------------

const AppliedFinding* AgentState::findFinding(const ConfigKey& key, const Digest& digest) const {
  for (const AppliedFinding& finding : findings) {
    if (finding.key == key && finding.digest == digest) {
      return &finding;
    }
  }
  return nullptr;
}

Result<std::vector<std::uint8_t>> AgentStateCodec::encodeSnapshot(const AgentState& state) {
  if (state.findings.size() > kMaxFindingsPerAgent || state.transfers.size() > 100000u) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::LimitExceeded,
                                                   "agent state exceeds the snapshot bound");
  }
  ByteWriter writer(2048);
  writer.u16(kStateFormatVersion);
  writer.string(state.target.str(), kMaxIdentifierLength);
  writer.u8(static_cast<std::uint8_t>(state.klass));
  writer.u8(static_cast<std::uint8_t>(state.guarantee));
  writer.u64(state.term.value());
  writer.opaque128(state.incarnation.bytes());
  writer.u32(state.restartCount);
  writer.u64(state.lastControllerEpoch.value());
  writer.opaque128(state.lastControllerIncarnation.bytes());
  writer.string(state.lastControllerNode.str(), kMaxIdentifierLength);
  writer.u64(state.committedGeneration.value());
  writer.digest(state.committedDigest);
  writer.string(state.committedArtifact.str(), kMaxIdentifierLength);
  writer.boolean(state.applyPrepared);
  writer.string(state.preparedDeployment.str(), kMaxIdentifierLength);
  writer.u64(state.preparedGeneration.value());
  writer.digest(state.preparedDigest);
  writer.u64(state.activations);
  writer.u64(state.duplicatesSuppressed);
  writer.u64(state.staleOffersRefused);
  writer.u64(state.digestRejections);
  writer.u64(state.applyRollbacks);
  writer.u32(static_cast<std::uint32_t>(state.transfers.size()));
  for (const auto& entry : state.transfers) {
    writeTransferRecord(writer, entry.second);
  }
  writer.u32(static_cast<std::uint32_t>(state.findings.size()));
  for (const AppliedFinding& finding : state.findings) {
    writeAppliedFinding(writer, finding);
  }
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<AgentState> AgentStateCodec::decodeSnapshot(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  AgentState state;
  CF_TRY_ASSIGN(const std::uint16_t version, reader.u16());
  if (version != kStateFormatVersion) {
    return Result<AgentState>::fail(ErrorCode::UnsupportedVersion,
                                    "agent state snapshot version is not supported",
                                    std::to_string(version));
  }
  CF_TRY_ASSIGN(const std::string target, reader.string(kMaxIdentifierLength));
  if (!target.empty()) {
    CF_TRY_ASSIGN(state.target, parseTargetId(target));
  }
  CF_TRY_ASSIGN(const std::uint8_t klass, reader.u8());
  if (klass > 2) {
    return Result<AgentState>::fail(ErrorCode::MalformedInput, "agent state has an unknown class");
  }
  state.klass = static_cast<TargetClass>(klass);
  CF_TRY_ASSIGN(const std::uint8_t guarantee, reader.u8());
  if (guarantee < 1 || guarantee > 2) {
    return Result<AgentState>::fail(ErrorCode::MalformedInput,
                                    "agent state has an unknown guarantee");
  }
  state.guarantee = static_cast<ApplyGuarantee>(guarantee);
  CF_TRY_ASSIGN(const std::uint64_t term, reader.u64());
  state.term = Term::fromValue(term);
  CF_TRY_ASSIGN(const OpaqueBytes incarnation, reader.opaque128());
  state.incarnation = IncarnationId(incarnation);
  CF_TRY_ASSIGN(state.restartCount, reader.u32());
  CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
  state.lastControllerEpoch = Epoch::fromValue(epoch);
  CF_TRY_ASSIGN(const OpaqueBytes controllerIncarnation, reader.opaque128());
  state.lastControllerIncarnation = IncarnationId(controllerIncarnation);
  CF_TRY_ASSIGN(const std::string controllerNode, reader.string(kMaxIdentifierLength));
  if (!controllerNode.empty()) {
    CF_TRY_ASSIGN(state.lastControllerNode, parseNodeId(controllerNode));
  }
  CF_TRY_ASSIGN(const std::uint64_t committed, reader.u64());
  state.committedGeneration = Generation::fromValue(committed);
  CF_TRY_ASSIGN(state.committedDigest, reader.digest());
  CF_TRY_ASSIGN(const std::string artifact, reader.string(kMaxIdentifierLength));
  if (!artifact.empty()) {
    CF_TRY_ASSIGN(state.committedArtifact, parseArtifactId(artifact));
  }
  CF_TRY_ASSIGN(state.applyPrepared, reader.boolean());
  CF_TRY_ASSIGN(const std::string preparedDeployment, reader.string(kMaxIdentifierLength));
  if (!preparedDeployment.empty()) {
    CF_TRY_ASSIGN(state.preparedDeployment, parseDeploymentId(preparedDeployment));
  }
  CF_TRY_ASSIGN(const std::uint64_t preparedGeneration, reader.u64());
  state.preparedGeneration = Generation::fromValue(preparedGeneration);
  CF_TRY_ASSIGN(state.preparedDigest, reader.digest());
  CF_TRY_ASSIGN(state.activations, reader.u64());
  CF_TRY_ASSIGN(state.duplicatesSuppressed, reader.u64());
  CF_TRY_ASSIGN(state.staleOffersRefused, reader.u64());
  CF_TRY_ASSIGN(state.digestRejections, reader.u64());
  CF_TRY_ASSIGN(state.applyRollbacks, reader.u64());
  CF_TRY_ASSIGN(const std::uint32_t transferCount, reader.u32());
  if (transferCount > 100000u) {
    return Result<AgentState>::fail(ErrorCode::OversizePayload,
                                    "agent state declares too many transfers");
  }
  for (std::uint32_t i = 0; i < transferCount; ++i) {
    CF_TRY_ASSIGN(TransferRecord record, readTransferRecord(reader));
    state.transfers.emplace(record.deployment, std::move(record));
  }
  CF_TRY_ASSIGN(const std::uint32_t findingCount, reader.u32());
  if (findingCount > kMaxFindingsPerAgent) {
    return Result<AgentState>::fail(ErrorCode::OversizePayload,
                                    "agent state declares too many findings");
  }
  state.findings.reserve(findingCount);
  for (std::uint32_t i = 0; i < findingCount; ++i) {
    CF_TRY_ASSIGN(AppliedFinding finding, readAppliedFinding(reader));
    state.findings.push_back(std::move(finding));
  }
  CF_TRY(reader.requireEnd());
  return Result<AgentState>::ok(std::move(state));
}

Status AgentStateCodec::apply(AgentState& state, JournalRecordType type,
                              std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  switch (type) {
    case JournalRecordType::AgentIdentity: {
      CF_TRY_ASSIGN(const std::string target, reader.string(kMaxIdentifierLength));
      CF_TRY_ASSIGN(state.target, parseTargetId(target));
      CF_TRY_ASSIGN(const std::uint8_t klass, reader.u8());
      if (klass > 2) {
        return Status::fail(ErrorCode::MalformedInput, "agent identity has an unknown class");
      }
      state.klass = static_cast<TargetClass>(klass);
      CF_TRY_ASSIGN(const std::uint8_t guarantee, reader.u8());
      if (guarantee < 1 || guarantee > 2) {
        return Status::fail(ErrorCode::MalformedInput, "agent identity has an unknown guarantee");
      }
      state.guarantee = static_cast<ApplyGuarantee>(guarantee);
      CF_TRY_ASSIGN(const std::uint64_t term, reader.u64());
      if (term == 0) {
        return Status::fail(ErrorCode::MalformedInput, "agent identity carries the unset term 0");
      }
      state.term = Term::fromValue(term);
      CF_TRY_ASSIGN(const OpaqueBytes incarnation, reader.opaque128());
      state.incarnation = IncarnationId(incarnation);
      CF_TRY_ASSIGN(state.restartCount, reader.u32());
      break;
    }
    case JournalRecordType::AgentControllerFence: {
      CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
      state.lastControllerEpoch = Epoch::fromValue(epoch);
      CF_TRY_ASSIGN(const OpaqueBytes incarnation, reader.opaque128());
      state.lastControllerIncarnation = IncarnationId(incarnation);
      CF_TRY_ASSIGN(const std::string node, reader.string(kMaxIdentifierLength));
      if (!node.empty()) {
        CF_TRY_ASSIGN(state.lastControllerNode, parseNodeId(node));
      }
      break;
    }
    case JournalRecordType::AgentTargetCommit: {
      CF_TRY_ASSIGN(const std::uint64_t generation, reader.u64());
      state.committedGeneration = Generation::fromValue(generation);
      CF_TRY_ASSIGN(state.committedDigest, reader.digest());
      CF_TRY_ASSIGN(const std::string artifact, reader.string(kMaxIdentifierLength));
      if (!artifact.empty()) {
        CF_TRY_ASSIGN(state.committedArtifact, parseArtifactId(artifact));
      }
      break;
    }
    case JournalRecordType::AgentTransferUpsert: {
      CF_TRY_ASSIGN(TransferRecord record, readTransferRecord(reader));
      state.transfers[record.deployment] = std::move(record);
      break;
    }
    case JournalRecordType::AgentTransferRemove: {
      CF_TRY_ASSIGN(const std::string deployment, reader.string(kMaxIdentifierLength));
      CF_TRY_ASSIGN(const DeploymentId id, parseDeploymentId(deployment));
      state.transfers.erase(id);
      break;
    }
    case JournalRecordType::AgentFindingUpsert: {
      CF_TRY_ASSIGN(AppliedFinding finding, readAppliedFinding(reader));
      bool replaced = false;
      for (AppliedFinding& existing : state.findings) {
        if (existing.key == finding.key && existing.digest == finding.digest) {
          existing = finding;
          replaced = true;
          break;
        }
      }
      if (!replaced) {
        if (state.findings.size() >= kMaxFindingsPerAgent) {
          // Bounded: the oldest finding is dropped so the table cannot grow
          // without limit. Dropping only ever loses duplicate-suppression
          // evidence for a generation that has already been superseded.
          state.findings.erase(state.findings.begin());
        }
        state.findings.push_back(std::move(finding));
      }
      break;
    }
    case JournalRecordType::AgentApplyPrepared: {
      CF_TRY_ASSIGN(const std::string deployment, reader.string(kMaxIdentifierLength));
      CF_TRY_ASSIGN(state.preparedDeployment, parseDeploymentId(deployment));
      CF_TRY_ASSIGN(const std::uint64_t generation, reader.u64());
      state.preparedGeneration = Generation::fromValue(generation);
      CF_TRY_ASSIGN(state.preparedDigest, reader.digest());
      state.applyPrepared = true;
      break;
    }
    case JournalRecordType::AgentApplyResolved: {
      state.applyPrepared = false;
      state.preparedDeployment = DeploymentId{};
      state.preparedGeneration = Generation{};
      state.preparedDigest = Digest{};
      CF_TRY_ASSIGN(const std::uint64_t activations, reader.u64());
      state.activations = activations;
      break;
    }
    case JournalRecordType::AgentRollbackNote: {
      CF_TRY_ASSIGN(state.applyRollbacks, reader.u64());
      CF_TRY_ASSIGN(state.duplicatesSuppressed, reader.u64());
      CF_TRY_ASSIGN(state.staleOffersRefused, reader.u64());
      CF_TRY_ASSIGN(state.digestRejections, reader.u64());
      break;
    }
    case JournalRecordType::Note: {
      CF_TRY_ASSIGN(const std::string text, reader.string(kMaxNoteBytes));
      (void)text;
      break;
    }
    default:
      return Status::fail(ErrorCode::UnexpectedMessage,
                          "record type is not valid for agent state",
                          std::string(journalRecordTypeName(type)));
  }
  CF_TRY(reader.requireEnd());
  return Status::ok();
}

}  // namespace cf
