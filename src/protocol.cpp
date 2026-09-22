// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/protocol.hpp"

#include <array>
#include <string>

#include "cf/codec.hpp"
#include "cf/contract.hpp"
#include "cf/hash.hpp"

namespace cf {
namespace {

/// Alias so that a comma-free type name can appear inside CF_TRY_ASSIGN.
using OpaqueBytes = std::array<std::uint8_t, 16>;

[[nodiscard]] bool isValidErrorCode(std::uint16_t raw) noexcept {
  return errorCodeName(static_cast<ErrorCode>(raw)) != "Unknown";
}

template <class E, class Validator>
[[nodiscard]] Result<E> readEnum8(ByteReader& reader, Validator validator) {
  CF_TRY_ASSIGN(const std::uint8_t raw, reader.u8());
  if (!validator(raw)) {
    return Result<E>::fail(ErrorCode::MalformedInput, "message carries an unknown enumerator",
                           std::to_string(raw));
  }
  return Result<E>::ok(static_cast<E>(raw));
}

[[nodiscard]] Result<ErrorCode> readErrorCode(ByteReader& reader) {
  CF_TRY_ASSIGN(const std::uint16_t raw, reader.u16());
  if (!isValidErrorCode(raw)) {
    return Result<ErrorCode>::fail(ErrorCode::MalformedInput,
                                   "message carries an unknown error code", std::to_string(raw));
  }
  return Result<ErrorCode>::ok(static_cast<ErrorCode>(raw));
}

[[nodiscard]] Result<DeliveryState> readDeliveryState(ByteReader& reader) {
  return readEnum8<DeliveryState>(reader, [](std::uint8_t raw) { return raw >= 1 && raw <= 10; });
}

[[nodiscard]] Result<TargetClass> readTargetClass(ByteReader& reader) {
  return readEnum8<TargetClass>(reader, [](std::uint8_t raw) { return raw <= 2; });
}

[[nodiscard]] Result<ApplyGuarantee> readApplyGuarantee(ByteReader& reader) {
  return readEnum8<ApplyGuarantee>(reader, [](std::uint8_t raw) { return raw >= 1 && raw <= 2; });
}

[[nodiscard]] Result<GuaranteeRequirement> readGuaranteeRequirement(ByteReader& reader) {
  return readEnum8<GuaranteeRequirement>(reader,
                                         [](std::uint8_t raw) { return raw >= 1 && raw <= 2; });
}

[[nodiscard]] Result<RetryDirective> readRetryDirective(ByteReader& reader) {
  return readEnum8<RetryDirective>(reader, [](std::uint8_t raw) { return raw <= 5; });
}

[[nodiscard]] Result<TargetId> readTargetId(ByteReader& reader) {
  CF_TRY_ASSIGN(const std::string text, reader.string(kMaxIdentifierLength));
  return parseTargetId(text);
}

[[nodiscard]] Result<ConfigKey> readConfigKey(ByteReader& reader) {
  CF_TRY_ASSIGN(const std::string text, reader.string(kMaxIdentifierLength));
  return parseConfigKey(text);
}

[[nodiscard]] Result<ArtifactId> readArtifactId(ByteReader& reader) {
  CF_TRY_ASSIGN(const std::string text, reader.string(kMaxIdentifierLength));
  return parseArtifactId(text);
}

/// Reads an artifact identity that is allowed to be absent: a target that has
/// committed nothing yet legitimately reports an empty artifact id, and that is
/// not a protocol error.
[[nodiscard]] Result<ArtifactId> readOptionalArtifactId(ByteReader& reader) {
  CF_TRY_ASSIGN(const std::string text, reader.string(kMaxIdentifierLength));
  if (text.empty()) {
    return Result<ArtifactId>::ok(ArtifactId{});
  }
  return parseArtifactId(text);
}

[[nodiscard]] Result<DeploymentId> readDeploymentId(ByteReader& reader) {
  CF_TRY_ASSIGN(const std::string text, reader.string(kMaxIdentifierLength));
  return parseDeploymentId(text);
}

/// Reads a deployment identity that is allowed to be absent, as in a reconcile
/// report from a target with no prepare window open.
[[nodiscard]] Result<DeploymentId> readOptionalDeploymentId(ByteReader& reader) {
  CF_TRY_ASSIGN(const std::string text, reader.string(kMaxIdentifierLength));
  if (text.empty()) {
    return Result<DeploymentId>::ok(DeploymentId{});
  }
  return parseDeploymentId(text);
}

[[nodiscard]] Result<NodeId> readNodeId(ByteReader& reader) {
  CF_TRY_ASSIGN(const std::string text, reader.string(kMaxIdentifierLength));
  return parseNodeId(text);
}

[[nodiscard]] Result<SchemaId> readSchemaId(ByteReader& reader) {
  CF_TRY_ASSIGN(const std::string text, reader.string(kMaxIdentifierLength));
  return parseSchemaId(text);
}

[[nodiscard]] Result<Generation> readGeneration(ByteReader& reader) {
  CF_TRY_ASSIGN(const std::uint64_t raw, reader.u64());
  if (raw == 0) {
    return Result<Generation>::fail(ErrorCode::MalformedInput,
                                    "message carries the unset generation 0");
  }
  return Result<Generation>::ok(Generation::fromValue(raw));
}

[[nodiscard]] Result<Generation> readOptionalGeneration(ByteReader& reader) {
  CF_TRY_ASSIGN(const std::uint64_t raw, reader.u64());
  return Result<Generation>::ok(Generation::fromValue(raw));
}

[[nodiscard]] Result<Digest> readDigestField(ByteReader& reader) { return reader.digest(); }

[[nodiscard]] Result<IncarnationId> readIncarnation(ByteReader& reader) {
  CF_TRY_ASSIGN(const OpaqueBytes raw, reader.opaque128());
  return Result<IncarnationId>::ok(IncarnationId(raw));
}

[[nodiscard]] Result<SessionNonce> readNonce(ByteReader& reader) {
  CF_TRY_ASSIGN(const OpaqueBytes raw, reader.opaque128());
  return Result<SessionNonce>::ok(SessionNonce(raw));
}

void writeDeploymentId(ByteWriter& writer, const DeploymentId& id) {
  writer.string(id.str(), kMaxIdentifierLength);
}

void writeConfigKey(ByteWriter& writer, const ConfigKey& key) {
  writer.string(key.str(), kMaxIdentifierLength);
}

void writeArtifactId(ByteWriter& writer, const ArtifactId& id) {
  writer.string(id.str(), kMaxIdentifierLength);
}

void writeDetail(ByteWriter& writer, const std::string& detail) {
  writer.string(detail, kMaxMessageDetailBytes);
}

[[nodiscard]] Status checkDetail(const std::string& detail) {
  if (detail.size() > kMaxMessageDetailBytes) {
    return Status::fail(ErrorCode::LimitExceeded, "message detail exceeds its bound",
                        std::to_string(detail.size()));
  }
  return Status::ok();
}

}  // namespace

std::uint32_t capabilitiesFor(ApplyGuarantee guarantee) noexcept {
  std::uint32_t capabilities =
      kCapabilityReconcile | kCapabilityResumeTransfer | kCapabilityRetire;
  switch (guarantee) {
    case ApplyGuarantee::AtomicActivate:
      capabilities |= kCapabilityAtomicApply;
      break;
    case ApplyGuarantee::PrepareCommitAbort:
      capabilities |= kCapabilityPrepareCommit;
      break;
  }
  return capabilities;
}

bool capabilitySupportsGuarantee(std::uint32_t capabilities, ApplyGuarantee guarantee) noexcept {
  switch (guarantee) {
    case ApplyGuarantee::AtomicActivate:
      return (capabilities & kCapabilityAtomicApply) != 0;
    case ApplyGuarantee::PrepareCommitAbort:
      return (capabilities & kCapabilityPrepareCommit) != 0;
  }
  return false;
}

std::string renderCapabilities(std::uint32_t capabilities) {
  std::string out;
  const auto append = [&out](const char* name) {
    if (!out.empty()) {
      out.push_back(',');
    }
    out.append(name);
  };
  if ((capabilities & kCapabilityAtomicApply) != 0) {
    append("atomic-apply");
  }
  if ((capabilities & kCapabilityPrepareCommit) != 0) {
    append("prepare-commit-abort");
  }
  if ((capabilities & kCapabilityReconcile) != 0) {
    append("reconcile");
  }
  if ((capabilities & kCapabilityResumeTransfer) != 0) {
    append("resume-transfer");
  }
  if ((capabilities & kCapabilityRetire) != 0) {
    append("retire");
  }
  if (out.empty()) {
    out = "none";
  }
  return out;
}

// --- Session establishment -------------------------------------------------

Result<std::vector<std::uint8_t>> encodeHello(const HelloMessage& message) {
  if (message.minWireVersion > message.maxWireVersion) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::InvalidArgument,
                                                   "hello version range is inverted");
  }
  ByteWriter writer(256);
  writer.string(message.nodeId.str(), kMaxIdentifierLength);
  writer.u64(message.epoch.value());
  writer.opaque128(message.incarnation.bytes());
  writer.opaque128(message.nonce.bytes());
  writer.u16(message.minWireVersion);
  writer.u16(message.maxWireVersion);
  writer.u32(message.maxPayloadBytes);
  writer.u32(message.capabilities);
  writer.sha256(message.authTag);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<HelloMessage> decodeHello(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  HelloMessage message;
  CF_TRY_ASSIGN(message.nodeId, readNodeId(reader));
  CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
  message.epoch = Epoch::fromValue(epoch);
  CF_TRY_ASSIGN(message.incarnation, readIncarnation(reader));
  CF_TRY_ASSIGN(message.nonce, readNonce(reader));
  CF_TRY_ASSIGN(message.minWireVersion, reader.u16());
  CF_TRY_ASSIGN(message.maxWireVersion, reader.u16());
  CF_TRY_ASSIGN(message.maxPayloadBytes, reader.u32());
  CF_TRY_ASSIGN(message.capabilities, reader.u32());
  CF_TRY_ASSIGN(message.authTag, reader.sha256());
  CF_TRY(reader.requireEnd());
  if (message.minWireVersion > message.maxWireVersion) {
    return Result<HelloMessage>::fail(ErrorCode::ProtocolViolation,
                                      "hello advertises an inverted version range");
  }
  if ((message.capabilities & ~kCapabilityKnownMask) != 0) {
    return Result<HelloMessage>::fail(ErrorCode::CapabilityMismatch,
                                      "hello advertises unknown capability bits");
  }
  if (message.maxPayloadBytes == 0 || message.maxPayloadBytes > kAbsoluteMaxPayloadBytes) {
    return Result<HelloMessage>::fail(ErrorCode::OversizePayload,
                                      "hello advertises an out-of-range payload ceiling");
  }
  return Result<HelloMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeHelloAck(const HelloAckMessage& message) {
  ByteWriter writer(320);
  writer.u16(message.wireVersion);
  writer.string(message.target.str(), kMaxIdentifierLength);
  writer.u8(static_cast<std::uint8_t>(message.targetClass));
  writer.u8(static_cast<std::uint8_t>(message.guarantee));
  writer.u64(message.term.value());
  writer.opaque128(message.incarnation.bytes());
  writer.opaque128(message.nonce.bytes());
  writer.u32(message.maxPayloadBytes);
  writer.u32(message.capabilities);
  writer.u64(message.committedGeneration.value());
  writer.digest(message.committedDigest);
  writer.string(message.committedArtifact.str(), kMaxIdentifierLength);
  writer.u32(message.restartCount);
  writer.sha256(message.authTag);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<HelloAckMessage> decodeHelloAck(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  HelloAckMessage message;
  CF_TRY_ASSIGN(message.wireVersion, reader.u16());
  CF_TRY_ASSIGN(message.target, readTargetId(reader));
  CF_TRY_ASSIGN(message.targetClass, readTargetClass(reader));
  CF_TRY_ASSIGN(message.guarantee, readApplyGuarantee(reader));
  CF_TRY_ASSIGN(const std::uint64_t term, reader.u64());
  message.term = Term::fromValue(term);
  CF_TRY_ASSIGN(message.incarnation, readIncarnation(reader));
  CF_TRY_ASSIGN(message.nonce, readNonce(reader));
  CF_TRY_ASSIGN(message.maxPayloadBytes, reader.u32());
  CF_TRY_ASSIGN(message.capabilities, reader.u32());
  CF_TRY_ASSIGN(message.committedGeneration, readOptionalGeneration(reader));
  CF_TRY_ASSIGN(message.committedDigest, readDigestField(reader));
  CF_TRY_ASSIGN(message.committedArtifact, readOptionalArtifactId(reader));
  CF_TRY_ASSIGN(message.restartCount, reader.u32());
  CF_TRY_ASSIGN(message.authTag, reader.sha256());
  CF_TRY(reader.requireEnd());
  if (message.wireVersion != kWireVersion) {
    return Result<HelloAckMessage>::fail(ErrorCode::UnsupportedVersion,
                                         "hello-ack negotiated an unsupported wire version",
                                         std::to_string(message.wireVersion));
  }
  if (!message.term.isSet()) {
    return Result<HelloAckMessage>::fail(ErrorCode::ProtocolViolation,
                                         "hello-ack carries the unset term 0");
  }
  if (message.maxPayloadBytes == 0 || message.maxPayloadBytes > kAbsoluteMaxPayloadBytes) {
    return Result<HelloAckMessage>::fail(ErrorCode::OversizePayload,
                                         "hello-ack advertises an out-of-range payload ceiling");
  }
  if ((message.capabilities & ~kCapabilityKnownMask) != 0) {
    return Result<HelloAckMessage>::fail(ErrorCode::CapabilityMismatch,
                                         "hello-ack advertises unknown capability bits");
  }
  if (!capabilitySupportsGuarantee(message.capabilities, message.guarantee)) {
    return Result<HelloAckMessage>::fail(
        ErrorCode::CapabilityMismatch,
        "hello-ack advertises a guarantee its capability bits do not support");
  }
  return Result<HelloAckMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeHelloConfirm(const HelloConfirmMessage& message) {
  ByteWriter writer(kAuthTagBytes);
  writer.sha256(message.authTag);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<HelloConfirmMessage> decodeHelloConfirm(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  HelloConfirmMessage message;
  CF_TRY_ASSIGN(message.authTag, reader.sha256());
  CF_TRY(reader.requireEnd());
  return Result<HelloConfirmMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeAuthReject(const AuthRejectMessage& message) {
  CF_TRY(checkDetail(message.detail));
  ByteWriter writer(128);
  writer.u16(static_cast<std::uint16_t>(message.code));
  writeDetail(writer, message.detail);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<AuthRejectMessage> decodeAuthReject(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  AuthRejectMessage message;
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.detail, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<AuthRejectMessage>::ok(message);
}

// --- Delivery --------------------------------------------------------------

Result<std::vector<std::uint8_t>> encodePrepare(const PrepareMessage& message) {
  ByteWriter writer(256);
  writeDeploymentId(writer, message.deployment);
  writeConfigKey(writer, message.key);
  writeArtifactId(writer, message.artifact);
  writer.u64(message.generation.value());
  writer.digest(message.digest);
  writer.u64(message.sizeBytes);
  writer.string(message.schema.str(), kMaxIdentifierLength);
  writer.u32(message.schemaVersion.value());
  writer.u8(static_cast<std::uint8_t>(message.requirement));
  writer.u8(static_cast<std::uint8_t>(message.guarantee));
  writer.u64(message.authorityEpoch.value());
  writer.u64(message.attempt.value());
  writer.u64(message.stream.value());
  writer.u32(message.chunkBytes);
  writer.u64(message.resumeFromOffset);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<PrepareMessage> decodePrepare(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  PrepareMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.key, readConfigKey(reader));
  CF_TRY_ASSIGN(message.artifact, readArtifactId(reader));
  CF_TRY_ASSIGN(message.generation, readGeneration(reader));
  CF_TRY_ASSIGN(message.digest, readDigestField(reader));
  CF_TRY_ASSIGN(message.sizeBytes, reader.u64());
  CF_TRY_ASSIGN(message.schema, readSchemaId(reader));
  CF_TRY_ASSIGN(const std::uint32_t schemaVersion, reader.u32());
  message.schemaVersion = SchemaVersion::fromValue(schemaVersion);
  CF_TRY_ASSIGN(message.requirement, readGuaranteeRequirement(reader));
  CF_TRY_ASSIGN(message.guarantee, readApplyGuarantee(reader));
  CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
  message.authorityEpoch = Epoch::fromValue(epoch);
  CF_TRY_ASSIGN(const std::uint64_t attempt, reader.u64());
  message.attempt = AttemptId::fromValue(attempt);
  CF_TRY_ASSIGN(const std::uint64_t stream, reader.u64());
  message.stream = StreamId::fromValue(stream);
  CF_TRY_ASSIGN(message.chunkBytes, reader.u32());
  CF_TRY_ASSIGN(message.resumeFromOffset, reader.u64());
  CF_TRY(reader.requireEnd());
  if (!message.digest.isSet()) {
    return Result<PrepareMessage>::fail(ErrorCode::MalformedInput,
                                        "prepare carries the all-zero digest");
  }
  if (message.sizeBytes == 0) {
    return Result<PrepareMessage>::fail(ErrorCode::MalformedInput,
                                        "prepare declares an empty artifact");
  }
  if (message.chunkBytes == 0 || message.chunkBytes > kMaxChunkPayloadBytes) {
    return Result<PrepareMessage>::fail(ErrorCode::OversizePayload,
                                        "prepare declares an out-of-range chunk size");
  }
  if (!message.stream.isSet()) {
    return Result<PrepareMessage>::fail(ErrorCode::MalformedInput,
                                        "prepare carries the unset stream id 0");
  }
  if (!message.authorityEpoch.isSet()) {
    return Result<PrepareMessage>::fail(ErrorCode::MalformedInput,
                                        "prepare carries the unset authority epoch 0");
  }
  return Result<PrepareMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodePrepareAck(const PrepareAckMessage& message) {
  ByteWriter writer(200);
  writeDeploymentId(writer, message.deployment);
  writer.u64(message.stream.value());
  writer.u64(message.resumeFromOffset);
  writer.u64(message.committedGeneration.value());
  writer.digest(message.committedDigest);
  writer.boolean(message.duplicateSuppressed);
  writer.u8(static_cast<std::uint8_t>(message.priorState));
  writer.u64(message.priorGeneration.value());
  writer.digest(message.priorDigest);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<PrepareAckMessage> decodePrepareAck(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  PrepareAckMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(const std::uint64_t stream, reader.u64());
  message.stream = StreamId::fromValue(stream);
  CF_TRY_ASSIGN(message.resumeFromOffset, reader.u64());
  CF_TRY_ASSIGN(message.committedGeneration, readOptionalGeneration(reader));
  CF_TRY_ASSIGN(message.committedDigest, readDigestField(reader));
  CF_TRY_ASSIGN(message.duplicateSuppressed, reader.boolean());
  CF_TRY_ASSIGN(message.priorState, readDeliveryState(reader));
  CF_TRY_ASSIGN(message.priorGeneration, readOptionalGeneration(reader));
  CF_TRY_ASSIGN(message.priorDigest, readDigestField(reader));
  CF_TRY(reader.requireEnd());
  return Result<PrepareAckMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodePrepareReject(const PrepareRejectMessage& message) {
  CF_TRY(checkDetail(message.detail));
  ByteWriter writer(160);
  writeDeploymentId(writer, message.deployment);
  writer.u16(static_cast<std::uint16_t>(message.code));
  writeDetail(writer, message.detail);
  writer.u8(static_cast<std::uint8_t>(message.observedState));
  writer.u64(message.committedGeneration.value());
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<PrepareRejectMessage> decodePrepareReject(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  PrepareRejectMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.detail, reader.string(kMaxMessageDetailBytes));
  CF_TRY_ASSIGN(message.observedState, readDeliveryState(reader));
  CF_TRY_ASSIGN(message.committedGeneration, readOptionalGeneration(reader));
  CF_TRY(reader.requireEnd());
  return Result<PrepareRejectMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeChunk(const ChunkMessage& message) {
  if (message.data.size() > kMaxChunkPayloadBytes) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::OversizePayload,
                                                   "chunk payload exceeds the protocol maximum",
                                                   std::to_string(message.data.size()));
  }
  ByteWriter writer(message.data.size() + 64);
  writer.u64(message.stream.value());
  writer.u64(message.sequence.value());
  writer.u64(message.offset);
  writer.string(std::string_view(reinterpret_cast<const char*>(message.data.data()),
                                 message.data.size()),
                kMaxChunkPayloadBytes);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ChunkMessage> decodeChunk(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ChunkMessage message;
  CF_TRY_ASSIGN(const std::uint64_t stream, reader.u64());
  message.stream = StreamId::fromValue(stream);
  CF_TRY_ASSIGN(const std::uint64_t sequence, reader.u64());
  message.sequence = Sequence::fromValue(sequence);
  CF_TRY_ASSIGN(message.offset, reader.u64());
  CF_TRY_ASSIGN(const std::string data, reader.string(kMaxChunkPayloadBytes));
  CF_TRY(reader.requireEnd());
  message.data.reserve(data.size());
  for (const char raw : data) {
    message.data.push_back(static_cast<std::uint8_t>(raw));
  }
  if (!message.stream.isSet()) {
    return Result<ChunkMessage>::fail(ErrorCode::MalformedInput, "chunk carries the unset stream id");
  }
  if (message.data.empty()) {
    return Result<ChunkMessage>::fail(ErrorCode::MalformedInput, "chunk carries no payload");
  }
  return Result<ChunkMessage>::ok(std::move(message));
}

Result<std::vector<std::uint8_t>> encodeChunkAck(const ChunkAckMessage& message) {
  CF_TRY(checkDetail(message.detail));
  ByteWriter writer(128);
  writer.u64(message.stream.value());
  writer.u64(message.sequence.value());
  writer.u16(static_cast<std::uint16_t>(message.code));
  writer.u64(message.bytesReceived);
  writeDetail(writer, message.detail);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ChunkAckMessage> decodeChunkAck(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ChunkAckMessage message;
  CF_TRY_ASSIGN(const std::uint64_t stream, reader.u64());
  message.stream = StreamId::fromValue(stream);
  CF_TRY_ASSIGN(const std::uint64_t sequence, reader.u64());
  message.sequence = Sequence::fromValue(sequence);
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.bytesReceived, reader.u64());
  CF_TRY_ASSIGN(message.detail, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<ChunkAckMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeTransferComplete(const TransferCompleteMessage& message) {
  ByteWriter writer(96);
  writeDeploymentId(writer, message.deployment);
  writer.u64(message.stream.value());
  writer.digest(message.digest);
  writer.u64(message.sizeBytes);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<TransferCompleteMessage> decodeTransferComplete(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  TransferCompleteMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(const std::uint64_t stream, reader.u64());
  message.stream = StreamId::fromValue(stream);
  CF_TRY_ASSIGN(message.digest, readDigestField(reader));
  CF_TRY_ASSIGN(message.sizeBytes, reader.u64());
  CF_TRY(reader.requireEnd());
  return Result<TransferCompleteMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeTransferResult(const TransferResultMessage& message) {
  CF_TRY(checkDetail(message.detail));
  ByteWriter writer(160);
  writeDeploymentId(writer, message.deployment);
  writer.u64(message.stream.value());
  writer.boolean(message.verified);
  writer.u64(message.bytesReceived);
  writer.u16(static_cast<std::uint16_t>(message.code));
  writeDetail(writer, message.detail);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<TransferResultMessage> decodeTransferResult(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  TransferResultMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(const std::uint64_t stream, reader.u64());
  message.stream = StreamId::fromValue(stream);
  CF_TRY_ASSIGN(message.verified, reader.boolean());
  CF_TRY_ASSIGN(message.bytesReceived, reader.u64());
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.detail, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<TransferResultMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeStage(const StageMessage& message) {
  ByteWriter writer(96);
  writeDeploymentId(writer, message.deployment);
  writer.u64(message.stream.value());
  writer.u64(message.generation.value());
  writer.digest(message.digest);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<StageMessage> decodeStage(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  StageMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(const std::uint64_t stream, reader.u64());
  message.stream = StreamId::fromValue(stream);
  CF_TRY_ASSIGN(message.generation, readGeneration(reader));
  CF_TRY_ASSIGN(message.digest, readDigestField(reader));
  CF_TRY(reader.requireEnd());
  return Result<StageMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeStageAck(const StageAckMessage& message) {
  CF_TRY(checkDetail(message.detail));
  ByteWriter writer(144);
  writeDeploymentId(writer, message.deployment);
  writer.boolean(message.staged);
  writer.u16(static_cast<std::uint16_t>(message.code));
  writeDetail(writer, message.detail);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<StageAckMessage> decodeStageAck(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  StageAckMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.staged, reader.boolean());
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.detail, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<StageAckMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeApplyPrepare(const ApplyPrepareMessage& message) {
  ByteWriter writer(96);
  writeDeploymentId(writer, message.deployment);
  writer.u64(message.generation.value());
  writer.digest(message.digest);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ApplyPrepareMessage> decodeApplyPrepare(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ApplyPrepareMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.generation, readGeneration(reader));
  CF_TRY_ASSIGN(message.digest, readDigestField(reader));
  CF_TRY(reader.requireEnd());
  return Result<ApplyPrepareMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeApplyPrepareAck(const ApplyPrepareAckMessage& message) {
  CF_TRY(checkDetail(message.detail));
  ByteWriter writer(144);
  writeDeploymentId(writer, message.deployment);
  writer.boolean(message.prepared);
  writer.u16(static_cast<std::uint16_t>(message.code));
  writeDetail(writer, message.detail);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ApplyPrepareAckMessage> decodeApplyPrepareAck(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ApplyPrepareAckMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.prepared, reader.boolean());
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.detail, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<ApplyPrepareAckMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeApplyCommit(const ApplyCommitMessage& message) {
  ByteWriter writer(96);
  writeDeploymentId(writer, message.deployment);
  writer.u64(message.generation.value());
  writer.digest(message.digest);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ApplyCommitMessage> decodeApplyCommit(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ApplyCommitMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.generation, readGeneration(reader));
  CF_TRY_ASSIGN(message.digest, readDigestField(reader));
  CF_TRY(reader.requireEnd());
  return Result<ApplyCommitMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeApplyCommitAck(const ApplyCommitAckMessage& message) {
  CF_TRY(checkDetail(message.detail));
  ByteWriter writer(176);
  writeDeploymentId(writer, message.deployment);
  writer.boolean(message.committed);
  writer.u8(static_cast<std::uint8_t>(message.state));
  writer.u64(message.committedGeneration.value());
  writer.digest(message.committedDigest);
  writer.u16(static_cast<std::uint16_t>(message.code));
  writeDetail(writer, message.detail);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ApplyCommitAckMessage> decodeApplyCommitAck(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ApplyCommitAckMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.committed, reader.boolean());
  CF_TRY_ASSIGN(message.state, readDeliveryState(reader));
  CF_TRY_ASSIGN(message.committedGeneration, readOptionalGeneration(reader));
  CF_TRY_ASSIGN(message.committedDigest, readDigestField(reader));
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.detail, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<ApplyCommitAckMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeApplyAbort(const ApplyAbortMessage& message) {
  CF_TRY(checkDetail(message.reason));
  ByteWriter writer(128);
  writeDeploymentId(writer, message.deployment);
  writer.u64(message.generation.value());
  writeDetail(writer, message.reason);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ApplyAbortMessage> decodeApplyAbort(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ApplyAbortMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.generation, readGeneration(reader));
  CF_TRY_ASSIGN(message.reason, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<ApplyAbortMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeApplyAbortAck(const ApplyAbortAckMessage& message) {
  CF_TRY(checkDetail(message.detail));
  ByteWriter writer(144);
  writeDeploymentId(writer, message.deployment);
  writer.boolean(message.aborted);
  writer.u16(static_cast<std::uint16_t>(message.code));
  writeDetail(writer, message.detail);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ApplyAbortAckMessage> decodeApplyAbortAck(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ApplyAbortAckMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.aborted, reader.boolean());
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.detail, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<ApplyAbortAckMessage>::ok(message);
}

// --- Evidence --------------------------------------------------------------

Result<std::vector<std::uint8_t>> encodeDeliveryAck(const DeliveryAckMessage& message) {
  ByteWriter writer(224);
  writeDeploymentId(writer, message.deployment);
  writeConfigKey(writer, message.key);
  writer.u64(message.generation.value());
  writer.digest(message.digest);
  writeArtifactId(writer, message.artifact);
  writer.u8(static_cast<std::uint8_t>(message.state));
  writer.u64(message.term.value());
  writer.opaque128(message.incarnation.bytes());
  writer.u64(message.authorityEpoch.value());
  writer.u8(static_cast<std::uint8_t>(message.guarantee));
  writer.u64(message.bytesTransferred);
  writer.i64(message.targetTimestampMillis);
  writer.boolean(message.evidenceFromReconcile);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<DeliveryAckMessage> decodeDeliveryAck(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  DeliveryAckMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.key, readConfigKey(reader));
  CF_TRY_ASSIGN(message.generation, readGeneration(reader));
  CF_TRY_ASSIGN(message.digest, readDigestField(reader));
  CF_TRY_ASSIGN(message.artifact, readOptionalArtifactId(reader));
  CF_TRY_ASSIGN(message.state, readDeliveryState(reader));
  CF_TRY_ASSIGN(const std::uint64_t term, reader.u64());
  message.term = Term::fromValue(term);
  CF_TRY_ASSIGN(message.incarnation, readIncarnation(reader));
  CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
  message.authorityEpoch = Epoch::fromValue(epoch);
  CF_TRY_ASSIGN(message.guarantee, readApplyGuarantee(reader));
  CF_TRY_ASSIGN(message.bytesTransferred, reader.u64());
  CF_TRY_ASSIGN(message.targetTimestampMillis, reader.i64());
  CF_TRY_ASSIGN(message.evidenceFromReconcile, reader.boolean());
  CF_TRY(reader.requireEnd());
  if (!isActivationState(message.state)) {
    return Result<DeliveryAckMessage>::fail(
        ErrorCode::ProtocolViolation,
        "delivery-ack must report an activation state; failures use delivery-nack");
  }
  if (!message.term.isSet() || !message.incarnation.isSet()) {
    return Result<DeliveryAckMessage>::fail(ErrorCode::ProtocolViolation,
                                            "delivery-ack carries unset target authority");
  }
  return Result<DeliveryAckMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeDeliveryNack(const DeliveryNackMessage& message) {
  CF_TRY(checkDetail(message.detail));
  ByteWriter writer(224);
  writeDeploymentId(writer, message.deployment);
  writeConfigKey(writer, message.key);
  writer.u64(message.generation.value());
  writer.digest(message.digest);
  writer.u16(static_cast<std::uint16_t>(message.code));
  writer.u8(static_cast<std::uint8_t>(message.directive));
  writer.u64(message.term.value());
  writer.opaque128(message.incarnation.bytes());
  writeDetail(writer, message.detail);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<DeliveryNackMessage> decodeDeliveryNack(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  DeliveryNackMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.key, readConfigKey(reader));
  CF_TRY_ASSIGN(message.generation, readGeneration(reader));
  CF_TRY_ASSIGN(message.digest, readDigestField(reader));
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.directive, readRetryDirective(reader));
  CF_TRY_ASSIGN(const std::uint64_t term, reader.u64());
  message.term = Term::fromValue(term);
  CF_TRY_ASSIGN(message.incarnation, readIncarnation(reader));
  CF_TRY_ASSIGN(message.detail, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<DeliveryNackMessage>::ok(message);
}

// --- Reconciliation --------------------------------------------------------

Result<std::vector<std::uint8_t>> encodeReconcileRequest(const ReconcileRequestMessage& message) {
  ByteWriter writer(96);
  writer.string(message.nodeId.str(), kMaxIdentifierLength);
  writer.u64(message.epoch.value());
  writer.opaque128(message.incarnation.bytes());
  writer.u32(message.maxFindings);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ReconcileRequestMessage> decodeReconcileRequest(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ReconcileRequestMessage message;
  CF_TRY_ASSIGN(message.nodeId, readNodeId(reader));
  CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
  message.epoch = Epoch::fromValue(epoch);
  CF_TRY_ASSIGN(message.incarnation, readIncarnation(reader));
  CF_TRY_ASSIGN(message.maxFindings, reader.u32());
  CF_TRY(reader.requireEnd());
  if (!message.epoch.isSet()) {
    return Result<ReconcileRequestMessage>::fail(ErrorCode::MalformedInput,
                                                 "reconcile request carries the unset epoch 0");
  }
  if (message.maxFindings > kMaxFindingsInReport) {
    return Result<ReconcileRequestMessage>::fail(
        ErrorCode::OversizePayload, "reconcile request asks for more findings than the protocol allows");
  }
  return Result<ReconcileRequestMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeReconcileReport(const ReconcileReportMessage& message) {
  if (message.transfers.size() > kMaxTransfersInReport ||
      message.findings.size() > kMaxFindingsInReport) {
    return Result<std::vector<std::uint8_t>>::fail(
        ErrorCode::OversizePayload, "reconcile report exceeds the bound collection sizes");
  }
  ByteWriter writer(512 + (message.transfers.size() * 128) + (message.findings.size() * 128));
  writer.string(message.target.str(), kMaxIdentifierLength);
  writer.u8(static_cast<std::uint8_t>(message.targetClass));
  writer.u8(static_cast<std::uint8_t>(message.guarantee));
  writer.u64(message.term.value());
  writer.opaque128(message.incarnation.bytes());
  writer.u64(message.committedGeneration.value());
  writer.digest(message.committedDigest);
  writer.string(message.committedArtifact.str(), kMaxIdentifierLength);
  writer.boolean(message.applyPrepared);
  writeDeploymentId(writer, message.preparedDeployment);
  writer.u64(message.preparedGeneration.value());
  writer.digest(message.preparedDigest);
  writer.u32(message.restartCount);
  writer.u32(message.applyRollbacks);
  writer.u32(static_cast<std::uint32_t>(message.transfers.size()));
  for (const TransferStatusRecord& record : message.transfers) {
    writeDeploymentId(writer, record.deployment);
    writer.u64(record.stream.value());
    writeConfigKey(writer, record.key);
    writer.u64(record.generation.value());
    writer.digest(record.digest);
    writer.u64(record.bytesReceived);
    writer.u64(record.totalBytes);
    writer.boolean(record.verified);
    writer.boolean(record.staged);
  }
  writer.u32(static_cast<std::uint32_t>(message.findings.size()));
  for (const ReconcileFinding& finding : message.findings) {
    writeConfigKey(writer, finding.key);
    writer.u64(finding.generation.value());
    writer.digest(finding.digest);
    writeArtifactId(writer, finding.artifact);
    writeDeploymentId(writer, finding.deployment);
    writer.u8(static_cast<std::uint8_t>(finding.state));
    writer.i64(finding.recordedAtMillis);
  }
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ReconcileReportMessage> decodeReconcileReport(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ReconcileReportMessage message;
  CF_TRY_ASSIGN(message.target, readTargetId(reader));
  CF_TRY_ASSIGN(message.targetClass, readTargetClass(reader));
  CF_TRY_ASSIGN(message.guarantee, readApplyGuarantee(reader));
  CF_TRY_ASSIGN(const std::uint64_t term, reader.u64());
  message.term = Term::fromValue(term);
  CF_TRY_ASSIGN(message.incarnation, readIncarnation(reader));
  CF_TRY_ASSIGN(message.committedGeneration, readOptionalGeneration(reader));
  CF_TRY_ASSIGN(message.committedDigest, readDigestField(reader));
  CF_TRY_ASSIGN(message.committedArtifact, readOptionalArtifactId(reader));
  CF_TRY_ASSIGN(message.applyPrepared, reader.boolean());
  CF_TRY_ASSIGN(message.preparedDeployment, readOptionalDeploymentId(reader));
  CF_TRY_ASSIGN(message.preparedGeneration, readOptionalGeneration(reader));
  CF_TRY_ASSIGN(message.preparedDigest, readDigestField(reader));
  CF_TRY_ASSIGN(message.restartCount, reader.u32());
  CF_TRY_ASSIGN(message.applyRollbacks, reader.u32());
  CF_TRY_ASSIGN(const std::uint32_t transferCount, reader.u32());
  if (transferCount > kMaxTransfersInReport) {
    return Result<ReconcileReportMessage>::fail(ErrorCode::OversizePayload,
                                                "reconcile report declares too many transfers",
                                                std::to_string(transferCount));
  }
  message.transfers.reserve(transferCount);
  for (std::uint32_t i = 0; i < transferCount; ++i) {
    TransferStatusRecord record;
    CF_TRY_ASSIGN(record.deployment, readDeploymentId(reader));
    CF_TRY_ASSIGN(const std::uint64_t stream, reader.u64());
    record.stream = StreamId::fromValue(stream);
    CF_TRY_ASSIGN(record.key, readConfigKey(reader));
    CF_TRY_ASSIGN(record.generation, readGeneration(reader));
    CF_TRY_ASSIGN(record.digest, readDigestField(reader));
    CF_TRY_ASSIGN(record.bytesReceived, reader.u64());
    CF_TRY_ASSIGN(record.totalBytes, reader.u64());
    CF_TRY_ASSIGN(record.verified, reader.boolean());
    CF_TRY_ASSIGN(record.staged, reader.boolean());
    if (record.bytesReceived > record.totalBytes) {
      return Result<ReconcileReportMessage>::fail(
          ErrorCode::MalformedInput, "reconcile transfer reports more bytes than its total");
    }
    message.transfers.push_back(std::move(record));
  }
  CF_TRY_ASSIGN(const std::uint32_t findingCount, reader.u32());
  if (findingCount > kMaxFindingsInReport) {
    return Result<ReconcileReportMessage>::fail(ErrorCode::OversizePayload,
                                                "reconcile report declares too many findings",
                                                std::to_string(findingCount));
  }
  message.findings.reserve(findingCount);
  for (std::uint32_t i = 0; i < findingCount; ++i) {
    ReconcileFinding finding;
    CF_TRY_ASSIGN(finding.key, readConfigKey(reader));
    CF_TRY_ASSIGN(finding.generation, readGeneration(reader));
    CF_TRY_ASSIGN(finding.digest, readDigestField(reader));
    CF_TRY_ASSIGN(finding.artifact, readOptionalArtifactId(reader));
    CF_TRY_ASSIGN(finding.deployment, readDeploymentId(reader));
    CF_TRY_ASSIGN(finding.state, readDeliveryState(reader));
    CF_TRY_ASSIGN(finding.recordedAtMillis, reader.i64());
    message.findings.push_back(std::move(finding));
  }
  CF_TRY(reader.requireEnd());
  if (!message.term.isSet() || !message.incarnation.isSet()) {
    return Result<ReconcileReportMessage>::fail(ErrorCode::ProtocolViolation,
                                                "reconcile report carries unset target authority");
  }
  return Result<ReconcileReportMessage>::ok(std::move(message));
}

// --- Control and teardown --------------------------------------------------

Result<std::vector<std::uint8_t>> encodeRetire(const RetireMessage& message) {
  CF_TRY(checkDetail(message.reason));
  ByteWriter writer(128);
  writeDeploymentId(writer, message.deployment);
  writer.u64(message.generation.value());
  writeDetail(writer, message.reason);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<RetireMessage> decodeRetire(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  RetireMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.generation, readGeneration(reader));
  CF_TRY_ASSIGN(message.reason, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<RetireMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeRetireAck(const RetireAckMessage& message) {
  ByteWriter writer(80);
  writeDeploymentId(writer, message.deployment);
  writer.boolean(message.retired);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<RetireAckMessage> decodeRetireAck(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  RetireAckMessage message;
  CF_TRY_ASSIGN(message.deployment, readDeploymentId(reader));
  CF_TRY_ASSIGN(message.retired, reader.boolean());
  CF_TRY(reader.requireEnd());
  return Result<RetireAckMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodePing(const PingMessage& message) {
  ByteWriter writer(16);
  writer.u64(message.nonce);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<PingMessage> decodePing(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  PingMessage message;
  CF_TRY_ASSIGN(message.nonce, reader.u64());
  CF_TRY(reader.requireEnd());
  return Result<PingMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodePong(const PongMessage& message) {
  ByteWriter writer(16);
  writer.u64(message.nonce);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<PongMessage> decodePong(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  PongMessage message;
  CF_TRY_ASSIGN(message.nonce, reader.u64());
  CF_TRY(reader.requireEnd());
  return Result<PongMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeGoodbye(const GoodbyeMessage& message) {
  CF_TRY(checkDetail(message.reason));
  ByteWriter writer(96);
  writer.u16(static_cast<std::uint16_t>(message.code));
  writeDetail(writer, message.reason);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<GoodbyeMessage> decodeGoodbye(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  GoodbyeMessage message;
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.reason, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<GoodbyeMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeError(const ErrorMessage& message) {
  CF_TRY(checkDetail(message.detail));
  ByteWriter writer(96);
  writer.u16(static_cast<std::uint16_t>(message.code));
  writer.u8(static_cast<std::uint8_t>(message.directive));
  writeDetail(writer, message.detail);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ErrorMessage> decodeError(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ErrorMessage message;
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.directive, readRetryDirective(reader));
  CF_TRY_ASSIGN(message.detail, reader.string(kMaxMessageDetailBytes));
  CF_TRY(reader.requireEnd());
  return Result<ErrorMessage>::ok(message);
}


// --- Inspection control channel --------------------------------------------

Result<std::vector<std::uint8_t>> encodeControlHello(const ControlHelloMessage& message) {
  if (message.clientName.size() > kMaxIdentifierLength) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::LimitExceeded,
                                                   "control client name exceeds its bound");
  }
  ByteWriter writer(96);
  writer.string(message.clientName, kMaxIdentifierLength);
  writer.opaque128(message.nonce.bytes());
  writer.sha256(message.authTag);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ControlHelloMessage> decodeControlHello(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ControlHelloMessage message;
  CF_TRY_ASSIGN(message.clientName, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(const OpaqueBytes nonce, reader.opaque128());
  message.nonce = SessionNonce(nonce);
  CF_TRY_ASSIGN(message.authTag, reader.sha256());
  CF_TRY(reader.requireEnd());
  if (message.clientName.empty()) {
    return Result<ControlHelloMessage>::fail(ErrorCode::MissingField,
                                             "control client name must not be empty");
  }
  return Result<ControlHelloMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeControlHelloAck(const ControlHelloAckMessage& message) {
  ByteWriter writer(112);
  writer.string(message.nodeId.str(), kMaxIdentifierLength);
  writer.u64(message.epoch.value());
  writer.opaque128(message.incarnation.bytes());
  writer.opaque128(message.nonce.bytes());
  writer.sha256(message.authTag);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ControlHelloAckMessage> decodeControlHelloAck(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ControlHelloAckMessage message;
  CF_TRY_ASSIGN(const std::string nodeId, reader.string(kMaxIdentifierLength));
  CF_TRY_ASSIGN(message.nodeId, parseNodeId(nodeId));
  CF_TRY_ASSIGN(const std::uint64_t epoch, reader.u64());
  message.epoch = Epoch::fromValue(epoch);
  CF_TRY_ASSIGN(const OpaqueBytes incarnation, reader.opaque128());
  message.incarnation = IncarnationId(incarnation);
  CF_TRY_ASSIGN(const OpaqueBytes nonce, reader.opaque128());
  message.nonce = SessionNonce(nonce);
  CF_TRY_ASSIGN(message.authTag, reader.sha256());
  CF_TRY(reader.requireEnd());
  return Result<ControlHelloAckMessage>::ok(message);
}

Result<std::vector<std::uint8_t>> encodeControlRequest(const ControlRequestMessage& message) {
  if (message.command.empty() || message.command.size() > kMaxControlCommandBytes) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::InvalidArgument,
                                                   "control command is empty or too long");
  }
  if (message.arguments.size() > kMaxControlArguments) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::LimitExceeded,
                                                   "control request has too many arguments");
  }
  ByteWriter writer(256);
  writer.string(message.command, kMaxControlCommandBytes);
  writer.u32(static_cast<std::uint32_t>(message.arguments.size()));
  for (const std::string& argument : message.arguments) {
    if (argument.size() > kMaxControlArgumentBytes) {
      return Result<std::vector<std::uint8_t>>::fail(ErrorCode::LimitExceeded,
                                                     "control argument exceeds its bound");
    }
    writer.string(argument, kMaxControlArgumentBytes);
  }
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ControlRequestMessage> decodeControlRequest(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ControlRequestMessage message;
  CF_TRY_ASSIGN(message.command, reader.string(kMaxControlCommandBytes));
  if (message.command.empty()) {
    return Result<ControlRequestMessage>::fail(ErrorCode::MissingField,
                                               "control request has no command");
  }
  CF_TRY_ASSIGN(const std::uint32_t count, reader.u32());
  if (count > kMaxControlArguments) {
    return Result<ControlRequestMessage>::fail(ErrorCode::OversizePayload,
                                                "control request declares too many arguments");
  }
  message.arguments.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    CF_TRY_ASSIGN(const std::string argument, reader.string(kMaxControlArgumentBytes));
    message.arguments.push_back(argument);
  }
  CF_TRY(reader.requireEnd());
  return Result<ControlRequestMessage>::ok(std::move(message));
}

Result<std::vector<std::uint8_t>> encodeControlResponse(const ControlResponseMessage& message) {
  if (message.body.size() > kMaxControlBodyBytes) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::LimitExceeded,
                                                   "control response body exceeds its bound");
  }
  ByteWriter writer(message.body.size() + 32);
  writer.u16(static_cast<std::uint16_t>(message.code));
  writer.string(message.body, kMaxControlBodyBytes);
  return Result<std::vector<std::uint8_t>>::ok(writer.take());
}

Result<ControlResponseMessage> decodeControlResponse(std::span<const std::uint8_t> payload) {
  ByteReader reader(payload);
  ControlResponseMessage message;
  CF_TRY_ASSIGN(message.code, readErrorCode(reader));
  CF_TRY_ASSIGN(message.body, reader.string(kMaxControlBodyBytes));
  CF_TRY(reader.requireEnd());
  return Result<ControlResponseMessage>::ok(std::move(message));
}

// --- Authentication --------------------------------------------------------

Status sealAuthenticated(std::vector<std::uint8_t>& payload, const HmacKey& key) {
  if (payload.size() < kAuthTagBytes) {
    return Status::fail(ErrorCode::Internal,
                        "payload is too short to carry an authentication tag");
  }
  const std::size_t tagOffset = payload.size() - kAuthTagBytes;
  std::fill(payload.begin() + static_cast<std::ptrdiff_t>(tagOffset), payload.end(),
            std::uint8_t{0});
  const Sha256Digest tag =
      hmacSha256(key, std::span<const std::uint8_t>(payload.data(), payload.size()));
  std::copy(tag.begin(), tag.end(), payload.begin() + static_cast<std::ptrdiff_t>(tagOffset));
  return Status::ok();
}

Status verifyAuthenticated(std::span<const std::uint8_t> payload, const HmacKey& key) {
  if (payload.size() < kAuthTagBytes) {
    return Status::fail(ErrorCode::Unauthenticated,
                        "payload is too short to carry an authentication tag");
  }
  const std::size_t tagOffset = payload.size() - kAuthTagBytes;
  std::vector<std::uint8_t> scratch(payload.begin(), payload.end());
  std::fill(scratch.begin() + static_cast<std::ptrdiff_t>(tagOffset), scratch.end(),
            std::uint8_t{0});
  const Sha256Digest expected =
      hmacSha256(key, std::span<const std::uint8_t>(scratch.data(), scratch.size()));
  if (!constantTimeEquals(std::span<const std::uint8_t>(payload.data() + tagOffset, kAuthTagBytes),
                          std::span<const std::uint8_t>(expected.data(), expected.size()))) {
    return Status::fail(ErrorCode::Unauthenticated,
                        "peer authentication tag does not match");
  }
  return Status::ok();
}

std::string renderMessageSummary(FrameType type, std::span<const std::uint8_t> payload) {
  std::string out(frameTypeName(type));
  switch (type) {
    case FrameType::Prepare: {
      auto decoded = decodePrepare(payload);
      if (decoded) {
        out.append(" deployment=");
        out.append(decoded.value().deployment.str());
        out.append(" gen=");
        out.append(std::to_string(decoded.value().generation.value()));
        out.append(" digest=");
        out.append(shortDigest(decoded.value().digest));
      }
      break;
    }
    case FrameType::Chunk: {
      auto decoded = decodeChunk(payload);
      if (decoded) {
        out.append(" stream=");
        out.append(std::to_string(decoded.value().stream.value()));
        out.append(" seq=");
        out.append(std::to_string(decoded.value().sequence.value()));
        out.append(" offset=");
        out.append(std::to_string(decoded.value().offset));
        out.append(" bytes=");
        out.append(std::to_string(decoded.value().data.size()));
      }
      break;
    }
    case FrameType::DeliveryAck: {
      auto decoded = decodeDeliveryAck(payload);
      if (decoded) {
        out.append(" deployment=");
        out.append(decoded.value().deployment.str());
        out.append(" state=");
        out.append(deliveryStateName(decoded.value().state));
      }
      break;
    }
    case FrameType::DeliveryNack: {
      auto decoded = decodeDeliveryNack(payload);
      if (decoded) {
        out.append(" deployment=");
        out.append(decoded.value().deployment.str());
        out.append(" code=");
        out.append(errorCodeName(decoded.value().code));
      }
      break;
    }
    default:
      break;
  }
  return out;
}

}  // namespace cf
