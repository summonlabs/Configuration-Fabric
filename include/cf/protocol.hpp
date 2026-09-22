// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Distribution protocol messages.
//
// Every message is an explicit struct with a bounded encoder and a strict
// decoder. The decoder rejects trailing bytes, unknown enumerators, oversized
// fields and unbounded collections; a malformed message can therefore never turn
// into plausible state.
//
// Peer identity is authenticated with an HMAC-SHA256 challenge/response over the
// encoded handshake payload itself:
//
//   controller -> agent   HELLO         (authTag = HMAC(key, hello bytes with a
//                                        zero tag))
//   agent      -> controller HELLO_ACK   (authTag covers the whole ack payload)
//   controller -> agent   HELLO_CONFIRM (authTag covers the ack bytes, which
//                                        proves the controller saw this exact
//                                        agent incarnation and nonce)
//
// The tag is always the final 32 bytes of the payload and is zeroed before the
// HMAC is computed, so producer and verifier hash identical bytes. A session
// that fails either direction is rejected with AuthReject and closed.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "cf/digest.hpp"
#include "cf/frame.hpp"
#include "cf/ids.hpp"
#include "cf/lifecycle.hpp"
#include "cf/result.hpp"

namespace cf {

inline constexpr std::size_t kAuthTagBytes = kSha256Bytes;
inline constexpr std::size_t kMaxMessageDetailBytes = 256;
inline constexpr std::size_t kMaxTransfersInReport = 64;
inline constexpr std::size_t kMaxFindingsInReport = 64;
inline constexpr std::size_t kMaxChunkPayloadBytes = kAbsoluteMaxPayloadBytes / 2;

/// Capability bits advertised during the handshake.
inline constexpr std::uint32_t kCapabilityAtomicApply = 1u << 0;
inline constexpr std::uint32_t kCapabilityPrepareCommit = 1u << 1;
inline constexpr std::uint32_t kCapabilityReconcile = 1u << 2;
inline constexpr std::uint32_t kCapabilityResumeTransfer = 1u << 3;
inline constexpr std::uint32_t kCapabilityRetire = 1u << 4;
inline constexpr std::uint32_t kCapabilityKnownMask = 0x1Fu;

[[nodiscard]] std::uint32_t capabilitiesFor(ApplyGuarantee guarantee) noexcept;
[[nodiscard]] bool capabilitySupportsGuarantee(std::uint32_t capabilities,
                                               ApplyGuarantee guarantee) noexcept;
[[nodiscard]] std::string renderCapabilities(std::uint32_t capabilities);

// ---------------------------------------------------------------------------
// Session establishment
// ---------------------------------------------------------------------------

struct HelloMessage {
  NodeId nodeId;
  Epoch epoch;
  IncarnationId incarnation;
  SessionNonce nonce;
  std::uint16_t minWireVersion{kWireVersion};
  std::uint16_t maxWireVersion{kWireVersion};
  std::uint32_t maxPayloadBytes{kDefaultMaxPayloadBytes};
  std::uint32_t capabilities{kCapabilityKnownMask};
  Sha256Digest authTag{};
};

struct HelloAckMessage {
  std::uint16_t wireVersion{kWireVersion};
  TargetId target;
  TargetClass targetClass{TargetClass::Unspecified};
  ApplyGuarantee guarantee{ApplyGuarantee::AtomicActivate};
  Term term;
  IncarnationId incarnation;
  SessionNonce nonce;
  std::uint32_t maxPayloadBytes{kDefaultMaxPayloadBytes};
  std::uint32_t capabilities{kCapabilityKnownMask};
  Generation committedGeneration;
  Digest committedDigest;
  ArtifactId committedArtifact;
  std::uint32_t restartCount{0};
  Sha256Digest authTag{};
};

struct HelloConfirmMessage {
  Sha256Digest authTag{};
};

struct AuthRejectMessage {
  ErrorCode code{ErrorCode::Unauthenticated};
  std::string detail;
};

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

struct PrepareMessage {
  DeploymentId deployment;
  ConfigKey key;
  ArtifactId artifact;
  Generation generation;
  Digest digest;
  std::uint64_t sizeBytes{0};
  SchemaId schema;
  SchemaVersion schemaVersion;
  GuaranteeRequirement requirement{GuaranteeRequirement::RequireAtomic};
  ApplyGuarantee guarantee{ApplyGuarantee::AtomicActivate};
  Epoch authorityEpoch;
  AttemptId attempt;
  StreamId stream;
  std::uint32_t chunkBytes{0};
  /// Zero for a fresh transfer; otherwise the byte offset the target should
  /// receive next. The target's own answer is authoritative.
  std::uint64_t resumeFromOffset{0};
};

struct PrepareAckMessage {
  DeploymentId deployment;
  StreamId stream;
  std::uint64_t resumeFromOffset{0};
  Generation committedGeneration;
  Digest committedDigest;
  /// The target already recorded a terminal outcome for this exact
  /// (key, generation, digest). The distributor must adopt it, not re-apply.
  bool duplicateSuppressed{false};
  DeliveryState priorState{DeliveryState::Prepared};
  Generation priorGeneration;
  Digest priorDigest;
};

struct PrepareRejectMessage {
  DeploymentId deployment;
  ErrorCode code{ErrorCode::Ok};
  std::string detail;
  DeliveryState observedState{DeliveryState::Prepared};
  Generation committedGeneration;
};

struct ChunkMessage {
  StreamId stream;
  Sequence sequence;
  std::uint64_t offset{0};
  std::vector<std::uint8_t> data;
};

struct ChunkAckMessage {
  StreamId stream;
  Sequence sequence;
  ErrorCode code{ErrorCode::Ok};
  /// Cumulative bytes the target has durably accepted for this stream. This is
  /// what makes a resumed transfer safe: the target's number, not the sender's.
  std::uint64_t bytesReceived{0};
  std::string detail;
};

struct TransferCompleteMessage {
  DeploymentId deployment;
  StreamId stream;
  Digest digest;
  std::uint64_t sizeBytes{0};
};

struct TransferResultMessage {
  DeploymentId deployment;
  StreamId stream;
  bool verified{false};
  std::uint64_t bytesReceived{0};
  ErrorCode code{ErrorCode::Ok};
  std::string detail;
};

struct StageMessage {
  DeploymentId deployment;
  StreamId stream;
  Generation generation;
  Digest digest;
};

struct StageAckMessage {
  DeploymentId deployment;
  bool staged{false};
  ErrorCode code{ErrorCode::Ok};
  std::string detail;
};

struct ApplyPrepareMessage {
  DeploymentId deployment;
  Generation generation;
  Digest digest;
};

struct ApplyPrepareAckMessage {
  DeploymentId deployment;
  /// True when the target has entered its prepare window and is holding
  /// resources for the commit.
  bool prepared{false};
  ErrorCode code{ErrorCode::Ok};
  std::string detail;
};

struct ApplyCommitMessage {
  DeploymentId deployment;
  Generation generation;
  Digest digest;
};

struct ApplyCommitAckMessage {
  DeploymentId deployment;
  bool committed{false};
  DeliveryState state{DeliveryState::Staged};
  Generation committedGeneration;
  Digest committedDigest;
  ErrorCode code{ErrorCode::Ok};
  std::string detail;
};

struct ApplyAbortMessage {
  DeploymentId deployment;
  Generation generation;
  std::string reason;
};

struct ApplyAbortAckMessage {
  DeploymentId deployment;
  bool aborted{false};
  ErrorCode code{ErrorCode::Ok};
  std::string detail;
};

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

struct DeliveryAckMessage {
  DeploymentId deployment;
  ConfigKey key;
  Generation generation;
  Digest digest;
  ArtifactId artifact;
  /// The lifecycle boundary the target actually reached. The distributor maps
  /// this value through its own transition table; a target cannot promote a
  /// delivery past what it can prove.
  DeliveryState state{DeliveryState::Applied};
  Term term;
  IncarnationId incarnation;
  Epoch authorityEpoch;
  ApplyGuarantee guarantee{ApplyGuarantee::AtomicActivate};
  std::uint64_t bytesTransferred{0};
  std::int64_t targetTimestampMillis{0};
  bool evidenceFromReconcile{false};
};

struct DeliveryNackMessage {
  DeploymentId deployment;
  ConfigKey key;
  Generation generation;
  Digest digest;
  ErrorCode code{ErrorCode::Ok};
  RetryDirective directive{RetryDirective::DoNotRetry};
  Term term;
  IncarnationId incarnation;
  std::string detail;
};

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

struct ReconcileRequestMessage {
  NodeId nodeId;
  Epoch epoch;
  IncarnationId incarnation;
  std::uint32_t maxFindings{kMaxFindingsInReport};
};

struct TransferStatusRecord {
  DeploymentId deployment;
  StreamId stream;
  ConfigKey key;
  Generation generation;
  Digest digest;
  std::uint64_t bytesReceived{0};
  std::uint64_t totalBytes{0};
  bool verified{false};
  bool staged{false};
};

/// One activation outcome reported during reconciliation. The durable record of
/// the same name lives in cf/state.hpp; this is its wire projection.
struct ReconcileFinding {
  ConfigKey key;
  Generation generation;
  Digest digest;
  ArtifactId artifact;
  DeploymentId deployment;
  DeliveryState state{DeliveryState::Applied};
  std::int64_t recordedAtMillis{0};
};

struct ReconcileReportMessage {
  TargetId target;
  TargetClass targetClass{TargetClass::Unspecified};
  ApplyGuarantee guarantee{ApplyGuarantee::AtomicActivate};
  Term term;
  IncarnationId incarnation;
  Generation committedGeneration;
  Digest committedDigest;
  ArtifactId committedArtifact;
  /// True when the target holds an unresolved prepare/commit window. The
  /// distributor must resolve it before it may treat the target's state as
  /// settled.
  bool applyPrepared{false};
  DeploymentId preparedDeployment;
  Generation preparedGeneration;
  Digest preparedDigest;
  std::uint32_t restartCount{0};
  /// Unresolved prepare windows this target has had to abort. Non-zero is the
  /// observable cost of a weaker activation contract.
  std::uint32_t applyRollbacks{0};
  std::vector<TransferStatusRecord> transfers;
  std::vector<ReconcileFinding> findings;
};

// ---------------------------------------------------------------------------
// Control and teardown
// ---------------------------------------------------------------------------

struct RetireMessage {
  DeploymentId deployment;
  Generation generation;
  std::string reason;
};

struct RetireAckMessage {
  DeploymentId deployment;
  bool retired{false};
};

struct PingMessage {
  std::uint64_t nonce{0};
};

struct PongMessage {
  std::uint64_t nonce{0};
};

struct GoodbyeMessage {
  ErrorCode code{ErrorCode::Ok};
  std::string reason;
};

struct ErrorMessage {
  ErrorCode code{ErrorCode::Ok};
  RetryDirective directive{RetryDirective::DoNotRetry};
  std::string detail;
};

// ---------------------------------------------------------------------------
// Inspection control channel
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMaxControlCommandBytes = 32;
inline constexpr std::size_t kMaxControlArguments = 16;
inline constexpr std::size_t kMaxControlArgumentBytes = 512;
inline constexpr std::size_t kMaxControlBodyBytes = 512u * 1024u;

struct ControlHelloMessage {
  std::string clientName;
  SessionNonce nonce;
  Sha256Digest authTag{};
};

struct ControlHelloAckMessage {
  NodeId nodeId;
  Epoch epoch;
  IncarnationId incarnation;
  SessionNonce nonce;
  Sha256Digest authTag{};
};

struct ControlRequestMessage {
  std::string command;
  std::vector<std::string> arguments;
};

struct ControlResponseMessage {
  ErrorCode code{ErrorCode::Ok};
  std::string body;
};

[[nodiscard]] Result<std::vector<std::uint8_t>> encodeControlHello(const ControlHelloMessage&);
[[nodiscard]] Result<ControlHelloMessage> decodeControlHello(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeControlHelloAck(
    const ControlHelloAckMessage&);
[[nodiscard]] Result<ControlHelloAckMessage> decodeControlHelloAck(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeControlRequest(const ControlRequestMessage&);
[[nodiscard]] Result<ControlRequestMessage> decodeControlRequest(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeControlResponse(
    const ControlResponseMessage&);
[[nodiscard]] Result<ControlResponseMessage> decodeControlResponse(std::span<const std::uint8_t>);

// ---------------------------------------------------------------------------
// Codecs. Every decode validates field bounds, enum ranges and trailing bytes.
// ---------------------------------------------------------------------------

[[nodiscard]] Result<std::vector<std::uint8_t>> encodeHello(const HelloMessage& message);
[[nodiscard]] Result<HelloMessage> decodeHello(std::span<const std::uint8_t> payload);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeHelloAck(const HelloAckMessage& message);
[[nodiscard]] Result<HelloAckMessage> decodeHelloAck(std::span<const std::uint8_t> payload);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeHelloConfirm(const HelloConfirmMessage&);
[[nodiscard]] Result<HelloConfirmMessage> decodeHelloConfirm(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeAuthReject(const AuthRejectMessage&);
[[nodiscard]] Result<AuthRejectMessage> decodeAuthReject(std::span<const std::uint8_t>);

[[nodiscard]] Result<std::vector<std::uint8_t>> encodePrepare(const PrepareMessage&);
[[nodiscard]] Result<PrepareMessage> decodePrepare(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodePrepareAck(const PrepareAckMessage&);
[[nodiscard]] Result<PrepareAckMessage> decodePrepareAck(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodePrepareReject(const PrepareRejectMessage&);
[[nodiscard]] Result<PrepareRejectMessage> decodePrepareReject(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeChunk(const ChunkMessage&);
[[nodiscard]] Result<ChunkMessage> decodeChunk(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeChunkAck(const ChunkAckMessage&);
[[nodiscard]] Result<ChunkAckMessage> decodeChunkAck(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeTransferComplete(
    const TransferCompleteMessage&);
[[nodiscard]] Result<TransferCompleteMessage> decodeTransferComplete(
    std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeTransferResult(const TransferResultMessage&);
[[nodiscard]] Result<TransferResultMessage> decodeTransferResult(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeStage(const StageMessage&);
[[nodiscard]] Result<StageMessage> decodeStage(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeStageAck(const StageAckMessage&);
[[nodiscard]] Result<StageAckMessage> decodeStageAck(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeApplyPrepare(const ApplyPrepareMessage&);
[[nodiscard]] Result<ApplyPrepareMessage> decodeApplyPrepare(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeApplyPrepareAck(
    const ApplyPrepareAckMessage&);
[[nodiscard]] Result<ApplyPrepareAckMessage> decodeApplyPrepareAck(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeApplyCommit(const ApplyCommitMessage&);
[[nodiscard]] Result<ApplyCommitMessage> decodeApplyCommit(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeApplyCommitAck(
    const ApplyCommitAckMessage&);
[[nodiscard]] Result<ApplyCommitAckMessage> decodeApplyCommitAck(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeApplyAbort(const ApplyAbortMessage&);
[[nodiscard]] Result<ApplyAbortMessage> decodeApplyAbort(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeApplyAbortAck(const ApplyAbortAckMessage&);
[[nodiscard]] Result<ApplyAbortAckMessage> decodeApplyAbortAck(std::span<const std::uint8_t>);

[[nodiscard]] Result<std::vector<std::uint8_t>> encodeDeliveryAck(const DeliveryAckMessage&);
[[nodiscard]] Result<DeliveryAckMessage> decodeDeliveryAck(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeDeliveryNack(const DeliveryNackMessage&);
[[nodiscard]] Result<DeliveryNackMessage> decodeDeliveryNack(std::span<const std::uint8_t>);

[[nodiscard]] Result<std::vector<std::uint8_t>> encodeReconcileRequest(
    const ReconcileRequestMessage&);
[[nodiscard]] Result<ReconcileRequestMessage> decodeReconcileRequest(
    std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeReconcileReport(
    const ReconcileReportMessage&);
[[nodiscard]] Result<ReconcileReportMessage> decodeReconcileReport(std::span<const std::uint8_t>);

[[nodiscard]] Result<std::vector<std::uint8_t>> encodeRetire(const RetireMessage&);
[[nodiscard]] Result<RetireMessage> decodeRetire(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeRetireAck(const RetireAckMessage&);
[[nodiscard]] Result<RetireAckMessage> decodeRetireAck(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodePing(const PingMessage&);
[[nodiscard]] Result<PingMessage> decodePing(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodePong(const PongMessage&);
[[nodiscard]] Result<PongMessage> decodePong(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeGoodbye(const GoodbyeMessage&);
[[nodiscard]] Result<GoodbyeMessage> decodeGoodbye(std::span<const std::uint8_t>);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeError(const ErrorMessage&);
[[nodiscard]] Result<ErrorMessage> decodeError(std::span<const std::uint8_t>);

// ---------------------------------------------------------------------------
// Authentication helpers
// ---------------------------------------------------------------------------

/// Appends the HMAC over the payload (with a zero tag) into the final 32 bytes.
/// The payload must already contain a zeroed tag field of exactly 32 bytes.
[[nodiscard]] Status sealAuthenticated(std::vector<std::uint8_t>& payload, const HmacKey& key);

/// Verifies a sealed payload in constant time. The payload is not modified.
[[nodiscard]] Status verifyAuthenticated(std::span<const std::uint8_t> payload, const HmacKey& key);

/// Renders a message type and its salient identity for logs. Deterministic.
[[nodiscard]] std::string renderMessageSummary(FrameType type, std::span<const std::uint8_t> payload);

}  // namespace cf
