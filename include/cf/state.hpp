// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Authoritative delivery state.
//
// Two stores exist, and the difference between them is the whole point of the
// runtime:
//
//   ControllerState - what the distributor believes each target should be
//                     running, what it has proven, and under whose authority.
//   AgentState      - what one target has actually committed locally.
//
// Neither is derived from the other by assumption. After a restart, the
// distributor's knowledge of a target is explicitly marked as not established by
// the current process, so persisted liveness is never treated as fresh, and an
// in-flight delivery is resolved by reconciliation rather than by guessing.

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cf/artifact.hpp"
#include "cf/digest.hpp"
#include "cf/ids.hpp"
#include "cf/journal.hpp"
#include "cf/lifecycle.hpp"
#include "cf/plan.hpp"
#include "cf/result.hpp"
#include "cf/store.hpp"

namespace cf {

inline constexpr std::uint16_t kStateFormatVersion = 1;
inline constexpr std::size_t kMaxDeliveryDetailBytes = 192;
inline constexpr std::size_t kMaxEndpointBytes = 128;

// ---------------------------------------------------------------------------
// Controller (distributor) state
// ---------------------------------------------------------------------------

/// What the distributor knows about one target. Every field is either supplied
/// by upstream, proven by a live session, or absent.
struct TargetRuntime {
  TargetId id;
  TargetClass klass{TargetClass::Unspecified};
  ApplyGuarantee guarantee{ApplyGuarantee::AtomicActivate};
  /// Target boot term. A session whose term is lower than this is fenced.
  Term term;
  IncarnationId incarnation;
  Generation committedGeneration;
  Digest committedDigest;
  ArtifactId committedArtifact;
  /// Wall-clock of the last accepted report. Durable, but see below.
  std::int64_t lastContactMillis{0};
  /// True only when the current process established contact. Never persisted as
  /// true: after a restart the previous evidence is historical, not current.
  bool contactEstablishedThisProcess{false};
  std::uint64_t sessionsEstablished{0};
  std::uint64_t restartsObserved{0};
  bool applyPrepared{false};
  DeploymentId preparedDeployment;
  Generation preparedGeneration;
  Digest preparedDigest;
  /// host:port supplied by upstream. Empty means the target cannot be dialled.
  std::string endpoint;

  friend bool operator==(const TargetRuntime&, const TargetRuntime&) noexcept = default;
};

/// One delivery: a configuration generation for one (target, config key).
struct DeliveryRecord {
  DeploymentId id;
  DeploymentSetId setId;
  RolloutSetId rolloutSet;
  TargetId target;
  ConfigKey key;
  ArtifactId artifact;
  Revision revision;
  Generation generation;
  Digest digest;
  SchemaId schema;
  SchemaVersion schemaVersion;
  std::uint64_t sizeBytes{0};
  GuaranteeRequirement requirement{GuaranteeRequirement::RequireAtomic};
  /// The guarantee the target actually offered, once it has reported one.
  ApplyGuarantee effectiveGuarantee{ApplyGuarantee::AtomicActivate};
  DeliveryState state{DeliveryState::Prepared};
  AttemptId attempt;
  std::uint32_t failures{0};
  ErrorCode lastError{ErrorCode::Ok};
  RetryDirective lastDirective{RetryDirective::DoNotRetry};
  std::string lastDetail;
  std::vector<LifecycleEvent> events;
  /// Distributor authority in force when the record last changed.
  Epoch authorityEpoch;
  IncarnationId authorityIncarnation;
  /// Target authority the newest evidence came from.
  Term targetTerm;
  IncarnationId targetIncarnation;
  bool acknowledgedFromReconcile{false};
  bool superseded{false};
  std::int64_t createdAtMillis{0};
  std::int64_t updatedAtMillis{0};

  friend bool operator==(const DeliveryRecord&, const DeliveryRecord&) noexcept = default;
};

struct ControllerState {
  NodeId nodeId;
  Epoch epoch;
  IncarnationId incarnation;
  std::int64_t startedAtMillis{0};
  std::map<TargetId, TargetRuntime> targets;
  std::map<DeploymentId, DeliveryRecord> deliveries;
  /// Artifact metadata mirrored from the artifact store so an offline
  /// inspection of the state directory is self-contained.
  std::map<Digest, ArtifactMetadata> artifacts;

  /// Deliveries that still owe work, ordered deterministically by id.
  [[nodiscard]] std::vector<const DeliveryRecord*> pendingDeliveries() const;
  [[nodiscard]] const DeliveryRecord* findDelivery(const DeploymentId& id) const;
  [[nodiscard]] const TargetRuntime* findTarget(const TargetId& id) const;
  /// Newest delivery for a lineage, or nullptr. Deterministic.
  [[nodiscard]] const DeliveryRecord* latestForLineage(const TargetId& target,
                                                       const ConfigKey& key) const;
};

struct ControllerStateCodec {
  [[nodiscard]] static Result<std::vector<std::uint8_t>> encodeSnapshot(
      const ControllerState& state);
  [[nodiscard]] static Result<ControllerState> decodeSnapshot(
      std::span<const std::uint8_t> payload);
  [[nodiscard]] static Status apply(ControllerState& state, JournalRecordType type,
                                    std::span<const std::uint8_t> payload);
};

using ControllerStore = DurableStore<ControllerState, ControllerStateCodec>;

// ---------------------------------------------------------------------------
// Target agent state
// ---------------------------------------------------------------------------

/// A partially received artifact. Retained across restarts so a transfer can
/// resume, but only after the on-disk partial file is shown to match the
/// recorded byte count.
struct TransferRecord {
  DeploymentId deployment;
  StreamId stream;
  ConfigKey key;
  ArtifactId artifact;
  Generation generation;
  Digest digest;
  std::uint64_t totalBytes{0};
  std::uint64_t bytesReceived{0};
  bool verified{false};
  bool staged{false};
  std::int64_t updatedAtMillis{0};

  friend bool operator==(const TransferRecord&, const TransferRecord&) noexcept = default;
};

/// A durable record of one activation outcome. This table is what makes
/// duplicate delivery idempotent: a redelivered (key, generation, digest) is
/// answered from here instead of being applied again.
struct AppliedFinding {
  ConfigKey key;
  Generation generation;
  Digest digest;
  ArtifactId artifact;
  DeploymentId deployment;
  /// The lifecycle boundary the target actually reached for this generation.
  DeliveryState state{DeliveryState::Applied};
  std::int64_t recordedAtMillis{0};

  friend bool operator==(const AppliedFinding&, const AppliedFinding&) noexcept = default;
};

struct AgentState {
  TargetId target;
  TargetClass klass{TargetClass::Unspecified};
  ApplyGuarantee guarantee{ApplyGuarantee::AtomicActivate};
  Term term;
  IncarnationId incarnation;
  std::uint32_t restartCount{0};
  /// Last controller authority accepted by this agent. A message carrying an
  /// older epoch, or a different incarnation for the same epoch, is fenced.
  Epoch lastControllerEpoch;
  IncarnationId lastControllerIncarnation;
  NodeId lastControllerNode;
  Generation committedGeneration;
  Digest committedDigest;
  ArtifactId committedArtifact;
  /// An unresolved prepare/commit window: the target has entered prepare for a
  /// generation it has not committed. Reconciliation must resolve it.
  bool applyPrepared{false};
  DeploymentId preparedDeployment;
  Generation preparedGeneration;
  Digest preparedDigest;
  std::map<DeploymentId, TransferRecord> transfers;
  std::vector<AppliedFinding> findings;
  std::uint64_t activations{0};
  std::uint64_t duplicatesSuppressed{0};
  std::uint64_t staleOffersRefused{0};
  std::uint64_t digestRejections{0};
  /// Unresolved prepare windows that had to be aborted. Non-zero here is the
  /// concrete cost of a target that cannot activate atomically.
  std::uint64_t applyRollbacks{0};

  [[nodiscard]] const AppliedFinding* findFinding(const ConfigKey& key,
                                                  const Digest& digest) const;
};

struct AgentStateCodec {
  [[nodiscard]] static Result<std::vector<std::uint8_t>> encodeSnapshot(const AgentState& state);
  [[nodiscard]] static Result<AgentState> decodeSnapshot(std::span<const std::uint8_t> payload);
  [[nodiscard]] static Status apply(AgentState& state, JournalRecordType type,
                                    std::span<const std::uint8_t> payload);
};

using AgentStore = DurableStore<AgentState, AgentStateCodec>;

/// Bounds applied to every collection in both stores.
inline constexpr std::size_t kMaxFindingsPerAgent = 128;

/// Loads controller state from a state directory without mutating anything: no
/// recovery truncation, no compaction, no epoch change. Used by the inspection
/// CLI so that reading state can never alter it. A gap between the newest
/// loadable snapshot and the journal base is reported, not hidden.
[[nodiscard]] Result<ControllerState> loadControllerStateOffline(const std::string& directory,
                                                                 std::string* detail);

/// Same, for one target agent's state directory.
[[nodiscard]] Result<AgentState> loadAgentStateOffline(const std::string& directory,
                                                       std::string* detail);

/// Encodes/decodes one delivery record. Exposed for the inspection CLI, which
/// replays journals without opening a store.
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeDeliveryRecord(
    const DeliveryRecord& record);
[[nodiscard]] Result<DeliveryRecord> decodeDeliveryRecord(std::span<const std::uint8_t> payload);
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeTargetRuntime(const TargetRuntime& runtime);
[[nodiscard]] Result<TargetRuntime> decodeTargetRuntime(std::span<const std::uint8_t> payload);

}  // namespace cf
