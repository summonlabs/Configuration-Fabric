// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Convergence reporting.
//
// The runtime never reports a single global success bit. For every (target,
// config key) lineage it reports the desired generation, the generation the
// target is believed to be on, the delivery lifecycle state, why the target is
// where it is, what is still pending, and every typed blocker standing between
// the two.
//
// render() is deterministic: it contains no wall-clock timestamps and no
// addresses, so two runs over the same durable state produce byte-identical
// output. That is what makes a convergence summary usable as evidence.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "cf/ids.hpp"
#include "cf/lifecycle.hpp"
#include "cf/policy.hpp"
#include "cf/state.hpp"

namespace cf {

/// Why a lineage is not converged. Typed, so reports can be grouped and tested.
enum class BlockerKind : std::uint8_t {
  None = 0,
  NotYetDelivered,
  DeliveryInFlight,
  AwaitingAcknowledgement,
  RetryBudgetExhausted,
  TargetUnreachable,
  TargetAuthorityFenced,
  GuaranteeUnsupported,
  ArtifactUnavailable,
  DigestMismatchReported,
  SizeMismatchReported,
  SchemaUnsupported,
  PolicyRejected,
  TargetAheadOfDesired,
  Superseded,
  LivenessEvidenceStale,
  PrepareWindowOpen,
  LivePointerUnverified,
};

[[nodiscard]] std::string_view blockerKindName(BlockerKind kind) noexcept;

struct LineageConvergence {
  TargetId target;
  ConfigKey key;
  ArtifactId artifact;
  Generation desiredGeneration;
  Digest desiredDigest;
  Generation currentGeneration;
  Digest currentDigest;
  DeliveryState state{DeliveryState::Prepared};
  ApplyGuarantee guarantee{ApplyGuarantee::AtomicActivate};
  GuaranteeRequirement requirement{GuaranteeRequirement::RequireAtomic};
  bool converged{false};
  /// The reason the target is where it is. Deterministic prose.
  std::string currentReason;
  std::vector<BlockerKind> blockers;
  /// Human-readable pending work, in a stable order.
  std::vector<std::string> pending;
  bool contactEstablishedThisProcess{false};
  bool evidenceFromReconciliation{false};
  std::uint32_t attempts{0};
  std::uint32_t failures{0};
};

struct ConvergenceReport {
  NodeId nodeId;
  Epoch epoch;
  IncarnationId incarnation;
  std::size_t lineageCount{0};
  std::size_t convergedCount{0};
  std::size_t pendingCount{0};
  std::size_t blockedCount{0};
  std::size_t divergedCount{0};
  std::vector<LineageConvergence> lineages;
  /// Deliveries that are not part of a lineage summary (retired history).
  std::size_t retiredCount{0};
  std::size_t rejectedCount{0};

  [[nodiscard]] bool converged() const noexcept {
    return blockedCount == 0 && divergedCount == 0 && pendingCount == 0;
  }
  /// Deterministic multi-line rendering. No timestamps, no addresses.
  [[nodiscard]] std::string render() const;
  /// Deterministic single-line digest of the whole report.
  [[nodiscard]] std::string fingerprint() const;
};

/// Builds the report from authoritative state. Pure: takes the state by const
/// reference and never blocks on I/O. nowMillis is used only to age persisted
/// liveness evidence, never to render it.
[[nodiscard]] ConvergenceReport buildConvergenceReport(const ControllerState& state,
                                                       const DistributorPolicy& policy,
                                                       std::int64_t nowMillis);

/// Full explanation for one target: every delivery, its evidence, and the
/// decision the policy would take right now. Deterministic.
[[nodiscard]] std::string explainTarget(const ControllerState& state,
                                        const DistributorPolicy& policy, const TargetId& target,
                                        std::int64_t nowMillis);

/// Builds the policy input for one delivery from authoritative state. Shared by
/// the scheduler and by the explanation renderer so they cannot disagree.
[[nodiscard]] DecisionInput buildDecisionInput(const ControllerState& state,
                                               const DistributorPolicy& policy,
                                               const DeliveryRecord& delivery,
                                               std::int64_t nowMillis);

}  // namespace cf
