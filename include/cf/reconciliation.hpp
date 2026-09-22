// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Reconciliation.
//
// A distributor that restarts knows what it intended, not what happened. A target
// that restarts knows what it committed, not what the distributor intended. The
// only honest way to close that gap is to ask, and then to accept the answer only
// if it is evidence: a live authenticated session, from a target incarnation that
// is not fenced, describing a generation and digest.
//
// reconcileDelivery() is a pure function over (delivery record, target runtime,
// agent report). It decides one of a small set of outcomes and explains itself.
// It never mutates state and never calls anything.

#pragma once

#include <string>
#include <string_view>

#include "cf/ids.hpp"
#include "cf/lifecycle.hpp"
#include "cf/protocol.hpp"
#include "cf/state.hpp"

namespace cf {

enum class ReconcileOutcome : std::uint8_t {
  /// Nothing is known either way; drive the delivery normally.
  DriveNormally = 0,
  /// The target's live report proves activation of exactly this generation and
  /// digest under current authority. The delivery may be acknowledged, with the
  /// evidence labelled as reconciliation-sourced.
  AdoptActivation = 1,
  /// The target already holds bytes for this deployment; resume rather than
  /// restart the transfer.
  ResumeTransfer = 2,
  /// The target has moved past this generation. The delivery is stale.
  RetireStale = 3,
  /// The target holds an unresolved prepare/commit window.
  ResolvePrepareWindow = 4,
  /// The target's authority does not match what this session established.
  FenceAuthority = 5,
  /// The target never heard of this deployment and holds nothing for it.
  UnknownAtTarget = 6,
};

[[nodiscard]] std::string_view reconcileOutcomeName(ReconcileOutcome outcome) noexcept;

/// Everything the decision is allowed to look at.
struct ReconcileInput {
  /// Null when the delivery has no target report (for example the target never
  /// reconnected).
  const ReconcileReportMessage* report{nullptr};
  /// Term and incarnation the current session established with the target.
  Term sessionTerm;
  IncarnationId sessionIncarnation;
  /// The delivery under consideration.
  Generation desiredGeneration;
  Digest desiredDigest;
  ConfigKey key;
  DeploymentId deployment;
  DeliveryState state{DeliveryState::Prepared};
  ApplyGuarantee guarantee{ApplyGuarantee::AtomicActivate};
  GuaranteeRequirement requirement{GuaranteeRequirement::RequireAtomic};
  bool artifactAvailable{false};
};

struct ReconcileDecision {
  ReconcileOutcome outcome{ReconcileOutcome::DriveNormally};
  std::string reason;
  /// Populated for AdoptActivation: the state the evidence supports.
  DeliveryState adoptedState{DeliveryState::Applied};
  /// Populated for ResumeTransfer.
  std::uint64_t resumeFromOffset{0};
  /// Populated for RetireStale: the generation the target reports.
  Generation targetGeneration;
  Digest targetDigest;

  [[nodiscard]] std::string render() const;
};

[[nodiscard]] ReconcileDecision reconcileDelivery(const ReconcileInput& input);

/// Finds the transfer status record for one deployment inside a report.
[[nodiscard]] const TransferStatusRecord* findTransferStatus(
    const ReconcileReportMessage& report, const DeploymentId& deployment);

/// True when the target's report proves the exact generation and digest is live.
[[nodiscard]] bool reportProvesActivation(const ReconcileReportMessage& report,
                                          Generation generation, const Digest& digest,
                                          const ConfigKey& key);

}  // namespace cf
