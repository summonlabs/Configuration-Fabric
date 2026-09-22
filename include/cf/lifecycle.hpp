// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Delivery lifecycle.
//
// The lifecycle is a guard-protected finite state machine. Every transition is
// decided by an explicit table, carries typed evidence, and records the
// authority (distributor epoch/incarnation, target term/incarnation) that was in
// force when the evidence was accepted. Nothing else in the runtime is allowed
// to assign a delivery state.
//
//   prepared -> offered -> transferred -> verified -> staged -> applied -> acknowledged
//                   \__________ failure / rejection / retirement paths __________/
//
// "acknowledged" is a claim with a precise meaning: the target reported, under a
// live session with a current incarnation, that the exact (generation, digest)
// pair is active, and that report was durably recorded by the current
// distributor authority. Losing the acknowledgement message loses the claim; it
// is never inferred from silence.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "cf/digest.hpp"
#include "cf/ids.hpp"
#include "cf/result.hpp"

namespace cf {

enum class DeliveryState : std::uint8_t {
  /// The distributor knows what this target should run and holds the bytes.
  Prepared = 1,
  /// The target has been told a transfer for this generation is coming.
  Offered = 2,
  /// Every byte has been accepted by the target.
  Transferred = 3,
  /// The target recomputed the digest and it matches.
  Verified = 4,
  /// The target holds the artifact in its staging area, ready to activate.
  Staged = 5,
  /// The target reports the generation is active. This is the activation
  /// boundary; for prepare/commit/abort targets it is the commit boundary.
  Applied = 6,
  /// The activation report is durably recorded under current authority.
  Acknowledged = 7,
  /// The delivery did not complete. Retryable.
  Failed = 8,
  /// The delivery was refused on principle (guarantee, schema, policy,
  /// integrity) and will not be retried for this generation.
  Rejected = 9,
  /// The delivery is superseded or abandoned; retained for history only.
  Retired = 10,
};

[[nodiscard]] std::string_view deliveryStateName(DeliveryState state) noexcept;
[[nodiscard]] bool parseDeliveryState(std::string_view text, DeliveryState& out) noexcept;
/// Rank is used only for ordering and for "progress" comparisons in reports.
[[nodiscard]] std::uint8_t deliveryStateRank(DeliveryState state) noexcept;
/// True for states that represent a completed activation of the generation.
[[nodiscard]] bool isActivationState(DeliveryState state) noexcept;
/// True when no transition out of the state advances the delivery.
[[nodiscard]] bool isTerminalState(DeliveryState state) noexcept;
/// True when the delivery is still owed work by the distributor.
[[nodiscard]] bool isPendingState(DeliveryState state) noexcept;

/// The complete legal transition relation. Total and deterministic.
[[nodiscard]] bool isLegalTransition(DeliveryState from, DeliveryState to) noexcept;
/// Renders the transition relation as a stable multi-line string. Used by
/// documentation tooling and by the inspection CLI so the documented machine and
/// the implemented machine cannot drift.
[[nodiscard]] std::string renderTransitionTable();

/// What kind of evidence caused a transition.
enum class EvidenceKind : std::uint8_t {
  Created = 1,
  OfferedToTarget = 2,
  BytesAccepted = 3,
  DigestVerified = 4,
  StagedAtTarget = 5,
  ApplyPrepared = 6,
  ActivationReported = 7,
  AcknowledgementRecorded = 8,
  ReconcileObserved = 9,
  FailureReported = 10,
  Refused = 11,
  Superseded = 12,
  Retried = 13,
};

[[nodiscard]] std::string_view evidenceKindName(EvidenceKind kind) noexcept;
[[nodiscard]] bool parseEvidenceKind(std::string_view text, EvidenceKind& out) noexcept;

inline constexpr std::size_t kMaxEvidenceDetailBytes = 256;
inline constexpr std::size_t kMaxEventsPerDelivery = 64;

/// One durable lifecycle event. The event is the audit record that makes a
/// decision inspectable after the fact.
struct LifecycleEvent {
  EvidenceKind kind{EvidenceKind::Created};
  DeliveryState from{DeliveryState::Prepared};
  DeliveryState to{DeliveryState::Prepared};
  Generation generation;
  Digest digest;
  ErrorCode code{ErrorCode::Ok};
  RetryDirective directive{RetryDirective::DoNotRetry};
  /// Distributor authority in force when the evidence was accepted.
  Epoch authorityEpoch;
  IncarnationId authorityIncarnation;
  /// Target authority the evidence came from (unset for distributor-local facts).
  Term targetTerm;
  IncarnationId targetIncarnation;
  /// True when the evidence was reconstructed during reconciliation rather than
  /// observed live. Convergence reports surface this distinction.
  bool fromReconciliation{false};
  std::int64_t atMillis{0};
  std::string detail;

  friend bool operator==(const LifecycleEvent&, const LifecycleEvent&) noexcept = default;

  [[nodiscard]] std::string render() const;
};

/// Applies a transition, enforcing the table. On success the destination state
/// is returned; on an illegal transition the caller's state is untouched.
[[nodiscard]] Result<DeliveryState> applyTransition(DeliveryState from, DeliveryState to,
                                                    std::string_view what);

}  // namespace cf
