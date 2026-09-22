// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic distribution policy.
//
// decide() is a pure function. Given the same policy and the same observation it
// returns byte-identical output, which is what makes a decision inspectable:
// every decision carries the inputs it saw, the governing policy values, the
// selected action, the alternatives it rejected and why, and the authority
// (epoch, generation, attempt) it was made under.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "cf/ids.hpp"
#include "cf/lifecycle.hpp"
#include "cf/result.hpp"

namespace cf {

struct DistributorPolicy {
  /// Bounded retry budget per delivery. Exhaustion is a reported blocker, never
  /// a silent stop.
  std::uint32_t maxAttempts{4};
  /// Base backoff between attempts, doubled per attempt up to maxBackoffMillis.
  std::int64_t retryBackoffMillis{200};
  std::int64_t maxBackoffMillis{5000};
  /// Connect/handshake budget before the session is abandoned.
  std::int64_t connectTimeoutMillis{5000};
  /// A session with no traffic for this long is considered dead.
  std::int64_t sessionIdleTimeoutMillis{10000};
  /// Per-request response budget.
  std::int64_t requestTimeoutMillis{10000};
  /// Maximum targets tracked. Deployments naming more targets are refused.
  std::size_t maxTargets{1024};
  /// Maximum live (non-retired) deliveries tracked.
  std::size_t maxLiveDeliveries{4096};
  /// Delivery history retained per target/config-key lineage; older records are
  /// retired so that durable state stays bounded.
  std::size_t maxHistoryPerLineage{8};
  /// Concurrent delivery sessions.
  std::size_t maxConcurrentSessions{8};
  /// Transfer chunk size. Must be <= maxPayloadBytes minus the message overhead.
  std::size_t transferChunkBytes{16384};
  /// Largest accepted wire payload. Advertised during the handshake; the peer's
  /// advertised value is bounded by this one.
  std::uint32_t maxPayloadBytes{1u * 1024u * 1024u};
  /// Require a target acknowledgement before a delivery may reach acknowledged.
  bool requireAcknowledgement{true};
  /// Reconstruct in-flight state from targets after a distributor restart.
  bool reconcileOnRestart{true};
  /// Findings requested in a reconcile report.
  std::size_t maxReconcileFindings{64};
  /// Wall-clock freshness window applied to persisted target contact evidence
  /// after a restart. Evidence older than this is reported as stale and forces a
  /// fresh session before it can count.
  std::int64_t livenessFreshnessMillis{15000};

  [[nodiscard]] Status validate() const;
  /// Stable rendering of every governing value, embedded in explanations.
  [[nodiscard]] std::string render() const;
};

enum class PolicyAction : std::uint8_t {
  None = 0,
  /// Dispatch a new session to push the generation.
  Offer,
  /// Resume an interrupted transfer from the target's reported byte count.
  ResumeTransfer,
  /// Re-issue the activation step for an already staged artifact.
  Activate,
  /// Ask the target for its authoritative state before doing anything else.
  Reconcile,
  /// Nothing to do yet: wait for the backoff to elapse, the deadline to pass, or
  /// the target to reconnect.
  Wait,
  /// Record a durable failure and schedule another attempt.
  RecordFailureAndRetry,
  /// Refuse the delivery permanently for this generation.
  Reject,
  /// Stop retrying and report a blocker.
  GiveUp,
  /// Supersede the delivery: a newer generation or explicit retirement applies.
  Retire,
};

[[nodiscard]] std::string_view policyActionName(PolicyAction action) noexcept;
[[nodiscard]] bool parsePolicyAction(std::string_view text, PolicyAction& out) noexcept;

/// Everything decide() is allowed to look at. Collected by the caller under the
/// state lock; decide() itself takes no locks and calls nothing.
struct DecisionInput {
  DeliveryState state{DeliveryState::Prepared};
  std::uint32_t failures{0};
  AttemptId attempt;
  ApplyGuarantee targetGuarantee{ApplyGuarantee::AtomicActivate};
  GuaranteeRequirement requirement{GuaranteeRequirement::RequireAtomic};
  Generation desiredGeneration;
  Generation targetGeneration;
  Digest desiredDigest;
  Digest targetDigest;
  /// True when the target has a live session with a current incarnation.
  bool targetLive{false};
  /// True when the target's persisted contact evidence predates the configured
  /// freshness window (post-restart) and therefore cannot be trusted.
  bool livenessEvidenceStale{false};
  /// True when the target reported an unresolved prepare/commit window.
  bool targetApplyPrepared{false};
  /// True when the artifact digest is present and verified in the store.
  bool artifactAvailable{false};
  /// True when the target reported partial bytes for this exact deployment.
  bool resumableTransfer{false};
  /// True when a newer generation exists for the same (target, config key).
  bool supersededByNewerGeneration{false};
  /// Elapsed milliseconds since the last attempt at this delivery.
  std::int64_t millisSinceLastAttempt{0};
};

struct RejectedAlternative {
  PolicyAction action{PolicyAction::None};
  std::string reason;
};

struct Decision {
  PolicyAction action{PolicyAction::None};
  std::string reason;
  std::vector<RejectedAlternative> alternatives;
  /// Authority the decision was taken under.
  Epoch epoch;
  Generation generation;
  AttemptId attempt;
  /// Backoff the caller must observe before acting, when the action is Wait.
  std::int64_t retryAfterMillis{0};
  /// True when the delivery reached a state that will not change on its own.
  bool terminal{false};

  /// Deterministic multi-line explanation. Identical inputs produce identical
  /// bytes.
  [[nodiscard]] std::string render(const DistributorPolicy& policy) const;
};

/// Pure decision function. No locks, no I/O, no calls back into mutable state.
[[nodiscard]] Decision decide(const DistributorPolicy& policy, const DecisionInput& input,
                              Epoch epoch, Generation generation);

}  // namespace cf
