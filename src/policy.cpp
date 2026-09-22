// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/policy.hpp"

#include <array>

#include "cf/checked.hpp"
#include "cf/contract.hpp"

namespace cf {
namespace {

/// Backoff grows geometrically but stays inside [retryBackoffMillis,
/// maxBackoffMillis]. Computed with checked arithmetic so an absurd attempt
/// count cannot overflow into an immediate retry.
[[nodiscard]] std::int64_t backoffFor(const DistributorPolicy& policy, std::uint32_t failures) {
  const auto ceiling = static_cast<std::uint64_t>(policy.maxBackoffMillis);
  std::uint64_t delay = static_cast<std::uint64_t>(policy.retryBackoffMillis);
  const std::uint32_t capped = (failures > 16u) ? 16u : failures;
  for (std::uint32_t i = 0; i < capped; ++i) {
    if (delay >= ceiling) {
      break;
    }
    const auto doubled = checkedMul<std::uint64_t>(delay, 2u);
    delay = doubled ? *doubled : ceiling;
  }
  return static_cast<std::int64_t>(delay > ceiling ? ceiling : delay);
}

}  // namespace

Status DistributorPolicy::validate() const {
  if (maxAttempts == 0) {
    return Status::fail(ErrorCode::InvalidArgument, "maxAttempts must be at least 1");
  }
  if (maxConcurrentSessions == 0) {
    return Status::fail(ErrorCode::InvalidArgument, "maxConcurrentSessions must be at least 1");
  }
  if (maxTargets == 0 || maxLiveDeliveries == 0) {
    return Status::fail(ErrorCode::InvalidArgument, "target and delivery budgets must be non-zero");
  }
  if (transferChunkBytes == 0) {
    return Status::fail(ErrorCode::InvalidArgument, "transferChunkBytes must be non-zero");
  }
  if (transferChunkBytes > maxPayloadBytes) {
    return Status::fail(ErrorCode::InvalidArgument,
                        "transferChunkBytes must not exceed maxPayloadBytes",
                        std::to_string(transferChunkBytes) + " > " +
                            std::to_string(maxPayloadBytes));
  }
  if (retryBackoffMillis < 0 || maxBackoffMillis < retryBackoffMillis) {
    return Status::fail(ErrorCode::InvalidArgument, "backoff bounds are inconsistent");
  }
  if (connectTimeoutMillis <= 0 || sessionIdleTimeoutMillis <= 0 || requestTimeoutMillis <= 0) {
    return Status::fail(ErrorCode::InvalidArgument, "timeouts must be positive");
  }
  if (livenessFreshnessMillis <= 0) {
    return Status::fail(ErrorCode::InvalidArgument, "livenessFreshnessMillis must be positive");
  }
  if (maxHistoryPerLineage == 0) {
    return Status::fail(ErrorCode::InvalidArgument, "maxHistoryPerLineage must be at least 1");
  }
  return Status::ok();
}

std::string DistributorPolicy::render() const {
  std::string out;
  out.reserve(640);
  const auto line = [&out](std::string_view key, auto value) {
    out.append("  ");
    out.append(key);
    out.append(" = ");
    out.append(std::to_string(value));
    out.push_back('\n');
  };
  out.append("policy:\n");
  line("max-attempts", maxAttempts);
  line("retry-backoff-ms", retryBackoffMillis);
  line("max-backoff-ms", maxBackoffMillis);
  line("connect-timeout-ms", connectTimeoutMillis);
  line("session-idle-timeout-ms", sessionIdleTimeoutMillis);
  line("request-timeout-ms", requestTimeoutMillis);
  line("max-targets", maxTargets);
  line("max-live-deliveries", maxLiveDeliveries);
  line("max-history-per-lineage", maxHistoryPerLineage);
  line("max-concurrent-sessions", maxConcurrentSessions);
  line("transfer-chunk-bytes", transferChunkBytes);
  line("max-payload-bytes", maxPayloadBytes);
  line("liveness-freshness-ms", livenessFreshnessMillis);
  out.append("  require-acknowledgement = ");
  out.append(requireAcknowledgement ? "true" : "false");
  out.push_back('\n');
  out.append("  reconcile-on-restart = ");
  out.append(reconcileOnRestart ? "true" : "false");
  out.push_back('\n');
  return out;
}

std::string_view policyActionName(PolicyAction action) noexcept {
  switch (action) {
    case PolicyAction::None:
      return "none";
    case PolicyAction::Offer:
      return "offer";
    case PolicyAction::ResumeTransfer:
      return "resume-transfer";
    case PolicyAction::Activate:
      return "activate";
    case PolicyAction::Reconcile:
      return "reconcile";
    case PolicyAction::Wait:
      return "wait";
    case PolicyAction::RecordFailureAndRetry:
      return "record-failure-and-retry";
    case PolicyAction::Reject:
      return "reject";
    case PolicyAction::GiveUp:
      return "give-up";
    case PolicyAction::Retire:
      return "retire";
  }
  return "unknown";
}

bool parsePolicyAction(std::string_view text, PolicyAction& out) noexcept {
  for (std::uint8_t raw = 0; raw <= 9; ++raw) {
    const auto action = static_cast<PolicyAction>(raw);
    if (policyActionName(action) == text) {
      out = action;
      return true;
    }
  }
  return false;
}

Decision decide(const DistributorPolicy& policy, const DecisionInput& input, Epoch epoch,
                Generation generation) {
  Decision decision;
  decision.epoch = epoch;
  decision.generation = generation;
  decision.attempt = input.attempt;

  const auto rejectAlternative = [&decision](PolicyAction action, std::string reason) {
    decision.alternatives.push_back(RejectedAlternative{action, std::move(reason)});
  };

  // Guard order is part of the contract: staleness and integrity are checked
  // before any action that could mutate target state.
  if (input.supersededByNewerGeneration ||
      (input.targetGeneration.isSet() && input.targetGeneration > input.desiredGeneration)) {
    rejectAlternative(PolicyAction::Offer,
                      "offering would push a generation the target has already moved past");
    rejectAlternative(PolicyAction::Activate,
                      "activation would install a stale generation over a newer one");
    decision.action = PolicyAction::Retire;
    decision.reason = "target is at generation " + std::to_string(input.targetGeneration.value()) +
                      " which is not older than the desired generation " +
                      std::to_string(input.desiredGeneration.value());
    decision.terminal = true;
    return decision;
  }

  if (!guaranteeSatisfies(input.targetGuarantee, input.requirement)) {
    rejectAlternative(PolicyAction::Offer, "the target cannot satisfy the required guarantee");
    decision.action = PolicyAction::Reject;
    decision.reason = std::string("target offers guarantee '") +
                      std::string(applyGuaranteeName(input.targetGuarantee)) +
                      "' which does not satisfy requirement '" +
                      std::string(guaranteeRequirementName(input.requirement)) + "'";
    decision.terminal = true;
    return decision;
  }

  if (!input.artifactAvailable) {
    if (input.state == DeliveryState::Prepared) {
      rejectAlternative(PolicyAction::Offer, "the artifact bytes are not in the store");
      decision.action = PolicyAction::Reject;
      decision.reason = "artifact for the desired digest is not present in the artifact store";
      decision.terminal = true;
      return decision;
    }
    rejectAlternative(PolicyAction::Offer, "digest is unavailable for distribution");
    decision.action = PolicyAction::RecordFailureAndRetry;
    decision.reason = "artifact bytes are no longer available; the delivery cannot progress";
    decision.retryAfterMillis = backoffFor(policy, input.failures);
    decision.terminal = input.failures >= policy.maxAttempts;
    if (decision.terminal) {
      decision.action = PolicyAction::GiveUp;
      rejectAlternative(PolicyAction::RecordFailureAndRetry,
                        "retry budget is exhausted for this delivery");
    }
    return decision;
  }

  if (isTerminalState(input.state)) {
    rejectAlternative(PolicyAction::Offer, "the delivery already reached a terminal state");
    decision.action = PolicyAction::None;
    decision.reason = std::string("delivery is terminal in state '") +
                      std::string(deliveryStateName(input.state)) + "'";
    decision.terminal = true;
    return decision;
  }

  if (input.state == DeliveryState::Applied) {
    if (policy.requireAcknowledgement) {
      rejectAlternative(PolicyAction::Activate, "the activation boundary already occurred");
      decision.action = PolicyAction::Reconcile;
      decision.reason =
          "target reported activation; the acknowledgement boundary must be confirmed against "
          "current target authority before it can be recorded";
    } else {
      decision.action = PolicyAction::None;
      decision.reason = "acknowledgement is not required by policy";
      decision.terminal = true;
    }
    return decision;
  }

  if (input.state == DeliveryState::Failed) {
    if (input.failures >= policy.maxAttempts) {
      rejectAlternative(PolicyAction::RecordFailureAndRetry,
                        "retry budget is exhausted for this delivery");
      decision.action = PolicyAction::GiveUp;
      decision.reason = "delivery failed " + std::to_string(input.failures) +
                        " time(s), which exhausts the retry budget of " +
                        std::to_string(policy.maxAttempts);
      decision.terminal = true;
      return decision;
    }
    if (input.millisSinceLastAttempt < backoffFor(policy, input.failures)) {
      rejectAlternative(PolicyAction::Offer, "the retry backoff has not elapsed");
      decision.action = PolicyAction::Wait;
      decision.reason = "waiting out the retry backoff before attempt " +
                        std::to_string(input.attempt.value() + 1);
      decision.retryAfterMillis = backoffFor(policy, input.failures) - input.millisSinceLastAttempt;
      return decision;
    }
    decision.action = PolicyAction::Offer;
    decision.reason = "retry budget remains and the backoff elapsed";
    return decision;
  }

  if (input.livenessEvidenceStale) {
    rejectAlternative(PolicyAction::Offer,
                      "persisted liveness evidence predates this process and is not fresh");
    rejectAlternative(PolicyAction::ResumeTransfer,
                      "resuming needs a fresh target report, not persisted evidence");
    decision.action = PolicyAction::Reconcile;
    decision.reason =
        "target contact evidence is older than the freshness window; a live session must "
        "re-establish it before any state change is accepted";
    return decision;
  }

  if (input.targetApplyPrepared) {
    rejectAlternative(PolicyAction::Activate,
                      "an unresolved prepare/commit window exists; committing blind could "
                      "activate an unverified generation");
    decision.action = PolicyAction::Reconcile;
    decision.reason =
        "target reported an unresolved prepare/commit window; its authoritative state must be "
        "resolved before the delivery continues";
    return decision;
  }

  if (!input.targetLive) {
    rejectAlternative(PolicyAction::Offer, "no live session exists for the target");
    decision.action = PolicyAction::Wait;
    decision.reason = "target has no live session; the next connection attempt will drive delivery";
    return decision;
  }

  switch (input.state) {
    case DeliveryState::Prepared:
      decision.action = PolicyAction::Offer;
      decision.reason = "artifact is available and the target is live";
      return decision;
    case DeliveryState::Offered:
    case DeliveryState::Transferred:
      if (input.resumableTransfer) {
        rejectAlternative(PolicyAction::Offer,
                          "the target already holds bytes for this exact deployment");
        decision.action = PolicyAction::ResumeTransfer;
        decision.reason = "target reported partial bytes for this deployment; resume instead of "
                          "restarting the transfer";
        return decision;
      }
      decision.action = PolicyAction::Offer;
      decision.reason = "transfer has not yet completed at the target";
      return decision;
    case DeliveryState::Verified:
    case DeliveryState::Staged:
      decision.action = PolicyAction::Activate;
      decision.reason = "target holds a verified, staged artifact; activation is the next boundary";
      return decision;
    case DeliveryState::Acknowledged:
    case DeliveryState::Rejected:
    case DeliveryState::Retired:
    case DeliveryState::Applied:
    case DeliveryState::Failed:
      break;
  }
  decision.action = PolicyAction::None;
  decision.reason = "no action required";
  decision.terminal = true;
  return decision;
}

std::string Decision::render(const DistributorPolicy& policy) const {
  std::string out;
  out.reserve(768);
  out.append("decision:\n");
  out.append("  action = ");
  out.append(policyActionName(action));
  out.push_back('\n');
  out.append("  reason = ");
  out.append(reason);
  out.push_back('\n');
  out.append("  authority-epoch = ");
  out.append(std::to_string(epoch.value()));
  out.push_back('\n');
  out.append("  generation = ");
  out.append(std::to_string(generation.value()));
  out.push_back('\n');
  out.append("  attempt = ");
  out.append(std::to_string(attempt.value()));
  out.push_back('\n');
  out.append("  terminal = ");
  out.append(terminal ? "true" : "false");
  out.push_back('\n');
  if (retryAfterMillis > 0) {
    out.append("  retry-after-ms = ");
    out.append(std::to_string(retryAfterMillis));
    out.push_back('\n');
  }
  if (!alternatives.empty()) {
    out.append("  rejected-alternatives:\n");
    for (const RejectedAlternative& alternative : alternatives) {
      out.append("    - ");
      out.append(policyActionName(alternative.action));
      out.append(": ");
      out.append(alternative.reason);
      out.push_back('\n');
    }
  }
  out.append(policy.render());
  return out;
}

}  // namespace cf
