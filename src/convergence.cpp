// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/convergence.hpp"

#include <algorithm>
#include <map>
#include <string>

#include "cf/checked.hpp"
#include "cf/hash.hpp"

namespace cf {
namespace {

[[nodiscard]] bool isFreshContact(const TargetRuntime& runtime, const DistributorPolicy& policy,
                                  std::int64_t nowMillis) {
  if (!runtime.contactEstablishedThisProcess) {
    return false;
  }
  if (runtime.lastContactMillis <= 0) {
    return false;
  }
  const std::int64_t age = nowMillis - runtime.lastContactMillis;
  return age >= 0 && age <= policy.livenessFreshnessMillis;
}

}  // namespace

std::string_view blockerKindName(BlockerKind kind) noexcept {
  switch (kind) {
    case BlockerKind::None:
      return "none";
    case BlockerKind::NotYetDelivered:
      return "not-yet-delivered";
    case BlockerKind::DeliveryInFlight:
      return "delivery-in-flight";
    case BlockerKind::AwaitingAcknowledgement:
      return "awaiting-acknowledgement";
    case BlockerKind::RetryBudgetExhausted:
      return "retry-budget-exhausted";
    case BlockerKind::TargetUnreachable:
      return "target-unreachable";
    case BlockerKind::TargetAuthorityFenced:
      return "target-authority-fenced";
    case BlockerKind::GuaranteeUnsupported:
      return "guarantee-unsupported";
    case BlockerKind::ArtifactUnavailable:
      return "artifact-unavailable";
    case BlockerKind::DigestMismatchReported:
      return "digest-mismatch-reported";
    case BlockerKind::SizeMismatchReported:
      return "size-mismatch-reported";
    case BlockerKind::SchemaUnsupported:
      return "schema-unsupported";
    case BlockerKind::PolicyRejected:
      return "policy-rejected";
    case BlockerKind::TargetAheadOfDesired:
      return "target-ahead-of-desired";
    case BlockerKind::Superseded:
      return "superseded";
    case BlockerKind::LivenessEvidenceStale:
      return "liveness-evidence-stale";
    case BlockerKind::PrepareWindowOpen:
      return "prepare-window-open";
    case BlockerKind::LivePointerUnverified:
      return "live-pointer-unverified";
  }
  return "unknown";
}

DecisionInput buildDecisionInput(const ControllerState& state, const DistributorPolicy& policy,
                                 const DeliveryRecord& delivery, std::int64_t nowMillis) {
  DecisionInput input;
  input.state = delivery.state;
  input.failures = delivery.failures;
  input.attempt = delivery.attempt;
  input.requirement = delivery.requirement;
  input.desiredGeneration = delivery.generation;
  input.desiredDigest = delivery.digest;
  input.artifactAvailable = state.artifacts.find(delivery.digest) != state.artifacts.end();
  input.millisSinceLastAttempt = nowMillis - delivery.updatedAtMillis;

  const TargetRuntime* runtime = state.findTarget(delivery.target);
  if (runtime != nullptr) {
    input.targetGuarantee = runtime->guarantee;
    input.targetGeneration = runtime->committedGeneration;
    input.targetDigest = runtime->committedDigest;
    input.targetLive = isFreshContact(*runtime, policy, nowMillis);
    input.livenessEvidenceStale = !runtime->contactEstablishedThisProcess;
    input.targetApplyPrepared = runtime->applyPrepared;
  } else {
    input.targetLive = false;
    input.livenessEvidenceStale = false;
  }

  const DeliveryRecord* latest = state.latestForLineage(delivery.target, delivery.key);
  input.supersededByNewerGeneration =
      (latest != nullptr) && (latest->id.str() != delivery.id.str()) &&
      (latest->generation > delivery.generation);

  for (const auto& entry : state.deliveries) {
    const DeliveryRecord& other = entry.second;
    if (other.id.str() == delivery.id.str()) {
      continue;
    }
    if (other.target == delivery.target && other.key == delivery.key &&
        other.generation == delivery.generation && other.digest == delivery.digest &&
        other.state == DeliveryState::Failed) {
      input.resumableTransfer = true;
    }
  }
  return input;
}

ConvergenceReport buildConvergenceReport(const ControllerState& state,
                                         const DistributorPolicy& policy,
                                         std::int64_t nowMillis) {
  ConvergenceReport report;
  report.nodeId = state.nodeId;
  report.epoch = state.epoch;
  report.incarnation = state.incarnation;

  // Group deliveries by lineage. A map keeps the iteration order deterministic
  // and independent of insertion history.
  std::map<std::pair<std::string, std::string>, std::vector<const DeliveryRecord*>> lineages;
  for (const auto& entry : state.deliveries) {
    const DeliveryRecord& record = entry.second;
    lineages[{record.target.str(), record.key.str()}].push_back(&record);
  }

  for (auto& entry : lineages) {
    std::vector<const DeliveryRecord*>& records = entry.second;
    std::sort(records.begin(), records.end(), [](const DeliveryRecord* lhs, const DeliveryRecord* rhs) {
      if (lhs->generation != rhs->generation) {
        return lhs->generation < rhs->generation;
      }
      return lhs->id.str() < rhs->id.str();
    });

    // The desired delivery is the newest record for the lineage. A lineage whose
    // only record is retired is still reported: omitting it would hide a target
    // from the summary, and the summary exists to be complete.
    const DeliveryRecord* desired = records.back();
    for (const DeliveryRecord* record : records) {
      if (record->state == DeliveryState::Retired) {
        report.retiredCount += 1;
      }
    }

    LineageConvergence lineage;
    lineage.target = desired->target;
    lineage.key = desired->key;
    lineage.artifact = desired->artifact;
    lineage.desiredGeneration = desired->generation;
    lineage.desiredDigest = desired->digest;
    lineage.state = desired->state;
    lineage.guarantee = desired->effectiveGuarantee;
    lineage.requirement = desired->requirement;
    lineage.attempts =
        static_cast<std::uint32_t>(std::min<std::uint64_t>(desired->attempt.value(),
                                                          0xFFFFFFFFull));
    lineage.failures = desired->failures;
    lineage.evidenceFromReconciliation = desired->acknowledgedFromReconcile;

    const TargetRuntime* runtime = state.findTarget(desired->target);
    if (runtime != nullptr) {
      lineage.currentGeneration = runtime->committedGeneration;
      lineage.currentDigest = runtime->committedDigest;
      lineage.guarantee = runtime->guarantee;
      lineage.contactEstablishedThisProcess = runtime->contactEstablishedThisProcess;
    }

    switch (desired->state) {
      case DeliveryState::Acknowledged:
        lineage.converged = true;
        lineage.currentReason =
            "the target reported activation of the desired generation and the acknowledgement "
            "was durably recorded under the current authority";
        if (desired->acknowledgedFromReconcile) {
          lineage.currentReason.append(" (evidence recovered by reconciliation)");
        }
        break;
      case DeliveryState::Applied:
        lineage.blockers.push_back(BlockerKind::AwaitingAcknowledgement);
        lineage.pending.push_back("await the activation acknowledgement or reconcile it");
        lineage.currentReason =
            "the target reports the desired generation active, but the acknowledgement boundary "
            "has not been recorded";
        break;
      case DeliveryState::Staged:
      case DeliveryState::Verified:
        lineage.blockers.push_back(BlockerKind::DeliveryInFlight);
        lineage.pending.push_back("activate the staged artifact");
        lineage.currentReason = "the artifact is verified and staged at the target";
        break;
      case DeliveryState::Offered:
      case DeliveryState::Transferred:
        lineage.blockers.push_back(BlockerKind::DeliveryInFlight);
        lineage.pending.push_back("finish transferring the artifact");
        lineage.currentReason = "the transfer to the target has started but has not completed";
        break;
      case DeliveryState::Prepared:
        lineage.blockers.push_back(BlockerKind::NotYetDelivered);
        lineage.pending.push_back("deliver the artifact to the target");
        lineage.currentReason = "the delivery has been prepared but nothing has been sent";
        break;
      case DeliveryState::Failed:
        lineage.currentReason = "the last attempt failed: " + desired->lastDetail;
        if (desired->failures >= policy.maxAttempts) {
          lineage.blockers.push_back(BlockerKind::RetryBudgetExhausted);
          lineage.pending.push_back("operator action: raise the retry budget or fix the target");
        } else {
          lineage.blockers.push_back(BlockerKind::DeliveryInFlight);
          lineage.pending.push_back("retry the delivery");
        }
        switch (desired->lastError) {
          case ErrorCode::DigestMismatch:
            lineage.blockers.push_back(BlockerKind::DigestMismatchReported);
            break;
          case ErrorCode::SizeMismatch:
            lineage.blockers.push_back(BlockerKind::SizeMismatchReported);
            break;
          case ErrorCode::ArtifactUnavailable:
            lineage.blockers.push_back(BlockerKind::ArtifactUnavailable);
            break;
          case ErrorCode::StaleEpoch:
          case ErrorCode::StaleGeneration:
          case ErrorCode::FencedIncarnation:
            lineage.blockers.push_back(BlockerKind::TargetAuthorityFenced);
            break;
          case ErrorCode::GenerationConflict:
          case ErrorCode::Conflict:
            lineage.blockers.push_back(BlockerKind::PolicyRejected);
            break;
          default:
            break;
        }
        break;
      case DeliveryState::Rejected:
        report.rejectedCount += 1;
        lineage.currentReason = "the delivery was refused: " + desired->lastDetail;
        switch (desired->lastError) {
          case ErrorCode::GuaranteeUnsupported:
            lineage.blockers.push_back(BlockerKind::GuaranteeUnsupported);
            break;
          case ErrorCode::ArtifactUnavailable:
            lineage.blockers.push_back(BlockerKind::ArtifactUnavailable);
            break;
          case ErrorCode::SchemaUnsupported:
            lineage.blockers.push_back(BlockerKind::SchemaUnsupported);
            break;
          default:
            lineage.blockers.push_back(BlockerKind::PolicyRejected);
            break;
        }
        lineage.pending.push_back("operator action: change the deployment instruction");
        break;
      case DeliveryState::Retired:
        lineage.blockers.push_back(BlockerKind::Superseded);
        lineage.currentReason = "the delivery was superseded";
        break;
    }

    if (runtime == nullptr) {
      lineage.blockers.push_back(BlockerKind::TargetUnreachable);
      if (lineage.currentReason.empty()) {
        lineage.currentReason = "the target has never been contacted by this controller";
      }
    } else {
      if (!isFreshContact(*runtime, policy, nowMillis) && isPendingState(desired->state)) {
        lineage.blockers.push_back(BlockerKind::LivenessEvidenceStale);
        lineage.pending.push_back("establish a live session with the target");
      }
      if (runtime->applyPrepared) {
        lineage.blockers.push_back(BlockerKind::PrepareWindowOpen);
        lineage.pending.push_back("resolve the target's prepare/commit window");
      }
      if (runtime->committedGeneration > desired->generation) {
        lineage.blockers.push_back(BlockerKind::TargetAheadOfDesired);
        lineage.currentReason =
            "the target is at generation " + std::to_string(runtime->committedGeneration.value()) +
            ", which is newer than the desired generation " +
            std::to_string(desired->generation.value());
      }
    }

    std::sort(lineage.blockers.begin(), lineage.blockers.end(),
              [](BlockerKind lhs, BlockerKind rhs) {
                return static_cast<std::uint8_t>(lhs) < static_cast<std::uint8_t>(rhs);
              });
    lineage.blockers.erase(std::unique(lineage.blockers.begin(), lineage.blockers.end()),
                           lineage.blockers.end());
    std::sort(lineage.pending.begin(), lineage.pending.end());
    lineage.pending.erase(std::unique(lineage.pending.begin(), lineage.pending.end()),
                          lineage.pending.end());

    report.lineageCount += 1;
    if (lineage.converged) {
      report.convergedCount += 1;
    } else if (!lineage.blockers.empty() &&
               (lineage.blockers.front() == BlockerKind::RetryBudgetExhausted ||
                lineage.blockers.front() == BlockerKind::GuaranteeUnsupported ||
                lineage.blockers.front() == BlockerKind::ArtifactUnavailable ||
                lineage.blockers.front() == BlockerKind::PolicyRejected ||
                lineage.blockers.front() == BlockerKind::TargetAheadOfDesired ||
                lineage.blockers.front() == BlockerKind::DigestMismatchReported ||
                lineage.blockers.front() == BlockerKind::SchemaUnsupported)) {
      report.blockedCount += 1;
    } else if (lineage.currentGeneration.isSet() &&
               lineage.currentGeneration < lineage.desiredGeneration) {
      report.divergedCount += 1;
    } else {
      report.pendingCount += 1;
    }
    report.lineages.push_back(std::move(lineage));
  }
  return report;
}

std::string ConvergenceReport::render() const {
  std::string out;
  out.reserve(512 + (lineages.size() * 320));
  out.append("convergence node=");
  out.append(nodeId.str());
  out.append(" epoch=");
  out.append(std::to_string(epoch.value()));
  out.append(" incarnation=");
  out.append(incarnation.hex().substr(0, 8));
  out.push_back('\n');
  out.append("lineages=");
  out.append(std::to_string(lineageCount));
  out.append(" converged=");
  out.append(std::to_string(convergedCount));
  out.append(" pending=");
  out.append(std::to_string(pendingCount));
  out.append(" diverged=");
  out.append(std::to_string(divergedCount));
  out.append(" blocked=");
  out.append(std::to_string(blockedCount));
  out.append(" retired=");
  out.append(std::to_string(retiredCount));
  out.append(" rejected=");
  out.append(std::to_string(rejectedCount));
  out.push_back('\n');
  out.append("state=");
  out.append(converged() ? "converged" : "not-converged");
  out.push_back('\n');

  for (const LineageConvergence& lineage : lineages) {
    out.append("target=");
    out.append(lineage.target.str());
    out.append(" key=");
    out.append(lineage.key.str());
    out.append(" desired-generation=");
    out.append(std::to_string(lineage.desiredGeneration.value()));
    out.append(" desired-digest=");
    out.append(shortDigest(lineage.desiredDigest));
    out.append(" current-generation=");
    out.append(lineage.currentGeneration.isSet() ? std::to_string(lineage.currentGeneration.value())
                                                 : std::string("none"));
    out.append(" current-digest=");
    out.append(lineage.currentDigest.isSet() ? shortDigest(lineage.currentDigest)
                                             : std::string("none"));
    out.append(" state=");
    out.append(deliveryStateName(lineage.state));
    out.append(" guarantee=");
    out.append(applyGuaranteeName(lineage.guarantee));
    out.append(" required=");
    out.append(guaranteeRequirementName(lineage.requirement));
    out.append(" outcome=");
    out.append(lineage.converged ? "converged" : "not-converged");
    out.push_back('\n');
    out.append("  reason: ");
    out.append(lineage.currentReason);
    out.push_back('\n');
    if (!lineage.blockers.empty()) {
      out.append("  blockers:");
      for (const BlockerKind blocker : lineage.blockers) {
        out.push_back(' ');
        out.append(blockerKindName(blocker));
      }
      out.push_back('\n');
    }
    if (!lineage.pending.empty()) {
      out.append("  pending:\n");
      for (const std::string& item : lineage.pending) {
        out.append("    - ");
        out.append(item);
        out.push_back('\n');
      }
    }
  }
  return out;
}

std::string ConvergenceReport::fingerprint() const {
  std::string material;
  material.reserve(256 + (lineages.size() * 128));
  material.append(nodeId.str());
  material.push_back('|');
  material.append(std::to_string(epoch.value()));
  material.push_back('|');
  for (const LineageConvergence& lineage : lineages) {
    material.append(lineage.target.str());
    material.push_back(':');
    material.append(lineage.key.str());
    material.push_back(':');
    material.append(std::to_string(lineage.desiredGeneration.value()));
    material.push_back(':');
    material.append(lineage.currentGeneration.isSet()
                        ? std::to_string(lineage.currentGeneration.value())
                        : std::string("-"));
    material.push_back(':');
    material.append(deliveryStateName(lineage.state));
    material.push_back(':');
    material.append(lineage.converged ? "1" : "0");
    material.push_back(';');
  }
  return shortDigest(Digest::ofText(material));
}

std::string explainTarget(const ControllerState& state, const DistributorPolicy& policy,
                          const TargetId& target, std::int64_t nowMillis) {
  std::string out;
  out.reserve(2048);
  out.append("target: ");
  out.append(target.str());
  out.push_back('\n');

  const TargetRuntime* runtime = state.findTarget(target);
  if (runtime == nullptr) {
    out.append("  runtime: never contacted\n");
  } else {
    out.append("  class = ");
    out.append(targetClassName(runtime->klass));
    out.push_back('\n');
    out.append("  apply-guarantee = ");
    out.append(applyGuaranteeName(runtime->guarantee));
    out.push_back('\n');
    out.append("  target-term = ");
    out.append(std::to_string(runtime->term.value()));
    out.push_back('\n');
    out.append("  target-incarnation = ");
    out.append(runtime->incarnation.isSet() ? runtime->incarnation.hex() : std::string("unset"));
    out.push_back('\n');
    out.append("  committed-generation = ");
    out.append(runtime->committedGeneration.isSet()
                   ? std::to_string(runtime->committedGeneration.value())
                   : std::string("none"));
    out.push_back('\n');
    out.append("  committed-digest = ");
    out.append(runtime->committedDigest.isSet() ? runtime->committedDigest.hex()
                                                : std::string("none"));
    out.push_back('\n');
    out.append("  contact-established-this-process = ");
    out.append(runtime->contactEstablishedThisProcess ? "true" : "false");
    out.push_back('\n');
    out.append("  sessions-established = ");
    out.append(std::to_string(runtime->sessionsEstablished));
    out.push_back('\n');
    out.append("  restarts-observed = ");
    out.append(std::to_string(runtime->restartsObserved));
    out.push_back('\n');
    out.append("  unresolved-prepare-window = ");
    out.append(runtime->applyPrepared ? "true" : "false");
    out.push_back('\n');
    out.append("  live = ");
    out.append(isFreshContact(*runtime, policy, nowMillis) ? "true" : "false");
    out.push_back('\n');
  }

  bool any = false;
  for (const auto& entry : state.deliveries) {
    const DeliveryRecord& record = entry.second;
    if (!(record.target == target)) {
      continue;
    }
    any = true;
    out.append("  delivery ");
    out.append(record.id.str());
    out.push_back('\n');
    out.append("    deployment-set = ");
    out.append(record.setId.str());
    out.push_back('\n');
    out.append("    config-key = ");
    out.append(record.key.str());
    out.push_back('\n');
    out.append("    artifact = ");
    out.append(record.artifact.str());
    out.append(" revision=");
    out.append(std::to_string(record.revision.value()));
    out.push_back('\n');
    out.append("    generation = ");
    out.append(std::to_string(record.generation.value()));
    out.append(" digest = ");
    out.append(record.digest.hex());
    out.push_back('\n');
    out.append("    schema = ");
    out.append(record.schema.str());
    out.append(" schema-version=");
    out.append(std::to_string(record.schemaVersion.value()));
    out.push_back('\n');
    out.append("    requirement = ");
    out.append(guaranteeRequirementName(record.requirement));
    out.append(" effective-guarantee = ");
    out.append(applyGuaranteeName(record.effectiveGuarantee));
    out.push_back('\n');
    out.append("    state = ");
    out.append(deliveryStateName(record.state));
    out.append(" attempt = ");
    out.append(std::to_string(record.attempt.value()));
    out.append(" failures = ");
    out.append(std::to_string(record.failures));
    out.push_back('\n');
    if (record.lastError != ErrorCode::Ok) {
      out.append("    last-error = ");
      out.append(errorCodeName(record.lastError));
      out.append(" (");
      out.append(retryDirectiveName(record.lastDirective));
      out.append(")");
      if (!record.lastDetail.empty()) {
        out.append(": ");
        out.append(record.lastDetail);
      }
      out.push_back('\n');
    }
    out.append("    authority-epoch = ");
    out.append(std::to_string(record.authorityEpoch.value()));
    out.append(" authority-incarnation = ");
    out.append(record.authorityIncarnation.isSet()
                   ? record.authorityIncarnation.hex().substr(0, 8)
                   : std::string("unset"));
    out.push_back('\n');
    out.append("    acknowledged-from-reconciliation = ");
    out.append(record.acknowledgedFromReconcile ? "true" : "false");
    out.push_back('\n');
    if (!record.events.empty()) {
      out.append("    evidence:\n");
      for (const LifecycleEvent& event : record.events) {
        out.append("      - ");
        out.append(event.render());
        out.push_back('\n');
      }
    }
    const Decision decision =
        decide(policy, buildDecisionInput(state, policy, record, nowMillis), state.epoch,
               record.generation);
    std::string rendered = decision.render(policy);
    out.append("    ");
    std::size_t start = 0;
    while (start < rendered.size()) {
      const std::size_t newline = rendered.find('\n', start);
      const std::string_view lineValue =
          (newline == std::string::npos)
              ? std::string_view(rendered).substr(start)
              : std::string_view(rendered).substr(start, newline - start);
      out.append("    ");
      out.append(lineValue);
      out.push_back('\n');
      if (newline == std::string::npos) {
        break;
      }
      start = newline + 1;
    }
  }
  if (!any) {
    out.append("  no deliveries are recorded for this target\n");
  }
  return out;
}

}  // namespace cf
