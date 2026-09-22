// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/reconciliation.hpp"

#include <string>

namespace cf {

std::string_view reconcileOutcomeName(ReconcileOutcome outcome) noexcept {
  switch (outcome) {
    case ReconcileOutcome::DriveNormally:
      return "drive-normally";
    case ReconcileOutcome::AdoptActivation:
      return "adopt-activation";
    case ReconcileOutcome::ResumeTransfer:
      return "resume-transfer";
    case ReconcileOutcome::RetireStale:
      return "retire-stale";
    case ReconcileOutcome::ResolvePrepareWindow:
      return "resolve-prepare-window";
    case ReconcileOutcome::FenceAuthority:
      return "fence-authority";
    case ReconcileOutcome::UnknownAtTarget:
      return "unknown-at-target";
  }
  return "unknown";
}

const TransferStatusRecord* findTransferStatus(const ReconcileReportMessage& report,
                                               const DeploymentId& deployment) {
  for (const TransferStatusRecord& record : report.transfers) {
    if (record.deployment == deployment) {
      return &record;
    }
  }
  return nullptr;
}

bool reportProvesActivation(const ReconcileReportMessage& report, Generation generation,
                            const Digest& digest, const ConfigKey& key) {
  if (!generation.isSet() || !digest.isSet()) {
    return false;
  }
  if (!(report.committedGeneration == generation) || !(report.committedDigest == digest)) {
    // The live pointer is the strongest evidence; the findings table is the
    // durable record of an activation that may since have been superseded.
    for (const ReconcileFinding& finding : report.findings) {
      if (finding.generation == generation && finding.digest == digest &&
          isActivationState(finding.state)) {
        // A finding only proves the boundary occurred for this config key.
        (void)key;
        return true;
      }
    }
    return false;
  }
  return true;
}

std::string ReconcileDecision::render() const {
  std::string out;
  out.reserve(192);
  out.append("reconcile: ");
  out.append(reconcileOutcomeName(outcome));
  out.append(" - ");
  out.append(reason);
  if (outcome == ReconcileOutcome::ResumeTransfer) {
    out.append(" resume-from=");
    out.append(std::to_string(resumeFromOffset));
  }
  if (outcome == ReconcileOutcome::RetireStale) {
    out.append(" target-generation=");
    out.append(std::to_string(targetGeneration.value()));
  }
  return out;
}

ReconcileDecision reconcileDelivery(const ReconcileInput& input) {
  ReconcileDecision decision;
  if (input.report == nullptr) {
    decision.outcome = ReconcileOutcome::DriveNormally;
    decision.reason =
        "no live report from the target in this session; persisted evidence is not treated as "
        "current, so the delivery is driven from its recorded state";
    return decision;
  }
  const ReconcileReportMessage& report = *input.report;

  // Authority first: a report from a different term or incarnation than the one
  // this session authenticated is not evidence about this target.
  if (!(report.term == input.sessionTerm) || !(report.incarnation == input.sessionIncarnation)) {
    decision.outcome = ReconcileOutcome::FenceAuthority;
    decision.reason =
        "the report carries target authority that does not match the authenticated session";
    return decision;
  }

  if (report.applyPrepared) {
    decision.outcome = ReconcileOutcome::ResolvePrepareWindow;
    decision.reason =
        "the target reports an unresolved prepare/commit window for generation " +
        std::to_string(report.preparedGeneration.value()) +
        "; committing blind could activate content the target never verified";
    return decision;
  }

  if (report.committedGeneration.isSet() && report.committedGeneration > input.desiredGeneration) {
    decision.outcome = ReconcileOutcome::RetireStale;
    decision.targetGeneration = report.committedGeneration;
    decision.targetDigest = report.committedDigest;
    decision.reason =
        "the target is already at generation " + std::to_string(report.committedGeneration.value()) +
        ", which is newer than the desired generation " +
        std::to_string(input.desiredGeneration.value()) +
        "; pushing this delivery would move the target backwards";
    return decision;
  }

  if (reportProvesActivation(report, input.desiredGeneration, input.desiredDigest, input.key)) {
    decision.outcome = ReconcileOutcome::AdoptActivation;
    decision.adoptedState = DeliveryState::Applied;
    decision.reason =
        "the target reports generation " + std::to_string(input.desiredGeneration.value()) +
        " with the expected digest as active under the current incarnation";
    return decision;
  }

  const TransferStatusRecord* transfer = findTransferStatus(report, input.deployment);
  if (transfer != nullptr && transfer->bytesReceived > 0 &&
      transfer->generation == input.desiredGeneration && transfer->digest == input.desiredDigest &&
      transfer->bytesReceived < transfer->totalBytes) {
    decision.outcome = ReconcileOutcome::ResumeTransfer;
    decision.resumeFromOffset = transfer->bytesReceived;
    decision.reason = "the target holds " + std::to_string(transfer->bytesReceived) +
                      " verified byte(s) for this deployment; restarting the transfer would "
                      "discard them";
    return decision;
  }
  if (transfer != nullptr && transfer->verified && transfer->staged &&
      transfer->generation == input.desiredGeneration && transfer->digest == input.desiredDigest) {
    decision.outcome = ReconcileOutcome::DriveNormally;
    decision.reason =
        "the target holds a verified, staged artifact for this generation; activation is the "
        "remaining boundary";
    return decision;
  }
  if (transfer == nullptr && !report.committedGeneration.isSet() &&
      report.findings.empty()) {
    decision.outcome = ReconcileOutcome::UnknownAtTarget;
    decision.reason = "the target reports no state at all; the delivery starts from the beginning";
    return decision;
  }
  decision.outcome = ReconcileOutcome::DriveNormally;
  decision.reason = "the target holds nothing usable for this deployment; it is driven normally";
  return decision;
}

}  // namespace cf
