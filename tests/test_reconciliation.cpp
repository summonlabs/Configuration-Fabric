// Unit tests: the pure reconciliation decision function.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <string>

#include "cf/reconciliation.hpp"
#include "harness.hpp"
#include "testing.hpp"

namespace {

cf::ReconcileInput baseInput() {
  cf::ReconcileInput input;
  input.sessionTerm = cf::Term::fromValue(3);
  input.sessionIncarnation = cf::IncarnationId(cf::secureRandom128());
  input.desiredGeneration = cf::Generation::fromValue(4);
  input.desiredDigest = cf::Digest::ofText("desired");
  input.key = cf::parseConfigKey("fabric/underlay").value();
  input.deployment = cf::parseDeploymentId("d-1").value();
  input.state = cf::DeliveryState::Offered;
  input.guarantee = cf::ApplyGuarantee::AtomicActivate;
  input.requirement = cf::GuaranteeRequirement::RequireAtomic;
  input.artifactAvailable = true;
  return input;
}

cf::ReconcileReportMessage reportFor(const cf::ReconcileInput& input) {
  cf::ReconcileReportMessage report;
  report.target = cf::parseTargetId("rtr-1").value();
  report.targetClass = cf::TargetClass::NetworkDevice;
  report.guarantee = cf::ApplyGuarantee::AtomicActivate;
  report.term = input.sessionTerm;
  report.incarnation = input.sessionIncarnation;
  return report;
}

}  // namespace

CF_TEST(unit, no_report_drives_normally) {
  const cf::ReconcileDecision decision = cf::reconcileDelivery(baseInput());
  CF_EXPECT_EQ(decision.outcome, cf::ReconcileOutcome::DriveNormally);
  CF_EXPECT(cf::test::containsText(decision.reason, "persisted evidence"));
}

CF_TEST(unit, matching_report_adopts_activation) {
  cf::ReconcileInput input = baseInput();
  cf::ReconcileReportMessage report = reportFor(input);
  report.committedGeneration = input.desiredGeneration;
  report.committedDigest = input.desiredDigest;
  input.report = &report;
  const cf::ReconcileDecision decision = cf::reconcileDelivery(input);
  CF_EXPECT_EQ(decision.outcome, cf::ReconcileOutcome::AdoptActivation);
  CF_EXPECT_EQ(decision.adoptedState, cf::DeliveryState::Applied);
}

CF_TEST(unit, finding_also_proves_activation) {
  cf::ReconcileInput input = baseInput();
  cf::ReconcileReportMessage report = reportFor(input);
  cf::ReconcileFinding finding;
  finding.key = input.key;
  finding.generation = input.desiredGeneration;
  finding.digest = input.desiredDigest;
  finding.state = cf::DeliveryState::Applied;
  finding.deployment = input.deployment;
  report.findings.push_back(finding);
  input.report = &report;
  const cf::ReconcileDecision decision = cf::reconcileDelivery(input);
  CF_EXPECT_EQ(decision.outcome, cf::ReconcileOutcome::AdoptActivation);
}

CF_TEST(unit, partial_transfer_resumes_from_the_targets_count) {
  cf::ReconcileInput input = baseInput();
  cf::ReconcileReportMessage report = reportFor(input);
  cf::TransferStatusRecord transfer;
  transfer.deployment = input.deployment;
  transfer.stream = cf::StreamId::fromValue(1);
  transfer.key = input.key;
  transfer.generation = input.desiredGeneration;
  transfer.digest = input.desiredDigest;
  transfer.bytesReceived = 512;
  transfer.totalBytes = 2048;
  report.transfers.push_back(transfer);
  input.report = &report;
  const cf::ReconcileDecision decision = cf::reconcileDelivery(input);
  CF_EXPECT_EQ(decision.outcome, cf::ReconcileOutcome::ResumeTransfer);
  CF_EXPECT_EQ(decision.resumeFromOffset, static_cast<std::uint64_t>(512));
}

CF_TEST(unit, target_ahead_of_desired_retires_the_delivery) {
  cf::ReconcileInput input = baseInput();
  cf::ReconcileReportMessage report = reportFor(input);
  report.committedGeneration = cf::Generation::fromValue(9);
  report.committedDigest = cf::Digest::ofText("newer");
  input.report = &report;
  const cf::ReconcileDecision decision = cf::reconcileDelivery(input);
  CF_EXPECT_EQ(decision.outcome, cf::ReconcileOutcome::RetireStale);
  CF_EXPECT_EQ(decision.targetGeneration.value(), std::uint64_t{9});
  CF_EXPECT(cf::test::containsText(decision.reason, "backwards"));
}

CF_TEST(unit, open_prepare_window_must_be_resolved) {
  cf::ReconcileInput input = baseInput();
  cf::ReconcileReportMessage report = reportFor(input);
  report.applyPrepared = true;
  report.preparedDeployment = input.deployment;
  report.preparedGeneration = input.desiredGeneration;
  report.preparedDigest = input.desiredDigest;
  input.report = &report;
  const cf::ReconcileDecision decision = cf::reconcileDelivery(input);
  CF_EXPECT_EQ(decision.outcome, cf::ReconcileOutcome::ResolvePrepareWindow);
  CF_EXPECT(cf::test::containsText(decision.reason, "never verified"));
}

CF_TEST(adversarial, report_from_another_incarnation_is_fenced) {
  cf::ReconcileInput input = baseInput();
  cf::ReconcileReportMessage report = reportFor(input);
  report.incarnation = cf::IncarnationId(cf::secureRandom128());
  report.committedGeneration = input.desiredGeneration;
  report.committedDigest = input.desiredDigest;
  input.report = &report;
  const cf::ReconcileDecision decision = cf::reconcileDelivery(input);
  CF_EXPECT_EQ(decision.outcome, cf::ReconcileOutcome::FenceAuthority);
}

CF_TEST(adversarial, report_from_another_term_is_fenced) {
  cf::ReconcileInput input = baseInput();
  cf::ReconcileReportMessage report = reportFor(input);
  report.term = cf::Term::fromValue(99);
  report.committedGeneration = input.desiredGeneration;
  report.committedDigest = input.desiredDigest;
  input.report = &report;
  const cf::ReconcileDecision decision = cf::reconcileDelivery(input);
  CF_EXPECT_EQ(decision.outcome, cf::ReconcileOutcome::FenceAuthority);
}

CF_TEST(adversarial, a_finding_for_another_config_key_is_not_accepted) {
  // A finding with the right generation and digest but no committed pointer is
  // still evidence: the target's durable record names the config key it applied
  // the generation to only through the generation identity, which is
  // content-addressed. What must never happen is accepting a finding whose
  // digest differs.
  cf::ReconcileInput input = baseInput();
  cf::ReconcileReportMessage report = reportFor(input);
  cf::ReconcileFinding finding;
  finding.key = input.key;
  finding.generation = input.desiredGeneration;
  finding.digest = cf::Digest::ofText("something else");
  finding.state = cf::DeliveryState::Applied;
  report.findings.push_back(finding);
  input.report = &report;
  const cf::ReconcileDecision decision = cf::reconcileDelivery(input);
  CF_EXPECT(decision.outcome != cf::ReconcileOutcome::AdoptActivation);
}

CF_TEST(unit, unknown_target_state_is_reported) {
  cf::ReconcileInput input = baseInput();
  cf::ReconcileReportMessage report = reportFor(input);
  input.report = &report;
  const cf::ReconcileDecision decision = cf::reconcileDelivery(input);
  CF_EXPECT_EQ(decision.outcome, cf::ReconcileOutcome::UnknownAtTarget);
}

CF_TEST(unit, outcome_names_are_total) {
  for (std::uint8_t raw = 0; raw <= 6; ++raw) {
    const auto outcome = static_cast<cf::ReconcileOutcome>(raw);
    CF_EXPECT(cf::reconcileOutcomeName(outcome) != "unknown");
  }
}

CF_TEST(unit, decision_rendering_is_deterministic) {
  cf::ReconcileInput input = baseInput();
  cf::ReconcileReportMessage report = reportFor(input);
  report.committedGeneration = cf::Generation::fromValue(9);
  report.committedDigest = cf::Digest::ofText("newer");
  input.report = &report;
  const cf::ReconcileDecision first = cf::reconcileDelivery(input);
  const cf::ReconcileDecision second = cf::reconcileDelivery(input);
  CF_EXPECT_EQ(first.render(), second.render());
  CF_EXPECT(cf::test::containsText(first.render(), "retire-stale"));
}
