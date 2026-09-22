// Unit tests: deterministic convergence summaries and explanations.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <string>

#include "cf/convergence.hpp"
#include "harness.hpp"
#include "cf/rng.hpp"
#include "testing.hpp"

namespace {

cf::ControllerState baseState() {
  cf::ControllerState state;
  state.nodeId = cf::parseNodeId("ctl-a").value();
  state.epoch = cf::Epoch::fromValue(3);
  state.incarnation = cf::IncarnationId(cf::secureRandom128());
  return state;
}

cf::TargetRuntime targetAt(const std::string& id, std::uint64_t generation, bool contactCurrent) {
  cf::TargetRuntime runtime;
  runtime.id = cf::parseTargetId(id).value();
  runtime.klass = cf::TargetClass::NetworkDevice;
  runtime.guarantee = cf::ApplyGuarantee::AtomicActivate;
  runtime.term = cf::Term::fromValue(4);
  runtime.incarnation = cf::IncarnationId(cf::secureRandom128());
  runtime.committedGeneration = cf::Generation::fromValue(generation);
  runtime.committedDigest = cf::Digest::ofText("generation-" + std::to_string(generation));
  runtime.committedArtifact = cf::parseArtifactId("cfg/underlay").value();
  runtime.endpoint = "127.0.0.1:9000";
  runtime.contactEstablishedThisProcess = contactCurrent;
  runtime.lastContactMillis = cf::nowUnixMillis();
  return runtime;
}

cf::DeliveryRecord deliveryFor(const std::string& target, std::uint64_t generation,
                               cf::DeliveryState state) {
  cf::DeliveryRecord record;
  record.setId = cf::parseDeploymentSetId("set-1").value();
  record.target = cf::parseTargetId(target).value();
  record.key = cf::parseConfigKey("fabric/underlay").value();
  record.artifact = cf::parseArtifactId("cfg/underlay").value();
  record.revision = cf::Revision::fromValue(generation);
  record.generation = cf::Generation::fromValue(generation);
  record.digest = cf::Digest::ofText("generation-" + std::to_string(generation));
  record.schema = cf::parseSchemaId("cf.underlay").value();
  record.schemaVersion = cf::SchemaVersion::fromValue(1);
  record.sizeBytes = 64;
  record.state = state;
  record.id = cf::deriveDeploymentId(record.target, record.key, record.generation, record.digest);
  record.updatedAtMillis = cf::nowUnixMillis();
  return record;
}

}  // namespace

CF_TEST(unit, converged_acknowledged_delivery) {
  cf::ControllerState state = baseState();
  const cf::TargetRuntime runtime = targetAt("rtr-1", 4, true);
  state.targets.emplace(runtime.id, runtime);
  const cf::DeliveryRecord record = deliveryFor("rtr-1", 4, cf::DeliveryState::Acknowledged);
  state.deliveries.emplace(record.id, record);
  state.artifacts.emplace(record.digest, cf::ArtifactMetadata{});

  const cf::DistributorPolicy policy;
  const cf::ConvergenceReport report =
      cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
  CF_EXPECT_EQ(report.lineageCount, std::size_t{1});
  CF_EXPECT_EQ(report.convergedCount, std::size_t{1});
  CF_EXPECT(report.converged());
  CF_EXPECT(report.lineages[0].converged);
  CF_EXPECT(report.lineages[0].blockers.empty());
  const std::string rendered = report.render();
  CF_EXPECT(cf::test::containsText(rendered, "state=converged"));
  CF_EXPECT(cf::test::containsText(rendered, "desired-generation=4"));
}

CF_TEST(unit, applied_but_unacknowledged_is_a_blocker) {
  cf::ControllerState state = baseState();
  const cf::TargetRuntime runtime = targetAt("rtr-1", 4, true);
  state.targets.emplace(runtime.id, runtime);
  const cf::DeliveryRecord record = deliveryFor("rtr-1", 4, cf::DeliveryState::Applied);
  state.deliveries.emplace(record.id, record);

  const cf::DistributorPolicy policy;
  const cf::ConvergenceReport report =
      cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
  CF_EXPECT(!report.converged());
  CF_EXPECT_EQ(report.pendingCount, std::size_t{1});
  bool mentioned = false;
  for (const cf::BlockerKind blocker : report.lineages[0].blockers) {
    if (blocker == cf::BlockerKind::AwaitingAcknowledgement) {
      mentioned = true;
    }
  }
  CF_EXPECT(mentioned);
  CF_EXPECT(cf::test::containsText(report.render(), "awaiting-acknowledgement"));
}

CF_TEST(unit, diverged_target_is_reported_with_its_reason) {
  cf::ControllerState state = baseState();
  const cf::TargetRuntime runtime = targetAt("rtr-1", 2, true);
  state.targets.emplace(runtime.id, runtime);
  const cf::DeliveryRecord record = deliveryFor("rtr-1", 5, cf::DeliveryState::Offered);
  state.deliveries.emplace(record.id, record);

  const cf::DistributorPolicy policy;
  const cf::ConvergenceReport report =
      cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
  CF_EXPECT_EQ(report.divergedCount, std::size_t{1});
  CF_EXPECT_EQ(report.lineages[0].currentGeneration.value(), std::uint64_t{2});
  CF_EXPECT_EQ(report.lineages[0].desiredGeneration.value(), std::uint64_t{5});
  CF_EXPECT(!report.lineages[0].currentReason.empty());
}

CF_TEST(unit, exhausted_retries_are_blocked_not_pending) {
  cf::ControllerState state = baseState();
  const cf::TargetRuntime runtime = targetAt("rtr-1", 1, true);
  state.targets.emplace(runtime.id, runtime);
  cf::DeliveryRecord record = deliveryFor("rtr-1", 5, cf::DeliveryState::Failed);
  record.failures = 9;
  record.lastError = cf::ErrorCode::DigestMismatch;
  record.lastDetail = "digest mismatch at the target";
  state.deliveries.emplace(record.id, record);

  const cf::DistributorPolicy policy;
  const cf::ConvergenceReport report =
      cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
  CF_EXPECT_EQ(report.blockedCount, std::size_t{1});
  bool exhausted = false;
  bool digest = false;
  for (const cf::BlockerKind blocker : report.lineages[0].blockers) {
    if (blocker == cf::BlockerKind::RetryBudgetExhausted) {
      exhausted = true;
    }
    if (blocker == cf::BlockerKind::DigestMismatchReported) {
      digest = true;
    }
  }
  CF_EXPECT(exhausted);
  CF_EXPECT(digest);
}

CF_TEST(unit, guarantee_mismatch_is_blocked_with_the_weaker_guarantee_named) {
  cf::ControllerState state = baseState();
  cf::TargetRuntime runtime = targetAt("rtr-1", 0, true);
  runtime.guarantee = cf::ApplyGuarantee::PrepareCommitAbort;
  state.targets.emplace(runtime.id, runtime);
  cf::DeliveryRecord record = deliveryFor("rtr-1", 1, cf::DeliveryState::Rejected);
  record.effectiveGuarantee = cf::ApplyGuarantee::PrepareCommitAbort;
  record.requirement = cf::GuaranteeRequirement::RequireAtomic;
  record.lastError = cf::ErrorCode::GuaranteeUnsupported;
  record.lastDetail = "target cannot satisfy the required guarantee";
  state.deliveries.emplace(record.id, record);

  const cf::DistributorPolicy policy;
  const cf::ConvergenceReport report =
      cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
  CF_EXPECT_EQ(report.rejectedCount, std::size_t{1});
  CF_EXPECT_EQ(report.blockedCount, std::size_t{1});
  const std::string rendered = report.render();
  CF_EXPECT(cf::test::containsText(rendered, "guarantee-unsupported"));
  CF_EXPECT(cf::test::containsText(rendered, "guarantee=prepare-commit-abort"));
}

CF_TEST(unit, persisted_liveness_evidence_is_not_treated_as_current) {
  cf::ControllerState state = baseState();
  const cf::TargetRuntime runtime = targetAt("rtr-1", 1, false);
  state.targets.emplace(runtime.id, runtime);
  const cf::DeliveryRecord record = deliveryFor("rtr-1", 2, cf::DeliveryState::Prepared);
  state.deliveries.emplace(record.id, record);

  const cf::DistributorPolicy policy;
  const cf::ConvergenceReport report =
      cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
  bool stale = false;
  for (const cf::BlockerKind blocker : report.lineages[0].blockers) {
    if (blocker == cf::BlockerKind::LivenessEvidenceStale) {
      stale = true;
    }
  }
  CF_EXPECT(stale);

  // The decision must not treat the persisted evidence as a live session.
  const cf::DecisionInput input =
      cf::buildDecisionInput(state, policy, record, cf::nowUnixMillis());
  CF_EXPECT(!input.targetLive);
  CF_EXPECT(input.livenessEvidenceStale);
}

CF_TEST(unit, fingerprint_is_deterministic_and_sensitive) {
  cf::ControllerState state = baseState();
  const cf::TargetRuntime runtime = targetAt("rtr-1", 4, true);
  state.targets.emplace(runtime.id, runtime);
  const cf::DeliveryRecord record = deliveryFor("rtr-1", 4, cf::DeliveryState::Acknowledged);
  state.deliveries.emplace(record.id, record);

  const cf::DistributorPolicy policy;
  const cf::ConvergenceReport first =
      cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
  const cf::ConvergenceReport second =
      cf::buildConvergenceReport(state, policy, cf::nowUnixMillis() + 1000);
  CF_EXPECT_EQ(first.fingerprint(), second.fingerprint());
  // The rendering contains no wall-clock values, so it is byte-identical too.
  CF_EXPECT_EQ(first.render(), second.render());

  cf::ControllerState changed = state;
  changed.deliveries.begin()->second.state = cf::DeliveryState::Applied;
  const cf::ConvergenceReport updated =
      cf::buildConvergenceReport(changed, policy, cf::nowUnixMillis());
  CF_EXPECT(first.fingerprint() != updated.fingerprint());
}

CF_TEST(unit, explanation_lists_evidence_policy_and_decision) {
  cf::ControllerState state = baseState();
  const cf::TargetRuntime runtime = targetAt("rtr-1", 3, true);
  state.targets.emplace(runtime.id, runtime);
  cf::DeliveryRecord record = deliveryFor("rtr-1", 4, cf::DeliveryState::Verified);
  cf::LifecycleEvent event;
  event.kind = cf::EvidenceKind::DigestVerified;
  event.from = cf::DeliveryState::Transferred;
  event.to = cf::DeliveryState::Verified;
  event.generation = record.generation;
  event.digest = record.digest;
  event.authorityEpoch = state.epoch;
  event.authorityIncarnation = state.incarnation;
  event.atMillis = 1;
  event.detail = "digest matched";
  record.events.push_back(event);
  state.deliveries.emplace(record.id, record);
  state.artifacts.emplace(record.digest, cf::ArtifactMetadata{});

  const cf::DistributorPolicy policy;
  const std::string explanation =
      cf::explainTarget(state, policy, runtime.id, cf::nowUnixMillis());
  CF_EXPECT(cf::test::containsText(explanation, "apply-guarantee"));
  CF_EXPECT(cf::test::containsText(explanation, "digest-verified"));
  CF_EXPECT(cf::test::containsText(explanation, "action = activate"));
  CF_EXPECT(cf::test::containsText(explanation, "decision:"));
  CF_EXPECT(cf::test::containsText(explanation, "policy:"));
  CF_EXPECT(cf::test::containsText(explanation, "authority-epoch"));
  CF_EXPECT(cf::test::containsText(explanation, "transferred->verified"));

  // Explaining an unknown target is still deterministic and honest.
  const std::string unknown = cf::explainTarget(
      state, policy, cf::parseTargetId("never-seen").value(), cf::nowUnixMillis());
  CF_EXPECT(cf::test::containsText(unknown, "never contacted"));
}

CF_TEST(unit, newest_generation_wins_the_lineage) {
  cf::ControllerState state = baseState();
  const cf::TargetRuntime runtime = targetAt("rtr-1", 1, true);
  state.targets.emplace(runtime.id, runtime);
  const cf::DeliveryRecord older = deliveryFor("rtr-1", 1, cf::DeliveryState::Retired);
  const cf::DeliveryRecord newer = deliveryFor("rtr-1", 2, cf::DeliveryState::Prepared);
  state.deliveries.emplace(older.id, older);
  state.deliveries.emplace(newer.id, newer);

  const cf::DistributorPolicy policy;
  const cf::ConvergenceReport report =
      cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
  CF_EXPECT_EQ(report.lineageCount, std::size_t{1});
  CF_EXPECT_EQ(report.retiredCount, std::size_t{1});
  CF_EXPECT_EQ(report.lineages[0].desiredGeneration.value(), std::uint64_t{2});
}

CF_TEST(property, reports_are_deterministic_under_permutation) {
  const cf::DistributorPolicy policy;
  cf::Rng rng(cftest::runSeed() ^ 0x0C0Eu);
  for (int trial = 0; trial < 200; ++trial) {
    cf::ControllerState state = baseState();
    const std::size_t targets = 1 + rng.bounded(4);
    for (std::size_t i = 0; i < targets; ++i) {
      const std::string id = "rtr-" + std::to_string(i);
      const std::uint64_t committed = rng.bounded(4);
      const cf::TargetRuntime runtime = targetAt(id, committed, rng.chance(1, 2));
      state.targets.emplace(runtime.id, runtime);
      const cf::DeliveryRecord record = deliveryFor(
          id, committed + 1, static_cast<cf::DeliveryState>(1 + rng.bounded(10)));
      state.deliveries.emplace(record.id, record);
    }
    const cf::ConvergenceReport first =
        cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
    const cf::ConvergenceReport second =
        cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
    CF_EXPECT_EQ(first.render(), second.render());
    CF_EXPECT_EQ(first.fingerprint(), second.fingerprint());
    CF_EXPECT_EQ(first.lineages.size(), state.deliveries.size());
    // Counts must add up: every lineage lands in exactly one bucket.
    CF_EXPECT_EQ(first.convergedCount + first.pendingCount + first.blockedCount +
                     first.divergedCount,
                 first.lineageCount);
  }
}
