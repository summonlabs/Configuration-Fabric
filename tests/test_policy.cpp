// Unit and property tests: deterministic policy decisions and explanations.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <string>
#include <vector>

#include "cf/policy.hpp"
#include "harness.hpp"
#include "cf/rng.hpp"
#include "testing.hpp"

namespace {

cf::DecisionInput baseInput() {
  cf::DecisionInput input;
  input.state = cf::DeliveryState::Prepared;
  input.targetGuarantee = cf::ApplyGuarantee::AtomicActivate;
  input.requirement = cf::GuaranteeRequirement::RequireAtomic;
  input.desiredGeneration = cf::Generation::fromValue(4);
  input.desiredDigest = cf::Digest::ofText("payload");
  input.targetGeneration = cf::Generation::fromValue(3);
  input.targetDigest = cf::Digest::ofText("previous");
  input.targetLive = true;
  input.artifactAvailable = true;
  input.attempt = cf::AttemptId::fromValue(1);
  return input;
}

}  // namespace

CF_TEST(unit, policy_validation_rejects_inconsistent_bounds) {
  cf::DistributorPolicy policy;
  CF_EXPECT_OK(policy.validate());
  policy.maxAttempts = 0;
  CF_EXPECT_CODE(policy.validate(), cf::ErrorCode::InvalidArgument);
  policy = cf::DistributorPolicy{};
  policy.transferChunkBytes = policy.maxPayloadBytes + 1;
  CF_EXPECT_CODE(policy.validate(), cf::ErrorCode::InvalidArgument);
  policy = cf::DistributorPolicy{};
  policy.maxBackoffMillis = policy.retryBackoffMillis - 1;
  CF_EXPECT_CODE(policy.validate(), cf::ErrorCode::InvalidArgument);
}

CF_TEST(unit, fresh_delivery_is_offered) {
  const cf::DistributorPolicy policy;
  const cf::Decision decision =
      cf::decide(policy, baseInput(), cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(decision.action, cf::PolicyAction::Offer);
  CF_EXPECT(!decision.terminal);
  const std::string rendered = decision.render(policy);
  CF_EXPECT(rendered.find("action = offer") != std::string::npos);
  CF_EXPECT(rendered.find("authority-epoch") != std::string::npos);
}

CF_TEST(unit, stale_generation_is_retired_never_offered) {
  const cf::DistributorPolicy policy;
  cf::DecisionInput input = baseInput();
  input.targetGeneration = cf::Generation::fromValue(9);
  const cf::Decision decision =
      cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(decision.action, cf::PolicyAction::Retire);
  CF_EXPECT(decision.terminal);
  bool mentionedOffer = false;
  for (const cf::RejectedAlternative& alternative : decision.alternatives) {
    if (alternative.action == cf::PolicyAction::Offer) {
      mentionedOffer = true;
    }
  }
  CF_EXPECT(mentionedOffer);
}

CF_TEST(unit, guarantee_mismatch_is_rejected) {
  const cf::DistributorPolicy policy;
  cf::DecisionInput input = baseInput();
  input.targetGuarantee = cf::ApplyGuarantee::PrepareCommitAbort;
  input.requirement = cf::GuaranteeRequirement::RequireAtomic;
  const cf::Decision decision =
      cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(decision.action, cf::PolicyAction::Reject);
  CF_EXPECT(decision.terminal);
  CF_EXPECT(decision.reason.find("prepare-commit-abort") != std::string::npos);
}

CF_TEST(unit, missing_artifact_is_rejected) {
  const cf::DistributorPolicy policy;
  cf::DecisionInput input = baseInput();
  input.artifactAvailable = false;
  const cf::Decision decision =
      cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(decision.action, cf::PolicyAction::Reject);
}

CF_TEST(unit, stale_liveness_evidence_forces_reconciliation) {
  const cf::DistributorPolicy policy;
  cf::DecisionInput input = baseInput();
  input.livenessEvidenceStale = true;
  const cf::Decision decision =
      cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(decision.action, cf::PolicyAction::Reconcile);
  CF_EXPECT(decision.reason.find("freshness window") != std::string::npos);
}

CF_TEST(unit, open_prepare_window_forces_reconciliation) {
  const cf::DistributorPolicy policy;
  cf::DecisionInput input = baseInput();
  input.targetApplyPrepared = true;
  const cf::Decision decision =
      cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(decision.action, cf::PolicyAction::Reconcile);
}

CF_TEST(unit, retry_backoff_is_bounded_and_monotone) {
  const cf::DistributorPolicy policy;
  cf::DecisionInput input = baseInput();
  input.state = cf::DeliveryState::Failed;
  std::int64_t previous = -1;
  for (std::uint32_t failures = 1; failures < policy.maxAttempts; ++failures) {
    input.failures = failures;
    input.millisSinceLastAttempt = 0;
    const cf::Decision decision =
        cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
    CF_EXPECT_EQ(decision.action, cf::PolicyAction::Wait);
    CF_EXPECT(decision.retryAfterMillis > previous);
    CF_EXPECT(decision.retryAfterMillis <= policy.maxBackoffMillis);
    previous = decision.retryAfterMillis;
  }
  // Once the backoff elapses the delivery is offered again.
  input.millisSinceLastAttempt = policy.maxBackoffMillis;
  const cf::Decision afterBackoff =
      cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(afterBackoff.action, cf::PolicyAction::Offer);
}

CF_TEST(unit, exhausted_retry_budget_gives_up) {
  const cf::DistributorPolicy policy;
  cf::DecisionInput input = baseInput();
  input.state = cf::DeliveryState::Failed;
  input.failures = policy.maxAttempts;
  input.millisSinceLastAttempt = policy.maxBackoffMillis * 4;
  const cf::Decision decision =
      cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(decision.action, cf::PolicyAction::GiveUp);
  CF_EXPECT(decision.terminal);
}

CF_TEST(unit, staged_delivery_is_activated) {
  const cf::DistributorPolicy policy;
  cf::DecisionInput input = baseInput();
  input.state = cf::DeliveryState::Staged;
  const cf::Decision decision =
      cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(decision.action, cf::PolicyAction::Activate);
}

CF_TEST(unit, partial_transfer_resumes) {
  const cf::DistributorPolicy policy;
  cf::DecisionInput input = baseInput();
  input.state = cf::DeliveryState::Offered;
  input.resumableTransfer = true;
  const cf::Decision decision =
      cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(decision.action, cf::PolicyAction::ResumeTransfer);
}

CF_TEST(unit, applied_delivery_awaits_reconciliation_when_ack_required) {
  const cf::DistributorPolicy policy;
  cf::DecisionInput input = baseInput();
  input.state = cf::DeliveryState::Applied;
  const cf::Decision decision =
      cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(decision.action, cf::PolicyAction::Reconcile);

  cf::DistributorPolicy permissive = policy;
  permissive.requireAcknowledgement = false;
  const cf::Decision relaxed =
      cf::decide(permissive, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(relaxed.action, cf::PolicyAction::None);
}

CF_TEST(unit, offline_target_requests_a_session) {
  // A target whose contact evidence is not fresh cannot justify any state change,
  // and doing nothing would leave it unreachable forever. The decision is to
  // establish evidence with a session; the scheduler rate-limits how often that
  // may be attempted and the retry budget bounds how often it may fail.
  const cf::DistributorPolicy policy;
  cf::DecisionInput input = baseInput();
  input.targetLive = false;
  const cf::Decision decision =
      cf::decide(policy, input, cf::Epoch::fromValue(1), cf::Generation::fromValue(4));
  CF_EXPECT_EQ(decision.action, cf::PolicyAction::Reconcile);
  CF_EXPECT(cf::test::containsText(decision.reason, "freshness window") ||
            cf::test::containsText(decision.reason, "predates this process"));
  bool mentionedOffer = false;
  for (const cf::RejectedAlternative& alternative : decision.alternatives) {
    if (alternative.action == cf::PolicyAction::Offer) {
      mentionedOffer = true;
    }
  }
  CF_EXPECT(mentionedOffer);
}

CF_TEST(unit, policy_action_names_round_trip) {
  for (std::uint8_t raw = 0; raw <= 9; ++raw) {
    const auto action = static_cast<cf::PolicyAction>(raw);
    cf::PolicyAction parsed{};
    CF_EXPECT(cf::parsePolicyAction(cf::policyActionName(action), parsed));
    CF_EXPECT(parsed == action);
  }
}

CF_TEST(property, decisions_are_pure_and_repeatable) {
  const cf::DistributorPolicy policy;
  cf::Rng rng(cftest::runSeed() ^ 0xD00Du);
  for (int iteration = 0; iteration < 2000; ++iteration) {
    cf::DecisionInput input = baseInput();
    input.state = static_cast<cf::DeliveryState>(1 + rng.bounded(10));
    input.targetGuarantee = static_cast<cf::ApplyGuarantee>(1 + rng.bounded(2));
    input.requirement = static_cast<cf::GuaranteeRequirement>(1 + rng.bounded(2));
    input.desiredGeneration = cf::Generation::fromValue(1 + rng.bounded(10));
    input.targetGeneration =
        cf::Generation::fromValue(rng.chance(1, 4) ? 0 : 1 + rng.bounded(12));
    input.targetLive = rng.chance(3, 4);
    input.livenessEvidenceStale = rng.chance(1, 5);
    input.targetApplyPrepared = rng.chance(1, 6);
    input.artifactAvailable = rng.chance(4, 5);
    input.resumableTransfer = rng.chance(1, 3);
    input.supersededByNewerGeneration = rng.chance(1, 7);
    input.failures = static_cast<std::uint32_t>(rng.bounded(8));
    input.millisSinceLastAttempt = rng.bounded(20000);
    input.attempt = cf::AttemptId::fromValue(rng.bounded(8));

    const cf::Decision first =
        cf::decide(policy, input, cf::Epoch::fromValue(3), cf::Generation::fromValue(5));
    const cf::Decision second =
        cf::decide(policy, input, cf::Epoch::fromValue(3), cf::Generation::fromValue(5));
    CF_EXPECT_EQ(first.action, second.action);
    CF_EXPECT_EQ(first.render(policy), second.render(policy));
    CF_EXPECT(!first.reason.empty());

    // The invariant the scheduler depends on: a decision never asks to activate
    // a generation the target has already moved past.
    if (input.targetGeneration.isSet() &&
        input.targetGeneration > input.desiredGeneration) {
      CF_EXPECT(first.action != cf::PolicyAction::Activate);
      CF_EXPECT(first.action != cf::PolicyAction::Offer);
    }
    // A guarantee mismatch is never offered or activated.
    if (!cf::guaranteeSatisfies(input.targetGuarantee, input.requirement)) {
      CF_EXPECT(first.action != cf::PolicyAction::Offer);
      CF_EXPECT(first.action != cf::PolicyAction::Activate);
    }
  }
}
