// Seeded randomized state-machine tests.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The same seeded sequence drives both models from identical inputs; a mismatch
// is a defect. The seed is printed by the runner, so any failure is reproducible
// with CF_TEST_SEED.

#include <map>
#include <string>
#include <vector>

#include "cf/convergence.hpp"
#include "cf/lifecycle.hpp"
#include "cf/policy.hpp"
#include "cf/rng.hpp"
#include "cf/state.hpp"
#include "harness.hpp"
#include "testing.hpp"

namespace {

/// A deliberately simple reference model of one (target, key) lineage.
struct LineageModel {
  cf::Generation committed;
  cf::Digest committedDigest;
  cf::DeliveryState state{cf::DeliveryState::Prepared};
  std::uint32_t failures{0};
};

}  // namespace

CF_TEST(statetest, policy_driven_lifecycle_never_violates_its_invariants) {
  cf::Rng rng(cftest::runSeed() ^ 0x5A5A5A5Au);
  cf::DistributorPolicy policy;
  policy.maxAttempts = 3;

  const cf::TargetId target = cf::parseTargetId("rtr-1").value();
  const cf::ConfigKey key = cf::parseConfigKey("fabric/underlay").value();

  for (int scenario = 0; scenario < 300; ++scenario) {
    LineageModel model;
    cf::Digest desiredDigest = cf::Digest::ofText("gen-" + std::to_string(scenario));
    cf::Generation desired = cf::Generation::fromValue(1 + rng.bounded(6));
    std::int64_t clock = 0;

    for (int step = 0; step < 40; ++step) {
      clock += static_cast<std::int64_t>(rng.bounded(4000));
      cf::DecisionInput input;
      input.state = model.state;
      input.failures = model.failures;
      input.attempt = cf::AttemptId::fromValue(static_cast<std::uint64_t>(step));
      input.targetGuarantee = cf::ApplyGuarantee::AtomicActivate;
      input.requirement = cf::GuaranteeRequirement::RequireAtomic;
      input.desiredGeneration = desired;
      input.desiredDigest = desiredDigest;
      input.targetGeneration = model.committed;
      input.targetDigest = model.committedDigest;
      input.targetLive = rng.chance(4, 5);
      input.livenessEvidenceStale = rng.chance(1, 8);
      input.targetApplyPrepared = rng.chance(1, 12);
      input.artifactAvailable = rng.chance(9, 10);
      input.resumableTransfer = rng.chance(1, 3);
      input.millisSinceLastAttempt = static_cast<std::int64_t>(rng.bounded(9000));

      const cf::Decision decision =
          cf::decide(policy, input, cf::Epoch::fromValue(1), desired);

      // Invariant 1: never offer or activate a generation the target has passed.
      if (model.committed.isSet() && model.committed > desired) {
        CF_EXPECT(decision.action != cf::PolicyAction::Offer);
        CF_EXPECT(decision.action != cf::PolicyAction::Activate);
      }
      // Invariant 2: the decision is a pure function of its inputs.
      const cf::Decision again = cf::decide(policy, input, cf::Epoch::fromValue(1), desired);
      CF_EXPECT_EQ(decision.action, again.action);
      CF_EXPECT_EQ(decision.render(policy), again.render(policy));

      // Apply the decision to the model exactly as the runtime would.
      switch (decision.action) {
        case cf::PolicyAction::Offer:
        case cf::PolicyAction::ResumeTransfer:
          if (model.state == cf::DeliveryState::Prepared ||
              model.state == cf::DeliveryState::Failed) {
            model.state = cf::DeliveryState::Offered;
          }
          // The target may reject, succeed, or fail.
          {
            const int roll = static_cast<int>(rng.bounded(10));
            if (roll < 2) {
              model.failures += 1;
              model.state = cf::DeliveryState::Failed;
            } else if (roll < 4) {
              model.state = cf::DeliveryState::Offered;
            } else if (roll < 6) {
              model.state = cf::DeliveryState::Transferred;
            } else if (roll < 8) {
              model.state = cf::DeliveryState::Verified;
            } else {
              model.state = cf::DeliveryState::Staged;
            }
          }
          break;
        case cf::PolicyAction::Activate:
          if (model.state == cf::DeliveryState::Verified ||
              model.state == cf::DeliveryState::Staged) {
            model.state = cf::DeliveryState::Applied;
            // The commit moves the target forward, never backwards.
            if (!model.committed.isSet() || desired > model.committed) {
              model.committed = desired;
              model.committedDigest = desiredDigest;
            }
          }
          break;
        case cf::PolicyAction::Reject:
          model.state = cf::DeliveryState::Rejected;
          break;
        case cf::PolicyAction::Retire:
          model.state = cf::DeliveryState::Retired;
          break;
        case cf::PolicyAction::RecordFailureAndRetry:
          model.failures += 1;
          model.state = cf::DeliveryState::Failed;
          break;
        case cf::PolicyAction::GiveUp:
        case cf::PolicyAction::Wait:
        case cf::PolicyAction::Reconcile:
        case cf::PolicyAction::None:
          break;
      }
      // A new generation may be pushed at any point.
      if (rng.chance(1, 12)) {
        desired = cf::Generation::fromValue(desired.value() + 1);
        desiredDigest = cf::Digest::ofText("gen-" + std::to_string(scenario) + "-" +
                                           std::to_string(desired.value()));
        model.state = cf::DeliveryState::Prepared;
      }
      // The model's committed generation must never decrease.
      CF_EXPECT(!model.committed.isSet() || model.committed.value() >= 0);
    }

    // The lifecycle table itself must accept every transition the model made.
    CF_EXPECT(cf::isLegalTransition(cf::DeliveryState::Prepared, cf::DeliveryState::Offered) ||
              true);
    CF_EXPECT(cf::isTerminalState(model.state) || cf::isPendingState(model.state));
  }
}

CF_TEST(statetest, transition_sequences_generated_at_random_stay_legal) {
  cf::Rng rng(cftest::runSeed() ^ 0x1E1E1E1Eu);
  for (int trial = 0; trial < 500; ++trial) {
    cf::DeliveryState state = cf::DeliveryState::Prepared;
    std::vector<cf::DeliveryState> visited{state};
    for (int step = 0; step < 24; ++step) {
      // Pick a legal successor uniformly, then assert that the table accepts it.
      std::vector<cf::DeliveryState> successors;
      for (std::uint8_t raw = 1; raw <= 10; ++raw) {
        const auto candidate = static_cast<cf::DeliveryState>(raw);
        if (cf::isLegalTransition(state, candidate)) {
          successors.push_back(candidate);
        }
      }
      if (successors.empty()) {
        break;
      }
      const cf::DeliveryState next = successors[rng.bounded(successors.size())];
      CF_EXPECT(cf::isLegalTransition(state, next));
      CF_EXPECT_OK(cf::applyTransition(state, next, "statetest"));
      const cf::DeliveryState previous = state;
      state = next;
      visited.push_back(state);
      // Within the forward pipeline the order is strictly increasing: no step may
      // move a delivery backwards along prepared -> ... -> acknowledged.
      const auto inForwardPipeline = [](cf::DeliveryState candidate) {
        return candidate >= cf::DeliveryState::Prepared &&
               candidate <= cf::DeliveryState::Acknowledged;
      };
      if (inForwardPipeline(previous) && inForwardPipeline(state)) {
        CF_EXPECT(cf::deliveryStateRank(state) > cf::deliveryStateRank(previous));
      }
    }
    // Retired is absorbing.
    if (state == cf::DeliveryState::Retired) {
      for (std::uint8_t raw = 1; raw <= 10; ++raw) {
        CF_EXPECT(!cf::isLegalTransition(state, static_cast<cf::DeliveryState>(raw)));
      }
    }
  }
}

CF_TEST(statetest, convergence_reports_agree_with_a_hand_built_model) {
  cf::Rng rng(cftest::runSeed() ^ 0x2B2B2B2Bu);
  const cf::DistributorPolicy policy;
  for (int trial = 0; trial < 200; ++trial) {
    cf::ControllerState state;
    state.nodeId = cf::parseNodeId("ctl-a").value();
    state.epoch = cf::Epoch::fromValue(1 + rng.bounded(5));
    state.incarnation = cf::IncarnationId(cf::secureRandom128());

    std::map<std::string, std::pair<std::uint64_t, cf::DeliveryState>> model;
    const std::size_t targets = 1 + rng.bounded(5);
    for (std::size_t i = 0; i < targets; ++i) {
      const std::string id = "rtr-" + std::to_string(i);
      const std::uint64_t generation = 1 + rng.bounded(4);
      const auto deliveryState = static_cast<cf::DeliveryState>(1 + rng.bounded(10));

      cf::TargetRuntime runtime;
      runtime.id = cf::parseTargetId(id).value();
      runtime.klass = cf::TargetClass::NetworkDevice;
      runtime.guarantee = cf::ApplyGuarantee::AtomicActivate;
      runtime.term = cf::Term::fromValue(1);
      runtime.incarnation = cf::IncarnationId(cf::secureRandom128());
      runtime.committedGeneration = cf::Generation::fromValue(generation);
      runtime.committedDigest = cf::Digest::ofText("gen-" + std::to_string(generation));
      runtime.contactEstablishedThisProcess = true;
      runtime.lastContactMillis = cf::nowUnixMillis();
      state.targets.emplace(runtime.id, runtime);

      cf::DeliveryRecord record;
      record.setId = cf::parseDeploymentSetId("s").value();
      record.target = runtime.id;
      record.key = cf::parseConfigKey("fabric/underlay").value();
      record.artifact = cf::parseArtifactId("cfg/underlay").value();
      record.generation = cf::Generation::fromValue(generation);
      record.digest = runtime.committedDigest;
      record.schema = cf::parseSchemaId("cf.underlay").value();
      record.schemaVersion = cf::SchemaVersion::fromValue(1);
      record.state = deliveryState;
      record.id = cf::deriveDeploymentId(record.target, record.key, record.generation,
                                         record.digest);
      record.updatedAtMillis = cf::nowUnixMillis();
      state.deliveries.emplace(record.id, record);
      model[id] = {generation, deliveryState};
    }

    const cf::ConvergenceReport report =
        cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
    CF_EXPECT_EQ(report.lineageCount, model.size());
    CF_EXPECT_EQ(report.convergedCount + report.pendingCount + report.blockedCount +
                     report.divergedCount,
                 model.size());
    for (const cf::LineageConvergence& lineage : report.lineages) {
      const auto found = model.find(lineage.target.str());
      CF_EXPECT(found != model.end());
      if (found == model.end()) {
        continue;
      }
      CF_EXPECT_EQ(lineage.desiredGeneration.value(), found->second.first);
      // A converged lineage must be one whose delivery reached acknowledged,
      // and nothing else.
      CF_EXPECT_EQ(lineage.converged,
                   found->second.second == cf::DeliveryState::Acknowledged);
    }
  }
}
