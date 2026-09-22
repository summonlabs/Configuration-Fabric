// Unit and property tests: the delivery lifecycle state machine.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <set>
#include <string>
#include <vector>

#include "cf/lifecycle.hpp"
#include "cf/rng.hpp"
#include "testing.hpp"

namespace {

const std::vector<cf::DeliveryState> kAllStates = {
    cf::DeliveryState::Prepared,  cf::DeliveryState::Offered,
    cf::DeliveryState::Transferred, cf::DeliveryState::Verified,
    cf::DeliveryState::Staged,    cf::DeliveryState::Applied,
    cf::DeliveryState::Acknowledged, cf::DeliveryState::Failed,
    cf::DeliveryState::Rejected,  cf::DeliveryState::Retired};

}  // namespace

CF_TEST(unit, state_names_round_trip) {
  for (const cf::DeliveryState state : kAllStates) {
    cf::DeliveryState parsed{};
    CF_EXPECT(cf::parseDeliveryState(cf::deliveryStateName(state), parsed));
    CF_EXPECT(parsed == state);
  }
  cf::DeliveryState unused{};
  CF_EXPECT(!cf::parseDeliveryState("nonsense", unused));
}

CF_TEST(unit, happy_path_is_linear) {
  CF_EXPECT(cf::isLegalTransition(cf::DeliveryState::Prepared, cf::DeliveryState::Offered));
  CF_EXPECT(cf::isLegalTransition(cf::DeliveryState::Offered, cf::DeliveryState::Transferred));
  CF_EXPECT(cf::isLegalTransition(cf::DeliveryState::Transferred, cf::DeliveryState::Verified));
  CF_EXPECT(cf::isLegalTransition(cf::DeliveryState::Verified, cf::DeliveryState::Staged));
  CF_EXPECT(cf::isLegalTransition(cf::DeliveryState::Staged, cf::DeliveryState::Applied));
  CF_EXPECT(cf::isLegalTransition(cf::DeliveryState::Applied, cf::DeliveryState::Acknowledged));
  // The pipeline never skips a boundary on the way up.
  CF_EXPECT(!cf::isLegalTransition(cf::DeliveryState::Prepared, cf::DeliveryState::Staged));
  CF_EXPECT(!cf::isLegalTransition(cf::DeliveryState::Prepared, cf::DeliveryState::Acknowledged));
  CF_EXPECT(!cf::isLegalTransition(cf::DeliveryState::Transferred, cf::DeliveryState::Staged));
}

CF_TEST(unit, terminal_states_are_terminal) {
  CF_EXPECT(cf::isTerminalState(cf::DeliveryState::Acknowledged));
  CF_EXPECT(cf::isTerminalState(cf::DeliveryState::Rejected));
  CF_EXPECT(cf::isTerminalState(cf::DeliveryState::Retired));
  CF_EXPECT(!cf::isTerminalState(cf::DeliveryState::Failed));
  for (const cf::DeliveryState state : kAllStates) {
    if (state == cf::DeliveryState::Retired) {
      for (const cf::DeliveryState other : kAllStates) {
        CF_EXPECT(!cf::isLegalTransition(state, other));
      }
    }
  }
}

CF_TEST(unit, illegal_transition_is_refused_without_mutation) {
  const cf::Result<cf::DeliveryState> refused = cf::applyTransition(
      cf::DeliveryState::Prepared, cf::DeliveryState::Acknowledged, "test");
  CF_EXPECT_CODE(refused, cf::ErrorCode::IllegalTransition);
  CF_EXPECT_OK(cf::applyTransition(cf::DeliveryState::Prepared, cf::DeliveryState::Offered, "test"));
}

CF_TEST(unit, transition_table_renders) {
  const std::string rendered = cf::renderTransitionTable();
  CF_EXPECT(rendered.find("prepared -> offered") != std::string::npos);
  CF_EXPECT(rendered.find("retired -> (terminal)") != std::string::npos);
}

CF_TEST(property, legal_transitions_never_move_backwards) {
  cf::Rng rng(cftest::runSeed() ^ 0x5EEDu);
  for (int trial = 0; trial < 5000; ++trial) {
    const auto from = kAllStates[rng.bounded(kAllStates.size())];
    const auto to = kAllStates[rng.bounded(kAllStates.size())];
    if (!cf::isLegalTransition(from, to)) {
      continue;
    }
    // Nothing ever leaves Retired.
    CF_EXPECT(from != cf::DeliveryState::Retired);
    // The acknowledgement boundary is reachable only from the activation that it
    // acknowledges. A delivery cannot become acknowledged without having been
    // observed as applied first.
    if (to == cf::DeliveryState::Acknowledged) {
      CF_EXPECT(from == cf::DeliveryState::Applied);
    }
    // Once acknowledged, the only possible move is retirement: nothing may
    // reopen, fail or re-drive an acknowledged delivery.
    if (from == cf::DeliveryState::Acknowledged) {
      CF_EXPECT(to == cf::DeliveryState::Retired);
    }
    // An applied delivery may be acknowledged, may be discovered to have failed,
    // or may be retired - never sent back to a pre-activation state.
    if (from == cf::DeliveryState::Applied) {
      CF_EXPECT(to == cf::DeliveryState::Acknowledged || to == cf::DeliveryState::Failed ||
                to == cf::DeliveryState::Retired);
    }
    // A rejected delivery is only ever retired; rejection is final for a
    // generation.
    if (from == cf::DeliveryState::Rejected) {
      CF_EXPECT(to == cf::DeliveryState::Retired);
    }
  }
}

CF_TEST(property, terminals_and_successors_agree_with_the_table) {
  for (const cf::DeliveryState state : kAllStates) {
    bool hasSuccessor = false;
    for (const cf::DeliveryState other : kAllStates) {
      if (cf::isLegalTransition(state, other)) {
        hasSuccessor = true;
      }
    }
    // Acknowledged is terminal for progress yet may still be retired, so the
    // relation is: every state except Retired has at least one successor.
    CF_EXPECT_EQ(hasSuccessor, state != cf::DeliveryState::Retired);
    CF_EXPECT_EQ(cf::isTerminalState(state),
                 state == cf::DeliveryState::Acknowledged ||
                     state == cf::DeliveryState::Rejected || state == cf::DeliveryState::Retired);
  }
}

CF_TEST(unit, evidence_names_round_trip) {
  std::set<std::string> names;
  for (std::uint8_t raw = 1; raw <= 13; ++raw) {
    const auto kind = static_cast<cf::EvidenceKind>(raw);
    CF_EXPECT(names.insert(std::string(cf::evidenceKindName(kind))).second);
    cf::EvidenceKind parsed{};
    CF_EXPECT(cf::parseEvidenceKind(cf::evidenceKindName(kind), parsed));
    CF_EXPECT(parsed == kind);
  }
}

CF_TEST(unit, lifecycle_event_renders_deterministically) {
  cf::LifecycleEvent event;
  event.kind = cf::EvidenceKind::ActivationReported;
  event.from = cf::DeliveryState::Staged;
  event.to = cf::DeliveryState::Applied;
  event.generation = cf::Generation::fromValue(4);
  event.digest = cf::Digest::ofText("x");
  event.authorityEpoch = cf::Epoch::fromValue(2);
  event.authorityIncarnation = cf::IncarnationId(cf::secureRandom128());
  event.targetTerm = cf::Term::fromValue(7);
  event.targetIncarnation = cf::IncarnationId(cf::secureRandom128());
  event.atMillis = 1234;
  event.detail = "activation reported";
  const std::string first = event.render();
  const std::string second = event.render();
  CF_EXPECT_EQ(first, second);
  CF_EXPECT(first.find("activation-reported") != std::string::npos);
  CF_EXPECT(first.find("staged->applied") != std::string::npos);
  CF_EXPECT(first.find("activation reported") != std::string::npos);
}
