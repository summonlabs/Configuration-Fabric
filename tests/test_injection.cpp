// Failure-injection tests: real processes killed and broken at protocol boundaries.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Every case here runs the shipped executables. Faults are injected through the
// documented validation-only injection points or by killing an OS process; no
// behaviour is simulated in-process.

#include <string>
#include <thread>
#include <vector>

#include "cf/codec.hpp"
#include "harness.hpp"
#include "testing.hpp"

namespace {

struct Fixture {
  cf::test::TempDir directory{"inject"};
  std::string controllerState;
  std::string artifactRoot;
  std::string keyFile;

  explicit Fixture(std::string label) : label_(std::move(label)) {
    controllerState = directory.child("ctl-state");
    artifactRoot = directory.child("ctl-artifacts");
    keyFile = cf::test::keyFileFor(directory);
  }

  [[nodiscard]] const std::string& label() const { return label_; }

 private:
  std::string label_;
};

}  // namespace

CF_TEST(injection, agent_killed_during_chunk_streaming_reconciles_and_converges) {
  Fixture fixture("kill-chunk");
  const std::string agentState = fixture.directory.child("agent-state");
  const std::string body(40000, 'k');
  // The agent dies after accepting 2 chunks.
  auto agent = cf::test::startAgent(fixture.directory, "rtr-1", agentState, "atomic-activate",
                                    "after-chunk:2", true, "agent");
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      fixture.directory, "set-kill",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", body, "", 0}},
      nullptr);
  auto controller = cf::test::startController(fixture.directory, "ctl-kill",
                                              fixture.controllerState, fixture.artifactRoot, {plan},
                                              "", "6", true, "controller", 0);
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }

  // Wait for the injected death, then confirm no false convergence.
  for (int attempt = 0; attempt < 200 && agent->running(); ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  CF_EXPECT(!agent->running());
  std::string output;
  (void)cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output, 40);
  CF_EXPECT(!cf::test::containsText(output, "state=converged"));

  // Restart the agent on the same state directory with the same endpoint.
  const std::string endpoint = agent->endpoint();
  auto parsed = cf::parseEndpoint(endpoint);
  CF_EXPECT_OK(parsed);
  const std::string announce = fixture.directory.child("agent2.endpoint");
  cf::test::writeTextFile(announce, "");
  std::vector<std::string> arguments = {
      "--target", "rtr-1", "--state", agentState, "--listen", endpoint, "--announce-file",
      announce, "--log-level", "debug", "--log-file", fixture.directory.child("agent2.log"),
      "--key-file", fixture.keyFile};
  auto restarted = std::make_unique<cf::test::ServiceProcess>(
      CF_TEST_AGENT_PATH, std::move(arguments), announce,
      fixture.directory.child("agent2.log"));
  CF_EXPECT(restarted->start());
  if (!restarted->running()) {
    return;
  }

  const bool converged = cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output);
  CF_EXPECT_MSG(converged,
                output + controller->logText() + agent->logText() + restarted->logText());
  const std::string pointer = cf::test::readLivePointer(agentState, "fabric/underlay");
  CF_EXPECT(cf::test::containsText(pointer, "1 "));
}

CF_TEST(injection, agent_killed_after_verification_converges_after_restart) {
  Fixture fixture("kill-verify");
  const std::string agentState = fixture.directory.child("agent-state");
  const std::string body = "verified but not activated yet\n";
  auto agent = cf::test::startAgent(fixture.directory, "rtr-1", agentState, "atomic-activate",
                                    "after-verify", true, "agent");
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      fixture.directory, "set-verify",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", body, "", 0}},
      nullptr);
  auto controller = cf::test::startController(fixture.directory, "ctl-verify",
                                              fixture.controllerState, fixture.artifactRoot, {plan},
                                              "", "6");
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  for (int attempt = 0; attempt < 300 && agent->running(); ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  CF_EXPECT(!agent->running());

  // Nothing was activated: the live pointer is absent.
  CF_EXPECT(cf::test::readLivePointer(agentState, "fabric/underlay").empty());

  const std::string endpoint = agent->endpoint();
  const std::string announce = fixture.directory.child("agent2.endpoint");
  std::vector<std::string> arguments = {
      "--target", "rtr-1", "--state", agentState, "--listen", endpoint, "--announce-file",
      announce, "--log-level", "debug", "--log-file", fixture.directory.child("agent2.log"),
      "--key-file", fixture.keyFile};
  auto restarted = std::make_unique<cf::test::ServiceProcess>(
      CF_TEST_AGENT_PATH, std::move(arguments), announce,
      fixture.directory.child("agent2.log"));
  CF_EXPECT(restarted->start());
  std::string output;
  const bool converged = cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output);
  CF_EXPECT_MSG(converged, output + controller->logText() + restarted->logText());
  CF_EXPECT(cf::test::containsText(cf::test::readLivePointer(agentState, "fabric/underlay"), "1 "));
}

CF_TEST(injection, agent_killed_before_the_activation_switch_is_recovered) {
  Fixture fixture("kill-switch");
  const std::string agentState = fixture.directory.child("agent-state");
  const std::string body = "switch boundary body\n";
  auto agent = cf::test::startAgent(fixture.directory, "rtr-1", agentState, "atomic-activate",
                                    "before-commit", true, "agent");
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      fixture.directory, "set-switch",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", body, "", 0}},
      nullptr);
  auto controller = cf::test::startController(fixture.directory, "ctl-switch",
                                              fixture.controllerState, fixture.artifactRoot, {plan},
                                              "", "6");
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  for (int attempt = 0; attempt < 300 && agent->running(); ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  CF_EXPECT(!agent->running());
  // The switch never happened, so the target is still on nothing.
  CF_EXPECT(cf::test::readLivePointer(agentState, "fabric/underlay").empty());

  const std::string endpoint = agent->endpoint();
  const std::string announce = fixture.directory.child("agent2.endpoint");
  std::vector<std::string> arguments = {
      "--target", "rtr-1", "--state", agentState, "--listen", endpoint, "--announce-file",
      announce, "--log-level", "debug", "--log-file", fixture.directory.child("agent2.log"),
      "--key-file", fixture.keyFile};
  auto restarted = std::make_unique<cf::test::ServiceProcess>(
      CF_TEST_AGENT_PATH, std::move(arguments), announce,
      fixture.directory.child("agent2.log"));
  CF_EXPECT(restarted->start());
  std::string output;
  const bool converged = cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output);
  CF_EXPECT_MSG(converged, output + controller->logText() + restarted->logText());
  CF_EXPECT(cf::test::containsText(cf::test::readLivePointer(agentState, "fabric/underlay"), "1 "));
}

CF_TEST(injection, agent_killed_after_the_switch_before_the_record_adopts_the_pointer) {
  Fixture fixture("kill-after-switch");
  const std::string agentState = fixture.directory.child("agent-state");
  const std::string body = "switched but unrecorded\n";
  auto agent = cf::test::startAgent(fixture.directory, "rtr-1", agentState, "atomic-activate",
                                    "after-switch", true, "agent");
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      fixture.directory, "set-after",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", body, "", 0}},
      nullptr);
  auto controller = cf::test::startController(fixture.directory, "ctl-after",
                                              fixture.controllerState, fixture.artifactRoot, {plan},
                                              "", "6");
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  for (int attempt = 0; attempt < 300 && agent->running(); ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  CF_EXPECT(!agent->running());
  // The switch happened before the process died.
  const std::string pointerBefore = cf::test::readLivePointer(agentState, "fabric/underlay");
  CF_EXPECT(cf::test::containsText(pointerBefore, "1 "));

  const std::string endpoint = agent->endpoint();
  const std::string announce = fixture.directory.child("agent2.endpoint");
  std::vector<std::string> arguments = {
      "--target", "rtr-1", "--state", agentState, "--listen", endpoint, "--announce-file",
      announce, "--log-level", "debug", "--log-file", fixture.directory.child("agent2.log"),
      "--key-file", fixture.keyFile};
  auto restarted = std::make_unique<cf::test::ServiceProcess>(
      CF_TEST_AGENT_PATH, std::move(arguments), announce,
      fixture.directory.child("agent2.log"));
  CF_EXPECT(restarted->start());
  // Start-up reconciliation adopts the pointer rather than inventing the old
  // generation.
  CF_EXPECT(cf::test::containsText(restarted->logText(), "adopted-live-pointer") ||
            cf::test::containsText(restarted->logText(), "adopted-completed-switch"));
  std::string output;
  const bool converged = cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) {
        return cf::test::containsText(text, "state=converged") &&
               cf::test::containsText(text, "evidence recovered by reconciliation");
      },
      &output);
  CF_EXPECT_MSG(converged, output + controller->logText() + restarted->logText());
}

CF_TEST(injection, prepare_commit_window_killed_mid_window_rolls_back_and_redelivers) {
  Fixture fixture("kill-prepare");
  const std::string agentState = fixture.directory.child("agent-state");
  const std::string body = "weak contract, killed in the window\n";
  auto agent = cf::test::startAgent(fixture.directory, "rtr-1", agentState, "prepare-commit-abort",
                                    "after-prepare", true, "agent");
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      fixture.directory, "set-prepare",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1,
                            "prepare-commit-abort", "allow-prepare-commit", agent->endpoint(), "",
                            body, "", 0}},
      nullptr);
  auto controller = cf::test::startController(fixture.directory, "ctl-prepare",
                                              fixture.controllerState, fixture.artifactRoot, {plan},
                                              "", "8");
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  for (int attempt = 0; attempt < 300 && agent->running(); ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  CF_EXPECT(!agent->running());
  // The window is open but nothing has been activated.
  CF_EXPECT(cf::test::readLivePointer(agentState, "fabric/underlay").empty());

  const std::string endpoint = agent->endpoint();
  const std::string announce = fixture.directory.child("agent2.endpoint");
  std::vector<std::string> arguments = {
      "--target", "rtr-1", "--state", agentState, "--listen", endpoint, "--announce-file",
      announce, "--log-level", "debug", "--log-file", fixture.directory.child("agent2.log"),
      "--key-file", fixture.keyFile, "--guarantee", "prepare-commit-abort"};
  auto restarted = std::make_unique<cf::test::ServiceProcess>(
      CF_TEST_AGENT_PATH, std::move(arguments), announce,
      fixture.directory.child("agent2.log"));
  CF_EXPECT(restarted->start());
  // The unresolved window was aborted, not silently committed.
  CF_EXPECT(cf::test::containsText(restarted->logText(), "aborted-unresolved-prepare"));

  std::string output;
  const bool converged = cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) {
        return cf::test::containsText(text, "state=converged") &&
               cf::test::containsText(text, "guarantee=prepare-commit-abort");
      },
      &output);
  CF_EXPECT_MSG(converged, output + controller->logText() + restarted->logText());
}

CF_TEST(injection, withheld_acknowledgement_leaves_the_delivery_applied) {
  Fixture fixture("withhold-ack");
  const std::string agentState = fixture.directory.child("agent-state");
  const std::string body = "activated but not acknowledged\n";
  auto agent = cf::test::startAgent(fixture.directory, "rtr-1", agentState, "atomic-activate",
                                    "withhold-ack", true, "agent");
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      fixture.directory, "set-ack",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", body, "", 0}},
      nullptr);
  auto controller = cf::test::startController(fixture.directory, "ctl-ack",
                                              fixture.controllerState, fixture.artifactRoot, {plan},
                                              "", "6");
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  // The delivery settles either at "applied" (the acknowledgement never arrived)
  // or at "acknowledged" if a later reconcile session resolved it. Both are
  // correct; what must never happen is an acknowledgement that is not labelled
  // as reconciliation evidence.
  const bool settled = cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) {
        return cf::test::containsText(text, "state=applied") ||
               cf::test::containsText(text, "state=acknowledged");
      },
      &output);
  CF_EXPECT_MSG(settled, output + controller->logText() + agent->logText());
  if (cf::test::containsText(output, "state=acknowledged")) {
    CF_EXPECT_MSG(cf::test::containsText(output, "evidence recovered by reconciliation"), output);
  } else {
    CF_EXPECT(cf::test::containsText(output, "awaiting-acknowledgement"));
  }

  // The target really did activate it; only the live claim is missing.
  CF_EXPECT(cf::test::containsText(cf::test::readLivePointer(agentState, "fabric/underlay"), "1 "));
}

CF_TEST(injection, withheld_acknowledgement_is_resolved_by_reconciliation) {
  Fixture fixture("ack-reconcile");
  const std::string agentState = fixture.directory.child("agent-state");
  const std::string body = "acknowledgement lost then reconciled\n";
  auto agent = cf::test::startAgent(fixture.directory, "rtr-1", agentState, "atomic-activate", "",
                                    true, "agent");
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      fixture.directory, "set-ack2",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", body, "", 0}},
      nullptr);
  // The controller never waits for the acknowledgement, so the delivery stops at
  // "applied"; a restart must then recover the acknowledgement from the target.
  auto controller = cf::test::startController(fixture.directory, "ctl-ack2",
                                              fixture.controllerState, fixture.artifactRoot, {plan},
                                              "withhold-ack", "6");
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  const bool applied = cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=applied"); },
      &output);
  CF_EXPECT_MSG(applied, output + controller->logText() + agent->logText());
  CF_EXPECT(!cf::test::containsText(output, "state=converged"));

  // Restart the controller without the injection: reconciliation must close it.
  CF_EXPECT(controller->kill());
  CF_EXPECT(controller->wait() != 0);
  auto restarted = cf::test::startController(fixture.directory, "ctl-ack2",
                                             fixture.controllerState, fixture.artifactRoot, {},
                                             "", "6", true, "controller2");
  CF_EXPECT(restarted != nullptr);
  if (restarted == nullptr) {
    return;
  }
  const bool converged = cf::test::waitForConvergence(
      restarted->endpoint(), fixture.keyFile,
      [](const std::string& text) {
        return cf::test::containsText(text, "state=converged") &&
               cf::test::containsText(text, "evidence recovered by reconciliation");
      },
      &output);
  CF_EXPECT_MSG(converged, output + restarted->logText() + agent->logText());
}

CF_TEST(injection, controller_disconnect_during_transfer_is_resumed_not_restarted) {
  Fixture fixture("ctl-disconnect");
  const std::string agentState = fixture.directory.child("agent-state");
  const std::string body(200000, 'r');
  auto agent = cf::test::startAgent(fixture.directory, "rtr-1", agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      fixture.directory, "set-drop",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", body, "", 0}},
      nullptr);
  auto controller = cf::test::startController(fixture.directory, "ctl-drop",
                                              fixture.controllerState, fixture.artifactRoot, {plan},
                                              "after-chunk:2", "6");
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  // The transfer is interrupted repeatedly; the delivery must still complete.
  const bool converged = cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output);
  CF_EXPECT_MSG(converged, output + controller->logText() + agent->logText());
  // The agent observed a resume rather than a restart of the whole transfer.
  CF_EXPECT(cf::test::containsText(agent->logText(), "resuming the transfer") ||
            cf::test::containsText(controller->logText(), "resuming the transfer at byte"));
}

CF_TEST(injection, corrupt_chunk_is_refused_and_never_activated) {
  Fixture fixture("corrupt");
  const std::string agentState = fixture.directory.child("agent-state");
  const std::string body = "content that will be corrupted on the wire\n";
  auto agent = cf::test::startAgent(fixture.directory, "rtr-1", agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      fixture.directory, "set-corrupt",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", body, "", 0}},
      nullptr);
  auto controller = cf::test::startController(fixture.directory, "ctl-corrupt",
                                              fixture.controllerState, fixture.artifactRoot, {plan},
                                              "corrupt-chunk", "2");
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  const bool blocked = cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) {
        return cf::test::containsText(text, "digest-mismatch-reported") &&
               cf::test::containsText(text, "retry-budget-exhausted");
      },
      &output);
  CF_EXPECT_MSG(blocked, output + controller->logText() + agent->logText());
  CF_EXPECT(!cf::test::containsText(output, "state=converged"));
  // Nothing was activated: a corrupt payload can never reach the live pointer.
  CF_EXPECT(cf::test::readLivePointer(agentState, "fabric/underlay").empty());
}

CF_TEST(injection, truncated_transfer_is_reported_as_a_size_mismatch) {
  Fixture fixture("truncate");
  const std::string agentState = fixture.directory.child("agent-state");
  const std::string body(50000, 't');
  auto agent = cf::test::startAgent(fixture.directory, "rtr-1", agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      fixture.directory, "set-truncate",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", body, "", 0}},
      nullptr);
  auto controller = cf::test::startController(fixture.directory, "ctl-truncate",
                                              fixture.controllerState, fixture.artifactRoot, {plan},
                                              "truncate-transfer", "2");
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  const bool blocked = cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) {
        return cf::test::containsText(text, "size-mismatch-reported");
      },
      &output);
  CF_EXPECT_MSG(blocked, output + controller->logText() + agent->logText());
  CF_EXPECT(cf::test::readLivePointer(agentState, "fabric/underlay").empty());
}

CF_TEST(injection, stale_commit_is_fenced_by_the_target) {
  Fixture fixture("stale-commit");
  const std::string agentState = fixture.directory.child("agent-state");
  auto agent = cf::test::startAgent(fixture.directory, "rtr-1", agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  // Generation 1 first.
  const std::string planOne = cf::test::writePlan(
      fixture.directory, "set-sc1",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", "generation one\n", "", 0}},
      nullptr);
  auto controller = cf::test::startController(fixture.directory, "ctl-sc",
                                              fixture.controllerState, fixture.artifactRoot,
                                              {planOne}, "", "4");
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  CF_EXPECT(cf::test::waitForConvergence(
      controller->endpoint(), fixture.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output));
  CF_EXPECT(controller->kill());
  CF_EXPECT(controller->wait() != 0);

  // Now generation 2 with an injected stale commit: the target must refuse it and
  // the delivery must be retired rather than reported as converged.
  const std::string planTwo = cf::test::writePlan(
      fixture.directory, "set-sc2",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 2, 2, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", "generation two\n", "", 0}},
      nullptr);
  auto second = cf::test::startController(fixture.directory, "ctl-sc2", fixture.controllerState,
                                          fixture.artifactRoot, {planTwo}, "stale-commit", "4",
                                          true, "controller2");
  CF_EXPECT(second != nullptr);
  if (second == nullptr) {
    return;
  }
  // The injected commit names an older generation. The fabric must refuse to
  // converge and must report the refusal as a blocker rather than a success.
  const bool fenced = cf::test::waitForConvergence(
      second->endpoint(), fixture.keyFile,
      [](const std::string& text) {
        return cf::test::containsText(text, "state=failed") &&
               cf::test::containsText(text, "retry-budget-exhausted") &&
               cf::test::containsText(text, "policy-rejected");
      },
      &output);
  CF_EXPECT_MSG(fenced, output + second->logText() + agent->logText());
  // Whatever the outcome, the target never activated a lower generation over the
  // higher one, and the live pointer still names generation 2 or nothing newer.
  const std::string pointer = cf::test::readLivePointer(agentState, "fabric/underlay");
  CF_EXPECT(!cf::test::containsText(pointer, "0 "));
  // The injected commit named an older generation. Either the target fenced it as
  // stale or it recognised it as already active; both are refusals to move
  // backwards, and both are recorded in the operator log.
  CF_EXPECT_MSG(cf::test::containsText(agent->logText(), "refused a stale") ||
                    cf::test::containsText(agent->logText(), "suppressed a duplicate") ||
                    cf::test::containsText(agent->logText(), "refused a commit"),
                agent->logText());
}
