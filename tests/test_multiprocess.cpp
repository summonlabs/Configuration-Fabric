// End-to-end tests across independent OS processes over real loopback sockets.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Nothing here is mocked. A controller process dials an agent process, streams a
// real artifact over a real socket, and the inspection CLI reads the result over
// the real control channel.

#include <string>
#include <vector>

#include "cf/plan.hpp"
#include "harness.hpp"
#include "testing.hpp"

namespace {

struct Deployment {
  cf::test::TempDir directory{"e2e"};
  std::string agentState;
  std::string controllerState;
  std::string artifactRoot;
  std::unique_ptr<cf::test::ServiceProcess> agent;
  std::unique_ptr<cf::test::ServiceProcess> controller;
  std::string keyFile;

  Deployment() {
    agentState = directory.child("agent-state");
    controllerState = directory.child("ctl-state");
    artifactRoot = directory.child("ctl-artifacts");
    keyFile = cf::test::keyFileFor(directory);
  }
};

}  // namespace

CF_TEST(multiprocess, single_target_delivery_converges) {
  Deployment deployment;
  auto agent = cf::test::startAgent(deployment.directory, "rtr-1", deployment.agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      deployment.directory, "set-a",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", "hostname rtr-1\n", "", 0}},
      nullptr);
  auto controller = cf::test::startController(deployment.directory, "ctl-a",
                                              deployment.controllerState, deployment.artifactRoot,
                                              {plan});
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }

  std::string output;
  const bool converged = cf::test::waitForConvergence(
      controller->endpoint(), deployment.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output);
  CF_EXPECT_MSG(converged, output + controller->logText() + agent->logText());
  CF_EXPECT(cf::test::containsText(output, "state=acknowledged"));

  int exitCode = 0;
  const std::string deliveries = cf::test::runCtl(
      {"--endpoint", controller->endpoint(), "--key-file", deployment.keyFile, "deliveries"},
      &exitCode);
  CF_EXPECT_EQ(exitCode, 0);
  CF_EXPECT(cf::test::containsText(deliveries, "failures=0"));

  // The live configuration area really holds generation 1.
  const std::string pointer = cf::test::readLivePointer(deployment.agentState, "fabric/underlay");
  CF_EXPECT(cf::test::containsText(pointer, "1 "));

  // Offline inspection of the controller state directory agrees with the live
  // report, without opening or mutating the store.
  const std::string offline = cf::test::runCtl(
      {"--state", deployment.controllerState, "--artifacts", deployment.artifactRoot, "converge"},
      &exitCode);
  CF_EXPECT_EQ(exitCode, 0);
  CF_EXPECT(cf::test::containsText(offline, "current-generation=1"));
}

CF_TEST(multiprocess, one_controller_serves_several_targets_with_partial_failure) {
  Deployment deployment;
  auto agentA = cf::test::startAgent(deployment.directory, "rtr-a", deployment.directory.child("state-a"),
                                     "atomic-activate", "", true, "agent-a");
  auto agentB = cf::test::startAgent(deployment.directory, "rtr-b", deployment.directory.child("state-b"),
                                     "atomic-activate", "", true, "agent-b");
  CF_EXPECT(agentA != nullptr && agentB != nullptr);
  if (agentA == nullptr || agentB == nullptr) {
    return;
  }
  // rtr-c is named by the plan but has no agent: it must fail on its own without
  // affecting the other two.
  const std::string plan = cf::test::writePlan(
      deployment.directory, "set-multi",
      {cf::test::TargetSpec{"rtr-a", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agentA->endpoint(), "", "hostname rtr-a\n", "", 0},
       cf::test::TargetSpec{"rtr-b", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agentB->endpoint(), "", "hostname rtr-b\n", "", 0},
       cf::test::TargetSpec{"rtr-c", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", "127.0.0.1:1", "", "hostname rtr-c\n", "", 0}},
      nullptr);
  auto controller = cf::test::startController(deployment.directory, "ctl-multi",
                                              deployment.controllerState, deployment.artifactRoot,
                                              {plan}, "", "2");
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }

  std::string output;
  const bool partial = cf::test::waitForConvergence(
      controller->endpoint(), deployment.keyFile,
      [](const std::string& text) {
        return cf::test::containsText(text, "target=rtr-a") &&
               cf::test::containsText(text, "target=rtr-b") &&
               cf::test::containsText(text, "state=acknowledged") &&
               cf::test::containsText(text, "target=rtr-c") &&
               cf::test::containsText(text, "state=failed") &&
               cf::test::containsText(text, "blockers: retry-budget-exhausted");
      },
      &output);
  CF_EXPECT_MSG(partial, output + controller->logText());
  // Two of three lineages are on the desired generation; the report says so
  // per target rather than as one global bit.
  CF_EXPECT(cf::test::containsText(output, "lineages=3"));
  CF_EXPECT(cf::test::containsText(output, "converged=2"));

  int exitCode = 0;
  const std::string explanation = cf::test::runCtl(
      {"--endpoint", controller->endpoint(), "--key-file", deployment.keyFile, "explain", "rtr-c"},
      &exitCode);
  CF_EXPECT_EQ(exitCode, 0);
  CF_EXPECT_MSG(cf::test::containsText(explanation, "state = failed"), explanation);
  CF_EXPECT_MSG(cf::test::containsText(explanation, "ConnectionRefused"), explanation);
}

CF_TEST(multiprocess, second_generation_supersedes_the_first) {
  Deployment deployment;
  auto agent = cf::test::startAgent(deployment.directory, "rtr-1", deployment.agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string planOne = cf::test::writePlan(
      deployment.directory, "set-gen1",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", "hostname rtr-1 gen1\n", "", 0}},
      nullptr);
  auto controller = cf::test::startController(deployment.directory, "ctl-gen",
                                              deployment.controllerState, deployment.artifactRoot,
                                              {planOne});
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  CF_EXPECT(cf::test::waitForConvergence(
      controller->endpoint(), deployment.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output));

  const std::string planTwo = cf::test::writePlan(
      deployment.directory, "set-gen2",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 2, 2, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", "hostname rtr-1 gen2\n", "", 0}},
      nullptr);
  int exitCode = 0;
  const std::string submitted = cf::test::runCtl(
      {"--endpoint", controller->endpoint(), "--key-file", deployment.keyFile, "plan", planTwo},
      &exitCode);
  CF_EXPECT_EQ(exitCode, 0);
  CF_EXPECT(cf::test::containsText(submitted, "accepted"));

  const bool advanced = cf::test::waitForConvergence(
      controller->endpoint(), deployment.keyFile,
      [](const std::string& text) {
        return cf::test::containsText(text, "state=converged") &&
               cf::test::containsText(text, "desired-generation=2") &&
               cf::test::containsText(text, "current-generation=2");
      },
      &output);
  CF_EXPECT_MSG(advanced, output + controller->logText() + agent->logText());

  const std::string pointer = cf::test::readLivePointer(deployment.agentState, "fabric/underlay");
  CF_EXPECT(cf::test::containsText(pointer, "2 "));
}

CF_TEST(multiprocess, plan_targeting_an_unsupported_guarantee_is_rejected_per_target) {
  Deployment deployment;
  // The agent can only offer prepare/commit/abort.
  auto agent = cf::test::startAgent(deployment.directory, "rtr-weak", deployment.agentState,
                                    "prepare-commit-abort");
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  // The instruction demands atomic activation.
  const std::string plan = cf::test::writePlan(
      deployment.directory, "set-weak",
      {cf::test::TargetSpec{"rtr-weak", "fabric/underlay", "cfg/underlay", 1, 1,
                            "prepare-commit-abort", "require-atomic", agent->endpoint(), "",
                            "hostname weak\n", "", 0}},
      nullptr);
  auto controller = cf::test::startController(deployment.directory, "ctl-weak",
                                              deployment.controllerState, deployment.artifactRoot,
                                              {plan});
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  const bool rejected = cf::test::waitForConvergence(
      controller->endpoint(), deployment.keyFile,
      [](const std::string& text) {
        return cf::test::containsText(text, "state=rejected") &&
               cf::test::containsText(text, "guarantee-unsupported");
      },
      &output);
  CF_EXPECT_MSG(rejected, output + controller->logText() + agent->logText());
  // Nothing was activated on the target.
  const std::string pointer = cf::test::readLivePointer(deployment.agentState, "fabric/underlay");
  CF_EXPECT(pointer.empty());
}

CF_TEST(multiprocess, weaker_guarantee_is_carried_and_activation_still_converges) {
  Deployment deployment;
  auto agent = cf::test::startAgent(deployment.directory, "rtr-weak", deployment.agentState,
                                    "prepare-commit-abort");
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      deployment.directory, "set-weak-ok",
      {cf::test::TargetSpec{"rtr-weak", "fabric/underlay", "cfg/underlay", 1, 1,
                            "prepare-commit-abort", "allow-prepare-commit", agent->endpoint(), "",
                            "hostname weak\n", "", 0}},
      nullptr);
  auto controller = cf::test::startController(deployment.directory, "ctl-weak-ok",
                                              deployment.controllerState, deployment.artifactRoot,
                                              {plan});
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  const bool converged = cf::test::waitForConvergence(
      controller->endpoint(), deployment.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output);
  CF_EXPECT_MSG(converged, output + controller->logText() + agent->logText());
  // The weaker guarantee is visible in the report, not hidden.
  CF_EXPECT(cf::test::containsText(output, "guarantee=prepare-commit-abort"));
  CF_EXPECT(cf::test::containsText(output, "required=allow-prepare-commit"));
}

CF_TEST(multiprocess, authenticated_channel_rejects_a_wrong_secret) {
  Deployment deployment;
  auto agent = cf::test::startAgent(deployment.directory, "rtr-1", deployment.agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string plan = cf::test::writePlan(
      deployment.directory, "set-auth",
      {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", 1, 1, "atomic-activate",
                            "require-atomic", agent->endpoint(), "", "hostname rtr-1\n", "", 0}},
      nullptr);
  // A controller with a different secret must never converge.
  const std::string wrongKeyFile = deployment.directory.child("wrong.key");
  cf::test::writeTextFile(wrongKeyFile,
                          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
  // The controller is given a different secret than the agent holds.
  auto controller = cf::test::startController(deployment.directory, "ctl-wrong",
                                              deployment.controllerState, deployment.artifactRoot,
                                              {plan}, "", "2", true, "wrongctl", 0, wrongKeyFile);
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  (void)cf::test::waitForConvergence(
      controller->endpoint(), wrongKeyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output, 60);
  CF_EXPECT(!cf::test::containsText(output, "state=converged"));
  CF_EXPECT(cf::test::containsText(agent->logText(), "authentication tag did not verify") ||
            cf::test::containsText(agent->logText(), "Unauthenticated"));
}
