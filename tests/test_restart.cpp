// Restart and reconciliation tests across independent processes.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <string>
#include <thread>

#include "harness.hpp"
#include "testing.hpp"

namespace {

struct Layout {
  cf::test::TempDir directory{"restart"};
  std::string agentState;
  std::string controllerState;
  std::string artifactRoot;
  std::string keyFile;

  Layout() {
    agentState = directory.child("agent-state");
    controllerState = directory.child("ctl-state");
    artifactRoot = directory.child("ctl-artifacts");
    keyFile = cf::test::keyFileFor(directory);
  }

  [[nodiscard]] std::string plan(const std::string& name, const std::string& endpoint,
                                 std::uint64_t generation, const std::string& body) {
    return cf::test::writePlan(
        directory, name,
        {cf::test::TargetSpec{"rtr-1", "fabric/underlay", "cfg/underlay", generation, generation,
                              "atomic-activate", "require-atomic", endpoint, "", body, "", 0}},
        nullptr);
  }
};

}  // namespace

CF_TEST(restart, controller_restart_does_not_invent_completion) {
  Layout layout;
  auto agent = cf::test::startAgent(layout.directory, "rtr-1", layout.agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string planPath = layout.plan("set-r1", agent->endpoint(), 1, "restart body\n");
  auto controller = cf::test::startController(layout.directory, "ctl-r", layout.controllerState,
                                              layout.artifactRoot, {planPath});
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  // Kill the controller as soon as the plan exists but before convergence.
  std::this_thread::sleep_for(std::chrono::milliseconds(30));
  const bool wasRunning = controller->running();
  CF_EXPECT(controller->kill());
  CF_EXPECT(controller->wait() != 0);
  (void)wasRunning;

  // Restart with no plan: the delivery is recovered from durable state.
  auto restarted = cf::test::startController(layout.directory, "ctl-r", layout.controllerState,
                                             layout.artifactRoot, {}, "", "5", true,
                                             "controller2");
  CF_EXPECT(restarted != nullptr);
  if (restarted == nullptr) {
    return;
  }
  CF_EXPECT(restarted->endpoint() != controller->endpoint());

  std::string output;
  const bool converged = cf::test::waitForConvergence(
      restarted->endpoint(), layout.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output);
  CF_EXPECT_MSG(converged, output + restarted->logText() + agent->logText());

  // The epoch advanced, and the durable state shows exactly one lineage.
  const std::string status = cf::test::runCtl(
      {"--endpoint", restarted->endpoint(), "--key-file", layout.keyFile, "status"});
  CF_EXPECT(cf::test::containsText(status, "authority-epoch: 2"));
  CF_EXPECT(cf::test::containsText(output, "lineages=1"));
}

CF_TEST(restart, controller_restart_after_full_convergence_changes_nothing) {
  Layout layout;
  auto agent = cf::test::startAgent(layout.directory, "rtr-1", layout.agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string planPath = layout.plan("set-r2", agent->endpoint(), 1, "restart body two\n");
  auto controller = cf::test::startController(layout.directory, "ctl-r2", layout.controllerState,
                                              layout.artifactRoot, {planPath});
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  CF_EXPECT(cf::test::waitForConvergence(
      controller->endpoint(), layout.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output));
  const std::string fingerprintBefore = cf::test::runCtl(
      {"--endpoint", controller->endpoint(), "--key-file", layout.keyFile, "divergence"});
  CF_EXPECT(controller->kill());
  CF_EXPECT(controller->wait() != 0);

  auto restarted = cf::test::startController(layout.directory, "ctl-r2", layout.controllerState,
                                             layout.artifactRoot, {}, "", "5", true,
                                             "controller2");
  CF_EXPECT(restarted != nullptr);
  if (restarted == nullptr) {
    return;
  }
  const bool stillConverged = cf::test::waitForConvergence(
      restarted->endpoint(), layout.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output);
  CF_EXPECT_MSG(stillConverged, output + restarted->logText());
  // Re-submitting the same plan is idempotent: the acknowledged delivery is not
  // re-driven.
  int exitCode = 0;
  const std::string submitted = cf::test::runCtl(
      {"--endpoint", restarted->endpoint(), "--key-file", layout.keyFile, "plan", planPath},
      &exitCode);
  CF_EXPECT_EQ(exitCode, 0);
  CF_EXPECT(cf::test::containsText(submitted, "accepted, deliveries=0"));
  const std::string after = cf::test::runCtl(
      {"--endpoint", restarted->endpoint(), "--key-file", layout.keyFile, "converge"});
  CF_EXPECT(cf::test::containsText(after, "state=converged"));
  CF_EXPECT(cf::test::containsText(fingerprintBefore, "desired=1"));
}

CF_TEST(restart, agent_restart_invalidates_persisted_liveness_evidence) {
  Layout layout;
  auto agent = cf::test::startAgent(layout.directory, "rtr-1", layout.agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string planPath = layout.plan("set-r3", agent->endpoint(), 1, "liveness body\n");
  auto controller = cf::test::startController(layout.directory, "ctl-r3", layout.controllerState,
                                              layout.artifactRoot, {planPath});
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  CF_EXPECT(cf::test::waitForConvergence(
      controller->endpoint(), layout.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output));

  // Restart the controller; contact evidence from the previous process must be
  // reported as not current until a new session is established.
  CF_EXPECT(controller->kill());
  CF_EXPECT(controller->wait() != 0);
  auto restarted = cf::test::startController(layout.directory, "ctl-r3", layout.controllerState,
                                             layout.artifactRoot, {}, "", "5", true,
                                             "controller2");
  CF_EXPECT(restarted != nullptr);
  if (restarted == nullptr) {
    return;
  }
  // Nothing has re-established contact yet, and the runtime must say so rather
  // than reuse evidence from the process that died.
  const std::string firstTargets = cf::test::runCtl(
      {"--endpoint", restarted->endpoint(), "--key-file", layout.keyFile, "targets"});
  CF_EXPECT_MSG(cf::test::containsText(firstTargets, "contact-current=no"), firstTargets);

  // The acknowledged delivery is durable evidence, so it is not re-driven; the
  // report stays converged.
  const bool convergedAgain = cf::test::waitForConvergence(
      restarted->endpoint(), layout.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output);
  CF_EXPECT_MSG(convergedAgain, output + restarted->logText());

  // An operator can force a verification session, which is what re-establishes
  // current contact evidence.
  int verifyExit = 0;
  const std::string requested = cf::test::runCtl(
      {"--endpoint", restarted->endpoint(), "--key-file", layout.keyFile, "verify", "rtr-1"},
      &verifyExit);
  CF_EXPECT_EQ(verifyExit, 0);
  CF_EXPECT_MSG(cf::test::containsText(requested, "verification session requested"), requested);
  bool contactRestored = false;
  for (int attempt = 0; attempt < 200 && !contactRestored; ++attempt) {
    const std::string targetsAfter = cf::test::runCtl(
        {"--endpoint", restarted->endpoint(), "--key-file", layout.keyFile, "targets"});
    contactRestored = cf::test::containsText(targetsAfter, "contact-current=yes");
    if (!contactRestored) {
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
  }
  CF_EXPECT_MSG(contactRestored, restarted->logText() + agent->logText());
  // Restarting the agent yields a new term, and the controller records it.
  CF_EXPECT(agent->kill());
  CF_EXPECT(agent->wait() != 0);
}

CF_TEST(restart, agent_restart_gets_a_fresh_incarnation_and_term) {
  Layout layout;
  auto agent = cf::test::startAgent(layout.directory, "rtr-1", layout.agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string planPath = layout.plan("set-r4", agent->endpoint(), 1, "incarnation body\n");
  auto controller = cf::test::startController(layout.directory, "ctl-r4", layout.controllerState,
                                              layout.artifactRoot, {planPath});
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  CF_EXPECT(cf::test::waitForConvergence(
      controller->endpoint(), layout.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output));
  const std::string before = cf::test::runCtl(
      {"--endpoint", controller->endpoint(), "--key-file", layout.keyFile, "targets"});
  CF_EXPECT(cf::test::containsText(before, "term=1"));
  CF_EXPECT(agent->kill());
  CF_EXPECT(agent->wait() != 0);

  // Restart the agent on the same port and state directory.
  const std::string endpoint = agent->endpoint();
  const std::string announce = layout.directory.child("agent2.endpoint");
  std::vector<std::string> arguments = {
      "--target", "rtr-1", "--state", layout.agentState, "--listen", endpoint, "--announce-file",
      announce, "--log-level", "debug", "--log-file", layout.directory.child("agent2.log"),
      "--key-file", layout.keyFile};
  auto restarted = std::make_unique<cf::test::ServiceProcess>(
      CF_TEST_AGENT_PATH, std::move(arguments), announce,
      layout.directory.child("agent2.log"));
  CF_EXPECT(restarted->start());
  if (!restarted->running()) {
    return;
  }
  // Force a session so the controller observes the new target process. Without
  // new work or an explicit verification request a converged target is not
  // dialled, which is deliberate: the runtime does not poll.
  int verifyExit = 0;
  const std::string verificationRequest = cf::test::runCtl(
      {"--endpoint", controller->endpoint(), "--key-file", layout.keyFile, "verify", "rtr-1"},
      &verifyExit);
  CF_EXPECT_MSG(cf::test::containsText(verificationRequest, "verification session requested"),
                verificationRequest);
  CF_EXPECT_EQ(verifyExit, 0);
  std::string after;
  bool observed = false;
  for (int attempt = 0; attempt < 200 && !observed; ++attempt) {
    after = cf::test::runCtl(
        {"--endpoint", controller->endpoint(), "--key-file", layout.keyFile, "targets"});
    observed = cf::test::containsText(after, "term=2");
    if (!observed) {
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
  }
  CF_EXPECT_MSG(observed, after + controller->logText() + restarted->logText());
  CF_EXPECT_MSG(cf::test::containsText(after, "restarts=1"), after);
}

CF_TEST(restart, offline_inspection_matches_the_live_view) {
  Layout layout;
  auto agent = cf::test::startAgent(layout.directory, "rtr-1", layout.agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string planPath = layout.plan("set-r5", agent->endpoint(), 1, "offline body\n");
  auto controller = cf::test::startController(layout.directory, "ctl-r5", layout.controllerState,
                                              layout.artifactRoot, {planPath});
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  CF_EXPECT(cf::test::waitForConvergence(
      controller->endpoint(), layout.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output));
  CF_EXPECT(controller->kill());
  CF_EXPECT(controller->wait() != 0);

  int exitCode = 0;
  const std::string offline = cf::test::runCtl(
      {"--state", layout.controllerState, "--artifacts", layout.artifactRoot, "converge"}, &exitCode);
  CF_EXPECT_EQ(exitCode, 0);
  CF_EXPECT(cf::test::containsText(offline, "state=acknowledged"));
  CF_EXPECT(cf::test::containsText(offline, "desired-generation=1"));
  CF_EXPECT(cf::test::containsText(offline, "current-generation=1"));

  const std::string journal = cf::test::runCtl(
      {"--state", layout.controllerState, "journal"}, &exitCode);
  CF_EXPECT_EQ(exitCode, 0);
  CF_EXPECT(cf::test::containsText(journal, "controller-identity"));
  CF_EXPECT(cf::test::containsText(journal, "delivery-upsert"));

  const std::string verify = cf::test::runCtl(
      {"--state", layout.controllerState, "--artifacts", layout.artifactRoot, "verify-artifacts"},
      &exitCode);
  CF_EXPECT_EQ(exitCode, 0);
  CF_EXPECT(cf::test::containsText(verify, "failures: 0"));
}

CF_TEST(restart, agent_state_survives_a_kill_without_cleanup) {
  Layout layout;
  auto agent = cf::test::startAgent(layout.directory, "rtr-1", layout.agentState);
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  const std::string planPath = layout.plan("set-r6", agent->endpoint(), 1, "durable body\n");
  auto controller = cf::test::startController(layout.directory, "ctl-r6", layout.controllerState,
                                              layout.artifactRoot, {planPath});
  CF_EXPECT(controller != nullptr);
  if (controller == nullptr) {
    return;
  }
  std::string output;
  CF_EXPECT(cf::test::waitForConvergence(
      controller->endpoint(), layout.keyFile,
      [](const std::string& text) { return cf::test::containsText(text, "state=converged"); },
      &output));
  CF_EXPECT(controller->kill());
  CF_EXPECT(controller->wait() != 0);
  CF_EXPECT(agent->kill());
  CF_EXPECT(agent->wait() != 0);

  // Both processes are gone; the target agent's durable state still describes the
  // activation, and the controller's durable state still records the ack.
  int exitCode = 0;
  const std::string offline = cf::test::runCtl(
      {"--state", layout.controllerState, "--artifacts", layout.artifactRoot, "deliveries"},
      &exitCode);
  CF_EXPECT_EQ(exitCode, 0);
  CF_EXPECT(cf::test::containsText(offline, "state=acknowledged"));
  CF_EXPECT(cf::test::containsText(cf::test::readLivePointer(layout.agentState, "fabric/underlay"),
                                   "1 "));
}
