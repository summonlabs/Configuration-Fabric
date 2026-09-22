// Independent downstream consumer of the installed Configuration Fabric package.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// This program links only against the installed artifact. It exercises the
// public surface a real integrator uses: parse a deployment instruction set,
// derive the delivery identity, check the plan against a policy, and print a
// deterministic summary. It returns a non-zero exit code if any of those steps
// disagrees with the documented behaviour.

#include <cstdio>
#include <string>

#include "cf/convergence.hpp"
#include "cf/ids.hpp"
#include "cf/lifecycle.hpp"
#include "cf/plan.hpp"
#include "cf/policy.hpp"
#include "cf/state.hpp"
#include "cf/version.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* what) {
  if (!condition) {
    std::fprintf(stderr, "downstream check failed: %s\n", what);
    g_failures += 1;
  }
}

}  // namespace

int main() {
  std::printf("%s (installed package %s)\n", std::string(cf::buildIdentification()).c_str(),
              std::string(cf::versionString()).c_str());

  const std::string body = "hostname rtr-1\ninterface eth0\n  mtu 9000\n";
  const cf::Digest digest = cf::Digest::ofText(body);

  std::string plan;
  plan.append("cf-plan 1\n");
  plan.append("set-id downstream-set\n");
  plan.append("target rtr-1\n");
  plan.append("  class network-device\n");
  plan.append("  guarantee atomic-activate\n");
  plan.append("  config-key fabric/underlay\n");
  plan.append("  artifact cfg/underlay\n");
  plan.append("  revision 7\n");
  plan.append("  generation 3\n");
  plan.append("  schema cf.underlay\n");
  plan.append("  schema-version 1\n");
  plan.append("  digest " + digest.hex() + "\n");
  plan.append("  size " + std::to_string(body.size()) + "\n");
  plan.append("  requires require-atomic\n");
  plan.append("  endpoint 127.0.0.1:9100\n");
  plan.append("end\n");

  auto parsed = cf::parseDeploymentPlan(plan, "downstream");
  check(parsed.hasValue(), "a well-formed plan parses");
  if (!parsed) {
    std::fprintf(stderr, "downstream: %s\n", parsed.error().str().c_str());
    return 1;
  }
  check(parsed.value().instructions.size() == 1, "the plan names one target");

  const cf::DeploymentInstruction& instruction = parsed.value().instructions[0];
  const cf::DeploymentId deployment = cf::deriveDeploymentId(
      instruction.target, instruction.configKey, instruction.generation, instruction.digest);
  check(cf::isValidIdentifier(deployment.str()), "the derived delivery identity is a valid id");
  check(cf::deriveDeploymentId(instruction.target, instruction.configKey, instruction.generation,
                               instruction.digest) == deployment,
        "the derived delivery identity is deterministic");

  // Render and re-parse: the plan format must round-trip.
  const std::string rendered = cf::renderDeploymentPlan(parsed.value());
  auto reparsed = cf::parseDeploymentPlan(rendered, "rendered");
  check(reparsed.hasValue(), "the rendered plan re-parses");
  if (reparsed) {
    check(reparsed.value() == parsed.value(), "the plan round-trips exactly");
  }

  // The lifecycle relation is part of the public contract.
  check(cf::isLegalTransition(cf::DeliveryState::Staged, cf::DeliveryState::Applied),
        "staged may become applied");
  check(!cf::isLegalTransition(cf::DeliveryState::Acknowledged, cf::DeliveryState::Prepared),
        "an acknowledged delivery cannot be reopened");

  // A policy decision is deterministic and explainable.
  const cf::DistributorPolicy policy;
  cf::DecisionInput input;
  input.state = cf::DeliveryState::Prepared;
  input.desiredGeneration = instruction.generation;
  input.requirement = instruction.requirement;
  input.artifactAvailable = true;
  const cf::Decision decision =
      cf::decide(policy, input, cf::Epoch::fromValue(1), instruction.generation);
  check(!decision.reason.empty(), "every decision carries a reason");
  check(decision.render(policy) == decision.render(policy), "decisions render deterministically");

  // Authoritative state can be built and summarised without a running daemon.
  cf::ControllerState state;
  state.nodeId = cf::parseNodeId("downstream").value();
  state.epoch = cf::Epoch::fromValue(1);
  const cf::ConvergenceReport report =
      cf::buildConvergenceReport(state, policy, cf::nowUnixMillis());
  check(report.lineageCount == 0, "an empty state reports no lineages");
  check(report.fingerprint() == report.fingerprint(), "the convergence fingerprint is stable");

  std::printf("plan-set: %s\n", parsed.value().setId.str().c_str());
  std::printf("deployment: %s\n", deployment.str().c_str());
  std::printf("decision: %s\n", std::string(cf::policyActionName(decision.action)).c_str());
  std::printf("convergence-fingerprint: %s\n", report.fingerprint().c_str());
  std::printf("downstream checks: %s\n", g_failures == 0 ? "ok" : "FAILED");
  return g_failures == 0 ? 0 : 1;
}
