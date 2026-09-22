// Unit and adversarial tests: deployment plan parsing and rendering.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <string>

#include "cf/plan.hpp"
#include "harness.hpp"
#include "testing.hpp"

namespace {

std::string planText(const std::string& target, std::uint64_t generation,
                     const std::string& digest, std::size_t size) {
  std::string text;
  text.append("cf-plan 1\n");
  text.append("set-id set-1\n");
  text.append("rollout-set rollout/edge\n");
  text.append("target " + target + "\n");
  text.append("  class network-device\n");
  text.append("  guarantee atomic-activate\n");
  text.append("  config-key fabric/underlay\n");
  text.append("  artifact cfg/underlay\n");
  text.append("  revision 1\n");
  text.append("  generation " + std::to_string(generation) + "\n");
  text.append("  schema cf.underlay\n");
  text.append("  schema-version 1\n");
  text.append("  digest " + digest + "\n");
  text.append("  size " + std::to_string(size) + "\n");
  text.append("  requires require-atomic\n");
  text.append("  endpoint 127.0.0.1:9001\n");
  text.append("end\n");
  return text;
}

}  // namespace

CF_TEST(unit, plan_parse_and_render_round_trip) {
  const std::string body = "hostname rtr-1\n";
  const std::string digest = cf::Digest::ofText(body).hex();
  auto plan = cf::parseDeploymentPlan(planText("rtr-1", 3, digest, body.size()), "test");
  CF_EXPECT_OK(plan);
  CF_EXPECT_EQ(plan.value().setId.str(), std::string("set-1"));
  CF_EXPECT_EQ(plan.value().instructions.size(), std::size_t{1});
  CF_EXPECT_EQ(plan.value().instructions[0].generation.value(), std::uint64_t{3});
  CF_EXPECT_EQ(plan.value().instructions[0].endpoint, std::string("127.0.0.1:9001"));

  const std::string rendered = cf::renderDeploymentPlan(plan.value());
  auto reparsed = cf::parseDeploymentPlan(rendered, "rendered");
  CF_EXPECT_OK(reparsed);
  CF_EXPECT(reparsed.value() == plan.value());
}

CF_TEST(unit, plan_requires_mandatory_fields) {
  const std::string digest = cf::Digest::ofText("x").hex();
  std::string text = planText("rtr-1", 1, digest, 100);
  const std::size_t position = text.find("  schema-version 1\n");
  text.erase(position, std::string("  schema-version 1\n").size());
  CF_EXPECT_CODE(cf::parseDeploymentPlan(text, "test"), cf::ErrorCode::MalformedInput);
}

CF_TEST(adversarial, plan_rejects_malformed_input) {
  const std::string digest = cf::Digest::ofText("x").hex();
  CF_EXPECT(!cf::parseDeploymentPlan("set-id x\n", "t").hasValue());

  std::string unknown = planText("rtr-1", 1, digest, 100);
  unknown.insert(unknown.find("end\n"), "  nonsense 1\n");
  CF_EXPECT(!cf::parseDeploymentPlan(unknown, "t").hasValue());

  std::string duplicate = planText("rtr-1", 1, digest, 100);
  duplicate.insert(duplicate.find("end\n"), "  revision 2\n");
  CF_EXPECT(!cf::parseDeploymentPlan(duplicate, "t").hasValue());

  std::string twoTargets = "cf-plan 1\nset-id set-1\n" + planText("rtr-1", 1, digest, 100) +
                           planText("rtr-1", 2, digest, 100);
  CF_EXPECT(!cf::parseDeploymentPlan(twoTargets, "t").hasValue());

  std::string truncated = planText("rtr-1", 1, digest, 100);
  truncated.erase(truncated.size() - 5);
  CF_EXPECT(!cf::parseDeploymentPlan(truncated, "t").hasValue());

  CF_EXPECT(!cf::parseDeploymentPlan(planText("rtr-1", 0, digest, 100), "t").hasValue());
  CF_EXPECT(!cf::parseDeploymentPlan(planText("rtr-1", 1, std::string(64, '0'), 100), "t")
                 .hasValue());
  CF_EXPECT(!cf::parseDeploymentPlan(planText("rtr-1", 1, digest, 0), "t").hasValue());

  std::string wrongVersion = planText("rtr-1", 1, digest, 100);
  wrongVersion.replace(8, 1, "9");
  CF_EXPECT_CODE(cf::parseDeploymentPlan(wrongVersion, "t"), cf::ErrorCode::UnsupportedVersion);

  // An endpoint that is not dialable is refused.
  std::string badEndpoint = planText("rtr-1", 1, digest, 100);
  const std::size_t endpointPosition = badEndpoint.find("127.0.0.1:9001");
  badEndpoint.replace(endpointPosition, std::string("127.0.0.1:9001").size(), "127.0.0.1:0");
  CF_EXPECT(!cf::parseDeploymentPlan(badEndpoint, "t").hasValue());
}

CF_TEST(adversarial, plan_rejects_oversize_input) {
  std::string huge = "cf-plan 1\nset-id s\n";
  huge.append(cf::kMaxPlanBytes + 10, '#');
  CF_EXPECT_CODE(cf::parseDeploymentPlan(huge, "t"), cf::ErrorCode::OversizePayload);

  std::string longLine = "cf-plan 1\nset-id s\n#";
  longLine.append(cf::kMaxPlanLineBytes + 10, 'x');
  CF_EXPECT_CODE(cf::parseDeploymentPlan(longLine, "t"), cf::ErrorCode::LimitExceeded);
}

CF_TEST(unit, plan_loads_from_a_file) {
  cf::test::TempDir directory("plan-file");
  const std::string digest = cf::Digest::ofText("x").hex();
  const std::string path = directory.child("plan.txt");
  cf::test::writeTextFile(path, planText("rtr-1", 2, digest, 42));
  auto plan = cf::loadDeploymentPlanFile(path);
  CF_EXPECT_OK(plan);
  CF_EXPECT_EQ(plan.value().instructions.size(), std::size_t{1});
  CF_EXPECT_CODE(cf::loadDeploymentPlanFile(directory.child("missing.plan")),
                 cf::ErrorCode::NotFound);
}
