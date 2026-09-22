// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deployment instructions from upstream systems.
//
// Configuration Fabric does not decide desired network intent, does not compute
// transition sequences and does not choose rollout cohorts. It consumes an
// explicit deployment set: a list of targets, each with an explicit
// configuration identity, generation, digest and activation requirement. This
// module parses, validates and renders that input.
//
// The plan format is a strict, line-oriented text format. It is deliberately
// boring: bounded lines, bounded blocks, case-sensitive keywords, no implicit
// defaults for mandatory fields, no unknown keys, and a line number in every
// error. It round-trips exactly, so a plan can be archived next to the delivery
// evidence it produced.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "cf/ids.hpp"
#include "cf/result.hpp"

namespace cf {

inline constexpr std::uint32_t kDeploymentPlanFormatVersion = 1;
inline constexpr std::size_t kMaxPlanBytes = 4u * 1024u * 1024u;
inline constexpr std::size_t kMaxPlanLineBytes = 4096;
inline constexpr std::size_t kMaxPlanTargets = 4096;
inline constexpr std::size_t kMaxPlanSourcePathBytes = 512;

/// One target's configuration assignment. Every field is supplied by upstream;
/// nothing here is inferred by this runtime.
struct DeploymentInstruction {
  TargetId target;
  TargetClass targetClass{TargetClass::Unspecified};
  ApplyGuarantee declaredGuarantee{ApplyGuarantee::AtomicActivate};
  ConfigKey configKey;
  ArtifactId artifact;
  Revision revision;
  Generation generation;
  SchemaId schema;
  SchemaVersion schemaVersion;
  Digest digest;
  std::uint64_t sizeBytes{0};
  GuaranteeRequirement requirement{GuaranteeRequirement::RequireAtomic};
  std::string mediaType{"application/octet-stream"};
  std::string producer;
  /// Optional local path the distributor may use to ingest the artifact when the
  /// store does not already hold it. Empty means "the store must already hold it".
  std::string sourcePath;
  /// Optional "host:port" the distributor dials to reach the target agent. Part
  /// of the upstream instruction, because Configuration Fabric does not discover
  /// targets.
  std::string endpoint;

  friend bool operator==(const DeploymentInstruction&, const DeploymentInstruction&) noexcept =
      default;
};

struct DeploymentPlan {
  DeploymentSetId setId;
  RolloutSetId rolloutSet;
  std::vector<DeploymentInstruction> instructions;

  friend bool operator==(const DeploymentPlan&, const DeploymentPlan&) noexcept = default;
};

/// Parses a plan. sourceName is used only to make error messages actionable.
[[nodiscard]] Result<DeploymentPlan> parseDeploymentPlan(std::string_view text,
                                                         std::string_view sourceName);
[[nodiscard]] Result<DeploymentPlan> loadDeploymentPlanFile(const std::string& path);
/// Deterministic rendering. parseDeploymentPlan(render(plan)) == plan.
[[nodiscard]] std::string renderDeploymentPlan(const DeploymentPlan& plan);

}  // namespace cf
