// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/plan.hpp"

#include <map>
#include <set>
#include <string>
#include <vector>

#include "cf/checked.hpp"
#include "cf/codec.hpp"
#include "cf/contract.hpp"
#include "cf/transport.hpp"

namespace cf {
namespace {

[[nodiscard]] std::string_view trim(std::string_view text) noexcept {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r')) {
    text.remove_prefix(1);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) {
    text.remove_suffix(1);
  }
  return text;
}

[[nodiscard]] Result<std::uint64_t> parseUnsigned(std::string_view text,
                                                  std::string_view what) {
  if (text.empty()) {
    return Result<std::uint64_t>::fail(ErrorCode::MissingField,
                                       std::string("missing value for ") + std::string(what));
  }
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return Result<std::uint64_t>::fail(ErrorCode::InvalidArgument,
                                         std::string("expected a decimal integer for ") +
                                             std::string(what),
                                         std::string(text));
    }
    const auto multiplied = checkedMul<std::uint64_t>(value, 10);
    if (!multiplied) {
      return Result<std::uint64_t>::fail(ErrorCode::ArithmeticOverflow,
                                         std::string("integer overflow in ") + std::string(what));
    }
    const auto added = checkedAdd<std::uint64_t>(*multiplied, static_cast<std::uint64_t>(c - '0'));
    if (!added) {
      return Result<std::uint64_t>::fail(ErrorCode::ArithmeticOverflow,
                                         std::string("integer overflow in ") + std::string(what));
    }
    value = *added;
  }
  return Result<std::uint64_t>::ok(value);
}

struct Line {
  std::size_t number{0};
  std::string_view text;
};

[[nodiscard]] Result<std::vector<Line>> splitLines(std::string_view text) {
  std::vector<Line> lines;
  std::size_t number = 0;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t end = text.find('\n', start);
    const std::string_view raw =
        (end == std::string_view::npos) ? text.substr(start) : text.substr(start, end - start);
    number += 1;
    if (raw.size() > kMaxPlanLineBytes) {
      return Result<std::vector<Line>>::fail(ErrorCode::LimitExceeded,
                                             "plan line exceeds the accepted length",
                                             std::to_string(number));
    }
    lines.push_back(Line{number, trim(raw)});
    if (lines.size() > kMaxPlanTargets * 16u + 64u) {
      return Result<std::vector<Line>>::fail(ErrorCode::LimitExceeded,
                                             "plan has more lines than the format permits");
    }
    if (end == std::string_view::npos) {
      break;
    }
    start = end + 1;
  }
  return Result<std::vector<Line>>::ok(std::move(lines));
}

[[nodiscard]] Status reject(std::size_t line, std::string_view message, std::string_view detail) {
  return Status::fail(ErrorCode::MalformedInput, std::string(message),
                      "line " + std::to_string(line) + ": " + std::string(detail));
}

}  // namespace

Result<DeploymentPlan> parseDeploymentPlan(std::string_view text, std::string_view sourceName) {
  if (text.size() > kMaxPlanBytes) {
    return Result<DeploymentPlan>::fail(ErrorCode::OversizePayload,
                                        "deployment plan exceeds the accepted size",
                                        std::string(sourceName));
  }
  CF_TRY_ASSIGN(const std::vector<Line> lines, splitLines(text));

  DeploymentPlan plan;
  bool haveHeader = false;
  bool haveSetId = false;
  bool inTarget = false;
  DeploymentInstruction current;
  std::set<std::string> seenFields;
  std::set<std::string> seenTargets;

  const auto finishTarget = [&](std::size_t line) -> Status {
    const std::array<std::pair<std::string_view, bool>, 12> mandatory = {{
        {"class", true},        {"guarantee", true}, {"config-key", true}, {"artifact", true},
        {"revision", true},     {"generation", true}, {"schema", true},     {"schema-version", true},
        {"digest", true},       {"size", true},       {"requires", true},   {"target", true},
    }};
    for (const auto& entry : mandatory) {
      if (seenFields.find(std::string(entry.first)) == seenFields.end()) {
        return reject(line, "target block is missing a mandatory field",
                      std::string("missing '") + std::string(entry.first) + "'");
      }
    }
    if (current.sizeBytes == 0) {
      return reject(line, "target block declares an empty artifact",
                    "size must be greater than zero");
    }
    if (!current.digest.isSet()) {
      return reject(line, "target block declares the all-zero digest",
                    "digest must be a real content digest");
    }
    if (current.generation.value() == 0) {
      return reject(line, "target block declares generation 0",
                    "generation 0 is reserved as the unset generation");
    }
    if (!seenTargets.insert(current.target.str()).second) {
      return reject(line, "duplicate target in deployment set", current.target.str());
    }
    plan.instructions.push_back(current);
    return Status::ok();
  };

  for (const Line& line : lines) {
    if (line.text.empty() || line.text.front() == '#') {
      continue;
    }
    const std::size_t space = line.text.find(' ');
    const std::string_view keyword =
        (space == std::string_view::npos) ? line.text : line.text.substr(0, space);
    const std::string_view value =
        (space == std::string_view::npos) ? std::string_view() : trim(line.text.substr(space + 1));

    if (!haveHeader) {
      if (keyword != "cf-plan") {
        return Result<DeploymentPlan>::fail(
            ErrorCode::MalformedInput, "deployment plan must start with a 'cf-plan <version>' line",
            "line " + std::to_string(line.number));
      }
      CF_TRY_ASSIGN(const std::uint64_t version, parseUnsigned(value, "plan format version"));
      if (version != kDeploymentPlanFormatVersion) {
        return Result<DeploymentPlan>::fail(ErrorCode::UnsupportedVersion,
                                            "deployment plan format version is not supported",
                                            std::to_string(version));
      }
      haveHeader = true;
      continue;
    }

    if (keyword == "set-id") {
      if (inTarget) {
        return Result<DeploymentPlan>::fail(ErrorCode::MalformedInput,
                                            "set-id must appear before the first target block",
                                            "line " + std::to_string(line.number));
      }
      CF_TRY_ASSIGN(plan.setId, parseDeploymentSetId(value));
      haveSetId = true;
      continue;
    }
    if (keyword == "rollout-set") {
      if (inTarget) {
        return Result<DeploymentPlan>::fail(ErrorCode::MalformedInput,
                                            "rollout-set must appear before the first target block",
                                            "line " + std::to_string(line.number));
      }
      CF_TRY_ASSIGN(plan.rolloutSet, parseRolloutSetId(value));
      continue;
    }
    if (keyword == "target") {
      if (inTarget) {
        CF_TRY(finishTarget(line.number));
      }
      if (!haveSetId) {
        return Result<DeploymentPlan>::fail(ErrorCode::MalformedInput,
                                            "deployment set id must be declared before targets",
                                            "line " + std::to_string(line.number));
      }
      if (plan.instructions.size() >= kMaxPlanTargets) {
        return Result<DeploymentPlan>::fail(ErrorCode::LimitExceeded,
                                            "deployment set exceeds the maximum target count",
                                            std::to_string(kMaxPlanTargets));
      }
      if (value.empty()) {
        return Result<DeploymentPlan>::fail(ErrorCode::MissingField,
                                            "target block is missing its target id",
                                            "line " + std::to_string(line.number));
      }
      current = DeploymentInstruction{};
      CF_TRY_ASSIGN(current.target, parseTargetId(value));
      seenFields.clear();
      seenFields.insert("target");
      inTarget = true;
      continue;
    }
    if (keyword == "end") {
      if (!inTarget) {
        return Result<DeploymentPlan>::fail(ErrorCode::MalformedInput,
                                            "'end' without a matching target block",
                                            "line " + std::to_string(line.number));
      }
      CF_TRY(finishTarget(line.number));
      inTarget = false;
      continue;
    }
    if (!inTarget) {
      return Result<DeploymentPlan>::fail(ErrorCode::MalformedInput, "unknown plan keyword",
                                          "line " + std::to_string(line.number) + ": " +
                                              std::string(keyword));
    }
    if (!seenFields.insert(std::string(keyword)).second) {
      return Result<DeploymentPlan>::fail(ErrorCode::AlreadyExists,
                                          "duplicate field in target block",
                                          "line " + std::to_string(line.number) + ": " +
                                              std::string(keyword));
    }
    if (keyword == "class") {
      if (!parseTargetClass(value, current.targetClass)) {
        return Result<DeploymentPlan>::fail(ErrorCode::InvalidArgument, "unknown target class",
                                            "line " + std::to_string(line.number) + ": " +
                                                std::string(value));
      }
    } else if (keyword == "guarantee") {
      if (!parseApplyGuarantee(value, current.declaredGuarantee)) {
        return Result<DeploymentPlan>::fail(ErrorCode::InvalidArgument, "unknown apply guarantee",
                                            "line " + std::to_string(line.number) + ": " +
                                                std::string(value));
      }
    } else if (keyword == "config-key") {
      CF_TRY_ASSIGN(current.configKey, parseConfigKey(value));
    } else if (keyword == "artifact") {
      CF_TRY_ASSIGN(current.artifact, parseArtifactId(value));
    } else if (keyword == "revision") {
      CF_TRY_ASSIGN(const std::uint64_t parsed, parseUnsigned(value, "revision"));
      current.revision = Revision::fromValue(parsed);
    } else if (keyword == "generation") {
      CF_TRY_ASSIGN(const std::uint64_t parsed, parseUnsigned(value, "generation"));
      current.generation = Generation::fromValue(parsed);
    } else if (keyword == "schema") {
      CF_TRY_ASSIGN(current.schema, parseSchemaId(value));
    } else if (keyword == "schema-version") {
      CF_TRY_ASSIGN(const std::uint64_t parsed, parseUnsigned(value, "schema-version"));
      const auto narrowed = checkedCast<std::uint32_t>(parsed);
      if (!narrowed) {
        return Result<DeploymentPlan>::fail(ErrorCode::OutOfRange,
                                            "schema-version is out of range",
                                            "line " + std::to_string(line.number));
      }
      current.schemaVersion = SchemaVersion::fromValue(*narrowed);
    } else if (keyword == "digest") {
      CF_TRY_ASSIGN(current.digest, Digest::parse(value));
    } else if (keyword == "size") {
      CF_TRY_ASSIGN(current.sizeBytes, parseUnsigned(value, "size"));
    } else if (keyword == "requires") {
      if (!parseGuaranteeRequirement(value, current.requirement)) {
        return Result<DeploymentPlan>::fail(ErrorCode::InvalidArgument,
                                            "unknown guarantee requirement",
                                            "line " + std::to_string(line.number) + ": " +
                                                std::string(value));
      }
    } else if (keyword == "media-type") {
      if (value.empty() || value.size() > kMaxMediaTypeBytes) {
        return Result<DeploymentPlan>::fail(ErrorCode::InvalidArgument,
                                            "media-type is empty or too long",
                                            "line " + std::to_string(line.number));
      }
      current.mediaType.assign(value);
    } else if (keyword == "producer") {
      if (value.size() > kMaxProducerBytes) {
        return Result<DeploymentPlan>::fail(ErrorCode::InvalidArgument, "producer is too long",
                                            "line " + std::to_string(line.number));
      }
      current.producer.assign(value);
    } else if (keyword == "source") {
      if (value.empty() || value.size() > kMaxPlanSourcePathBytes) {
        return Result<DeploymentPlan>::fail(ErrorCode::InvalidArgument,
                                            "source path is empty or too long",
                                            "line " + std::to_string(line.number));
      }
      current.sourcePath.assign(value);
    } else if (keyword == "endpoint") {
      auto endpoint = parseEndpoint(value);
      if (!endpoint || !endpoint.value().isSet()) {
        return Result<DeploymentPlan>::fail(
            endpoint ? ErrorCode::OutOfRange : endpoint.error().code(),
            "endpoint is not a dialable host:port pair",
            "line " + std::to_string(line.number));
      }
      current.endpoint.assign(value);
    } else {
      return Result<DeploymentPlan>::fail(ErrorCode::MalformedInput,
                                          "unknown keyword inside a target block",
                                          "line " + std::to_string(line.number) + ": " +
                                              std::string(keyword));
    }
  }

  if (!haveHeader) {
    return Result<DeploymentPlan>::fail(ErrorCode::MalformedInput,
                                        "deployment plan is empty or has no header");
  }
  if (inTarget) {
    return Result<DeploymentPlan>::fail(ErrorCode::TruncatedFrame,
                                        "deployment plan ends inside a target block",
                                        std::string(sourceName));
  }
  if (!haveSetId) {
    return Result<DeploymentPlan>::fail(ErrorCode::MissingField,
                                        "deployment plan does not declare a deployment set id");
  }
  if (plan.instructions.empty()) {
    return Result<DeploymentPlan>::fail(ErrorCode::MissingField,
                                        "deployment plan declares no targets");
  }
  return Result<DeploymentPlan>::ok(std::move(plan));
}

Result<DeploymentPlan> loadDeploymentPlanFile(const std::string& path) {
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> bytes, readFileBounded(path, kMaxPlanBytes));
  return parseDeploymentPlan(
      std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()), path);
}

std::string renderDeploymentPlan(const DeploymentPlan& plan) {
  std::string out;
  out.reserve(256 + (plan.instructions.size() * 256));
  out.append("cf-plan ");
  out.append(std::to_string(kDeploymentPlanFormatVersion));
  out.push_back('\n');
  out.append("set-id ");
  out.append(plan.setId.str());
  out.push_back('\n');
  if (plan.rolloutSet.isSet()) {
    out.append("rollout-set ");
    out.append(plan.rolloutSet.str());
    out.push_back('\n');
  }
  for (const DeploymentInstruction& instruction : plan.instructions) {
    out.append("target ");
    out.append(instruction.target.str());
    out.push_back('\n');
    out.append("  class ");
    out.append(targetClassName(instruction.targetClass));
    out.push_back('\n');
    out.append("  guarantee ");
    out.append(applyGuaranteeName(instruction.declaredGuarantee));
    out.push_back('\n');
    out.append("  config-key ");
    out.append(instruction.configKey.str());
    out.push_back('\n');
    out.append("  artifact ");
    out.append(instruction.artifact.str());
    out.push_back('\n');
    out.append("  revision ");
    out.append(std::to_string(instruction.revision.value()));
    out.push_back('\n');
    out.append("  generation ");
    out.append(std::to_string(instruction.generation.value()));
    out.push_back('\n');
    out.append("  schema ");
    out.append(instruction.schema.str());
    out.push_back('\n');
    out.append("  schema-version ");
    out.append(std::to_string(instruction.schemaVersion.value()));
    out.push_back('\n');
    out.append("  digest ");
    out.append(instruction.digest.hex());
    out.push_back('\n');
    out.append("  size ");
    out.append(std::to_string(instruction.sizeBytes));
    out.push_back('\n');
    out.append("  requires ");
    out.append(guaranteeRequirementName(instruction.requirement));
    out.push_back('\n');
    out.append("  media-type ");
    out.append(instruction.mediaType);
    out.push_back('\n');
    if (!instruction.producer.empty()) {
      out.append("  producer ");
      out.append(instruction.producer);
      out.push_back('\n');
    }
    if (!instruction.sourcePath.empty()) {
      out.append("  source ");
      out.append(instruction.sourcePath);
      out.push_back('\n');
    }
    if (!instruction.endpoint.empty()) {
      out.append("  endpoint ");
      out.append(instruction.endpoint);
      out.push_back('\n');
    }
    out.append("end\n");
  }
  return out;
}

}  // namespace cf
