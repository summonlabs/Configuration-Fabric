// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/ids.hpp"

#include <array>
#include <cstdio>

namespace cf {
bool isValidIdentifier(std::string_view text) noexcept {
  if (text.empty() || text.size() > kMaxIdentifierLength) {
    return false;
  }
  if (text.front() == '-') {
    return false;
  }
  for (const char raw : text) {
    const unsigned char c = static_cast<unsigned char>(raw);
    const bool digit = c >= '0' && c <= '9';
    const bool upper = c >= 'A' && c <= 'Z';
    const bool lower = c >= 'a' && c <= 'z';
    const bool punctuation = c == '.' || c == '_' || c == '-' || c == ':' || c == '/';
    if (!digit && !upper && !lower && !punctuation) {
      return false;
    }
  }
  return true;
}

namespace {

template <class Id>
[[nodiscard]] Result<Id> parseId(std::string_view text, std::string_view what) {
  if (text.empty()) {
    return Result<Id>::fail(ErrorCode::MissingField, std::string(what) + " must not be empty");
  }
  if (!isValidIdentifier(text)) {
    return Result<Id>::fail(ErrorCode::InvalidArgument,
                            std::string(what) + " is not a valid identifier",
                            std::string(text));
  }
  return Result<Id>::ok(Id(std::string(text)));
}

}  // namespace

Result<TargetId> parseTargetId(std::string_view text) { return parseId<TargetId>(text, "target id"); }
Result<ConfigKey> parseConfigKey(std::string_view text) {
  return parseId<ConfigKey>(text, "config key");
}
Result<ArtifactId> parseArtifactId(std::string_view text) {
  return parseId<ArtifactId>(text, "artifact id");
}
Result<DeploymentSetId> parseDeploymentSetId(std::string_view text) {
  return parseId<DeploymentSetId>(text, "deployment set id");
}
Result<DeploymentId> parseDeploymentId(std::string_view text) {
  return parseId<DeploymentId>(text, "deployment id");
}
Result<NodeId> parseNodeId(std::string_view text) { return parseId<NodeId>(text, "node id"); }
Result<SchemaId> parseSchemaId(std::string_view text) { return parseId<SchemaId>(text, "schema id"); }
Result<RolloutSetId> parseRolloutSetId(std::string_view text) {
  return parseId<RolloutSetId>(text, "rollout set id");
}

template <class Tag>
bool OpaqueIdentity<Tag>::isSet() const noexcept {
  for (const std::uint8_t byte : bytes_) {
    if (byte != 0) {
      return true;
    }
  }
  return false;
}

template class OpaqueIdentity<IncarnationTag>;
template class OpaqueIdentity<SessionNonceTag>;

std::string_view targetClassName(TargetClass value) noexcept {
  switch (value) {
    case TargetClass::Unspecified:
      return "unspecified";
    case TargetClass::NetworkDevice:
      return "network-device";
    case TargetClass::ControlPlaneParticipant:
      return "control-plane-participant";
  }
  return "unknown";
}

bool parseTargetClass(std::string_view text, TargetClass& out) noexcept {
  if (text == "network-device") {
    out = TargetClass::NetworkDevice;
  } else if (text == "control-plane-participant") {
    out = TargetClass::ControlPlaneParticipant;
  } else if (text == "unspecified") {
    out = TargetClass::Unspecified;
  } else {
    return false;
  }
  return true;
}

std::string_view applyGuaranteeName(ApplyGuarantee value) noexcept {
  switch (value) {
    case ApplyGuarantee::AtomicActivate:
      return "atomic-activate";
    case ApplyGuarantee::PrepareCommitAbort:
      return "prepare-commit-abort";
  }
  return "unknown";
}

bool parseApplyGuarantee(std::string_view text, ApplyGuarantee& out) noexcept {
  if (text == "atomic-activate") {
    out = ApplyGuarantee::AtomicActivate;
  } else if (text == "prepare-commit-abort") {
    out = ApplyGuarantee::PrepareCommitAbort;
  } else {
    return false;
  }
  return true;
}

std::string_view guaranteeRequirementName(GuaranteeRequirement value) noexcept {
  switch (value) {
    case GuaranteeRequirement::RequireAtomic:
      return "require-atomic";
    case GuaranteeRequirement::AllowPrepareCommit:
      return "allow-prepare-commit";
  }
  return "unknown";
}

bool parseGuaranteeRequirement(std::string_view text, GuaranteeRequirement& out) noexcept {
  if (text == "require-atomic") {
    out = GuaranteeRequirement::RequireAtomic;
  } else if (text == "allow-prepare-commit") {
    out = GuaranteeRequirement::AllowPrepareCommit;
  } else {
    return false;
  }
  return true;
}

bool guaranteeSatisfies(ApplyGuarantee offered, GuaranteeRequirement required) noexcept {
  switch (required) {
    case GuaranteeRequirement::RequireAtomic:
      return offered == ApplyGuarantee::AtomicActivate;
    case GuaranteeRequirement::AllowPrepareCommit:
      // Both guarantees satisfy a permissive requirement; the weaker one is
      // always reported explicitly in the deployment record.
      return offered == ApplyGuarantee::AtomicActivate ||
             offered == ApplyGuarantee::PrepareCommitAbort;
  }
  return false;
}

DeploymentId deriveDeploymentId(const TargetId& target, const ConfigKey& key, Generation generation,
                                const Digest& digest) {
  std::string transcript;
  transcript.reserve(160);
  transcript.append("CF-DEPLOY-V1|");
  transcript.append(target.str());
  transcript.push_back('|');
  transcript.append(key.str());
  transcript.push_back('|');
  transcript.append(std::to_string(generation.value()));
  transcript.push_back('|');
  transcript.append(digest.hex());
  const Sha256Digest hash = sha256(transcript);
  const std::array<std::uint8_t, 16> truncated = [&hash] {
    std::array<std::uint8_t, 16> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
      out[i] = hash[i];
    }
    return out;
  }();
  DeploymentId id(toHex(std::span<const std::uint8_t>(truncated.data(), truncated.size())));
  return id;
}

StreamId deriveStreamId(const DeploymentId& deployment, AttemptId attempt) noexcept {
  std::string transcript;
  transcript.reserve(64);
  transcript.append("CF-STREAM-V1|");
  transcript.append(deployment.str());
  transcript.push_back('|');
  transcript.append(std::to_string(attempt.value()));
  const Sha256Digest hash = sha256(transcript);
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(hash[i]) << (i * 8);
  }
  // A zero stream id is the "unset" sentinel and must never be produced.
  return StreamId::fromValue(value | 1ULL);
}

// --- Digest ----------------------------------------------------------------

Result<Digest> Digest::parse(std::string_view hex) {
  if (hex.size() != kSha256HexChars) {
    return Result<Digest>::fail(ErrorCode::MalformedInput,
                                "digest must be exactly 64 hexadecimal characters");
  }
  Sha256Digest bytes{};
  if (!fromHex(hex, std::span<std::uint8_t>(bytes.data(), bytes.size()))) {
    return Result<Digest>::fail(ErrorCode::MalformedInput,
                                "digest contains non-hexadecimal characters", std::string(hex));
  }
  return Result<Digest>::ok(Digest::fromBytes(bytes));
}

Digest Digest::ofContent(std::span<const std::uint8_t> content) noexcept {
  return Digest::fromBytes(sha256(content));
}

Digest Digest::ofText(std::string_view text) noexcept { return Digest::fromBytes(sha256(text)); }

bool Digest::isSet() const noexcept {
  for (const std::uint8_t byte : bytes_) {
    if (byte != 0) {
      return true;
    }
  }
  return false;
}

std::string shortDigest(const Digest& digest) {
  const std::string full = digest.hex();
  return full.substr(0, 12);
}

}  // namespace cf
