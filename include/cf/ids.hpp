// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Strongly typed domain identity.
//
// Configuration Fabric never passes bare strings or integers between subsystems
// for domain objects. A TargetId cannot be assigned to a ConfigKey, a Generation
// cannot be compared against a Revision, and an IncarnationId cannot be used
// where an Epoch is expected. Conversions are explicit and reviewable.

#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "cf/digest.hpp"
#include "cf/result.hpp"
#include "cf/strong.hpp"

namespace cf {

// ---------------------------------------------------------------------------
// String identities
// ---------------------------------------------------------------------------

struct TargetIdTag;
struct ConfigKeyTag;
struct ArtifactIdTag;
struct DeploymentSetIdTag;
struct DeploymentIdTag;
struct NodeIdTag;
struct SchemaIdTag;
struct RolloutSetIdTag;

/// Identity of a delivery target: a network device or a control-plane
/// participant. Supplied by the upstream intent system; Configuration Fabric
/// never invents targets.
using TargetId = StrongString<TargetIdTag>;
/// Logical configuration slot on a target (for example "fabric/underlay").
/// Generation ordering is defined per (target, config key) lineage.
using ConfigKey = StrongString<ConfigKeyTag>;
/// Stable logical identity of a configuration artifact, independent of revision.
using ArtifactId = StrongString<ArtifactIdTag>;
/// Identity of a deployment set: an explicit list of targets supplied upstream.
using DeploymentSetId = StrongString<DeploymentSetIdTag>;
/// Deterministic identity of a single delivery attempt set for one target.
using DeploymentId = StrongString<DeploymentIdTag>;
/// Identity of a distributor/controller node (durable across restarts).
using NodeId = StrongString<NodeIdTag>;
/// Configuration schema identity (for example "cf.netconf.like.v1").
using SchemaId = StrongString<SchemaIdTag>;
/// Upstream rollout cohort identity. Carried for provenance only: Configuration
/// Fabric does not decide cohorts.
using RolloutSetId = StrongString<RolloutSetIdTag>;

inline constexpr std::size_t kMaxIdentifierLength = 128;
/// Bounds on free-form artifact metadata fields. Applied on both encode and
/// decode so a peer cannot push an unbounded string into durable state.
inline constexpr std::size_t kMaxMediaTypeBytes = 64;
inline constexpr std::size_t kMaxProducerBytes = 128;

/// Identifier character policy: printable ASCII, no whitespace, no control
/// characters, no leading '-'. Deliberately narrow so that identifiers can be
/// used in file names, CLI arguments and log lines without escaping.
[[nodiscard]] bool isValidIdentifier(std::string_view text) noexcept;

[[nodiscard]] Result<TargetId> parseTargetId(std::string_view text);
[[nodiscard]] Result<ConfigKey> parseConfigKey(std::string_view text);
[[nodiscard]] Result<ArtifactId> parseArtifactId(std::string_view text);
[[nodiscard]] Result<DeploymentSetId> parseDeploymentSetId(std::string_view text);
[[nodiscard]] Result<DeploymentId> parseDeploymentId(std::string_view text);
[[nodiscard]] Result<NodeId> parseNodeId(std::string_view text);
[[nodiscard]] Result<SchemaId> parseSchemaId(std::string_view text);
[[nodiscard]] Result<RolloutSetId> parseRolloutSetId(std::string_view text);

// ---------------------------------------------------------------------------
// Numeric identities and ordering tokens
// ---------------------------------------------------------------------------

struct GenerationTag;
struct EpochTag;
struct RevisionTag;
struct SequenceTag;
struct AttemptTag;
struct SchemaVersionTag;
struct StreamTag;
struct TermTag;

/// Fabric-assigned monotonic delivery generation for one (target, config key)
/// lineage. Strictly increasing. A lower generation is stale by definition.
using Generation = StrongUint<GenerationTag, std::uint64_t>;
/// Authority epoch of a distributor/controller process. Incremented on every
/// start. Any message carrying an older epoch than the observed one is fenced.
using Epoch = StrongUint<EpochTag, std::uint64_t>;
/// Producer-assigned revision of an artifact lineage (upstream provenance).
using Revision = StrongUint<RevisionTag, std::uint64_t>;
/// Durable store sequence number (journal record ordering).
using Sequence = StrongUint<SequenceTag, std::uint64_t>;
/// Attempt counter for one deployment, incremented for every retry.
using AttemptId = StrongUint<AttemptTag, std::uint64_t>;
/// Configuration schema version.
using SchemaVersion = StrongUint<SchemaVersionTag, std::uint32_t>;
/// Wire stream identity within a session.
using StreamId = StrongUint<StreamTag, std::uint64_t>;
/// Raft-like term is not used; this token identifies an agent's boot term for
/// fencing old sessions. It is allocated from the same monotonic space as Epoch
/// but is a distinct type so it cannot be confused with controller authority.
using Term = StrongUint<TermTag, std::uint64_t>;

// ---------------------------------------------------------------------------
// Opaque identities
// ---------------------------------------------------------------------------

/// 128-bit opaque identity with hex round-tripping. Used for process
/// incarnations and session nonces: values that must be unguessable and must
/// change on every process start.
template <class Tag>
class OpaqueIdentity final {
 public:
  static constexpr std::size_t kBytes = 16;

  constexpr OpaqueIdentity() noexcept = default;
  explicit constexpr OpaqueIdentity(std::array<std::uint8_t, kBytes> bytes) noexcept
      : bytes_(bytes) {}

  [[nodiscard]] static Result<OpaqueIdentity> parse(std::string_view hex) {
    OpaqueIdentity value;
    if (!fromHex(hex, std::span<std::uint8_t>(value.bytes_.data(), kBytes))) {
      return Result<OpaqueIdentity>::fail(ErrorCode::MalformedInput,
                                          "opaque identity must be 32 hexadecimal characters");
    }
    return Result<OpaqueIdentity>::ok(value);
  }

  [[nodiscard]] std::string hex() const {
    return toHex(std::span<const std::uint8_t>(bytes_.data(), kBytes));
  }

  [[nodiscard]] const std::array<std::uint8_t, kBytes>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] bool isSet() const noexcept;

  friend bool operator==(const OpaqueIdentity&, const OpaqueIdentity&) noexcept = default;
  friend std::strong_ordering operator<=>(const OpaqueIdentity& lhs,
                                          const OpaqueIdentity& rhs) noexcept {
    return lhs.bytes_ <=> rhs.bytes_;
  }

 private:
  std::array<std::uint8_t, kBytes> bytes_{};
};

struct IncarnationTag;
struct SessionNonceTag;

/// Identity of one OS process lifetime of a target agent (or of a distributor).
/// A new process start always produces a new incarnation; persisted evidence
/// from an older incarnation is never treated as current.
using IncarnationId = OpaqueIdentity<IncarnationTag>;
/// Per-connection nonce, unique per session, bound into the authentication tag.
using SessionNonce = OpaqueIdentity<SessionNonceTag>;

// ---------------------------------------------------------------------------
// Wire-safe enumeration identities
// ---------------------------------------------------------------------------

/// Kind of participant that a target identity denotes. Carried on the wire so
/// that a control-plane participant can never be mistaken for a device.
enum class TargetClass : std::uint8_t {
  Unspecified = 0,
  NetworkDevice = 1,
  ControlPlaneParticipant = 2,
};

[[nodiscard]] std::string_view targetClassName(TargetClass value) noexcept;
[[nodiscard]] bool parseTargetClass(std::string_view text, TargetClass& out) noexcept;

/// What the target agent can honestly guarantee about activation.
enum class ApplyGuarantee : std::uint8_t {
  /// The target swaps to the new configuration atomically; readers observe
  /// either the old or the new configuration, never a mixture.
  AtomicActivate = 1,
  /// The target cannot swap atomically. The agent exposes explicit
  /// prepare/commit/abort boundaries; a crash between prepare and commit leaves
  /// an unresolved window that reconciliation must resolve.
  PrepareCommitAbort = 2,
};

[[nodiscard]] std::string_view applyGuaranteeName(ApplyGuarantee value) noexcept;
[[nodiscard]] bool parseApplyGuarantee(std::string_view text, ApplyGuarantee& out) noexcept;

/// What the upstream deployment instruction demands of the target.
enum class GuaranteeRequirement : std::uint8_t {
  /// Atomic activation is mandatory; a weaker target must reject the delivery.
  RequireAtomic = 1,
  /// Prepare/commit/abort is acceptable; the weaker guarantee is recorded.
  AllowPrepareCommit = 2,
};

[[nodiscard]] std::string_view guaranteeRequirementName(GuaranteeRequirement value) noexcept;
[[nodiscard]] bool parseGuaranteeRequirement(std::string_view text,
                                             GuaranteeRequirement& out) noexcept;

/// Deterministic compatibility decision between what a target offers and what
/// the deployment demands.
[[nodiscard]] bool guaranteeSatisfies(ApplyGuarantee offered, GuaranteeRequirement required) noexcept;

// ---------------------------------------------------------------------------
// Derived identities
// ---------------------------------------------------------------------------

/// Deterministic deployment identity. Recomputing it from the same inputs always
/// yields the same value, which is what makes redelivery idempotent across
/// controller restarts.
[[nodiscard]] DeploymentId deriveDeploymentId(const TargetId& target, const ConfigKey& key,
                                              Generation generation, const Digest& digest);
/// Deterministic stream identity for one attempt of one deployment.
[[nodiscard]] StreamId deriveStreamId(const DeploymentId& deployment, AttemptId attempt) noexcept;

}  // namespace cf

namespace std {

template <class Tag>
struct hash<::cf::OpaqueIdentity<Tag>> {
  [[nodiscard]] size_t operator()(const ::cf::OpaqueIdentity<Tag>& id) const noexcept {
    const auto& bytes = id.bytes();
    size_t seed = 1469598103934665603ULL;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      seed = (seed ^ bytes[i]) * 1099511628211ULL;
    }
    return seed;
  }
};

}  // namespace std
