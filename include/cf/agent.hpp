// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Target agent.
//
// One agent runs per target and owns exactly one thing: the truth about what
// this target has activated. It is the only component allowed to move bytes into
// the live configuration area, and it does so under three rules that are
// enforced in code, not by convention:
//
//   1. Stale fencing.  An offer, chunk, stage or commit carrying a generation
//      older than the committed generation is refused before anything is
//      touched. A same-generation offer with different content is a conflict and
//      is refused too.
//   2. Digest before activation.  The staged bytes are hashed and compared with
//      the declared digest. A mismatch destroys the staged artifact; there is no
//      path from a mismatched digest to an activated configuration.
//   3. Idempotent activation.  Every activation outcome is recorded durably
//      against (config key, generation, digest). A duplicate delivery is answered
//      from that record and never re-applied.
//
// The activation contract itself is honest about what the target can do:
//
//   AtomicActivate      one atomic pointer replacement; a crash leaves the
//                       target on exactly the old or exactly the new
//                       configuration.
//   PrepareCommitAbort  the target cannot swap atomically, so the agent exposes
//                       an explicit prepare window. A crash inside that window
//                       leaves the live area dirty; the agent detects it at
//                       start-up, aborts it, and reports the rollback. The
//                       weaker guarantee is carried through the protocol and is
//                       visible in every convergence report.
//
// The live pointer file is the authority for what is activated. If it and the
// durable record ever disagree - which is what a kill between the switch and the
// record looks like - start-up reconciling resolves it in favour of the pointer,
// because that is what the target is actually running.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cf/artifact.hpp"
#include "cf/ids.hpp"
#include "cf/protocol.hpp"
#include "cf/state.hpp"
#include "cf/transport.hpp"

namespace cf {

/// Named failure-injection points. These exist so that the validation suite can
/// stop a process at an exact protocol boundary; they are never enabled by
/// default and never change a decision, only the moment a process dies.
namespace fault {

inline constexpr std::string_view kAfterOffer = "after-offer";
inline constexpr std::string_view kAfterChunk = "after-chunk";
inline constexpr std::string_view kAfterVerify = "after-verify";
inline constexpr std::string_view kAfterStage = "after-stage";
inline constexpr std::string_view kAfterPrepare = "after-prepare";
inline constexpr std::string_view kBeforeCommit = "before-commit";
inline constexpr std::string_view kAfterCommit = "after-commit";
inline constexpr std::string_view kWithholdAck = "withhold-ack";
inline constexpr std::string_view kCorruptChunk = "corrupt-chunk";
inline constexpr std::string_view kTruncateTransfer = "truncate-transfer";
inline constexpr std::string_view kDropAfterPrepare = "drop-after-prepare";
inline constexpr std::string_view kStaleCommit = "stale-commit";
inline constexpr std::string_view kDuplicateChunk = "duplicate-chunk";
inline constexpr std::string_view kReorderChunk = "reorder-chunk";
inline constexpr std::string_view kOversizeDeclare = "oversize-declare";

/// A parsed fault plan. Unknown names are rejected at start-up so a typo cannot
/// silently disable a validation scenario.
class FaultPlan final {
 public:
  FaultPlan() = default;
  [[nodiscard]] static Result<FaultPlan> parse(std::string_view text);
  [[nodiscard]] bool armed(std::string_view point) const;
  /// Counter-style points ("after-chunk:3") match their prefix with a count.
  [[nodiscard]] std::uint32_t countFor(std::string_view point) const;
  [[nodiscard]] bool empty() const noexcept { return points_.empty(); }
  [[nodiscard]] std::string render() const;

 private:
  struct Entry {
    std::string name;
    std::uint32_t count{0};
  };
  std::vector<Entry> points_;
};

}  // namespace fault

/// The result of bringing the live configuration area back into agreement with
/// durable state at start-up.
struct LiveRecovery {
  bool rolledBackUnresolvedPrepare{false};
  bool adoptedCompletedSwitch{false};
  bool clearedUnverifiableCommit{false};
  std::size_t removedStagingFiles{0};
  std::size_t verifiedPayloads{0};
  std::string detail;
};

class TargetAgent final {
 public:
  struct Options {
    /// Durable state directory.
    std::string stateDirectory;
    /// Live configuration area. Empty means "<stateDirectory>/live".
    std::string liveDirectory;
    TargetId target;
    TargetClass klass{TargetClass::Unspecified};
    ApplyGuarantee guarantee{ApplyGuarantee::AtomicActivate};
    /// Largest artifact this target will accept.
    std::uint64_t maxArtifactBytes{64ull * 1024ull * 1024ull};
    /// Payload generations retained per config key.
    std::size_t retainedPayloadsPerKey{4};
    /// Idle budget for one session before it is abandoned.
    std::int64_t sessionIdleTimeoutMillis{10000};
    /// Shared secret for peer authentication. authenticate=false disables the
    /// handshake tag and is reported as a degraded guarantee.
    HmacKey key{};
    bool authenticate{true};
    /// Verify the committed payload digest at start-up.
    bool verifyCommittedPayloadOnStart{true};
    fault::FaultPlan faults;
  };

  TargetAgent(const TargetAgent&) = delete;
  TargetAgent& operator=(const TargetAgent&) = delete;
  ~TargetAgent();

  [[nodiscard]] static Result<std::unique_ptr<TargetAgent>> open(const Options& options,
                                                                 AgentStore::Recovery& recovery,
                                                                 LiveRecovery& liveRecovery);

  /// Serves exactly one session. Returns when the peer goes away, the session
  /// goes idle, or the protocol fails. Never throws and never leaves the live
  /// area in a state that is not explained by durable records.
  [[nodiscard]] Status serve(FramedConnection& connection);

  [[nodiscard]] const AgentState& state() const noexcept { return store_->state(); }
  [[nodiscard]] const Options& options() const noexcept { return options_; }
  [[nodiscard]] bool authenticated() const noexcept { return options_.authenticate; }
  [[nodiscard]] std::size_t storedTransfers() const noexcept { return store_->state().transfers.size(); }

  /// Reads the live pointer for a config key. Used by inspection tooling and by
  /// the validation suite to prove that a rollback really happened.
  struct LivePointer {
    Generation generation;
    Digest digest;
    bool present{false};
  };
  [[nodiscard]] Result<LivePointer> readLivePointer(const ConfigKey& key) const;
  [[nodiscard]] std::string liveKeyDirectory(const ConfigKey& key) const;

  /// Records a diagnostic note in durable state. Used by operators and by tests.
  [[nodiscard]] Status recordNote(std::string_view text);

 private:
  TargetAgent() = default;

  struct Session {
    FramedConnection* connection{nullptr};
    std::uint32_t peerMaxPayload{kDefaultMaxPayloadBytes};
    bool authenticated{false};
    Epoch authorityEpoch;
    IncarnationId authorityIncarnation;
    NodeId authorityNode;
  };

  [[nodiscard]] Status handshake(Session& session);
  [[nodiscard]] Status dispatch(Session& session, const Frame& frame, bool* keepGoing);
  [[nodiscard]] Status onPrepare(Session& session, std::span<const std::uint8_t> payload);
  [[nodiscard]] Status onChunk(Session& session, std::span<const std::uint8_t> payload);
  [[nodiscard]] Status onTransferComplete(Session& session, std::span<const std::uint8_t> payload);
  [[nodiscard]] Status onStage(Session& session, std::span<const std::uint8_t> payload);
  [[nodiscard]] Status onApplyPrepare(Session& session, std::span<const std::uint8_t> payload);
  [[nodiscard]] Status onApplyCommit(Session& session, std::span<const std::uint8_t> payload);
  [[nodiscard]] Status onApplyAbort(Session& session, std::span<const std::uint8_t> payload);
  [[nodiscard]] Status onReconcileRequest(Session& session, std::span<const std::uint8_t> payload);
  [[nodiscard]] Status onRetire(Session& session, std::span<const std::uint8_t> payload);
  [[nodiscard]] Status onPing(Session& session, std::span<const std::uint8_t> payload);

  [[nodiscard]] Status sendNack(Session& session, const DeploymentId& deployment,
                                const ConfigKey& key, Generation generation, const Digest& digest,
                                ErrorCode code, std::string detail);
  [[nodiscard]] Status sendAck(Session& session, const DeploymentId& deployment, const ConfigKey& key,
                               Generation generation, const Digest& digest, DeliveryState state,
                               std::uint64_t bytesTransferred, bool fromReconcile);

  [[nodiscard]] Status refusePrepare(Session& session, const PrepareMessage& message, ErrorCode code,
                                     std::string detail, DeliveryState observed);

  [[nodiscard]] Status beginTransfer(const PrepareMessage& message, std::uint64_t resumeFrom,
                                     StreamId* stream);
  [[nodiscard]] Status destroyTransfer(const DeploymentId& deployment, std::string_view why);
  [[nodiscard]] Status checkpointTransfer(const TransferRecord& record);
  [[nodiscard]] std::string stagingPath(const DeploymentId& deployment) const;

  [[nodiscard]] Result<Digest> hashStagingFile(const std::string& path, std::uint64_t expectedBytes);
  /// Performs the activation switch for an already staged transfer. When
  /// explicitPrepare is set the target cannot activate atomically, so the switch
  /// is bracketed by a durable prepare marker that a crash survives.
  [[nodiscard]] Status activate(const TransferRecord& transfer, bool explicitPrepare);
  [[nodiscard]] Status activate(const DeploymentId& deployment, const TransferRecord& transfer,
                                bool explicitPrepare);
  [[nodiscard]] Status commitGeneration(const DeploymentId& deployment, const ConfigKey& key,
                                        Generation generation, const Digest& digest,
                                        const ArtifactId& artifact);
  [[nodiscard]] Status recoverLiveArea(LiveRecovery& recovery);
  [[nodiscard]] Status prunePayloads(const ConfigKey& key);
  [[nodiscard]] Status note(std::string_view text);

  Options options_;
  std::unique_ptr<AgentStore> store_;
  std::string liveRoot_;
  std::string stagingRoot_;
  /// In-memory only: how many chunks this process has accepted. Used solely by
  /// fault injection, so it is deliberately not durable.
  std::uint64_t chunkCounter_{0};
};

}  // namespace cf
