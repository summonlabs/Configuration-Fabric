// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Distributor (controller).
//
// The distributor owns authoritative delivery state. It does not decide network
// intent, does not compute transition sequences and does not choose cohorts: it
// consumes explicit deployment instructions and is responsible for getting the
// named configuration generation to the named target with explicit evidence.
//
// Concurrency model, audited and deliberately small:
//
//   * One mutex (stateMutex) guards the durable controller state and the
//     artifact store. It is always acquired outermost and never held across a
//     socket operation, a filesystem hash, or a log call that could block on a
//     peer.
//   * Worker threads own one target session each. A target is claimed by at most
//     one worker at a time, which is what makes per-target ordering trivial.
//   * Connection objects are shared through weak references so that shutdown can
//     interrupt a blocked worker without racing its destruction.
//   * Logging is a leaf: no logger call can re-enter the distributor.
//   * stop() stops admission, interrupts every live connection, then joins; a
//     worker that observes the stop flag returns Cancelled and never publishes a
//     success it did not verify.

#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "cf/agent.hpp"
#include "cf/artifact.hpp"
#include "cf/convergence.hpp"
#include "cf/plan.hpp"
#include "cf/policy.hpp"
#include "cf/state.hpp"
#include "cf/transport.hpp"

namespace cf {

/// Outcome of resolving an explicit deployment set against this runtime.
struct TargetResolution {
  TargetId target;
  ConfigKey configKey;
  bool accepted{false};
  std::string reason;
};

class Distributor final {
 public:
  struct Options {
    NodeId nodeId;
    std::string stateDirectory;
    std::string artifactRoot;
    std::uint64_t maxArtifactBytes{64ull * 1024ull * 1024ull};
    std::uint64_t maxStoreBytes{4ull * 1024ull * 1024ull * 1024ull};
    std::size_t maxArtifacts{4096};
    DistributorPolicy policy;
    HmacKey key{};
    bool authenticate{true};
    /// Control endpoint. Loopback by default; exposing it is an operator
    /// decision, not a default.
    std::string controlHost{"127.0.0.1"};
    std::uint16_t controlPort{0};
    fault::FaultPlan faults;
    bool traceProtocol{false};
  };

  struct Recovery {
    ControllerStore::Recovery store;
    ArtifactStore::RecoveryReport artifacts;
  };

  Distributor(const Distributor&) = delete;
  Distributor& operator=(const Distributor&) = delete;
  ~Distributor();

  [[nodiscard]] static Result<std::unique_ptr<Distributor>> open(const Options& options,
                                                                 Recovery& recovery);

  /// Binds the control endpoint and starts the worker pool.
  [[nodiscard]] Status start();
  /// Stops admission, interrupts live sessions, joins workers and compacts the
  /// durable state. Idempotent.
  void stop();

  // --- Control surface. Every method is safe to call from any single thread. ---

  [[nodiscard]] Result<std::vector<TargetResolution>> resolveDeploymentSet(
      const DeploymentPlan& plan) const;
  [[nodiscard]] Status submitPlan(const DeploymentPlan& plan,
                                  std::vector<DeploymentId>* created);
  [[nodiscard]] Result<ConvergenceReport> convergence() const;
  [[nodiscard]] Result<std::string> explain(const TargetId& target) const;
  [[nodiscard]] Result<std::vector<DeliveryRecord>> deliveries() const;
  [[nodiscard]] Result<std::vector<TargetRuntime>> targets() const;
  [[nodiscard]] Result<std::vector<ArtifactMetadata>> artifacts() const;
  [[nodiscard]] Status retireDeployment(const DeploymentId& deployment, std::string reason);
  [[nodiscard]] Status ingestArtifact(const std::string& path, const ArtifactMetadata& declared);
  [[nodiscard]] Result<std::string> statusText() const;
  /// Registered shutdown hook used by the CLI's signal handling.
  void setShutdownFlag(std::atomic<bool>* flag) noexcept { externalShutdown_ = flag; }
  /// Requests a clean shutdown from the control channel. Idempotent.
  void requestShutdown() noexcept { shutdownRequested_.store(true, std::memory_order_relaxed); }
  /// Asks the scheduler to open one verification session against a target, even
  /// if it has no pending delivery. That session re-establishes contact evidence
  /// and reconciles authoritative state, which is how an operator re-validates a
  /// converged claim after a target restart without waiting for new work.
  [[nodiscard]] Status requestVerification(const TargetId& target);
  /// Recomputes every stored artifact digest. Reports one result per artifact.
  [[nodiscard]] Result<std::vector<std::pair<Digest, Status>>> verifyArtifacts() const;

  [[nodiscard]] std::uint16_t controlPort() const noexcept { return controlPort_; }
  [[nodiscard]] const NodeId& nodeId() const noexcept { return options_.nodeId; }
  [[nodiscard]] Epoch epoch() const;
  /// The incarnation of this controller process. It is allocated once at open and
  /// is the authority identity every session presents; a per-session value would
  /// make the target's fencing logic refuse the controller's own reconnections.
  [[nodiscard]] IncarnationId incarnation() const;
  [[nodiscard]] bool running() const noexcept { return running_.load(std::memory_order_relaxed); }
  [[nodiscard]] bool authenticated() const noexcept { return options_.authenticate; }

  /// Serves the control protocol on an accepted connection. Exposed so the
  /// validation suite can drive it directly over a real socket.
  [[nodiscard]] Status handleControlConnection(Socket socket);
  /// The shared secret, so the control channel authenticates with the same
  /// identity material as the agent protocol.
  [[nodiscard]] const HmacKey& sharedKey() const noexcept { return options_.key; }


 private:
  Distributor() = default;

  struct SessionContext {
    FramedConnection* connection{nullptr};
    TargetId target;
    Endpoint endpoint;
    Term targetTerm;
    IncarnationId targetIncarnation;
    std::uint32_t peerMaxPayload{kDefaultMaxPayloadBytes};
    ReconcileReportMessage report;
    bool haveReport{false};
    std::uint64_t chunksSent{0};
  };

  void workerLoop(std::size_t workerIndex);
  void controlLoop();
  [[nodiscard]] bool pickWork(TargetId* target, Endpoint* endpoint);
  /// Rate limit: a target may not be dialled more often than the configured
  /// session interval, and never while another worker holds it. Callers must
  /// hold stateMutex_.
  [[nodiscard]] bool mayDial(const TargetId& target, std::int64_t nowMillis) const;
  /// Resolves a target's dialable endpoint, or an unset endpoint when it has
  /// none. Callers must hold stateMutex_.
  [[nodiscard]] const Endpoint* endpointOfTarget(const ControllerState& state,
                                                 const TargetId& target) const;
  /// Applies a policy decision that needs no target session (reject, retire or
  /// account a failure). Called with no lock held.
  void applyLocalDecision(const DeliveryRecord& candidate);
  void runSession(const TargetId& target, const Endpoint& endpoint);
  /// Records session-establishment failure against every pending delivery for the
  /// target, so retries are bounded and spaced by the configured backoff.
  void recordSessionFailure(const TargetId& target, ErrorCode code, std::string detail);
  [[nodiscard]] Status handshake(SessionContext& session);
  [[nodiscard]] Status reconcile(SessionContext& session);
  [[nodiscard]] Status driveDeliveries(SessionContext& session);
  [[nodiscard]] Status driveDelivery(SessionContext& session, const DeliveryRecord& record);
  [[nodiscard]] Status offerAndTransfer(SessionContext& session, DeliveryRecord& record);
  [[nodiscard]] Status activateDelivery(SessionContext& session, DeliveryRecord& record);
  [[nodiscard]] Status awaitAcknowledgement(SessionContext& session, DeliveryRecord& record);

  // State helpers. Each takes the state lock for the shortest possible window.
  [[nodiscard]] DeliveryRecord snapshotDelivery(const DeploymentId& id) const;
  [[nodiscard]] DecisionInput decisionInputFor(const DeliveryRecord& record,
                                               std::int64_t nowMillis) const;
  [[nodiscard]] Status recordTransition(DeliveryRecord& record, DeliveryState target,
                                        EvidenceKind kind, ErrorCode code, std::string detail,
                                        bool fromReconciliation);
  [[nodiscard]] Status recordFailure(DeliveryRecord& record, ErrorCode code, std::string detail,
                                     bool fromTarget);
  [[nodiscard]] Status recordRejected(DeliveryRecord& record, ErrorCode code, std::string detail);
  [[nodiscard]] Status recordRetired(DeliveryRecord& record, std::string reason);
  [[nodiscard]] Status adoptActivation(DeliveryRecord& record, bool fromReconciliation,
                                       std::string detail);
  [[nodiscard]] Status acknowledge(DeliveryRecord& record, bool fromReconciliation,
                                   std::string detail);
  /// Appends an evidence event without changing lifecycle state. Used where a
  /// fact is worth recording but no boundary was crossed.
  [[nodiscard]] Status noteEvent(DeliveryRecord& record, EvidenceKind kind, std::string detail);
  [[nodiscard]] Status upsertDelivery(const DeliveryRecord& record);
  [[nodiscard]] Status upsertTarget(const TargetRuntime& runtime);
  /// Sets the process-local contact evidence for a target. This is deliberately
  /// not a durable write: liveness evidence must never survive as "current"
  /// across a restart, so it is recorded in memory only, while the durable
  /// timestamp is written by upsertTarget.
  void markContactCurrent(const TargetId& target, bool current, std::int64_t atMillis);
  /// Re-arms the retry budget of a target's failed deliveries after the target
  /// comes back with a new boot term. A restarted process is not the process the
  /// failures were recorded against, so the budget is restored exactly once per
  /// observed restart and the reason is recorded as evidence.
  [[nodiscard]] Status rearmAfterRestart(const TargetId& target, Term newTerm);
  [[nodiscard]] Status applyReconcileReport(const SessionContext& session);
  void registerConnection(const std::shared_ptr<FramedConnection>& connection);
  void unregisterConnection(FramedConnection* connection);
  [[nodiscard]] bool stopRequested() const;

  Options options_;
  std::unique_ptr<ControllerStore> store_;
  std::unique_ptr<ArtifactStore> artifactStore_;
  std::unique_ptr<Listener> controlListener_;
  std::vector<std::thread> workers_;
  std::thread controlThread_;

  mutable std::mutex stateMutex_;
  std::set<std::string> claimedTargets_;
  /// Process-local record of when each target was last dialled, used only to
  /// rate-limit session attempts. Never persisted: it is scheduling state, not
  /// delivery evidence.
  std::map<std::string, std::int64_t> lastSessionAttemptMillis_;
  /// Targets an operator asked to re-verify. Process-local by design: a request
  /// is a scheduling instruction, not delivery evidence.
  std::set<std::string> verificationRequests_;

  std::mutex connectionsMutex_;
  std::vector<std::weak_ptr<FramedConnection>> connections_;

  std::atomic<bool> stopRequested_{false};
  std::atomic<bool> shutdownRequested_{false};
  std::atomic<bool> running_{false};
  std::atomic<bool>* externalShutdown_{nullptr};
  std::uint16_t controlPort_{0};
};

}  // namespace cf
