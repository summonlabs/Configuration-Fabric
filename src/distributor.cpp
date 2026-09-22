// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/distributor.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>

#include "cf/checked.hpp"
#include "cf/codec.hpp"
#include "cf/contract.hpp"
#include "cf/control.hpp"
#include "cf/log.hpp"
#include "cf/reconciliation.hpp"
#include "cf/rng.hpp"

namespace cf {
namespace {

constexpr std::string_view kComponent = "distributor";
/// Upper bound on how many protocol steps one delivery may take inside a single
/// session, so a pathological peer cannot keep a worker busy forever.
constexpr int kMaxStepsPerDelivery = 16;
/// Idle sleep for a worker that found no work.
constexpr std::int64_t kIdleSleepMillis = 25;
/// A session is torn down after this many consecutive protocol failures so a
/// hot loop cannot spin against a broken peer.
constexpr int kMaxSessionErrors = 3;

[[nodiscard]] bool isRetryableFromTarget(ErrorCode code) {
  const RetryDirective directive = retryDirectiveFor(code);
  return directive == RetryDirective::RetryNow || directive == RetryDirective::RetryWithBackoff ||
         directive == RetryDirective::RetryNewSession ||
         directive == RetryDirective::RetryAfterReconcile;
}

[[nodiscard]] bool isTerminalRejection(ErrorCode code) {
  return code == ErrorCode::GuaranteeUnsupported || code == ErrorCode::SchemaUnsupported ||
         code == ErrorCode::OversizePayload || code == ErrorCode::InvalidArgument ||
         code == ErrorCode::UnsupportedVersion || code == ErrorCode::UnsupportedFeature ||
         code == ErrorCode::PolicyDenied || code == ErrorCode::CapabilityMismatch;
}

}  // namespace

Distributor::~Distributor() { stop(); }

Result<std::unique_ptr<Distributor>> Distributor::open(const Options& options, Recovery& recovery) {
  if (!options.nodeId.isSet()) {
    return Result<std::unique_ptr<Distributor>>::fail(ErrorCode::InvalidArgument,
                                                      "distributor node id must be set");
  }
  if (options.stateDirectory.empty() || options.artifactRoot.empty()) {
    return Result<std::unique_ptr<Distributor>>::fail(
        ErrorCode::InvalidArgument,
        "distributor state and artifact directories must not be empty");
  }
  CF_TRY(options.policy.validate());

  std::unique_ptr<Distributor> distributor(new Distributor());
  distributor->options_ = options;

  ArtifactStore::Options artifactOptions;
  artifactOptions.root = options.artifactRoot;
  artifactOptions.maxArtifactBytes = options.maxArtifactBytes;
  artifactOptions.maxTotalBytes = options.maxStoreBytes;
  artifactOptions.maxArtifacts = options.maxArtifacts;
  auto artifacts = ArtifactStore::open(artifactOptions, recovery.artifacts);
  if (!artifacts) {
    return Result<std::unique_ptr<Distributor>>::fail(artifacts.error());
  }
  distributor->artifactStore_ = std::move(artifacts).value();

  ControllerStore::Options storeOptions;
  storeOptions.directory = options.stateDirectory;
  storeOptions.name = "controller";
  auto store = ControllerStore::open(storeOptions, recovery.store);
  if (!store) {
    return Result<std::unique_ptr<Distributor>>::fail(store.error());
  }
  distributor->store_ = std::move(store).value();

  // A new authority epoch. Everything the previous process believed about target
  // liveness is historical from here on, and every delivery that was in flight is
  // resolved by reconciliation rather than by assumption.
  ControllerState& state = distributor->store_->state();
  const auto nextEpoch = checkedAdd<std::uint64_t>(state.epoch.value(), 1u);
  if (!nextEpoch) {
    return Result<std::unique_ptr<Distributor>>::fail(ErrorCode::ArithmeticOverflow,
                                                      "distributor epoch exhausted");
  }
  const IncarnationId incarnation = IncarnationId(secureRandom128());
  ByteWriter identity(256);
  identity.string(options.nodeId.str(), kMaxIdentifierLength);
  identity.u64(*nextEpoch);
  identity.opaque128(incarnation.bytes());
  identity.i64(nowUnixMillis());
  CF_TRY(distributor->store_->commit(JournalRecordType::ControllerIdentity, identity.span()));

  {
    std::lock_guard<std::mutex> guard(distributor->stateMutex_);
    ControllerState& committed = distributor->store_->state();
    for (auto& entry : committed.targets) {
      TargetRuntime& runtime = entry.second;
      // Persisted contact evidence is loaded, but it is explicitly not current.
      runtime.contactEstablishedThisProcess = false;
    }
    for (auto& entry : committed.deliveries) {
      DeliveryRecord& record = entry.second;
      if (record.state == DeliveryState::Transferred) {
        // A transfer that had not been verified at the previous authority is not
        // trusted; the delivery is re-driven from the offer boundary.
        record.state = DeliveryState::Offered;
        record.lastDetail = "reset to offered after distributor restart: the previous transfer was "
                            "never verified";
      }
    }
  }
  CF_TRY(distributor->store_->compactIfNeeded());
  return Result<std::unique_ptr<Distributor>>::ok(std::move(distributor));
}

Epoch Distributor::epoch() const {
  std::lock_guard<std::mutex> guard(stateMutex_);
  return store_->state().epoch;
}

IncarnationId Distributor::incarnation() const {
  std::lock_guard<std::mutex> guard(stateMutex_);
  return store_->state().incarnation;
}

bool Distributor::stopRequested() const {
  if (stopRequested_.load(std::memory_order_relaxed)) {
    return true;
  }
  if (shutdownRequested_.load(std::memory_order_relaxed)) {
    return true;
  }
  return externalShutdown_ != nullptr && externalShutdown_->load(std::memory_order_relaxed);
}

Result<std::vector<std::pair<Digest, Status>>> Distributor::verifyArtifacts() const {
  return Result<std::vector<std::pair<Digest, Status>>>::ok(artifactStore_->verifyAll());
}

Status Distributor::start() {
  if (running_.load(std::memory_order_relaxed)) {
    return Status::fail(ErrorCode::AlreadyExists, "distributor is already running");
  }
  CF_TRY(ensureSocketRuntime());
  auto listener = Listener::bindTcp(options_.controlHost, options_.controlPort, 16);
  if (!listener) {
    return Status::fail(listener.error());
  }
  controlListener_ = std::move(listener).value();
  controlPort_ = controlListener_->port();
  stopRequested_.store(false, std::memory_order_relaxed);
  shutdownRequested_.store(false, std::memory_order_relaxed);
  running_.store(true, std::memory_order_relaxed);

  const std::size_t workerCount = options_.policy.maxConcurrentSessions;
  workers_.reserve(workerCount);
  for (std::size_t i = 0; i < workerCount; ++i) {
    workers_.emplace_back([this, i] { workerLoop(i); });
  }
  controlThread_ = std::thread([this] { controlLoop(); });
  Logger::global().info(kComponent, "control endpoint listening on " + options_.controlHost + ":" +
                                        std::to_string(controlPort_) + " with " +
                                        std::to_string(workerCount) + " delivery worker(s)");
  return Status::ok();
}

void Distributor::stop() {
  if (!running_.exchange(false, std::memory_order_relaxed)) {
    return;
  }
  stopRequested_.store(true, std::memory_order_relaxed);
  // Interrupt every live connection so a worker blocked in receive() wakes up.
  {
    std::lock_guard<std::mutex> guard(connectionsMutex_);
    for (auto& weak : connections_) {
      if (auto connection = weak.lock()) {
        connection->interrupt();
      }
    }
    connections_.clear();
  }
  if (controlListener_ != nullptr) {
    controlListener_->interrupt();
  }
  for (std::thread& worker : workers_) {
    if (worker.joinable()) {
      worker.join();
    }
  }
  workers_.clear();
  if (controlThread_.joinable()) {
    controlThread_.join();
  }
  if (controlListener_ != nullptr) {
    controlListener_->close();
    controlListener_.reset();
  }
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    const Status compacted = store_->compact();
    if (!compacted) {
      Logger::global().error(kComponent, "final state compaction failed: " + compacted.str());
    }
  }
  Logger::global().info(kComponent, "stopped");
}

void Distributor::registerConnection(const std::shared_ptr<FramedConnection>& connection) {
  std::lock_guard<std::mutex> guard(connectionsMutex_);
  connections_.push_back(connection);
}

void Distributor::unregisterConnection(FramedConnection* connection) {
  std::lock_guard<std::mutex> guard(connectionsMutex_);
  connections_.erase(std::remove_if(connections_.begin(), connections_.end(),
                                    [connection](const std::weak_ptr<FramedConnection>& weak) {
                                      const auto locked = weak.lock();
                                      return !locked || locked.get() == connection;
                                    }),
                     connections_.end());
}

// --- Scheduling ------------------------------------------------------------

bool Distributor::mayDial(const TargetId& target, std::int64_t nowMillis) const {
  if (claimedTargets_.find(target.str()) != claimedTargets_.end()) {
    return false;
  }
  const auto found = lastSessionAttemptMillis_.find(target.str());
  if (found == lastSessionAttemptMillis_.end()) {
    return true;
  }
  return (nowMillis - found->second) >= options_.policy.sessionMinIntervalMillis;
}

const Endpoint* Distributor::endpointOfTarget(const ControllerState& state,
                                              const TargetId& target) const {
  static const Endpoint kNone{};
  const TargetRuntime* runtime = state.findTarget(target);
  if (runtime == nullptr || runtime->endpoint.empty()) {
    return &kNone;
  }
  static thread_local Endpoint parsed;
  auto result = parseEndpoint(runtime->endpoint);
  if (!result || !result.value().isSet()) {
    return &kNone;
  }
  parsed = result.value();
  return &parsed;
}

Status Distributor::requestVerification(const TargetId& target) {
  std::lock_guard<std::mutex> guard(stateMutex_);
  if (store_->state().findTarget(target) == nullptr) {
    return Status::fail(ErrorCode::NotFound, "no such target", target.str());
  }
  verificationRequests_.insert(target.str());
  return Status::ok();
}

bool Distributor::pickWork(TargetId* target, Endpoint* endpoint) {
  std::vector<DeliveryRecord> localWork;
  bool selected = false;
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    const ControllerState& state = store_->state();
    const std::int64_t now = nowUnixMillis();

    // Operator-requested verification sessions come first: they exist to
    // re-establish evidence that only a live session can produce.
    for (auto request = verificationRequests_.begin(); request != verificationRequests_.end();) {
      auto targetId = parseTargetId(*request);
      if (!targetId || !mayDial(targetId.value(), now)) {
        ++request;
        continue;
      }
      claimedTargets_.insert(*request);
      lastSessionAttemptMillis_[*request] = now;
      *target = targetId.value();
      *endpoint = *endpointOfTarget(state, targetId.value());
      verificationRequests_.erase(request);
      return true;
    }

    for (const auto& entry : state.deliveries) {
      const DeliveryRecord& record = entry.second;
      if (!isPendingState(record.state)) {
        continue;
      }
      const DecisionInput input = buildDecisionInput(state, options_.policy, record, now);
      const Decision decision = decide(options_.policy, input, state.epoch, record.generation);
      switch (decision.action) {
        case PolicyAction::Offer:
        case PolicyAction::ResumeTransfer:
        case PolicyAction::Activate:
        case PolicyAction::Reconcile: {
          if (selected || !mayDial(record.target, now)) {
            break;
          }
          claimedTargets_.insert(record.target.str());
          lastSessionAttemptMillis_[record.target.str()] = now;
          *target = record.target;
          *endpoint = *endpointOfTarget(state, record.target);
          selected = true;
          break;
        }
        case PolicyAction::Reject:
        case PolicyAction::Retire:
        case PolicyAction::RecordFailureAndRetry:
          localWork.push_back(record);
          break;
        case PolicyAction::GiveUp: {
          // The budget is exhausted, but the target may have been repaired or
          // restarted since. A slow probe costs one session per probe interval
          // and is what lets a restarted target re-arm its delivery without
          // operator action.
          if (selected || input.millisSinceLastAttempt < options_.policy.repairProbeMillis) {
            break;
          }
          if (!mayDial(record.target, now)) {
            break;
          }
          claimedTargets_.insert(record.target.str());
          lastSessionAttemptMillis_[record.target.str()] = now;
          *target = record.target;
          *endpoint = *endpointOfTarget(state, record.target);
          selected = true;
          break;
        }
        case PolicyAction::Wait:
        case PolicyAction::None:
          // Nothing to do: the delivery is waiting out its backoff. A session
          // would achieve nothing.
          break;
      }
    }
  }
  for (DeliveryRecord& record : localWork) {
    applyLocalDecision(record);
  }
  return selected;
}

void Distributor::applyLocalDecision(const DeliveryRecord& candidate) {
  DeliveryRecord record = snapshotDelivery(candidate.id);
  if (!record.id.isSet() || !isPendingState(record.state)) {
    return;
  }
  const std::int64_t now = nowUnixMillis();
  const DecisionInput input = decisionInputFor(record, now);
  const Decision decision = decide(options_.policy, input, epoch(), record.generation);
  Status applied = Status::ok();
  switch (decision.action) {
    case PolicyAction::Reject: {
      ErrorCode code = ErrorCode::PolicyDenied;
      if (!guaranteeSatisfies(input.targetGuarantee, record.requirement)) {
        code = ErrorCode::GuaranteeUnsupported;
      } else if (!input.artifactAvailable) {
        code = ErrorCode::ArtifactUnavailable;
      }
      applied = recordRejected(record, code, decision.reason);
      if (applied) {
        Logger::global().warn(kComponent, "delivery " + record.id.str() + " rejected: " +
                                              decision.reason);
      }
      break;
    }
    case PolicyAction::Retire:
      applied = recordRetired(record, decision.reason);
      break;
    case PolicyAction::RecordFailureAndRetry:
      applied = recordFailure(record,
                              record.lastError == ErrorCode::Ok ? ErrorCode::IoFailure
                                                                : record.lastError,
                              decision.reason, false);
      break;
    default:
      return;
  }
  if (!applied) {
    Logger::global().warn(kComponent, "cannot apply a local decision to " + record.id.str() + ": " +
                                          applied.str());
  }
}

void Distributor::workerLoop(std::size_t workerIndex) {
  while (!stopRequested()) {
    TargetId target;
    Endpoint endpoint;
    if (!pickWork(&target, &endpoint)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(kIdleSleepMillis));
      continue;
    }
    runSession(target, endpoint);
    {
      std::lock_guard<std::mutex> guard(stateMutex_);
      claimedTargets_.erase(target.str());
    }
  }
  Logger::global().debug(kComponent, "worker " + std::to_string(workerIndex) + " exiting");
}

void Distributor::controlLoop() {
  while (!stopRequested() && controlListener_ != nullptr) {
    auto accepted = controlListener_->accept(monotonicMillis() + 100);
    if (!accepted) {
      if (accepted.error().code() == ErrorCode::PeerIdleTimeout) {
        continue;
      }
      if (accepted.error().code() == ErrorCode::ShuttingDown) {
        return;
      }
      Logger::global().warn(kComponent, "control accept failed: " + accepted.error().str());
      continue;
    }
    const Status served = handleControlConnection(std::move(accepted).value());
    if (!served && served.code() != ErrorCode::ConnectionClosed &&
        served.code() != ErrorCode::PeerIdleTimeout) {
      Logger::global().warn(kComponent, "control session ended: " + served.str());
    }
  }
}

// --- Session ---------------------------------------------------------------

void Distributor::runSession(const TargetId& target, const Endpoint& endpoint) {
  auto socket = connectTcp(endpoint.host, endpoint.port,
                           options_.policy.connectTimeoutMillis);
  if (!socket) {
    // A target that cannot be reached is a delivery failure like any other: it
    // must consume the retry budget and be reported, never retried in a hot loop.
    Logger::global().warn(kComponent, "cannot reach target " + target.str() + " at " +
                                          endpoint.str() + ": " + socket.error().str());
    recordSessionFailure(target, socket.error().code(), socket.error().str());
    return;
  }
  auto connection = std::make_shared<FramedConnection>(std::move(socket).value(),
                                                       options_.policy.maxPayloadBytes);
  registerConnection(connection);

  SessionContext session;
  session.connection = connection.get();
  session.target = target;
  session.endpoint = endpoint;

  Status result = handshake(session);
  const bool established = static_cast<bool>(result);
  if (result) {
    result = reconcile(session);
  }
  if (!result) {
    // A session that never established cannot have advanced anything, so the
    // pending deliveries consume one attempt and wait out the backoff.
    recordSessionFailure(target, result.code(), result.str());
  }
  if (result) {
    result = driveDeliveries(session);
  }
  if (!result && result.code() != ErrorCode::ConnectionClosed &&
      result.code() != ErrorCode::Cancelled && result.code() != ErrorCode::ShuttingDown) {
    Logger::global().debug(kComponent,
                           "session with " + target.str() + " ended: " + result.str());
  }
  if (established && connection->valid()) {
    GoodbyeMessage goodbye;
    goodbye.code = ErrorCode::Ok;
    goodbye.reason = "session complete";
    auto encoded = encodeGoodbye(goodbye);
    if (encoded) {
      (void)connection->send(FrameType::Goodbye, 0, encoded.value(),
                             monotonicMillis() + 200);
    }
  }
  connection->close();
  unregisterConnection(connection.get());
}

Status Distributor::handshake(SessionContext& session) {
  FramedConnection& connection = *session.connection;
  const std::int64_t deadline = monotonicMillis() + options_.policy.requestTimeoutMillis;

  HelloMessage hello;
  hello.nodeId = options_.nodeId;
  hello.epoch = epoch();
  hello.incarnation = incarnation();
  hello.nonce = SessionNonce(secureRandom128());
  hello.minWireVersion = kWireVersion;
  hello.maxWireVersion = kWireVersion;
  hello.maxPayloadBytes = options_.policy.maxPayloadBytes;
  hello.capabilities = kCapabilityKnownMask;
  CF_TRY_ASSIGN(std::vector<std::uint8_t> encoded, encodeHello(hello));
  if (options_.authenticate) {
    CF_TRY(sealAuthenticated(encoded, options_.key));
  }
  CF_TRY(connection.send(FrameType::Hello, 0, encoded, deadline));

  auto response = connection.receive(deadline);
  if (!response) {
    return Status::fail(response.error());
  }
  if (response.value().type() == FrameType::AuthReject) {
    CF_TRY_ASSIGN(const AuthRejectMessage reject, decodeAuthReject(response.value().payload));
    return Status::fail(reject.code, "target refused the session", reject.detail);
  }
  if (response.value().type() != FrameType::HelloAck) {
    return Status::fail(ErrorCode::UnexpectedMessage, "expected a hello-ack from the target",
                        std::string(frameTypeName(response.value().type())));
  }
  CF_TRY_ASSIGN(HelloAckMessage ack, decodeHelloAck(response.value().payload));
  if (!(ack.target == session.target)) {
    return Status::fail(ErrorCode::Unauthorized, "the peer identifies as a different target",
                        ack.target.str());
  }
  if (options_.authenticate) {
    const Status authenticated = verifyAuthenticated(response.value().payload, options_.key);
    if (!authenticated) {
      return Status::fail(authenticated.error());
    }
  }
  // Effective payload ceiling is the smaller of what each side advertised.
  session.peerMaxPayload =
      std::min(options_.policy.maxPayloadBytes, ack.maxPayloadBytes);
  session.targetTerm = ack.term;
  session.targetIncarnation = ack.incarnation;

  // Fence a target incarnation this controller already moved past.
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    const TargetRuntime* runtime = store_->state().findTarget(session.target);
    if (runtime != nullptr && runtime->term.isSet()) {
      if (ack.term < runtime->term) {
        return Status::fail(ErrorCode::FencedIncarnation,
                            "the target presented an older boot term than the one already fenced",
                            std::to_string(ack.term.value()) + " < " +
                                std::to_string(runtime->term.value()));
      }
      if (ack.term == runtime->term && runtime->incarnation.isSet() &&
          !(ack.incarnation == runtime->incarnation)) {
        return Status::fail(ErrorCode::FencedIncarnation,
                            "a different incarnation claims an already observed boot term",
                            ack.incarnation.hex());
      }
    }
  }

  HelloConfirmMessage confirm;
  confirm.authTag = hmacSha256(options_.key,
                               std::span<const std::uint8_t>(
                                   response.value().payload.data(),
                                   response.value().payload.size()));
  if (options_.authenticate) {
    // The tag must cover the ack payload with its own tag field zeroed, which is
    // what the agent produced.
    std::vector<std::uint8_t> scratch = response.value().payload;
    std::fill(scratch.begin() + static_cast<std::ptrdiff_t>(scratch.size() - kAuthTagBytes),
              scratch.end(), std::uint8_t{0});
    confirm.authTag = hmacSha256(options_.key,
                                 std::span<const std::uint8_t>(scratch.data(), scratch.size()));
  } else {
    confirm.authTag = Sha256Digest{};
  }
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> confirmBytes, encodeHelloConfirm(confirm));
  CF_TRY(connection.send(FrameType::HelloConfirm, 0, confirmBytes, deadline));

  // Adopt the target's report as the session's starting point, marked as current
  // because this process established it.
  TargetRuntime runtime;
  bool observedRestart = false;
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    const TargetRuntime* existing = store_->state().findTarget(session.target);
    if (existing != nullptr) {
      runtime = *existing;
      observedRestart = runtime.term.isSet() && ack.term > runtime.term;
      if (observedRestart) {
        runtime.restartsObserved += 1;
      }
    }
  }
  runtime.id = session.target;
  runtime.klass = ack.targetClass;
  runtime.guarantee = ack.guarantee;
  runtime.term = ack.term;
  runtime.incarnation = ack.incarnation;
  runtime.committedGeneration = ack.committedGeneration;
  runtime.committedDigest = ack.committedDigest;
  runtime.committedArtifact = ack.committedArtifact;
  runtime.lastContactMillis = nowUnixMillis();
  runtime.contactEstablishedThisProcess = false;
  runtime.sessionsEstablished += 1;
  CF_TRY(upsertTarget(runtime));
  markContactCurrent(session.target, true, runtime.lastContactMillis);
  if (observedRestart) {
    CF_TRY(rearmAfterRestart(session.target, ack.term));
  }
  Logger::global().info(kComponent, "session established with " + session.target.str() + " at " +
                                        session.endpoint.str() + " term=" +
                                        std::to_string(ack.term.value()) + " guarantee=" +
                                        std::string(applyGuaranteeName(ack.guarantee)));
  return Status::ok();
}

void Distributor::recordSessionFailure(const TargetId& target, ErrorCode code,
                                       std::string detail) {
  std::vector<DeliveryRecord> pending;
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    for (const auto& entry : store_->state().deliveries) {
      if (entry.second.target == target && isPendingState(entry.second.state)) {
        pending.push_back(entry.second);
      }
    }
  }
  for (DeliveryRecord& record : pending) {
    const Status recorded = recordFailure(record, code, detail, false);
    if (!recorded) {
      Logger::global().warn(kComponent, "cannot record a session failure for " + record.id.str() +
                                            ": " + recorded.str());
    }
  }
  // Contact evidence is no longer current once a session fails to establish.
  TargetRuntime runtime;
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    const TargetRuntime* existing = store_->state().findTarget(target);
    if (existing == nullptr) {
      return;
    }
    runtime = *existing;
  }
  runtime.contactEstablishedThisProcess = false;
  const Status updated = upsertTarget(runtime);
  if (!updated) {
    Logger::global().warn(kComponent, "cannot update target contact evidence: " + updated.str());
  }
  markContactCurrent(target, false, 0);
}

Status Distributor::upsertTarget(const TargetRuntime& runtime) {
  std::lock_guard<std::mutex> guard(stateMutex_);
  auto encoded = encodeTargetRuntime(runtime);
  if (!encoded) {
    return Status::fail(encoded.error());
  }
  return store_->commit(JournalRecordType::TargetUpsert, encoded.value());
}

Status Distributor::rearmAfterRestart(const TargetId& target, Term newTerm) {
  std::vector<DeliveryRecord> failed;
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    for (const auto& entry : store_->state().deliveries) {
      if (entry.second.target == target && entry.second.state == DeliveryState::Failed) {
        failed.push_back(entry.second);
      }
    }
  }
  for (DeliveryRecord& record : failed) {
    record.failures = 0;
    record.attempt = AttemptId::fromValue(record.attempt.value() + 1);
    const Status noted =
        noteEvent(record, EvidenceKind::Retried,
                  "retry budget re-armed: the target came back with boot term " +
                      std::to_string(newTerm.value()));
    if (!noted) {
      return noted;
    }
    Logger::global().info(kComponent, "retry budget re-armed for " + record.id.str() +
                                          " after target " + target.str() + " restarted");
  }
  return Status::ok();
}

void Distributor::markContactCurrent(const TargetId& target, bool current, std::int64_t atMillis) {
  std::lock_guard<std::mutex> guard(stateMutex_);
  const auto found = store_->state().targets.find(target);
  if (found == store_->state().targets.end()) {
    return;
  }
  found->second.contactEstablishedThisProcess = current;
  if (atMillis > 0) {
    found->second.lastContactMillis = atMillis;
  }
}

Status Distributor::upsertDelivery(const DeliveryRecord& record) {
  std::lock_guard<std::mutex> guard(stateMutex_);
  auto encoded = encodeDeliveryRecord(record);
  if (!encoded) {
    return Status::fail(encoded.error());
  }
  return store_->commit(JournalRecordType::DeliveryUpsert, encoded.value());
}

DeliveryRecord Distributor::snapshotDelivery(const DeploymentId& id) const {
  std::lock_guard<std::mutex> guard(stateMutex_);
  const DeliveryRecord* record = store_->state().findDelivery(id);
  return record != nullptr ? *record : DeliveryRecord{};
}

DecisionInput Distributor::decisionInputFor(const DeliveryRecord& record,
                                            std::int64_t nowMillis) const {
  std::lock_guard<std::mutex> guard(stateMutex_);
  return buildDecisionInput(store_->state(), options_.policy, record, nowMillis);
}

Status Distributor::reconcile(SessionContext& session) {
  FramedConnection& connection = *session.connection;
  const std::int64_t deadline = monotonicMillis() + options_.policy.requestTimeoutMillis;
  ReconcileRequestMessage request;
  request.nodeId = options_.nodeId;
  request.epoch = epoch();
  request.incarnation = incarnation();
  request.maxFindings = static_cast<std::uint32_t>(
      std::min<std::size_t>(options_.policy.maxReconcileFindings, kMaxFindingsInReport));
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeReconcileRequest(request));
  CF_TRY(connection.send(FrameType::ReconcileRequest, 0, encoded, deadline));
  auto response = connection.receive(deadline);
  if (!response) {
    return Status::fail(response.error());
  }
  if (response.value().type() != FrameType::ReconcileReport) {
    return Status::fail(ErrorCode::UnexpectedMessage, "expected a reconcile report",
                        std::string(frameTypeName(response.value().type())));
  }
  CF_TRY_ASSIGN(ReconcileReportMessage report, decodeReconcileReport(response.value().payload));
  if (!(report.target == session.target)) {
    return Status::fail(ErrorCode::Unauthorized, "the reconcile report names a different target",
                        report.target.str());
  }
  session.report = std::move(report);
  session.haveReport = true;

  // The report is evidence only under the authority this session established.
  if (!(session.report.term == session.targetTerm) ||
      !(session.report.incarnation == session.targetIncarnation)) {
    return Status::fail(ErrorCode::FencedIncarnation,
                        "the reconcile report carries authority that does not match the session");
  }

  TargetRuntime runtime;
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    const TargetRuntime* existing = store_->state().findTarget(session.target);
    if (existing != nullptr) {
      runtime = *existing;
    }
  }
  runtime.id = session.target;
  runtime.klass = session.report.targetClass;
  runtime.guarantee = session.report.guarantee;
  runtime.term = session.report.term;
  runtime.incarnation = session.report.incarnation;
  runtime.committedGeneration = session.report.committedGeneration;
  runtime.committedDigest = session.report.committedDigest;
  runtime.committedArtifact = session.report.committedArtifact;
  runtime.applyPrepared = session.report.applyPrepared;
  runtime.preparedDeployment = session.report.preparedDeployment;
  runtime.preparedGeneration = session.report.preparedGeneration;
  runtime.preparedDigest = session.report.preparedDigest;
  runtime.lastContactMillis = nowUnixMillis();
  runtime.contactEstablishedThisProcess = false;
  // restartsObserved counts restarts this controller has witnessed. The target's
  // own start counter is a different number and is reported by the target, so the
  // two are never merged into one field.
  CF_TRY(upsertTarget(runtime));
  markContactCurrent(session.target, true, runtime.lastContactMillis);
  Logger::global().debug(kComponent, "target " + session.target.str() +
                                         " reports restart count " +
                                         std::to_string(session.report.restartCount));
  return applyReconcileReport(session);
}

Status Distributor::applyReconcileReport(const SessionContext& session) {
  std::vector<DeliveryRecord> pending;
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    for (const auto& entry : store_->state().deliveries) {
      if (!(entry.second.target == session.target)) {
        continue;
      }
      pending.push_back(entry.second);
    }
  }
  std::sort(pending.begin(), pending.end(), [](const DeliveryRecord& lhs, const DeliveryRecord& rhs) {
    if (lhs.generation != rhs.generation) {
      return lhs.generation < rhs.generation;
    }
    return lhs.id.str() < rhs.id.str();
  });

  for (DeliveryRecord& record : pending) {
    if (!isPendingState(record.state)) {
      continue;
    }
    ReconcileInput input;
    input.report = session.haveReport ? &session.report : nullptr;
    input.sessionTerm = session.targetTerm;
    input.sessionIncarnation = session.targetIncarnation;
    input.desiredGeneration = record.generation;
    input.desiredDigest = record.digest;
    input.key = record.key;
    input.deployment = record.id;
    input.state = record.state;
    input.guarantee = record.effectiveGuarantee;
    input.requirement = record.requirement;
    input.artifactAvailable = true;

    const ReconcileDecision decision = reconcileDelivery(input);
    switch (decision.outcome) {
      case ReconcileOutcome::AdoptActivation: {
        const Status adopted =
            adoptActivation(record, true, "reconciliation: " + decision.reason);
        if (!adopted) {
          return adopted;
        }
        record = snapshotDelivery(record.id);
        const Status acked = acknowledge(record, true, "acknowledgement recorded from a live "
                                                       "reconcile report: " +
                                                           decision.reason);
        if (!acked) {
          return acked;
        }
        break;
      }
      case ReconcileOutcome::RetireStale: {
        const Status retired = recordRetired(
            record, "reconciliation: the target is already at generation " +
                        std::to_string(decision.targetGeneration.value()));
        if (!retired) {
          return retired;
        }
        break;
      }
      case ReconcileOutcome::ResolvePrepareWindow: {
        // An unresolved window is aborted so the target returns to a defined
        // state before this delivery is driven again.
        ApplyAbortMessage abort;
        abort.deployment = session.report.preparedDeployment;
        abort.generation = session.report.preparedGeneration.isSet()
                               ? session.report.preparedGeneration
                               : record.generation;
        abort.reason = "distributor reconciliation resolved an unresolved prepare window";
        auto encoded = encodeApplyAbort(abort);
        if (!encoded) {
          return Status::fail(encoded.error());
        }
        const std::int64_t deadline =
            monotonicMillis() + options_.policy.requestTimeoutMillis;
        CF_TRY(session.connection->send(FrameType::ApplyAbort, 0, encoded.value(), deadline));
        auto response = session.connection->receive(deadline);
        if (!response) {
          return Status::fail(response.error());
        }
        if (response.value().type() != FrameType::ApplyAbortAck) {
          return Status::fail(ErrorCode::UnexpectedMessage, "expected an apply-abort-ack");
        }
        CF_TRY_ASSIGN(const ApplyAbortAckMessage ack, decodeApplyAbortAck(response.value().payload));
        Logger::global().warn(kComponent, "resolved an unresolved prepare window on " +
                                              session.target.str() + ": " +
                                              (ack.aborted ? "aborted" : "not aborted"));
        break;
      }
      case ReconcileOutcome::FenceAuthority:
        return Status::fail(ErrorCode::FencedIncarnation, decision.reason);
      case ReconcileOutcome::UnknownAtTarget:
      case ReconcileOutcome::ResumeTransfer:
      case ReconcileOutcome::DriveNormally:
        break;
    }
  }
  return Status::ok();
}

// --- Delivery driving ------------------------------------------------------

Status Distributor::recordTransition(DeliveryRecord& record, DeliveryState target,
                                     EvidenceKind kind, ErrorCode code, std::string detail,
                                     bool fromReconciliation) {
  auto moved = applyTransition(record.state, target, "distributor");
  if (!moved) {
    return Status::fail(moved.error());
  }
  if (detail.size() > kMaxDeliveryDetailBytes) {
    detail.resize(kMaxDeliveryDetailBytes);
  }
  std::lock_guard<std::mutex> guard(stateMutex_);
  const ControllerState& state = store_->state();
  LifecycleEvent event;
  event.kind = kind;
  event.from = record.state;
  event.to = target;
  event.generation = record.generation;
  event.digest = record.digest;
  event.code = code;
  event.directive = retryDirectiveFor(code);
  event.authorityEpoch = state.epoch;
  event.authorityIncarnation = state.incarnation;
  event.targetTerm = record.targetTerm;
  event.targetIncarnation = record.targetIncarnation;
  event.fromReconciliation = fromReconciliation;
  event.atMillis = nowUnixMillis();
  event.detail = detail;

  record.state = target;
  record.updatedAtMillis = event.atMillis;
  record.authorityEpoch = state.epoch;
  record.authorityIncarnation = state.incarnation;
  record.lastError = code;
  record.lastDirective = retryDirectiveFor(code);
  record.lastDetail = detail;
  record.events.push_back(std::move(event));
  while (record.events.size() > kMaxEventsPerDelivery) {
    record.events.erase(record.events.begin());
  }
  auto encoded = encodeDeliveryRecord(record);
  if (!encoded) {
    return Status::fail(encoded.error());
  }
  return store_->commit(JournalRecordType::DeliveryUpsert, encoded.value());
}

Status Distributor::noteEvent(DeliveryRecord& record, EvidenceKind kind,
                                  std::string detail) {
  if (detail.size() > kMaxDeliveryDetailBytes) {
    detail.resize(kMaxDeliveryDetailBytes);
  }
  std::lock_guard<std::mutex> guard(stateMutex_);
  const ControllerState& state = store_->state();
  LifecycleEvent event;
  event.kind = kind;
  event.from = record.state;
  event.to = record.state;
  event.generation = record.generation;
  event.digest = record.digest;
  event.authorityEpoch = state.epoch;
  event.authorityIncarnation = state.incarnation;
  event.targetTerm = record.targetTerm;
  event.targetIncarnation = record.targetIncarnation;
  event.atMillis = nowUnixMillis();
  event.detail = detail;
  record.events.push_back(std::move(event));
  while (record.events.size() > kMaxEventsPerDelivery) {
    record.events.erase(record.events.begin());
  }
  record.updatedAtMillis = nowUnixMillis();
  auto encoded = encodeDeliveryRecord(record);
  if (!encoded) {
    return Status::fail(encoded.error());
  }
  return store_->commit(JournalRecordType::DeliveryUpsert, encoded.value());
}

Status Distributor::recordFailure(DeliveryRecord& record, ErrorCode code, std::string detail,
                                  bool fromTarget) {
  // The durable event must say what the failure means, not only what it was:
  // an indeterminate outcome and a fenced operation both require a different
  // next step from an ordinary retry, and the classification is part of the
  // error-model contract.
  if (isIndeterminateCode(code)) {
    detail.append("; the outcome at the target is unknown, so the next step is reconciliation");
  } else if (isFencingCode(code)) {
    detail.append("; the operation was fenced as stale authority, generation or replay");
  }
  if (detail.size() > kMaxDeliveryDetailBytes) {
    detail.resize(kMaxDeliveryDetailBytes);
  }
  const auto nextFailures = checkedAdd<std::uint32_t>(record.failures, 1u);
  if (!nextFailures) {
    return Status::fail(ErrorCode::ArithmeticOverflow, "delivery failure counter exhausted");
  }
  const auto nextAttempt = checkedAdd<std::uint64_t>(record.attempt.value(), 1u);
  if (!nextAttempt) {
    return Status::fail(ErrorCode::ArithmeticOverflow, "delivery attempt counter exhausted");
  }
  record.failures = *nextFailures;
  record.attempt = AttemptId::fromValue(*nextAttempt);
  record.lastError = code;
  record.lastDirective = retryDirectiveFor(code);
  record.lastDetail = detail;
  if (fromTarget) {
    record.targetTerm = record.targetTerm;
  }
  Logger::global().warn(kComponent,
                        "delivery " + record.id.str() + " attempt " +
                            std::to_string(record.attempt.value()) + " failed: " +
                            std::string(errorCodeName(code)) + " " + detail);
  if (record.state == DeliveryState::Failed) {
    // Already failed: refresh the evidence without an illegal self-transition.
    return noteEvent(record, EvidenceKind::FailureReported, detail);
  }
  return recordTransition(record, DeliveryState::Failed, EvidenceKind::FailureReported, code, detail,
                          false);
}

Status Distributor::recordRejected(DeliveryRecord& record, ErrorCode code, std::string detail) {
  if (detail.size() > kMaxDeliveryDetailBytes) {
    detail.resize(kMaxDeliveryDetailBytes);
  }
  if (record.state == DeliveryState::Rejected) {
    return noteEvent(record, EvidenceKind::Refused, detail);
  }
  const Status moved = recordTransition(record, DeliveryState::Rejected, EvidenceKind::Refused, code,
                                        detail, false);
  if (!moved) {
    return moved;
  }
  record.lastError = code;
  record.lastDetail = detail;
  return upsertDelivery(record);
}

Status Distributor::recordRetired(DeliveryRecord& record, std::string reason) {
  if (reason.size() > kMaxDeliveryDetailBytes) {
    reason.resize(kMaxDeliveryDetailBytes);
  }
  if (record.state == DeliveryState::Retired) {
    return Status::ok();
  }
  const Status moved = recordTransition(record, DeliveryState::Retired,
                                        EvidenceKind::Superseded, ErrorCode::Retired, reason, false);
  if (!moved) {
    return moved;
  }
  record.superseded = true;
  return upsertDelivery(record);
}

Status Distributor::adoptActivation(DeliveryRecord& record, bool fromReconciliation,
                                    std::string detail) {
  if (record.state != DeliveryState::Applied && record.state != DeliveryState::Acknowledged) {
    CF_TRY(recordTransition(record, DeliveryState::Applied, EvidenceKind::ActivationReported,
                            ErrorCode::Ok, std::move(detail), fromReconciliation));
  }
  // The distributor now knows what this target is running. Recording it keeps
  // every report honest; it can never move the recorded target generation
  // backwards, which is the distributor-side half of stale fencing.
  TargetRuntime runtime;
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    const TargetRuntime* existing = store_->state().findTarget(record.target);
    if (existing == nullptr) {
      return Status::ok();
    }
    runtime = *existing;
  }
  if (runtime.committedGeneration.isSet() && runtime.committedGeneration > record.generation) {
    return Status::ok();
  }
  runtime.committedGeneration = record.generation;
  runtime.committedDigest = record.digest;
  runtime.committedArtifact = record.artifact;
  runtime.lastContactMillis = nowUnixMillis();
  return upsertTarget(runtime);
}

Status Distributor::acknowledge(DeliveryRecord& record, bool fromReconciliation,
                                std::string detail) {
  if (record.state == DeliveryState::Acknowledged) {
    if (fromReconciliation && !record.acknowledgedFromReconcile) {
      record.acknowledgedFromReconcile = true;
      return upsertDelivery(record);
    }
    return Status::ok();
  }
  const Status moved = recordTransition(record, DeliveryState::Acknowledged,
                                        EvidenceKind::AcknowledgementRecorded, ErrorCode::Ok,
                                        std::move(detail), fromReconciliation);
  if (!moved) {
    return moved;
  }
  record.acknowledgedFromReconcile = fromReconciliation;
  return upsertDelivery(record);
}

Status Distributor::driveDeliveries(SessionContext& session) {
  std::vector<DeliveryRecord> work;
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    for (const auto& entry : store_->state().deliveries) {
      if (!(entry.second.target == session.target) || !isPendingState(entry.second.state)) {
        continue;
      }
      work.push_back(entry.second);
    }
  }
  std::sort(work.begin(), work.end(), [](const DeliveryRecord& lhs, const DeliveryRecord& rhs) {
    if (lhs.generation != rhs.generation) {
      return lhs.generation < rhs.generation;
    }
    return lhs.id.str() < rhs.id.str();
  });

  int consecutiveErrors = 0;
  for (const DeliveryRecord& queued : work) {
    if (stopRequested()) {
      return Status::fail(ErrorCode::Cancelled, "distributor is stopping");
    }
    const Status driven = driveDelivery(session, queued);
    if (!driven) {
      // A delivery that cannot progress must say so: silence here would look
      // exactly like a healthy session.
      Logger::global().warn(kComponent, "delivery " + queued.id.str() +
                                            " could not progress in this session: " +
                                            driven.str());
      if (driven.code() == ErrorCode::ConnectionClosed ||
          driven.code() == ErrorCode::ConnectionReset ||
          driven.code() == ErrorCode::TruncatedFrame ||
          driven.code() == ErrorCode::PeerIdleTimeout) {
        return driven;
      }
      consecutiveErrors += 1;
      if (consecutiveErrors >= kMaxSessionErrors) {
        return driven;
      }
    }
  }
  return Status::ok();
}

Status Distributor::driveDelivery(SessionContext& session, const DeliveryRecord& queued) {
  for (int step = 0; step < kMaxStepsPerDelivery; ++step) {
    if (stopRequested()) {
      return Status::fail(ErrorCode::Cancelled, "distributor is stopping");
    }
    DeliveryRecord record = snapshotDelivery(queued.id);
    if (!record.id.isSet()) {
      return Status::ok();
    }
    const std::int64_t now = nowUnixMillis();
    const DecisionInput input = decisionInputFor(record, now);
    const Decision decision = decide(options_.policy, input, epoch(), record.generation);
    switch (decision.action) {
      case PolicyAction::None:
        return Status::ok();
      case PolicyAction::Wait:
        return Status::ok();
      case PolicyAction::Reject: {
        ErrorCode code = ErrorCode::PolicyDenied;
        if (!guaranteeSatisfies(input.targetGuarantee, record.requirement)) {
          code = ErrorCode::GuaranteeUnsupported;
        } else if (!input.artifactAvailable) {
          code = ErrorCode::ArtifactUnavailable;
        }
        CF_TRY(recordRejected(record, code, decision.reason));
        Logger::global().warn(kComponent, "delivery " + record.id.str() + " rejected: " +
                                              decision.reason);
        return Status::ok();
      }
      case PolicyAction::Retire:
        CF_TRY(recordRetired(record, decision.reason));
        return Status::ok();
      case PolicyAction::GiveUp: {
        DeliveryRecord failed = record;
        if (failed.state != DeliveryState::Failed) {
          const Status moved =
              recordTransition(failed, DeliveryState::Failed, EvidenceKind::FailureReported,
                               failed.lastError, decision.reason, false);
          if (!moved) {
            return moved;
          }
          CF_TRY(upsertDelivery(failed));
        }
        Logger::global().error(kComponent, "delivery " + record.id.str() +
                                               " exhausted its retry budget: " + decision.reason);
        return Status::ok();
      }
      case PolicyAction::RecordFailureAndRetry:
        CF_TRY(recordFailure(record, record.lastError == ErrorCode::Ok ? ErrorCode::IoFailure
                                                                      : record.lastError,
                             decision.reason, false));
        return Status::ok();
      case PolicyAction::Offer:
      case PolicyAction::ResumeTransfer: {
        // A retry re-enters the pipeline at its first boundary. The lifecycle has
        // exactly one edge for that (failed -> prepared); taking it keeps every
        // later transition forward and legal instead of silently stretching the
        // table.
        if (record.state == DeliveryState::Failed) {
          CF_TRY(recordTransition(record, DeliveryState::Prepared, EvidenceKind::Retried,
                                  ErrorCode::Ok,
                                  "retry attempt " +
                                      std::to_string(record.attempt.value() + 1) +
                                      " begins; the delivery re-enters at the offer boundary",
                                  false));
        }
        CF_TRY(offerAndTransfer(session, record));
        break;
      }
      case PolicyAction::Activate:
        CF_TRY(activateDelivery(session, record));
        break;
      case PolicyAction::Reconcile:
        // Already handled at session start; if the policy asks again the
        // delivery cannot progress in this session.
        return Status::ok();
    }
  }
  return Status::ok();
}

Status Distributor::offerAndTransfer(SessionContext& session, DeliveryRecord& record) {
  FramedConnection& connection = *session.connection;
  std::uint64_t resumeFrom = 0;
  if (session.haveReport) {
    const TransferStatusRecord* status = findTransferStatus(session.report, record.id);
    if (status != nullptr && status->generation == record.generation &&
        status->digest == record.digest) {
      resumeFrom = status->bytesReceived;
    }
  }

  PrepareMessage prepare;
  prepare.deployment = record.id;
  prepare.key = record.key;
  prepare.artifact = record.artifact;
  prepare.generation = record.generation;
  prepare.digest = record.digest;
  prepare.sizeBytes = record.sizeBytes;
  prepare.schema = record.schema;
  prepare.schemaVersion = record.schemaVersion;
  prepare.requirement = record.requirement;
  prepare.guarantee = record.effectiveGuarantee;
  prepare.authorityEpoch = epoch();
  prepare.attempt = record.attempt;
  prepare.stream = deriveStreamId(record.id, record.attempt);
  prepare.chunkBytes = static_cast<std::uint32_t>(
      std::min<std::size_t>(options_.policy.transferChunkBytes, session.peerMaxPayload / 2u));
  if (prepare.chunkBytes == 0) {
    prepare.chunkBytes = 1024;
  }
  prepare.resumeFromOffset = resumeFrom;

  // A lying declaration: the artifact is shorter than the size the controller
  // claims. The target must refuse to declare the transfer complete rather than
  // accepting a short payload as if it were whole.
  const bool oversizeDeclare = options_.faults.armed(fault::kOversizeDeclare);
  if (oversizeDeclare) {
    prepare.sizeBytes = record.sizeBytes + (4u * 1024u);
    Logger::global().warn(kComponent, "fault injection: declaring " +
                                          std::to_string(prepare.sizeBytes) +
                                          " bytes for an artifact of " +
                                          std::to_string(record.sizeBytes) + " bytes");
  }

  auto encoded = encodePrepare(prepare);
  if (!encoded) {
    return Status::fail(encoded.error());
  }
  const std::int64_t deadline = monotonicMillis() + options_.policy.requestTimeoutMillis;
  CF_TRY(connection.send(FrameType::Prepare, 0, encoded.value(), deadline));
  if (record.state == DeliveryState::Prepared) {
    CF_TRY(recordTransition(record, DeliveryState::Offered, EvidenceKind::OfferedToTarget,
                            ErrorCode::Ok, "offer sent to the target", false));
  }

  auto response = connection.receive(deadline);
  if (!response) {
    return Status::fail(response.error());
  }
  switch (response.value().type()) {
    case FrameType::PrepareAck: {
      CF_TRY_ASSIGN(const PrepareAckMessage ack, decodePrepareAck(response.value().payload));
      if (!(ack.deployment == record.id) || !(ack.stream == prepare.stream)) {
        return Status::fail(ErrorCode::ProtocolViolation,
                            "the prepare acknowledgement does not describe this deployment");
      }
      if (ack.duplicateSuppressed) {
        // The target already activated this exact content and says so under the
        // current incarnation. That is evidence, and it is recorded as evidence.
        CF_TRY(adoptActivation(
            record, false,
            "the target reported this generation already active and suppressed the duplicate"));
        record = snapshotDelivery(record.id);
        CF_TRY(acknowledge(record, false,
                           "acknowledgement recorded from the target's duplicate suppression"));
        return Status::ok();
      }
      resumeFrom = ack.resumeFromOffset;
      break;
    }
    case FrameType::PrepareReject: {
      CF_TRY_ASSIGN(const PrepareRejectMessage reject, decodePrepareReject(response.value().payload));
      if (isTerminalRejection(reject.code)) {
        CF_TRY(recordRejected(record, reject.code, reject.detail));
      } else if (reject.code == ErrorCode::StaleGeneration) {
        CF_TRY(recordRetired(record, "the target refused a stale generation: " + reject.detail));
      } else if (reject.code == ErrorCode::GenerationConflict) {
        CF_TRY(recordRejected(record, reject.code,
                              "the target has different content for this generation: " +
                                  reject.detail));
      } else {
        CF_TRY(recordFailure(record, reject.code, reject.detail, true));
      }
      return Status::ok();
    }
    case FrameType::DeliveryNack: {
      CF_TRY_ASSIGN(const DeliveryNackMessage nack, decodeDeliveryNack(response.value().payload));
      CF_TRY(recordFailure(record, nack.code, nack.detail, true));
      return Status::ok();
    }
    default:
      return Status::fail(ErrorCode::UnexpectedMessage, "expected a prepare response",
                          std::string(frameTypeName(response.value().type())));
  }

  // Stream the artifact. The target's acknowledgement carries the authoritative
  // byte count, which is what makes retries and resumes safe.
  auto reader = ArtifactReader::open(*artifactStore_, record.digest);
  if (!reader) {
    CF_TRY(recordFailure(record, ErrorCode::ArtifactUnavailable, reader.error().str(), false));
    return Status::ok();
  }
  std::uint64_t offset = resumeFrom;
  if (offset != 0) {
    Logger::global().info(kComponent, "resuming the transfer for " + record.id.str() +
                                          " at byte " + std::to_string(offset));
    CF_TRY(noteEvent(record, EvidenceKind::BytesAccepted,
                     "resuming the transfer at byte " + std::to_string(offset)));
  }

  std::uint64_t sequence = offset;
  bool truncate = options_.faults.armed(fault::kTruncateTransfer);
  bool duplicate = options_.faults.armed(fault::kDuplicateChunk);
  bool reorder = options_.faults.armed(fault::kReorderChunk);
  bool corrupt = options_.faults.armed(fault::kCorruptChunk);
  const std::uint32_t dropAfter = options_.faults.countFor(fault::kAfterChunk);
  const std::uint64_t limit = truncate ? (record.sizeBytes / 2u) : record.sizeBytes;

  while (offset < limit) {
    if (stopRequested()) {
      return Status::fail(ErrorCode::Cancelled, "distributor is stopping");
    }
    auto chunk = reader.value()->readAt(offset, prepare.chunkBytes);
    if (!chunk) {
      CF_TRY(recordFailure(record, chunk.error().code(), chunk.error().str(), false));
      return Status::ok();
    }
    if (chunk.value().empty()) {
      CF_TRY(recordFailure(record, ErrorCode::IntegrityFailure,
                           "the artifact ended before its declared size", false));
      return Status::ok();
    }
    ChunkMessage message;
    message.stream = prepare.stream;
    message.sequence = Sequence::fromValue(sequence);
    message.offset = offset;
    message.data = chunk.value();
    if (corrupt && !message.data.empty()) {
      // A single flipped bit, exactly what a transport that silently corrupts
      // data would deliver. The target must refuse to activate it.
      message.data[0] = static_cast<std::uint8_t>(message.data[0] ^ 0x01u);
      corrupt = false;
    }
    auto chunkBytes = encodeChunk(message);
    if (!chunkBytes) {
      return Status::fail(chunkBytes.error());
    }
    CF_TRY(connection.send(FrameType::Chunk, 0, chunkBytes.value(), deadline));
    session.chunksSent += 1;
    if (reorder && session.chunksSent == 1u) {
      // Send the same frame twice: the target must refuse the duplicate and the
      // transfer must still converge.
      reorder = false;
      duplicate = true;
    }
    if (duplicate && session.chunksSent == 1u) {
      duplicate = false;
      CF_TRY(connection.send(FrameType::Chunk, 0, chunkBytes.value(), deadline));
    }
    if (dropAfter != 0 && session.chunksSent >= dropAfter) {
      Logger::global().warn(kComponent,
                            "fault injection: dropping the connection after " +
                                std::to_string(dropAfter) + " chunk(s)");
      connection.close();
      return Status::fail(ErrorCode::ConnectionClosed,
                          "connection dropped by fault injection");
    }

    // Read acknowledgements until the target confirms this offset. A refusal
    // (duplicate or reordered frame) is answered with the authoritative byte
    // count, from which the sender resynchronizes.
    std::uint64_t advanced = offset;
    for (;;) {
      auto ackFrame = connection.receive(deadline);
      if (!ackFrame) {
        return Status::fail(ackFrame.error());
      }
      if (ackFrame.value().type() == FrameType::DeliveryNack) {
        CF_TRY_ASSIGN(const DeliveryNackMessage nack,
                      decodeDeliveryNack(ackFrame.value().payload));
        CF_TRY(recordFailure(record, nack.code, nack.detail, true));
        return Status::ok();
      }
      if (ackFrame.value().type() != FrameType::ChunkAck) {
        return Status::fail(ErrorCode::UnexpectedMessage, "expected a chunk acknowledgement",
                            std::string(frameTypeName(ackFrame.value().type())));
      }
      CF_TRY_ASSIGN(const ChunkAckMessage ack, decodeChunkAck(ackFrame.value().payload));
      if (!(ack.stream == prepare.stream)) {
        return Status::fail(ErrorCode::ProtocolViolation,
                            "the chunk acknowledgement names a different stream");
      }
      if (ack.code == ErrorCode::ReorderedFrame) {
        advanced = ack.bytesReceived;
        break;
      }
      if (ack.code != ErrorCode::Ok) {
        CF_TRY(recordFailure(record, ack.code, ack.detail, true));
        return Status::ok();
      }
      advanced = ack.bytesReceived;
      break;
    }
    if (advanced <= offset) {
      // The target refused the chunk and reported a byte count that does not move
      // forward. Re-read from its authoritative offset rather than spinning.
      if (advanced < offset) {
        offset = advanced;
        sequence = offset;
        continue;
      }
      CF_TRY(recordFailure(record, ErrorCode::ProtocolViolation,
                           "the target did not advance its accepted byte count", true));
      return Status::ok();
    }
    offset = advanced;
    sequence = offset;
  }

  TransferCompleteMessage complete;
  complete.deployment = record.id;
  complete.stream = prepare.stream;
  complete.digest = record.digest;
  complete.sizeBytes = prepare.sizeBytes;
  auto completeBytes = encodeTransferComplete(complete);
  if (!completeBytes) {
    return Status::fail(completeBytes.error());
  }
  CF_TRY(connection.send(FrameType::TransferComplete, 0, completeBytes.value(), deadline));
  if (record.state == DeliveryState::Offered || record.state == DeliveryState::Prepared) {
    CF_TRY(recordTransition(record, DeliveryState::Transferred, EvidenceKind::BytesAccepted,
                            ErrorCode::Ok,
                            "all declared bytes were accepted by the target", false));
  }

  auto verifyFrame = connection.receive(deadline);
  if (!verifyFrame) {
    return Status::fail(verifyFrame.error());
  }
  if (verifyFrame.value().type() == FrameType::DeliveryNack) {
    CF_TRY_ASSIGN(const DeliveryNackMessage nack, decodeDeliveryNack(verifyFrame.value().payload));
    CF_TRY(recordFailure(record, nack.code, nack.detail, true));
    return Status::ok();
  }
  if (verifyFrame.value().type() != FrameType::TransferResult) {
    return Status::fail(ErrorCode::UnexpectedMessage, "expected a transfer result",
                        std::string(frameTypeName(verifyFrame.value().type())));
  }
  CF_TRY_ASSIGN(const TransferResultMessage result,
                decodeTransferResult(verifyFrame.value().payload));
  if (!result.verified) {
    CF_TRY(recordFailure(record, result.code == ErrorCode::Ok ? ErrorCode::DigestMismatch
                                                             : result.code,
                         result.detail, true));
    return Status::ok();
  }
  CF_TRY(recordTransition(record, DeliveryState::Verified, EvidenceKind::DigestVerified,
                          ErrorCode::Ok,
                          "the target recomputed the digest and it matched", false));
  return activateDelivery(session, record);
}

Status Distributor::activateDelivery(SessionContext& session, DeliveryRecord& record) {
  FramedConnection& connection = *session.connection;
  const std::int64_t deadline = monotonicMillis() + options_.policy.requestTimeoutMillis;

  if (record.state == DeliveryState::Verified) {
    StageMessage stage;
    stage.deployment = record.id;
    stage.stream = deriveStreamId(record.id, record.attempt);
    stage.generation = record.generation;
    stage.digest = record.digest;
    auto encoded = encodeStage(stage);
    if (!encoded) {
      return Status::fail(encoded.error());
    }
    CF_TRY(connection.send(FrameType::Stage, 0, encoded.value(), deadline));
    auto response = connection.receive(deadline);
    if (!response) {
      return Status::fail(response.error());
    }
    if (response.value().type() == FrameType::DeliveryNack) {
      CF_TRY_ASSIGN(const DeliveryNackMessage nack, decodeDeliveryNack(response.value().payload));
      CF_TRY(recordFailure(record, nack.code, nack.detail, true));
      return Status::ok();
    }
    if (response.value().type() != FrameType::StageAck) {
      return Status::fail(ErrorCode::UnexpectedMessage, "expected a stage acknowledgement",
                          std::string(frameTypeName(response.value().type())));
    }
    CF_TRY_ASSIGN(const StageAckMessage ack, decodeStageAck(response.value().payload));
    if (!ack.staged) {
      CF_TRY(recordFailure(record, ack.code == ErrorCode::Ok ? ErrorCode::ApplyFailed : ack.code,
                           ack.detail, true));
      return Status::ok();
    }
    CF_TRY(recordTransition(record, DeliveryState::Staged, EvidenceKind::StagedAtTarget,
                            ErrorCode::Ok, "the target holds the verified artifact staged", false));
  }

  // The stale-commit injection proves the target fences a lower generation even
  // when the controller asks for it.
  Generation commitGeneration = record.generation;
  if (options_.faults.armed(fault::kStaleCommit) && record.generation.value() > 1) {
    commitGeneration = Generation::fromValue(record.generation.value() - 1);
    Logger::global().warn(kComponent, "fault injection: sending a stale commit for generation " +
                                          std::to_string(commitGeneration.value()));
  }

  if (record.effectiveGuarantee == ApplyGuarantee::PrepareCommitAbort) {
    ApplyPrepareMessage prepareApply;
    prepareApply.deployment = record.id;
    prepareApply.generation = record.generation;
    prepareApply.digest = record.digest;
    auto encoded = encodeApplyPrepare(prepareApply);
    if (!encoded) {
      return Status::fail(encoded.error());
    }
    CF_TRY(connection.send(FrameType::ApplyPrepare, 0, encoded.value(), deadline));
    auto response = connection.receive(deadline);
    if (!response) {
      return Status::fail(response.error());
    }
    if (response.value().type() == FrameType::DeliveryNack) {
      CF_TRY_ASSIGN(const DeliveryNackMessage nack, decodeDeliveryNack(response.value().payload));
      CF_TRY(recordFailure(record, nack.code, nack.detail, true));
      return Status::ok();
    }
    if (response.value().type() != FrameType::ApplyPrepareAck) {
      return Status::fail(ErrorCode::UnexpectedMessage, "expected an apply-prepare acknowledgement",
                          std::string(frameTypeName(response.value().type())));
    }
    CF_TRY_ASSIGN(const ApplyPrepareAckMessage ack,
                  decodeApplyPrepareAck(response.value().payload));
    if (!ack.prepared) {
      CF_TRY(recordFailure(record, ack.code == ErrorCode::Ok ? ErrorCode::NotPrepared : ack.code,
                           ack.detail, true));
      return Status::ok();
    }
    // The prepare boundary is recorded so the weaker guarantee is visible in
    // every report for this target.
    CF_TRY(noteEvent(record, EvidenceKind::ApplyPrepared,
                     "target entered a prepare window; activation is not atomic for this target"));
  }

  ApplyCommitMessage commit;
  commit.deployment = record.id;
  commit.generation = commitGeneration;
  commit.digest = record.digest;
  auto encoded = encodeApplyCommit(commit);
  if (!encoded) {
    return Status::fail(encoded.error());
  }
  CF_TRY(connection.send(FrameType::ApplyCommit, 0, encoded.value(), deadline));

  auto response = connection.receive(deadline);
  if (!response) {
    return Status::fail(response.error());
  }
  if (response.value().type() == FrameType::DeliveryNack) {
    CF_TRY_ASSIGN(const DeliveryNackMessage nack, decodeDeliveryNack(response.value().payload));
    if (nack.code == ErrorCode::StaleGeneration) {
      CF_TRY(recordRetired(record, "the target fenced the commit as stale: " + nack.detail));
      return Status::ok();
    }
    CF_TRY(recordFailure(record, nack.code, nack.detail, true));
    return Status::ok();
  }
  if (response.value().type() != FrameType::ApplyCommitAck) {
    return Status::fail(ErrorCode::UnexpectedMessage, "expected an apply-commit acknowledgement",
                        std::string(frameTypeName(response.value().type())));
  }
  CF_TRY_ASSIGN(const ApplyCommitAckMessage ack, decodeApplyCommitAck(response.value().payload));
  if (!ack.committed) {
    CF_TRY(recordFailure(record, ack.code == ErrorCode::Ok ? ErrorCode::ApplyFailed : ack.code,
                         ack.detail, true));
    return Status::ok();
  }
  if (!(ack.committedGeneration == record.generation) || !(ack.committedDigest == record.digest)) {
    CF_TRY(recordFailure(record, ErrorCode::Conflict,
                         "the target committed a different generation than the one requested",
                         true));
    return Status::ok();
  }
  CF_TRY(adoptActivation(record, false,
                         "the target reported the generation active at the commit boundary"));
  record = snapshotDelivery(record.id);
  return awaitAcknowledgement(session, record);
}

Status Distributor::awaitAcknowledgement(SessionContext& session, DeliveryRecord& record) {
  if (options_.faults.armed(fault::kWithholdAck)) {
    Logger::global().warn(kComponent,
                          "fault injection: not waiting for the activation acknowledgement");
    return Status::ok();
  }
  FramedConnection& connection = *session.connection;
  const std::int64_t deadline = monotonicMillis() + options_.policy.requestTimeoutMillis;
  for (;;) {
    auto frame = connection.receive(deadline);
    if (!frame) {
      if (frame.error().code() == ErrorCode::PeerIdleTimeout ||
          frame.error().code() == ErrorCode::ConnectionClosed) {
        // The activation was reported but the acknowledgement never arrived. The
        // delivery stays Applied: losing the message loses the claim, and the
        // next reconciliation resolves it from the target.
        Logger::global().warn(kComponent,
                              "acknowledgement not received for " + record.id.str() +
                                  "; the delivery remains applied and awaits reconciliation");
        return Status::ok();
      }
      return Status::fail(frame.error());
    }
    if (frame.value().type() == FrameType::DeliveryAck) {
      CF_TRY_ASSIGN(const DeliveryAckMessage ack, decodeDeliveryAck(frame.value().payload));
      if (!(ack.deployment == record.id) || !(ack.generation == record.generation) ||
          !(ack.digest == record.digest)) {
        return Status::fail(ErrorCode::ProtocolViolation,
                            "the acknowledgement does not describe this deployment");
      }
      if (!(ack.term == session.targetTerm) || !(ack.incarnation == session.targetIncarnation)) {
        return Status::fail(ErrorCode::FencedIncarnation,
                            "the acknowledgement carries target authority that is not current");
      }
      CF_TRY(adoptActivation(record, ack.evidenceFromReconcile,
                             "the target reported the activation boundary under current authority"));
      record = snapshotDelivery(record.id);
      CF_TRY(acknowledge(record, ack.evidenceFromReconcile,
                         "the activation acknowledgement was durably recorded under epoch " +
                             std::to_string(epoch().value())));
      Logger::global().info(kComponent, "delivery " + record.id.str() + " acknowledged: " +
                                            record.key.str() + " generation " +
                                            std::to_string(record.generation.value()) + " on " +
                                            record.target.str());
      return Status::ok();
    }
    if (frame.value().type() == FrameType::DeliveryNack) {
      CF_TRY_ASSIGN(const DeliveryNackMessage nack, decodeDeliveryNack(frame.value().payload));
      CF_TRY(recordFailure(record, nack.code, nack.detail, true));
      return Status::ok();
    }
    if (frame.value().type() == FrameType::Ping) {
      CF_TRY_ASSIGN(const PingMessage ping, decodePing(frame.value().payload));
      PongMessage pong;
      pong.nonce = ping.nonce;
      auto encoded = encodePong(pong);
      if (!encoded) {
        return Status::fail(encoded.error());
      }
      CF_TRY(connection.send(FrameType::Pong, kFrameFlagResponse, encoded.value(), deadline));
      continue;
    }
    return Status::fail(ErrorCode::UnexpectedMessage,
                        "unexpected message while awaiting an acknowledgement",
                        std::string(frameTypeName(frame.value().type())));
  }
}

// --- Control surface -------------------------------------------------------

Result<std::vector<TargetResolution>> Distributor::resolveDeploymentSet(
    const DeploymentPlan& plan) const {
  std::vector<TargetResolution> resolutions;
  resolutions.reserve(plan.instructions.size());
  std::set<std::string> seen;
  for (const DeploymentInstruction& instruction : plan.instructions) {
    TargetResolution resolution;
    resolution.target = instruction.target;
    resolution.configKey = instruction.configKey;
    if (!seen.insert(instruction.target.str()).second) {
      resolution.accepted = false;
      resolution.reason = "the deployment set names the same target more than once";
    } else if (!instruction.endpoint.empty()) {
      auto endpoint = parseEndpoint(instruction.endpoint);
      if (!endpoint) {
        resolution.accepted = false;
        resolution.reason = "the instruction endpoint is not a valid host:port pair";
      } else {
        resolution.accepted = true;
        resolution.reason = "explicitly selected by the deployment set; endpoint " +
                            endpoint.value().str();
      }
    } else {
      resolution.accepted = true;
      resolution.reason = "explicitly selected by the deployment set; no endpoint supplied";
    }
    resolutions.push_back(std::move(resolution));
  }
  if (resolutions.size() > options_.policy.maxTargets) {
    for (TargetResolution& resolution : resolutions) {
      resolution.accepted = false;
      resolution.reason = "the deployment set exceeds the configured target budget";
    }
  }
  return Result<std::vector<TargetResolution>>::ok(std::move(resolutions));
}

Status Distributor::ingestArtifact(const std::string& path, const ArtifactMetadata& declared) {
  CF_TRY(artifactStore_->ingestFromFile(path, declared));
  std::lock_guard<std::mutex> guard(stateMutex_);
  auto encoded = encodeArtifactMetadata(declared);
  if (!encoded) {
    return Status::fail(encoded.error());
  }
  ByteWriter writer(encoded.value().size() + 8);
  writer.string(std::string_view(reinterpret_cast<const char*>(encoded.value().data()),
                                 encoded.value().size()),
                kAbsoluteMaxFieldBytes);
  return store_->commit(JournalRecordType::ArtifactUpsert, writer.span());
}

Status Distributor::submitPlan(const DeploymentPlan& plan, std::vector<DeploymentId>* created) {
  auto resolutions = resolveDeploymentSet(plan);
  if (!resolutions) {
    return Status::fail(resolutions.error());
  }
  std::size_t accepted = 0;
  for (const TargetResolution& resolution : resolutions.value()) {
    if (resolution.accepted) {
      accepted += 1;
    }
  }
  if (accepted == 0) {
    return Status::fail(ErrorCode::InvalidArgument,
                        "the deployment set selects no usable target");
  }

  for (std::size_t index = 0; index < plan.instructions.size(); ++index) {
    const DeploymentInstruction& instruction = plan.instructions[index];
    const TargetResolution& resolution = resolutions.value()[index];

    // The artifact must be present before a delivery can be created; a source
    // path is upstream's way of handing over the bytes exactly once.
    if (!instruction.sourcePath.empty() && !artifactStore_->contains(instruction.digest)) {
      ArtifactMetadata declared;
      declared.id = instruction.artifact;
      declared.revision = instruction.revision;
      declared.schema = instruction.schema;
      declared.schemaVersion = instruction.schemaVersion;
      declared.digest = instruction.digest;
      declared.sizeBytes = instruction.sizeBytes;
      declared.mediaType = instruction.mediaType;
      declared.producer = instruction.producer;
      declared.producedAtMillis = nowUnixMillis();
      declared.storedAtMillis = nowUnixMillis();
      const Status ingested = ingestArtifact(instruction.sourcePath, declared);
      if (!ingested) {
        Logger::global().warn(kComponent, "cannot ingest the artifact for " +
                                              instruction.target.str() + ": " + ingested.str());
      }
    }

    DeliveryRecord record;
    record.id = deriveDeploymentId(instruction.target, instruction.configKey,
                                   instruction.generation, instruction.digest);
    record.setId = plan.setId;
    record.rolloutSet = plan.rolloutSet;
    record.target = instruction.target;
    record.key = instruction.configKey;
    record.artifact = instruction.artifact;
    record.revision = instruction.revision;
    record.generation = instruction.generation;
    record.digest = instruction.digest;
    record.schema = instruction.schema;
    record.schemaVersion = instruction.schemaVersion;
    record.sizeBytes = instruction.sizeBytes;
    record.requirement = instruction.requirement;
    record.effectiveGuarantee = instruction.declaredGuarantee;
    record.state = DeliveryState::Prepared;
    record.createdAtMillis = nowUnixMillis();
    record.updatedAtMillis = record.createdAtMillis;

    {
      std::lock_guard<std::mutex> guard(stateMutex_);
      const ControllerState& state = store_->state();
      const DeliveryRecord* existing = state.findDelivery(record.id);
      if (existing != nullptr && existing->state == DeliveryState::Acknowledged) {
        // Re-submitting an identical instruction is a no-op: the fabric already
        // proved this generation is active on this target.
        continue;
      }
      if (existing != nullptr) {
        record.attempt = existing->attempt;
        record.failures = existing->failures;
        record.events = existing->events;
        record.authorityEpoch = existing->authorityEpoch;
        record.authorityIncarnation = existing->authorityIncarnation;
        record.targetTerm = existing->targetTerm;
        record.targetIncarnation = existing->targetIncarnation;
        if (isPendingState(existing->state)) {
          record.state = existing->state;
        }
      }
    }

    // Everything older on this lineage is superseded, and history is bounded.
    {
      std::vector<DeliveryRecord> superseded;
      {
        std::lock_guard<std::mutex> guard(stateMutex_);
        for (const auto& entry : store_->state().deliveries) {
          const DeliveryRecord& other = entry.second;
          if (other.id.str() == record.id.str()) {
            continue;
          }
          if (other.target == record.target && other.key == record.key &&
              other.generation < record.generation && isPendingState(other.state)) {
            superseded.push_back(other);
          }
        }
      }
      for (DeliveryRecord& other : superseded) {
        CF_TRY(recordRetired(other, "superseded by generation " +
                                        std::to_string(record.generation.value())));
      }
    }

    // Bounded history: only the newest records per lineage are retained.
    {
      std::vector<DeliveryRecord> doomed;
      {
        std::lock_guard<std::mutex> guard(stateMutex_);
        std::map<std::string, std::vector<DeliveryRecord>> byLineage;
        for (const auto& entry : store_->state().deliveries) {
          const DeliveryRecord& other = entry.second;
          if (other.target == record.target && other.key == record.key) {
            byLineage[other.key.str()].push_back(other);
          }
        }
        for (auto& lineage : byLineage) {
          std::vector<DeliveryRecord>& history = lineage.second;
          std::sort(history.begin(), history.end(),
                    [](const DeliveryRecord& lhs, const DeliveryRecord& rhs) {
                      if (lhs.generation != rhs.generation) {
                        return lhs.generation > rhs.generation;
                      }
                      return lhs.id.str() > rhs.id.str();
                    });
          for (std::size_t i = options_.policy.maxHistoryPerLineage; i < history.size(); ++i) {
            doomed.push_back(history[i]);
          }
        }
      }
      for (const DeliveryRecord& stale : doomed) {
        std::lock_guard<std::mutex> guard(stateMutex_);
        ByteWriter writer(128);
        writer.string(stale.id.str(), kMaxIdentifierLength);
        CF_TRY(store_->commit(JournalRecordType::DeliveryRemove, writer.span()));
      }
    }

    // The target record carries the endpoint and the declared guarantee.
    {
      TargetRuntime runtime;
      {
        std::lock_guard<std::mutex> guard(stateMutex_);
        const TargetRuntime* existing = store_->state().findTarget(instruction.target);
        if (existing != nullptr) {
          runtime = *existing;
        }
      }
      runtime.id = instruction.target;
      if (runtime.klass == TargetClass::Unspecified) {
        runtime.klass = resolution.accepted ? instruction.targetClass : TargetClass::Unspecified;
      }
      if (!instruction.endpoint.empty()) {
        runtime.endpoint = instruction.endpoint;
      }
      if (!runtime.term.isSet()) {
        runtime.guarantee = instruction.declaredGuarantee;
      }
      CF_TRY(upsertTarget(runtime));
    }

    CF_TRY(upsertDelivery(record));
    if (created != nullptr) {
      created->push_back(record.id);
    }
    Logger::global().info(kComponent, "planned delivery " + record.id.str() + " for " +
                                          record.target.str() + " generation " +
                                          std::to_string(record.generation.value()));
  }

  // Bounded live delivery set.
  {
    std::lock_guard<std::mutex> guard(stateMutex_);
    std::size_t live = 0;
    for (const auto& entry : store_->state().deliveries) {
      if (isPendingState(entry.second.state)) {
        live += 1;
      }
    }
    if (live > options_.policy.maxLiveDeliveries) {
      return Status::fail(ErrorCode::LimitExceeded,
                          "the live delivery count exceeds the configured budget",
                          std::to_string(live));
    }
  }
  CF_TRY(store_->compactIfNeeded());
  return Status::ok();
}

Status Distributor::retireDeployment(const DeploymentId& deployment, std::string reason) {
  DeliveryRecord record = snapshotDelivery(deployment);
  if (!record.id.isSet()) {
    return Status::fail(ErrorCode::NotFound, "no such delivery", deployment.str());
  }
  return recordRetired(record, std::move(reason));
}

Result<ConvergenceReport> Distributor::convergence() const {
  std::lock_guard<std::mutex> guard(stateMutex_);
  return Result<ConvergenceReport>::ok(
      buildConvergenceReport(store_->state(), options_.policy, nowUnixMillis()));
}

Result<std::string> Distributor::explain(const TargetId& target) const {
  std::lock_guard<std::mutex> guard(stateMutex_);
  return Result<std::string>::ok(
      explainTarget(store_->state(), options_.policy, target, nowUnixMillis()));
}

Result<std::vector<DeliveryRecord>> Distributor::deliveries() const {
  std::lock_guard<std::mutex> guard(stateMutex_);
  std::vector<DeliveryRecord> records;
  records.reserve(store_->state().deliveries.size());
  for (const auto& entry : store_->state().deliveries) {
    records.push_back(entry.second);
  }
  return Result<std::vector<DeliveryRecord>>::ok(std::move(records));
}

Result<std::vector<TargetRuntime>> Distributor::targets() const {
  std::lock_guard<std::mutex> guard(stateMutex_);
  std::vector<TargetRuntime> runtimes;
  runtimes.reserve(store_->state().targets.size());
  for (const auto& entry : store_->state().targets) {
    runtimes.push_back(entry.second);
  }
  return Result<std::vector<TargetRuntime>>::ok(std::move(runtimes));
}

Result<std::vector<ArtifactMetadata>> Distributor::artifacts() const {
  return artifactStore_->list();
}

Result<std::string> Distributor::statusText() const {
  // Artifact counts are read before the state lock is taken so that the two
  // mutexes are never nested: the state lock is the only outer lock in this
  // class, and keeping it that way is what makes the lock order auditable.
  const std::size_t artifactCount = artifactStore_->artifactCount();
  const std::uint64_t artifactBytes = artifactStore_->usedBytes();

  std::lock_guard<std::mutex> guard(stateMutex_);
  const ControllerState& state = store_->state();
  std::string out;
  out.reserve(512);
  out.append("node-id: ");
  out.append(state.nodeId.str());
  out.push_back('\n');
  out.append("authority-epoch: ");
  out.append(std::to_string(state.epoch.value()));
  out.push_back('\n');
  out.append("incarnation: ");
  out.append(state.incarnation.hex());
  out.push_back('\n');
  out.append("authenticated-peer-identity: ");
  out.append(options_.authenticate ? "required" : "DISABLED (degraded guarantee)");
  out.push_back('\n');
  out.append("control-endpoint: ");
  out.append(options_.controlHost);
  out.push_back(':');
  out.append(std::to_string(controlPort_));
  out.push_back('\n');
  out.append("targets: ");
  out.append(std::to_string(state.targets.size()));
  out.push_back('\n');
  out.append("deliveries: ");
  out.append(std::to_string(state.deliveries.size()));
  out.push_back('\n');
  out.append("artifacts: ");
  out.append(std::to_string(artifactCount));
  out.append(" (");
  out.append(std::to_string(artifactBytes));
  out.append(" bytes)\n");
  out.append("durable-journal-bytes: ");
  out.append(std::to_string(store_->journalBytes()));
  out.push_back('\n');
  out.append(options_.policy.render());
  return Result<std::string>::ok(std::move(out));
}

Status Distributor::handleControlConnection(Socket socket) {
  return serveControlConnection(*this, std::move(socket), options_.key);
}

}  // namespace cf
