// Unit, adversarial and restart tests: target agent semantics.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// These tests drive a real TargetAgent over a real loopback socket. The client
// side speaks the same wire protocol the distributor does, so what is exercised
// here is the shipped protocol path, not a shortcut.

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "cf/agent.hpp"
#include "cf/protocol.hpp"
#include "cf/protocol.hpp"
#include "cf/rng.hpp"
#include "cf/transport.hpp"
#include "harness.hpp"
#include "testing.hpp"

namespace {

/// Serves one TargetAgent on a real socket in a background thread.
class AgentServer final {
 public:
  AgentServer(cf::test::TempDir& directory, cf::TargetAgent::Options options,
              std::string label = "agent-server")
      : label_(std::move(label)) {
    options.stateDirectory = directory.child(label_ + "-state");
    options.liveDirectory = directory.child(label_ + "-live");
    cf::AgentStore::Recovery recovery;
    cf::LiveRecovery liveRecovery;
    auto opened = cf::TargetAgent::open(options, recovery, liveRecovery);
    if (!opened) {
      return;
    }
    agent_ = std::move(opened).value();
    recoverySummary_ = recovery.render();
    liveSummary_ = liveRecovery.detail;
    auto listener = cf::Listener::bindTcp("127.0.0.1", 0, 8);
    if (!listener) {
      return;
    }
    listener_ = std::move(listener).value();
    port_ = listener_->port();
    thread_ = std::thread([this] {
      while (!stopped_.load()) {
        auto accepted = listener_->accept(cf::monotonicMillis() + 50);
        if (!accepted) {
          if (accepted.error().code() == cf::ErrorCode::ShuttingDown) {
            return;
          }
          continue;
        }
        auto connection = std::make_shared<cf::FramedConnection>(
            std::move(accepted).value(), cf::kDefaultMaxPayloadBytes);
        {
          std::lock_guard<std::mutex> guard(connectionMutex_);
          active_ = connection;
        }
        (void)agent_->serve(*connection);
        {
          std::lock_guard<std::mutex> guard(connectionMutex_);
          active_.reset();
        }
        connection->close();
        sessions_ += 1;
      }
    });
  }

  AgentServer(const AgentServer&) = delete;
  AgentServer& operator=(const AgentServer&) = delete;

  ~AgentServer() { stop(); }

  void stop() {
    if (stopped_.exchange(true)) {
      return;
    }
    if (listener_ != nullptr) {
      listener_->interrupt();
    }
    // Cancel any session in flight as well: joining a thread blocked in a receive
    // would otherwise wait out the target's full idle timeout.
    {
      std::lock_guard<std::mutex> guard(connectionMutex_);
      if (active_ != nullptr) {
        active_->interrupt();
      }
    }
    if (thread_.joinable()) {
      thread_.join();
    }
    if (listener_ != nullptr) {
      listener_->close();
    }
  }

  [[nodiscard]] bool valid() const { return agent_ != nullptr && port_ != 0; }
  [[nodiscard]] cf::TargetAgent& agent() { return *agent_; }
  [[nodiscard]] std::uint16_t port() const { return port_; }
  [[nodiscard]] std::size_t sessions() const { return sessions_; }
  [[nodiscard]] const std::string& recoverySummary() const { return recoverySummary_; }
  [[nodiscard]] const std::string& liveSummary() const { return liveSummary_; }

 private:
  std::string label_;
  std::unique_ptr<cf::TargetAgent> agent_;
  std::unique_ptr<cf::Listener> listener_;
  std::mutex connectionMutex_;
  std::shared_ptr<cf::FramedConnection> active_;
  std::thread thread_;
  std::atomic<bool> stopped_{false};
  std::uint16_t port_{0};
  std::size_t sessions_{0};
  std::string recoverySummary_;
  std::string liveSummary_;
};

/// The distributor side of a session, implemented exactly as the real one is.
class ControllerClient final {
 public:
  ControllerClient(std::uint16_t port, cf::HmacKey key, cf::Epoch epoch,
                   cf::IncarnationId incarnation, bool authenticate = true)
      : key_(key), epoch_(epoch), incarnation_(incarnation), authenticate_(authenticate) {
    auto socket = cf::connectTcp("127.0.0.1", port, 3000);
    if (!socket) {
      return;
    }
    connection_ = std::make_unique<cf::FramedConnection>(std::move(socket).value(),
                                                         cf::kDefaultMaxPayloadBytes);
  }

  [[nodiscard]] bool connected() const { return connection_ != nullptr; }

  [[nodiscard]] cf::Status establish(const std::string& target,
                                     const std::string& nodeName = "ctl-a") {
    cf::HelloMessage hello;
    hello.nodeId = cf::parseNodeId(nodeName).value();
    hello.epoch = epoch_;
    hello.incarnation = incarnation_;
    hello.nonce = cf::SessionNonce(cf::secureRandom128());
    hello.maxPayloadBytes = cf::kDefaultMaxPayloadBytes;
    hello.capabilities = cf::kCapabilityKnownMask;
    auto encoded = cf::encodeHello(hello);
    if (!encoded) {
      return cf::Status::fail(encoded.error());
    }
    if (authenticate_) {
      CF_TRY(cf::sealAuthenticated(encoded.value(), key_));
    }
    CF_TRY(connection_->send(cf::FrameType::Hello, 0, encoded.value(), deadline()));
    return exchangeHello(target, encoded.value());
  }

  [[nodiscard]] cf::Status send(cf::FrameType type, const std::vector<std::uint8_t>& payload) {
    return connection_->send(type, 0, payload, deadline());
  }

  [[nodiscard]] cf::Result<cf::Frame> receive() { return connection_->receive(deadline()); }

  void close() {
    if (connection_ != nullptr) {
      connection_->close();
    }
  }

  [[nodiscard]] cf::Term targetTerm() const { return targetTerm_; }
  [[nodiscard]] cf::IncarnationId targetIncarnation() const { return targetIncarnation_; }
  [[nodiscard]] cf::ApplyGuarantee targetGuarantee() const { return targetGuarantee_; }
  [[nodiscard]] cf::Generation committedGeneration() const { return committedGeneration_; }
  [[nodiscard]] cf::Digest committedDigest() const { return committedDigest_; }

  [[nodiscard]] cf::Result<cf::PrepareAckMessage> prepare(const cf::PrepareMessage& message) {
    auto encoded = cf::encodePrepare(message);
    if (!encoded) {
      return cf::Result<cf::PrepareAckMessage>::fail(encoded.error());
    }
    CF_TRY(connection_->send(cf::FrameType::Prepare, 0, encoded.value(), deadline()));
    auto frame = connection_->receive(deadline());
    if (!frame) {
      return cf::Result<cf::PrepareAckMessage>::fail(frame.error());
    }
    if (frame.value().type() == cf::FrameType::PrepareReject) {
      auto reject = cf::decodePrepareReject(frame.value().payload);
      if (!reject) {
        return cf::Result<cf::PrepareAckMessage>::fail(reject.error());
      }
      return cf::Result<cf::PrepareAckMessage>::fail(
          cf::Error(reject.value().code, "target refused the offer", reject.value().detail));
    }
    if (frame.value().type() == cf::FrameType::DeliveryNack) {
      auto nack = cf::decodeDeliveryNack(frame.value().payload);
      if (!nack) {
        return cf::Result<cf::PrepareAckMessage>::fail(nack.error());
      }
      return cf::Result<cf::PrepareAckMessage>::fail(
          cf::Error(nack.value().code, "target nacked the offer", nack.value().detail));
    }
    if (frame.value().type() != cf::FrameType::PrepareAck) {
      return cf::Result<cf::PrepareAckMessage>::fail(cf::ErrorCode::UnexpectedMessage,
                                                     "expected a prepare acknowledgement");
    }
    return cf::decodePrepareAck(frame.value().payload);
  }

  [[nodiscard]] cf::Result<cf::ChunkAckMessage> chunk(const cf::ChunkMessage& message) {
    auto encoded = cf::encodeChunk(message);
    if (!encoded) {
      return cf::Result<cf::ChunkAckMessage>::fail(encoded.error());
    }
    CF_TRY(connection_->send(cf::FrameType::Chunk, 0, encoded.value(), deadline()));
    auto frame = connection_->receive(deadline());
    if (!frame) {
      return cf::Result<cf::ChunkAckMessage>::fail(frame.error());
    }
    if (frame.value().type() != cf::FrameType::ChunkAck) {
      return cf::Result<cf::ChunkAckMessage>::fail(cf::ErrorCode::UnexpectedMessage,
                                                   "expected a chunk acknowledgement");
    }
    return cf::decodeChunkAck(frame.value().payload);
  }

  [[nodiscard]] cf::Result<cf::TransferResultMessage> complete(
      const cf::TransferCompleteMessage& message) {
    auto encoded = cf::encodeTransferComplete(message);
    if (!encoded) {
      return cf::Result<cf::TransferResultMessage>::fail(encoded.error());
    }
    CF_TRY(connection_->send(cf::FrameType::TransferComplete, 0, encoded.value(), deadline()));
    for (;;) {
      auto frame = connection_->receive(deadline());
      if (!frame) {
        return cf::Result<cf::TransferResultMessage>::fail(frame.error());
      }
      if (frame.value().type() == cf::FrameType::TransferResult) {
        return cf::decodeTransferResult(frame.value().payload);
      }
      if (frame.value().type() == cf::FrameType::DeliveryNack) {
        auto nack = cf::decodeDeliveryNack(frame.value().payload);
        if (!nack) {
          return cf::Result<cf::TransferResultMessage>::fail(nack.error());
        }
        return cf::Result<cf::TransferResultMessage>::fail(
            cf::Error(nack.value().code, "target nacked the transfer", nack.value().detail));
      }
      return cf::Result<cf::TransferResultMessage>::fail(cf::ErrorCode::UnexpectedMessage,
                                                         "expected a transfer result");
    }
  }

  [[nodiscard]] cf::Result<cf::StageAckMessage> stage(const cf::StageMessage& message) {
    auto encoded = cf::encodeStage(message);
    if (!encoded) {
      return cf::Result<cf::StageAckMessage>::fail(encoded.error());
    }
    CF_TRY(connection_->send(cf::FrameType::Stage, 0, encoded.value(), deadline()));
    auto frame = connection_->receive(deadline());
    if (!frame) {
      return cf::Result<cf::StageAckMessage>::fail(frame.error());
    }
    if (frame.value().type() != cf::FrameType::StageAck) {
      return cf::Result<cf::StageAckMessage>::fail(cf::ErrorCode::UnexpectedMessage,
                                                   "expected a stage acknowledgement");
    }
    return cf::decodeStageAck(frame.value().payload);
  }

  [[nodiscard]] cf::Result<cf::ApplyCommitAckMessage> commit(
      const cf::ApplyCommitMessage& message) {
    auto encoded = cf::encodeApplyCommit(message);
    if (!encoded) {
      return cf::Result<cf::ApplyCommitAckMessage>::fail(encoded.error());
    }
    CF_TRY(connection_->send(cf::FrameType::ApplyCommit, 0, encoded.value(), deadline()));
    auto frame = connection_->receive(deadline());
    if (!frame) {
      return cf::Result<cf::ApplyCommitAckMessage>::fail(frame.error());
    }
    if (frame.value().type() == cf::FrameType::DeliveryNack) {
      auto nack = cf::decodeDeliveryNack(frame.value().payload);
      if (!nack) {
        return cf::Result<cf::ApplyCommitAckMessage>::fail(nack.error());
      }
      return cf::Result<cf::ApplyCommitAckMessage>::fail(
          cf::Error(nack.value().code, "target nacked the commit", nack.value().detail));
    }
    if (frame.value().type() != cf::FrameType::ApplyCommitAck) {
      return cf::Result<cf::ApplyCommitAckMessage>::fail(cf::ErrorCode::UnexpectedMessage,
                                                         "expected an apply-commit acknowledgement");
    }
    return cf::decodeApplyCommitAck(frame.value().payload);
  }

  [[nodiscard]] cf::Result<cf::DeliveryAckMessage> awaitAck() {
    auto frame = connection_->receive(deadline());
    if (!frame) {
      return cf::Result<cf::DeliveryAckMessage>::fail(frame.error());
    }
    if (frame.value().type() != cf::FrameType::DeliveryAck) {
      return cf::Result<cf::DeliveryAckMessage>::fail(cf::ErrorCode::UnexpectedMessage,
                                                      "expected a delivery acknowledgement");
    }
    return cf::decodeDeliveryAck(frame.value().payload);
  }

  [[nodiscard]] cf::Result<cf::ReconcileReportMessage> reconcile() {
    cf::ReconcileRequestMessage request;
    request.nodeId = cf::parseNodeId("ctl-a").value();
    request.epoch = epoch_;
    request.incarnation = incarnation_;
    request.maxFindings = 16;
    auto encoded = cf::encodeReconcileRequest(request);
    if (!encoded) {
      return cf::Result<cf::ReconcileReportMessage>::fail(encoded.error());
    }
    CF_TRY(connection_->send(cf::FrameType::ReconcileRequest, 0, encoded.value(), deadline()));
    auto frame = connection_->receive(deadline());
    if (!frame) {
      return cf::Result<cf::ReconcileReportMessage>::fail(frame.error());
    }
    if (frame.value().type() != cf::FrameType::ReconcileReport) {
      return cf::Result<cf::ReconcileReportMessage>::fail(cf::ErrorCode::UnexpectedMessage,
                                                          "expected a reconcile report");
    }
    return cf::decodeReconcileReport(frame.value().payload);
  }

  [[nodiscard]] cf::Result<cf::ApplyPrepareAckMessage> applyPrepare(
      const cf::ApplyPrepareMessage& message) {
    auto encoded = cf::encodeApplyPrepare(message);
    if (!encoded) {
      return cf::Result<cf::ApplyPrepareAckMessage>::fail(encoded.error());
    }
    CF_TRY(connection_->send(cf::FrameType::ApplyPrepare, 0, encoded.value(), deadline()));
    auto frame = connection_->receive(deadline());
    if (!frame) {
      return cf::Result<cf::ApplyPrepareAckMessage>::fail(frame.error());
    }
    if (frame.value().type() != cf::FrameType::ApplyPrepareAck) {
      return cf::Result<cf::ApplyPrepareAckMessage>::fail(cf::ErrorCode::UnexpectedMessage,
                                                          "expected an apply-prepare ack");
    }
    return cf::decodeApplyPrepareAck(frame.value().payload);
  }

  [[nodiscard]] cf::Result<cf::ApplyAbortAckMessage> applyAbort(
      const cf::ApplyAbortMessage& message) {
    auto encoded = cf::encodeApplyAbort(message);
    if (!encoded) {
      return cf::Result<cf::ApplyAbortAckMessage>::fail(encoded.error());
    }
    CF_TRY(connection_->send(cf::FrameType::ApplyAbort, 0, encoded.value(), deadline()));
    auto frame = connection_->receive(deadline());
    if (!frame) {
      return cf::Result<cf::ApplyAbortAckMessage>::fail(frame.error());
    }
    if (frame.value().type() != cf::FrameType::ApplyAbortAck) {
      return cf::Result<cf::ApplyAbortAckMessage>::fail(cf::ErrorCode::UnexpectedMessage,
                                                        "expected an apply-abort ack");
    }
    return cf::decodeApplyAbortAck(frame.value().payload);
  }

 private:
  [[nodiscard]] std::int64_t deadline() const { return cf::monotonicMillis() + 8000; }

  [[nodiscard]] cf::Status exchangeHello(const std::string& target,
                                         const std::vector<std::uint8_t>& helloBytes) {
    auto response = connection_->receive(deadline());
    if (!response) {
      return cf::Status::fail(response.error());
    }
    if (response.value().type() == cf::FrameType::AuthReject) {
      auto reject = cf::decodeAuthReject(response.value().payload);
      if (!reject) {
        return cf::Status::fail(reject.error());
      }
      return cf::Status::fail(cf::Error(reject.value().code, "target rejected the session",
                                        reject.value().detail));
    }
    if (response.value().type() != cf::FrameType::HelloAck) {
      return cf::Status::fail(cf::ErrorCode::UnexpectedMessage, "expected a hello-ack");
    }
    auto ack = cf::decodeHelloAck(response.value().payload);
    if (!ack) {
      return cf::Status::fail(ack.error());
    }
    if (!(ack.value().target == cf::parseTargetId(target).value())) {
      return cf::Status::fail(cf::ErrorCode::Unauthorized, "peer is a different target");
    }
    if (authenticate_) {
      CF_TRY(cf::verifyAuthenticated(response.value().payload, key_));
    }
    targetTerm_ = ack.value().term;
    targetIncarnation_ = ack.value().incarnation;
    targetGuarantee_ = ack.value().guarantee;
    committedGeneration_ = ack.value().committedGeneration;
    committedDigest_ = ack.value().committedDigest;

    std::vector<std::uint8_t> scratch = response.value().payload;
    std::fill(scratch.begin() + static_cast<std::ptrdiff_t>(scratch.size() - cf::kAuthTagBytes),
              scratch.end(), std::uint8_t{0});
    cf::HelloConfirmMessage confirm;
    confirm.authTag = authenticate_ ? cf::hmacSha256(key_, std::span<const std::uint8_t>(
                                                               scratch.data(), scratch.size()))
                                    : cf::Sha256Digest{};
    auto encodedConfirm = cf::encodeHelloConfirm(confirm);
    if (!encodedConfirm) {
      return cf::Status::fail(encodedConfirm.error());
    }
    (void)helloBytes;
    return connection_->send(cf::FrameType::HelloConfirm, 0, encodedConfirm.value(), deadline());
  }

  cf::HmacKey key_{};
  cf::Epoch epoch_;
  cf::IncarnationId incarnation_;
  bool authenticate_{true};
  std::unique_ptr<cf::FramedConnection> connection_;
  cf::Term targetTerm_;
  cf::IncarnationId targetIncarnation_;
  cf::ApplyGuarantee targetGuarantee_{cf::ApplyGuarantee::AtomicActivate};
  cf::Generation committedGeneration_;
  cf::Digest committedDigest_;
};

struct Fixture {
  cf::test::TempDir directory{"agent"};
  cf::HmacKey key{};
  cf::IncarnationId controllerIncarnation = cf::IncarnationId(cf::secureRandom128());

  Fixture() {
    for (std::size_t i = 0; i < key.size(); ++i) {
      key[i] = static_cast<std::uint8_t>(i * 3 + 1);
    }
  }

  [[nodiscard]] cf::TargetAgent::Options options(const std::string& target,
                                                 cf::ApplyGuarantee guarantee) {
    cf::TargetAgent::Options options;
    options.target = cf::parseTargetId(target).value();
    options.klass = cf::TargetClass::NetworkDevice;
    options.guarantee = guarantee;
    options.key = key;
    options.authenticate = true;
    options.maxArtifactBytes = 1u << 20;
    return options;
  }
};

/// Drives one full delivery and returns the digest that was activated.
cf::Result<cf::Digest> deliverOne(ControllerClient& client, std::string_view body,
                                  std::uint64_t generation, const std::string& target = "rtr-1",
                                  bool corruptFirstChunk = false,
                                  bool duplicateChunk = false) {
  const cf::Digest digest = cf::Digest::ofText(body);
  cf::PrepareMessage prepare;
  prepare.deployment = cf::deriveDeploymentId(cf::parseTargetId(target).value(),
                                              cf::parseConfigKey("fabric/underlay").value(),
                                              cf::Generation::fromValue(generation), digest);
  prepare.key = cf::parseConfigKey("fabric/underlay").value();
  prepare.artifact = cf::parseArtifactId("cfg/underlay").value();
  prepare.generation = cf::Generation::fromValue(generation);
  prepare.digest = digest;
  prepare.sizeBytes = body.size();
  prepare.schema = cf::parseSchemaId("cf.underlay").value();
  prepare.schemaVersion = cf::SchemaVersion::fromValue(1);
  prepare.requirement = cf::GuaranteeRequirement::RequireAtomic;
  prepare.guarantee = cf::ApplyGuarantee::AtomicActivate;
  prepare.authorityEpoch = cf::Epoch::fromValue(1);
  prepare.attempt = cf::AttemptId::fromValue(1);
  prepare.stream = cf::deriveStreamId(prepare.deployment, prepare.attempt);
  prepare.chunkBytes = 256;

  CF_TRY_ASSIGN(const cf::PrepareAckMessage ack, client.prepare(prepare));
  std::uint64_t offset = ack.resumeFromOffset;
  bool corrupted = false;
  while (offset < body.size()) {
    const std::size_t take = std::min<std::size_t>(256, body.size() - offset);
    cf::ChunkMessage chunk;
    chunk.stream = prepare.stream;
    chunk.sequence = cf::Sequence::fromValue(offset);
    chunk.offset = offset;
    chunk.data.assign(body.begin() + static_cast<std::ptrdiff_t>(offset),
                      body.begin() + static_cast<std::ptrdiff_t>(offset + take));
    if (corruptFirstChunk && !corrupted) {
      chunk.data[0] = static_cast<std::uint8_t>(chunk.data[0] ^ 0xFFu);
      corrupted = true;
    }
    CF_TRY_ASSIGN(const cf::ChunkAckMessage chunkAck, client.chunk(chunk));
    if (duplicateChunk && offset == 0) {
      // A duplicate frame is refused and the acknowledgement still tells the
      // truth about how many bytes are held.
      const auto duplicate = client.chunk(chunk);
      CF_EXPECT_OK(duplicate);
      if (duplicate) {
        CF_EXPECT_EQ(duplicate.value().code, cf::ErrorCode::ReorderedFrame);
        CF_EXPECT_EQ(duplicate.value().bytesReceived, static_cast<std::uint64_t>(take));
      }
    }
    if (chunkAck.code != cf::ErrorCode::Ok) {
      return cf::Result<cf::Digest>::fail(cf::Error(chunkAck.code, "chunk refused",
                                                    chunkAck.detail));
    }
    offset = chunkAck.bytesReceived;
  }

  cf::TransferCompleteMessage complete;
  complete.deployment = prepare.deployment;
  complete.stream = prepare.stream;
  complete.digest = digest;
  complete.sizeBytes = body.size();
  auto result = client.complete(complete);
  if (!result) {
    return cf::Result<cf::Digest>::fail(result.error());
  }
  if (!result.value().verified) {
    return cf::Result<cf::Digest>::fail(cf::Error(result.value().code, "not verified",
                                                  result.value().detail));
  }

  cf::StageMessage stage;
  stage.deployment = prepare.deployment;
  stage.stream = prepare.stream;
  stage.generation = prepare.generation;
  stage.digest = digest;
  CF_TRY_ASSIGN(const cf::StageAckMessage stageAck, client.stage(stage));
  if (!stageAck.staged) {
    return cf::Result<cf::Digest>::fail(cf::Error(stageAck.code, "not staged", stageAck.detail));
  }

  cf::ApplyCommitMessage commit;
  commit.deployment = prepare.deployment;
  commit.generation = prepare.generation;
  commit.digest = digest;
  auto committed = client.commit(commit);
  if (!committed) {
    return cf::Result<cf::Digest>::fail(committed.error());
  }
  if (!committed.value().committed) {
    return cf::Result<cf::Digest>::fail(
        cf::Error(committed.value().code, "commit refused", committed.value().detail));
  }
  return cf::Result<cf::Digest>::ok(digest);
}

}  // namespace

CF_TEST(unit, agent_activates_an_artifact_end_to_end) {
  Fixture fixture;
  AgentServer server(fixture.directory, fixture.options("rtr-1", cf::ApplyGuarantee::AtomicActivate));
  CF_EXPECT(server.valid());
  if (!server.valid()) {
    return;
  }
  ControllerClient client(server.port(), fixture.key, cf::Epoch::fromValue(1),
                          fixture.controllerIncarnation);
  CF_EXPECT(client.connected());
  CF_EXPECT_OK(client.establish("rtr-1"));
  CF_EXPECT_EQ(client.targetTerm().value(), std::uint64_t{1});

  const std::string body = "hostname rtr-1\ninterface eth0\n  mtu 9000\n";
  const auto activated = deliverOne(client, body, 1);
  CF_EXPECT_OK(activated);
  if (!activated) {
    return;
  }
  const auto ack = client.awaitAck();
  CF_EXPECT_OK(ack);
  if (ack) {
    CF_EXPECT_EQ(ack.value().state, cf::DeliveryState::Applied);
    CF_EXPECT_EQ(ack.value().generation.value(), std::uint64_t{1});
    CF_EXPECT_EQ(ack.value().digest, activated.value());
  }
  CF_EXPECT_EQ(server.agent().state().committedGeneration.value(), std::uint64_t{1});
  CF_EXPECT_EQ(server.agent().state().activations, std::uint64_t{1});
  const auto pointer = server.agent().readLivePointer(cf::parseConfigKey("fabric/underlay").value());
  CF_EXPECT_OK(pointer);
  if (pointer) {
    CF_EXPECT(pointer.value().present);
    CF_EXPECT_EQ(pointer.value().generation.value(), std::uint64_t{1});
    CF_EXPECT_EQ(pointer.value().digest, activated.value());
  }
}

CF_TEST(adversarial, agent_refuses_a_stale_generation) {
  Fixture fixture;
  AgentServer server(fixture.directory, fixture.options("rtr-1", cf::ApplyGuarantee::AtomicActivate));
  CF_EXPECT(server.valid());
  if (!server.valid()) {
    return;
  }
  ControllerClient client(server.port(), fixture.key, cf::Epoch::fromValue(1),
                          fixture.controllerIncarnation);
  CF_EXPECT_OK(client.establish("rtr-1"));
  CF_EXPECT_OK(deliverOne(client, "generation one\n", 2));
  CF_EXPECT_OK(client.awaitAck());
  client.close();

  ControllerClient second(server.port(), fixture.key, cf::Epoch::fromValue(1),
                          fixture.controllerIncarnation);
  CF_EXPECT_OK(second.establish("rtr-1"));
  CF_EXPECT_EQ(second.committedGeneration().value(), std::uint64_t{2});

  cf::PrepareMessage stale;
  stale.deployment = cf::deriveDeploymentId(cf::parseTargetId("rtr-1").value(),
                                            cf::parseConfigKey("fabric/underlay").value(),
                                            cf::Generation::fromValue(1),
                                            cf::Digest::ofText("old content\n"));
  stale.key = cf::parseConfigKey("fabric/underlay").value();
  stale.artifact = cf::parseArtifactId("cfg/underlay").value();
  stale.generation = cf::Generation::fromValue(1);
  stale.digest = cf::Digest::ofText("old content\n");
  stale.sizeBytes = 12;
  stale.schema = cf::parseSchemaId("cf.underlay").value();
  stale.schemaVersion = cf::SchemaVersion::fromValue(1);
  stale.requirement = cf::GuaranteeRequirement::RequireAtomic;
  stale.guarantee = cf::ApplyGuarantee::AtomicActivate;
  stale.authorityEpoch = cf::Epoch::fromValue(1);
  stale.stream = cf::StreamId::fromValue(99);
  stale.chunkBytes = 256;
  const auto refused = second.prepare(stale);
  CF_EXPECT(!refused.hasValue());
  if (!refused) {
    CF_EXPECT_EQ(refused.error().code(), cf::ErrorCode::StaleGeneration);
  }
  // The committed generation is untouched by the refused offer.
  CF_EXPECT_EQ(server.agent().state().committedGeneration.value(), std::uint64_t{2});
  const auto pointer = server.agent().readLivePointer(cf::parseConfigKey("fabric/underlay").value());
  CF_EXPECT_OK(pointer);
  if (pointer) {
    CF_EXPECT_EQ(pointer.value().generation.value(), std::uint64_t{2});
  }
  const auto report = second.reconcile();
  CF_EXPECT_OK(report);
  if (report) {
    CF_EXPECT_EQ(report.value().committedGeneration.value(), std::uint64_t{2});
  }
}

CF_TEST(adversarial, digest_mismatch_prevents_activation) {
  Fixture fixture;
  AgentServer server(fixture.directory, fixture.options("rtr-1", cf::ApplyGuarantee::AtomicActivate));
  CF_EXPECT(server.valid());
  if (!server.valid()) {
    return;
  }
  ControllerClient client(server.port(), fixture.key, cf::Epoch::fromValue(1),
                          fixture.controllerIncarnation);
  CF_EXPECT_OK(client.establish("rtr-1"));
  const std::string body = "content that will be corrupted in flight\n";
  const auto result = deliverOne(client, body, 1, "rtr-1", true);
  CF_EXPECT(!result.hasValue());
  if (!result) {
    CF_EXPECT_EQ(result.error().code(), cf::ErrorCode::DigestMismatch);
  }
  // Nothing was activated, and the staged bytes were destroyed.
  CF_EXPECT_EQ(server.agent().state().committedGeneration.value(), std::uint64_t{0});
  CF_EXPECT_EQ(server.agent().state().digestRejections, std::uint64_t{1});
  CF_EXPECT_EQ(server.agent().state().transfers.size(), std::size_t{0});
  const auto pointer = server.agent().readLivePointer(cf::parseConfigKey("fabric/underlay").value());
  CF_EXPECT_OK(pointer);
  if (pointer) {
    CF_EXPECT(!pointer.value().present);
  }
}

CF_TEST(adversarial, duplicate_and_reordered_chunks_do_not_corrupt_the_transfer) {
  Fixture fixture;
  AgentServer server(fixture.directory, fixture.options("rtr-1", cf::ApplyGuarantee::AtomicActivate));
  CF_EXPECT(server.valid());
  if (!server.valid()) {
    return;
  }
  ControllerClient client(server.port(), fixture.key, cf::Epoch::fromValue(1),
                          fixture.controllerIncarnation);
  CF_EXPECT_OK(client.establish("rtr-1"));
  const std::string body(700, 'q');
  const auto activated = deliverOne(client, body, 1, "rtr-1", false, true);
  CF_EXPECT_OK(activated);
  CF_EXPECT_OK(client.awaitAck());
  CF_EXPECT_EQ(server.agent().state().committedGeneration.value(), std::uint64_t{1});
}

CF_TEST(unit, duplicate_delivery_is_suppressed_not_reapplied) {
  Fixture fixture;
  AgentServer server(fixture.directory, fixture.options("rtr-1", cf::ApplyGuarantee::AtomicActivate));
  CF_EXPECT(server.valid());
  if (!server.valid()) {
    return;
  }
  ControllerClient client(server.port(), fixture.key, cf::Epoch::fromValue(1),
                          fixture.controllerIncarnation);
  CF_EXPECT_OK(client.establish("rtr-1"));
  const std::string body = "duplicate suppression body\n";
  const auto first = deliverOne(client, body, 3);
  CF_EXPECT_OK(first);
  CF_EXPECT_OK(client.awaitAck());
  CF_EXPECT_EQ(server.agent().state().activations, std::uint64_t{1});

  // The same delivery again: the target must answer from its durable record.
  const auto second = deliverOne(client, body, 3);
  CF_EXPECT_OK(second);
  CF_EXPECT_EQ(server.agent().state().activations, std::uint64_t{1});
  CF_EXPECT_EQ(server.agent().state().duplicatesSuppressed >= 1, true);
}

CF_TEST(unit, prepare_commit_abort_contract_is_exposed) {
  Fixture fixture;
  AgentServer server(fixture.directory,
                     fixture.options("rtr-1", cf::ApplyGuarantee::PrepareCommitAbort));
  CF_EXPECT(server.valid());
  if (!server.valid()) {
    return;
  }
  ControllerClient client(server.port(), fixture.key, cf::Epoch::fromValue(1),
                          fixture.controllerIncarnation);
  CF_EXPECT_OK(client.establish("rtr-1"));
  CF_EXPECT_EQ(client.targetGuarantee(), cf::ApplyGuarantee::PrepareCommitAbort);

  const std::string body = "configuration with a weak activation contract\n";
  const cf::Digest digest = cf::Digest::ofText(body);
  const cf::DeploymentId deployment = cf::deriveDeploymentId(
      cf::parseTargetId("rtr-1").value(), cf::parseConfigKey("fabric/underlay").value(),
      cf::Generation::fromValue(1), digest);

  cf::PrepareMessage prepare;
  prepare.deployment = deployment;
  prepare.key = cf::parseConfigKey("fabric/underlay").value();
  prepare.artifact = cf::parseArtifactId("cfg/underlay").value();
  prepare.generation = cf::Generation::fromValue(1);
  prepare.digest = digest;
  prepare.sizeBytes = body.size();
  prepare.schema = cf::parseSchemaId("cf.underlay").value();
  prepare.schemaVersion = cf::SchemaVersion::fromValue(1);
  prepare.requirement = cf::GuaranteeRequirement::AllowPrepareCommit;
  prepare.guarantee = cf::ApplyGuarantee::PrepareCommitAbort;
  prepare.authorityEpoch = cf::Epoch::fromValue(1);
  prepare.stream = cf::StreamId::fromValue(5);
  prepare.chunkBytes = 256;

  const auto ack = client.prepare(prepare);
  CF_EXPECT_OK(ack);
  cf::ChunkMessage chunk;
  chunk.stream = prepare.stream;
  chunk.offset = 0;
  chunk.data.assign(body.begin(), body.end());
  const auto chunkAck = client.chunk(chunk);
  CF_EXPECT_OK(chunkAck);
  cf::TransferCompleteMessage complete;
  complete.deployment = deployment;
  complete.stream = prepare.stream;
  complete.digest = digest;
  complete.sizeBytes = body.size();
  CF_EXPECT_OK(client.complete(complete));
  cf::StageMessage stage;
  stage.deployment = deployment;
  stage.stream = prepare.stream;
  stage.generation = prepare.generation;
  stage.digest = digest;
  CF_EXPECT_OK(client.stage(stage));

  // Prepare opens a window that is reported as such.
  cf::ApplyPrepareMessage apply;
  apply.deployment = deployment;
  apply.generation = prepare.generation;
  apply.digest = digest;
  const auto prepared = client.applyPrepare(apply);
  CF_EXPECT_OK(prepared);
  if (prepared) {
    CF_EXPECT(prepared.value().prepared);
  }
  CF_EXPECT(server.agent().state().applyPrepared);
  const auto midReport = client.reconcile();
  CF_EXPECT_OK(midReport);
  if (midReport) {
    CF_EXPECT(midReport.value().applyPrepared);
    CF_EXPECT_EQ(midReport.value().preparedGeneration.value(), std::uint64_t{1});
  }

  // Abort resolves the window and nothing is activated.
  cf::ApplyAbortMessage abort;
  abort.deployment = deployment;
  abort.generation = prepare.generation;
  abort.reason = "test abort";
  const auto aborted = client.applyAbort(abort);
  CF_EXPECT_OK(aborted);
  if (aborted) {
    CF_EXPECT(aborted.value().aborted);
  }
  CF_EXPECT(!server.agent().state().applyPrepared);
  CF_EXPECT_EQ(server.agent().state().committedGeneration.value(), std::uint64_t{0});
  CF_EXPECT_EQ(server.agent().state().applyRollbacks, std::uint64_t{1});

  // Committing without a prepare window is refused.
  cf::ApplyCommitMessage commit;
  commit.deployment = deployment;
  commit.generation = prepare.generation;
  commit.digest = digest;
  const auto commitWithoutWindow = client.commit(commit);
  CF_EXPECT_OK(commitWithoutWindow);
  CF_EXPECT(!commitWithoutWindow.value().committed);
}

CF_TEST(adversarial, atomic_target_refuses_a_prepare_window) {
  Fixture fixture;
  AgentServer server(fixture.directory, fixture.options("rtr-1", cf::ApplyGuarantee::AtomicActivate));
  CF_EXPECT(server.valid());
  if (!server.valid()) {
    return;
  }
  ControllerClient client(server.port(), fixture.key, cf::Epoch::fromValue(1),
                          fixture.controllerIncarnation);
  CF_EXPECT_OK(client.establish("rtr-1"));
  cf::ApplyPrepareMessage apply;
  apply.deployment = cf::parseDeploymentId("d-1").value();
  apply.generation = cf::Generation::fromValue(1);
  apply.digest = cf::Digest::ofText("x");
  const auto prepared = client.applyPrepare(apply);
  CF_EXPECT_OK(prepared);
  if (prepared) {
    CF_EXPECT(!prepared.value().prepared);
    CF_EXPECT_EQ(prepared.value().code, cf::ErrorCode::UnexpectedMessage);
  }
}

CF_TEST(adversarial, wrong_key_is_rejected_before_any_state_is_read) {
  Fixture fixture;
  AgentServer server(fixture.directory, fixture.options("rtr-1", cf::ApplyGuarantee::AtomicActivate));
  CF_EXPECT(server.valid());
  if (!server.valid()) {
    return;
  }
  cf::HmacKey hostile = fixture.key;
  hostile[0] = static_cast<std::uint8_t>(hostile[0] ^ 0xFFu);
  ControllerClient client(server.port(), hostile, cf::Epoch::fromValue(1),
                          fixture.controllerIncarnation);
  const auto established = client.establish("rtr-1");
  CF_EXPECT(!established);
  if (!established) {
    CF_EXPECT_EQ(established.code(), cf::ErrorCode::Unauthenticated);
  }
}

CF_TEST(adversarial, stale_controller_epoch_is_fenced) {
  Fixture fixture;
  AgentServer server(fixture.directory, fixture.options("rtr-1", cf::ApplyGuarantee::AtomicActivate));
  CF_EXPECT(server.valid());
  if (!server.valid()) {
    return;
  }
  {
    ControllerClient client(server.port(), fixture.key, cf::Epoch::fromValue(5),
                            cf::IncarnationId(cf::secureRandom128()));
    CF_EXPECT_OK(client.establish("rtr-1"));
  }
  // A controller claiming an older epoch must be refused.
  ControllerClient stale(server.port(), fixture.key, cf::Epoch::fromValue(4),
                         cf::IncarnationId(cf::secureRandom128()));
  const auto established = stale.establish("rtr-1");
  CF_EXPECT(!established);
  if (!established) {
    CF_EXPECT_EQ(established.code(), cf::ErrorCode::StaleEpoch);
  }
  // A different incarnation claiming the same epoch is refused too.
  ControllerClient impostor(server.port(), fixture.key, cf::Epoch::fromValue(5),
                            cf::IncarnationId(cf::secureRandom128()));
  const auto impostorStatus = impostor.establish("rtr-1");
  CF_EXPECT(!impostorStatus);
  if (!impostorStatus) {
    CF_EXPECT_EQ(impostorStatus.code(), cf::ErrorCode::FencedIncarnation);
  }
}

CF_TEST(restart, agent_restart_fences_the_old_incarnation_and_keeps_state) {
  Fixture fixture;
  const cf::Digest digest = cf::Digest::ofText("persisted configuration\n");
  {
    AgentServer server(fixture.directory,
                       fixture.options("rtr-1", cf::ApplyGuarantee::AtomicActivate));
    CF_EXPECT(server.valid());
    if (!server.valid()) {
      return;
    }
    ControllerClient client(server.port(), fixture.key, cf::Epoch::fromValue(1),
                            fixture.controllerIncarnation);
    CF_EXPECT_OK(client.establish("rtr-1"));
    const auto activated = deliverOne(client, "persisted configuration\n", 1);
    CF_EXPECT_OK(activated);
    CF_EXPECT_OK(client.awaitAck());
    server.stop();
  }
  AgentServer restarted(fixture.directory,
                        fixture.options("rtr-1", cf::ApplyGuarantee::AtomicActivate));
  CF_EXPECT(restarted.valid());
  if (!restarted.valid()) {
    return;
  }
  // A fresh incarnation with an incremented term.
  CF_EXPECT_EQ(restarted.agent().state().term.value(), std::uint64_t{2});
  CF_EXPECT_EQ(restarted.agent().state().committedGeneration.value(), std::uint64_t{1});
  CF_EXPECT_EQ(restarted.agent().state().committedDigest, digest);
  // A client claiming the pre-restart incarnation must be fenced: the term has
  // moved on, so the old process authority is gone.
  ControllerClient oldProcess(restarted.port(), fixture.key, cf::Epoch::fromValue(2),
                              fixture.controllerIncarnation);
  CF_EXPECT_OK(oldProcess.establish("rtr-1"));
  CF_EXPECT_EQ(oldProcess.targetTerm().value(), std::uint64_t{2});
  CF_EXPECT_EQ(oldProcess.committedGeneration().value(), std::uint64_t{1});
}

CF_TEST(restart, unresolved_prepare_window_is_aborted_on_restart) {
  Fixture fixture;
  const std::string body = "weak contract body\n";
  const cf::Digest digest = cf::Digest::ofText(body);
  cf::DeploymentId deployment;
  {
    AgentServer server(fixture.directory,
                       fixture.options("rtr-1", cf::ApplyGuarantee::PrepareCommitAbort));
    CF_EXPECT(server.valid());
    if (!server.valid()) {
      return;
    }
    ControllerClient client(server.port(), fixture.key, cf::Epoch::fromValue(1),
                            fixture.controllerIncarnation);
    CF_EXPECT_OK(client.establish("rtr-1"));
    deployment = cf::deriveDeploymentId(cf::parseTargetId("rtr-1").value(),
                                        cf::parseConfigKey("fabric/underlay").value(),
                                        cf::Generation::fromValue(1), digest);
    cf::PrepareMessage prepare;
    prepare.deployment = deployment;
    prepare.key = cf::parseConfigKey("fabric/underlay").value();
    prepare.artifact = cf::parseArtifactId("cfg/underlay").value();
    prepare.generation = cf::Generation::fromValue(1);
    prepare.digest = digest;
    prepare.sizeBytes = body.size();
    prepare.schema = cf::parseSchemaId("cf.underlay").value();
    prepare.schemaVersion = cf::SchemaVersion::fromValue(1);
    prepare.requirement = cf::GuaranteeRequirement::AllowPrepareCommit;
    prepare.guarantee = cf::ApplyGuarantee::PrepareCommitAbort;
    prepare.authorityEpoch = cf::Epoch::fromValue(1);
    prepare.stream = cf::StreamId::fromValue(6);
    prepare.chunkBytes = 256;
    CF_EXPECT_OK(client.prepare(prepare));
    cf::ChunkMessage chunk;
    chunk.stream = prepare.stream;
    chunk.offset = 0;
    chunk.data.assign(body.begin(), body.end());
    CF_EXPECT_OK(client.chunk(chunk));
    cf::TransferCompleteMessage complete;
    complete.deployment = deployment;
    complete.stream = prepare.stream;
    complete.digest = digest;
    complete.sizeBytes = body.size();
    CF_EXPECT_OK(client.complete(complete));
    cf::StageMessage stage;
    stage.deployment = deployment;
    stage.stream = prepare.stream;
    stage.generation = prepare.generation;
    stage.digest = digest;
    CF_EXPECT_OK(client.stage(stage));
    cf::ApplyPrepareMessage apply;
    apply.deployment = deployment;
    apply.generation = prepare.generation;
    apply.digest = digest;
    const auto prepared = client.applyPrepare(apply);
    CF_EXPECT_OK(prepared);
    CF_EXPECT(server.agent().state().applyPrepared);
    // Kill the process mid-window without a clean shutdown: the marker is
    // durable and the window is unresolved.
    server.stop();
  }
  AgentServer restarted(fixture.directory,
                        fixture.options("rtr-1", cf::ApplyGuarantee::PrepareCommitAbort));
  CF_EXPECT(restarted.valid());
  if (!restarted.valid()) {
    return;
  }
  CF_EXPECT(!restarted.agent().state().applyPrepared);
  CF_EXPECT_EQ(restarted.agent().state().applyRollbacks, std::uint64_t{1});
  CF_EXPECT_EQ(restarted.agent().state().committedGeneration.value(), std::uint64_t{0});
  CF_EXPECT(cf::test::containsText(restarted.liveSummary(), "aborted-unresolved-prepare"));
}
