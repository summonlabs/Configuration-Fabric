// Unit, adversarial and property tests: the distribution protocol codecs.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <string>
#include <vector>

#include "cf/codec.hpp"
#include "cf/protocol.hpp"
#include "cf/rng.hpp"
#include "testing.hpp"

namespace {

cf::HelloMessage sampleHello() {
  cf::HelloMessage hello;
  hello.nodeId = cf::parseNodeId("ctl-a").value();
  hello.epoch = cf::Epoch::fromValue(4);
  hello.incarnation = cf::IncarnationId(cf::secureRandom128());
  hello.nonce = cf::SessionNonce(cf::secureRandom128());
  hello.minWireVersion = cf::kWireVersion;
  hello.maxWireVersion = cf::kWireVersion;
  hello.maxPayloadBytes = 65536;
  hello.capabilities = cf::kCapabilityKnownMask;
  return hello;
}

cf::HelloAckMessage sampleAck() {
  cf::HelloAckMessage ack;
  ack.wireVersion = cf::kWireVersion;
  ack.target = cf::parseTargetId("rtr-1").value();
  ack.targetClass = cf::TargetClass::NetworkDevice;
  ack.guarantee = cf::ApplyGuarantee::AtomicActivate;
  ack.term = cf::Term::fromValue(2);
  ack.incarnation = cf::IncarnationId(cf::secureRandom128());
  ack.nonce = cf::SessionNonce(cf::secureRandom128());
  ack.maxPayloadBytes = 65536;
  ack.capabilities = cf::capabilitiesFor(cf::ApplyGuarantee::AtomicActivate);
  ack.committedGeneration = cf::Generation::fromValue(3);
  ack.committedDigest = cf::Digest::ofText("committed");
  ack.committedArtifact = cf::parseArtifactId("cfg/underlay").value();
  return ack;
}

template <class T, class Encoder, class Decoder>
void expectRoundTrip(const T& message, Encoder encode, Decoder decode) {
  const auto encoded = encode(message);
  CF_EXPECT(encoded.hasValue());
  if (!encoded) {
    return;
  }
  const auto decoded = decode(encoded.value());
  CF_EXPECT(decoded.hasValue());
}

}  // namespace

CF_TEST(unit, hello_round_trip_and_negotiation) {
  const cf::HelloMessage hello = sampleHello();
  const auto encoded = cf::encodeHello(hello);
  CF_EXPECT_OK(encoded);
  const auto decoded = cf::decodeHello(encoded.value());
  CF_EXPECT_OK(decoded);
  CF_EXPECT_EQ(decoded.value().nodeId.str(), hello.nodeId.str());
  CF_EXPECT_EQ(decoded.value().epoch.value(), hello.epoch.value());
  CF_EXPECT_EQ(decoded.value().incarnation, hello.incarnation);
  CF_EXPECT_EQ(decoded.value().nonce, hello.nonce);
}

CF_TEST(adversarial, hello_rejects_hostile_fields) {
  // Payload ceiling above the protocol ceiling.
  cf::HelloMessage hello = sampleHello();
  hello.maxPayloadBytes = cf::kAbsoluteMaxPayloadBytes + 1u;
  auto encoded = cf::encodeHello(hello);
  CF_EXPECT_OK(encoded);
  CF_EXPECT_CODE(cf::decodeHello(encoded.value()), cf::ErrorCode::OversizePayload);

  // Unknown capability bits.
  hello = sampleHello();
  hello.capabilities = 0x80000000u;
  encoded = cf::encodeHello(hello);
  CF_EXPECT_OK(encoded);
  CF_EXPECT_CODE(cf::decodeHello(encoded.value()), cf::ErrorCode::CapabilityMismatch);

  // Inverted version range.
  hello = sampleHello();
  hello.minWireVersion = 5;
  hello.maxWireVersion = 1;
  CF_EXPECT_CODE(cf::encodeHello(hello), cf::ErrorCode::InvalidArgument);

  // Trailing garbage.
  hello = sampleHello();
  encoded = cf::encodeHello(hello);
  CF_EXPECT_OK(encoded);
  std::vector<std::uint8_t> padded = encoded.value();
  padded.push_back(0x00);
  CF_EXPECT_CODE(cf::decodeHello(padded), cf::ErrorCode::ProtocolViolation);

  // Every truncation must be refused.
  for (std::size_t length = 0; length < encoded.value().size(); ++length) {
    CF_EXPECT(!cf::decodeHello(
                   std::span<const std::uint8_t>(encoded.value().data(), length))
                   .hasValue());
  }
}

CF_TEST(unit, hello_ack_requires_matching_capabilities) {
  const cf::HelloAckMessage ack = sampleAck();
  const auto encoded = cf::encodeHelloAck(ack);
  CF_EXPECT_OK(encoded);
  CF_EXPECT_OK(cf::decodeHelloAck(encoded.value()));

  // Claiming a guarantee the capability bits do not support must be refused.
  cf::HelloAckMessage inconsistent = sampleAck();
  inconsistent.guarantee = cf::ApplyGuarantee::PrepareCommitAbort;
  inconsistent.capabilities = cf::kCapabilityAtomicApply;
  const auto inconsistentBytes = cf::encodeHelloAck(inconsistent);
  CF_EXPECT_OK(inconsistentBytes);
  CF_EXPECT_CODE(cf::decodeHelloAck(inconsistentBytes.value()), cf::ErrorCode::CapabilityMismatch);

  // An unset term is not a valid target authority.
  cf::HelloAckMessage noTerm = sampleAck();
  noTerm.term = cf::Term{};
  const auto noTermBytes = cf::encodeHelloAck(noTerm);
  CF_EXPECT_OK(noTermBytes);
  CF_EXPECT_CODE(cf::decodeHelloAck(noTermBytes.value()), cf::ErrorCode::ProtocolViolation);

  // An empty committed artifact is legitimate for a target that has committed
  // nothing yet.
  cf::HelloAckMessage fresh = sampleAck();
  fresh.committedArtifact = cf::ArtifactId{};
  fresh.committedGeneration = cf::Generation{};
  fresh.committedDigest = cf::Digest{};
  const auto freshBytes = cf::encodeHelloAck(fresh);
  CF_EXPECT_OK(freshBytes);
  CF_EXPECT_OK(cf::decodeHelloAck(freshBytes.value()));
}

CF_TEST(unit, prepare_and_chunk_round_trip) {
  cf::PrepareMessage prepare;
  prepare.deployment = cf::parseDeploymentId("d-1").value();
  prepare.key = cf::parseConfigKey("fabric/underlay").value();
  prepare.artifact = cf::parseArtifactId("cfg/underlay").value();
  prepare.generation = cf::Generation::fromValue(9);
  prepare.digest = cf::Digest::ofText("payload");
  prepare.sizeBytes = 4096;
  prepare.schema = cf::parseSchemaId("cf.underlay").value();
  prepare.schemaVersion = cf::SchemaVersion::fromValue(2);
  prepare.requirement = cf::GuaranteeRequirement::RequireAtomic;
  prepare.guarantee = cf::ApplyGuarantee::AtomicActivate;
  prepare.authorityEpoch = cf::Epoch::fromValue(3);
  prepare.attempt = cf::AttemptId::fromValue(1);
  prepare.stream = cf::deriveStreamId(prepare.deployment, prepare.attempt);
  prepare.chunkBytes = 1024;
  const auto encoded = cf::encodePrepare(prepare);
  CF_EXPECT_OK(encoded);
  const auto decoded = cf::decodePrepare(encoded.value());
  CF_EXPECT_OK(decoded);
  CF_EXPECT_EQ(decoded.value().deployment.str(), prepare.deployment.str());
  CF_EXPECT_EQ(decoded.value().generation.value(), prepare.generation.value());
  CF_EXPECT_EQ(decoded.value().stream.value(), prepare.stream.value());
  CF_EXPECT_EQ(decoded.value().sizeBytes, prepare.sizeBytes);

  cf::ChunkMessage chunk;
  chunk.stream = prepare.stream;
  chunk.sequence = cf::Sequence::fromValue(1024);
  chunk.offset = 1024;
  chunk.data = std::vector<std::uint8_t>(900, 0x5A);
  const auto chunkBytes = cf::encodeChunk(chunk);
  CF_EXPECT_OK(chunkBytes);
  const auto chunkDecoded = cf::decodeChunk(chunkBytes.value());
  CF_EXPECT_OK(chunkDecoded);
  CF_EXPECT_EQ(chunkDecoded.value().offset, chunk.offset);
  CF_EXPECT(chunkDecoded.value().data == chunk.data);
}

CF_TEST(adversarial, prepare_rejects_zero_digest_and_empty_artifact) {
  cf::PrepareMessage prepare;
  prepare.deployment = cf::parseDeploymentId("d-1").value();
  prepare.key = cf::parseConfigKey("k").value();
  prepare.artifact = cf::parseArtifactId("a").value();
  prepare.generation = cf::Generation::fromValue(1);
  prepare.digest = cf::Digest::ofText("x");
  prepare.sizeBytes = 10;
  prepare.schema = cf::parseSchemaId("s").value();
  prepare.schemaVersion = cf::SchemaVersion::fromValue(1);
  prepare.requirement = cf::GuaranteeRequirement::RequireAtomic;
  prepare.guarantee = cf::ApplyGuarantee::AtomicActivate;
  prepare.authorityEpoch = cf::Epoch::fromValue(1);
  prepare.attempt = cf::AttemptId::fromValue(0);
  prepare.stream = cf::StreamId::fromValue(1);
  prepare.chunkBytes = 64;

  cf::PrepareMessage zeroDigest = prepare;
  zeroDigest.digest = cf::Digest{};
  auto bytes = cf::encodePrepare(zeroDigest);
  CF_EXPECT_OK(bytes);
  CF_EXPECT_CODE(cf::decodePrepare(bytes.value()), cf::ErrorCode::MalformedInput);

  cf::PrepareMessage emptyArtifact = prepare;
  emptyArtifact.sizeBytes = 0;
  bytes = cf::encodePrepare(emptyArtifact);
  CF_EXPECT_OK(bytes);
  CF_EXPECT_CODE(cf::decodePrepare(bytes.value()), cf::ErrorCode::MalformedInput);

  cf::PrepareMessage noStream = prepare;
  noStream.stream = cf::StreamId{};
  bytes = cf::encodePrepare(noStream);
  CF_EXPECT_OK(bytes);
  CF_EXPECT_CODE(cf::decodePrepare(bytes.value()), cf::ErrorCode::MalformedInput);

  cf::PrepareMessage hugeChunk = prepare;
  hugeChunk.chunkBytes = 0xFFFFFFFFu;
  bytes = cf::encodePrepare(hugeChunk);
  CF_EXPECT_OK(bytes);
  CF_EXPECT_CODE(cf::decodePrepare(bytes.value()), cf::ErrorCode::OversizePayload);
}

CF_TEST(adversarial, delivery_ack_must_report_an_activation_state) {
  cf::DeliveryAckMessage ack;
  ack.deployment = cf::parseDeploymentId("d-1").value();
  ack.key = cf::parseConfigKey("k").value();
  ack.generation = cf::Generation::fromValue(2);
  ack.digest = cf::Digest::ofText("x");
  ack.state = cf::DeliveryState::Applied;
  ack.term = cf::Term::fromValue(1);
  ack.incarnation = cf::IncarnationId(cf::secureRandom128());
  ack.authorityEpoch = cf::Epoch::fromValue(1);
  ack.guarantee = cf::ApplyGuarantee::AtomicActivate;
  auto encoded = cf::encodeDeliveryAck(ack);
  CF_EXPECT_OK(encoded);
  CF_EXPECT_OK(cf::decodeDeliveryAck(encoded.value()));

  cf::DeliveryAckMessage notActivation = ack;
  notActivation.state = cf::DeliveryState::Offered;
  encoded = cf::encodeDeliveryAck(notActivation);
  CF_EXPECT_OK(encoded);
  CF_EXPECT_CODE(cf::decodeDeliveryAck(encoded.value()), cf::ErrorCode::ProtocolViolation);

  cf::DeliveryAckMessage noAuthority = ack;
  noAuthority.term = cf::Term{};
  encoded = cf::encodeDeliveryAck(noAuthority);
  CF_EXPECT_OK(encoded);
  CF_EXPECT_CODE(cf::decodeDeliveryAck(encoded.value()), cf::ErrorCode::ProtocolViolation);
}

CF_TEST(unit, reconcile_report_round_trip_with_bounds) {
  cf::ReconcileReportMessage report;
  report.target = cf::parseTargetId("rtr-1").value();
  report.targetClass = cf::TargetClass::NetworkDevice;
  report.guarantee = cf::ApplyGuarantee::PrepareCommitAbort;
  report.term = cf::Term::fromValue(5);
  report.incarnation = cf::IncarnationId(cf::secureRandom128());
  for (int i = 0; i < 3; ++i) {
    cf::TransferStatusRecord transfer;
    transfer.deployment = cf::parseDeploymentId("d-" + std::to_string(i)).value();
    transfer.stream = cf::StreamId::fromValue(static_cast<std::uint64_t>(i + 1));
    transfer.key = cf::parseConfigKey("k").value();
    transfer.generation = cf::Generation::fromValue(static_cast<std::uint64_t>(i + 1));
    transfer.digest = cf::Digest::ofText("payload-" + std::to_string(i));
    transfer.bytesReceived = 100;
    transfer.totalBytes = 400;
    report.transfers.push_back(transfer);

    cf::ReconcileFinding finding;
    finding.key = cf::parseConfigKey("k").value();
    finding.generation = cf::Generation::fromValue(static_cast<std::uint64_t>(i + 1));
    finding.digest = cf::Digest::ofText("applied-" + std::to_string(i));
    finding.artifact = cf::parseArtifactId("cfg/x").value();
    finding.deployment = cf::parseDeploymentId("d-" + std::to_string(i)).value();
    finding.state = cf::DeliveryState::Applied;
    report.findings.push_back(finding);
  }
  report.applyPrepared = true;
  report.preparedDeployment = cf::parseDeploymentId("d-0").value();
  report.preparedGeneration = cf::Generation::fromValue(1);
  report.preparedDigest = cf::Digest::ofText("pending");
  report.applyRollbacks = 2;

  const auto encoded = cf::encodeReconcileReport(report);
  CF_EXPECT_OK(encoded);
  const auto decoded = cf::decodeReconcileReport(encoded.value());
  CF_EXPECT_OK(decoded);
  CF_EXPECT_EQ(decoded.value().transfers.size(), std::size_t{3});
  CF_EXPECT_EQ(decoded.value().findings.size(), std::size_t{3});
  CF_EXPECT_EQ(decoded.value().applyRollbacks, std::uint32_t{2});
  CF_EXPECT(decoded.value().applyPrepared);
}

CF_TEST(adversarial, reconcile_report_refuses_impossible_collections) {
  // Declaring more transfers than the protocol allows must be refused before the
  // decoder tries to read them.
  cf::ByteWriter writer;
  writer.string("rtr-1", cf::kMaxIdentifierLength);
  writer.u8(static_cast<std::uint8_t>(cf::TargetClass::NetworkDevice));
  writer.u8(static_cast<std::uint8_t>(cf::ApplyGuarantee::AtomicActivate));
  writer.u64(1);
  writer.opaque128(cf::secureRandom128());
  writer.u64(0);
  writer.digest(cf::Digest{});
  writer.string("", cf::kMaxIdentifierLength);
  writer.boolean(false);
  writer.string("", cf::kMaxIdentifierLength);
  writer.u64(0);
  writer.digest(cf::Digest{});
  writer.u32(0);  // restart count
  writer.u32(0);  // apply rollbacks
  writer.u32(9999);  // transfer count, far beyond the protocol bound
  CF_EXPECT_CODE(cf::decodeReconcileReport(writer.span()), cf::ErrorCode::OversizePayload);
}

CF_TEST(unit, authenticate_seal_and_verify) {
  cf::HmacKey key{};
  for (std::size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<std::uint8_t>(i * 7);
  }
  const cf::HelloMessage hello = sampleHello();
  auto encoded = cf::encodeHello(hello);
  CF_EXPECT_OK(encoded);
  CF_EXPECT_OK(cf::sealAuthenticated(encoded.value(), key));
  CF_EXPECT_OK(cf::verifyAuthenticated(encoded.value(), key));

  // A single flipped bit anywhere in the authenticated payload must fail.
  for (std::size_t i = 0; i < encoded.value().size(); ++i) {
    std::vector<std::uint8_t> damaged = encoded.value();
    damaged[i] = static_cast<std::uint8_t>(damaged[i] ^ 0x01u);
    CF_EXPECT_CODE(cf::verifyAuthenticated(damaged, key), cf::ErrorCode::Unauthenticated);
  }

  // A different key must fail.
  cf::HmacKey other = key;
  other[0] = static_cast<std::uint8_t>(other[0] ^ 0xFFu);
  CF_EXPECT_CODE(cf::verifyAuthenticated(encoded.value(), other), cf::ErrorCode::Unauthenticated);

  // A payload shorter than the tag is refused rather than read past.
  const std::vector<std::uint8_t> tiny(10, 0);
  CF_EXPECT_CODE(cf::verifyAuthenticated(tiny, key), cf::ErrorCode::Unauthenticated);
}

CF_TEST(unit, control_channel_codecs) {
  cf::ControlHelloMessage hello;
  hello.clientName = "cfctl";
  hello.nonce = cf::SessionNonce(cf::secureRandom128());
  auto encoded = cf::encodeControlHello(hello);
  CF_EXPECT_OK(encoded);
  const auto decodedHello = cf::decodeControlHello(encoded.value());
  CF_EXPECT_OK(decodedHello);
  CF_EXPECT_EQ(decodedHello.value().clientName, std::string("cfctl"));

  cf::ControlRequestMessage request;
  request.command = "explain";
  request.arguments = {"rtr-1"};
  const auto requestBytes = cf::encodeControlRequest(request);
  CF_EXPECT_OK(requestBytes);
  const auto decodedRequest = cf::decodeControlRequest(requestBytes.value());
  CF_EXPECT_OK(decodedRequest);
  CF_EXPECT_EQ(decodedRequest.value().arguments.size(), std::size_t{1});

  cf::ControlResponseMessage response;
  response.code = cf::ErrorCode::Ok;
  response.body = "text";
  const auto responseBytes = cf::encodeControlResponse(response);
  CF_EXPECT_OK(responseBytes);
  CF_EXPECT_OK(cf::decodeControlResponse(responseBytes.value()));

  // Too many arguments is refused at encode time and at decode time.
  cf::ControlRequestMessage tooMany;
  tooMany.command = "x";
  for (std::size_t i = 0; i < cf::kMaxControlArguments + 1; ++i) {
    tooMany.arguments.push_back("a");
  }
  CF_EXPECT_CODE(cf::encodeControlRequest(tooMany), cf::ErrorCode::LimitExceeded);
}

CF_TEST(unit, message_summary_is_deterministic) {
  cf::PrepareMessage prepare;
  prepare.deployment = cf::parseDeploymentId("d-1").value();
  prepare.key = cf::parseConfigKey("fabric/underlay").value();
  prepare.artifact = cf::parseArtifactId("cfg/underlay").value();
  prepare.generation = cf::Generation::fromValue(9);
  prepare.digest = cf::Digest::ofText("payload");
  prepare.sizeBytes = 4096;
  prepare.schema = cf::parseSchemaId("cf.underlay").value();
  prepare.schemaVersion = cf::SchemaVersion::fromValue(2);
  prepare.requirement = cf::GuaranteeRequirement::RequireAtomic;
  prepare.guarantee = cf::ApplyGuarantee::AtomicActivate;
  prepare.authorityEpoch = cf::Epoch::fromValue(3);
  prepare.attempt = cf::AttemptId::fromValue(1);
  prepare.stream = cf::StreamId::fromValue(7);
  prepare.chunkBytes = 1024;
  const auto encoded = cf::encodePrepare(prepare);
  CF_EXPECT_OK(encoded);
  const std::string first = cf::renderMessageSummary(cf::FrameType::Prepare, encoded.value());
  const std::string second = cf::renderMessageSummary(cf::FrameType::Prepare, encoded.value());
  CF_EXPECT_EQ(first, second);
  CF_EXPECT(first.find("d-1") != std::string::npos);
}

CF_TEST(property, random_message_payloads_never_crash_the_decoder) {
  cf::Rng rng(cftest::runSeed() ^ 0xBEEFu);
  for (int iteration = 0; iteration < 4000; ++iteration) {
    const std::size_t length = static_cast<std::size_t>(rng.bounded(96));
    std::vector<std::uint8_t> payload(length);
    rng.fillBytes(std::span<std::uint8_t>(payload.data(), payload.size()));
    const std::span<const std::uint8_t> view(payload.data(), payload.size());
    // Every decoder must return a typed error rather than reading out of bounds.
    (void)cf::decodeHello(view);
    (void)cf::decodeHelloAck(view);
    (void)cf::decodeHelloConfirm(view);
    (void)cf::decodeAuthReject(view);
    (void)cf::decodePrepare(view);
    (void)cf::decodePrepareAck(view);
    (void)cf::decodePrepareReject(view);
    (void)cf::decodeChunk(view);
    (void)cf::decodeChunkAck(view);
    (void)cf::decodeTransferComplete(view);
    (void)cf::decodeTransferResult(view);
    (void)cf::decodeStage(view);
    (void)cf::decodeStageAck(view);
    (void)cf::decodeApplyPrepare(view);
    (void)cf::decodeApplyPrepareAck(view);
    (void)cf::decodeApplyCommit(view);
    (void)cf::decodeApplyCommitAck(view);
    (void)cf::decodeApplyAbort(view);
    (void)cf::decodeApplyAbortAck(view);
    (void)cf::decodeDeliveryAck(view);
    (void)cf::decodeDeliveryNack(view);
    (void)cf::decodeReconcileRequest(view);
    (void)cf::decodeReconcileReport(view);
    (void)cf::decodeRetire(view);
    (void)cf::decodeRetireAck(view);
    (void)cf::decodePing(view);
    (void)cf::decodePong(view);
    (void)cf::decodeGoodbye(view);
    (void)cf::decodeError(view);
    (void)cf::decodeControlHello(view);
    (void)cf::decodeControlHelloAck(view);
    (void)cf::decodeControlRequest(view);
    (void)cf::decodeControlResponse(view);
    (void)cf::verifyAuthenticated(view, cf::HmacKey{});
  }
  CF_EXPECT(true);
}
