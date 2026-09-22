// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/control.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <vector>

#include "cf/checked.hpp"
#include "cf/codec.hpp"
#include "cf/convergence.hpp"
#include "cf/log.hpp"
#include "cf/plan.hpp"
#include "cf/protocol.hpp"
#include "cf/rng.hpp"

namespace cf {
namespace {

constexpr std::string_view kComponent = "control";
constexpr std::int64_t kControlBudgetMillis = 30000;

[[nodiscard]] std::string joinArguments(const std::vector<std::string>& arguments,
                                        std::size_t from) {
  std::string out;
  for (std::size_t i = from; i < arguments.size(); ++i) {
    if (!out.empty()) {
      out.push_back(' ');
    }
    out.append(arguments[i]);
  }
  return out;
}

[[nodiscard]] std::string renderTargetLine(const TargetRuntime& runtime) {
  std::string out;
  out.reserve(256);
  out.append(runtime.id.str());
  out.append(" class=");
  out.append(targetClassName(runtime.klass));
  out.append(" guarantee=");
  out.append(applyGuaranteeName(runtime.guarantee));
  out.append(" term=");
  out.append(std::to_string(runtime.term.value()));
  out.append(" incarnation=");
  out.append(runtime.incarnation.isSet() ? runtime.incarnation.hex().substr(0, 8)
                                         : std::string("unset"));
  out.append(" committed-generation=");
  out.append(runtime.committedGeneration.isSet()
                 ? std::to_string(runtime.committedGeneration.value())
                 : std::string("none"));
  out.append(" committed-digest=");
  out.append(runtime.committedDigest.isSet() ? shortDigest(runtime.committedDigest)
                                             : std::string("none"));
  out.append(" endpoint=");
  out.append(runtime.endpoint.empty() ? std::string("-") : runtime.endpoint);
  out.append(" contact-current=");
  out.append(runtime.contactEstablishedThisProcess ? "yes" : "no");
  out.append(" sessions=");
  out.append(std::to_string(runtime.sessionsEstablished));
  out.append(" restarts=");
  out.append(std::to_string(runtime.restartsObserved));
  if (runtime.applyPrepared) {
    out.append(" prepare-window=open");
  }
  return out;
}

[[nodiscard]] std::string renderDeliveryLine(const DeliveryRecord& record) {
  std::string out;
  out.reserve(320);
  out.append(record.id.str());
  out.append(" target=");
  out.append(record.target.str());
  out.append(" key=");
  out.append(record.key.str());
  out.append(" generation=");
  out.append(std::to_string(record.generation.value()));
  out.append(" digest=");
  out.append(shortDigest(record.digest));
  out.append(" state=");
  out.append(deliveryStateName(record.state));
  out.append(" attempt=");
  out.append(std::to_string(record.attempt.value()));
  out.append(" failures=");
  out.append(std::to_string(record.failures));
  out.append(" guarantee=");
  out.append(applyGuaranteeName(record.effectiveGuarantee));
  out.append(" requirement=");
  out.append(guaranteeRequirementName(record.requirement));
  if (record.lastError != ErrorCode::Ok) {
    out.append(" last-error=");
    out.append(errorCodeName(record.lastError));
  }
  if (record.acknowledgedFromReconcile) {
    out.append(" evidence=reconciliation");
  }
  return out;
}

}  // namespace

std::string renderControlCommands() {
  return std::string(
      "commands:\n"
      "  status                       controller identity, budgets and durable sizes\n"
      "  targets                      every known target and its authoritative state\n"
      "  deliveries                   every delivery record with its lifecycle state\n"
      "  pending                      transfers and acknowledgements still outstanding\n"
      "  divergence                   generation divergence per (target, config key)\n"
      "  converge                     deterministic convergence summary\n"
      "  explain <target>             full explanation for one target\n"
      "  artifacts                    artifact inventory\n"
      "  verify-artifacts             recompute every stored artifact digest\n"
      "  plan <path>                  load and submit a deployment plan file\n"
      "  retire <deployment-id> [why] retire a delivery\n"
      "  lifecycle                    the delivery transition relation\n"
      "  shutdown                     stop the controller cleanly\n");
}

Result<ControlRequest> parseControlLine(std::string_view line) {
  ControlRequest request;
  std::string current;
  bool inQuotes = false;
  bool haveToken = false;
  for (std::size_t i = 0; i < line.size(); ++i) {
    const char c = line[i];
    if (c == '"') {
      inQuotes = !inQuotes;
      haveToken = true;
      continue;
    }
    if (!inQuotes && (c == ' ' || c == '\t')) {
      if (haveToken) {
        if (request.command.empty()) {
          request.command = current;
        } else {
          request.arguments.push_back(current);
        }
        current.clear();
        haveToken = false;
      }
      continue;
    }
    if (c == '\\' && inQuotes && i + 1 < line.size()) {
      current.push_back(line[i + 1]);
      ++i;
      haveToken = true;
      continue;
    }
    current.push_back(c);
    haveToken = true;
  }
  if (inQuotes) {
    return Result<ControlRequest>::fail(ErrorCode::MalformedInput,
                                        "control line has an unterminated quoted argument");
  }
  if (haveToken) {
    if (request.command.empty()) {
      request.command = current;
    } else {
      request.arguments.push_back(current);
    }
  }
  if (request.command.empty()) {
    return Result<ControlRequest>::fail(ErrorCode::MissingField, "control line has no command");
  }
  if (request.arguments.size() > kMaxControlArguments) {
    return Result<ControlRequest>::fail(ErrorCode::LimitExceeded,
                                        "control line has too many arguments");
  }
  return Result<ControlRequest>::ok(std::move(request));
}

Result<std::string> executeControlCommand(Distributor& distributor,
                                          const ControlRequest& request) {
  const std::string& command = request.command;
  if (command == "status") {
    return distributor.statusText();
  }
  if (command == "targets") {
    auto targets = distributor.targets();
    if (!targets) {
      return Result<std::string>::fail(targets.error());
    }
    std::string out;
    out.append("targets: ");
    out.append(std::to_string(targets.value().size()));
    out.push_back('\n');
    for (const TargetRuntime& runtime : targets.value()) {
      out.append(renderTargetLine(runtime));
      out.push_back('\n');
    }
    return Result<std::string>::ok(std::move(out));
  }
  if (command == "deliveries") {
    auto deliveries = distributor.deliveries();
    if (!deliveries) {
      return Result<std::string>::fail(deliveries.error());
    }
    std::string out;
    out.append("deliveries: ");
    out.append(std::to_string(deliveries.value().size()));
    out.push_back('\n');
    for (const DeliveryRecord& record : deliveries.value()) {
      out.append(renderDeliveryLine(record));
      out.push_back('\n');
    }
    return Result<std::string>::ok(std::move(out));
  }
  if (command == "pending") {
    auto deliveries = distributor.deliveries();
    if (!deliveries) {
      return Result<std::string>::fail(deliveries.error());
    }
    std::string out;
    std::size_t pendingCount = 0;
    for (const DeliveryRecord& record : deliveries.value()) {
      if (!isPendingState(record.state)) {
        continue;
      }
      pendingCount += 1;
      out.append(renderDeliveryLine(record));
      if (record.state == DeliveryState::Applied) {
        out.append(" awaiting=activation-acknowledgement");
      } else if (record.state == DeliveryState::Offered ||
                 record.state == DeliveryState::Transferred) {
        out.append(" awaiting=transfer-completion");
      } else if (record.state == DeliveryState::Verified ||
                 record.state == DeliveryState::Staged) {
        out.append(" awaiting=activation");
      }
      out.push_back('\n');
    }
    std::string header;
    header.append("pending: ");
    header.append(std::to_string(pendingCount));
    header.push_back('\n');
    header.append(out);
    return Result<std::string>::ok(std::move(header));
  }
  if (command == "divergence" || command == "converge") {
    auto report = distributor.convergence();
    if (!report) {
      return Result<std::string>::fail(report.error());
    }
    if (command == "divergence") {
      std::string out;
      out.append("fingerprint: ");
      out.append(report.value().fingerprint());
      out.push_back('\n');
      for (const LineageConvergence& lineage : report.value().lineages) {
        out.append(lineage.target.str());
        out.append(" key=");
        out.append(lineage.key.str());
        out.append(" desired=");
        out.append(std::to_string(lineage.desiredGeneration.value()));
        out.append(" current=");
        out.append(lineage.currentGeneration.isSet()
                       ? std::to_string(lineage.currentGeneration.value())
                       : std::string("none"));
        out.append(" state=");
        out.append(deliveryStateName(lineage.state));
        out.append(" outcome=");
        out.append(lineage.converged ? "converged" : "not-converged");
        out.push_back('\n');
      }
      return Result<std::string>::ok(std::move(out));
    }
    return Result<std::string>::ok(report.value().render());
  }
  if (command == "explain") {
    if (request.arguments.empty()) {
      return Result<std::string>::fail(ErrorCode::MissingField,
                                       "explain needs a target id");
    }
    auto target = parseTargetId(request.arguments[0]);
    if (!target) {
      return Result<std::string>::fail(target.error());
    }
    return distributor.explain(target.value());
  }
  if (command == "artifacts") {
    auto artifacts = distributor.artifacts();
    if (!artifacts) {
      return Result<std::string>::fail(artifacts.error());
    }
    std::string out;
    out.append("artifacts: ");
    out.append(std::to_string(artifacts.value().size()));
    out.push_back('\n');
    for (const ArtifactMetadata& metadata : artifacts.value()) {
      out.append(renderArtifactMetadata(metadata));
      out.push_back('\n');
    }
    return Result<std::string>::ok(std::move(out));
  }
  if (command == "verify-artifacts") {
    auto results = distributor.verifyArtifacts();
    if (!results) {
      return Result<std::string>::fail(results.error());
    }
    std::string out;
    std::size_t failures = 0;
    for (const auto& entry : results.value()) {
      out.append(entry.first.hex().substr(0, 12));
      out.push_back(' ');
      out.append(entry.second ? "ok" : entry.second.str());
      out.push_back('\n');
      if (!entry.second) {
        failures += 1;
      }
    }
    out.append("verified: ");
    out.append(std::to_string(results.value().size() - failures));
    out.append(" failures: ");
    out.append(std::to_string(failures));
    out.push_back('\n');
    return Result<std::string>::ok(std::move(out));
  }
  if (command == "plan") {
    if (request.arguments.empty()) {
      return Result<std::string>::fail(ErrorCode::MissingField, "plan needs a file path");
    }
    auto plan = loadDeploymentPlanFile(request.arguments[0]);
    if (!plan) {
      return Result<std::string>::fail(plan.error());
    }
    std::vector<DeploymentId> created;
    const Status submitted = distributor.submitPlan(plan.value(), &created);
    if (!submitted) {
      return Result<std::string>::fail(submitted.error());
    }
    std::string out;
    out.append("plan ");
    out.append(plan.value().setId.str());
    out.append(" accepted, deliveries=");
    out.append(std::to_string(created.size()));
    out.push_back('\n');
    for (const DeploymentId& id : created) {
      out.append("  ");
      out.append(id.str());
      out.push_back('\n');
    }
    return Result<std::string>::ok(std::move(out));
  }
  if (command == "retire") {
    if (request.arguments.empty()) {
      return Result<std::string>::fail(ErrorCode::MissingField, "retire needs a deployment id");
    }
    auto id = parseDeploymentId(request.arguments[0]);
    if (!id) {
      return Result<std::string>::fail(id.error());
    }
    std::string reason = joinArguments(request.arguments, 1);
    if (reason.empty()) {
      reason = "retired by operator request";
    }
    const Status retired = distributor.retireDeployment(id.value(), reason);
    if (!retired) {
      return Result<std::string>::fail(retired.error());
    }
    return Result<std::string>::ok("retired " + id.value().str() + "\n");
  }
  if (command == "lifecycle") {
    return Result<std::string>::ok(renderTransitionTable());
  }
  if (command == "shutdown") {
    return Result<std::string>::ok("shutdown requested\n");
  }
  return Result<std::string>::fail(ErrorCode::NotFound, "unknown control command", command);
}

Status serveControlConnection(Distributor& distributor, Socket socket, const HmacKey& key) {
  auto connection = std::make_shared<FramedConnection>(std::move(socket), kDefaultMaxPayloadBytes);
  const std::int64_t deadline = monotonicMillis() + kControlBudgetMillis;

  auto helloFrame = connection->receive(deadline);
  if (!helloFrame) {
    return Status::fail(helloFrame.error());
  }
  if (helloFrame.value().type() != FrameType::ControlHello) {
    return Status::fail(ErrorCode::UnexpectedMessage, "expected a control hello",
                        std::string(frameTypeName(helloFrame.value().type())));
  }
  CF_TRY_ASSIGN(const ControlHelloMessage hello, decodeControlHello(helloFrame.value().payload));
  if (distributor.authenticated()) {
    // The control channel uses the same shared secret as the agent protocol. A
    // client that cannot produce the tag is refused before it sees any state.
    const Status authenticated = verifyAuthenticated(helloFrame.value().payload, key);
    if (!authenticated) {
      Logger::global().warn(kComponent, "control client '" + hello.clientName +
                                            "' refused: authentication tag did not verify");
      return Status::fail(authenticated.error());
    }
  }

  ControlHelloAckMessage ack;
  ack.nodeId = distributor.nodeId();
  ack.epoch = distributor.epoch();
  ack.incarnation = IncarnationId(secureRandom128());
  ack.nonce = hello.nonce;
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> ackBytes, encodeControlHelloAck(ack));
  CF_TRY(connection->send(FrameType::ControlHelloAck, kFrameFlagResponse, ackBytes, deadline));

  for (;;) {
    auto frame = connection->receive(monotonicMillis() + kControlBudgetMillis);
    if (!frame) {
      return Status::fail(frame.error());
    }
    if (frame.value().type() == FrameType::Goodbye) {
      return Status::ok();
    }
    if (frame.value().type() != FrameType::ControlRequest) {
      return Status::fail(ErrorCode::UnexpectedMessage, "expected a control request",
                          std::string(frameTypeName(frame.value().type())));
    }
    CF_TRY_ASSIGN(const ControlRequestMessage request,
                  decodeControlRequest(frame.value().payload));
    ControlRequest parsed;
    parsed.command = request.command;
    parsed.arguments = request.arguments;
    const bool wantsShutdown = parsed.command == "shutdown";
    auto body = executeControlCommand(distributor, parsed);
    ControlResponseMessage response;
    if (body) {
      response.code = ErrorCode::Ok;
      response.body = body.value();
    } else {
      response.code = body.error().code();
      response.body = body.error().str();
    }
    CF_TRY_ASSIGN(const std::vector<std::uint8_t> responseBytes, encodeControlResponse(response));
    CF_TRY(connection->send(FrameType::ControlResponse, kFrameFlagResponse, responseBytes,
                            monotonicMillis() + kControlBudgetMillis));
    if (wantsShutdown) {
      distributor.requestShutdown();
      return Status::ok();
    }
  }
}

Result<std::string> runControlCommand(const Endpoint& endpoint, const HmacKey& key,
                                      bool authenticate, const ControlRequest& request) {
  auto socket = connectTcp(endpoint.host, endpoint.port, 5000);
  if (!socket) {
    return Result<std::string>::fail(socket.error());
  }
  FramedConnection connection(std::move(socket).value(), kDefaultMaxPayloadBytes);
  const std::int64_t deadline = monotonicMillis() + kControlBudgetMillis;

  ControlHelloMessage hello;
  hello.clientName = "cfctl";
  hello.nonce = SessionNonce(secureRandom128());
  CF_TRY_ASSIGN(std::vector<std::uint8_t> helloBytes, encodeControlHello(hello));
  if (authenticate) {
    CF_TRY(sealAuthenticated(helloBytes, key));
  }
  CF_TRY(connection.send(FrameType::ControlHello, 0, helloBytes, deadline));
  auto ackFrame = connection.receive(deadline);
  if (!ackFrame) {
    return Result<std::string>::fail(ackFrame.error());
  }
  if (ackFrame.value().type() != FrameType::ControlHelloAck) {
    return Result<std::string>::fail(ErrorCode::UnexpectedMessage,
                                     "controller did not answer the control hello",
                                     std::string(frameTypeName(ackFrame.value().type())));
  }
  CF_TRY_ASSIGN(const ControlHelloAckMessage ack, decodeControlHelloAck(ackFrame.value().payload));

  ControlRequestMessage requestMessage;
  requestMessage.command = request.command;
  requestMessage.arguments = request.arguments;
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> requestBytes, encodeControlRequest(requestMessage));
  CF_TRY(connection.send(FrameType::ControlRequest, 0, requestBytes, deadline));
  auto responseFrame = connection.receive(deadline);
  if (!responseFrame) {
    return Result<std::string>::fail(responseFrame.error());
  }
  if (responseFrame.value().type() != FrameType::ControlResponse) {
    return Result<std::string>::fail(ErrorCode::UnexpectedMessage,
                                     "controller did not answer the control request",
                                     std::string(frameTypeName(responseFrame.value().type())));
  }
  CF_TRY_ASSIGN(const ControlResponseMessage response,
                decodeControlResponse(responseFrame.value().payload));
  GoodbyeMessage goodbye;
  goodbye.code = ErrorCode::Ok;
  goodbye.reason = "control session complete";
  auto goodbyeBytes = encodeGoodbye(goodbye);
  if (goodbyeBytes) {
    (void)connection.send(FrameType::Goodbye, 0, goodbyeBytes.value(), deadline);
  }
  connection.close();
  if (response.code != ErrorCode::Ok) {
    return Result<std::string>::fail(response.code, "controller rejected the command",
                                     response.body);
  }
  std::string body = response.body;
  body.append("node: ");
  body.append(ack.nodeId.str());
  body.append(" epoch=");
  body.append(std::to_string(ack.epoch.value()));
  body.push_back('\n');
  return Result<std::string>::ok(std::move(body));
}

}  // namespace cf
