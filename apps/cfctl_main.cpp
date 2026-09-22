// Configuration Fabric - inspection CLI.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Two modes:
//
//   online   cfctl --endpoint host:port --key-file <f> <command> [args]
//   offline  cfctl --state <dir> <command> [args]
//
// Offline mode reads durable state without opening a store, so inspection can
// never mutate or recover the state it is inspecting.

#include <cstdio>
#include <string>
#include <vector>

#include "cf/artifact.hpp"
#include "cf/codec.hpp"
#include "cf/control.hpp"
#include "cf/convergence.hpp"
#include "cf/distributor.hpp"
#include "cf/journal.hpp"
#include "cf/log.hpp"
#include "cf/plan.hpp"
#include "cf/state.hpp"
#include "cf/version.hpp"

namespace {

struct Arguments {
  std::string endpoint;
  std::string stateDirectory;
  std::string artifactRoot;
  std::string keyFile;
  bool authenticate{true};
  std::string logLevel{"warn"};
  std::vector<std::string> command;
};

void usage() {
  std::fputs(
      "cfctl - Configuration Fabric inspection and operations\n"
      "\n"
      "usage:\n"
      "  cfctl --endpoint <host:port> --key-file <f> <command> [args]\n"
      "  cfctl --state <dir> [--artifacts <dir>] <command> [args]\n"
      "\n"
      "options:\n"
      "  --endpoint <host:port>   talk to a running controller's control endpoint\n"
      "  --state <dir>            inspect a controller state directory offline\n"
      "  --artifacts <dir>        artifact store directory for offline verification\n"
      "  --key-file <path>        shared secret for the control channel\n"
      "  --insecure-no-auth       talk to a controller that has authentication disabled\n"
      "  --log-level <level>      trace|debug|info|warn|error|off\n"
      "  --version                print the build identification\n"
      "  --help                   print this text\n"
      "\n",
      stdout);
  std::fputs(cf::renderControlCommands().c_str(), stdout);
  std::fputs(
      "\n"
      "offline commands additionally support:\n"
      "  artifacts                list artifacts recorded in durable state\n"
      "  targets | deliveries | pending | explain <target> | converge | divergence\n",
      stdout);
}

cf::Result<cf::HmacKey> loadKey(const std::string& path) {
  auto bytes = cf::readFileBounded(path, 4096);
  if (!bytes) {
    return cf::Result<cf::HmacKey>::fail(bytes.error());
  }
  const std::string text(reinterpret_cast<const char*>(bytes.value().data()),
                         bytes.value().size());
  std::string trimmed;
  for (const char c : text) {
    if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
      trimmed.push_back(c);
    }
  }
  cf::HmacKey key{};
  if (trimmed.size() == cf::kSha256HexChars &&
      cf::fromHex(trimmed, std::span<std::uint8_t>(key.data(), key.size()))) {
    return cf::Result<cf::HmacKey>::ok(key);
  }
  if (trimmed.empty()) {
    return cf::Result<cf::HmacKey>::fail(cf::ErrorCode::InvalidArgument,
                                         "shared secret file is empty");
  }
  for (std::size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<std::uint8_t>(trimmed[i % trimmed.size()] ^
                                       static_cast<char>((i / trimmed.size()) * 0x5Au));
  }
  return cf::Result<cf::HmacKey>::ok(key);
}

std::string renderTargets(const cf::ControllerState& state) {
  std::string out;
  out.append("targets: ");
  out.append(std::to_string(state.targets.size()));
  out.push_back('\n');
  for (const auto& entry : state.targets) {
    const cf::TargetRuntime& runtime = entry.second;
    out.append(runtime.id.str());
    out.append(" class=");
    out.append(cf::targetClassName(runtime.klass));
    out.append(" guarantee=");
    out.append(cf::applyGuaranteeName(runtime.guarantee));
    out.append(" term=");
    out.append(std::to_string(runtime.term.value()));
    out.append(" committed-generation=");
    out.append(runtime.committedGeneration.isSet()
                   ? std::to_string(runtime.committedGeneration.value())
                   : std::string("none"));
    out.append(" contact-current-in-this-record=");
    out.append(runtime.contactEstablishedThisProcess ? "yes" : "no (persisted evidence)");
    out.push_back('\n');
  }
  return out;
}

std::string renderDeliveries(const cf::ControllerState& state, bool pendingOnly) {
  std::string out;
  std::size_t count = 0;
  for (const auto& entry : state.deliveries) {
    if (pendingOnly && !cf::isPendingState(entry.second.state)) {
      continue;
    }
    count += 1;
  }
  out.append(pendingOnly ? "pending: " : "deliveries: ");
  out.append(std::to_string(count));
  out.push_back('\n');
  for (const auto& entry : state.deliveries) {
    const cf::DeliveryRecord& record = entry.second;
    if (pendingOnly && !cf::isPendingState(record.state)) {
      continue;
    }
    out.append(record.id.str());
    out.append(" target=");
    out.append(record.target.str());
    out.append(" key=");
    out.append(record.key.str());
    out.append(" generation=");
    out.append(std::to_string(record.generation.value()));
    out.append(" digest=");
    out.append(cf::shortDigest(record.digest));
    out.append(" state=");
    out.append(cf::deliveryStateName(record.state));
    out.append(" attempt=");
    out.append(std::to_string(record.attempt.value()));
    out.append(" failures=");
    out.append(std::to_string(record.failures));
    if (record.lastError != cf::ErrorCode::Ok) {
      out.append(" last-error=");
      out.append(cf::errorCodeName(record.lastError));
    }
    if (record.acknowledgedFromReconcile) {
      out.append(" evidence=reconciliation");
    }
    out.push_back('\n');
  }
  return out;
}

std::string renderArtifacts(const cf::ControllerState& state) {
  std::string out;
  out.append("artifacts: ");
  out.append(std::to_string(state.artifacts.size()));
  out.push_back('\n');
  for (const auto& entry : state.artifacts) {
    out.append(cf::renderArtifactMetadata(entry.second));
    out.push_back('\n');
  }
  return out;
}

cf::Result<std::string> runOffline(const Arguments& args, const cf::ControlRequest& request) {
  std::string detail;
  auto state = cf::loadControllerStateOffline(args.stateDirectory, &detail);
  if (!state) {
    return cf::Result<std::string>::fail(state.error());
  }
  if (!detail.empty()) {
    // Recorded once at the top of every offline report so a reader always knows
    // how the state was recovered.
    detail = "recovery: " + detail + "\n";
  }
  const std::string& command = request.command;
  if (command == "status") {
    std::string out = detail;
    out.append("node-id: ");
    out.append(state.value().nodeId.str());
    out.push_back('\n');
    out.append("authority-epoch: ");
    out.append(std::to_string(state.value().epoch.value()));
    out.push_back('\n');
    out.append("incarnation: ");
    out.append(state.value().incarnation.hex());
    out.push_back('\n');
    out.append("targets: ");
    out.append(std::to_string(state.value().targets.size()));
    out.push_back('\n');
    out.append("deliveries: ");
    out.append(std::to_string(state.value().deliveries.size()));
    out.push_back('\n');
    return cf::Result<std::string>::ok(std::move(out));
  }
  if (command == "targets") {
    return cf::Result<std::string>::ok(detail + renderTargets(state.value()));
  }
  if (command == "deliveries") {
    return cf::Result<std::string>::ok(detail + renderDeliveries(state.value(), false));
  }
  if (command == "pending") {
    return cf::Result<std::string>::ok(detail + renderDeliveries(state.value(), true));
  }
  if (command == "artifacts") {
    return cf::Result<std::string>::ok(detail + renderArtifacts(state.value()));
  }
  if (command == "converge" || command == "divergence") {
    cf::DistributorPolicy policy;
    const cf::ConvergenceReport report =
        cf::buildConvergenceReport(state.value(), policy, cf::nowUnixMillis());
    if (command == "converge") {
      return cf::Result<std::string>::ok(detail + report.render());
    }
    std::string out = detail;
    out.append("fingerprint: ");
    out.append(report.fingerprint());
    out.push_back('\n');
    for (const cf::LineageConvergence& lineage : report.lineages) {
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
      out.append(cf::deliveryStateName(lineage.state));
      out.push_back('\n');
    }
    return cf::Result<std::string>::ok(std::move(out));
  }
  if (command == "explain") {
    if (request.arguments.empty()) {
      return cf::Result<std::string>::fail(cf::ErrorCode::MissingField, "explain needs a target");
    }
    auto target = cf::parseTargetId(request.arguments[0]);
    if (!target) {
      return cf::Result<std::string>::fail(target.error());
    }
    cf::DistributorPolicy policy;
    return cf::Result<std::string>::ok(
        detail + cf::explainTarget(state.value(), policy, target.value(), cf::nowUnixMillis()));
  }
  if (command == "verify-artifacts") {
    if (args.artifactRoot.empty()) {
      return cf::Result<std::string>::fail(cf::ErrorCode::MissingField,
                                           "verify-artifacts offline needs --artifacts <dir>");
    }
    cf::ArtifactStore::Options options;
    options.root = args.artifactRoot;
    cf::ArtifactStore::RecoveryReport recovery;
    auto store = cf::ArtifactStore::open(options, recovery);
    if (!store) {
      return cf::Result<std::string>::fail(store.error());
    }
    const auto results = store.value()->verifyAll();
    std::string out = detail;
    std::size_t failures = 0;
    for (const auto& entry : results) {
      out.append(entry.first.hex().substr(0, 12));
      out.push_back(' ');
      out.append(entry.second ? "ok" : entry.second.str());
      out.push_back('\n');
      if (!entry.second) {
        failures += 1;
      }
    }
    out.append("verified: ");
    out.append(std::to_string(results.size() - failures));
    out.append(" failures: ");
    out.append(std::to_string(failures));
    out.push_back('\n');
    return cf::Result<std::string>::ok(std::move(out));
  }
  if (command == "lifecycle") {
    return cf::Result<std::string>::ok(cf::renderTransitionTable());
  }
  if (command == "journal") {
    cf::JournalRecovery recovery;
    auto records =
        cf::Journal::readFile(args.stateDirectory + "/controller.journal", recovery);
    if (!records) {
      return cf::Result<std::string>::fail(records.error());
    }
    std::string out = detail;
    out.append("journal: ");
    out.append(recovery.render());
    out.push_back('\n');
    for (const cf::JournalRecord& record : records.value()) {
      out.append(std::to_string(record.sequence.value()));
      out.push_back(' ');
      out.append(cf::journalRecordTypeName(record.type));
      out.append(" bytes=");
      out.append(std::to_string(record.payload.size()));
      out.push_back('\n');
    }
    return cf::Result<std::string>::ok(std::move(out));
  }
  return cf::Result<std::string>::fail(
      cf::ErrorCode::NotFound,
      "command is not available offline; use --endpoint for operations", command);
}

}  // namespace

int main(int argc, char** argv) {
  Arguments args;
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    const auto next = [&](std::string& out) {
      if (i + 1 >= argc) {
        return false;
      }
      out = argv[++i];
      return true;
    };
    if (flag == "--help" || flag == "-h") {
      usage();
      return 0;
    }
    if (flag == "--version") {
      std::printf("%s\n", std::string(cf::buildIdentification()).c_str());
      return 0;
    }
    if (flag == "--endpoint" && !args.endpoint.empty()) {
      std::fprintf(stderr, "cfctl: --endpoint given twice\n");
      return 2;
    }
    if (flag == "--endpoint") {
      if (!next(args.endpoint)) {
        std::fprintf(stderr, "cfctl: --endpoint needs a value\n");
        return 2;
      }
      continue;
    }
    if (flag == "--state") {
      if (!next(args.stateDirectory)) {
        std::fprintf(stderr, "cfctl: --state needs a value\n");
        return 2;
      }
      continue;
    }
    if (flag == "--artifacts") {
      if (!next(args.artifactRoot)) {
        std::fprintf(stderr, "cfctl: --artifacts needs a value\n");
        return 2;
      }
      continue;
    }
    if (flag == "--key-file") {
      if (!next(args.keyFile)) {
        std::fprintf(stderr, "cfctl: --key-file needs a value\n");
        return 2;
      }
      continue;
    }
    if (flag == "--log-level") {
      if (!next(args.logLevel)) {
        std::fprintf(stderr, "cfctl: --log-level needs a value\n");
        return 2;
      }
      continue;
    }
    if (flag == "--insecure-no-auth") {
      args.authenticate = false;
      continue;
    }
    args.command.push_back(flag);
  }

  cf::LogLevel level = cf::LogLevel::Warn;
  if (!cf::parseLogLevel(args.logLevel, level)) {
    std::fprintf(stderr, "cfctl: unknown log level\n");
    return 2;
  }
  cf::Logger::global().setLevel(level);

  if (args.command.empty()) {
    usage();
    return 2;
  }

  cf::ControlRequest request;
  request.command = args.command[0];
  for (std::size_t i = 1; i < args.command.size(); ++i) {
    request.arguments.push_back(args.command[i]);
  }

  // Local helper: computing a digest is what an operator does before writing a
  // deployment plan, and it needs no controller.
  if (request.command == "digest") {
    if (request.arguments.size() != 1) {
      std::fprintf(stderr, "cfctl: digest needs exactly one file path\n");
      return 2;
    }
    std::FILE* file = std::fopen(request.arguments[0].c_str(), "rb");
    if (file == nullptr) {
      std::fprintf(stderr, "cfctl: cannot open %s\n", request.arguments[0].c_str());
      return 1;
    }
    cf::Sha256 hasher;
    std::vector<std::uint8_t> buffer(64u * 1024u);
    std::uint64_t total = 0;
    for (;;) {
      const std::size_t read = std::fread(buffer.data(), 1, buffer.size(), file);
      if (read == 0) {
        break;
      }
      hasher.update(std::span<const std::uint8_t>(buffer.data(), read));
      total += static_cast<std::uint64_t>(read);
    }
    const bool failed = std::ferror(file) != 0;
    std::fclose(file);
    if (failed) {
      std::fprintf(stderr, "cfctl: read error on %s\n", request.arguments[0].c_str());
      return 1;
    }
    const cf::Digest digest = cf::Digest::fromBytes(hasher.finish());
    std::printf("digest %s\nsize %llu\n", digest.hex().c_str(),
                static_cast<unsigned long long>(total));
    return 0;
  }

  cf::Result<std::string> output = cf::Result<std::string>::fail(
      cf::ErrorCode::InvalidArgument, "no source was selected");
  if (!args.endpoint.empty()) {
    auto endpoint = cf::parseEndpoint(args.endpoint);
    if (!endpoint) {
      std::fprintf(stderr, "cfctl: %s\n", endpoint.error().str().c_str());
      return 2;
    }
    cf::HmacKey key{};
    if (args.authenticate) {
      if (args.keyFile.empty()) {
        std::fprintf(stderr, "cfctl: --key-file is required unless --insecure-no-auth is given\n");
        return 2;
      }
      auto loaded = loadKey(args.keyFile);
      if (!loaded) {
        std::fprintf(stderr, "cfctl: %s\n", loaded.error().str().c_str());
        return 2;
      }
      key = loaded.value();
    }
    output = cf::runControlCommand(endpoint.value(), key, args.authenticate, request);
  } else if (!args.stateDirectory.empty()) {
    output = runOffline(args, request);
  } else {
    std::fprintf(stderr, "cfctl: either --endpoint or --state is required\n");
    return 2;
  }

  if (!output) {
    std::fprintf(stderr, "cfctl: %s\n", output.error().str().c_str());
    return 1;
  }
  std::fputs(output.value().c_str(), stdout);
  return 0;
}