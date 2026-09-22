// Configuration Fabric - controller (distributor) executable.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The distributor owns authoritative delivery state. It is a long-running
// process: deployment plans are submitted through the control channel (cfctl) or
// at start-up, and delivery workers dial the targets named by those plans.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>

#if defined(_WIN32)
#include <windows.h>
#endif
#include <string>
#include <thread>
#include <vector>

#include "cf/codec.hpp"
#include "cf/control.hpp"
#include "cf/distributor.hpp"
#include "cf/log.hpp"
#include "cf/plan.hpp"
#include "cf/version.hpp"

namespace {

std::atomic<bool> g_stop{false};

#if defined(_WIN32)
BOOL WINAPI consoleHandler(DWORD signal) {
  if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
    g_stop.store(true);
    return TRUE;
  }
  return FALSE;
}
#else
extern "C" void posixHandler(int) { g_stop.store(true); }
#endif

void installSignalHandlers() {
#if defined(_WIN32)
  ::SetConsoleCtrlHandler(consoleHandler, TRUE);
#else
  std::signal(SIGINT, posixHandler);
  std::signal(SIGTERM, posixHandler);
#endif
}

struct Arguments {
  cf::NodeId nodeId;
  std::string stateDirectory;
  std::string artifactRoot;
  std::string controlHost{"127.0.0.1"};
  std::uint16_t controlPort{0};
  std::string announceFile;
  std::string keyFile;
  bool authenticate{true};
  std::vector<std::string> planFiles;
  std::string faults;
  std::string logLevel{"info"};
  std::string logFile;
  std::uint32_t maxAttempts{4};
  std::size_t maxConcurrentSessions{4};
  std::size_t transferChunkBytes{16384};
  std::uint32_t maxPayloadBytes{1u << 20};
  std::uint64_t maxArtifactBytes{64ull * 1024ull * 1024ull};
  std::int64_t livenessFreshnessMillis{15000};
  std::uint32_t shutdownAfterMillis{0};
};

void usage() {
  std::fputs(
      "cf-controller - Configuration Fabric distributor\n"
      "\n"
      "usage: cf-controller --node <id> --state <dir> --artifacts <dir> [options]\n"
      "\n"
      "required:\n"
      "  --node <id>                distributor identity, durable across restarts\n"
      "  --state <dir>              durable authoritative state directory\n"
      "  --artifacts <dir>          content-addressed artifact store directory\n"
      "\n"
      "options:\n"
      "  --control <host:port>      control endpoint (default 127.0.0.1:0)\n"
      "  --announce-file <path>     write the bound control endpoint here\n"
      "  --key-file <path>          shared secret file (64 hex characters or raw)\n"
      "  --insecure-no-auth         disable peer authentication (degraded)\n"
      "  --plan <path>              submit a deployment plan at start-up (repeatable)\n"
      "  --max-attempts <n>         bounded retry budget per delivery\n"
      "  --sessions <n>             concurrent delivery workers\n"
      "  --chunk-bytes <n>          transfer chunk size\n"
      "  --max-payload-bytes <n>    largest accepted wire payload\n"
      "  --max-artifact-bytes <n>   largest artifact accepted\n"
      "  --liveness-fresh-ms <n>    freshness window for persisted contact evidence\n"
      "  --fault-inject <list>      validation-only failure injection points\n"
      "  --exit-after-ms <n>        stop cleanly after this long (validation aid)\n"
      "  --log-level <level>        trace|debug|info|warn|error|off\n"
      "  --log-file <path>          write diagnostics here instead of stderr\n"
      "  --version                  print the build identification\n"
      "  --help                     print this text\n",
      stdout);
}

bool nextValue(int argc, char** argv, int& index, std::string& out) {
  if (index + 1 >= argc) {
    return false;
  }
  out = argv[++index];
  return true;
}

cf::Result<std::uint64_t> parseU64(const std::string& text) {
  if (text.empty()) {
    return cf::Result<std::uint64_t>::fail(cf::ErrorCode::InvalidArgument, "expected a number");
  }
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return cf::Result<std::uint64_t>::fail(cf::ErrorCode::InvalidArgument,
                                             "expected a decimal integer", text);
    }
    value = (value * 10u) + static_cast<std::uint64_t>(c - '0');
  }
  return cf::Result<std::uint64_t>::ok(value);
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

cf::Result<bool> parseArgs(int argc, char** argv, Arguments& args) {
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    std::string value;
    if (flag == "--help" || flag == "-h") {
      usage();
      return cf::Result<bool>::ok(false);
    }
    if (flag == "--version") {
      std::printf("%s\n", std::string(cf::buildIdentification()).c_str());
      return cf::Result<bool>::ok(false);
    }
    if (flag == "--node") {
      if (!nextValue(argc, argv, i, value)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--node needs a value");
      }
      CF_TRY_ASSIGN(args.nodeId, cf::parseNodeId(value));
      continue;
    }
    if (flag == "--state") {
      if (!nextValue(argc, argv, i, args.stateDirectory)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--state needs a value");
      }
      continue;
    }
    if (flag == "--artifacts") {
      if (!nextValue(argc, argv, i, args.artifactRoot)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--artifacts needs a value");
      }
      continue;
    }
    if (flag == "--control") {
      if (!nextValue(argc, argv, i, value)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--control needs a value");
      }
      CF_TRY_ASSIGN(const cf::Endpoint endpoint, cf::parseEndpoint(value));
      args.controlHost = endpoint.host;
      args.controlPort = endpoint.port;
      continue;
    }
    if (flag == "--announce-file") {
      if (!nextValue(argc, argv, i, args.announceFile)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--announce-file needs a value");
      }
      continue;
    }
    if (flag == "--key-file") {
      if (!nextValue(argc, argv, i, args.keyFile)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--key-file needs a value");
      }
      continue;
    }
    if (flag == "--plan") {
      if (!nextValue(argc, argv, i, value)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--plan needs a value");
      }
      args.planFiles.push_back(value);
      continue;
    }
    if (flag == "--fault-inject") {
      if (!nextValue(argc, argv, i, args.faults)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--fault-inject needs a value");
      }
      continue;
    }
    if (flag == "--log-level") {
      if (!nextValue(argc, argv, i, args.logLevel)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--log-level needs a value");
      }
      continue;
    }
    if (flag == "--log-file") {
      if (!nextValue(argc, argv, i, args.logFile)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--log-file needs a value");
      }
      continue;
    }
    if (flag == "--insecure-no-auth") {
      args.authenticate = false;
      continue;
    }
    if (flag == "--max-attempts" || flag == "--sessions" || flag == "--chunk-bytes" ||
        flag == "--max-payload-bytes" || flag == "--max-artifact-bytes" ||
        flag == "--liveness-fresh-ms" || flag == "--exit-after-ms") {
      if (!nextValue(argc, argv, i, value)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, flag + " needs a value");
      }
      CF_TRY_ASSIGN(const std::uint64_t parsed, parseU64(value));
      if (flag == "--max-attempts") {
        args.maxAttempts = static_cast<std::uint32_t>(parsed);
      } else if (flag == "--sessions") {
        args.maxConcurrentSessions = static_cast<std::size_t>(parsed);
      } else if (flag == "--chunk-bytes") {
        args.transferChunkBytes = static_cast<std::size_t>(parsed);
      } else if (flag == "--max-payload-bytes") {
        args.maxPayloadBytes = static_cast<std::uint32_t>(parsed);
      } else if (flag == "--max-artifact-bytes") {
        args.maxArtifactBytes = parsed;
      } else if (flag == "--liveness-fresh-ms") {
        args.livenessFreshnessMillis = static_cast<std::int64_t>(parsed);
      } else {
        args.shutdownAfterMillis = static_cast<std::uint32_t>(parsed);
      }
      continue;
    }
    return cf::Result<bool>::fail(cf::ErrorCode::InvalidArgument, "unknown argument", flag);
  }
  return cf::Result<bool>::ok(true);
}

}  // namespace

int main(int argc, char** argv) {
  Arguments args;
  auto parsed = parseArgs(argc, argv, args);
  if (!parsed) {
    std::fprintf(stderr, "cf-controller: %s\n", parsed.error().str().c_str());
    return 2;
  }
  if (!parsed.value()) {
    return 0;
  }
  if (!args.nodeId.isSet() || args.stateDirectory.empty() || args.artifactRoot.empty()) {
    std::fprintf(stderr, "cf-controller: --node, --state and --artifacts are required\n");
    return 2;
  }

  cf::LogLevel level = cf::LogLevel::Info;
  if (!cf::parseLogLevel(args.logLevel, level)) {
    std::fprintf(stderr, "cf-controller: unknown log level '%s'\n", args.logLevel.c_str());
    return 2;
  }
  cf::Logger::global().setLevel(level);
  if (!args.logFile.empty()) {
    const cf::Status opened = cf::Logger::global().setOutputFile(args.logFile);
    if (!opened) {
      std::fprintf(stderr, "cf-controller: %s\n", opened.str().c_str());
      return 2;
    }
  }

  auto faults = cf::fault::FaultPlan::parse(args.faults);
  if (!faults) {
    std::fprintf(stderr, "cf-controller: %s\n", faults.error().str().c_str());
    return 2;
  }

  cf::Distributor::Options options;
  options.nodeId = args.nodeId;
  options.stateDirectory = args.stateDirectory;
  options.artifactRoot = args.artifactRoot;
  options.controlHost = args.controlHost;
  options.controlPort = args.controlPort;
  options.maxArtifactBytes = args.maxArtifactBytes;
  options.policy.maxAttempts = args.maxAttempts;
  options.policy.maxConcurrentSessions = args.maxConcurrentSessions;
  options.policy.transferChunkBytes = args.transferChunkBytes;
  options.policy.maxPayloadBytes = args.maxPayloadBytes;
  options.policy.livenessFreshnessMillis = args.livenessFreshnessMillis;
  options.authenticate = args.authenticate;
  options.faults = faults.value();
  if (args.authenticate) {
    if (args.keyFile.empty()) {
      std::fprintf(stderr,
                   "cf-controller: --key-file is required unless --insecure-no-auth is given\n");
      return 2;
    }
    auto key = loadKey(args.keyFile);
    if (!key) {
      std::fprintf(stderr, "cf-controller: %s\n", key.error().str().c_str());
      return 2;
    }
    options.key = key.value();
  }

  cf::Distributor::Recovery recovery;
  auto distributor = cf::Distributor::open(options, recovery);
  if (!distributor) {
    std::fprintf(stderr, "cf-controller: %s\n", distributor.error().str().c_str());
    return 1;
  }
  distributor.value()->setShutdownFlag(&g_stop);

  cf::Logger::global().info("controller", std::string(cf::buildIdentification()) + " node=" +
                                             args.nodeId.str() + " epoch=" +
                                             std::to_string(distributor.value()->epoch().value()));
  cf::Logger::global().info("controller", "durable state: " + recovery.store.render());
  if (!args.authenticate) {
    cf::Logger::global().warn("controller",
                              "peer authentication is DISABLED: any client that can reach the "
                              "control endpoint can read authoritative state");
  }
  if (!options.faults.empty()) {
    cf::Logger::global().warn("controller", "fault injection armed: " + options.faults.render());
  }

  const cf::Status started = distributor.value()->start();
  if (!started) {
    std::fprintf(stderr, "cf-controller: %s\n", started.str().c_str());
    return 1;
  }
  const cf::Endpoint bound{args.controlHost, distributor.value()->controlPort()};
  if (!args.announceFile.empty()) {
    const std::string text = bound.str() + "\n";
    const cf::Status written = cf::writeFileAtomic(
        args.announceFile,
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                      text.size()));
    if (!written) {
      std::fprintf(stderr, "cf-controller: cannot write the announce file: %s\n",
                   written.str().c_str());
      return 1;
    }
  }
  cf::Logger::global().info("controller", "control endpoint " + bound.str());

  installSignalHandlers();

  for (const std::string& planPath : args.planFiles) {
    auto plan = cf::loadDeploymentPlanFile(planPath);
    if (!plan) {
      cf::Logger::global().error("controller",
                                 "cannot load deployment plan " + planPath + ": " +
                                     plan.error().str());
      distributor.value()->stop();
      return 1;
    }
    std::vector<cf::DeploymentId> created;
    const cf::Status submitted = distributor.value()->submitPlan(plan.value(), &created);
    if (!submitted) {
      cf::Logger::global().error("controller", "cannot submit deployment plan " + planPath + ": " +
                                                   submitted.str());
      distributor.value()->stop();
      return 1;
    }
    cf::Logger::global().info("controller", "plan " + plan.value().setId.str() + " accepted: " +
                                                std::to_string(created.size()) + " delivery(ies)");
  }

  const std::int64_t startedAt = cf::monotonicMillis();
  while (!g_stop.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (args.shutdownAfterMillis != 0 &&
        cf::monotonicMillis() - startedAt >= static_cast<std::int64_t>(args.shutdownAfterMillis)) {
      cf::Logger::global().info("controller", "exit-after-ms elapsed; stopping cleanly");
      break;
    }
  }

  distributor.value()->stop();
  auto report = distributor.value()->convergence();
  if (report) {
    cf::Logger::global().info("controller", "final convergence " + report.value().fingerprint() +
                                                " (" +
                                                std::to_string(report.value().convergedCount) + "/" +
                                                std::to_string(report.value().lineageCount) +
                                                " converged)");
  }
  return 0;
}
