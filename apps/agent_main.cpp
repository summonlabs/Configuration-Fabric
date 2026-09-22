// Configuration Fabric - target agent executable.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// One process per target. It owns the live configuration area for this target and
// serves the distributor over a real socket. Nothing about what it has activated
// depends on the distributor still being alive.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>

#if defined(_WIN32)
#include <windows.h>
#endif
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "cf/agent.hpp"
#include "cf/codec.hpp"
#include "cf/log.hpp"
#include "cf/protocol.hpp"
#include "cf/rng.hpp"
#include "cf/transport.hpp"
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
  cf::TargetId target;
  cf::TargetClass klass{cf::TargetClass::NetworkDevice};
  cf::ApplyGuarantee guarantee{cf::ApplyGuarantee::AtomicActivate};
  std::string stateDirectory;
  std::string liveDirectory;
  std::string listenHost{"127.0.0.1"};
  std::uint16_t listenPort{0};
  std::string announceFile;
  std::string keyFile;
  bool authenticate{true};
  std::string faults;
  std::string logLevel{"info"};
  std::string logFile;
  std::uint64_t maxArtifactBytes{64ull * 1024ull * 1024ull};
  std::int64_t idleTimeoutMillis{10000};
  bool verifyOnStart{true};
};

void usage() {
  std::fputs(
      "cf-agent - Configuration Fabric target agent\n"
      "\n"
      "usage: cf-agent --target <id> --state <dir> [options]\n"
      "\n"
      "required:\n"
      "  --target <id>              target identity this agent speaks for\n"
      "  --state <dir>              durable state directory\n"
      "\n"
      "options:\n"
      "  --class <class>            network-device | control-plane-participant\n"
      "  --guarantee <kind>         atomic-activate | prepare-commit-abort\n"
      "  --live <dir>               live configuration area (default <state>/live)\n"
      "  --listen <host:port>       listen endpoint (default 127.0.0.1:0)\n"
      "  --announce-file <path>     write the bound endpoint here once listening\n"
      "  --key-file <path>          shared secret file (32 bytes, hex or raw)\n"
      "  --insecure-no-auth         disable peer authentication (degraded)\n"
      "  --max-artifact-bytes <n>   largest artifact accepted\n"
      "  --idle-timeout-ms <n>      session idle budget\n"
      "  --fault-inject <list>      validation-only failure injection points\n"
      "  --no-verify-on-start       skip hashing the committed payload at start-up\n"
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
    if (flag == "--target") {
      if (!nextValue(argc, argv, i, value)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--target needs a value");
      }
      CF_TRY_ASSIGN(args.target, cf::parseTargetId(value));
      continue;
    }
    if (flag == "--class") {
      if (!nextValue(argc, argv, i, value) || !cf::parseTargetClass(value, args.klass)) {
        return cf::Result<bool>::fail(cf::ErrorCode::InvalidArgument, "unknown target class");
      }
      continue;
    }
    if (flag == "--guarantee") {
      if (!nextValue(argc, argv, i, value) || !cf::parseApplyGuarantee(value, args.guarantee)) {
        return cf::Result<bool>::fail(cf::ErrorCode::InvalidArgument, "unknown apply guarantee");
      }
      continue;
    }
    if (flag == "--state") {
      if (!nextValue(argc, argv, i, args.stateDirectory)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--state needs a value");
      }
      continue;
    }
    if (flag == "--live") {
      if (!nextValue(argc, argv, i, args.liveDirectory)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--live needs a value");
      }
      continue;
    }
    if (flag == "--listen") {
      if (!nextValue(argc, argv, i, value)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField, "--listen needs a value");
      }
      CF_TRY_ASSIGN(const cf::Endpoint endpoint, cf::parseEndpoint(value));
      args.listenHost = endpoint.host;
      args.listenPort = endpoint.port;
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
    if (flag == "--max-artifact-bytes") {
      if (!nextValue(argc, argv, i, value)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField,
                                      "--max-artifact-bytes needs a value");
      }
      std::uint64_t parsed = 0;
      for (const char c : value) {
        if (c < '0' || c > '9') {
          return cf::Result<bool>::fail(cf::ErrorCode::InvalidArgument,
                                        "--max-artifact-bytes is not a decimal integer");
        }
        parsed = (parsed * 10u) + static_cast<std::uint64_t>(c - '0');
      }
      args.maxArtifactBytes = parsed;
      continue;
    }
    if (flag == "--idle-timeout-ms") {
      if (!nextValue(argc, argv, i, value)) {
        return cf::Result<bool>::fail(cf::ErrorCode::MissingField,
                                      "--idle-timeout-ms needs a value");
      }
      std::int64_t parsed = 0;
      for (const char c : value) {
        if (c < '0' || c > '9') {
          return cf::Result<bool>::fail(cf::ErrorCode::InvalidArgument,
                                        "--idle-timeout-ms is not a decimal integer");
        }
        parsed = (parsed * 10) + static_cast<std::int64_t>(c - '0');
      }
      args.idleTimeoutMillis = parsed;
      continue;
    }
    if (flag == "--insecure-no-auth") {
      args.authenticate = false;
      continue;
    }
    if (flag == "--no-verify-on-start") {
      args.verifyOnStart = false;
      continue;
    }
    return cf::Result<bool>::fail(cf::ErrorCode::InvalidArgument, "unknown argument", flag);
  }
  return cf::Result<bool>::ok(true);
}

/// Loads the shared secret. A 64-character hex string is the documented form; a
/// file of raw bytes is also accepted so the secret never has to be re-encoded.
cf::Result<cf::HmacKey> loadKey(const std::string& path) {
  auto bytes = cf::readFileBounded(path, 4096);
  if (!bytes) {
    return cf::Result<cf::HmacKey>::fail(bytes.error());
  }
  const std::string text(reinterpret_cast<const char*>(bytes.value().data()),
                         bytes.value().size());
  std::string trimmed;
  trimmed.reserve(text.size());
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

}  // namespace

int main(int argc, char** argv) {
  Arguments args;
  auto parsed = parseArgs(argc, argv, args);
  if (!parsed) {
    std::fprintf(stderr, "cf-agent: %s\n", parsed.error().str().c_str());
    return 2;
  }
  if (!parsed.value()) {
    return 0;
  }
  if (!args.target.isSet() || args.stateDirectory.empty()) {
    std::fprintf(stderr, "cf-agent: --target and --state are required\n");
    return 2;
  }

  cf::LogLevel level = cf::LogLevel::Info;
  if (!cf::parseLogLevel(args.logLevel, level)) {
    std::fprintf(stderr, "cf-agent: unknown log level '%s'\n", args.logLevel.c_str());
    return 2;
  }
  cf::Logger::global().setLevel(level);
  if (!args.logFile.empty()) {
    const cf::Status opened = cf::Logger::global().setOutputFile(args.logFile);
    if (!opened) {
      std::fprintf(stderr, "cf-agent: %s\n", opened.str().c_str());
      return 2;
    }
  }

  auto faults = cf::fault::FaultPlan::parse(args.faults);
  if (!faults) {
    std::fprintf(stderr, "cf-agent: %s\n", faults.error().str().c_str());
    return 2;
  }

  cf::TargetAgent::Options options;
  options.stateDirectory = args.stateDirectory;
  options.liveDirectory = args.liveDirectory;
  options.target = args.target;
  options.klass = args.klass;
  options.guarantee = args.guarantee;
  options.maxArtifactBytes = args.maxArtifactBytes;
  options.sessionIdleTimeoutMillis = args.idleTimeoutMillis;
  options.faults = faults.value();
  options.authenticate = args.authenticate;
  options.verifyCommittedPayloadOnStart = args.verifyOnStart;
  if (args.authenticate) {
    if (args.keyFile.empty()) {
      std::fprintf(stderr, "cf-agent: --key-file is required unless --insecure-no-auth is given\n");
      return 2;
    }
    auto key = loadKey(args.keyFile);
    if (!key) {
      std::fprintf(stderr, "cf-agent: %s\n", key.error().str().c_str());
      return 2;
    }
    options.key = key.value();
  }

  cf::AgentStore::Recovery recovery;
  cf::LiveRecovery liveRecovery;
  auto agent = cf::TargetAgent::open(options, recovery, liveRecovery);
  if (!agent) {
    std::fprintf(stderr, "cf-agent: %s\n", agent.error().str().c_str());
    return 1;
  }

  cf::Logger::global().info("agent", std::string(cf::buildIdentification()) + " target=" +
                                        args.target.str() + " guarantee=" +
                                        std::string(cf::applyGuaranteeName(args.guarantee)) +
                                        " term=" + std::to_string(agent.value()->state().term.value()) +
                                        " incarnation=" +
                                        agent.value()->state().incarnation.hex().substr(0, 8));
  if (!args.authenticate) {
    cf::Logger::global().warn("agent",
                              "peer authentication is DISABLED: this agent will accept commands "
                              "from any client that can reach its port");
  }
  if (!liveRecovery.detail.empty()) {
    cf::Logger::global().warn("agent", "start-up reconciliation: " + liveRecovery.detail);
  }
  if (liveRecovery.rolledBackUnresolvedPrepare) {
    cf::Logger::global().warn("agent",
                              "an unresolved prepare window was aborted: the target is on its "
                              "previous generation and the delivery must be re-driven");
  }
  if (liveRecovery.adoptedCompletedSwitch) {
    cf::Logger::global().info("agent",
                              "the live pointer recorded a completed activation; durable state "
                              "was reconciled to it (adopted-live-pointer)");
  }
  if (liveRecovery.clearedUnverifiableCommit) {
    cf::Logger::global().warn("agent",
                              "committed state could not be verified against the live area and "
                              "was cleared; the target reports no active generation");
  }
  cf::Logger::global().info("agent", "durable state: " + recovery.render());
  if (!options.faults.empty()) {
    cf::Logger::global().warn("agent", "fault injection armed: " + options.faults.render());
  }

  // Port 0 means "let the operating system choose"; the bound endpoint is
  // reported through --announce-file so a supervisor never has to guess.
  auto listener = cf::Listener::bindTcp(args.listenHost, args.listenPort, 16);
  if (!listener) {
    std::fprintf(stderr, "cf-agent: %s\n", listener.error().str().c_str());
    return 1;
  }
  const cf::Endpoint bound{listener.value()->host(), listener.value()->port()};
  if (!args.announceFile.empty()) {
    const std::string text = bound.str() + "\n";
    const cf::Status written = cf::writeFileAtomic(
        args.announceFile,
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                      text.size()));
    if (!written) {
      std::fprintf(stderr, "cf-agent: cannot write the announce file: %s\n",
                   written.str().c_str());
      return 1;
    }
  }
  cf::Logger::global().info("agent", "listening on " + bound.str());
  installSignalHandlers();

  while (!g_stop.load()) {
    auto accepted = listener.value()->accept(cf::monotonicMillis() + 100);
    if (!accepted) {
      if (accepted.error().code() == cf::ErrorCode::PeerIdleTimeout) {
        continue;
      }
      if (accepted.error().code() == cf::ErrorCode::ShuttingDown) {
        break;
      }
      cf::Logger::global().warn("agent", "accept failed: " + accepted.error().str());
      continue;
    }
    cf::FramedConnection connection(std::move(accepted).value(), cf::kDefaultMaxPayloadBytes);
    // Sessions are serialized: one distributor at a time may drive this target,
    // which is what makes per-target ordering trivial to reason about.
    const cf::Status served = agent.value()->serve(connection);
    if (!served && served.code() != cf::ErrorCode::ConnectionClosed &&
        served.code() != cf::ErrorCode::ConnectionReset &&
        served.code() != cf::ErrorCode::PeerIdleTimeout) {
      cf::Logger::global().debug("agent", "session ended: " + served.str());
    }
    connection.close();
  }

  listener.value()->close();
  cf::Logger::global().info("agent", "stopped cleanly after " +
                                         std::to_string(agent.value()->state().activations) +
                                         " activation(s)");
  return 0;
}
