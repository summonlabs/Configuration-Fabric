// Configuration Fabric validation suite - multiprocess harness.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Building blocks for tests that must run the real executables over real
// sockets: temporary directories, artifact construction, deployment plans, and
// process wrappers that can be killed at any moment.

#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "cf/artifact.hpp"
#include "cf/codec.hpp"
#include "cf/hash.hpp"
#include "cf/ids.hpp"
#include "cf/journal.hpp"
#include "cf/plan.hpp"
#include "cf/process.hpp"
#include "cf/rng.hpp"
#include "cf/state.hpp"
#include "cf/transport.hpp"
#include "testing.hpp"

#ifndef CF_TEST_AGENT_PATH
#define CF_TEST_AGENT_PATH "cf-agent"
#endif
#ifndef CF_TEST_CONTROLLER_PATH
#define CF_TEST_CONTROLLER_PATH "cf-controller"
#endif
#ifndef CF_TEST_CFCTL_PATH
#define CF_TEST_CFCTL_PATH "cfctl"
#endif

namespace cf::test {

/// Removes its directory tree when it goes out of scope, so a passing run leaves
/// no debris behind. CF_KEEP_TEMP=1 keeps the tree for post-mortem inspection.
class TempDir final {
 public:
  explicit TempDir(std::string_view label) {
    const std::array<std::uint8_t, 16> suffix = secureRandom128();
    root_ = std::filesystem::temp_directory_path() /
            ("cf-test-" + std::string(label) + "-" + toHex(std::span<const std::uint8_t>(
                                                               suffix.data(), suffix.size()))
                                                   .substr(0, 12));
    std::error_code ec;
    std::filesystem::create_directories(root_, ec);
  }

  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  ~TempDir() {
    if (std::getenv("CF_KEEP_TEMP") != nullptr) {
      std::fprintf(stderr, "    (kept %s)\n", root_.string().c_str());
      return;
    }
    std::error_code ec;
    std::filesystem::remove_all(root_, ec);
  }

  [[nodiscard]] std::string path() const { return root_.string(); }
  [[nodiscard]] std::string child(const std::string& name) const {
    return (root_ / name).string();
  }

 private:
  std::filesystem::path root_;
};

inline void writeTextFile(const std::string& path, std::string_view content) {
  std::filesystem::path target(path);
  if (target.has_parent_path()) {
    std::error_code ec;
    std::filesystem::create_directories(target.parent_path(), ec);
  }
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(content.data(), static_cast<std::streamsize>(content.size()));
}

[[nodiscard]] inline std::string readTextFile(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return std::string();
  }
  std::string content((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
  return content;
}

[[nodiscard]] inline std::string sharedSecret() {
  return std::string("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
}

/// Waits for a file to appear and returns its trimmed content. Polls with a
/// bounded number of attempts; a missing file is a test failure, not a hang.
[[nodiscard]] inline bool waitForFile(const std::string& path, std::string* content,
                                      int attempts = 400) {
  for (int attempt = 0; attempt < attempts; ++attempt) {
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
      const std::string text = readTextFile(path);
      if (!text.empty()) {
        std::string trimmed;
        for (const char c : text) {
          if (c != '\n' && c != '\r' && c != ' ') {
            trimmed.push_back(c);
          }
        }
        if (!trimmed.empty()) {
          *content = trimmed;
          return true;
        }
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return false;
}

/// A running process with its own directories and announce file.
class ServiceProcess final {
 public:
  ServiceProcess(std::string executable, std::vector<std::string> arguments,
                 std::string announceFile, std::string logFile)
      : executable_(std::move(executable)),
        arguments_(std::move(arguments)),
        announceFile_(std::move(announceFile)),
        logFile_(std::move(logFile)) {}

  ServiceProcess(const ServiceProcess&) = delete;
  ServiceProcess& operator=(const ServiceProcess&) = delete;

  [[nodiscard]] bool start() {
    ProcessSpawnOptions options;
    options.executable = executable_;
    options.arguments = arguments_;
    options.standardOutputPath = logFile_ + ".stdout";
    options.standardErrorPath = logFile_ + ".stderr";
    auto child = ChildProcess::spawn(options);
    if (!child) {
      return false;
    }
    process_ = std::move(child).value();
    return waitForFile(announceFile_, &endpoint_);
  }

  /// Hard kill: no cleanup, no flush, exactly like a power loss.
  [[nodiscard]] bool kill() {
    if (process_ == nullptr) {
      return false;
    }
    return static_cast<bool>(process_->kill());
  }

  [[nodiscard]] bool running() { return process_ != nullptr && process_->running(); }

  [[nodiscard]] int wait() {
    if (process_ == nullptr) {
      return -1;
    }
    auto code = process_->wait();
    return code ? code.value() : -1;
  }

  [[nodiscard]] const std::string& endpoint() const { return endpoint_; }
  [[nodiscard]] std::string logText() const {
    return readTextFile(logFile_) + readTextFile(logFile_ + ".stderr") +
           readTextFile(logFile_ + ".stdout");
  }
  [[nodiscard]] std::uint32_t pid() const { return process_ != nullptr ? process_->pid() : 0; }

  ~ServiceProcess() {
    if (process_ != nullptr && process_->running()) {
      (void)process_->kill();
      (void)process_->wait();
    }
  }

 private:
  std::string executable_;
  std::vector<std::string> arguments_;
  std::string announceFile_;
  std::string logFile_;
  std::unique_ptr<ChildProcess> process_;
  std::string endpoint_;
};

/// Runs cfctl to completion and returns its standard output.
[[nodiscard]] inline std::string runCtl(const std::vector<std::string>& arguments,
                                        int* exitCode = nullptr) {
  const std::array<std::uint8_t, 16> suffix = secureRandom128();
  const std::string outputPath =
      (std::filesystem::temp_directory_path() /
       ("cf-ctl-" + toHex(std::span<const std::uint8_t>(suffix.data(), suffix.size())).substr(0, 10) +
        ".out"))
          .string();
  ProcessSpawnOptions options;
  options.executable = CF_TEST_CFCTL_PATH;
  options.arguments = arguments;
  options.standardOutputPath = outputPath;
  options.standardErrorPath = outputPath + ".err";
  auto child = ChildProcess::spawn(options);
  if (!child) {
    if (exitCode != nullptr) {
      *exitCode = -1;
    }
    return std::string();
  }
  auto code = child.value()->wait();
  if (exitCode != nullptr) {
    *exitCode = code ? code.value() : -1;
  }
  std::string output = readTextFile(outputPath) + readTextFile(outputPath + ".err");
  std::error_code ec;
  std::filesystem::remove(outputPath, ec);
  std::filesystem::remove(outputPath + ".err", ec);
  return output;
}

/// One target's configuration assignment for a plan.
struct TargetSpec {
  std::string target{"rtr-1"};
  std::string configKey{"fabric/underlay"};
  std::string artifactId{"cfg/underlay"};
  std::uint64_t generation{1};
  std::uint64_t revision{1};
  std::string guarantee{"atomic-activate"};
  std::string requirement{"require-atomic"};
  std::string endpoint;
  std::string source;
  std::string body{"hostname rtr-1\n"};
  std::string digest;
  std::size_t size{0};
};

/// Builds a deployment plan for the given targets and writes the artifact files.
[[nodiscard]] inline std::string
writePlan(const TempDir& directory, const std::string& setName,
          const std::vector<TargetSpec>& specs, std::string* artifactDirectory) {
  std::string text = "cf-plan 1\nset-id " + setName + "\n";
  const std::string artifacts = directory.child("plan-artifacts");
  std::error_code ec;
  std::filesystem::create_directories(artifacts, ec);
  if (artifactDirectory != nullptr) {
    *artifactDirectory = artifacts;
  }
  for (const TargetSpec& spec : specs) {
    const std::string path = artifacts + "/" + spec.target + "-" + spec.artifactId + ".cfg";
    std::string body = spec.body;
    if (body.empty()) {
      body = "hostname " + spec.target + "\n";
    }
    writeTextFile(path, body);
    const cf::Sha256Digest digest = cf::sha256(body);
    const cf::Digest contentDigest = cf::Digest::fromBytes(digest);
    text.append("target ").append(spec.target).append("\n");
    text.append("  class network-device\n");
    text.append("  guarantee ").append(spec.guarantee).append("\n");
    text.append("  config-key ").append(spec.configKey).append("\n");
    text.append("  artifact ").append(spec.artifactId).append("\n");
    text.append("  revision ").append(std::to_string(spec.revision)).append("\n");
    text.append("  generation ").append(std::to_string(spec.generation)).append("\n");
    text.append("  schema cf.underlay\n");
    text.append("  schema-version 1\n");
    text.append("  digest ").append(contentDigest.hex()).append("\n");
    text.append("  size ").append(std::to_string(body.size())).append("\n");
    text.append("  requires ").append(spec.requirement).append("\n");
    text.append("  media-type text/plain\n");
    text.append("  producer validation-suite\n");
    text.append("  source ").append(spec.source.empty() ? path : spec.source).append("\n");
    if (!spec.endpoint.empty()) {
      text.append("  endpoint ").append(spec.endpoint).append("\n");
    }
    text.append("end\n");
  }
  const std::string planPath = directory.child(setName + ".plan");
  writeTextFile(planPath, text);
  return planPath;
}

[[nodiscard]] inline std::string keyFileFor(const TempDir& directory) {
  const std::string path = directory.child("secret.key");
  writeTextFile(path, sharedSecret());
  return path;
}

/// Convenience: start an agent process.
[[nodiscard]] inline std::unique_ptr<ServiceProcess>
startAgent(const TempDir& directory, const std::string& target, const std::string& stateDir,
           const std::string& guarantee = "atomic-activate", const std::string& faults = "",
           bool authenticate = true, const std::string& label = "agent") {
  const std::string announce = directory.child(label + ".endpoint");
  std::vector<std::string> arguments = {"--target", target, "--state", stateDir, "--listen",
                                        "127.0.0.1:0", "--announce-file", announce,
                                        "--log-level", "debug", "--log-file",
                                        directory.child(label + ".log")};
  if (authenticate) {
    arguments.push_back("--key-file");
    arguments.push_back(keyFileFor(directory));
  } else {
    arguments.push_back("--insecure-no-auth");
  }
  arguments.push_back("--guarantee");
  arguments.push_back(guarantee);
  if (!faults.empty()) {
    arguments.push_back("--fault-inject");
    arguments.push_back(faults);
  }
  auto service = std::make_unique<ServiceProcess>(CF_TEST_AGENT_PATH, std::move(arguments),
                                                  announce, directory.child(label + ".log"));
  // Starting here keeps every caller honest: a helper that returned an unstarted
  // process would make each test look like a runtime failure.
  (void)service->start();
  return service;
}

/// Convenience: start a controller process.
[[nodiscard]] inline std::unique_ptr<ServiceProcess>
startController(const TempDir& directory, const std::string& node, const std::string& stateDir,
                const std::string& artifactDir, const std::vector<std::string>& plans,
                const std::string& faults = "", const std::string& extraAttempts = "3",
                bool authenticate = true, const std::string& label = "controller",
                std::uint32_t exitAfterMillis = 0, const std::string& keyPath = std::string()) {
  const std::string announce = directory.child(label + ".endpoint");
  std::vector<std::string> arguments = {"--node",    node,        "--state", stateDir,
                                        "--artifacts", artifactDir, "--control", "127.0.0.1:0",
                                        "--announce-file", announce, "--log-level", "debug",
                                        "--log-file", directory.child(label + ".log"),
                                        "--max-attempts", extraAttempts, "--sessions", "2"};
  if (authenticate) {
    arguments.push_back("--key-file");
    arguments.push_back(keyPath.empty() ? keyFileFor(directory) : keyPath);
  } else {
    arguments.push_back("--insecure-no-auth");
  }
  for (const std::string& plan : plans) {
    arguments.push_back("--plan");
    arguments.push_back(plan);
  }
  if (!faults.empty()) {
    arguments.push_back("--fault-inject");
    arguments.push_back(faults);
  }
  if (exitAfterMillis != 0) {
    arguments.push_back("--exit-after-ms");
    arguments.push_back(std::to_string(exitAfterMillis));
  }
  arguments.push_back("--liveness-fresh-ms");
  arguments.push_back("3000");
  auto service = std::make_unique<ServiceProcess>(CF_TEST_CONTROLLER_PATH, std::move(arguments),
                                                  announce, directory.child(label + ".log"));
  (void)service->start();
  return service;
}

/// Polls convergence until predicate holds or the attempt budget is exhausted.
template <class Predicate>
[[nodiscard]] inline bool waitForConvergence(const std::string& endpoint,
                                             const std::string& keyFile, Predicate predicate,
                                             std::string* lastOutput, int attempts = 400) {
  for (int attempt = 0; attempt < attempts; ++attempt) {
    const std::string output = runCtl(
        {"--endpoint", endpoint, "--key-file", keyFile, "converge"});
    if (lastOutput != nullptr) {
      *lastOutput = output;
    }
    if (predicate(output)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  return false;
}

[[nodiscard]] inline bool containsText(const std::string& haystack, std::string_view needle) {
  return haystack.find(needle) != std::string::npos;
}

/// Reads the live pointer of one config key from an agent state directory.
[[nodiscard]] inline std::string readLivePointer(const std::string& stateDir,
                                                 const std::string& key) {
  return readTextFile(stateDir + "/live/" + key + "/current");
}

}  // namespace cf::test
