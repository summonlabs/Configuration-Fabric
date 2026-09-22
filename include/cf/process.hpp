// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Independent process control.
//
// The runtime's distributed claims are proven with independent OS processes:
// validation spawns real controller and agent executables, kills them with the
// platform's hard-kill primitive and restarts them. This wrapper is the only
// place that knows how to do that.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cf/result.hpp"

namespace cf {

struct ProcessSpawnOptions {
  /// Absolute path to the executable.
  std::string executable;
  /// Arguments, excluding argv[0].
  std::vector<std::string> arguments;
  /// Working directory. Empty inherits the parent's.
  std::string workingDirectory;
  /// Destination for the child's standard streams. Empty means discard.
  std::string standardOutputPath;
  std::string standardErrorPath;
  /// Extra environment entries in "NAME=VALUE" form, applied on top of the
  /// parent environment.
  std::vector<std::string> environment;
};

class ChildProcess final {
 public:
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ~ChildProcess();

  [[nodiscard]] static Result<std::unique_ptr<ChildProcess>> spawn(
      const ProcessSpawnOptions& options);

  /// Hard kill (TerminateProcess / SIGKILL). This is the primitive the failure
  /// injection tests use: no cleanup handlers run, exactly like a power loss.
  [[nodiscard]] Status kill();
  /// Blocks until the process exits and returns its exit code.
  [[nodiscard]] Result<int> wait();
  /// Non-blocking: returns true while the process is still running.
  [[nodiscard]] bool running();
  [[nodiscard]] std::uint32_t pid() const noexcept { return pid_; }
  [[nodiscard]] bool exited() const noexcept { return exited_; }
  [[nodiscard]] int exitCode() const noexcept { return exitCode_; }

 private:
  ChildProcess() = default;

  std::uintptr_t handle_{0};
  std::uint32_t pid_{0};
  bool exited_{false};
  int exitCode_{0};
};

/// Quotes one argument according to the platform's command-line rules. Exposed
/// so tests can verify the quoting rather than guess at it.
[[nodiscard]] std::string quoteArgument(const std::string& argument);

}  // namespace cf
