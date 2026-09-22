// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/process.hpp"

#include <string>

#include "cf/checked.hpp"
#include "cf/contract.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <csignal>
#include <cstring>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace cf {
namespace {

#if defined(_WIN32)

// The C runtime's argument splitting rules: an argument is wrapped in double
// quotes when it contains a space, and backslashes immediately before a quote (or
// before the closing quote) must be doubled.
[[nodiscard]] std::string quoteForWindows(const std::string& argument) {
  const bool needsQuotes =
      argument.empty() || argument.find_first_of(" \t\n\v\"") != std::string::npos;
  if (!needsQuotes) {
    return argument;
  }
  std::string out;
  out.push_back('"');
  std::size_t backslashes = 0;
  for (const char c : argument) {
    if (c == '\\') {
      backslashes += 1;
      continue;
    }
    if (c == '"') {
      out.append(backslashes * 2 + 1, '\\');
      out.push_back('"');
      backslashes = 0;
      continue;
    }
    out.append(backslashes, '\\');
    backslashes = 0;
    out.push_back(c);
  }
  out.append(backslashes * 2, '\\');
  out.push_back('"');
  return out;
}

#else

[[nodiscard]] std::string quoteForPosix(const std::string& argument) {
  std::string out;
  out.push_back('\'');
  for (const char c : argument) {
    if (c == '\'') {
      out.append("'\\''");
    } else {
      out.push_back(c);
    }
  }
  out.push_back('\'');
  return out;
}

#endif

}  // namespace

std::string quoteArgument(const std::string& argument) {
#if defined(_WIN32)
  return quoteForWindows(argument);
#else
  return quoteForPosix(argument);
#endif
}

ChildProcess::~ChildProcess() {
  if (!exited_) {
    (void)kill();
    (void)wait();
  }
}

#if defined(_WIN32)

Result<std::unique_ptr<ChildProcess>> ChildProcess::spawn(const ProcessSpawnOptions& options) {
  if (options.executable.empty()) {
    return Result<std::unique_ptr<ChildProcess>>::fail(ErrorCode::InvalidArgument,
                                                       "executable path must not be empty");
  }
  std::string commandLine = quoteForWindows(options.executable);
  for (const std::string& argument : options.arguments) {
    commandLine.push_back(' ');
    commandLine.append(quoteForWindows(argument));
  }

  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;

  const auto openRedirect = [&attributes](const std::string& path) -> HANDLE {
    if (path.empty()) {
      return INVALID_HANDLE_VALUE;
    }
    return ::CreateFileA(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         &attributes, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  };
  HANDLE stdoutHandle = openRedirect(options.standardOutputPath);
  HANDLE stderrHandle = openRedirect(options.standardErrorPath);

  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput =
      stdoutHandle != INVALID_HANDLE_VALUE ? stdoutHandle : ::GetStdHandle(STD_OUTPUT_HANDLE);
  startup.hStdError =
      stderrHandle != INVALID_HANDLE_VALUE ? stderrHandle : ::GetStdHandle(STD_ERROR_HANDLE);

  PROCESS_INFORMATION information{};
  std::vector<char> mutableCommand(commandLine.begin(), commandLine.end());
  mutableCommand.push_back('\0');
  const char* workingDirectory = options.workingDirectory.empty() ? nullptr
                                                                 : options.workingDirectory.c_str();
  const BOOL created = ::CreateProcessA(options.executable.c_str(), mutableCommand.data(), nullptr,
                                        nullptr, TRUE, 0, nullptr, workingDirectory, &startup,
                                        &information);
  if (stdoutHandle != INVALID_HANDLE_VALUE) {
    ::CloseHandle(stdoutHandle);
  }
  if (stderrHandle != INVALID_HANDLE_VALUE) {
    ::CloseHandle(stderrHandle);
  }
  if (created == FALSE) {
    return Result<std::unique_ptr<ChildProcess>>::fail(
        ErrorCode::OpenFailed, "cannot start child process",
        options.executable + " (error=" + std::to_string(::GetLastError()) + ")");
  }
  ::CloseHandle(information.hThread);
  std::unique_ptr<ChildProcess> child(new ChildProcess());
  child->handle_ = reinterpret_cast<std::uintptr_t>(information.hProcess);
  child->pid_ = information.dwProcessId;
  return Result<std::unique_ptr<ChildProcess>>::ok(std::move(child));
}

Status ChildProcess::kill() {
  if (exited_) {
    return Status::ok();
  }
  if (handle_ == 0) {
    return Status::fail(ErrorCode::Internal, "child process handle is not open");
  }
  if (::TerminateProcess(reinterpret_cast<HANDLE>(handle_), 0xDEADu) == FALSE) {
    return Status::fail(ErrorCode::IoFailure, "TerminateProcess failed",
                        std::to_string(::GetLastError()));
  }
  return Status::ok();
}

Result<int> ChildProcess::wait() {
  if (exited_) {
    return Result<int>::ok(exitCode_);
  }
  if (handle_ == 0) {
    return Result<int>::fail(ErrorCode::Internal, "child process handle is not open");
  }
  const DWORD waited = ::WaitForSingleObject(reinterpret_cast<HANDLE>(handle_), INFINITE);
  if (waited != WAIT_OBJECT_0) {
    return Result<int>::fail(ErrorCode::IoFailure, "WaitForSingleObject failed",
                             std::to_string(waited));
  }
  DWORD code = 0;
  if (::GetExitCodeProcess(reinterpret_cast<HANDLE>(handle_), &code) == FALSE) {
    return Result<int>::fail(ErrorCode::IoFailure, "GetExitCodeProcess failed");
  }
  ::CloseHandle(reinterpret_cast<HANDLE>(handle_));
  handle_ = 0;
  exited_ = true;
  exitCode_ = static_cast<int>(code);
  return Result<int>::ok(exitCode_);
}

bool ChildProcess::running() {
  if (exited_) {
    return false;
  }
  if (handle_ == 0) {
    return false;
  }
  const DWORD waited = ::WaitForSingleObject(reinterpret_cast<HANDLE>(handle_), 0);
  if (waited == WAIT_TIMEOUT) {
    return true;
  }
  (void)wait();
  return false;
}

#else

Result<std::unique_ptr<ChildProcess>> ChildProcess::spawn(const ProcessSpawnOptions& options) {
  if (options.executable.empty()) {
    return Result<std::unique_ptr<ChildProcess>>::fail(ErrorCode::InvalidArgument,
                                                       "executable path must not be empty");
  }
  std::vector<std::string> storage;
  storage.push_back(options.executable);
  for (const std::string& argument : options.arguments) {
    storage.push_back(argument);
  }
  std::vector<char*> argv;
  argv.reserve(storage.size() + 1);
  for (std::string& entry : storage) {
    argv.push_back(entry.data());
  }
  argv.push_back(nullptr);

  const pid_t pid = ::fork();
  if (pid < 0) {
    return Result<std::unique_ptr<ChildProcess>>::fail(ErrorCode::OpenFailed, "fork failed");
  }
  if (pid == 0) {
    if (!options.workingDirectory.empty()) {
      (void)::chdir(options.workingDirectory.c_str());
    }
    if (!options.standardOutputPath.empty()) {
      std::freopen(options.standardOutputPath.c_str(), "ab", stdout);
    }
    if (!options.standardErrorPath.empty()) {
      std::freopen(options.standardErrorPath.c_str(), "ab", stderr);
    }
    ::execv(options.executable.c_str(), argv.data());
    ::_exit(127);
  }
  std::unique_ptr<ChildProcess> child(new ChildProcess());
  child->handle_ = static_cast<std::uintptr_t>(pid);
  child->pid_ = static_cast<std::uint32_t>(pid);
  return Result<std::unique_ptr<ChildProcess>>::ok(std::move(child));
}

Status ChildProcess::kill() {
  if (exited_) {
    return Status::ok();
  }
  if (::kill(static_cast<pid_t>(handle_), SIGKILL) != 0) {
    return Status::fail(ErrorCode::IoFailure, "SIGKILL failed", std::strerror(errno));
  }
  return Status::ok();
}

Result<int> ChildProcess::wait() {
  if (exited_) {
    return Result<int>::ok(exitCode_);
  }
  int status = 0;
  if (::waitpid(static_cast<pid_t>(handle_), &status, 0) < 0) {
    return Result<int>::fail(ErrorCode::IoFailure, "waitpid failed", std::strerror(errno));
  }
  exited_ = true;
  if (WIFEXITED(status)) {
    exitCode_ = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    exitCode_ = 128 + WTERMSIG(status);
  } else {
    exitCode_ = -1;
  }
  return Result<int>::ok(exitCode_);
}

bool ChildProcess::running() {
  if (exited_) {
    return false;
  }
  int status = 0;
  const pid_t result = ::waitpid(static_cast<pid_t>(handle_), &status, WNOHANG);
  if (result == 0) {
    return true;
  }
  if (result > 0) {
    exited_ = true;
    if (WIFEXITED(status)) {
      exitCode_ = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      exitCode_ = 128 + WTERMSIG(status);
    }
    return false;
  }
  return false;
}

#endif

}  // namespace cf
