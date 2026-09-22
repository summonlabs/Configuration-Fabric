// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Diagnostics logging.
//
// Deliberately callback-free: there is no sink registration, so no logging call
// can re-enter user code while a lock is held. The only output target is a
// FILE* chosen at start-up. Lines are bounded; an oversized line is truncated
// with an explicit marker rather than being allowed to grow without limit.

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <string_view>

#include "cf/result.hpp"

namespace cf {

enum class LogLevel : std::uint8_t {
  Trace = 0,
  Debug = 1,
  Info = 2,
  Warn = 3,
  Error = 4,
  Off = 5,
};

[[nodiscard]] std::string_view logLevelName(LogLevel level) noexcept;
[[nodiscard]] bool parseLogLevel(std::string_view text, LogLevel& out) noexcept;

inline constexpr std::size_t kMaxLogLineBytes = 2048;

class Logger final {
 public:
  [[nodiscard]] static Logger& global();

  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

  void setLevel(LogLevel level) noexcept;
  [[nodiscard]] LogLevel level() const noexcept { return level_.load(std::memory_order_relaxed); }
  [[nodiscard]] bool enabled(LogLevel level) const noexcept {
    return static_cast<std::uint8_t>(level) >= static_cast<std::uint8_t>(level_.load(std::memory_order_relaxed));
  }

  /// Redirects output. An empty path means standard error (the default).
  Status setOutputFile(const std::string& path);
  void flush();

  void log(LogLevel level, std::string_view component, std::string_view message);

  void trace(std::string_view component, std::string_view message) {
    log(LogLevel::Trace, component, message);
  }
  void debug(std::string_view component, std::string_view message) {
    log(LogLevel::Debug, component, message);
  }
  void info(std::string_view component, std::string_view message) {
    log(LogLevel::Info, component, message);
  }
  void warn(std::string_view component, std::string_view message) {
    log(LogLevel::Warn, component, message);
  }
  void error(std::string_view component, std::string_view message) {
    log(LogLevel::Error, component, message);
  }

  /// Number of lines suppressed because they exceeded kMaxLogLineBytes before
  /// truncation, and number of writes that failed. Exposed so tests can assert
  /// that resource bounds actually engage.
  [[nodiscard]] std::uint64_t truncatedLines() const noexcept {
    return truncated_.load(std::memory_order_relaxed);
  }
  [[nodiscard]] std::uint64_t writeFailures() const noexcept {
    return writeFailures_.load(std::memory_order_relaxed);
  }

 private:
  Logger() = default;
  ~Logger();

  std::atomic<LogLevel> level_{LogLevel::Info};
  std::atomic<std::uint64_t> truncated_{0};
  std::atomic<std::uint64_t> writeFailures_{0};
  std::mutex mutex_;
  std::FILE* file_{nullptr};
  bool ownsFile_{false};
};

/// Formats a UTC timestamp as 2026-01-01T00:00:00.000Z. Deterministic given the
/// input milliseconds since the Unix epoch.
[[nodiscard]] std::string formatUtcMillis(std::int64_t unixMillis);

/// Milliseconds since the Unix epoch, from the system clock.
[[nodiscard]] std::int64_t nowUnixMillis() noexcept;
/// Monotonic milliseconds since an unspecified origin. Never goes backwards, so
/// it is the only clock used for deadlines and timeouts.
[[nodiscard]] std::int64_t monotonicMillis() noexcept;

}  // namespace cf
