// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/log.hpp"

#include <chrono>
#include <cstring>
#include <ctime>
#include <string>
#include <thread>

#include "cf/contract.hpp"

namespace cf {
namespace {

[[nodiscard]] std::string_view trimTrailingNewlines(std::string_view text) noexcept {
  while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
    text.remove_suffix(1);
  }
  return text;
}

}  // namespace

std::string_view logLevelName(LogLevel level) noexcept {
  switch (level) {
    case LogLevel::Trace:
      return "TRACE";
    case LogLevel::Debug:
      return "DEBUG";
    case LogLevel::Info:
      return "INFO";
    case LogLevel::Warn:
      return "WARN";
    case LogLevel::Error:
      return "ERROR";
    case LogLevel::Off:
      return "OFF";
  }
  return "UNKNOWN";
}

bool parseLogLevel(std::string_view text, LogLevel& out) noexcept {
  if (text == "trace") {
    out = LogLevel::Trace;
  } else if (text == "debug") {
    out = LogLevel::Debug;
  } else if (text == "info") {
    out = LogLevel::Info;
  } else if (text == "warn") {
    out = LogLevel::Warn;
  } else if (text == "error") {
    out = LogLevel::Error;
  } else if (text == "off") {
    out = LogLevel::Off;
  } else {
    return false;
  }
  return true;
}

Logger& Logger::global() {
  static Logger instance;
  return instance;
}

Logger::~Logger() {
  if (ownsFile_ && file_ != nullptr) {
    std::fclose(file_);
  }
}

void Logger::setLevel(LogLevel level) noexcept {
  level_.store(level, std::memory_order_relaxed);
}

Status Logger::setOutputFile(const std::string& path) {
  std::FILE* opened = nullptr;
  if (!path.empty()) {
    opened = std::fopen(path.c_str(), "ab");
    if (opened == nullptr) {
      return Status::fail(ErrorCode::OpenFailed, "cannot open log file", path);
    }
  }
  std::lock_guard<std::mutex> guard(mutex_);
  if (ownsFile_ && file_ != nullptr) {
    std::fclose(file_);
  }
  file_ = opened;
  ownsFile_ = opened != nullptr;
  return Status::ok();
}

void Logger::flush() {
  std::lock_guard<std::mutex> guard(mutex_);
  std::fflush(file_ != nullptr ? file_ : stderr);
}

void Logger::log(LogLevel level, std::string_view component, std::string_view message) {
  if (!enabled(level)) {
    return;
  }
  const std::string timestamp = formatUtcMillis(nowUnixMillis());
  std::string line;
  line.reserve(160);
  line.append(timestamp);
  line.push_back(' ');
  line.append(logLevelName(level));
  line.push_back(' ');
  const std::string_view trimmedComponent = trimTrailingNewlines(component);
  line.append(trimmedComponent.empty() ? std::string_view("cf") : trimmedComponent);
  line.append(": ");
  line.append(trimTrailingNewlines(message));

  if (line.size() > kMaxLogLineBytes) {
    line.resize(kMaxLogLineBytes - 16);
    line.append("...<truncated>");
    truncated_.fetch_add(1, std::memory_order_relaxed);
  }
  line.push_back('\n');

  std::lock_guard<std::mutex> guard(mutex_);
  std::FILE* target = file_ != nullptr ? file_ : stderr;
  const std::size_t written = std::fwrite(line.data(), 1, line.size(), target);
  if (written != line.size()) {
    writeFailures_.fetch_add(1, std::memory_order_relaxed);
  }
  // Log records are the operator's crash forensics; never buffer them away.
  std::fflush(target);
}

std::string formatUtcMillis(std::int64_t unixMillis) {
  const std::int64_t seconds = unixMillis / 1000;
  const std::int64_t millis = unixMillis - (seconds * 1000);
  std::time_t time = static_cast<std::time_t>(seconds);
  std::tm broken{};
#if defined(_WIN32)
  if (gmtime_s(&broken, &time) != 0) {
    return "1970-01-01T00:00:00.000Z";
  }
#else
  if (gmtime_r(&time, &broken) == nullptr) {
    return "1970-01-01T00:00:00.000Z";
  }
#endif
  char buffer[40] = {};
  const int written = std::snprintf(
      buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", broken.tm_year + 1900,
      broken.tm_mon + 1, broken.tm_mday, broken.tm_hour, broken.tm_min, broken.tm_sec,
      static_cast<int>(millis));
  if (written <= 0) {
    return "1970-01-01T00:00:00.000Z";
  }
  return std::string(buffer, static_cast<std::size_t>(written));
}

std::int64_t nowUnixMillis() noexcept {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

std::int64_t monotonicMillis() noexcept {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

}  // namespace cf
