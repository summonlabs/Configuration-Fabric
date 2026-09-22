// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Error model. The runtime does not use exceptions for control flow: every
// fallible operation returns a Status or a Result<T> carrying a typed Error.
//
// Error codes are part of the stable wire and persistence contract: their
// numeric values are never renumbered, only appended to.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace cf {

/// Typed failure classification. Numeric values are stable.
enum class ErrorCode : std::uint16_t {
  Ok = 0,

  // Input / value errors (100-199)
  InvalidArgument = 100,
  OutOfRange = 101,
  ArithmeticOverflow = 102,
  MalformedInput = 103,
  UnsupportedVersion = 104,
  UnsupportedFeature = 105,
  MissingField = 106,

  // Lookup / conflict (200-299)
  NotFound = 200,
  AlreadyExists = 201,
  Conflict = 202,
  PreconditionFailed = 203,

  // Domain, authority and integrity (300-399)
  StaleGeneration = 300,
  StaleEpoch = 301,
  FencedIncarnation = 302,
  GenerationConflict = 303,
  DigestMismatch = 304,
  IntegrityFailure = 305,
  SizeMismatch = 306,
  SchemaUnsupported = 307,
  GuaranteeUnsupported = 308,
  PolicyDenied = 309,
  Unauthenticated = 310,
  Unauthorized = 311,
  ReplayDetected = 312,
  DuplicateSuppressed = 313,
  Retired = 314,

  // Protocol (400-499)
  ProtocolViolation = 400,
  OversizePayload = 401,
  TruncatedFrame = 402,
  ReorderedFrame = 403,
  UnexpectedMessage = 404,
  CapabilityMismatch = 405,

  // Transport / I/O (500-599)
  IoFailure = 500,
  ConnectionRefused = 501,
  ConnectionReset = 502,
  ConnectionClosed = 503,
  PeerIdleTimeout = 504,
  OpenFailed = 505,

  // Resource bounds (600-699)
  CapacityExceeded = 600,
  QueueFull = 601,
  StoreFull = 602,
  LimitExceeded = 603,

  // Lifecycle / apply (700-799)
  IllegalTransition = 700,
  ApplyFailed = 701,
  ApplyUncertain = 702,
  NotPrepared = 703,
  RolledBack = 704,
  ArtifactUnavailable = 705,

  // Control flow (800-899)
  Cancelled = 800,
  ShuttingDown = 801,
  Busy = 802,
  Internal = 803,
};

/// Deterministic retry classification. Every error code maps to exactly one
/// directive; the mapping is total and is part of the runtime's contract.
enum class RetryDirective : std::uint8_t {
  /// The failure is permanent for this operation. Re-sending is pointless.
  DoNotRetry = 0,
  /// Retry immediately within the current session (transient, self-clearing).
  RetryNow = 1,
  /// Retry within the current session after a bounded backoff.
  RetryWithBackoff = 2,
  /// The session is unusable; re-establish it, then retry the operation.
  RetryNewSession = 3,
  /// Do not retry blindly: reconcile authoritative state with the peer first,
  /// then decide. Used where the outcome of an in-flight operation is unknown.
  RetryAfterReconcile = 4,
  /// Terminal for the target/attempt: the peer or the operation is retired.
  Terminal = 5,
};

[[nodiscard]] std::string_view errorCodeName(ErrorCode code) noexcept;
[[nodiscard]] std::string_view retryDirectiveName(RetryDirective directive) noexcept;

/// Total, deterministic classification of an error code.
[[nodiscard]] RetryDirective retryDirectiveFor(ErrorCode code) noexcept;
/// True when the code indicates stale authority/generation/incarnation replay.
[[nodiscard]] bool isFencingCode(ErrorCode code) noexcept;
/// True when the code indicates an integrity violation (digest/CRC/size).
[[nodiscard]] bool isIntegrityCode(ErrorCode code) noexcept;
/// True when the code means "the operation may or may not have happened".
[[nodiscard]] bool isIndeterminateCode(ErrorCode code) noexcept;
/// Parse an error code from its stable name (used by diagnostics tooling).
[[nodiscard]] ErrorCode errorCodeFromName(std::string_view name) noexcept;

/// A typed error: stable code plus human-readable message and structured detail.
class Error {
 public:
  Error() noexcept = default;
  explicit Error(ErrorCode code, std::string message = std::string())
      : code_(code), message_(std::move(message)) {}
  Error(ErrorCode code, std::string message, std::string detail)
      : code_(code), message_(std::move(message)), detail_(std::move(detail)) {}

  [[nodiscard]] ErrorCode code() const noexcept { return code_; }
  [[nodiscard]] std::string_view codeName() const noexcept { return errorCodeName(code_); }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }
  [[nodiscard]] RetryDirective retry() const noexcept { return retryDirectiveFor(code_); }
  [[nodiscard]] bool ok() const noexcept { return code_ == ErrorCode::Ok; }

  /// "code: message" plus " (detail)" when a detail is present. Deterministic.
  [[nodiscard]] std::string str() const;

  void setDetail(std::string detail) { detail_ = std::move(detail); }

 private:
  ErrorCode code_{ErrorCode::Ok};
  std::string message_;
  std::string detail_;
};

/// Status: the outcome of an operation with no value.
class Status {
 public:
  Status() noexcept = default;
  Status(Error error) : error_(std::move(error)) {}

  [[nodiscard]] static Status ok() noexcept { return Status(); }
  [[nodiscard]] static Status fail(ErrorCode code, std::string message = std::string()) {
    return Status(Error(code, std::move(message)));
  }
  [[nodiscard]] static Status fail(ErrorCode code, std::string message, std::string detail) {
    return Status(Error(code, std::move(message), std::move(detail)));
  }
  [[nodiscard]] static Status fail(Error error) { return Status(std::move(error)); }

  [[nodiscard]] bool hasValue() const noexcept { return error_.ok(); }
  [[nodiscard]] explicit operator bool() const noexcept { return error_.ok(); }
  [[nodiscard]] const Error& error() const noexcept { return error_; }
  [[nodiscard]] ErrorCode code() const noexcept { return error_.code(); }
  [[nodiscard]] std::string str() const { return error_.str(); }

 private:
  Error error_{};
};

/// Result<T>: either a value or a typed error. Exactly one is present.
template <class T>
class Result {
 public:
  using value_type = T;

  Result(T value) : storage_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
  Result(Error error) : storage_(std::move(error)) {}      // NOLINT(google-explicit-constructor)

  [[nodiscard]] static Result ok(T value) { return Result(std::move(value)); }
  [[nodiscard]] static Result fail(ErrorCode code, std::string message = std::string()) {
    return Result(Error(code, std::move(message)));
  }
  [[nodiscard]] static Result fail(ErrorCode code, std::string message, std::string detail) {
    return Result(Error(code, std::move(message), std::move(detail)));
  }
  [[nodiscard]] static Result fail(Error error) { return Result(std::move(error)); }
  /// Propagates a failed Status into a Result<T> without unwrapping by hand.
  [[nodiscard]] static Result fail(const Status& status) { return Result(status.error()); }

  [[nodiscard]] bool hasValue() const noexcept { return storage_.index() == 0; }
  [[nodiscard]] explicit operator bool() const noexcept { return hasValue(); }

  /// Precondition: hasValue(). Throws std::bad_variant_access otherwise.
  [[nodiscard]] T& value() & { return std::get<0>(storage_); }
  [[nodiscard]] const T& value() const& { return std::get<0>(storage_); }
  [[nodiscard]] T&& value() && { return std::get<0>(std::move(storage_)); }

  /// Non-throwing access. Null when the result carries an error.
  [[nodiscard]] T* tryValue() noexcept { return std::get_if<0>(&storage_); }
  [[nodiscard]] const T* tryValue() const noexcept { return std::get_if<0>(&storage_); }

  [[nodiscard]] const Error& error() const noexcept { return std::get<1>(storage_); }

  [[nodiscard]] T valueOr(T fallback) const {
    const T* v = tryValue();
    return v != nullptr ? *v : std::move(fallback);
  }

  template <class F>
  auto map(F&& fn) const -> Result<std::invoke_result_t<F, const T&>> {
    using U = std::invoke_result_t<F, const T&>;
    const T* v = tryValue();
    if (v == nullptr) {
      return Result<U>::fail(error());
    }
    return Result<U>::ok(fn(*v));
  }

 private:
  std::variant<T, Error> storage_;
};

#define CF_TRY_CONCAT_INNER(a, b) a##b
#define CF_TRY_CONCAT(a, b) CF_TRY_CONCAT_INNER(a, b)

#define CF_TRY_ASSIGN_IMPL(lhs, expr, name) \
  auto&& name = (expr);                    \
  if (!name) {                             \
    return name.error();                   \
  }                                        \
  lhs = std::move(name).value()

/// Evaluates expr, propagates its Error on failure, and otherwise binds the
/// value to lhs. lhs may be a declaration, which is the point: the bound name
/// must be visible in the enclosing scope after the statement. Each expansion
/// uses a unique internal name so several may appear in one scope.
#define CF_TRY_ASSIGN(lhs, expr) \
  CF_TRY_ASSIGN_IMPL(lhs, expr, CF_TRY_CONCAT(cf_try_result_, __COUNTER__))

#define CF_TRY(expr)                                \
  do {                                              \
    auto&& cf_try_result_ = (expr);                 \
    if (!cf_try_result_) {                          \
      return cf_try_result_.error();                \
    }                                               \
  } while (false)

}  // namespace cf
