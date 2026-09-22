// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/result.hpp"

#include <string_view>
#include <unordered_map>

namespace cf {

std::string_view errorCodeName(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::Ok:
      return "Ok";
    case ErrorCode::InvalidArgument:
      return "InvalidArgument";
    case ErrorCode::OutOfRange:
      return "OutOfRange";
    case ErrorCode::ArithmeticOverflow:
      return "ArithmeticOverflow";
    case ErrorCode::MalformedInput:
      return "MalformedInput";
    case ErrorCode::UnsupportedVersion:
      return "UnsupportedVersion";
    case ErrorCode::UnsupportedFeature:
      return "UnsupportedFeature";
    case ErrorCode::MissingField:
      return "MissingField";
    case ErrorCode::NotFound:
      return "NotFound";
    case ErrorCode::AlreadyExists:
      return "AlreadyExists";
    case ErrorCode::Conflict:
      return "Conflict";
    case ErrorCode::PreconditionFailed:
      return "PreconditionFailed";
    case ErrorCode::StaleGeneration:
      return "StaleGeneration";
    case ErrorCode::StaleEpoch:
      return "StaleEpoch";
    case ErrorCode::FencedIncarnation:
      return "FencedIncarnation";
    case ErrorCode::GenerationConflict:
      return "GenerationConflict";
    case ErrorCode::DigestMismatch:
      return "DigestMismatch";
    case ErrorCode::IntegrityFailure:
      return "IntegrityFailure";
    case ErrorCode::SizeMismatch:
      return "SizeMismatch";
    case ErrorCode::SchemaUnsupported:
      return "SchemaUnsupported";
    case ErrorCode::GuaranteeUnsupported:
      return "GuaranteeUnsupported";
    case ErrorCode::PolicyDenied:
      return "PolicyDenied";
    case ErrorCode::Unauthenticated:
      return "Unauthenticated";
    case ErrorCode::Unauthorized:
      return "Unauthorized";
    case ErrorCode::ReplayDetected:
      return "ReplayDetected";
    case ErrorCode::DuplicateSuppressed:
      return "DuplicateSuppressed";
    case ErrorCode::Retired:
      return "Retired";
    case ErrorCode::ProtocolViolation:
      return "ProtocolViolation";
    case ErrorCode::OversizePayload:
      return "OversizePayload";
    case ErrorCode::TruncatedFrame:
      return "TruncatedFrame";
    case ErrorCode::ReorderedFrame:
      return "ReorderedFrame";
    case ErrorCode::UnexpectedMessage:
      return "UnexpectedMessage";
    case ErrorCode::CapabilityMismatch:
      return "CapabilityMismatch";
    case ErrorCode::IoFailure:
      return "IoFailure";
    case ErrorCode::ConnectionRefused:
      return "ConnectionRefused";
    case ErrorCode::ConnectionReset:
      return "ConnectionReset";
    case ErrorCode::ConnectionClosed:
      return "ConnectionClosed";
    case ErrorCode::PeerIdleTimeout:
      return "PeerIdleTimeout";
    case ErrorCode::OpenFailed:
      return "OpenFailed";
    case ErrorCode::CapacityExceeded:
      return "CapacityExceeded";
    case ErrorCode::QueueFull:
      return "QueueFull";
    case ErrorCode::StoreFull:
      return "StoreFull";
    case ErrorCode::LimitExceeded:
      return "LimitExceeded";
    case ErrorCode::IllegalTransition:
      return "IllegalTransition";
    case ErrorCode::ApplyFailed:
      return "ApplyFailed";
    case ErrorCode::ApplyUncertain:
      return "ApplyUncertain";
    case ErrorCode::NotPrepared:
      return "NotPrepared";
    case ErrorCode::RolledBack:
      return "RolledBack";
    case ErrorCode::ArtifactUnavailable:
      return "ArtifactUnavailable";
    case ErrorCode::Cancelled:
      return "Cancelled";
    case ErrorCode::ShuttingDown:
      return "ShuttingDown";
    case ErrorCode::Busy:
      return "Busy";
    case ErrorCode::Internal:
      return "Internal";
  }
  return "Unknown";
}

std::string_view retryDirectiveName(RetryDirective directive) noexcept {
  switch (directive) {
    case RetryDirective::DoNotRetry:
      return "DoNotRetry";
    case RetryDirective::RetryNow:
      return "RetryNow";
    case RetryDirective::RetryWithBackoff:
      return "RetryWithBackoff";
    case RetryDirective::RetryNewSession:
      return "RetryNewSession";
    case RetryDirective::RetryAfterReconcile:
      return "RetryAfterReconcile";
    case RetryDirective::Terminal:
      return "Terminal";
  }
  return "Unknown";
}

RetryDirective retryDirectiveFor(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::Ok:
      return RetryDirective::DoNotRetry;

    // Permanent input/domain errors: re-sending identical bytes cannot help.
    case ErrorCode::InvalidArgument:
    case ErrorCode::OutOfRange:
    case ErrorCode::ArithmeticOverflow:
    case ErrorCode::MalformedInput:
    case ErrorCode::UnsupportedVersion:
    case ErrorCode::UnsupportedFeature:
    case ErrorCode::MissingField:
    case ErrorCode::NotFound:
    case ErrorCode::AlreadyExists:
    case ErrorCode::SchemaUnsupported:
    case ErrorCode::Unauthenticated:
    case ErrorCode::Unauthorized:
    case ErrorCode::PolicyDenied:
    case ErrorCode::ProtocolViolation:
    case ErrorCode::OversizePayload:
    case ErrorCode::UnexpectedMessage:
    case ErrorCode::CapabilityMismatch:
    case ErrorCode::IllegalTransition:
    case ErrorCode::DigestMismatch:
    case ErrorCode::IntegrityFailure:
    case ErrorCode::SizeMismatch:
    case ErrorCode::StaleGeneration:
    case ErrorCode::StaleEpoch:
    case ErrorCode::FencedIncarnation:
    case ErrorCode::ReplayDetected:
    case ErrorCode::GenerationConflict:
    case ErrorCode::Retired:
    case ErrorCode::ArtifactUnavailable:
    case ErrorCode::Cancelled:
    case ErrorCode::ShuttingDown:
    case ErrorCode::Internal:
      return RetryDirective::DoNotRetry;

    // Explicitly benign: the operation already succeeded earlier.
    case ErrorCode::DuplicateSuppressed:
      return RetryDirective::DoNotRetry;

    // Transient, self-clearing pressure.
    case ErrorCode::Busy:
    case ErrorCode::QueueFull:
    case ErrorCode::CapacityExceeded:
    case ErrorCode::StoreFull:
      return RetryDirective::RetryWithBackoff;

    // Transport faults: the session is gone, a new one may succeed.
    case ErrorCode::ConnectionRefused:
    case ErrorCode::ConnectionReset:
    case ErrorCode::ConnectionClosed:
    case ErrorCode::PeerIdleTimeout:
    case ErrorCode::TruncatedFrame:
    case ErrorCode::ReorderedFrame:
      return RetryDirective::RetryNewSession;

    case ErrorCode::IoFailure:
    case ErrorCode::OpenFailed:
      return RetryDirective::RetryWithBackoff;

    case ErrorCode::LimitExceeded:
      return RetryDirective::Terminal;

    // The target applied something but the outcome is unknown. Never retry
    // blindly: reconcile authoritative state first.
    case ErrorCode::ApplyUncertain:
      return RetryDirective::RetryAfterReconcile;
    case ErrorCode::ApplyFailed:
    case ErrorCode::NotPrepared:
    case ErrorCode::RolledBack:
    case ErrorCode::PreconditionFailed:
    case ErrorCode::Conflict:
      return RetryDirective::RetryAfterReconcile;

    case ErrorCode::GuaranteeUnsupported:
      return RetryDirective::Terminal;
  }
  return RetryDirective::Terminal;
}

bool isFencingCode(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::StaleGeneration:
    case ErrorCode::StaleEpoch:
    case ErrorCode::FencedIncarnation:
    case ErrorCode::GenerationConflict:
    case ErrorCode::ReplayDetected:
      return true;
    default:
      return false;
  }
}

bool isIntegrityCode(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::DigestMismatch:
    case ErrorCode::IntegrityFailure:
    case ErrorCode::SizeMismatch:
      return true;
    default:
      return false;
  }
}

bool isIndeterminateCode(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::ApplyUncertain:
    case ErrorCode::IoFailure:
    case ErrorCode::ConnectionReset:
    case ErrorCode::ConnectionClosed:
    case ErrorCode::TruncatedFrame:
    case ErrorCode::PeerIdleTimeout:
      return true;
    default:
      return false;
  }
}

ErrorCode errorCodeFromName(std::string_view name) noexcept {
  // Stable lookup used by the inspection CLI and by durable records. The table
  // is derived from errorCodeName, so the two can never drift apart.
  static const std::unordered_map<std::string_view, ErrorCode> table = [] {
    std::unordered_map<std::string_view, ErrorCode> built;
    for (std::uint32_t raw = 0; raw <= 0xFFFFu; ++raw) {
      const auto code = static_cast<ErrorCode>(raw);
      const std::string_view candidate = errorCodeName(code);
      if (candidate != "Unknown") {
        built.emplace(candidate, code);
      }
    }
    return built;
  }();
  const auto found = table.find(name);
  return found == table.end() ? ErrorCode::Internal : found->second;
}

std::string Error::str() const {
  std::string out;
  out.reserve(message_.size() + detail_.size() + 40);
  out.append(errorCodeName(code_));
  if (!message_.empty()) {
    out.append(": ");
    out.append(message_);
  }
  if (!detail_.empty()) {
    out.append(" [");
    out.append(detail_);
    out.append("]");
  }
  return out;
}

}  // namespace cf
