// Unit tests: the error model, retry classification and Result propagation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <set>
#include <string>

#include "cf/result.hpp"
#include "testing.hpp"

namespace {

cf::Result<int> half(int value) {
  if (value % 2 != 0) {
    return cf::Result<int>::fail(cf::ErrorCode::InvalidArgument, "odd");
  }
  return cf::Result<int>::ok(value / 2);
}

cf::Result<int> quarter(int value) {
  CF_TRY_ASSIGN(const int halved, half(value));
  CF_TRY_ASSIGN(const int quartered, half(halved));
  return cf::Result<int>::ok(quartered);
}

}  // namespace

CF_TEST(unit, result_and_status_basics) {
  const cf::Result<int> good = cf::Result<int>::ok(3);
  CF_EXPECT(good.hasValue());
  CF_EXPECT_EQ(good.value(), 3);
  const cf::Result<int> bad = cf::Result<int>::fail(cf::ErrorCode::NotFound, "missing", "detail");
  CF_EXPECT(!bad.hasValue());
  CF_EXPECT_EQ(bad.error().code(), cf::ErrorCode::NotFound);
  CF_EXPECT_EQ(bad.error().detail(), std::string("detail"));
  CF_EXPECT_EQ(bad.error().str(), std::string("NotFound: missing [detail]"));

  const cf::Status status = cf::Status::fail(cf::ErrorCode::Busy, "busy");
  CF_EXPECT(!status);
  CF_EXPECT_EQ(status.code(), cf::ErrorCode::Busy);
  CF_EXPECT(static_cast<bool>(cf::Status::ok()));
}

CF_TEST(unit, try_macros_propagate) {
  CF_EXPECT_OK(quarter(8));
  CF_EXPECT_EQ(quarter(8).value(), 2);
  CF_EXPECT_CODE(quarter(2), cf::ErrorCode::InvalidArgument);
  CF_EXPECT_CODE(quarter(3), cf::ErrorCode::InvalidArgument);
  CF_EXPECT_CODE(half(3), cf::ErrorCode::InvalidArgument);
}

CF_TEST(unit, every_error_code_has_a_name_and_a_directive) {
  std::set<std::string> names;
  for (std::uint32_t raw = 0; raw <= 0xFFFFu; ++raw) {
    const auto code = static_cast<cf::ErrorCode>(raw);
    const std::string_view name = cf::errorCodeName(code);
    if (name == "Unknown") {
      continue;
    }
    CF_EXPECT(names.insert(std::string(name)).second);
    // Both directions of the mapping must agree.
    CF_EXPECT_EQ(cf::errorCodeFromName(name), code);
    const cf::RetryDirective directive = cf::retryDirectiveFor(code);
    CF_EXPECT(cf::retryDirectiveName(directive) != "Unknown");
    // Classification predicates must be pure functions of the code.
    CF_EXPECT_EQ(cf::isFencingCode(code), cf::isFencingCode(code));
    CF_EXPECT_EQ(cf::isIntegrityCode(code), cf::isIntegrityCode(code));
    CF_EXPECT_EQ(cf::isIndeterminateCode(code), cf::isIndeterminateCode(code));
  }
  CF_EXPECT(names.size() > 40);
}

CF_TEST(unit, retry_directives_are_conservative) {
  // Fencing and integrity failures are never retried blindly.
  CF_EXPECT_EQ(cf::retryDirectiveFor(cf::ErrorCode::StaleGeneration),
               cf::RetryDirective::DoNotRetry);
  CF_EXPECT_EQ(cf::retryDirectiveFor(cf::ErrorCode::DigestMismatch),
               cf::RetryDirective::DoNotRetry);
  CF_EXPECT_EQ(cf::retryDirectiveFor(cf::ErrorCode::ApplyUncertain),
               cf::RetryDirective::RetryAfterReconcile);
  CF_EXPECT_EQ(cf::retryDirectiveFor(cf::ErrorCode::ConnectionReset),
               cf::RetryDirective::RetryNewSession);
  CF_EXPECT_EQ(cf::retryDirectiveFor(cf::ErrorCode::QueueFull),
               cf::RetryDirective::RetryWithBackoff);
  CF_EXPECT_EQ(cf::retryDirectiveFor(cf::ErrorCode::GuaranteeUnsupported),
               cf::RetryDirective::Terminal);
  CF_EXPECT(cf::isFencingCode(cf::ErrorCode::FencedIncarnation));
  CF_EXPECT(cf::isIntegrityCode(cf::ErrorCode::SizeMismatch));
  CF_EXPECT(cf::isIndeterminateCode(cf::ErrorCode::ApplyUncertain));
  CF_EXPECT(!cf::isIndeterminateCode(cf::ErrorCode::Ok));
  CF_EXPECT_EQ(cf::errorCodeFromName("NoSuchCode"), cf::ErrorCode::Internal);
}
