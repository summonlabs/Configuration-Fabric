// Configuration Fabric validation suite - test framework.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deliberately small and dependency-free. Design constraints that matter:
//
//   * a failing expectation records the failure and lets the test continue, so
//     one run reports every defect instead of only the first;
//   * tests are registered statically and run in a deterministic order;
//   * there is no watchdog and no timeout anywhere. A hang is a defect to be
//     diagnosed, never something to hide behind a timer.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace cftest {

using TestFn = void (*)();

struct TestCase {
  std::string suite;
  std::string name;
  TestFn fn;
};

void registerTest(const char* suite, const char* name, TestFn fn);

struct Registrar {
  Registrar(const char* suite, const char* name, TestFn fn) { registerTest(suite, name, fn); }
};

/// Records a failure against the currently running test.
void recordFailure(const char* file, int line, const std::string& message);

/// Deterministic seed for this run. Randomized tests print it so a failure is
/// reproducible from the printed value.
[[nodiscard]] std::uint64_t runSeed();

/// Runs every registered test whose suite is in suites (empty means all).
/// Returns the number of failed tests.
int runAll(const std::vector<std::string>& suites, const std::vector<std::string>& tests,
           bool listOnly, std::uint64_t seed);

}  // namespace cftest

#define CF_TEST(suite, name)                                                            \
  static void cf_test_##name();                                                         \
  static const ::cftest::Registrar cf_registrar_##name(#suite, #name, &cf_test_##name);  \
  static void cf_test_##name()

#define CF_EXPECT(expr)                                                                 \
  do {                                                                                  \
    if (!(expr)) {                                                                      \
      ::cftest::recordFailure(__FILE__, __LINE__, "expected: " #expr);                   \
    }                                                                                   \
  } while (false)

#define CF_EXPECT_MSG(expr, message)                                                     \
  do {                                                                                   \
    if (!(expr)) {                                                                       \
      ::cftest::recordFailure(__FILE__, __LINE__,                                        \
                              std::string("expected: " #expr " -- ") + (message));        \
    }                                                                                    \
  } while (false)

#define CF_EXPECT_EQ(actual, expected)                                                   \
  do {                                                                                   \
    const auto& cf_actual_ = (actual);                                                   \
    const auto& cf_expected_ = (expected);                                               \
    if (!(cf_actual_ == cf_expected_)) {                                                 \
      ::cftest::recordFailure(__FILE__, __LINE__,                                        \
                              std::string(#actual " == " #expected " (") +               \
                                  ::cftest::describe(cf_actual_) + " vs " +              \
                                  ::cftest::describe(cf_expected_) + ")");               \
    }                                                                                    \
  } while (false)

/// Records a failure and returns from the test when the result is not a success.
/// Used as a precondition before dereferencing a Result, so one defect produces
/// one clear failure instead of a cascade (or an exception).
#define CF_REQUIRE_OK(result)                                                              do {                                                                                       const auto& cf_required_ = (result);                                                     if (!cf_required_) {                                                                       ::cftest::recordFailure(__FILE__, __LINE__,                                                                      std::string("required success: " #result " -> ") +                                           cf_required_.error().str());                                 return;                                                                                }                                                                                      } while (false)

#define CF_EXPECT_CODE(result, expectedCode)                                             \
  do {                                                                                   \
    const auto& cf_result_ = (result);                                                   \
    if (cf_result_) {                                                                    \
      ::cftest::recordFailure(__FILE__, __LINE__,                                        \
                              std::string("expected failure " #expectedCode " but got "  \
                                          "success"));                                   \
    } else if (cf_result_.error().code() != (expectedCode)) {                            \
      ::cftest::recordFailure(__FILE__, __LINE__,                                        \
                              std::string("expected " #expectedCode " but got ") +       \
                                  std::string(cf_result_.error().codeName()) + " (" +    \
                                  cf_result_.error().str() + ")");                       \
    }                                                                                    \
  } while (false)

#define CF_EXPECT_OK(result)                                                             \
  do {                                                                                   \
    const auto& cf_result_ = (result);                                                   \
    if (!cf_result_) {                                                                   \
      ::cftest::recordFailure(__FILE__, __LINE__,                                        \
                              std::string("unexpected failure: ") +                      \
                                  cf_result_.error().str());                             \
    }                                                                                    \
  } while (false)

namespace cftest {

[[nodiscard]] std::string describe(std::string_view value);
[[nodiscard]] std::string describe(const std::string& value);
[[nodiscard]] std::string describe(const char* value);
[[nodiscard]] std::string describe(bool value);
// std::size_t and std::uint64_t are the same type on the supported 64-bit
// targets, so only one overload is declared.
[[nodiscard]] std::string describe(std::uint64_t value);
[[nodiscard]] std::string describe(std::int64_t value);
[[nodiscard]] std::string describe(int value);
[[nodiscard]] std::string describe(double value);

template <class T>
[[nodiscard]] std::string describe(const T& value) {
  if constexpr (requires { value.hex(); }) {
    return value.hex();
  } else if constexpr (requires { value.str(); }) {
    return value.str();
  } else if constexpr (requires { value.value(); }) {
    return std::to_string(value.value());
  } else if constexpr (requires { value.codeName(); }) {
    return std::string(value.codeName());
  } else {
    return "<value>";
  }
}

}  // namespace cftest
