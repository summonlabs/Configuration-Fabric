// Configuration Fabric validation suite - test framework implementation.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "testing.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <vector>

namespace cftest {
namespace {

std::vector<TestCase>& registry() {
  static std::vector<TestCase> tests;
  return tests;
}

struct RunState {
  std::size_t failures{0};
  std::string currentTest;
};

RunState& state() {
  static RunState runState;
  return runState;
}

}  // namespace

void registerTest(const char* suite, const char* name, TestFn fn) {
  registry().push_back(TestCase{suite, name, fn});
}

void recordFailure(const char* file, int line, const std::string& message) {
  state().failures += 1;
  std::fprintf(stderr, "    FAIL %s\n         at %s:%d\n         %s\n",
               state().currentTest.c_str(), file, line, message.c_str());
}

std::uint64_t runSeed() {
  static const std::uint64_t seed = [] {
    const char* fromEnvironment = std::getenv("CF_TEST_SEED");
    if (fromEnvironment != nullptr) {
      return static_cast<std::uint64_t>(std::strtoull(fromEnvironment, nullptr, 10));
    }
    const auto now = std::chrono::system_clock::now().time_since_epoch().count();
    return static_cast<std::uint64_t>(now) ^ 0x9E3779B97F4A7C15ull;
  }();
  return seed;
}

std::string describe(std::string_view value) { return std::string(value); }
std::string describe(const std::string& value) { return value; }
std::string describe(const char* value) { return value != nullptr ? std::string(value) : "<null>"; }
std::string describe(bool value) { return value ? "true" : "false"; }
std::string describe(std::uint64_t value) { return std::to_string(value); }
std::string describe(std::int64_t value) { return std::to_string(value); }
std::string describe(int value) { return std::to_string(value); }
std::string describe(double value) { return std::to_string(value); }

int runAll(const std::vector<std::string>& suites, const std::vector<std::string>& tests,
           bool listOnly, std::uint64_t seed) {
  std::size_t executed = 0;
  std::size_t failed = 0;
  std::string lastSuite;
  std::fprintf(stdout, "configuration-fabric validation suite (seed=%llu)\n",
               static_cast<unsigned long long>(seed));
  for (const TestCase& test : registry()) {
    if (!suites.empty()) {
      bool selected = false;
      for (const std::string& suite : suites) {
        if (suite == test.suite) {
          selected = true;
          break;
        }
      }
      if (!selected) {
        continue;
      }
    }
    if (!tests.empty()) {
      bool selected = false;
      for (const std::string& name : tests) {
        if (name == test.name) {
          selected = true;
          break;
        }
      }
      if (!selected) {
        continue;
      }
    }
    if (listOnly) {
      std::fprintf(stdout, "%s.%s\n", test.suite.c_str(), test.name.c_str());
      continue;
    }
    if (test.suite != lastSuite) {
      lastSuite = test.suite;
      std::fprintf(stdout, "[%s]\n", lastSuite.c_str());
    }
    state().failures = 0;
    state().currentTest = test.suite + "." + test.name;
    const auto started = std::chrono::steady_clock::now();
    try {
      test.fn();
    } catch (const std::exception& error) {
      recordFailure(__FILE__, __LINE__,
                    std::string("test threw std::exception: ") + error.what());
    } catch (...) {
      recordFailure(__FILE__, __LINE__, "test threw a non-standard exception");
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - started)
                             .count();
    executed += 1;
    if (state().failures == 0) {
      std::fprintf(stdout, "  ok   %-44s %5lld ms\n", test.name.c_str(),
                   static_cast<long long>(elapsed));
    } else {
      failed += 1;
      std::fprintf(stdout, "  FAIL %-44s %5lld ms (%llu expectation(s))\n", test.name.c_str(),
                   static_cast<long long>(elapsed),
                   static_cast<unsigned long long>(state().failures));
    }
    std::fflush(stdout);
  }
  if (listOnly) {
    return 0;
  }
  std::fprintf(stdout, "summary: %llu test(s) run, %llu failed\n",
               static_cast<unsigned long long>(executed),
               static_cast<unsigned long long>(failed));
  return static_cast<int>(failed);
}

}  // namespace cftest
