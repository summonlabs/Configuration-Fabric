// Configuration Fabric validation suite - entry point.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "cf/log.hpp"
#include "testing.hpp"

int main(int argc, char** argv) {
  std::vector<std::string> suites;
  std::vector<std::string> tests;
  bool listOnly = false;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--suite" && i + 1 < argc) {
      suites.emplace_back(argv[++i]);
      continue;
    }
    if (argument == "--test" && i + 1 < argc) {
      tests.emplace_back(argv[++i]);
      continue;
    }
    if (argument == "--list") {
      listOnly = true;
      continue;
    }
    if (argument == "--help" || argument == "-h") {
      std::fprintf(stdout,
                   "cftests [--suite <name>]... [--list]\n"
                   "  --suite <name>  run only this suite (repeatable)\n"
                   "  --list          list tests without running them\n"
                   "suites: unit property adversarial concurrency process multiprocess "
                   "injection restart statetest\n");
      return 0;
    }
    std::fprintf(stderr, "cftests: unknown argument '%s'\n", argument.c_str());
    return 2;
  }

  // Test diagnostics are available through CF_LOG_LEVEL when a defect needs
  // them; the default keeps the report readable.
  cf::LogLevel level = cf::LogLevel::Error;
  if (const char* requested = std::getenv("CF_LOG_LEVEL"); requested != nullptr) {
    (void)cf::parseLogLevel(requested, level);
  }
  cf::Logger::global().setLevel(level);
  if (const char* logPath = std::getenv("CF_LOG_FILE"); logPath != nullptr) {
    const cf::Status opened = cf::Logger::global().setOutputFile(logPath);
    if (!opened) {
      std::fprintf(stderr, "cftests: %s\n", opened.str().c_str());
      return 2;
    }
  }

  return cftest::runAll(suites, tests, listOnly, cftest::runSeed());
}
