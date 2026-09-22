// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Internal invariant checking. These are programming-error detectors, not
// input validation: input validation must always be explicit and must return a
// typed error instead of tripping a contract.

#pragma once

#include <cstdio>
#include <cstdlib>

namespace cf::detail {

[[noreturn]] inline void contractFailure(const char* expression, const char* file, int line,
                                        const char* message) noexcept {
  std::fprintf(stderr, "configuration-fabric contract violation: %s\n  at %s:%d\n  %s\n",
               expression, file, line, message != nullptr ? message : "");
  std::fflush(stderr);
  std::abort();
}

}  // namespace cf::detail

#define CF_CONTRACT(expr, message)                                                        \
  do {                                                                                    \
    if (!(expr)) {                                                                        \
      ::cf::detail::contractFailure(#expr, __FILE__, __LINE__, (message));                \
    }                                                                                     \
  } while (false)

/// Unreachable-by-construction marker for exhaustive switches over typed enums.
#define CF_UNREACHABLE(message) ::cf::detail::contractFailure("unreachable", __FILE__, __LINE__, (message))
