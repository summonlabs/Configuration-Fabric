// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Version identity of the runtime. The values are supplied by the build system
// (target_compile_definitions) and carry the same defaults as the exported
// package configuration, so an installed header and an installed package report
// the same version.

#pragma once

#include <cstdint>
#include <string_view>

#ifndef CF_VERSION_MAJOR
#define CF_VERSION_MAJOR 1
#endif
#ifndef CF_VERSION_MINOR
#define CF_VERSION_MINOR 0
#endif
#ifndef CF_VERSION_PATCH
#define CF_VERSION_PATCH 0
#endif

namespace cf {

inline constexpr std::uint32_t kVersionMajor = CF_VERSION_MAJOR;
inline constexpr std::uint32_t kVersionMinor = CF_VERSION_MINOR;
inline constexpr std::uint32_t kVersionPatch = CF_VERSION_PATCH;
inline constexpr std::string_view kProductName = "Configuration Fabric";
inline constexpr std::string_view kCopyrightNotice = "Copyright 2026 Summon Software Labs.";

/// Semantic version string, e.g. "1.0.0".
[[nodiscard]] std::string_view versionString() noexcept;

/// Single-line identification used by --version and by capability reports.
[[nodiscard]] std::string_view buildIdentification() noexcept;

}  // namespace cf
