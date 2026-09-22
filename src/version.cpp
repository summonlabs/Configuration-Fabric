// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/version.hpp"

#include <string>

namespace cf {
namespace {

[[nodiscard]] std::string decimal(std::uint32_t value) {
  if (value == 0) {
    return "0";
  }
  std::string out;
  while (value > 0) {
    out.insert(out.begin(), static_cast<char>('0' + (value % 10)));
    value /= 10;
  }
  return out;
}

}  // namespace

std::string_view versionString() noexcept {
  static const std::string value =
      decimal(kVersionMajor) + "." + decimal(kVersionMinor) + "." + decimal(kVersionPatch);
  return value;
}

std::string_view buildIdentification() noexcept {
  static const std::string value = std::string(kProductName) + " " + std::string(versionString());
  return value;
}

}  // namespace cf
