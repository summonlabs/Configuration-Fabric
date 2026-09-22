# Configuration Fabric - vendor-neutral Fabric OS runtime.
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
#
# Top-level build. The exported package is "ConfigurationFabric" and the single
# public library target is ConfigurationFabric::cf_core.

cmake_minimum_required(VERSION 3.21)

project(ConfigurationFabric
  VERSION 1.0.0
  DESCRIPTION "Vendor-neutral configuration distribution and delivery-state runtime"
  HOMEPAGE_URL "https://github.com/summonlabs/Configuration-Fabric"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

option(CF_BUILD_APPS "Build the controller, agent and inspection executables" ON)
option(CF_BUILD_TESTS "Build the validation suite" ON)
option(CF_BUILD_BENCHMARKS "Build benchmarks" ON)
option(CF_WARNINGS_AS_ERRORS "Promote first-party warnings to errors" ON)
option(CF_ENABLE_ASAN "Enable AddressSanitizer for first-party targets" OFF)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(CFWarnings)

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Core runtime library
# ---------------------------------------------------------------------------

set(CF_CORE_SOURCES
  src/agent.cpp
  src/artifact.cpp
  src/codec.cpp
  src/control.cpp
  src/convergence.cpp
  src/distributor.cpp
  src/frame.cpp
  src/hash.cpp
  src/ids.cpp
  src/journal.cpp
  src/lifecycle.cpp
  src/log.cpp
  src/plan.cpp
  src/policy.cpp
  src/process.cpp
  src/protocol.cpp
  src/reconciliation.cpp
  src/result.cpp
  src/rng.cpp
  src/state.cpp
  src/transport.cpp
  src/version.cpp
)

set(CF_PUBLIC_HEADERS
  include/cf/agent.hpp
  include/cf/artifact.hpp
  include/cf/checked.hpp
  include/cf/contract.hpp
  include/cf/control.hpp
  include/cf/convergence.hpp
  include/cf/digest.hpp
  include/cf/distributor.hpp
  include/cf/frame.hpp
  include/cf/hash.hpp
  include/cf/ids.hpp
  include/cf/journal.hpp
  include/cf/lifecycle.hpp
  include/cf/log.hpp
  include/cf/plan.hpp
  include/cf/policy.hpp
  include/cf/process.hpp
  include/cf/protocol.hpp
  include/cf/reconciliation.hpp
  include/cf/result.hpp
  include/cf/rng.hpp
  include/cf/state.hpp
  include/cf/store.hpp
  include/cf/strong.hpp
  include/cf/transport.hpp
  include/cf/version.hpp
)

add_library(cf_core STATIC ${CF_CORE_SOURCES} ${CF_PUBLIC_HEADERS})
add_library(ConfigurationFabric::cf_core ALIAS cf_core)

target_include_directories(cf_core
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_compile_definitions(cf_core
  PUBLIC
    CF_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    CF_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    CF_VERSION_PATCH=${PROJECT_VERSION_PATCH}
  PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0601
    _CRT_SECURE_NO_WARNINGS
)

target_link_libraries(cf_core PUBLIC Threads::Threads)
if(WIN32)
  target_link_libraries(cf_core PUBLIC ws2_32)
endif()

cf_set_project_warnings(cf_core)
cf_enable_sanitizers(cf_core)

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------

if(CF_BUILD_APPS)
  add_executable(cf-controller apps/controller_main.cpp)
  add_executable(cf-agent apps/agent_main.cpp)
  add_executable(cfctl apps/cfctl_main.cpp)

  foreach(app cf-controller cf-agent cfctl)
    target_link_libraries(${app} PRIVATE ConfigurationFabric::cf_core)
    target_compile_definitions(${app} PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      _CRT_SECURE_NO_WARNINGS
    )
    cf_set_project_warnings(${app})
    cf_enable_sanitizers(${app})
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Tests and benchmarks
# ---------------------------------------------------------------------------

if(CF_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(CF_BUILD_BENCHMARKS)
  add_subdirectory(bench)
endif()

# ---------------------------------------------------------------------------
# Install and export
# ---------------------------------------------------------------------------

install(TARGETS cf_core
  EXPORT ConfigurationFabricTargets
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

if(CF_BUILD_APPS)
  install(TARGETS cf-controller cf-agent cfctl
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

install(DIRECTORY include/cf
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.hpp")

install(EXPORT ConfigurationFabricTargets
  FILE ConfigurationFabricTargets.cmake
  NAMESPACE ConfigurationFabric::
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ConfigurationFabric")

configure_package_config_file(
  cmake/ConfigurationFabricConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/ConfigurationFabricConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ConfigurationFabric")

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/ConfigurationFabricConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/ConfigurationFabricConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/ConfigurationFabricConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ConfigurationFabric")
