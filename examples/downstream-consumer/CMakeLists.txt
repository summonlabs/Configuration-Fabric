# Independent downstream consumer of the installed Configuration Fabric package.
#
# This project is deliberately NOT part of the repository's own build: it exists
# to prove that the exported package works from a separate build tree with no
# access to the source tree, using nothing but find_package.
#
#   cmake -S examples/downstream-consumer -B <build dir> -DCMAKE_PREFIX_PATH=<install prefix>
#   cmake --build <build dir>
#   <build dir>/cf-downstream-consumer

cmake_minimum_required(VERSION 3.21)
project(ConfigurationFabricDownstreamConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(ConfigurationFabric 1.0 REQUIRED)

add_executable(cf-downstream-consumer main.cpp)
target_link_libraries(cf-downstream-consumer PRIVATE ConfigurationFabric::cf_core)

message(STATUS "Configuration Fabric ${ConfigurationFabric_VERSION} found at ${ConfigurationFabric_DIR}")
