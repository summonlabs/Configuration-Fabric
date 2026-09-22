# Validation suite.
#
# Every suite is a separate CTest entry so that a defect cannot mask another
# suite. No CTest TIMEOUT property is set anywhere: tests are expected to finish
# naturally and a hang is a defect to be diagnosed, never hidden behind a
# watchdog.

add_executable(cftests
  testing.cpp
  test_main.cpp
  test_agent.cpp
  test_artifact.cpp
  test_checked.cpp
  test_convergence.cpp
  test_frame.cpp
  test_hash.cpp
  test_ids.cpp
  test_injection.cpp
  test_journal.cpp
  test_lifecycle.cpp
  test_multiprocess.cpp
  test_plan.cpp
  test_policy.cpp
  test_process.cpp
  test_protocol.cpp
  test_reconciliation.cpp
  test_restart.cpp
  test_result.cpp
  test_rng.cpp
  test_state.cpp
  test_statetest.cpp
)

target_link_libraries(cftests PRIVATE ConfigurationFabric::cf_core)
target_include_directories(cftests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(cftests PRIVATE
  WIN32_LEAN_AND_MEAN
  NOMINMAX
  _CRT_SECURE_NO_WARNINGS
  CF_TEST_AGENT_PATH="$<TARGET_FILE:cf-agent>"
  CF_TEST_CONTROLLER_PATH="$<TARGET_FILE:cf-controller>"
  CF_TEST_CFCTL_PATH="$<TARGET_FILE:cfctl>"
  CF_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)
cf_set_project_warnings(cftests)
cf_enable_sanitizers(cftests)

add_dependencies(cftests cf-agent cf-controller cfctl)

add_test(NAME cf.unit COMMAND cftests --suite unit)
add_test(NAME cf.property COMMAND cftests --suite property)
add_test(NAME cf.adversarial COMMAND cftests --suite adversarial)
add_test(NAME cf.concurrency COMMAND cftests --suite concurrency)
add_test(NAME cf.process COMMAND cftests --suite process)
add_test(NAME cf.multiprocess COMMAND cftests --suite multiprocess)
add_test(NAME cf.injection COMMAND cftests --suite injection)
add_test(NAME cf.restart COMMAND cftests --suite restart)
add_test(NAME cf.statetest COMMAND cftests --suite statetest)
