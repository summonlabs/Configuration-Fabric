add_executable(cfbench bench_delivery.cpp)
target_link_libraries(cfbench PRIVATE ConfigurationFabric::cf_core)
target_compile_definitions(cfbench PRIVATE
  WIN32_LEAN_AND_MEAN
  NOMINMAX
  _CRT_SECURE_NO_WARNINGS
)
cf_set_project_warnings(cfbench)
cf_enable_sanitizers(cfbench)
