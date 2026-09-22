add_executable(cfbench bench_delivery.cpp)
target_link_libraries(cfbench PRIVATE ConfigurationFabric::cf_core)
cf_set_project_warnings(cfbench)
cf_enable_sanitizers(cfbench)
