find_package(Catch2 3 REQUIRED)

add_executable(atomwall_tests
    smoke_test.cpp
    net_utils_test.cpp
    checks_test.cpp
    blacklist_ops_test.cpp
    site_lookup_test.cpp
    site_ops_test.cpp
    status_page_ops_test.cpp
    yaml_codec_test.cpp
    request_log_test.cpp
    ip_block_tracker_test.cpp
    score_tracker_test.cpp
    request_rate_tracker_test.cpp
    password_hash_test.cpp
    geoip_service_test.cpp
    globe_event_log_test.cpp
)
target_link_libraries(atomwall_tests PRIVATE
    Catch2::Catch2WithMain
    atomwall_core
    atomwall_warnings
    atomwall_sanitizers
)

include(CTest)
include(Catch)
catch_discover_tests(atomwall_tests)
