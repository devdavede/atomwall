cmake_minimum_required(VERSION 3.25)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

project(atomwall
    VERSION 0.1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

option(ATOMWALL_BUILD_TESTS "Build atomwall unit tests" ON)
option(ATOMWALL_ENABLE_SANITIZERS "Build with ASan+UBSan (Debug only)" ON)

find_package(Boost REQUIRED COMPONENTS asio beast json)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(maxminddb CONFIG REQUIRED)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif()

add_library(atomwall_warnings INTERFACE)
target_compile_options(atomwall_warnings INTERFACE -Wall -Wextra -Wpedantic)

add_library(atomwall_sanitizers INTERFACE)
if(ATOMWALL_ENABLE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(atomwall_sanitizers INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(atomwall_sanitizers INTERFACE -fsanitize=address,undefined)
endif()

add_library(atomwall_core
    src/admin/admin_server.cpp
    src/admin/http_util.cpp
    src/admin/json_view.cpp
    src/admin/static_files.cpp
    src/admin/url_fetch.cpp
    src/auth/password_hash.cpp
    src/auth/session_store.cpp
    src/auth/user_store.cpp
    src/config/blacklist_ops.cpp
    src/config/config_store.cpp
    src/config/site_lookup.cpp
    src/config/site_ops.cpp
    src/config/status_page_ops.cpp
    src/config/yaml_codec.cpp
    src/geoip/asn_service.cpp
    src/geoip/geoip_service.cpp
    src/globe/globe_server.cpp
    src/history/globe_event_log.cpp
    src/history/ip_block_tracker.cpp
    src/history/login_history.cpp
    src/history/request_log.cpp
    src/history/request_rate_tracker.cpp
    src/history/score_tracker.cpp
    src/listener/listener.cpp
    src/listener/tls_listener.cpp
    src/listener/tls_site_contexts.cpp
    src/pipeline/checks.cpp
    src/pipeline/net_utils.cpp
    src/upstream/upstream.cpp
)
target_include_directories(atomwall_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(atomwall_core PUBLIC
    Boost::asio
    Boost::beast
    Boost::json
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
    yaml-cpp::yaml-cpp
    maxminddb::maxminddb
    atomwall_warnings
    atomwall_sanitizers
)

add_executable(atomwall src/main.cpp)
target_link_libraries(atomwall PRIVATE atomwall_core)

if(ATOMWALL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
