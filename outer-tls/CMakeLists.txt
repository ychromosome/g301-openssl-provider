# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20)

project(g301_alpha_beta_provider VERSION 0.1.0 LANGUAGES C)

option(G301_ENABLE_PRIVATE_TLS_E2E
    "Build the external E2E harness for the patched private OpenSSL fork"
    OFF)
option(G301_ENABLE_MBEDTLS_ORACLE
    "Build the optional independent Mbed TLS AES-GCM differential oracle"
    OFF)

include(CTest)
if(G301_ENABLE_PRIVATE_TLS_E2E)
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)
else()
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
endif()
find_package(Threads REQUIRED)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

function(g301_strict_target target)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Werror
            -Wcast-qual -Wconversion -Wformat=2 -Wshadow
            -Wstrict-prototypes -Wundef
            -fstack-protector-strong)
    endif()
endfunction()

add_library(g301 MODULE
    src/g301_provider.c
    src/g301_cipher.c
    src/g301_inner_evp.c)

target_include_directories(g301 PRIVATE src)
target_link_libraries(g301 PRIVATE OpenSSL::Crypto)
target_compile_definitions(g301 PRIVATE OPENSSL_API_COMPAT=30000)
set_target_properties(g301 PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    PREFIX ""
    OUTPUT_NAME "g301")
g301_strict_target(g301)

if(UNIX AND NOT APPLE)
    target_link_options(g301 PRIVATE
        "LINKER:-z,relro"
        "LINKER:-z,now"
        "LINKER:--no-undefined")
endif()

if(BUILD_TESTING)
    find_package(Python3 QUIET COMPONENTS Interpreter)

    add_executable(g301_integration_test tests/test_integration.c)
    target_link_libraries(g301_integration_test PRIVATE OpenSSL::Crypto Threads::Threads)
    target_compile_definitions(g301_integration_test PRIVATE OPENSSL_API_COMPAT=30000)
    g301_strict_target(g301_integration_test)
    add_test(NAME g301_integration
        COMMAND g301_integration_test "$<TARGET_FILE_DIR:g301>")
    set_tests_properties(g301_integration PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=$<TARGET_FILE_DIR:g301>")

    add_executable(g301_state_machine_test
        tests/test_state_machine.c
        src/g301_cipher.c)
    target_include_directories(g301_state_machine_test PRIVATE src)
    target_link_libraries(g301_state_machine_test PRIVATE OpenSSL::Crypto)
    target_compile_definitions(g301_state_machine_test PRIVATE
        G301_TESTING=1
        OPENSSL_API_COMPAT=30000)
    g301_strict_target(g301_state_machine_test)
    add_test(NAME g301_state_machine COMMAND g301_state_machine_test)

    add_test(NAME g301_dispatch_surface
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE_FILE=${CMAKE_CURRENT_SOURCE_DIR}/src/g301_cipher.c
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_dispatch.cmake)

    if(Python3_Interpreter_FOUND)
        add_test(NAME g301_benchmark_gate
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_benchmark_gate.py)
    endif()

    add_executable(g301_manifest_test tests/test_manifest.c)
    target_link_libraries(g301_manifest_test PRIVATE OpenSSL::Crypto)
    target_compile_definitions(g301_manifest_test PRIVATE OPENSSL_API_COMPAT=30000)
    g301_strict_target(g301_manifest_test)
    add_test(NAME g301_manifest_reconstruction COMMAND g301_manifest_test)

    add_executable(g301_param_policy_test tests/test_param_policy.c)
    target_include_directories(g301_param_policy_test PRIVATE src)
    target_link_libraries(g301_param_policy_test PRIVATE OpenSSL::Crypto)
    target_compile_definitions(g301_param_policy_test PRIVATE
        OPENSSL_API_COMPAT=30000)
    g301_strict_target(g301_param_policy_test)
    add_test(NAME g301_param_policy
        COMMAND g301_param_policy_test "$<TARGET_FILE_DIR:g301>")
    set_tests_properties(g301_param_policy PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=$<TARGET_FILE_DIR:g301>")

    if(DEFINED OPENSSL_VERSION AND OPENSSL_VERSION VERSION_GREATER_EQUAL 3.0)
        add_executable(g301_capability_test tests/test_capability.c)
        target_include_directories(g301_capability_test PRIVATE src)
        target_link_libraries(g301_capability_test PRIVATE OpenSSL::Crypto)
        target_compile_definitions(g301_capability_test PRIVATE
            OPENSSL_API_COMPAT=30000)
        g301_strict_target(g301_capability_test)
        add_test(NAME g301_capability
            COMMAND g301_capability_test "$<TARGET_FILE_DIR:g301>")
        set_tests_properties(g301_capability PROPERTIES
            ENVIRONMENT "OPENSSL_MODULES=$<TARGET_FILE_DIR:g301>")
    endif()

    if(G301_ENABLE_PRIVATE_TLS_E2E)
        add_library(g301_limit_test MODULE
            src/g301_provider.c
            src/g301_cipher.c
            src/g301_inner_evp.c)
        target_include_directories(g301_limit_test PRIVATE src)
        target_link_libraries(g301_limit_test PRIVATE OpenSSL::Crypto)
        target_compile_definitions(g301_limit_test PRIVATE
            G301_TEST_RECORD_LIMIT=8
            OPENSSL_API_COMPAT=30000)
        set_target_properties(g301_limit_test PROPERTIES
            C_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN YES
            PREFIX ""
            OUTPUT_NAME "g301"
            LIBRARY_OUTPUT_DIRECTORY
                "${CMAKE_CURRENT_BINARY_DIR}/limit-provider")
        g301_strict_target(g301_limit_test)
        if(UNIX AND NOT APPLE)
            target_link_options(g301_limit_test PRIVATE
                "LINKER:-z,relro"
                "LINKER:-z,now"
                "LINKER:--no-undefined")
        endif()

        add_executable(g301_private_tls_e2e_test tests/test_private_tls_e2e.c)
        target_include_directories(g301_private_tls_e2e_test PRIVATE src)
        target_link_libraries(g301_private_tls_e2e_test PRIVATE
            OpenSSL::SSL OpenSSL::Crypto)
        target_compile_definitions(g301_private_tls_e2e_test PRIVATE
            G301_ACCELERATED_RECORD_LIMIT=8
            OPENSSL_API_COMPAT=30000)
        add_dependencies(g301_private_tls_e2e_test g301 g301_limit_test)
        g301_strict_target(g301_private_tls_e2e_test)

        add_test(NAME g301_private_tls_e2e
            COMMAND g301_private_tls_e2e_test "$<TARGET_FILE_DIR:g301>")
        set_tests_properties(g301_private_tls_e2e PROPERTIES
            LABELS "private-fork;e2e"
            TIMEOUT 30)

        foreach(mode IN ITEMS
                record-limit-client
                record-limit-server
                record-limit-client-keyupdate
                record-limit-server-keyupdate)
            add_test(NAME "g301_private_tls_${mode}"
                COMMAND g301_private_tls_e2e_test
                    "$<TARGET_FILE_DIR:g301_limit_test>" "${mode}")
            set_tests_properties("g301_private_tls_${mode}" PROPERTIES
                LABELS "private-fork;e2e;record-limit"
                TIMEOUT 30)
        endforeach()
    endif()

    if(G301_ENABLE_MBEDTLS_ORACLE)
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(MBEDCRYPTO REQUIRED IMPORTED_TARGET mbedcrypto)
        add_executable(g301_mbedtls_oracle_test
            tests/test_mbedtls_oracle.c)
        target_link_libraries(g301_mbedtls_oracle_test PRIVATE
            OpenSSL::Crypto PkgConfig::MBEDCRYPTO)
        target_compile_definitions(g301_mbedtls_oracle_test PRIVATE
            OPENSSL_API_COMPAT=30000)
        g301_strict_target(g301_mbedtls_oracle_test)
        add_test(NAME g301_mbedtls_oracle
            COMMAND g301_mbedtls_oracle_test "$<TARGET_FILE_DIR:g301>")
        set_tests_properties(g301_mbedtls_oracle PROPERTIES
            ENVIRONMENT "OPENSSL_MODULES=$<TARGET_FILE_DIR:g301>"
            LABELS "independent-oracle")
    endif()
endif()

if(G301_ENABLE_PRIVATE_TLS_E2E AND NOT BUILD_TESTING)
    message(FATAL_ERROR
        "G301_ENABLE_PRIVATE_TLS_E2E requires BUILD_TESTING=ON")
endif()
