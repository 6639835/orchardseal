cmake_minimum_required(VERSION 3.18)

project(OrchardSeal
    VERSION 1.0.0
    DESCRIPTION "Cross-platform iOS signing and SealCheck preflight audit toolkit"
    LANGUAGES C CXX
)

option(ORCHARDSEAL_BUILD_TESTS "Build and register OrchardSeal tests" ON)
option(ORCHARDSEAL_WARNINGS_AS_ERRORS "Treat project compiler warnings as errors" OFF)

include(GNUInstallDirs)
include(cmake/CompilerOptions.cmake)

find_package(OpenSSL REQUIRED)

find_package(Git QUIET)
set(ORCHARDSEAL_GIT_REVISION "unknown")
set(ORCHARDSEAL_VERSION_STRING "${PROJECT_VERSION}")
if(Git_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" describe --tags --always --dirty
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE ORCHARDSEAL_GIT_DESCRIBE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(ORCHARDSEAL_GIT_DESCRIBE)
        string(REGEX REPLACE "^v" "" ORCHARDSEAL_VERSION_STRING "${ORCHARDSEAL_GIT_DESCRIBE}")
        set(ORCHARDSEAL_GIT_REVISION "${ORCHARDSEAL_GIT_DESCRIBE}")
    endif()
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/orchardseal/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/include/orchardseal/version.h"
    @ONLY
)

set(ORCHARDSEAL_COMMON_SOURCES
    src/common/zip_archive.cpp
    src/common/base64.cpp
    src/common/file_system.cpp
    src/common/json.cpp
    src/common/logger.cpp
    src/common/hash.cpp
    src/common/stopwatch.cpp
    src/common/utility.cpp
)

if(WIN32)
    list(APPEND ORCHARDSEAL_COMMON_SOURCES
        src/platform/windows/windows_text_converter.cpp
    )
endif()

set(ORCHARDSEAL_CORE_SOURCES
    src/core/audit.cpp
    src/core/audit_report.cpp
    src/core/macho_slice.cpp
    src/core/app_bundle.cpp
    src/core/certificate_check.cpp
    src/core/macho_file.cpp
    src/core/metadata.cpp
    src/core/signing_asset.cpp
    src/core/code_signature.cpp
)

set(ORCHARDSEAL_ZLIB_SOURCES
    vendor/zlib/adler32.c
    vendor/zlib/compress.c
    vendor/zlib/crc32.c
    vendor/zlib/deflate.c
    vendor/zlib/gzclose.c
    vendor/zlib/gzlib.c
    vendor/zlib/gzread.c
    vendor/zlib/gzwrite.c
    vendor/zlib/infback.c
    vendor/zlib/inffast.c
    vendor/zlib/inflate.c
    vendor/zlib/inftrees.c
    vendor/zlib/trees.c
    vendor/zlib/uncompr.c
    vendor/zlib/zutil.c
)

set(ORCHARDSEAL_MINIZIP_SOURCES
    vendor/minizip/ioapi.c
    vendor/minizip/zip.c
    vendor/minizip/unzip.c
)

if(WIN32)
    list(APPEND ORCHARDSEAL_MINIZIP_SOURCES vendor/minizip/iowin32.c)
endif()

add_library(orchardseal_zlib STATIC ${ORCHARDSEAL_ZLIB_SOURCES})
target_include_directories(orchardseal_zlib PUBLIC vendor/zlib)
set_target_properties(orchardseal_zlib PROPERTIES C_STANDARD 99 POSITION_INDEPENDENT_CODE ON)

add_library(orchardseal_minizip STATIC ${ORCHARDSEAL_MINIZIP_SOURCES})
target_include_directories(orchardseal_minizip PUBLIC vendor/minizip vendor/zlib)
target_link_libraries(orchardseal_minizip PUBLIC orchardseal_zlib)
set_target_properties(orchardseal_minizip PROPERTIES C_STANDARD 99 POSITION_INDEPENDENT_CODE ON)

add_library(orchardseal_core STATIC ${ORCHARDSEAL_COMMON_SOURCES} ${ORCHARDSEAL_CORE_SOURCES})
orchardseal_apply_default_options(orchardseal_core)
target_include_directories(orchardseal_core
    PUBLIC
        src/common
        src/core
        vendor/minizip
        vendor/zlib
    PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated/include"
)
if(WIN32)
    target_include_directories(orchardseal_core PRIVATE src/platform/windows)
endif()
target_link_libraries(orchardseal_core
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        orchardseal_minizip
)

set(ORCHARDSEAL_CLI_SOURCES
    src/cli/application.cpp
    src/cli/options.cpp
    src/cli/main.cpp
)

if(WIN32)
    list(APPEND ORCHARDSEAL_CLI_SOURCES
        src/platform/windows/getopt.cpp
    )
endif()

add_executable(orchardseal ${ORCHARDSEAL_CLI_SOURCES})
orchardseal_apply_default_options(orchardseal)
target_include_directories(orchardseal PRIVATE
    src/cli
    src/common
    src/core
    "${CMAKE_CURRENT_BINARY_DIR}/generated/include"
)
if(WIN32)
    target_include_directories(orchardseal PRIVATE src/platform/windows)
endif()
target_link_libraries(orchardseal PRIVATE orchardseal_core)

install(TARGETS orchardseal RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(
    FILES README.md LICENSE THIRD_PARTY_NOTICES.md
    DESTINATION "${CMAKE_INSTALL_DOCDIR}"
)

if(ORCHARDSEAL_BUILD_TESTS)
    enable_testing()

    add_executable(orchardseal_base64_test tests/unit/base64_test.cpp)
    orchardseal_apply_default_options(orchardseal_base64_test)
    target_link_libraries(orchardseal_base64_test PRIVATE orchardseal_core)

    add_executable(orchardseal_macho_slice_test tests/unit/macho_slice_test.cpp)
    orchardseal_apply_default_options(orchardseal_macho_slice_test)
    target_link_libraries(orchardseal_macho_slice_test PRIVATE orchardseal_core)

    add_test(NAME orchardseal.base64 COMMAND orchardseal_base64_test)
    add_test(NAME orchardseal.macho-slice COMMAND orchardseal_macho_slice_test)
    add_test(NAME orchardseal.version COMMAND orchardseal --version)
    add_test(NAME orchardseal.help COMMAND orchardseal --help)
    add_test(
        NAME orchardseal.audit-smoke
        COMMAND "${CMAKE_COMMAND}"
            "-DORCHARDSEAL_BIN=$<TARGET_FILE:orchardseal>"
            "-DFIXTURE_BINARY=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/macho/arm64-executable"
            "-DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/tests/audit-smoke"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/audit_smoke.cmake"
    )
    add_test(
        NAME orchardseal.archive-safety
        COMMAND "${CMAKE_COMMAND}"
            "-DORCHARDSEAL_BIN=$<TARGET_FILE:orchardseal>"
            "-DMALICIOUS_ARCHIVE=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/archives/path-traversal.zip"
            "-DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/tests/archive-safety"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/archive_safety.cmake"
    )
    add_test(
        NAME orchardseal.malformed-macho
        COMMAND "${CMAKE_COMMAND}"
            "-DORCHARDSEAL_BIN=$<TARGET_FILE:orchardseal>"
            "-DMALFORMED_MACHO=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/macho/malformed-load-command"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/malformed_macho.cmake"
    )
endif()
