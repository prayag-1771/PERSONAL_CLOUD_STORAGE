cmake_minimum_required(VERSION 3.16)
project(personal_cloud_storage LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# A plain "cmake .." should produce an optimised build rather than an
# unoptimised one, which matters when a file is being encrypted block by block.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# --- shared core -------------------------------------------------------------

add_library(pcs_core STATIC
    src/core/cipher.cpp
    src/core/daemon.cpp
    src/core/digest.cpp
    src/core/erasure.cpp
    src/core/gf256.cpp
    src/core/hex.cpp
    src/core/keysource.cpp
    src/core/manifest.cpp
    src/core/passwd.cpp
    src/core/progress.cpp
    src/core/protocol.cpp
    src/core/safename.cpp
    src/core/settings.cpp
    src/core/shardfile.cpp
    src/core/stream.cpp
    src/core/tlsca.cpp
    src/core/wire.cpp
)

target_include_directories(pcs_core PUBLIC include)
target_link_libraries(pcs_core
    PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

if(WIN32)
    target_link_libraries(pcs_core PUBLIC ws2_32)
endif()

if(MSVC)
    target_compile_options(pcs_core PRIVATE /W4)
else()
    target_compile_options(pcs_core PRIVATE -Wall -Wextra)
endif()

# Applies the same warning level to every target below.
function(pcs_configure target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra)
    endif()
endfunction()

# --- server ------------------------------------------------------------------

add_executable(pcs-server
    src/server/http.cpp
    src/server/main.cpp
    src/server/page.cpp
    src/server/webui.cpp
    src/server/session.cpp
    src/server/store.cpp
    src/server/users.cpp
)
target_include_directories(pcs-server PRIVATE src/server)
target_link_libraries(pcs-server PRIVATE pcs_core)
pcs_configure(pcs-server)

# --- client ------------------------------------------------------------------

add_executable(pcs-client
    src/client/main.cpp
    src/client/upload.cpp
    src/client/watch.cpp
    src/client/download.cpp
    src/client/list.cpp
    src/client/local.cpp
    src/client/sync.cpp
    src/client/recover.cpp
    src/client/remote.cpp
    src/client/workspace.cpp
)
target_include_directories(pcs-client PRIVATE src/client)
target_link_libraries(pcs-client PRIVATE pcs_core)
pcs_configure(pcs-client)

# --- tests -------------------------------------------------------------------

option(PCS_BUILD_TESTS "Build the unit tests" ON)

if(PCS_BUILD_TESTS)
    enable_testing()

    add_executable(pcs-tests
        tests/harness.cpp
        tests/test_basics.cpp
        tests/test_cipher.cpp
        tests/test_erasure.cpp
        tests/test_gf256.cpp
        tests/test_manifest.cpp
        tests/test_passwd.cpp
        tests/test_shardfile.cpp
        tests/test_settings.cpp
        tests/test_stream.cpp
        tests/test_http.cpp
        tests/test_tlsca.cpp
    )
    # The HTTP parser lives with the server but is worth testing directly.
    target_sources(pcs-tests PRIVATE src/server/http.cpp)
    target_include_directories(pcs-tests PRIVATE tests src/server)
    target_link_libraries(pcs-tests PRIVATE pcs_core)
    pcs_configure(pcs-tests)

    add_test(NAME unit COMMAND pcs-tests)
endif()
