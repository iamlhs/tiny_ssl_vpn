cmake_minimum_required(VERSION 3.12)
project(tiny_ssl_vpn)

option(REQUIRE_SERVER_HANDSHAKE "Require the server to perform a handshake" ON)
option(USE_ZSTD "Use ZSTD for compression" ON)
option(HELLO_MSG "Print Hello World instead of the message from the TUN" OFF)

if (REQUIRE_SERVER_HANDSHAKE)
    add_compile_definitions(REQUIRE_SERVER_HANDSHAKE)
endif()

if (HELLO_MSG)
    add_compile_definitions(HELLO_MSG)
endif()

if (USE_ZSTD)
    add_compile_definitions(USE_ZSTD)
    find_package(zstd CONFIG REQUIRED)
endif()

if (MSVC)
    add_compile_definitions(_WIN32_WINNT=0x0A00) # Change this to the appropriate value to target other versions of Windows.
    # copy the dlls in the wintun directory to the binary directory
    string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} ARCH)
    if (CMAKE_BUILD_TYPE)
        file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/wintun/bin/${ARCH}/wintun.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_BUILD_TYPE})
    else()
        file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/wintun/bin/${ARCH}/wintun.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
    endif()
    message(STATUS "Copied wintun.dll to ${CMAKE_BUILD_TYPE}")
endif()

set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(protobuf CONFIG REQUIRED)
pkg_check_modules(gmpxx REQUIRED IMPORTED_TARGET gmpxx)

set(PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/utils/message.proto")
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILE})

add_executable(client client/main.cpp ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(client PkgConfig::gmpxx asio::asio spdlog::spdlog protobuf::libprotobuf protobuf::libprotoc $<IF:$<TARGET_EXISTS:zstd::libzstd_shared>,zstd::libzstd_shared,zstd::libzstd_static>)
target_include_directories(client PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

add_executable(server server/main.cpp ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(server PkgConfig::gmpxx asio::asio spdlog::spdlog protobuf::libprotobuf protobuf::libprotoc $<IF:$<TARGET_EXISTS:zstd::libzstd_shared>,zstd::libzstd_shared,zstd::libzstd_static>)
target_include_directories(server PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

add_executable(ca utils/ca.cpp)
target_link_libraries(ca PkgConfig::gmpxx spdlog::spdlog)
target_include_directories(ca PRIVATE ${CMAKE_CURRENT_BINARY_DIR})