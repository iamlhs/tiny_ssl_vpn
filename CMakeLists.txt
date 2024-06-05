cmake_minimum_required(VERSION 3.12)#这行指定CMake的最小版本要求是3.12。

project(tiny_ssl_vpn)#这行设置项目的名称是 tiny_ssl_vpn。

#这三行分别定义了三个选项，默认值分别为 ON、ON 和 OFF。这些选项可以在命令行中通过 -D 标志覆盖。
option(REQUIRE_SERVER_HANDSHAKE "Require the server to perform a handshake" ON)
option(USE_ZSTD "Use ZSTD for compression" ON)
option(HELLO_MSG "Print Hello World instead of the message from the TUN" OFF)

#如果 REQUIRE_SERVER_HANDSHAKE 选项被启用，这行代码会在编译时添加一个定义 REQUIRE_SERVER_HANDSHAKE。
if (REQUIRE_SERVER_HANDSHAKE)
    add_compile_definitions(REQUIRE_SERVER_HANDSHAKE)
endif()

#如果 HELLO_MSG 选项被启用，这行代码会在编译时添加一个定义 HELLO_MSG。
if (HELLO_MSG)
    add_compile_definitions(HELLO_MSG)
endif()

#如果 USE_ZSTD 选项被启用，这行代码会在编译时添加一个定义 USE_ZSTD，并且会查找 zstd 库的配置。
if (USE_ZSTD)
    add_compile_definitions(USE_ZSTD)
    find_package(zstd CONFIG REQUIRED)
endif()

#如果 USE_ZSTD 选项被启用，这行代码会在编译时添加一个定义 USE_ZSTD，并且会查找 zstd 库的配置。
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

#这段代码仅在MSVC（Microsoft Visual C++）编译器下执行。它会定义 _WIN32_WINNT 预处理器定义，并复制 wintun.dll 文件到二进制目录。
set(CMAKE_CXX_STANDARD 20)

#这些行使用 find_package 命令来查找外部库的配置，包括 PkgConfig、spdlog、asio、protobuf 和 gmpxx。
#这一行指令CMake去查找PkgConfig库的配置，这是用于在CMake中处理外部库的一种方式。REQUIRED标志表示这个包是必须的。
find_package(PkgConfig REQUIRED)
#这一行指令CMake去查找spdlog库的配置，spdlog是一个高性能的日志库。CONFIG表示CMake会查找预配置的spdlog包，REQUIRED表示这个包是必须的。
find_package(spdlog CONFIG REQUIRED)
#这一行指令CMake去查找asio库的配置，asio是一个用于网络编程的库。CONFIG和REQUIRED的含义同上。
find_package(asio CONFIG REQUIRED)
#这一行指令CMake去查找protobuf库的配置，protobuf是一个用于序列化结构z的库，常用于跨语言通信。CONFIG和REQUIRED的含义同上。
find_package(protobuf CONFIG REQUIRED)
#这一行指令CMake去检查gmpxx模块，这是GMP库的一个组件，用于处理大整数。REQUIRED表示这个模块是必须的，IMPORTED_TARGET表示CMake将创建一个名为gmpxx的目标来引用这个库。
pkg_check_modules(gmpxx REQUIRED IMPORTED_TARGET gmpxx)

#这一行设置了一个变量PROTO_FILE，它的值是当前源代码目录下utils子目录中的message.proto文件。
set(PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/utils/message.proto")
#这一行调用了一个CMake宏protobuf_generate_cpp，它根据message.proto文件生成C++源文件和头文件。生成的文件被命名为PROTO_SRCS和PROTO_HDRS。
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILE})

#这一行指令CMake创建一个名为client的可执行文件，它的主要源文件是client/main.cpp，并且它包含了PROTO_SRCS和PROTO_HDRS中定义的Protobuf源文件和头文件。
add_executable(client client/main.cpp ${PROTO_SRCS} ${PROTO_HDRS})
#这一行链接client可执行文件时需要链接的库。它链接了gmpxx、asio、spdlog、protobuf和protoc（protobuf的编译器）。$<IF:$<TARGET_EXISTS:zstd::libzstd_shared>,zstd::libzstd_shared,zstd::libzstd_static>是一个条件表达式，如果zstd::libzstd_shared目标存在，则链接共享版本的zstd库，否则链接静态版本的zstd库。
target_link_libraries(client PkgConfig::gmpxx asio::asio spdlog::spdlog protobuf::libprotobuf protobuf::libprotoc $<IF:$<TARGET_EXISTS:zstd::libzstd_shared>,zstd::libzstd_shared,zstd::libzstd_static>)
#这一行指令CMake将CMAKE_CURRENT_BINARY_DIR目录添加到client可执行文件的私有包含目录中。这意味着在编译client时，它的源文件会查找这个目录中的头文件
target_include_directories(client PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

add_executable(server server/main.cpp ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(server PkgConfig::gmpxx asio::asio spdlog::spdlog protobuf::libprotobuf protobuf::libprotoc $<IF:$<TARGET_EXISTS:zstd::libzstd_shared>,zstd::libzstd_shared,zstd::libzstd_static>)
target_include_directories(server PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

add_executable(ca utils/ca.cpp)
target_link_libraries(ca PkgConfig::gmpxx spdlog::spdlog)
target_include_directories(ca PRIVATE ${CMAKE_CURRENT_BINARY_DIR})