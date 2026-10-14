cmake_minimum_required(VERSION 3.24)
project(SentinelGuard LANGUAGES C CXX)

if(NOT WIN32)
    message(FATAL_ERROR "SentinelGuard currently targets Windows.")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(SentinelGuard
    src/main.cpp
    src/scanner.c
    src/realtime.cpp
    src/virustotal.cpp
    src/service.cpp
)

target_include_directories(SentinelGuard PRIVATE include)
target_compile_definitions(SentinelGuard PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(SentinelGuard PRIVATE bcrypt winhttp advapi32)
add_custom_command(TARGET SentinelGuard POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/signatures.txt"
        "$<TARGET_FILE_DIR:SentinelGuard>/signatures.txt"
)

if(MSVC)
    target_compile_options(SentinelGuard PRIVATE /W4 /permissive- /utf-8)
endif()
