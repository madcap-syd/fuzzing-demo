cmake_minimum_required(VERSION 3.10)
project(fuzzing-demo VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Основная библиотека
add_library(packet_parser STATIC src/packet_parser.cpp)
target_include_directories(packet_parser PUBLIC src)

# Основное приложение
add_executable(packet_app src/main.cpp)
target_link_libraries(packet_app packet_parser)

# Harness для libFuzzer (собирается только с Clang)
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_executable(fuzz_libfuzzer fuzz/harness.cpp)
    target_link_libraries(fuzz_libfuzzer packet_parser)
    target_compile_options(fuzz_libfuzzer PRIVATE 
        -fsanitize=fuzzer,address,undefined 
        -O1 -g)
endif()

# Harness для AFL++
add_executable(fuzz_afl fuzz/afl_harness.cpp)
target_link_libraries(fuzz_afl packet_parser)
