# ==============================================================================
# Project: sentinel-rt
# Description: High-Throughput C++/CUDA Fuzzing Harness & Memory Auditor
# Author: Kamran Saberifard
# License: Apache 2.0
# ==============================================================================

cmake_minimum_required(VERSION 3.20)

project(sentinel-rt
    VERSION 0.1.0
    DESCRIPTION "Native AI Runtime Security Auditor & Fuzzer"
    LANGUAGES CXX CUDA
)

# ------------------------------------------------------------------------------
# 1. C++ Standard & Global Configuration
# ------------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for language servers (clangd, ccls)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Default to Debug build type if none is specified (ideal for fuzzing/sanitizers)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose build type: Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ------------------------------------------------------------------------------
# 2. Build Options
# ------------------------------------------------------------------------------
option(SENTINEL_ENABLE_ASAN      "Enable AddressSanitizer (ASan)"          ON)
option(SENTINEL_ENABLE_UBSAN     "Enable UndefinedBehaviorSanitizer"       ON)
option(SENTINEL_ENABLE_TSAN      "Enable ThreadSanitizer (TSan)"           OFF)
option(SENTINEL_ENABLE_COVERAGE  "Enable Source-Based Code Coverage"       OFF)
option(SENTINEL_BUILD_HARNESSES  "Build LibFuzzer & AFL++ Harnesses"       ON)
option(SENTINEL_BUILD_MUTATORS   "Build Custom AFL++ Structure Mutators"   ON)
option(SENTINEL_BUILD_TESTS      "Build Unit & Integration Tests"          ON)

# ------------------------------------------------------------------------------
# 3. Compiler Flags & Warnings
# ------------------------------------------------------------------------------
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
    )
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
        -Wmisleading-indentation
        -Wduplicated-cond
        -Wduplicated-branches
        -Wlogical-op
    )
endif()

# ------------------------------------------------------------------------------
# 4. Sanitizers Configuration
# ------------------------------------------------------------------------------
set(SENTINEL_SANITIZER_FLAGS "")

if(SENTINEL_ENABLE_ASAN)
    message(STATUS "[sentinel-rt] Enabling AddressSanitizer (ASan)")
    list(APPEND SENTINEL_SANITIZER_FLAGS "-fsanitize=address" "-fno-omit-frame-pointer")
endif()

if(SENTINEL_ENABLE_UBSAN)
    message(STATUS "[sentinel-rt] Enabling UndefinedBehaviorSanitizer (UBSan)")
    list(APPEND SENTINEL_SANITIZER_FLAGS "-fsanitize=undefined" "-fno-sanitize-recover=all")
endif()

if(SENTINEL_ENABLE_TSAN)
    if(SENTINEL_ENABLE_ASAN)
        message(FATAL_ERROR "[sentinel-rt] AddressSanitizer and ThreadSanitizer cannot be used together.")
    endif()
    message(STATUS "[sentinel-rt] Enabling ThreadSanitizer (TSan)")
    list(APPEND SENTINEL_SANITIZER_FLAGS "-fsanitize=thread")
endif()

if(SENTINEL_ENABLE_COVERAGE)
    message(STATUS "[sentinel-rt] Enabling Clang Source Coverage")
    list(APPEND SENTINEL_SANITIZER_FLAGS "-fprofile-instr-generate" "-fcoverage-mapping")
endif()

# Apply sanitizer flags to CXX options
add_compile_options(${SENTINEL_SANITIZER_FLAGS})
add_link_options(${SENTINEL_SANITIZER_FLAGS})

# ------------------------------------------------------------------------------
# 5. CUDA Dependencies & Architecture Flags
# ------------------------------------------------------------------------------
find_package(CUDAToolkit REQUIRED)

set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

# Enable modern GPU architectures (Ampere, Hopper, Blackwell ready)
if(NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES 80 86 89 90)
endif()

message(STATUS "[sentinel-rt] CUDA Version: ${CUDAToolkit_VERSION}")
message(STATUS "[sentinel-rt] Target CUDA Architectures: ${CMAKE_CUDA_ARCHITECTURES}")

# ------------------------------------------------------------------------------
# 6. Core Library Target (`sentinel_core`)
# ------------------------------------------------------------------------------
file(GLOB_RECURSE SENTINEL_SOURCES
    "src/*.cpp"
    "src/*.cu"
)

add_library(sentinel_core SHARED ${SENTINEL_SOURCES})

target_include_directories(sentinel_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        ${CUDAToolkit_INCLUDE_DIRS}
)

target_link_libraries(sentinel_core
    PUBLIC
        CUDA::cudart
        CUDA::cuda_driver
        Threads::Threads
)

target_compile_definitions(sentinel_core
    PRIVATE
        SENTINEL_BUILD_INTERNAL=1
)

# ------------------------------------------------------------------------------
# 7. Fuzzing Harnesses Target
# ------------------------------------------------------------------------------
if(SENTINEL_BUILD_HARNESSES)
    message(STATUS "[sentinel-rt] Configuring Fuzzing Harnesses")

    # Check for LibFuzzer support via Clang
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        set(FUZZ_FLAGS "-fsanitize=fuzzer")

        # GGUF Parser Harness
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/harnesses/fuzz_gguf.cpp")
            add_executable(fuzz_gguf harnesses/fuzz_gguf.cpp)
            target_link_libraries(fuzz_gguf PRIVATE sentinel_core)
            target_compile_options(fuzz_gguf PRIVATE ${FUZZ_FLAGS})
            target_link_options(fuzz_gguf PRIVATE ${FUZZ_FLAGS})
        endif()

        # Safetensors Parser Harness
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/harnesses/fuzz_safetensors.cpp")
            add_executable(fuzz_safetensors harnesses/fuzz_safetensors.cpp)
            target_link_libraries(fuzz_safetensors PRIVATE sentinel_core)
            target_compile_options(fuzz_safetensors PRIVATE ${FUZZ_FLAGS})
            target_link_options(fuzz_safetensors PRIVATE ${FUZZ_FLAGS})
        endif()

        # ONNX Parser Harness
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/harnesses/fuzz_onnx.cpp")
            add_executable(fuzz_onnx harnesses/fuzz_onnx.cpp)
            target_link_libraries(fuzz_onnx PRIVATE sentinel_core)
            target_compile_options(fuzz_onnx PRIVATE ${FUZZ_FLAGS})
            target_link_options(fuzz_onnx PRIVATE ${FUZZ_FLAGS})
        endif()

    else()
        message(WARNING "[sentinel-rt] LibFuzzer requires Clang compiler. Harness targets skipped.")
    endif()
endif()

# ------------------------------------------------------------------------------
# 8. Custom AFL++ Mutator Modules
# ------------------------------------------------------------------------------
if(SENTINEL_BUILD_MUTATORS)
    message(STATUS "[sentinel-rt] Configuring AFL++ Custom Mutators")

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/mutators/gguf_mutator.cpp")
        add_library(gguf_mutator SHARED mutators/gguf_mutator.cpp)
        target_include_directories(gguf_mutator PRIVATE include)
        set_target_properties(gguf_mutator PROPERTIES PREFIX "")
    endif()

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/mutators/safetensors_mutator.cpp")
        add_library(safetensors_mutator SHARED mutators/safetensors_mutator.cpp)
        target_include_directories(safetensors_mutator PRIVATE include)
        set_target_properties(safetensors_mutator PROPERTIES PREFIX "")
    endif()
endif()

# ------------------------------------------------------------------------------
# 9. Unit Testing Targets
# ------------------------------------------------------------------------------
if(SENTINEL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ------------------------------------------------------------------------------
# 10. Summary Display
# ------------------------------------------------------------------------------
message(STATUS "------------------------------------------------------------")
message(STATUS " sentinel-rt Configuration Summary")
message(STATUS "------------------------------------------------------------")
message(STATUS " Build Type           : ${CMAKE_BUILD_TYPE}")
message(STATUS " C++ Compiler         : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS " AddressSanitizer     : ${SENTINEL_ENABLE_ASAN}")
message(STATUS " UBSanitizer          : ${SENTINEL_ENABLE_UBSAN}")
message(STATUS " Build Harnesses      : ${SENTINEL_BUILD_HARNESSES}")
message(STATUS " Build Mutators       : ${SENTINEL_BUILD_MUTATORS}")
message(STATUS "------------------------------------------------------------")