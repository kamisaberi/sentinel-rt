# tests/CMakeLists.txt
# Unit Test Configuration for sentinel-rt

message(STATUS "[sentinel-rt] Configuring Unit Tests")

# Test 1: GGUF Parser
add_executable(test_gguf_parser test_gguf_parser.cpp)
target_link_libraries(test_gguf_parser PRIVATE sentinel_core)
add_test(NAME GGUFParserTest COMMAND test_gguf_parser)

# Test 2: CUDA Sanitizer
add_executable(test_cuda_sanitizer test_cuda_sanitizer.cpp)
target_link_libraries(test_cuda_sanitizer PRIVATE sentinel_core)
add_test(NAME CUDASanitizerTest COMMAND test_cuda_sanitizer)

# Test 3: Crash Analyzer
add_executable(test_crash_analyzer test_crash_analyzer.cpp)
target_link_libraries(test_crash_analyzer PRIVATE sentinel_core)
add_test(NAME CrashAnalyzerTest COMMAND test_crash_analyzer)