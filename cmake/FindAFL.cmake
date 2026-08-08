# cmake/FindAFL.cmake
# Finds AFL++ Fuzzing Tools and Compiler Wrappers

find_program(AFL_FUZZ_EXECUTABLE NAMES afl-fuzz)
find_program(AFL_CXX_COMPILER NAMES afl-clang-lto++ afl-clang-fast++ afl-g++)
find_program(AFL_CMIN_EXECUTABLE NAMES afl-cmin)
find_program(AFL_TMIN_EXECUTABLE NAMES afl-tmin)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(AFL DEFAULT_MSG AFL_FUZZ_EXECUTABLE AFL_CXX_COMPILER)

if(AFL_FOUND)
    message(STATUS "[sentinel-rt] Found AFL++ Fuzzer: ${AFL_FUZZ_EXECUTABLE}")
    message(STATUS "[sentinel-rt] Found AFL++ Compiler Wrapper: ${AFL_CXX_COMPILER}")
else()
    message(STATUS "[sentinel-rt] AFL++ not found. AFL++ targets will be skipped.")
endif()