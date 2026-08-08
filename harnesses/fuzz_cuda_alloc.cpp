/**
 * @file fuzz_cuda_alloc.cpp
 * @brief LibFuzzer Harness for CUDA Allocator Boundary Checking in sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/sanitizers/cuda_sanitizer.hpp>

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <span>

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    std::cout.rdbuf(nullptr);
    std::cerr.rdbuf(nullptr);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2) {
        return 0; // Need at least requested_size + access_size
    }

    size_t requested_alloc_size = 0;
    size_t test_access_size = 0;

    std::memcpy(&requested_alloc_size, data, sizeof(size_t));
    std::memcpy(&test_access_size, data + sizeof(size_t), sizeof(size_t));

    // Cap requested allocation size to avoid excessive VRAM usage during fuzzing
    requested_alloc_size %= (1024 * 1024 * 100); // Max 100 MB
    test_access_size %= (1024 * 1024 * 200);     // Max 200 MB

    void* dev_ptr = nullptr;
    auto& sanitizer = sentinel::sanitizers::CUDASanitizer::instance();

    // Audit allocation
    sentinel::Status status = sanitizer.audit_malloc(&dev_ptr, requested_alloc_size, "FuzzAlloc");

    if (status == sentinel::Status::Success && dev_ptr != nullptr) {
        // Test boundary checking logic
        bool is_valid = sanitizer.check_bounds(dev_ptr, test_access_size);
        (void)is_valid;

        // Test poisoning and unpoisoning logic
        (void)sanitizer.poison_region(dev_ptr, requested_alloc_size);
        (void)sanitizer.check_bounds(dev_ptr, test_access_size);
        (void)sanitizer.unpoison_region(dev_ptr, requested_alloc_size);

        // Audit free
        (void)sanitizer.audit_free(dev_ptr);
    }

    return 0;
}