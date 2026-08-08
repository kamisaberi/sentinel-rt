/**
 * @file test_cuda_sanitizer.cpp
 * @brief Unit Tests for CUDA Sanitizer in sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/sanitizers/cuda_sanitizer.hpp>
#include <cassert>
#include <iostream>

void test_allocation_and_bounds() {
    auto& sanitizer = sentinel::sanitizers::CUDASanitizer::instance();
    void* dev_ptr = nullptr;
    size_t alloc_bytes = 1024;

    sentinel::Status status = sanitizer.audit_malloc(&dev_ptr, alloc_bytes, "UnitTestBuffer");
    assert(status == sentinel::Status::Success);
    assert(dev_ptr != nullptr);

    // Test valid access inside bounds
    assert(sanitizer.check_bounds(dev_ptr, 512) == true);
    assert(sanitizer.check_bounds(dev_ptr, 1024) == true);

    // Test invalid access out of bounds
    assert(sanitizer.check_bounds(dev_ptr, 1025) == false);

    // Test free
    status = sanitizer.audit_free(dev_ptr);
    assert(status == sentinel::Status::Success);

    // Test double free detection
    status = sanitizer.audit_free(dev_ptr);
    assert(status == sentinel::Status::ErrCUDABoundaryViolation);

    std::cout << "[PASS] test_allocation_and_bounds\n";
}

int main() {
    std::cout << "[SENTINEL-TEST] Running CUDA Sanitizer Unit Tests...\n";
    test_allocation_and_bounds();
    std::cout << "[SENTINEL-TEST] All CUDA Sanitizer Tests PASSED!\n";
    return 0;
}