/**
 * @file fuzz_safetensors.cpp
 * @brief LibFuzzer Harness for Safetensors Parser in sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/parsers/safetensors_parser.hpp>

#include <cstdint>
#include <cstddef>
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
    if (size < sizeof(uint64_t)) {
        return 0; // Safetensors requires at least an 8-byte header size prefix
    }

    std::span<const uint8_t> buffer(data, size);
    sentinel::parsers::SafetensorsParser parser;

    try {
        sentinel::Status status = parser.parse(buffer);

        if (status == sentinel::Status::Success) {
            const auto &header = parser.header();
            (void)header.header_size_bytes;
            (void)header.total_tensor_count;

            const auto &tensors = parser.tensors();
            for (const auto &tensor : tensors) {
                (void)tensor.name.size();
                (void)tensor.dtype.size();
                (void)tensor.data_offsets[0];
                (void)tensor.data_offsets[1];
                (void)tensor.calculated_bytes;
            }

            (void)parser.validate_boundaries(size);
        }
    } catch (const sentinel::SentinelException &) {
        // Expected bounds check exceptions gracefully handled
    } catch (...) {
        // Catch any unhandled C++ runtime exceptions
    }

    parser.reset();
    return 0;
}