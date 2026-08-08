/**
 * @file fuzz_onnx.cpp
 * @brief LibFuzzer Harness for ONNX Parser in sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/parsers/onnx_parser.hpp>

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
    if (size < 4) {
        return 0; // Minimum protobuf varint tag size requirement
    }

    std::span<const uint8_t> buffer(data, size);
    sentinel::parsers::ONNXParser parser;

    try {
        sentinel::Status status = parser.parse(buffer);

        if (status == sentinel::Status::Success) {
            const auto &header = parser.header();
            (void)header.ir_version;
            (void)header.model_version;
            (void)header.node_count;
            (void)header.producer_name.size();

            const auto &nodes = parser.nodes();
            for (const auto &node : nodes) {
                (void)node.op_type.size();
                (void)node.name.size();
                (void)node.inputs.size();
                (void)node.outputs.size();
            }

            (void)parser.validate_graph_metadata();
        }
    } catch (const sentinel::SentinelException &) {
        // Expected bounds check exceptions gracefully caught
    } catch (...) {
        // Catch any unhandled C++ runtime exceptions
    }

    parser.reset();
    return 0;
}