/**
 * @file test_gguf_parser.cpp
 * @brief Unit Tests for GGUF Parser in sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/parsers/gguf_parser.hpp>
#include <cassert>
#include <iostream>
#include <vector>
#include <cstring>

void test_invalid_magic() {
    std::vector<uint8_t> buffer = {0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
    sentinel::parsers::GGUFParser parser;

    sentinel::Status status = parser.parse(buffer);
    assert(status == sentinel::Status::ErrInvalidMagic);
    std::cout << "[PASS] test_invalid_magic\n";
}

void test_valid_header_parsing() {
    std::vector<uint8_t> buffer(32, 0);
    uint32_t magic = sentinel::parsers::GGUF_MAGIC;
    uint32_t version = 3;
    uint64_t tensor_count = 0;
    uint64_t kv_count = 0;

    std::memcpy(buffer.data(), &magic, 4);
    std::memcpy(buffer.data() + 4, &version, 4);
    std::memcpy(buffer.data() + 8, &tensor_count, 8);
    std::memcpy(buffer.data() + 16, &kv_count, 8);

    sentinel::parsers::GGUFParser parser;
    sentinel::Status status = parser.parse(buffer);

    assert(status == sentinel::Status::Success);
    assert(parser.header().magic == sentinel::parsers::GGUF_MAGIC);
    assert(parser.header().version == 3);
    assert(parser.header().tensor_count == 0);
    std::cout << "[PASS] test_valid_header_parsing\n";
}

int main() {
    std::cout << "[SENTINEL-TEST] Running GGUF Parser Unit Tests...\n";
    test_invalid_magic();
    test_valid_header_parsing();
    std::cout << "[SENTINEL-TEST] All GGUF Parser Tests PASSED!\n";
    return 0;
}