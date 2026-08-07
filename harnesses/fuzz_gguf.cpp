/**
 * @file fuzz_gguf.cpp
 * @brief Complete LibFuzzer Harness for GGUF Format Parser in sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 * 
 * Compilation with Clang (LibFuzzer + AddressSanitizer):
 *   clang++ -std=c++20 -O2 -g -fsanitize=fuzzer,address,undefined \
 *     -I../include harnesses/fuzz_gguf.cpp src/parsers/gguf_parser.cpp \
 *     -o fuzz_gguf
 * 
 * Compilation for Standalone Driver (Without LibFuzzer):
 *   clang++ -std=c++20 -O2 -g -DSENTINEL_FUZZ_STANDALONE -fsanitize=address \
 *     -I../include harnesses/fuzz_gguf.cpp src/parsers/gguf_parser.cpp \
 *     -o fuzz_gguf_standalone
 * 
 * Execution:
 *   ./fuzz_gguf ../seeds/gguf/ -max_len=1048576 -rss_limit_mb=4096 -jobs=4 -workers=4
 */

#include <sentinel/parsers/gguf_parser.hpp>

#include <cstdint>
#include <cstddef>
#include <iostream>
#include <fstream>
#include <vector>
#include <span>

/**
 * @brief LibFuzzer initialization callback.
 * Called once at startup before the first fuzzing iteration.
 */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    // Suppress C++ standard output streams during fuzzing for performance
    std::cout.rdbuf(nullptr);
    std::cerr.rdbuf(nullptr);
    return 0;
}

/**
 * @brief LibFuzzer target entrypoint.
 * 
 * Called continuously by LibFuzzer/AFL++ with mutated input byte streams.
 * 
 * @param data Pointer to raw fuzz input byte array.
 * @param size Length of the fuzz input in bytes.
 * @return 0 on completion.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 1. Early rejection filter for extremely small inputs
    if (size < sizeof(uint32_t) * 2) {
        return 0; // GGUF requires at least magic (4B) + version (4B)
    }

    // 2. Wrap input in non-owning C++20 span
    std::span<const uint8_t> buffer(data, size);

    // 3. Instantiate target parser
    sentinel::parsers::GGUFParser parser;

    // 4. Execute parsing and boundary audit
    try {
        sentinel::Status status = parser.parse(buffer);

        if (status == sentinel::Status::Success) {
            // Force AddressSanitizer to exercise memory allocations in parsed data structures
            const auto &header = parser.header();
            (void)header.magic;
            (void)header.version;
            (void)header.tensor_count;
            (void)header.metadata_kv_count;

            // Iterate over key-value metadata to exercise hash map allocations
            const auto &metadata = parser.metadata();
            for (const auto &[key, val] : metadata) {
                (void)key.size();
                (void)val.index();
            }

            // Iterate over tensor descriptors to exercise dimension calculations and memory bounds
            const auto &tensors = parser.tensors();
            for (const auto &tensor : tensors) {
                (void)tensor.name.size();
                (void)tensor.dimensions.size();
                (void)tensor.calculated_bytes;
                (void)tensor.offset;
            }

            // Perform secondary mathematical boundary validation
            (void)parser.validate_tensor_metadata();
        }
    } catch (const sentinel::SentinelException &/* ex */) {
        // Expected bounds-check failure exceptions caught safely.
        // Unhandled hardware crashes (SIGSEGV, ASan heap-buffer-overflow) will be caught by ASan.
    } catch (...) {
        // Catch any unhandled C++ runtime exceptions
    }

    // 5. Explicitly reset parser state to verify destructor and allocator cleanup
    parser.reset();

    return 0;
}

#ifdef SENTINEL_FUZZ_STANDALONE
/**
 * @brief Standalone main function for testing seed files without LibFuzzer.
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <path_to_gguf_seed_file>" << std::endl;
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << argv[1] << std::endl;
        return 1;
    }

    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(file_size));
    if (!file.read(reinterpret_cast<char *>(buffer.data()), file_size)) {
        std::cerr << "Failed to read file into memory." << std::endl;
        return 1;
    }

    std::cout << "[SENTINEL-STANDALONE] Executing test on file: " << argv[1] 
              << " (" << file_size << " bytes)" << std::endl;

    int result = LLVMFuzzerTestOneInput(buffer.data(), buffer.size());

    std::cout << "[SENTINEL-STANDALONE] Execution completed successfully (Exit Code: " 
              << result << ")." << std::endl;

    return 0;
}
#endif