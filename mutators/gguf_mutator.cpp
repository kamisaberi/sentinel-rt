/**
 * @file gguf_mutator.cpp
 * @brief Structure-Aware AFL++ Custom Mutator for GGUF Binary Format
 * @author Kamran Saberifard
 * @license Apache 2.0
 * 
 * Compilation:
 *   clang++ -std=c++20 -O2 -fPIC -shared mutators/gguf_mutator.cpp -o gguf_mutator.so
 * 
 * Execution with AFL++:
 *   export AFL_CUSTOM_MUTATOR_LIBRARY="/path/to/gguf_mutator.so"
 *   afl-fuzz -i seeds/gguf -o out -- ./fuzz_gguf
 */

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>
#include <algorithm>

namespace {

constexpr uint32_t GGUF_MAGIC_LE = 0x46554747;

struct GGUFMutatorState {
    std::mt19937 rng;
    std::vector<uint8_t> output_buffer;

    explicit GGUFMutatorState(unsigned int seed) : rng(seed) {
        output_buffer.reserve(1024 * 1024); // 1 MB initial capacity
    }
};

enum class MutationStrategy {
    CorruptMagic = 0,
    CorruptVersion,
    ExtremeTensorCount,
    ExtremeMetadataCount,
    MangleStringLength,
    BitFlipPayload,
    Count
};

} // anonymous namespace

extern "C" {

/**
 * @brief Initializes the custom mutator state.
 * Called once by AFL++ during fuzzer startup.
 */
void *afl_custom_init(void * /* afl */, unsigned int seed) {
    return new GGUFMutatorState(seed);
}

/**
 * @brief Performs structure-aware mutation on the input buffer.
 * 
 * @param data Mutator instance pointer returned by afl_custom_init.
 * @param buf Raw seed buffer.
 * @param buf_size Size of the raw seed buffer.
 * @param out_buf Output pointer where mutated buffer address is written.
 * @param add_buf Additional mutation buffer (optional).
 * @param add_buf_size Size of additional mutation buffer.
 * @param max_size Maximum allowed output size.
 * @return Size of the mutated output buffer.
 */
size_t afl_custom_fuzz(
    void *data,
    uint8_t *buf,
    size_t buf_size,
    uint8_t **out_buf,
    uint8_t * /* add_buf */,
    size_t /* add_buf_size */,
    size_t max_size
) {
    if (!data || !buf || buf_size < 8) {
        *out_buf = buf;
        return buf_size;
    }

    auto *state = static_cast<GGUFMutatorState *>(data);
    state->output_buffer.assign(buf, buf + buf_size);

    std::uniform_int_function<int> dist(0, static_cast<int>(MutationStrategy::Count) - 1);
    MutationStrategy strategy = static_cast<MutationStrategy>(dist(state->rng));

    switch (strategy) {
        case MutationStrategy::CorruptMagic: {
            // Flip magic bytes to test header magic validation
            uint32_t invalid_magic = (dist(state->rng) % 2 == 0) ? 0xDEADBEEF : 0x00000000;
            std::memcpy(state->output_buffer.data(), &invalid_magic, sizeof(uint32_t));
            break;
        }

        case MutationStrategy::CorruptVersion: {
            // Mutate GGUF version field (offset 4) to out-of-spec integers
            if (state->output_buffer.size() >= 8) {
                uint32_t bad_version = (dist(state->rng) % 2 == 0) ? 0 : 9999;
                std::memcpy(state->output_buffer.data() + 4, &bad_version, sizeof(uint32_t));
            }
            break;
        }

        case MutationStrategy::ExtremeTensorCount: {
            // Inject extreme tensor count integer (offset 8) to test for OOM/alloc vulnerabilities
            if (state->output_buffer.size() >= 16) {
                uint64_t extreme_count = 0xFFFFFFFFFFFFFFFF0000ULL;
                std::memcpy(state->output_buffer.data() + 8, &extreme_count, sizeof(uint64_t));
            }
            break;
        }

        case MutationStrategy::ExtremeMetadataCount: {
            // Inject extreme metadata KV count integer (offset 16)
            if (state->output_buffer.size() >= 24) {
                uint64_t extreme_count = 0x7FFFFFFFFFFFFFFFULL;
                std::memcpy(state->output_buffer.data() + 16, &extreme_count, sizeof(uint64_t));
            }
            break;
        }

        case MutationStrategy::MangleStringLength: {
            // Mangle length prefix of metadata strings if buffer is long enough
            if (state->output_buffer.size() >= 32) {
                uint64_t huge_str_len = 0x0000FFFFFFFFFFFFULL;
                std::memcpy(state->output_buffer.data() + 24, &huge_str_len, sizeof(uint64_t));
            }
            break;
        }

        case MutationStrategy::BitFlipPayload: {
            // Random bit flips in tensor metadata section
            if (state->output_buffer.size() > 24) {
                size_t offset = 24 + (static_cast<size_t>(dist(state->rng)) % (state->output_buffer.size() - 24));
                state->output_buffer[offset] ^= static_cast<uint8_t>(1 << (dist(state->rng) % 8));
            }
            break;
        }

        default:
            break;
    }

    // Ensure output size does not exceed AFL++ max_size
    if (state->output_buffer.size() > max_size) {
        state->output_buffer.resize(max_size);
    }

    *out_buf = state->output_buffer.data();
    return state->output_buffer.size();
}

/**
 * @brief Cleans up and frees custom mutator state.
 * Called by AFL++ upon session termination.
 */
void afl_custom_deinit(void *data) {
    if (data) {
        auto *state = static_cast<GGUFMutatorState *>(data);
        delete state;
    }
}

} // extern "C"