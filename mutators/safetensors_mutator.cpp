/**
 * @file safetensors_mutator.cpp
 * @brief Structure-Aware AFL++ Custom Mutator for Safetensors JSON Headers
 * @author Kamran Saberifard
 * @license Apache 2.0
 * 
 * Compilation:
 *   clang++ -std=c++20 -O2 -fPIC -shared mutators/safetensors_mutator.cpp -o safetensors_mutator.so
 */

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>
#include <string>

namespace {

struct SafetensorsMutatorState {
    std::mt19937 rng;
    std::vector<uint8_t> output_buffer;

    explicit SafetensorsMutatorState(unsigned int seed) : rng(seed) {
        output_buffer.reserve(512 * 1024); // 512 KB
    }
};

enum class MutationStrategy {
    CorruptHeaderLength = 0,
    InvalidJSONBrackets,
    ExtremeDataOffsets,
    MangleDTypeString,
    Count
};

} // anonymous namespace

extern "C" {

void *afl_custom_init(void * /* afl */, unsigned int seed) {
    return new SafetensorsMutatorState(seed);
}

size_t afl_custom_fuzz(
    void *data,
    uint8_t *buf,
    size_t buf_size,
    uint8_t **out_buf,
    uint8_t * /* add_buf */,
    size_t /* add_buf_size */,
    size_t max_size
) {
    if (!data || !buf || buf_size < 12) {
        *out_buf = buf;
        return buf_size;
    }

    auto *state = static_cast<SafetensorsMutatorState *>(data);
    state->output_buffer.assign(buf, buf + buf_size);

    std::uniform_int_distribution<int> dist(0, static_cast<int>(MutationStrategy::Count) - 1);
    MutationStrategy strategy = static_cast<MutationStrategy>(dist(state->rng));

    switch (strategy) {
        case MutationStrategy::CorruptHeaderLength: {
            // Inject massive 64-bit uint header length (offset 0)
            uint64_t huge_len = 0xFFFFFFFFFF000000ULL;
            std::memcpy(state->output_buffer.data(), &huge_len, sizeof(uint64_t));
            break;
        }

        case MutationStrategy::InvalidJSONBrackets: {
            // Mangle JSON opening/closing braces
            if (state->output_buffer.size() > 8) {
                state->output_buffer[8] = '['; // Replace '{' with '['
            }
            break;
        }

        case MutationStrategy::ExtremeDataOffsets: {
            // Inject overlapping/inverted data offsets into the JSON string
            std::string malicious_json = R"({"weight":{"dtype":"F32","shape":[1],"data_offsets":[99999999, 100]}})";
            uint64_t new_len = malicious_json.size();

            state->output_buffer.resize(sizeof(uint64_t) + new_len);
            std::memcpy(state->output_buffer.data(), &new_len, sizeof(uint64_t));
            std::memcpy(state->output_buffer.data() + sizeof(uint64_t), malicious_json.data(), new_len);
            break;
        }

        case MutationStrategy::MangleDTypeString: {
            // Inject unknown data type string
            std::string bad_dtype = R"({"tensor":{"dtype":"MALICIOUS_TYPE_OVERFLOW","shape":[1],"data_offsets":[0,4]}})";
            uint64_t new_len = bad_dtype.size();

            state->output_buffer.resize(sizeof(uint64_t) + new_len);
            std::memcpy(state->output_buffer.data(), &new_len, sizeof(uint64_t));
            std::memcpy(state->output_buffer.data() + sizeof(uint64_t), bad_dtype.data(), new_len);
            break;
        }

        default:
            break;
    }

    if (state->output_buffer.size() > max_size) {
        state->output_buffer.resize(max_size);
    }

    *out_buf = state->output_buffer.data();
    return state->output_buffer.size();
}

void afl_custom_deinit(void *data) {
    if (data) {
        delete static_cast<SafetensorsMutatorState *>(data);
    }
}

} // extern "C"