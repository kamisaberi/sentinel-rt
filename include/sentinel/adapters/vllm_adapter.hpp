/**
 * @file vllm_adapter.hpp
 * @brief Memory Safety & KV-Cache Boundary Audit Adapter for vLLM Backends
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <sentinel/sentinel.hpp>
#include <sentinel/sanitizers/cuda_sanitizer.hpp>

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

namespace sentinel::adapters {

/**
 * @brief Metadata tracking a vLLM PagedAttention KV-Cache memory allocation block.
 */
struct SENTINEL_API KVCacheBlockMetadata {
    uint32_t block_id{0};
    uint32_t block_size_tokens{0};
    size_t num_heads{0};
    size_t head_dim{0};
    void* device_ptr{nullptr};
    size_t total_bytes{0};
};

/**
 * @brief Memory Safety and PagedAttention Auditor for vLLM Execution Nodes.
 */
class SENTINEL_API VLLMAdapter {
public:
    VLLMAdapter() = default;
    ~VLLMAdapter() = default;

    /**
     * @brief Audits and allocates a vLLM PagedAttention KV-cache memory block on the GPU.
     * @param block_id Unique identifier for the KV-cache physical page.
     * @param block_size Number of tokens per block (e.g., 16 or 32).
     * @param num_heads Number of attention heads.
     * @param head_dim Head dimension size (e.g., 128).
     * @return Status::Success if allocated and registered with CUDA Sanitizer.
     */
    Status allocate_kv_block(uint32_t block_id, uint32_t block_size, size_t num_heads, size_t head_dim);

    /**
     * @brief Validates token index access within a physical PagedAttention block.
     * @param block_id Target block ID.
     * @param token_index Token index within block.
     * @return True if access falls strictly inside memory boundaries.
     */
    [[nodiscard]] bool validate_token_access(uint32_t block_id, uint32_t token_index) const;

    /**
     * @brief Frees and unregisters a KV-cache physical block.
     */
    Status free_kv_block(uint32_t block_id);

    /**
     * @brief Resets all tracked KV-cache blocks.
     */
    void reset() noexcept;

private:
    std::unordered_map<uint32_t, KVCacheBlockMetadata> m_blocks;
};

} // namespace sentinel::adapters