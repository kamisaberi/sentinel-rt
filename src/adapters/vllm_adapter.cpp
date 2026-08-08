/**
 * @file vllm_adapter.cpp
 * @brief vLLM Memory Safety & PagedAttention Auditor Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/adapters/vllm_adapter.hpp>
#include <format>

namespace sentinel::adapters {

Status VLLMAdapter::allocate_kv_block(uint32_t block_id, uint32_t block_size, size_t num_heads, size_t head_dim) {
    if (m_blocks.contains(block_id)) {
        return Status::ErrCUDAAllocation; // Block ID already exists
    }

    // PagedAttention Block Size Calculation: block_size * num_heads * head_dim * sizeof(fp16) * 2 (Key + Value)
    size_t element_size = 2; // FP16
    size_t bytes_per_token = num_heads * head_dim * element_size * 2;
    size_t total_bytes = static_cast<size_t>(block_size) * bytes_per_token;

    void* dev_ptr = nullptr;
    std::string label = std::format("vLLM_KV_Block_{}", block_id);

    // Delegate allocation to CUDASanitizer to inject redzone boundaries
    Status status = sanitizers::CUDASanitizer::instance().audit_malloc(&dev_ptr, total_bytes, label);
    if (status != Status::Success) {
        return status;
    }

    KVCacheBlockMetadata meta{
        .block_id = block_id,
        .block_size_tokens = block_size,
        .num_heads = num_heads,
        .head_dim = head_dim,
        .device_ptr = dev_ptr,
        .total_bytes = total_bytes
    };

    m_blocks.insert_or_assign(block_id, meta);
    return Status::Success;
}

bool VLLMAdapter::validate_token_access(uint32_t block_id, uint32_t token_index) const {
    auto it = m_blocks.find(block_id);
    if (it == m_blocks.end()) {
        return false; // Invalid block access
    }

    const auto& meta = it->second;
    if (token_index >= meta.block_size_tokens) {
        return false; // Out of bounds token index inside physical page
    }

    // Delegate memory check to CUDA Sanitizer
    size_t bytes_per_token = meta.num_heads * meta.head_dim * 2 * 2;
    uintptr_t token_addr = reinterpret_cast<uintptr_t>(meta.device_ptr) + (token_index * bytes_per_token);

    return sanitizers::CUDASanitizer::instance().check_bounds(reinterpret_cast<const void*>(token_addr), bytes_per_token);
}

Status VLLMAdapter::free_kv_block(uint32_t block_id) {
    auto it = m_blocks.find(block_id);
    if (it == m_blocks.end()) {
        return Status::ErrCUDABoundaryViolation;
    }

    Status status = sanitizers::CUDASanitizer::instance().audit_free(it->second.device_ptr);
    m_blocks.erase(it);
    return status;
}

void VLLMAdapter::reset() noexcept {
    for (const auto& [id, meta] : m_blocks) {
        sanitizers::CUDASanitizer::instance().audit_free(meta.device_ptr);
    }
    m_blocks.clear();
}

} // namespace sentinel::adapters