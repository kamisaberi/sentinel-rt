/**
 * @file llamacpp_adapter.cpp
 * @brief llama.cpp Security Auditor Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/adapters/llamacpp_adapter.hpp>
#include <limits>
#include <format>

namespace sentinel::adapters {

LlamaCppAdapter::~LlamaCppAdapter() {
    release();
}

Status LlamaCppAdapter::init_context(const LlamaContextParams& params) {
    release();

    if (params.n_ctx == 0 || params.vocab_size == 0 || params.embedding_dim == 0) {
        return Status::ErrMalformedHeader;
    }

    // 1. Calculate required GPU memory size for offloaded layers
    // Size = n_ctx * embedding_dim * sizeof(float16) * 2 (K/V cache)
    constexpr size_t element_size = 2; // FP16
    uint64_t ctx_tokens = params.n_ctx;
    uint64_t embed_dim = params.embedding_dim;

    if (ctx_tokens > std::numeric_limits<uint64_t>::max() / embed_dim) {
        return Status::ErrIntegerOverflow;
    }

    uint64_t total_elements = ctx_tokens * embed_dim * 2;
    if (total_elements > std::numeric_limits<uint64_t>::max() / element_size) {
        return Status::ErrIntegerOverflow;
    }

    size_t required_bytes = total_elements * element_size;

    // 2. Allocate VRAM if GPU offloading is requested
    if (params.n_gpu_layers > 0) {
        std::string label = std::format("llama_cpp_ctx_{}_layers", params.n_gpu_layers);
        Status status = sanitizers::CUDASanitizer::instance().audit_malloc(&m_gpu_context_ptr, required_bytes, label);
        if (status != Status::Success) {
            return status;
        }
    }

    m_params = params;
    m_allocated_bytes = required_bytes;
    m_initialized = true;

    return Status::Success;
}

Status LlamaCppAdapter::audit_tokens(std::span<const int32_t> tokens) const {
    if (!m_initialized) {
        return Status::ErrSanitizerViolation;
    }

    // Guard against prompt length exceeding the configured context window
    if (tokens.size() > m_params.n_ctx) {
        return Status::ErrOutOfBoundsRead;
    }

    // Audit individual token ID values against the vocabulary size
    for (int32_t token_id : tokens) {
        if (token_id < 0 || static_cast<size_t>(token_id) >= m_params.vocab_size) {
            return Status::ErrOutOfBoundsRead; // Invalid token ID
        }
    }

    return Status::Success;
}

Status LlamaCppAdapter::audit_prompt_string(std::string_view text) const {
    // Prevent overly huge text buffers (e.g., > 10 MB prompts) from overflowing memory
    constexpr size_t MAX_PROMPT_BYTES = 10 * 1024 * 1024;
    if (text.size() > MAX_PROMPT_BYTES) {
        return Status::ErrOutOfBoundsRead;
    }

    return Status::Success;
}

void LlamaCppAdapter::release() noexcept {
    if (m_gpu_context_ptr != nullptr) {
        sanitizers::CUDASanitizer::instance().audit_free(m_gpu_context_ptr);
        m_gpu_context_ptr = nullptr;
    }
    m_allocated_bytes = 0;
    m_initialized = false;
}

} // namespace sentinel::adapters