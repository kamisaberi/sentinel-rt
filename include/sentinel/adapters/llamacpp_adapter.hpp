/**
 * @file llamacpp_adapter.hpp
 * @brief llama.cpp Execution Context & Tokenizer Buffer Security Auditor for sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <sentinel/sentinel.hpp>
#include <sentinel/sanitizers/cuda_sanitizer.hpp>

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <span>

namespace sentinel::adapters {

/**
 * @brief Allocation parameters for a llama.cpp evaluation context.
 */
struct SENTINEL_API LlamaContextParams {
    uint32_t n_ctx{2048};               // Context window size (tokens)
    uint32_t n_batch{512};              // Batch size for prompt evaluation
    uint32_t n_gpu_layers{0};          // Layers offloaded to CUDA VRAM
    size_t vocab_size{32000};           // Vocabulary size
    size_t embedding_dim{4096};         // Hidden dimension size
};

/**
 * @brief Memory Safety and Tokenizer Auditor for llama.cpp Native Backends.
 */
class SENTINEL_API LlamaCppAdapter {
public:
    LlamaCppAdapter() = default;
    ~LlamaCppAdapter();

    // Non-copyable, movable
    LlamaCppAdapter(const LlamaCppAdapter&) = delete;
    LlamaCppAdapter& operator=(const LlamaCppAdapter&) = delete;
    LlamaCppAdapter(LlamaCppAdapter&&) noexcept = default;
    LlamaCppAdapter& operator=(LlamaCppAdapter&&) noexcept = default;

    /**
     * @brief Audits and initializes a llama.cpp context buffer allocation.
     * @param params Target llama.cpp configuration parameters.
     * @return Status::Success if memory allocations pass security boundary checks.
     */
    Status init_context(const LlamaContextParams& params);

    /**
     * @brief Audits incoming prompt token arrays against context window limits.
     * @param tokens Input token array span.
     * @return Status::Success if token count is within context boundaries.
     */
    Status audit_tokens(std::span<const int32_t> tokens) const;

    /**
     * @brief Audits string buffers before passing to the llama.cpp tokenizer parser.
     * @param text Raw prompt string_view.
     * @return Status::Success if string length and byte null-terminators pass bounds checks.
     */
    Status audit_prompt_string(std::string_view text) const;

    /**
     * @brief Releases allocated context buffers.
     */
    void release() noexcept;

    [[nodiscard]] bool is_initialized() const noexcept { return m_initialized; }
    [[nodiscard]] size_t total_allocated_bytes() const noexcept { return m_allocated_bytes; }

private:
    LlamaContextParams m_params{};
    void* m_gpu_context_ptr{nullptr};
    size_t m_allocated_bytes{0};
    bool m_initialized{false};
};

} // namespace sentinel::adapters