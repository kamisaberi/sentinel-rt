/**
 * @file libtorch_adapter.hpp
 * @brief LibTorch (PyTorch C++ API) CUDA Allocator Security Hook Adapter for sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <sentinel/sentinel.hpp>
#include <sentinel/sanitizers/cuda_sanitizer.hpp>

#include <cstdint>
#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

namespace sentinel::adapters {

/**
 * @brief Descriptor for a C++ tensor memory allocation originating from LibTorch.
 */
struct SENTINEL_API LibTorchTensorInfo {
    uintptr_t tensor_id{0};
    int32_t scalar_type{0};             // PyTorch ScalarType enum
    std::vector<int64_t> sizes;         // Tensor shape dimensions
    void* device_ptr{nullptr};
    size_t allocated_bytes{0};
};

/**
 * @brief Custom C++ Caching Allocator Hook for LibTorch CUDA Tensors.
 */
class SENTINEL_API LibTorchAdapter {
public:
    LibTorchAdapter() = default;
    ~LibTorchAdapter();

    /**
     * @brief Hook replacing PyTorch's raw CUDA allocation with CUDASanitizer redzone checking.
     * @param tensor_id Unique hash/identifier of the LibTorch tensor object.
     * @param shape Vector of tensor dimensions.
     * @param element_size Size of single scalar type in bytes.
     * @param out_ptr Pointer to receive the allocated device pointer.
     * @return Status::Success if memory is safely allocated with poison boundaries.
     */
    Status allocate_tensor(uintptr_t tensor_id, const std::vector<int64_t>& shape, size_t element_size, void** out_ptr);

    /**
     * @brief Audits memory bounds during raw pointer tensor slicing or zero-copy strided views.
     * @param tensor_id Target tensor identifier.
     * @param offset_bytes Byte offset into tensor memory.
     * @param access_bytes Size of read/write operation.
     * @return True if access falls strictly within the safe allocation boundaries.
     */
    [[nodiscard]] bool validate_view_access(uintptr_t tensor_id, size_t offset_bytes, size_t access_bytes) const;

    /**
     * @brief Frees a registered LibTorch tensor allocation.
     * @param tensor_id Target tensor identifier.
     * @return Status::Success if freed and redzones are validated.
     */
    Status free_tensor(uintptr_t tensor_id);

    /**
     * @brief Resets all tracked LibTorch allocations.
     */
    void reset() noexcept;

private:
    std::unordered_map<uintptr_t, LibTorchTensorInfo> m_tensors;
};

} // namespace sentinel::adapters