/**
 * @file libtorch_adapter.cpp
 * @brief LibTorch CUDA Allocator Security Hook Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/adapters/libtorch_adapter.hpp>

#include <limits>
#include <format>

namespace sentinel::adapters {

LibTorchAdapter::~LibTorchAdapter() {
    reset();
}

Status LibTorchAdapter::allocate_tensor(uintptr_t tensor_id, const std::vector<int64_t>& shape, size_t element_size, void** out_ptr) {
    if (out_ptr == nullptr || element_size == 0) {
        return Status::ErrCUDAAllocation;
    }

    if (m_tensors.contains(tensor_id)) {
        return Status::ErrCUDAAllocation; // Tensor ID already registered
    }

    // Calculate total tensor element count with integer overflow guards
    uint64_t total_elements = 1;
    for (int64_t dim : shape) {
        if (dim <= 0) continue;
        uint64_t udim = static_cast<uint64_t>(dim);

        if (total_elements > std::numeric_limits<uint64_t>::max() / udim) {
            return Status::ErrIntegerOverflow;
        }
        total_elements *= udim;
    }

    if (total_elements > std::numeric_limits<uint64_t>::max() / element_size) {
        return Status::ErrIntegerOverflow;
    }

    size_t total_bytes = static_cast<size_t>(total_elements * element_size);
    void* dev_ptr = nullptr;
    std::string label = std::format("LibTorch_Tensor_0x{:x}", tensor_id);

    // Delegate allocation to CUDASanitizer to inject redzone guard bands
    Status status = sanitizers::CUDASanitizer::instance().audit_malloc(&dev_ptr, total_bytes, label);
    if (status != Status::Success) {
        return status;
    }

    *out_ptr = dev_ptr;

    LibTorchTensorInfo info{
        .tensor_id = tensor_id,
        .scalar_type = 0,
        .sizes = shape,
        .device_ptr = dev_ptr,
        .allocated_bytes = total_bytes
    };

    m_tensors.insert_or_assign(tensor_id, std::move(info));
    return Status::Success;
}

bool LibTorchAdapter::validate_view_access(uintptr_t tensor_id, size_t offset_bytes, size_t access_bytes) const {
    auto it = m_tensors.find(tensor_id);
    if (it == m_tensors.end()) {
        return false;
    }

    const auto& info = it->second;
    if (offset_bytes + access_bytes > info.allocated_bytes) {
        return false; // Out-of-bounds view slice
    }

    uintptr_t view_addr = reinterpret_cast<uintptr_t>(info.device_ptr) + offset_bytes;
    return sanitizers::CUDASanitizer::instance().check_bounds(reinterpret_cast<const void*>(view_addr), access_bytes);
}

Status LibTorchAdapter::free_tensor(uintptr_t tensor_id) {
    auto it = m_tensors.find(tensor_id);
    if (it == m_tensors.end()) {
        return Status::ErrCUDABoundaryViolation;
    }

    Status status = sanitizers::CUDASanitizer::instance().audit_free(it->second.device_ptr);
    m_tensors.erase(it);
    return status;
}

void LibTorchAdapter::reset() noexcept {
    for (const auto& [id, info] : m_tensors) {
        sanitizers::CUDASanitizer::instance().audit_free(info.device_ptr);
    }
    m_tensors.clear();
}

} // namespace sentinel::adapters