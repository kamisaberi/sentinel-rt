/**
 * @file cuda_sanitizer.cu
 * @brief Dynamic GPU VRAM Memory Auditor and Boundary Sanitizer Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/sanitizers/cuda_sanitizer.hpp>

#include <cuda_runtime.h>
#include <iostream>
#include <algorithm>
#include <format>

namespace sentinel::sanitizers {

CUDASanitizer::~CUDASanitizer() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_tracked_regions.empty()) {
        std::cerr << "[SENTINEL-WARNING] CUDASanitizer destroyed with " 
                  << m_tracked_regions.size() << " active un-freed VRAM allocations ("
                  << m_total_bytes << " bytes leaked).\n";
    }
}

CUDASanitizer& CUDASanitizer::instance() noexcept {
    static CUDASanitizer static_instance;
    return static_instance;
}

Status CUDASanitizer::audit_malloc(void** dev_ptr, size_t size, std::string_view label, size_t redzone_bytes) {
    if (dev_ptr == nullptr) {
        return Status::ErrCUDAAllocation;
    }

    if (size == 0) {
        *dev_ptr = nullptr;
        return Status::Success;
    }

    // Total memory allocated = front redzone + usable payload + back redzone
    size_t total_allocation_bytes = size + (redzone_bytes * 2);
    void* raw_device_ptr = nullptr;

    cudaError_t cuda_err = cudaMalloc(&raw_device_ptr, total_allocation_bytes);
    if (cuda_err != cudaSuccess) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_last_violation = CUDAViolationReport{
            .faulting_address = 0,
            .requested_access_bytes = size,
            .violation_type = Status::ErrCUDAAllocation,
            .message = std::format("cudaMalloc failed for label '{}': {}", label, cudaGetErrorString(cuda_err))
        };
        return Status::ErrCUDAAllocation;
    }

    // Zero out initial allocation including redzones
    cudaMemset(raw_device_ptr, 0, total_allocation_bytes);

    // Compute usable pointer offset past front redzone
    uintptr_t raw_address = reinterpret_cast<uintptr_t>(raw_device_ptr);
    uintptr_t usable_address = raw_address + redzone_bytes;
    *dev_ptr = reinterpret_cast<void*>(usable_address);

    // Register allocation in thread-safe tracking table
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        CUDAMemoryRegion region{
            .device_address = usable_address,
            .size_bytes = size,
            .redzone_bytes = redzone_bytes,
            .label = std::string(label),
            .is_poisoned = false
        };

        m_tracked_regions.insert_or_assign(usable_address, std::move(region));
        m_total_bytes += size;
    }

    return Status::Success;
}

Status CUDASanitizer::audit_free(void* dev_ptr) {
    if (dev_ptr == nullptr) {
        return Status::Success; // Freeing nullptr is a safe no-op
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(dev_ptr);
    void* raw_ptr_to_free = nullptr;

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_tracked_regions.find(target_address);
        if (it == m_tracked_regions.end()) {
            // Double-free or invalid pointer free detected!
            m_last_violation = CUDAViolationReport{
                .faulting_address = target_address,
                .requested_access_bytes = 0,
                .violation_type = Status::ErrCUDABoundaryViolation,
                .message = std::format("Double-free or unallocated VRAM free attempt at address 0x{:x}", target_address)
            };
            return Status::ErrCUDABoundaryViolation;
        }

        const auto& region = it->second;
        uintptr_t raw_address = region.device_address - region.redzone_bytes;
        raw_ptr_to_free = reinterpret_cast<void*>(raw_address);

        m_total_bytes -= region.size_bytes;
        m_tracked_regions.erase(it);
    }

    // Perform actual CUDA memory deallocation on raw pointer
    cudaError_t cuda_err = cudaFree(raw_ptr_to_free);
    if (cuda_err != cudaSuccess) {
        return Status::ErrCUDAAllocation;
    }

    return Status::Success;
}

bool CUDASanitizer::check_bounds(const void* dev_ptr, size_t access_bytes) const {
    if (dev_ptr == nullptr || access_bytes == 0) {
        return false;
    }

    uintptr_t access_address = reinterpret_cast<uintptr_t>(dev_ptr);
    uintptr_t access_end = access_address + access_bytes;

    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& [base_addr, region] : m_tracked_regions) {
        uintptr_t valid_start = region.device_address;
        uintptr_t valid_end = valid_start + region.size_bytes;

        // Check if access starts within registered payload region
        if (access_address >= valid_start && access_address < valid_end) {
            // Check if access extends past bounds or hits poisoned memory
            if (access_end > valid_end || region.is_poisoned) {
                return false;
            }
            return true;
        }
    }

    // Access address falls outside all registered active VRAM regions
    return false;
}

Status CUDASanitizer::poison_region(void* dev_ptr, size_t size) {
    if (dev_ptr == nullptr || size == 0) {
        return Status::Success;
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(dev_ptr);
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_tracked_regions.find(target_address);
    if (it != m_tracked_regions.end()) {
        it->second.is_poisoned = true;
        return Status::Success;
    }

    return Status::ErrCUDABoundaryViolation;
}

Status CUDASanitizer::unpoison_region(void* dev_ptr, size_t size) {
    if (dev_ptr == nullptr || size == 0) {
        return Status::Success;
    }

    uintptr_t target_address = reinterpret_cast<uintptr_t>(dev_ptr);
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_tracked_regions.find(target_address);
    if (it != m_tracked_regions.end()) {
        it->second.is_poisoned = false;
        return Status::Success;
    }

    return Status::ErrCUDABoundaryViolation;
}

std::optional<CUDAViolationReport> CUDASanitizer::get_last_violation() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_last_violation;
}

void CUDASanitizer::reset() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& [addr, region] : m_tracked_regions) {
        void* raw_ptr = reinterpret_cast<void*>(region.device_address - region.redzone_bytes);
        cudaFree(raw_ptr);
    }

    m_tracked_regions.clear();
    m_last_violation.reset();
    m_total_bytes = 0;
}

size_t CUDASanitizer::active_allocations_count() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_tracked_regions.size();
}

size_t CUDASanitizer::total_allocated_bytes() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_total_bytes;
}

} // namespace sentinel::sanitizers