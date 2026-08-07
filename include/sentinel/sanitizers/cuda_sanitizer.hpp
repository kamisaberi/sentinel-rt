/**
 * @file cuda_sanitizer.hpp
 * @brief Dynamic GPU VRAM Memory Auditor and Boundary Sanitizer for sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <sentinel/sentinel.hpp>

#include <cuda_runtime.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <optional>
#include <span>

namespace sentinel::sanitizers {

/**
 * @brief Structure representing a registered GPU VRAM memory allocation.
 */
struct SENTINEL_API CUDAMemoryRegion {
    uintptr_t device_address{0};
    size_t size_bytes{0};
    size_t redzone_bytes{0};
    std::string label;
    bool is_poisoned{false};
};

/**
 * @brief Structure holding a report of a detected GPU memory violation.
 */
struct SENTINEL_API CUDAViolationReport {
    uintptr_t faulting_address{0};
    size_t requested_access_bytes{0};
    Status violation_type{Status::Success};
    std::string message;
};

/**
 * @brief Thread-safe dynamic GPU VRAM Memory Auditor and Sanitizer.
 */
class SENTINEL_API CUDASanitizer {
public:
    CUDASanitizer() = default;
    ~CUDASanitizer();

    // Non-copyable, non-movable (Singleton/Auditor instance pattern)
    CUDASanitizer(const CUDASanitizer&) = delete;
    CUDASanitizer& operator=(const CUDASanitizer&) = delete;
    CUDASanitizer(CUDASanitizer&&) = delete;
    CUDASanitizer& operator=(CUDASanitizer&&) = delete;

    /**
     * @brief Returns the global singleton instance of the CUDA Sanitizer.
     */
    static CUDASanitizer& instance() noexcept;

    /**
     * @brief Wraps cudaMalloc with dynamic boundary tracking and redzone padding.
     * 
     * @param dev_ptr Pointer to receive the allocated device pointer.
     * @param size Size in bytes to allocate on the GPU.
     * @param label Optional human-readable label for tracking (e.g., "KV_Cache_Buffer").
     * @param redzone_bytes Size of boundary padding (poisoned memory guard bands).
     * @return Status::Success if allocation succeeded and was registered; error code otherwise.
     */
    Status audit_malloc(void** dev_ptr, size_t size, std::string_view label = "unlabeled_vram", size_t redzone_bytes = 256);

    /**
     * @brief Wraps cudaFree, verifying pointer validity and checking for double-free bugs.
     * 
     * @param dev_ptr Device pointer to free.
     * @return Status::Success if safely unregistered and freed; error code otherwise.
     */
    Status audit_free(void* dev_ptr);

    /**
     * @brief Validates whether a device memory access range falls strictly within an active allocation.
     * 
     * @param dev_ptr Target GPU memory address.
     * @param access_bytes Size of the access in bytes.
     * @return True if access is valid and unpoisoned; false if a boundary violation occurs.
     */
    [[nodiscard]] bool check_bounds(const void* dev_ptr, size_t access_bytes) const;

    /**
     * @brief Marks a region of GPU memory as unaddressable (poisoned redzone).
     * 
     * @param dev_ptr Starting device address.
     * @param size Size in bytes to poison.
     * @return Status::Success if region was poisoned.
     */
    Status poison_region(void* dev_ptr, size_t size);

    /**
     * @brief Unmarks a poisoned region of GPU memory, allowing valid access.
     * 
     * @param dev_ptr Starting device address.
     * @param size Size in bytes to unpoison.
     * @return Status::Success if region was unpoisoned.
     */
    Status unpoison_region(void* dev_ptr, size_t size);

    /**
     * @brief Returns details of the last detected VRAM memory violation, if any.
     */
    [[nodiscard]] std::optional<CUDAViolationReport> get_last_violation() const noexcept;

    /**
     * @brief Resets all tracked memory regions and clears violation logs.
     */
    void reset() noexcept;

    /**
     * @brief Returns the count of currently active tracked VRAM allocations.
     */
    [[nodiscard]] size_t active_allocations_count() const noexcept;

    /**
     * @brief Returns the total bytes of GPU memory currently tracked.
     */
    [[nodiscard]] size_t total_allocated_bytes() const noexcept;

private:
    mutable std::mutex m_mutex;
    std::unordered_map<uintptr_t, CUDAMemoryRegion> m_tracked_regions;
    std::optional<CUDAViolationReport> m_last_violation;
    size_t m_total_bytes{0};
};

} // namespace sentinel::sanitizers