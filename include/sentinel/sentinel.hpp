/**
 * @file sentinel.hpp
 * @brief Master Header and Core Interface Definitions for sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <exception>
#include <span>
#include <format>

// -----------------------------------------------------------------------------
// Versioning & Metadata
// -----------------------------------------------------------------------------
#define SENTINEL_VERSION_MAJOR 0
#define SENTINEL_VERSION_MINOR 1
#define SENTINEL_VERSION_PATCH 0
#define SENTINEL_VERSION_STRING "0.1.0"

// -----------------------------------------------------------------------------
// Symbol Visibility Macros (Shared Library Exports)
// -----------------------------------------------------------------------------
#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(SENTINEL_BUILD_INTERNAL)
        #define SENTINEL_API __declspec(dllexport)
    #else
        #define SENTINEL_API __declspec(dllimport)
    #endif
#else
    #if __GNUC__ >= 4 || defined(__clang__)
        #define SENTINEL_API __attribute__((visibility("default")))
    #else
        #define SENTINEL_API
    #endif
#endif

namespace sentinel {

/**
 * @brief System-wide status codes for sentinel-rt operations.
 */
enum class Status : uint32_t {
    Success                   = 0,
    ErrInvalidMagic           = 1,
    ErrUnsupportedVersion     = 2,
    ErrMalformedHeader        = 3,
    ErrOutOfBoundsRead        = 4,
    ErrIntegerOverflow        = 5,
    ErrCUDAAllocation         = 6,
    ErrCUDABoundaryViolation  = 7,
    ErrSanitizerViolation     = 8,
    ErrUnknown                = 999
};

/**
 * @brief Converts a Status code into a human-readable string_view.
 */
[[nodiscard]] constexpr std::string_view status_to_string(Status status) noexcept {
    switch (status) {
        case Status::Success:                   return "Success";
        case Status::ErrInvalidMagic:           return "Error: Invalid Magic Bytes";
        case Status::ErrUnsupportedVersion:     return "Error: Unsupported Format Version";
        case Status::ErrMalformedHeader:        return "Error: Malformed Header Metadata";
        case Status::ErrOutOfBoundsRead:        return "Error: Out-of-Bounds Memory Read";
        case Status::ErrIntegerOverflow:        return "Error: Integer Overflow Detected";
        case Status::ErrCUDAAllocation:         return "Error: CUDA Memory Allocation Failed";
        case Status::ErrCUDABoundaryViolation:  return "Error: CUDA Dynamic Boundary Violation";
        case Status::ErrSanitizerViolation:     return "Error: Address/UBSan Sanitizer Violation";
        default:                                return "Error: Unknown Failure";
    }
}

/**
 * @brief Base exception class for all sentinel-rt runtime failures.
 */
class SENTINEL_API SentinelException : public std::exception {
public:
    explicit SentinelException(Status status, std::string_view message)
        : m_status(status), m_message(std::format("[SENTINEL-{}] {}", static_cast<uint32_t>(status), message)) {}

    [[nodiscard]] const char* what() const noexcept override {
        return m_message.c_str();
    }

    [[nodiscard]] Status status() const noexcept {
        return m_status;
    }

private:
    Status m_status;
    std::string m_message;
};

/**
 * @brief Struct representing version details.
 */
struct Version {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;

    [[nodiscard]] std::string to_string() const {
        return std::format("{}.{}.{}", major, minor, patch);
    }
};

/**
 * @brief Returns the runtime version of the sentinel-rt core library.
 */
[[nodiscard]] inline Version get_version() noexcept {
    return Version{SENTINEL_VERSION_MAJOR, SENTINEL_VERSION_MINOR, SENTINEL_VERSION_PATCH};
}

// -----------------------------------------------------------------------------
// Sub-namespace Forward Declarations
// -----------------------------------------------------------------------------
namespace parsers {}
namespace sanitizers {}
namespace fuzzer {}
namespace triage {}
namespace adapters {}

} // namespace sentinel