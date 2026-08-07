/**
 * @file gguf_parser.hpp
 * @brief Memory-Safe GGUF Format Parser and Header Auditor for sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <sentinel/sentinel.hpp>

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <variant>
#include <unordered_map>
#include <optional>
#include <span>

namespace sentinel::parsers {

/**
 * @brief Magic bytes identifier for GGUF binary format ("GGUF" in Little-Endian)
 */
constexpr uint32_t GGUF_MAGIC = 0x46554747;

/**
 * @brief Supported GGUF specification versions.
 */
enum class GGUFVersion : uint32_t {
    V1 = 1,
    V2 = 2,
    V3 = 3
};

/**
 * @brief Value types supported in GGUF key-value metadata arrays and fields.
 */
enum class GGUFValueType : uint32_t {
    UINT8   = 0,
    INT8    = 1,
    UINT16  = 2,
    INT16   = 3,
    UINT32  = 4,
    INT32   = 5,
    FLOAT32 = 6,
    BOOL    = 7,
    STRING  = 8,
    ARRAY   = 9,
    UINT64  = 10,
    INT64   = 11,
    FLOAT64 = 12
};

// Forward declaration for recursive array values
struct GGUFArray;

/**
 * @brief Variant type encapsulating any GGUF metadata value.
 */
using GGUFValue = std::variant<
    uint8_t,
    int8_t,
    uint16_t,
    int16_t,
    uint32_t,
    int32_t,
    float,
    bool,
    std::string,
    uint64_t,
    int64_t,
    double
>;

/**
 * @brief Structure representing a GGUF tensor descriptor.
 */
struct SENTINEL_API GGUFTensorInfo {
    std::string name;
    uint32_t n_dimensions{0};
    std::vector<uint64_t> dimensions;
    uint32_t type{0};           // GGML quantization type (e.g., Q4_0, Q8_0, FP16)
    uint64_t offset{0};         // Relative offset to tensor data block
    uint64_t calculated_bytes{0}; // Computed total memory size of tensor payload
};

/**
 * @brief Structure holding header metadata for a parsed GGUF payload.
 */
struct SENTINEL_API GGUFHeader {
    uint32_t magic{0};
    uint32_t version{0};
    uint64_t tensor_count{0};
    uint64_t metadata_kv_count{0};
};

/**
 * @brief Safe C++20 GGUF Parser and Memory Boundary Auditor.
 */
class SENTINEL_API GGUFParser {
public:
    GGUFParser() = default;
    ~GGUFParser() = default;

    // Non-copyable, movable
    GGUFParser(const GGUFParser&) = delete;
    GGUFParser& operator=(const GGUFParser&) = delete;
    GGUFParser(GGUFParser&&) noexcept = default;
    GGUFParser& operator=(GGUFParser&&) noexcept = default;

    /**
     * @brief Parses and audits GGUF binary data from a non-owning memory span.
     * @param buffer Raw buffer containing the GGUF file data.
     * @return Status::Success if parsing and boundary checks pass; error status otherwise.
     * @throws SentinelException if strict security constraints are violated.
     */
    Status parse(std::span<const uint8_t> buffer);

    /**
     * @brief Validates tensor dimensions and offsets against integer overflow and out-of-bounds memory.
     * @return Status::Success if all tensor specifications are safe.
     */
    Status validate_tensor_metadata();

    /**
     * @brief Resets internal parser state.
     */
    void reset() noexcept;

    // -------------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------------
    [[nodiscard]] const GGUFHeader& header() const noexcept { return m_header; }
    [[nodiscard]] const std::vector<GGUFTensorInfo>& tensors() const noexcept { return m_tensors; }
    [[nodiscard]] const std::unordered_map<std::string, GGUFValue>& metadata() const noexcept { return m_metadata; }
    [[nodiscard]] size_t bytes_parsed() const noexcept { return m_cursor; }

private:
    // Helper read operations with explicit bounds checking
    template <typename T>
    [[nodiscard]] std::optional<T> read_pod(std::span<const uint8_t> buffer);

    [[nodiscard]] std::optional<std::string> read_string(std::span<const uint8_t> buffer);
    [[nodiscard]] std::optional<GGUFValue> read_value(std::span<const uint8_t> buffer, GGUFValueType type);

    GGUFHeader m_header{};
    std::unordered_map<std::string, GGUFValue> m_metadata{};
    std::vector<GGUFTensorInfo> m_tensors{};
    size_t m_cursor{0};
};

} // namespace sentinel::parsers