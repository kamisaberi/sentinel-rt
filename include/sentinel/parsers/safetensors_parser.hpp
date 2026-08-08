/**
 * @file safetensors_parser.hpp
 * @brief Memory-Safe Safetensors Format Parser and Header Auditor for sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#pragma once

#include <sentinel/sentinel.hpp>

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <unordered_map>
#include <optional>
#include <span>

namespace sentinel::parsers {

/**
 * @brief Structure representing a tensor entry inside a Safetensors JSON header.
 */
struct SENTINEL_API SafetensorsTensorInfo {
    std::string name;
    std::string dtype;                  // Data type string (e.g., "F32", "F16", "I64", "BF16")
    std::vector<uint64_t> shape;        // Tensor dimension lengths
    uint64_t data_offsets[2]{0, 0};     // [start_byte, end_byte] relative to binary buffer start
    uint64_t calculated_bytes{0};       // Mathematical size calculation for validation
};

/**
 * @brief Structure holding parsed metadata and execution attributes for Safetensors.
 */
struct SENTINEL_API SafetensorsHeader {
    uint64_t header_size_bytes{0};
    uint64_t total_tensor_count{0};
    std::unordered_map<std::string, std::string> metadata_kv;
};

/**
 * @brief Safe C++20 Safetensors Format Parser and Zero-Copy Boundary Auditor.
 */
class SENTINEL_API SafetensorsParser {
public:
    SafetensorsParser() = default;
    ~SafetensorsParser() = default;

    // Non-copyable, movable
    SafetensorsParser(const SafetensorsParser&) = delete;
    SafetensorsParser& operator=(const SafetensorsParser&) = delete;
    SafetensorsParser(SafetensorsParser&&) noexcept = default;
    SafetensorsParser& operator=(SafetensorsParser&&) noexcept = default;

    /**
     * @brief Parses and audits Safetensors binary data from a non-owning byte span.
     * @param buffer Raw span containing the 8-byte length prefix + JSON header + tensor binary payloads.
     * @return Status::Success if parsing and boundary checks pass; error status otherwise.
     * @throws SentinelException if security/memory constraints are violated.
     */
    Status parse(std::span<const uint8_t> buffer);

    /**
     * @brief Validates tensor offsets against the physical file bounds and checks for integer overflows.
     * @param total_buffer_size Total length of the input byte payload.
     * @return Status::Success if all tensor offsets are valid and non-overlapping.
     */
    Status validate_boundaries(size_t total_buffer_size);

    /**
     * @brief Resets internal parser state.
     */
    void reset() noexcept;

    // -------------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------------
    [[nodiscard]] const SafetensorsHeader& header() const noexcept { return m_header; }
    [[nodiscard]] const std::vector<SafetensorsTensorInfo>& tensors() const noexcept { return m_tensors; }
    [[nodiscard]] size_t bytes_parsed() const noexcept { return m_cursor; }

private:
    [[nodiscard]] Status parse_json_header(std::string_view json_str);

    SafetensorsHeader m_header{};
    std::vector<SafetensorsTensorInfo> m_tensors{};
    size_t m_cursor{0};
};

} // namespace sentinel::parsers