/**
 * @file onnx_parser.hpp
 * @brief Memory-Safe ONNX Model Graph Inspector and Parser for sentinel-rt
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
 * @brief Represents a single operator node in an ONNX model graph.
 */
struct SENTINEL_API ONNXNodeInfo {
    std::string op_type;               // Operator type (e.g., "Conv", "MatMul", "Relu")
    std::string name;                  // Node identifier name
    std::vector<std::string> inputs;   // Input tensor names
    std::vector<std::string> outputs;  // Output tensor names
    size_t attribute_count{0};
};

/**
 * @brief Represents tensor shape and type information inside an ONNX graph.
 */
struct SENTINEL_API ONNXTensorInfo {
    std::string name;
    int32_t elem_type{0};              // ONNX TensorProto DataType enum value
    std::vector<int64_t> dims;         // Tensor dimensions
    uint64_t calculated_bytes{0};      // Calculated size in bytes
};

/**
 * @brief Summary metadata extracted from an ONNX Protobuf payload.
 */
struct SENTINEL_API ONNXModelHeader {
    int64_t ir_version{0};
    std::string producer_name;
    std::string producer_version;
    std::string domain;
    int64_t model_version{0};
    uint64_t node_count{0};
    uint64_t initializer_count{0};
};

/**
 * @brief Safe Zero-Dependency C++20 ONNX Protobuf Structure Auditor.
 */
class SENTINEL_API ONNXParser {
public:
    ONNXParser() = default;
    ~ONNXParser() = default;

    // Non-copyable, movable
    ONNXParser(const ONNXParser&) = delete;
    ONNXParser& operator=(const ONNXParser&) = delete;
    ONNXParser(ONNXParser&&) noexcept = default;
    ONNXParser& operator=(ONNXParser&&) noexcept = default;

    /**
     * @brief Parses and audits an ONNX model protobuf payload from a byte span.
     * @param buffer Raw ONNX binary buffer span.
     * @return Status::Success if parsing and boundary validation pass.
     * @throws SentinelException if security or memory boundaries are breached.
     */
    Status parse(std::span<const uint8_t> buffer);

    /**
     * @brief Validates model node counts and tensor dimension calculations.
     * @return Status::Success if all tensor dimensions are non-overflowing.
     */
    Status validate_graph_metadata();

    /**
     * @brief Resets internal parser state.
     */
    void reset() noexcept;

    // -------------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------------
    [[nodiscard]] const ONNXModelHeader& header() const noexcept { return m_header; }
    [[nodiscard]] const std::vector<ONNXNodeInfo>& nodes() const noexcept { return m_nodes; }
    [[nodiscard]] const std::vector<ONNXTensorInfo>& initializers() const noexcept { return m_initializers; }
    [[nodiscard]] size_t bytes_parsed() const noexcept { return m_cursor; }

private:
    [[nodiscard]] std::optional<uint64_t> read_varint(std::span<const uint8_t> buffer);
    [[nodiscard]] std::optional<std::string> read_length_delimited_string(std::span<const uint8_t> buffer);

    ONNXModelHeader m_header{};
    std::vector<ONNXNodeInfo> m_nodes{};
    std::vector<ONNXTensorInfo> m_initializers{};
    size_t m_cursor{0};
};

} // namespace sentinel::parsers