/**
 * @file onnx_parser.cpp
 * @brief Memory-Safe ONNX Protobuf Structure Auditor Implementation
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/parsers/onnx_parser.hpp>

#include <cstring>
#include <limits>
#include <format>

namespace sentinel::parsers {

void ONNXParser::reset() noexcept {
    m_header = ONNXModelHeader{};
    m_nodes.clear();
    m_initializers.clear();
    m_cursor = 0;
}

Status ONNXParser::parse(std::span<const uint8_t> buffer) {
    reset();

    if (buffer.empty()) {
        return Status::ErrMalformedHeader;
    }

    // Zero-dependency protobuf wire-format parser loop
    while (m_cursor < buffer.size()) {
        auto tag_or_null = read_varint(buffer);
        if (!tag_or_null.has_value()) {
            break;
        }

        uint64_t tag = *tag_or_null;
        uint32_t field_number = static_cast<uint32_t>(tag >> 3);
        uint32_t wire_type = static_cast<uint32_t>(tag & 0x07);

        // Field 1: ir_version (int64)
        if (field_number == 1 && wire_type == 0) {
            auto val = read_varint(buffer);
            if (!val.has_value()) return Status::ErrOutOfBoundsRead;
            m_header.ir_version = static_cast<int64_t>(*val);
        }
        // Field 2: producer_name (string)
        else if (field_number == 2 && wire_type == 2) {
            auto str = read_length_delimited_string(buffer);
            if (!str.has_value()) return Status::ErrOutOfBoundsRead;
            m_header.producer_name = std::move(*str);
        }
        // Field 3: producer_version (string)
        else if (field_number == 3 && wire_type == 2) {
            auto str = read_length_delimited_string(buffer);
            if (!str.has_value()) return Status::ErrOutOfBoundsRead;
            m_header.producer_version = std::move(*str);
        }
        // Field 7: Model Graph payload
        else if (field_number == 7 && wire_type == 2) {
            auto len = read_varint(buffer);
            if (!len.has_value() || m_cursor + *len > buffer.size()) {
                return Status::ErrOutOfBoundsRead;
            }

            // Extract lightweight graph info heuristics
            m_header.node_count += 1;
            m_cursor += static_cast<size_t>(*len);
        }
        // Skip unknown fields cleanly based on wire type
        else {
            if (wire_type == 0) { // Varint
                if (!read_varint(buffer).has_value()) return Status::ErrOutOfBoundsRead;
            } else if (wire_type == 1) { // 64-bit
                if (m_cursor + 8 > buffer.size()) return Status::ErrOutOfBoundsRead;
                m_cursor += 8;
            } else if (wire_type == 2) { // Length-delimited
                auto len = read_varint(buffer);
                if (!len.has_value() || m_cursor + *len > buffer.size()) {
                    return Status::ErrOutOfBoundsRead;
                }
                m_cursor += static_cast<size_t>(*len);
            } else if (wire_type == 5) { // 32-bit
                if (m_cursor + 4 > buffer.size()) return Status::ErrOutOfBoundsRead;
                m_cursor += 4;
            } else {
                return Status::ErrMalformedHeader;
            }
        }
    }

    return validate_graph_metadata();
}

Status ONNXParser::validate_graph_metadata() {
    // Sanity check to prevent resource exhaustion attacks
    if (m_header.node_count > 500000) {
        return Status::ErrMalformedHeader;
    }

    for (auto& tensor : m_initializers) {
        uint64_t total_elements = 1;

        for (int64_t dim : tensor.dims) {
            if (dim <= 0) continue;
            uint64_t udim = static_cast<uint64_t>(dim);

            if (total_elements > std::numeric_limits<uint64_t>::max() / udim) {
                return Status::ErrIntegerOverflow;
            }
            total_elements *= udim;
        }

        tensor.calculated_bytes = total_elements * 4; // FP32 worst case assumption
    }

    return Status::Success;
}

std::optional<uint64_t> ONNXParser::read_varint(std::span<const uint8_t> buffer) {
    uint64_t result = 0;
    int shift = 0;

    while (m_cursor < buffer.size()) {
        uint8_t byte = buffer[m_cursor++];
        result |= static_cast<uint64_t>(byte & 0x7F) << shift;

        if ((byte & 0x80) == 0) {
            return result;
        }

        shift += 7;
        if (shift >= 64) {
            return std::nullopt; // Varint overflow protection
        }
    }

    return std::nullopt;
}

std::optional<std::string> ONNXParser::read_length_delimited_string(std::span<const uint8_t> buffer) {
    auto len = read_varint(buffer);
    if (!len.has_value() || *len > 10 * 1024 * 1024) { // 10 MB string limit
        return std::nullopt;
    }

    if (m_cursor + *len > buffer.size()) {
        return std::nullopt;
    }

    std::string str(reinterpret_cast<const char*>(buffer.data() + m_cursor), static_cast<size_t>(*len));
    m_cursor += static_cast<size_t>(*len);
    return str;
}

} // namespace sentinel::parsers