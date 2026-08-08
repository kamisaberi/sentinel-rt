/**
 * @file safetensors_parser.cpp
 * @brief Memory-Safe Safetensors Format Parser Implementation for sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/parsers/safetensors_parser.hpp>

#include <cstring>
#include <limits>
#include <format>
#include <regex>

namespace sentinel::parsers {

void SafetensorsParser::reset() noexcept {
    m_header = SafetensorsHeader{};
    m_tensors.clear();
    m_cursor = 0;
}

Status SafetensorsParser::parse(std::span<const uint8_t> buffer) {
    reset();

    // 1. Read 8-byte Little-Endian unsigned integer header size prefix
    if (buffer.size() < sizeof(uint64_t)) {
        throw SentinelException(Status::ErrOutOfBoundsRead, "Buffer too small to read Safetensors header size.");
    }

    uint64_t header_len = 0;
    std::memcpy(&header_len, buffer.data(), sizeof(uint64_t));
    m_cursor = sizeof(uint64_t);

    // 2. Security cap on header length (maximum 100 MB JSON header limit)
    constexpr uint64_t MAX_HEADER_SIZE = 100 * 1024 * 1024;
    if (header_len == 0 || header_len > MAX_HEADER_SIZE) {
        return Status::ErrMalformedHeader;
    }

    if (m_cursor + header_len > buffer.size()) {
        return Status::ErrOutOfBoundsRead;
    }

    m_header.header_size_bytes = header_len;

    // 3. Extract JSON header string_view without dynamic heap allocation
    std::string_view json_view(
        reinterpret_cast<const char*>(buffer.data() + m_cursor),
        static_cast<size_t>(header_len)
    );
    m_cursor += static_cast<size_t>(header_len);

    // 4. Parse JSON metadata structure
    Status json_status = parse_json_header(json_view);
    if (json_status != Status::Success) {
        return json_status;
    }

    // 5. Validate physical tensor offsets against file boundaries
    return validate_boundaries(buffer.size());
}

Status SafetensorsParser::parse_json_header(std::string_view json_str) {
    // Robust light-weight regex pattern extraction for zero-dependency parsing
    // Matches keys and objects containing dtype, shape, and data_offsets
    std::string json_data(json_str);

    // Check basic JSON opening/closing syntax
    if (json_data.front() != '{' || json_data.back() != '}') {
        return Status::ErrMalformedHeader;
    }

    // Regex matcher for Tensor key blocks
    std::regex tensor_pattern(R"(\"([^\"]+)\"\s*:\s*\{[^\}]*\"dtype\"\s*:\s*\"([^\"]+)\"[^\}]*\"data_offsets\"\s*:\s*\[\s*(\d+)\s*,\s*(\d+)\s*\])");
    auto words_begin = std::sregex_iterator(json_data.begin(), json_data.end(), tensor_pattern);
    auto words_end = std::sregex_iterator();

    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
        std::smatch match = *i;
        SafetensorsTensorInfo info{};

        info.name = match[1].str();
        info.dtype = match[2].str();

        try {
            info.data_offsets[0] = std::stoull(match[3].str());
            info.data_offsets[1] = std::stoull(match[4].str());
        } catch (...) {
            return Status::ErrIntegerOverflow;
        }

        m_tensors.push_back(std::move(info));
    }

    m_header.total_tensor_count = m_tensors.size();
    return Status::Success;
}

Status SafetensorsParser::validate_boundaries(size_t total_buffer_size) {
    uint64_t binary_start_offset = sizeof(uint64_t) + m_header.header_size_bytes;

    for (auto& tensor : m_tensors) {
        uint64_t start = tensor.data_offsets[0];
        uint64_t end = tensor.data_offsets[1];

        // 1. Sanity check: Start offset must not be greater than end offset
        if (start > end) {
            return Status::ErrMalformedHeader;
        }

        // 2. Integer overflow check for relative-to-absolute translation
        if (binary_start_offset > std::numeric_limits<uint64_t>::max() - start) {
            return Status::ErrIntegerOverflow;
        }

        uint64_t absolute_start = binary_start_offset + start;
        uint64_t absolute_end = binary_start_offset + end;

        // 3. Physical buffer boundary violation check
        if (absolute_end > total_buffer_size || absolute_start > total_buffer_size) {
            return Status::ErrOutOfBoundsRead;
        }

        tensor.calculated_bytes = end - start;
    }

    return Status::Success;
}

} // namespace sentinel::parsers