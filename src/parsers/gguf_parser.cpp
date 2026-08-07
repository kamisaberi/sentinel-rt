/**
 * @file gguf_parser.cpp
 * @brief Memory-Safe GGUF Format Parser Implementation for sentinel-rt
 * @author Kamran Saberifard
 * @license Apache 2.0
 */

#include <sentinel/parsers/gguf_parser.hpp>

#include <cstring>
#include <limits>
#include <format>

namespace sentinel::parsers {

void GGUFParser::reset() noexcept {
    m_header = GGUFHeader{};
    m_metadata.clear();
    m_tensors.clear();
    m_cursor = 0;
}

Status GGUFParser::parse(std::span<const uint8_t> buffer) {
    reset();

    // 1. Read and validate GGUF Header
    auto magic = read_pod<uint32_t>(buffer);
    if (!magic.has_value()) {
        throw SentinelException(Status::ErrOutOfBoundsRead, "Buffer too small to read GGUF magic bytes.");
    }

    if (*magic != GGUF_MAGIC) {
        return Status::ErrInvalidMagic;
    }
    m_header.magic = *magic;

    auto version = read_pod<uint32_t>(buffer);
    if (!version.has_value()) {
        throw SentinelException(Status::ErrOutOfBoundsRead, "Buffer too small to read GGUF format version.");
    }

    if (*version < static_cast<uint32_t>(GGUFVersion::V1) || *version > static_cast<uint32_t>(GGUFVersion::V3)) {
        return Status::ErrUnsupportedVersion;
    }
    m_header.version = *version;

    auto tensor_count = read_pod<uint64_t>(buffer);
    if (!tensor_count.has_value()) {
        throw SentinelException(Status::ErrOutOfBoundsRead, "Buffer too small to read tensor count.");
    }
    m_header.tensor_count = *tensor_count;

    auto metadata_kv_count = read_pod<uint64_t>(buffer);
    if (!metadata_kv_count.has_value()) {
        throw SentinelException(Status::ErrOutOfBoundsRead, "Buffer too small to read metadata KV count.");
    }
    m_header.metadata_kv_count = *metadata_kv_count;

    // Sanity check to prevent resource exhaustion from fuzzed metadata counts
    if (m_header.metadata_kv_count > 65536 || m_header.tensor_count > 1000000) {
        throw SentinelException(Status::ErrMalformedHeader, "Metadata KV count or tensor count exceeds safe threshold.");
    }

    // 2. Parse Metadata Key-Value Pairs
    for (uint64_t i = 0; i < m_header.metadata_kv_count; ++i) {
        auto key = read_string(buffer);
        if (!key.has_value()) {
            throw SentinelException(Status::ErrMalformedHeader, std::format("Failed to read metadata key at index {}.", i));
        }

        auto val_type_raw = read_pod<uint32_t>(buffer);
        if (!val_type_raw.has_value() || *val_type_raw > 12) {
            throw SentinelException(Status::ErrMalformedHeader, std::format("Invalid metadata value type at index {}.", i));
        }

        auto value = read_value(buffer, static_cast<GGUFValueType>(*val_type_raw));
        if (!value.has_value()) {
            throw SentinelException(Status::ErrMalformedHeader, std::format("Failed to parse metadata value for key '{}'.", *key));
        }

        m_metadata.insert_or_assign(std::move(*key), std::move(*value));
    }

    // 3. Parse Tensor Descriptors
    m_tensors.reserve(m_header.tensor_count);
    for (uint64_t i = 0; i < m_header.tensor_count; ++i) {
        GGUFTensorInfo info{};

        auto name = read_string(buffer);
        if (!name.has_value()) {
            throw SentinelException(Status::ErrMalformedHeader, std::format("Failed to read tensor name at index {}.", i));
        }
        info.name = std::move(*name);

        auto n_dims = read_pod<uint32_t>(buffer);
        if (!n_dims.has_value() || *n_dims > 8) { // Maximum 8D tensor limit
            throw SentinelException(Status::ErrMalformedHeader, std::format("Invalid tensor dimensions ({}) at index {}.", n_dims.value_or(0), i));
        }
        info.n_dimensions = *n_dims;

        info.dimensions.reserve(info.n_dimensions);
        for (uint32_t d = 0; d < info.n_dimensions; ++d) {
            auto dim_size = read_pod<uint64_t>(buffer);
            if (!dim_size.has_value()) {
                throw SentinelException(Status::ErrOutOfBoundsRead, std::format("Failed to read dimension {} for tensor '{}'.", d, info.name));
            }
            info.dimensions.push_back(*dim_size);
        }

        auto type = read_pod<uint32_t>(buffer);
        if (!type.has_value()) {
            throw SentinelException(Status::ErrOutOfBoundsRead, std::format("Failed to read type for tensor '{}'.", info.name));
        }
        info.type = *type;

        auto offset = read_pod<uint64_t>(buffer);
        if (!offset.has_value()) {
            throw SentinelException(Status::ErrOutOfBoundsRead, std::format("Failed to read offset for tensor '{}'.", info.name));
        }
        info.offset = *offset;

        m_tensors.push_back(std::move(info));
    }

    // 4. Perform secondary mathematical boundary checks
    return validate_tensor_metadata();
}

Status GGUFParser::validate_tensor_metadata() {
    for (auto& tensor : m_tensors) {
        uint64_t total_elements = 1;

        for (uint64_t dim : tensor.dimensions) {
            // Guard against integer overflow during dimension multiplication
            if (dim > 0 && total_elements > std::numeric_limits<uint64_t>::max() / dim) {
                return Status::ErrIntegerOverflow;
            }
            total_elements *= dim;
        }

        // Assuming worst-case 4 bytes per element for validation check
        if (total_elements > std::numeric_limits<uint64_t>::max() / 4) {
            return Status::ErrIntegerOverflow;
        }
        tensor.calculated_bytes = total_elements * 4;
    }

    return Status::Success;
}

template <typename T>
std::optional<T> GGUFParser::read_pod(std::span<const uint8_t> buffer) {
    if (m_cursor + sizeof(T) > buffer.size()) {
        return std::nullopt;
    }

    T value;
    std::memcpy(&value, buffer.data() + m_cursor, sizeof(T));
    m_cursor += sizeof(T);
    return value;
}

std::optional<std::string> GGUFParser::read_string(std::span<const uint8_t> buffer) {
    auto len = read_pod<uint64_t>(buffer);
    if (!len.has_value() || *len > 65536) { // Safe string length cap (64 KB)
        return std::nullopt;
    }

    if (m_cursor + *len > buffer.size()) {
        return std::nullopt;
    }

    std::string str(reinterpret_cast<const char*>(buffer.data() + m_cursor), static_cast<size_t>(*len));
    m_cursor += static_cast<size_t>(*len);
    return str;
}

std::optional<GGUFValue> GGUFParser::read_value(std::span<const uint8_t> buffer, GGUFValueType type) {
    switch (type) {
        case GGUFValueType::UINT8:   if (auto v = read_pod<uint8_t>(buffer))  return *v; break;
        case GGUFValueType::INT8:    if (auto v = read_pod<int8_t>(buffer))   return *v; break;
        case GGUFValueType::UINT16:  if (auto v = read_pod<uint16_t>(buffer)) return *v; break;
        case GGUFValueType::INT16:   if (auto v = read_pod<int16_t>(buffer))  return *v; break;
        case GGUFValueType::UINT32:  if (auto v = read_pod<uint32_t>(buffer)) return *v; break;
        case GGUFValueType::INT32:   if (auto v = read_pod<int32_t>(buffer))  return *v; break;
        case GGUFValueType::FLOAT32: if (auto v = read_pod<float>(buffer))    return *v; break;
        case GGUFValueType::BOOL:    if (auto v = read_pod<uint8_t>(buffer))  return static_cast<bool>(*v); break;
        case GGUFValueType::STRING:  if (auto v = read_string(buffer))        return *v; break;
        case GGUFValueType::UINT64:  if (auto v = read_pod<uint64_t>(buffer)) return *v; break;
        case GGUFValueType::INT64:   if (auto v = read_pod<int64_t>(buffer))  return *v; break;
        case GGUFValueType::FLOAT64: if (auto v = read_pod<double>(buffer))   return *v; break;
        default: break;
    }
    return std::nullopt;
}

} // namespace sentinel::parsers