#include "base64.h"

#include <array>
#include <cstring>
#include <limits>
#include <utility>

namespace {

    constexpr char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

} // namespace

char Base64Codec::EncodeValue(unsigned int value) noexcept {
    return value < 64U ? kBase64Alphabet[value] : '=';
}

int Base64Codec::DecodeIndex(char value) noexcept {
    if (value >= 'A' && value <= 'Z') {
        return value - 'A';
    }
    if (value >= 'a' && value <= 'z') {
        return value - 'a' + 26;
    }
    if (value >= '0' && value <= '9') {
        return value - '0' + 52;
    }
    if (value == '+') {
        return 62;
    }
    if (value == '/') {
        return 63;
    }
    return -1;
}

std::string Base64Codec::EncodeToString(const char* source, std::size_t sourceLength) {
    if (source == nullptr || sourceLength == 0) {
        return {};
    }

    std::string output;
    output.reserve(((sourceLength + 2U) / 3U) * 4U);
    const auto* bytes = reinterpret_cast<const unsigned char*>(source);
    for (std::size_t offset = 0; offset < sourceLength; offset += 3U) {
        const std::size_t remaining = sourceLength - offset;
        const unsigned int first = bytes[offset];
        const unsigned int second = remaining > 1U ? bytes[offset + 1U] : 0U;
        const unsigned int third = remaining > 2U ? bytes[offset + 2U] : 0U;

        output.push_back(EncodeValue(first >> 2U));
        output.push_back(EncodeValue(((first & 0x03U) << 4U) | (second >> 4U)));
        output.push_back(remaining > 1U ? EncodeValue(((second & 0x0fU) << 2U) | (third >> 6U)) : '=');
        output.push_back(remaining > 2U ? EncodeValue(third & 0x3fU) : '=');
    }
    return output;
}

std::string Base64Codec::DecodeToString(const char* source, std::size_t sourceLength) {
    if (source == nullptr || sourceLength == 0) {
        return {};
    }

    std::string output;
    output.reserve(((sourceLength + 3U) / 4U) * 3U);
    std::array<int, 4> quartet{};
    std::size_t quartetSize = 0;

    for (std::size_t index = 0; index < sourceLength; ++index) {
        const char value = source[index];
        if (value == '=') {
            break;
        }

        const int decoded = DecodeIndex(value);
        if (decoded < 0) {
            continue;
        }

        quartet[quartetSize++] = decoded;
        if (quartetSize == quartet.size()) {
            output.push_back(static_cast<char>((quartet[0] << 2) | (quartet[1] >> 4)));
            output.push_back(static_cast<char>((quartet[1] << 4) | (quartet[2] >> 2)));
            output.push_back(static_cast<char>((quartet[2] << 6) | quartet[3]));
            quartetSize = 0;
        }
    }

    if (quartetSize >= 2U) {
        output.push_back(static_cast<char>((quartet[0] << 2) | (quartet[1] >> 4)));
        if (quartetSize >= 3U) {
            output.push_back(static_cast<char>((quartet[1] << 4) | (quartet[2] >> 2)));
        }
    }
    return output;
}

const char* Base64Codec::Store(std::string value) {
    buffers_.push_back(std::move(value));
    return buffers_.back().c_str();
}

const char* Base64Codec::Encode(const char* source, int sourceLength) {
    if (source == nullptr) {
        return Store({});
    }
    if (sourceLength < 0) {
        return Store({});
    }

    std::size_t length = static_cast<std::size_t>(sourceLength);
    if (sourceLength == 0) {
        length = std::strlen(source);
    }
    return Store(EncodeToString(source, length));
}

const char* Base64Codec::Encode(const std::string& input) {
    return Store(EncodeToString(input.data(), input.size()));
}

const char* Base64Codec::Decode(const char* source, int sourceLength, int* decodedLength) {
    if (decodedLength != nullptr) {
        *decodedLength = 0;
    }
    if (source == nullptr || sourceLength < 0) {
        return Store({});
    }

    std::size_t length = static_cast<std::size_t>(sourceLength);
    if (sourceLength == 0) {
        length = std::strlen(source);
    }

    std::string decoded = DecodeToString(source, length);
    if (decoded.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return Store({});
    }
    if (decodedLength != nullptr) {
        *decodedLength = static_cast<int>(decoded.size());
    }
    return Store(std::move(decoded));
}

void Base64Codec::Decode(const char* source, std::string& output) {
    output.clear();
    if (source != nullptr) {
        output = DecodeToString(source, std::strlen(source));
    }
}
