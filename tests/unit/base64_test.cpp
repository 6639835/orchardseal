#include "base64.h"

#include <array>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>

namespace {

bool ExpectEqual(std::string_view actual, std::string_view expected, std::string_view label)
{
    if (actual == expected) {
        return true;
    }

    std::cerr << label << " failed: expected '" << expected << "', got '" << actual << "'\n";
    return false;
}

} // namespace

int main()
{
    Base64Codec codec;
    const std::array<std::pair<std::string_view, std::string_view>, 7> vectors {{
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"},
    }};

    for (const auto& [plain, encoded] : vectors) {
        if (!ExpectEqual(codec.Encode(std::string(plain)), encoded, "encode vector")) {
            return 1;
        }

        int decodedLength = -1;
        const char* decoded = codec.Decode(encoded.data(), static_cast<int>(encoded.size()), &decodedLength);
        if (decodedLength != static_cast<int>(plain.size()) ||
            !ExpectEqual(std::string_view(decoded, static_cast<std::size_t>(decodedLength)),
                         plain,
                         "decode vector")) {
            return 1;
        }
    }

    const std::string binary {"\0\x01\x7f\xff", 4};
    const char* firstResult = codec.Encode(binary);
    const std::string firstCopy = firstResult;
    (void)codec.Encode("another value");
    if (!ExpectEqual(firstResult, firstCopy, "stable result storage")) {
        return 1;
    }

    int binaryLength = 0;
    const char* decodedBinary = codec.Decode(firstCopy.c_str(), 0, &binaryLength);
    if (binaryLength != static_cast<int>(binary.size()) ||
        std::memcmp(decodedBinary, binary.data(), binary.size()) != 0) {
        std::cerr << "binary round-trip failed\n";
        return 1;
    }

    std::string whitespaceDecoded;
    codec.Decode(" Zm9v\nYmFy\t", whitespaceDecoded);
    if (!ExpectEqual(whitespaceDecoded, "foobar", "whitespace-tolerant decode")) {
        return 1;
    }

    int invalidLength = 7;
    if (!ExpectEqual(codec.Decode(nullptr, 0, &invalidLength), "", "null decode") || invalidLength != 0) {
        return 1;
    }
    if (!ExpectEqual(codec.Encode("ignored", -1), "", "negative encode length")) {
        return 1;
    }

    return 0;
}
