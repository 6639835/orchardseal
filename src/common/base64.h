#pragma once

#include <list>
#include <string>

class Base64Codec final {
public:
    Base64Codec() = default;
    ~Base64Codec() = default;

    Base64Codec(const Base64Codec&) = delete;
    Base64Codec& operator=(const Base64Codec&) = delete;

    [[nodiscard]] const char* Encode(const char* source, int sourceLength = 0);
    [[nodiscard]] const char* Encode(const std::string& input);
    [[nodiscard]] const char* Decode(const char* source,
                                     int sourceLength = 0,
                                     int* decodedLength = nullptr);
    void Decode(const char* source, std::string& output);

private:
    [[nodiscard]] static int DecodeIndex(char value) noexcept;
    [[nodiscard]] static char EncodeValue(unsigned int value) noexcept;
    [[nodiscard]] static std::string EncodeToString(const char* source, std::size_t sourceLength);
    [[nodiscard]] static std::string DecodeToString(const char* source, std::size_t sourceLength);
    [[nodiscard]] const char* Store(std::string value);

    // std::list keeps c_str() addresses stable for the lifetime of the codec.
    std::list<std::string> buffers_;
};
