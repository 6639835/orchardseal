#pragma once

#include <list>
#include <string>

class WindowsTextConverter final {
public:
    WindowsTextConverter() = default;
    ~WindowsTextConverter() = default;

    WindowsTextConverter(const WindowsTextConverter&) = delete;
    WindowsTextConverter& operator=(const WindowsTextConverter&) = delete;

    [[nodiscard]] const char* AnsiToUtf8(const char* value);
    [[nodiscard]] const char* AnsiToUtf8(const std::string& value);
    [[nodiscard]] const char* Utf8ToAnsi(const char* value);
    [[nodiscard]] const char* Utf8ToAnsi(const std::string& value);

private:
    [[nodiscard]] const wchar_t* MultiByteToWide(const char* value, unsigned int codePage);
    [[nodiscard]] const char* WideToMultiByte(const wchar_t* value, unsigned int codePage);

    std::list<std::string> narrowBuffers_;
    std::list<std::wstring> wideBuffers_;
};
