#include "windows_text_converter.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <utility>

const char* WindowsTextConverter::AnsiToUtf8(const char* value)
{
    return WideToMultiByte(MultiByteToWide(value, CP_ACP), CP_UTF8);
}

const char* WindowsTextConverter::AnsiToUtf8(const std::string& value)
{
    return AnsiToUtf8(value.c_str());
}

const char* WindowsTextConverter::Utf8ToAnsi(const char* value)
{
    return WideToMultiByte(MultiByteToWide(value, CP_UTF8), CP_ACP);
}

const char* WindowsTextConverter::Utf8ToAnsi(const std::string& value)
{
    return Utf8ToAnsi(value.c_str());
}

const wchar_t* WindowsTextConverter::MultiByteToWide(const char* value, unsigned int codePage)
{
    if (value == nullptr) {
        return L"";
    }

    const int required = ::MultiByteToWideChar(codePage, 0, value, -1, nullptr, 0);
    if (required <= 0) {
        return L"";
    }

    std::wstring converted(static_cast<std::size_t>(required), L'\0');
    const int written = ::MultiByteToWideChar(codePage, 0, value, -1, converted.data(), required);
    if (written <= 0) {
        return L"";
    }

    converted.resize(static_cast<std::size_t>(written - 1));
    wideBuffers_.push_back(std::move(converted));
    return wideBuffers_.back().c_str();
}

const char* WindowsTextConverter::WideToMultiByte(const wchar_t* value, unsigned int codePage)
{
    if (value == nullptr) {
        return "";
    }

    const int required = ::WideCharToMultiByte(codePage, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return "";
    }

    std::string converted(static_cast<std::size_t>(required), '\0');
    const int written = ::WideCharToMultiByte(codePage,
                                               0,
                                               value,
                                               -1,
                                               converted.data(),
                                               required,
                                               nullptr,
                                               nullptr);
    if (written <= 0) {
        return "";
    }

    converted.resize(static_cast<std::size_t>(written - 1));
    narrowBuffers_.push_back(std::move(converted));
    return narrowBuffers_.back().c_str();
}
