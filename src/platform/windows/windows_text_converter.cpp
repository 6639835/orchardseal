#include "windows_text_converter.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <utility>

bool WindowsTextConverter::WideToUtf8(const wchar_t* value, std::string& output) const {
    output.clear();
    if (value == nullptr) {
        return false;
    }
    const int required = ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return false;
    }
    std::string converted(static_cast<std::size_t>(required), '\0');
    const int written =
        ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, converted.data(), required, nullptr, nullptr);
    if (written != required) {
        return false;
    }
    converted.resize(static_cast<std::size_t>(written - 1));
    output = std::move(converted);
    return true;
}
