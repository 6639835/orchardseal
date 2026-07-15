#pragma once

#include <string>

class WindowsTextConverter final {
  public:
    WindowsTextConverter() = default;
    ~WindowsTextConverter() = default;

    WindowsTextConverter(const WindowsTextConverter&) = delete;
    WindowsTextConverter& operator=(const WindowsTextConverter&) = delete;

    [[nodiscard]] bool WideToUtf8(const wchar_t* value, std::string& output) const;
};
