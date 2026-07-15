#include "logger.h"

#include <limits>

int Logger::g_nLogLevel = Logger::E_INFO;

void Logger::_Print(const char* szLog, int nColor, bool toStandardError) {
    if (g_nLogLevel <= E_NONE || szLog == nullptr) {
        return;
    }
    _Write(szLog, nColor, toStandardError);
}

void Logger::_Write(const char* szLog, int nColor, bool toStandardError) {
    if (szLog == nullptr) {
        return;
    }

#ifdef _WIN32

    string strLog = szLog;
    HANDLE hConsole = ::GetStdHandle(toStandardError ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
    DWORD consoleMode = 0;
    const bool isConsole =
        hConsole != nullptr && hConsole != INVALID_HANDLE_VALUE && GetConsoleMode(hConsole, &consoleMode) != 0;
    SetLastError(ERROR_SUCCESS);
    const DWORD noColorLength = GetEnvironmentVariableW(L"NO_COLOR", nullptr, 0);
    const bool noColor = noColorLength != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND;
    const bool useColor = nColor > 0 && static_cast<unsigned int>(nColor) <= std::numeric_limits<WORD>::max() &&
                          !noColor && isConsole;
    WORD originalAttributes = 7;
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo{};
    if (isConsole && GetConsoleScreenBufferInfo(hConsole, &consoleInfo) != 0) {
        originalAttributes = consoleInfo.wAttributes;
    }
    if (useColor) {
        ::SetConsoleTextAttribute(hConsole, static_cast<WORD>(nColor));
    }

    if (isConsole) {
        const bool inputLengthValid = strLog.size() <= static_cast<size_t>(std::numeric_limits<int>::max());
        const int inputLength = inputLengthValid ? static_cast<int>(strLog.size()) : 0;
        const int wideLength = inputLength == 0 ? 0
                                                : MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, strLog.data(),
                                                                      inputLength, nullptr, 0);
        if (wideLength > 0) {
            std::wstring wideLog(static_cast<size_t>(wideLength), L'\0');
            if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, strLog.data(), inputLength, wideLog.data(),
                                    wideLength) == wideLength) {
                size_t offset = 0;
                while (offset < wideLog.size()) {
                    const DWORD remaining = static_cast<DWORD>(std::min<size_t>(
                        wideLog.size() - offset, static_cast<size_t>(std::numeric_limits<DWORD>::max())));
                    DWORD written = 0;
                    if (WriteConsoleW(hConsole, wideLog.data() + offset, remaining, &written, nullptr) == 0 ||
                        written == 0) {
                        break;
                    }
                    offset += written;
                }
            }
        } else if (!strLog.empty()) {
            static const wchar_t invalidUtf8[] = L"[invalid UTF-8 log message]\n";
            DWORD written = 0;
            WriteConsoleW(hConsole, invalidUtf8, static_cast<DWORD>((sizeof(invalidUtf8) / sizeof(wchar_t)) - 1U),
                          &written, nullptr);
        }
    } else if (hConsole != nullptr && hConsole != INVALID_HANDLE_VALUE) {
        size_t offset = 0;
        while (offset < strLog.size()) {
            const DWORD remaining = static_cast<DWORD>(
                std::min<size_t>(strLog.size() - offset, static_cast<size_t>(std::numeric_limits<DWORD>::max())));
            DWORD written = 0;
            if (WriteFile(hConsole, strLog.data() + offset, remaining, &written, nullptr) == 0 || written == 0) {
                break;
            }
            offset += written;
        }
    }
    if (useColor) {
        ::SetConsoleTextAttribute(hConsole, originalAttributes);
    }

#else

    const int outputDescriptor = toStandardError ? STDERR_FILENO : STDOUT_FILENO;
    const auto writeOutput = [outputDescriptor](const char* data, size_t size) {
        while (size > 0) {
            const ssize_t written = write(outputDescriptor, data, size);
            if (written <= 0) {
                return;
            }
            data += written;
            size -= static_cast<size_t>(written);
        }
    };

    const char* szColor = NULL;
    switch (nColor) {
    case 6:
        szColor = "\033[33m";
        break;
    case 10:
        szColor = "\033[32m";
        break;
    case 12:
        szColor = "\033[31m";
        break;
    default:
        break;
    }

    const bool useColor = szColor != nullptr && isatty(outputDescriptor) != 0 && getenv("NO_COLOR") == nullptr;
    if (useColor) {
        writeOutput(szColor, strlen(szColor));
    }
    writeOutput(szLog, strlen(szLog));
    if (useColor) {
        writeOutput("\033[0m", 4);
    }

#endif
}

void Logger::Print(int nLevel, const char* szLog) {
    if (g_nLogLevel >= nLevel) {
        _Print(szLog, 0, nLevel != E_INFO);
    }
}

void Logger::PrintV(int nLevel, const char* szFormat, ...) {
    if (g_nLogLevel >= nLevel) {
        FORMAT_V(szFormat, szLog);
        _Print(szLog, 0, nLevel != E_INFO);
    }
}

bool Logger::Error(const char* szLog) {
    _Print(szLog, 12, true);
    return false;
}

bool Logger::ErrorV(const char* szFormat, ...) {
    FORMAT_V(szFormat, szLog);
    _Print(szLog, 12, true);
    return false;
}

bool Logger::Success(const char* szLog) {
    _Print(szLog, 10, true);
    return true;
}

bool Logger::SuccessV(const char* szFormat, ...) {
    FORMAT_V(szFormat, szLog);
    _Print(szLog, 10, true);
    return true;
}

bool Logger::PrintResult(bool bSuccess, const char* szLog) {
    return bSuccess ? Success(szLog) : Error(szLog);
}

bool Logger::PrintResultV(bool bSuccess, const char* szFormat, ...) {
    FORMAT_V(szFormat, szLog);
    return bSuccess ? Success(szLog) : Error(szLog);
}

bool Logger::Warn(const char* szLog) {
    _Print(szLog, 6, true);
    return false;
}

bool Logger::WarnV(const char* szFormat, ...) {
    FORMAT_V(szFormat, szLog);
    _Print(szLog, 6, true);
    return false;
}

void Logger::Print(const char* szLog) {
    if (g_nLogLevel >= E_INFO) {
        _Print(szLog, 0, true);
    }
}

void Logger::PrintV(const char* szFormat, ...) {
    if (g_nLogLevel >= E_INFO) {
        FORMAT_V(szFormat, szLog);
        _Print(szLog, 0, true);
    }
}

void Logger::Debug(const char* szLog) {
    if (g_nLogLevel >= E_DEBUG) {
        _Print(szLog, 0, true);
    }
}

void Logger::DebugV(const char* szFormat, ...) {
    if (g_nLogLevel >= E_DEBUG) {
        FORMAT_V(szFormat, szLog);
        _Print(szLog, 0, true);
    }
}

void Logger::Diagnostic(const char* szLog) {
    if (g_nLogLevel >= E_INFO) {
        _Print(szLog, 0, true);
    }
}

void Logger::DiagnosticV(const char* szFormat, ...) {
    if (g_nLogLevel >= E_INFO) {
        FORMAT_V(szFormat, szLog);
        _Print(szLog, 0, true);
    }
}

void Logger::Report(const char* utf8Text) {
    _Write(utf8Text, 0, false);
}

void Logger::ReportV(const char* utf8Format, ...) {
    FORMAT_V(utf8Format, utf8Text);
    _Write(utf8Text, 0, false);
}

void Logger::ReportError(const char* utf8Text) {
    _Write(utf8Text, 0, true);
}

void Logger::ReportErrorV(const char* utf8Format, ...) {
    FORMAT_V(utf8Format, utf8Text);
    _Write(utf8Text, 0, true);
}
