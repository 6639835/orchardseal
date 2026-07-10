#include "logger.h"

int Logger::g_nLogLevel = Logger::E_INFO;

void Logger::_Print(const char* szLog, int nColor) {
    if (g_nLogLevel <= E_NONE) {
        return;
    }

#ifdef _WIN32

    string strLog = szLog;
    HANDLE hConsole = ::GetStdHandle(STD_OUTPUT_HANDLE);
    if (nColor > 0) {
        ::SetConsoleTextAttribute(hConsole, nColor);
    }
    ::WriteFile(hConsole, strLog.data(), (DWORD)strLog.size(), NULL, NULL);
    if (nColor > 0) {
        ::SetConsoleTextAttribute(hConsole, 7);
    }

#else

    const auto writeToStdout = [](const char* data, size_t size) {
        while (size > 0) {
            const ssize_t written = write(STDOUT_FILENO, data, size);
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

    if (NULL != szColor) {
        writeToStdout(szColor, strlen(szColor));
    }
    writeToStdout(szLog, strlen(szLog));
    if (NULL != szColor) {
        writeToStdout("\033[0m", 4);
    }

#endif
}

void Logger::Print(int nLevel, const char* szLog) {
    if (g_nLogLevel >= nLevel) {
        _Print(szLog);
    }
}

void Logger::PrintV(int nLevel, const char* szFormat, ...) {
    if (g_nLogLevel >= nLevel) {
        FORMAT_V(szFormat, szLog);
        _Print(szLog);
    }
}

bool Logger::Error(const char* szLog) {
    _Print(szLog, 12);
    return false;
}

bool Logger::ErrorV(const char* szFormat, ...) {
    FORMAT_V(szFormat, szLog);
    _Print(szLog, 12);
    return false;
}

bool Logger::Success(const char* szLog) {
    _Print(szLog, 10);
    return true;
}

bool Logger::SuccessV(const char* szFormat, ...) {
    FORMAT_V(szFormat, szLog);
    _Print(szLog, 10);
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
    _Print(szLog, 6);
    return false;
}

bool Logger::WarnV(const char* szFormat, ...) {
    FORMAT_V(szFormat, szLog);
    _Print(szLog, 6);
    return false;
}

void Logger::Print(const char* szLog) {
    if (g_nLogLevel >= E_INFO) {
        _Print(szLog);
    }
}

void Logger::PrintV(const char* szFormat, ...) {
    if (g_nLogLevel >= E_INFO) {
        FORMAT_V(szFormat, szLog);
        _Print(szLog);
    }
}

void Logger::Debug(const char* szLog) {
    if (g_nLogLevel >= E_DEBUG) {
        _Print(szLog);
    }
}

void Logger::DebugV(const char* szFormat, ...) {
    if (g_nLogLevel >= E_DEBUG) {
        FORMAT_V(szFormat, szLog);
        _Print(szLog);
    }
}
