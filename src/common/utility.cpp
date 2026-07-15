#include "utility.h"

#ifndef _WIN32
#include <sys/wait.h>
#endif

#ifdef _WIN32
#define PRId64 "lld"
#elif __APPLE__
#define PRId64 "lld"
#else
#define PRId64 "ld"
#endif

string Utility::FormatSize(int64_t size, int64_t base) {
    if (base <= 1) {
        base = 1024;
    }

    double fsize = 0;
    char ret[64] = {0};
    if (size >= base * base * base * base) {
        fsize = (size * 1.0) / (base * base * base * base);
        snprintf(ret, sizeof(ret), "%.2f TB", fsize);
    } else if (size >= base * base * base) {
        fsize = (size * 1.0) / (base * base * base);
        snprintf(ret, sizeof(ret), "%.2f GB", fsize);
    } else if (size >= base * base) {
        fsize = (size * 1.0) / (base * base);
        snprintf(ret, sizeof(ret), "%.2f MB", fsize);
    } else if (size >= base) {
        fsize = (size * 1.0) / (base);
        snprintf(ret, sizeof(ret), "%.2f KB", fsize);
    } else {
        snprintf(ret, sizeof(ret), "%" PRId64 " B", size);
    }
    return ret;
}

time_t Utility::GetUnixStamp() {
    time_t ustime = 0;
    time(&ustime);
    return ustime;
}

uint64_t Utility::GetMicroSecond() {
#ifdef _WIN32
    static const LONGLONG frequency = []() {
        LARGE_INTEGER value{};
        return QueryPerformanceFrequency(&value) && value.QuadPart > 0 ? value.QuadPart : 0;
    }();
    LARGE_INTEGER counter{};
    if (frequency == 0 || !QueryPerformanceCounter(&counter) || counter.QuadPart < 0) {
        return 0;
    }
    const uint64_t ticks = static_cast<uint64_t>(counter.QuadPart);
    const uint64_t divisor = static_cast<uint64_t>(frequency);
    return (ticks / divisor) * UINT64_C(1000000) + ((ticks % divisor) * UINT64_C(1000000)) / divisor;
#else
    struct timespec value{};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0 || value.tv_sec < 0 || value.tv_nsec < 0) {
        return 0;
    }
    return static_cast<uint64_t>(value.tv_sec) * UINT64_C(1000000) +
           static_cast<uint64_t>(value.tv_nsec) / UINT64_C(1000);
#endif
}

bool Utility::SystemExec(const vector<string>& arguments) {
    if (arguments.empty() || arguments.front().empty()) {
        return false;
    }
#ifdef _WIN32
    const auto utf8ToWide = [](const string& input, std::wstring& output) {
        if (input.empty()) {
            output.clear();
            return true;
        }
        const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                              static_cast<int>(input.size()), nullptr, 0);
        if (count <= 0) {
            return false;
        }
        output.resize(static_cast<size_t>(count));
        return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()),
                                   output.data(), count) == count;
    };
    const auto quote = [](const std::wstring& argument) {
        if (argument.empty()) {
            return std::wstring(L"\"\"");
        }
        if (argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
            return argument;
        }
        std::wstring result(1, L'"');
        size_t backslashes = 0;
        for (const wchar_t character : argument) {
            if (character == L'\\') {
                ++backslashes;
            } else if (character == L'"') {
                result.append(backslashes * 2 + 1, L'\\');
                result.push_back(L'"');
                backslashes = 0;
            } else {
                result.append(backslashes, L'\\');
                backslashes = 0;
                result.push_back(character);
            }
        }
        result.append(backslashes * 2, L'\\');
        result.push_back(L'"');
        return result;
    };

    std::wstring commandLine;
    for (const string& argument : arguments) {
        std::wstring wideArgument;
        if (!utf8ToWide(argument, wideArgument)) {
            return false;
        }
        if (!commandLine.empty()) {
            commandLine.push_back(L' ');
        }
        commandLine += quote(wideArgument);
    }
    vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup,
                        &process)) {
        return false;
    }
    CloseHandle(process.hThread);
    const DWORD waitResult = WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = 1;
    const bool success =
        waitResult == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &exitCode) && exitCode == 0;
    CloseHandle(process.hProcess);
    return success;
#else
    vector<char*> argv;
    argv.reserve(arguments.size() + 1);
    for (const string& argument : arguments) {
        argv.push_back(const_cast<char*>(argument.c_str()));
    }
    argv.push_back(nullptr);

    const pid_t child = fork();
    if (child < 0) {
        return false;
    }
    if (child == 0) {
        execvp(argv[0], argv.data());
        _exit(127);
    }

    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}

uint16_t Utility::Swap(uint16_t value) {
    return ((value >> 8) & 0x00ff) | ((value << 8) & 0xff00);
}

uint32_t Utility::Swap(uint32_t value) {
    value = ((value >> 8) & 0x00ff00ff) | ((value << 8) & 0xff00ff00);
    value = ((value >> 16) & 0x0000ffff) | ((value << 16) & 0xffff0000);
    return value;
}

uint64_t Utility::Swap(uint64_t value) {
    value = (value & 0x00000000ffffffffULL) << 32 | (value & 0xffffffff00000000ULL) >> 32;
    value = (value & 0x0000ffff0000ffffULL) << 16 | (value & 0xffff0000ffff0000ULL) >> 16;
    value = (value & 0x00ff00ff00ff00ffULL) << 8 | (value & 0xff00ff00ff00ff00ULL) >> 8;
    return value;
}

uint32_t Utility::ByteAlign(uint32_t uValue, uint32_t uAlign) {
    if (0 == uAlign) {
        return uValue;
    }

    const uint32_t remainder = uValue % uAlign;
    return (0 == remainder) ? uValue : (uValue + (uAlign - remainder));
}

const char* Utility::StringFormatV(string& strFormat, const char* szFormatArgs, ...) {
    FORMAT_V(szFormatArgs, szFormat);
    strFormat = szFormat;
    return strFormat.c_str();
}

string& Utility::StringReplace(string& context, const string& from, const string& to) {
    size_t lookHere = 0;
    size_t foundHere;
    while ((foundHere = context.find(from, lookHere)) != string::npos) {
        context.replace(foundHere, from.size(), to);
        lookHere = foundHere + to.size();
    }
    return context;
}

void Utility::StringSplit(const string& src, const string& split, vector<string>& dest) {
    dest.clear();
    if (split.empty()) {
        dest.push_back(src);
        return;
    }

    size_t oldPos = 0;
    size_t newPos = src.find(split, oldPos);
    while (newPos != string::npos) {
        dest.push_back(src.substr(oldPos, newPos - oldPos));
        oldPos = newPos + split.size();
        newPos = src.find(split, oldPos);
    }
    dest.push_back(src.substr(oldPos));
}

string& Utility::StringTrim(string& str) {
    static const char* kWhitespace = " \t\r\n";
    const size_t first = str.find_first_not_of(kWhitespace);
    if (first == string::npos) {
        str.clear();
        return str;
    }

    const size_t last = str.find_last_not_of(kWhitespace);
    str = str.substr(first, last - first + 1);
    return str;
}

const char* Utility::GetBaseName(const char* path) {
    static thread_local string s_baseName;
    s_baseName.clear();
    if (NULL == path) {
        return s_baseName.c_str();
    }

    s_baseName = path;
    const size_t pos = s_baseName.find_last_of("/\\");
    if (pos != string::npos) {
        s_baseName = s_baseName.substr(pos + 1);
    }
    return s_baseName.c_str();
}

int Utility::builtin_clzll(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return x == 0 ? 64 : __builtin_clzll(x);
#else
    if (x == 0) {
        return 64;
    }

    int count = 0;
    if (x <= 0x00000000FFFFFFFF) {
        count += 32;
        x <<= 32;
    }
    if (x <= 0x0000FFFFFFFFFFFF) {
        count += 16;
        x <<= 16;
    }
    if (x <= 0x00FFFFFFFFFFFFFF) {
        count += 8;
        x <<= 8;
    }
    if (x <= 0x0FFFFFFFFFFFFFFF) {
        count += 4;
        x <<= 4;
    }
    if (x <= 0x3FFFFFFFFFFFFFFF) {
        count += 2;
        x <<= 2;
    }
    if (x <= 0x7FFFFFFFFFFFFFFF) {
        count += 1;
    }

    return count;
#endif
}
