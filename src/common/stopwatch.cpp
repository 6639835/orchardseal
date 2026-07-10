#include "stopwatch.h"

Stopwatch::Stopwatch() {
    Reset();
}

std::uint64_t Stopwatch::Reset() {
    beginTime_ = Utility::GetMicroSecond();
    return beginTime_;
}

std::uint64_t Stopwatch::Print(const char* format, ...) {
    FORMAT_V(format, message);
    const std::uint64_t elapsedMicroseconds = Utility::GetMicroSecond() - beginTime_;
    Logger::PrintV("%s (%.03fs, %lluus)\n", message, elapsedMicroseconds / 1000000.0,
                   static_cast<unsigned long long>(elapsedMicroseconds));
    return Reset();
}

std::uint64_t Stopwatch::PrintResult(bool success, const char* format, ...) {
    FORMAT_V(format, message);
    const std::uint64_t elapsedMicroseconds = Utility::GetMicroSecond() - beginTime_;
    Logger::PrintResultV(success, "%s (%.03fs, %lluus)\n", message, elapsedMicroseconds / 1000000.0,
                         static_cast<unsigned long long>(elapsedMicroseconds));
    return Reset();
}
