#pragma once

#include "common.h"

#include <cstdint>

class Stopwatch
{
public:
    Stopwatch();

    std::uint64_t Reset();
    std::uint64_t Print(const char* format, ...);
    std::uint64_t PrintResult(bool success, const char* format, ...);

private:
    std::uint64_t beginTime_ = 0;
};
