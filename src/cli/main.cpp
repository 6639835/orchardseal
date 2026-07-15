#include "application.h"
#include "options.h"

#include "common.h"
#include "orchardseal/version.h"

#include <cstdio>
#include <string>
#include <vector>

#ifdef _WIN32
#include "windows_text_converter.h"
#endif

namespace {
    int RunMain(int argc, char* argv[]) {
        const auto parsed = orchardseal::cli::CommandLineOptions::Parse(argc, argv);

        switch (parsed.status) {
        case orchardseal::cli::ParseStatus::Ok:
            return orchardseal::cli::Application(parsed.options).Run();
        case orchardseal::cli::ParseStatus::VersionRequested:
            Logger::ReportV("OrchardSeal %s\n", ORCHARDSEAL_VERSION_STRING);
            return 0;
        case orchardseal::cli::ParseStatus::HelpRequested:
            orchardseal::cli::CommandLineOptions::PrintUsage(parsed.exitCode != 0);
            return parsed.exitCode;
        case orchardseal::cli::ParseStatus::Error:
            if (!parsed.message.empty()) {
                Logger::ErrorV(">>> %s\n", parsed.message.c_str());
            }
            orchardseal::cli::CommandLineOptions::PrintUsage(true);
            return parsed.exitCode == 0 ? 2 : parsed.exitCode;
        }

        return 2;
    }
} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t* argv[]) {
    WindowsTextConverter converter;
    std::vector<std::string> utf8Arguments;
    utf8Arguments.reserve(static_cast<std::size_t>(argc));
    for (int index = 0; index < argc; ++index) {
        std::string argument;
        if (!converter.WideToUtf8(argv[index], argument)) {
            Logger::ReportError(">>> Command-line arguments contain invalid Unicode.\n");
            return 2;
        }
        utf8Arguments.push_back(std::move(argument));
    }

    std::vector<char*> argumentPointers;
    argumentPointers.reserve(utf8Arguments.size());
    for (std::string& argument : utf8Arguments) {
        argumentPointers.push_back(argument.data());
    }
    return RunMain(argc, argumentPointers.data());
}
#else
int main(int argc, char* argv[]) {
    return RunMain(argc, argv);
}
#endif
