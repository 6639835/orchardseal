#include "application.h"
#include "options.h"

#include "common.h"
#include "orchardseal/version.h"

#include <cstdio>

int main(int argc, char* argv[]) {
    const auto parsed = orchardseal::cli::CommandLineOptions::Parse(argc, argv);

    switch (parsed.status) {
    case orchardseal::cli::ParseStatus::Ok:
        return orchardseal::cli::Application(parsed.options).Run();
    case orchardseal::cli::ParseStatus::VersionRequested:
        std::printf("OrchardSeal %s\n", ORCHARDSEAL_VERSION_STRING);
        return 0;
    case orchardseal::cli::ParseStatus::HelpRequested:
        orchardseal::cli::CommandLineOptions::PrintUsage();
        return parsed.exitCode;
    case orchardseal::cli::ParseStatus::Error:
        if (!parsed.message.empty()) {
            Logger::ErrorV(">>> %s\n", parsed.message.c_str());
        }
        orchardseal::cli::CommandLineOptions::PrintUsage();
        return parsed.exitCode == 0 ? 2 : parsed.exitCode;
    }

    return 2;
}
