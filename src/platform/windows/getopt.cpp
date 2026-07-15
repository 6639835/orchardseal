#include "getopt.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

int optind = 1;
int opterr = 1;
int optopt = 0;
char* optarg = nullptr;

namespace {
    const char* g_nextShortOption = nullptr;

    int MissingArgument(const char* shortopts, const char* spelling, int optionValue) {
        optopt = optionValue;
        if (opterr != 0 && shortopts[0] != ':') {
            std::fprintf(stderr, "option requires an argument -- %s\n", spelling);
        }
        return shortopts[0] == ':' ? ':' : '?';
    }

    int UnknownOption(const char* shortopts, const char* spelling, int optionValue) {
        optopt = optionValue;
        if (opterr != 0 && shortopts[0] != ':') {
            std::fprintf(stderr, "unrecognized option -- %s\n", spelling);
        }
        return '?';
    }

    int OptionSpan(int argc, char* argv[], int index, const char* shortopts, const struct option* longopts) {
        const char* argument = argv[index];
        if (std::strcmp(argument, "--") == 0 || argument[1] == '\0') {
            return 1;
        }
        if (argument[1] == '-') {
            const char* name = argument + 2;
            const char* equals = std::strchr(name, '=');
            const std::size_t length = equals == nullptr ? std::strlen(name) : static_cast<std::size_t>(equals - name);
            for (int optionIndex = 0; longopts[optionIndex].name != nullptr; ++optionIndex) {
                if (std::strlen(longopts[optionIndex].name) == length &&
                    std::strncmp(longopts[optionIndex].name, name, length) == 0) {
                    return equals == nullptr && longopts[optionIndex].has_arg == required_argument && index + 1 < argc
                               ? 2
                               : 1;
                }
            }
            return 1;
        }

        for (const char* character = argument + 1; *character != '\0'; ++character) {
            const char* declaration = std::strchr(shortopts, *character);
            if (declaration != nullptr && declaration[1] == ':') {
                return character[1] == '\0' && declaration[2] != ':' && index + 1 < argc ? 2 : 1;
            }
        }
        return 1;
    }
} // namespace

int getopt_long(int argc, char* argv[], const char* shortopts, const struct option* longopts, int* longindex) {
    optarg = nullptr;
    optopt = 0;
    if (longindex != nullptr) {
        *longindex = -1;
    }

    if (optind == 0) {
        optind = 1;
        g_nextShortOption = nullptr;
    }

    if (g_nextShortOption != nullptr && *g_nextShortOption != '\0') {
        const char optionCharacter = *g_nextShortOption++;
        const char* declaration = std::strchr(shortopts, optionCharacter);
        if (declaration == nullptr || optionCharacter == ':') {
            if (*g_nextShortOption == '\0') {
                ++optind;
                g_nextShortOption = nullptr;
            }
            char spelling[2] = {optionCharacter, '\0'};
            return UnknownOption(shortopts, spelling, static_cast<unsigned char>(optionCharacter));
        }

        const bool takesArgument = declaration[1] == ':';
        const bool optionalArgument = takesArgument && declaration[2] == ':';
        if (!takesArgument) {
            if (*g_nextShortOption == '\0') {
                ++optind;
                g_nextShortOption = nullptr;
            }
            return static_cast<unsigned char>(optionCharacter);
        }

        if (*g_nextShortOption != '\0') {
            optarg = const_cast<char*>(g_nextShortOption);
            ++optind;
            g_nextShortOption = nullptr;
            return static_cast<unsigned char>(optionCharacter);
        }

        g_nextShortOption = nullptr;
        ++optind;
        if (!optionalArgument) {
            if (optind >= argc) {
                char spelling[2] = {optionCharacter, '\0'};
                return MissingArgument(shortopts, spelling, static_cast<unsigned char>(optionCharacter));
            }
            optarg = argv[optind++];
        }
        return static_cast<unsigned char>(optionCharacter);
    }

    if (optind >= argc || argv[optind] == nullptr) {
        return -1;
    }

    const char* argument = argv[optind];
    if (std::strcmp(argument, "--") == 0) {
        ++optind;
        return -1;
    }
    if (argument[0] != '-' || argument[1] == '\0') {
        int optionIndex = optind + 1;
        while (optionIndex < argc && argv[optionIndex] != nullptr) {
            const char* candidate = argv[optionIndex];
            if (candidate[0] == '-' && candidate[1] != '\0') {
                const int span = OptionSpan(argc, argv, optionIndex, shortopts, longopts);
                std::rotate(argv + optind, argv + optionIndex, argv + optionIndex + span);
                argument = argv[optind];
                break;
            }
            ++optionIndex;
        }
        if (optionIndex >= argc || argv[optionIndex] == nullptr) {
            return -1;
        }
    }

    if (argument[1] != '-') {
        g_nextShortOption = argument + 1;
        return getopt_long(argc, argv, shortopts, longopts, longindex);
    }

    const char* name = argument + 2;
    const char* equals = std::strchr(name, '=');
    const std::size_t nameLength = equals == nullptr ? std::strlen(name) : static_cast<std::size_t>(equals - name);
    for (int index = 0; longopts[index].name != nullptr; ++index) {
        if (std::strlen(longopts[index].name) != nameLength ||
            std::strncmp(name, longopts[index].name, nameLength) != 0) {
            continue;
        }

        ++optind;
        if (longindex != nullptr) {
            *longindex = index;
        }
        if (longopts[index].has_arg == no_argument) {
            if (equals != nullptr) {
                return UnknownOption(shortopts, argument, longopts[index].val);
            }
        } else if (equals != nullptr) {
            optarg = const_cast<char*>(equals + 1);
        } else if (longopts[index].has_arg == required_argument) {
            if (optind >= argc) {
                return MissingArgument(shortopts, argument, longopts[index].val);
            }
            optarg = argv[optind++];
        }

        if (longopts[index].flag != nullptr) {
            *longopts[index].flag = longopts[index].val;
            return 0;
        }
        return longopts[index].val;
    }

    ++optind;
    return UnknownOption(shortopts, argument, 0);
}
