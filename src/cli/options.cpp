#include "options.h"

#include "app_bundle.h"
#include "common.h"
#include "macho_file.h"
#include "orchardseal/version.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>

#ifdef _WIN32
#include "common_win32.h"
#endif

namespace orchardseal::cli {
    namespace {

        enum LongOptionValue {
            OptDylibScope = 1000,
            OptIcon,
            OptAudit,
            OptAuditFormat,
            OptAuditReport,
            OptStrictAudit,
        };

        const option kOptions[] = {
            {"debug", no_argument, nullptr, 'd'},
            {"force", no_argument, nullptr, 'f'},
            {"verbose", no_argument, nullptr, 'V'},
            {"adhoc", no_argument, nullptr, 'a'},
            {"cert", required_argument, nullptr, 'c'},
            {"pkey", required_argument, nullptr, 'k'},
            {"prov", required_argument, nullptr, 'm'},
            {"password", required_argument, nullptr, 'p'},
            {"bundle_id", required_argument, nullptr, 'b'},
            {"bundle_name", required_argument, nullptr, 'n'},
            {"bundle_version", required_argument, nullptr, 'r'},
            {"entitlements", required_argument, nullptr, 'e'},
            {"output", required_argument, nullptr, 'o'},
            {"zip_level", required_argument, nullptr, 'z'},
            {"dylib", required_argument, nullptr, 'l'},
            {"dylib_scope", required_argument, nullptr, OptDylibScope},
            {"rm_dylib", required_argument, nullptr, 'D'},
            {"weak", no_argument, nullptr, 'w'},
            {"temp_folder", required_argument, nullptr, 't'},
            {"sha256_only", no_argument, nullptr, '2'},
            {"legacy_sha1", no_argument, nullptr, 'L'},
            {"install", no_argument, nullptr, 'i'},
            {"check", no_argument, nullptr, 'C'},
            {"quiet", no_argument, nullptr, 'q'},
            {"metadata", required_argument, nullptr, 'x'},
            {"icon", required_argument, nullptr, OptIcon},
            {"audit", no_argument, nullptr, OptAudit},
            {"audit-format", required_argument, nullptr, OptAuditFormat},
            {"audit-report", required_argument, nullptr, OptAuditReport},
            {"strict-audit", no_argument, nullptr, OptStrictAudit},
            {"rm_provision", no_argument, nullptr, 'R'},
            {"enable_docs", no_argument, nullptr, 'S'},
            {"min_version", required_argument, nullptr, 'M'},
            {"rm_extensions", no_argument, nullptr, 'E'},
            {"rm_watch", no_argument, nullptr, 'W'},
            {"rm_uisd", no_argument, nullptr, 'U'},
            {"version", no_argument, nullptr, 'v'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, 0, nullptr, 0},
        };

        bool StartsWith(const std::string& value, const char* prefix) {
            return value.compare(0, std::strlen(prefix), prefix) == 0;
        }

        std::string LowerCopy(std::string value) {
            std::transform(value.begin(), value.end(), value.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            return value;
        }

        bool TryParseZipLevel(const char* value, int& zipLevel) {
            if (value == nullptr || *value == '\0') {
                return false;
            }

            char* end = nullptr;
            const long parsed = std::strtol(value, &end, 10);
            if (end == value || *end != '\0' || parsed < 0 || parsed > 9) {
                return false;
            }

            zipLevel = static_cast<int>(parsed);
            return true;
        }

        std::string FullPathOrEmpty(const char* path) {
            return path == nullptr ? std::string() : FileSystem::GetFullPath(path);
        }

        const char* DebugOptionValue(int optionValue, const char* value) {
            if (optionValue == 'p') {
                return "<redacted>";
            }
            return value == nullptr ? "" : value;
        }

    } // namespace

    bool CommandLineOptions::IsDylibLoadCommandName(const std::string& name) {
        return StartsWith(name, "@executable_path/") || StartsWith(name, "@loader_path/") ||
               StartsWith(name, "@rpath/") || StartsWith(name, "/usr/lib/") || StartsWith(name, "/System/Library/");
    }

    bool CommandLineOptions::ParseDylibInjectScope(const std::string& scope, std::uint32_t& parsedScope) {
        std::vector<std::string> scopes;
        Utility::StringSplit(scope, ",", scopes);
        if (scopes.empty()) {
            scopes.push_back(scope);
        }

        std::uint32_t result = 0;
        for (std::string item : scopes) {
            Utility::StringTrim(item);
            item = LowerCopy(item);

            if (item.empty()) {
                continue;
            }

            if (item == "all") {
                result |= DYLIB_INJECT_ALL;
            } else if (item == "root" || item == "app" || item == "main") {
                result |= DYLIB_INJECT_ROOT;
            } else if (item == "extensions" || item == "extension" || item == "plugins" || item == "plugin" ||
                       item == "appex") {
                result |= DYLIB_INJECT_EXTENSIONS;
            } else if (item == "frameworks" || item == "framework") {
                result |= DYLIB_INJECT_FRAMEWORKS;
            } else if (item == "files" || item == "file" || item == "binaries" || item == "binary" || item == "macho") {
                result |= DYLIB_INJECT_FILES;
            } else {
                return false;
            }
        }

        if (result == 0) {
            return false;
        }

        parsedScope = result;
        return true;
    }

    ParseResult CommandLineOptions::Parse(int argc, char* argv[]) {
        ParseResult result;
        result.options.tempFolder = FileSystem::GetTempFolder();

#ifdef _WIN32
        optind = 0;
#else
        optind = 1;
#endif
        opterr = 0;

        int optionIndex = -1;
        int opt = 0;
        while ((opt = getopt_long(argc, argv, "dfvVa2LhiqwCRSEWUc:k:m:o:p:e:b:n:z:l:D:t:r:x:M:", kOptions,
                                  &optionIndex)) != -1) {
            switch (opt) {
            case 'd':
                Logger::SetLogLevel(Logger::E_DEBUG);
                break;
            case 'V':
                Logger::SetLogLevel(Logger::E_INFO);
                break;
            case 'f':
                result.options.force = true;
                break;
            case 'c':
                result.options.certificateFile = FullPathOrEmpty(optarg);
                break;
            case 'k':
                result.options.privateKeyFile = FullPathOrEmpty(optarg);
                break;
            case 'm':
                result.options.provisionFiles.push_back(FullPathOrEmpty(optarg));
                break;
            case 'a':
                result.options.adhoc = true;
                break;
            case 'p':
                result.options.password = optarg == nullptr ? std::string() : optarg;
                break;
            case 'b':
                result.options.bundleId = optarg == nullptr ? std::string() : optarg;
                break;
            case 'r':
                result.options.bundleVersion = optarg == nullptr ? std::string() : optarg;
                break;
            case 'n':
                result.options.displayName = optarg == nullptr ? std::string() : optarg;
                break;
            case 'e':
                result.options.entitlementsFile = FullPathOrEmpty(optarg);
                break;
            case 'l': {
                const std::string value = optarg == nullptr ? std::string() : optarg;
                result.options.dylibFiles.push_back(
                    IsDylibLoadCommandName(value) ? value : FileSystem::GetFullPath(value.c_str()));
                break;
            }
            case OptDylibScope:
                if (!ParseDylibInjectScope(optarg == nullptr ? std::string() : optarg,
                                           result.options.dylibInjectScope)) {
                    result.status = ParseStatus::Error;
                    result.message = "Invalid dylib scope.";
                    result.exitCode = 2;
                    return result;
                }
                break;
            case 'D':
                result.options.removeDylibNames.push_back(optarg == nullptr ? std::string() : optarg);
                break;
            case 'i':
                result.options.install = true;
                break;
            case 'o':
                result.options.outputFile = FullPathOrEmpty(optarg);
                break;
            case 'z':
                if (!TryParseZipLevel(optarg, result.options.zipLevel)) {
                    result.status = ParseStatus::Error;
                    result.message = "Invalid zip level. Use a value from 0 to 9.";
                    result.exitCode = 2;
                    return result;
                }
                break;
            case 'w':
                result.options.weakInject = true;
                break;
            case 't':
                result.options.tempFolder = FullPathOrEmpty(optarg);
                break;
            case '2':
                result.options.sha256Only = true;
                break;
            case 'L':
                result.options.sha256Only = false;
                break;
            case 'C':
                result.options.checkSignature = true;
                break;
            case 'q':
                Logger::SetLogLevel(Logger::E_NONE);
                break;
            case 'x':
                result.options.metadataDirectory = FullPathOrEmpty(optarg);
                break;
            case OptIcon:
                result.options.iconFile = FullPathOrEmpty(optarg);
                break;
            case OptAudit:
                result.options.audit = true;
                break;
            case OptAuditFormat: {
                const std::string format = LowerCopy(optarg == nullptr ? std::string() : optarg);
                if (format == "text") {
                    result.options.auditFormat = AuditFormat::Text;
                } else if (format == "json") {
                    result.options.auditFormat = AuditFormat::Json;
                } else {
                    result.status = ParseStatus::Error;
                    result.message = "Invalid audit format. Use 'text' or 'json'.";
                    result.exitCode = 2;
                    return result;
                }
                result.options.audit = true;
                break;
            }
            case OptAuditReport:
                result.options.auditReportFile = FullPathOrEmpty(optarg);
                result.options.audit = true;
                break;
            case OptStrictAudit:
                result.options.strictAudit = true;
                result.options.audit = true;
                break;
            case 'R':
                result.options.removeProvision = true;
                break;
            case 'S':
                result.options.enableDocuments = true;
                break;
            case 'M':
                result.options.minimumVersion = optarg == nullptr ? std::string() : optarg;
                break;
            case 'E':
                result.options.removeExtensions = true;
                break;
            case 'W':
                result.options.removeWatchApp = true;
                break;
            case 'U':
                result.options.removeUISupportedDevices = true;
                break;
            case 'v':
                result.status = ParseStatus::VersionRequested;
                break;
            case 'h':
                result.status = ParseStatus::HelpRequested;
                break;
            case '?':
            default:
                result.status = ParseStatus::Error;
                result.message = "Unknown or incomplete option.";
                result.exitCode = 2;
                return result;
            }

            if (Logger::IsDebug()) {
                Logger::DebugV(">>> Option:\t%d, %s\n", opt, DebugOptionValue(opt, optarg));
            }
        }

        for (int index = optind; index < argc; ++index) {
            result.options.rawArguments.emplace_back(argv[index]);
        }

        if (result.status == ParseStatus::HelpRequested || result.status == ParseStatus::VersionRequested) {
            if (!result.options.rawArguments.empty()) {
                result.status = ParseStatus::Error;
                result.message = "Help and version modes do not accept input operands.";
                result.exitCode = 2;
            }
            return result;
        }

        if (result.options.rawArguments.empty()) {
            result.status = ParseStatus::HelpRequested;
            result.exitCode = 1;
            return result;
        }

        if (result.options.rawArguments.size() != 1U) {
            result.status = ParseStatus::Error;
            result.message = "Expected exactly one input path; extra operands are not supported.";
            result.exitCode = 2;
            return result;
        }

        result.options.targetPath = FileSystem::GetFullPath(result.options.rawArguments.front().c_str());
        return result;
    }

    int CommandLineOptions::PrintUsage(bool toStandardError) {
        const std::string heading = std::string("OrchardSeal ") + ORCHARDSEAL_VERSION_STRING +
                                    " — portable iOS signing and SealCheck preflight audits.\n\n";
        static const char usage[] =
            "Usage: orchardseal [options] [-k privkey.pem] [-m dev.mobileprovision] [-o output.ipa] file|folder\n\n"
            "Signing options:\n"
            "  -k, --pkey              Path to private key or p12 file. PEM or DER format.\n"
            "  -m, --prov              Path to mobile provisioning profile. Repeat for multiple profiles.\n"
            "  -c, --cert              Path to certificate file. PEM or DER format.\n"
            "  -a, --adhoc             Perform an ad-hoc signature only.\n"
            "  -p, --password          Password for private key or p12 file.\n"
            "  -2, --sha256_only       Deprecated; SHA256-only is the default.\n"
            "  -L, --legacy_sha1       Emit a dual SHA1+SHA256 CodeDirectory for old iOS support.\n\n"
            "Bundle mutation options:\n"
            "  -b, --bundle_id         New bundle identifier.\n"
            "  -n, --bundle_name       New display name.\n"
            "  -r, --bundle_version    New bundle version.\n"
            "  -e, --entitlements      Entitlements plist to use.\n"
            "  -l, --dylib             Dylib path or load command to inject. Repeatable.\n"
            "      --dylib_scope       Scope for -l/-D: root, extensions, frameworks, files, all.\n"
            "  -D, --rm_dylib          Dylib load command or name to remove. Repeatable.\n"
            "  -w, --weak              Inject dylibs as LC_LOAD_WEAK_DYLIB.\n"
            "      --icon              Replace declared app icon PNG files before signing.\n"
            "  -R, --rm_provision      Remove embedded.mobileprovision after signing.\n"
            "  -S, --enable_docs       Enable document browser and file sharing keys.\n"
            "  -M, --min_version       Set MinimumOSVersion in Info.plist.\n"
            "  -E, --rm_extensions     Remove all app extensions.\n"
            "  -W, --rm_watch          Remove Watch app content.\n"
            "  -U, --rm_uisd           Remove UISupportedDevices from Info.plist.\n\n"
            "Preflight audit (read-only):\n"
            "      --audit             Inspect an IPA, app bundle, folder, or Mach-O without modifying it.\n"
            "      --audit-format      Report format written to stdout: text or json. Default: text.\n"
            "      --audit-report      Save the full JSON report to a file; implies --audit.\n"
            "      --strict-audit      Return exit code 3 for warnings as well as errors.\n\n"
            "Output and diagnostics:\n"
            "  -o, --output            Output IPA path. Required when input is an IPA.\n"
            "  -z, --zip_level         Compression level for IPA output: 0-9.\n"
            "  -x, --metadata          Extract metadata and icon to a directory after archive.\n"
            "  -C, --check             Check certificate validity / signed binary details.\n"
            "  -i, --install           Install IPA using ideviceinstaller after signing.\n"
            "  -t, --temp_folder       Temporary working directory.\n"
            "  -d, --debug             Enable debug logging and .orchardseal_debug output.\n"
            "  -V, --verbose           Enable normal informational logs.\n"
            "  -q, --quiet             Suppress logs.\n"
            "  -v, --version           Show version.\n"
            "  -h, --help              Show this help.\n";
        if (toStandardError) {
            Logger::ReportError(heading.c_str());
            Logger::ReportError(usage);
        } else {
            Logger::Report(heading.c_str());
            Logger::Report(usage);
        }
        return 0;
    }

} // namespace orchardseal::cli
