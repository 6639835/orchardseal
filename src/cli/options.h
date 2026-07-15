#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace orchardseal::cli {

    enum class AuditFormat {
        Text,
        Json,
    };

    enum class ParseStatus {
        Ok,
        HelpRequested,
        VersionRequested,
        Error,
    };

    struct Options {
        bool force = false;
        bool install = false;
        bool weakInject = false;
        bool adhoc = false;
        bool sha256Only = true;
        bool checkSignature = false;
        bool removeProvision = false;
        bool enableDocuments = false;
        bool removeExtensions = false;
        bool removeWatchApp = false;
        bool removeUISupportedDevices = false;
        bool audit = false;
        bool strictAudit = false;

        std::uint32_t dylibInjectScope = 1U;
        int zipLevel = 0;
        AuditFormat auditFormat = AuditFormat::Text;

        std::string certificateFile;
        std::string privateKeyFile;
        std::vector<std::string> provisionFiles;
        std::string password;
        std::string bundleId;
        std::string bundleVersion;
        std::string outputFile;
        std::string displayName;
        std::string entitlementsFile;
        std::vector<std::string> dylibFiles;
        std::vector<std::string> removeDylibNames;
        std::string metadataDirectory;
        std::string iconFile;
        std::string tempFolder;
        std::string minimumVersion;
        std::string auditReportFile;
        std::string targetPath;
        std::vector<std::string> rawArguments;
    };

    struct ParseResult {
        ParseStatus status = ParseStatus::Ok;
        Options options;
        int exitCode = 0;
        std::string message;
    };

    class CommandLineOptions {
      public:
        static ParseResult Parse(int argc, char* argv[]);
        static int PrintUsage(bool toStandardError = false);
        static bool IsDylibLoadCommandName(const std::string& name);

      private:
        static bool ParseDylibInjectScope(const std::string& scope, std::uint32_t& parsedScope);
    };

} // namespace orchardseal::cli
