#pragma once

#include "macho_slice.h"

#include <cstdint>
#include <string>
#include <vector>

namespace orchardseal::audit {

    enum class Severity {
        Info,
        Warning,
        Error,
    };

    struct Issue {
        Severity severity = Severity::Info;
        std::string code;
        std::string message;
        std::string path;
    };

    struct ProvisioningProfileInfo {
        std::string path;
        std::string name;
        std::string uuid;
        std::string teamId;
        std::string teamName;
        std::string applicationIdentifier;
        std::string expiration;
        std::string kind;
        std::vector<std::string> platforms;
        bool embedded = false;
        bool valid = false;
        bool expired = false;
    };

    struct BundleInfo {
        std::string path;
        std::string type;
        std::string bundleId;
        std::string displayName;
        std::string version;
        std::string shortVersion;
        std::string minimumOsVersion;
        std::string executable;
        std::string matchedProfile;
        bool mainBundle = false;
        bool infoPlistValid = false;
        bool provisioningProfilePresent = false;
    };

    struct BinaryInfo {
        std::string path;
        std::string ownerBundleId;
        std::int64_t sizeBytes = 0;
        bool mainExecutable = false;
        bool signaturePresent = false;
        bool encrypted = false;
        std::vector<MachOSliceInfo> architectures;
    };

    struct SigningAssetInfo {
        bool requested = false;
        bool valid = false;
        std::string certificateSubject;
        std::string teamId;
        std::string applicationIdentifier;
    };

    struct Summary {
        std::int64_t bundleCount = 0;
        std::int64_t binaryCount = 0;
        std::int64_t signedBinaryCount = 0;
        std::int64_t unsignedBinaryCount = 0;
        std::int64_t encryptedBinaryCount = 0;
        std::int64_t infoCount = 0;
        std::int64_t warningCount = 0;
        std::int64_t errorCount = 0;
    };

    struct Report {
        std::string schemaVersion = "1.0";
        std::string product = "OrchardSeal";
        std::string engine = "SealCheck";
        std::string productVersion;
        std::string generatedAt;
        std::string inputPath;
        std::string inputType;
        std::int64_t inputSizeBytes = 0;
        bool readyForSigning = false;
        Summary summary;
        SigningAssetInfo signingAsset;
        std::vector<ProvisioningProfileInfo> profiles;
        std::vector<BundleInfo> bundles;
        std::vector<BinaryInfo> binaries;
        std::vector<Issue> issues;
    };

    struct Request {
        std::string inputPath;
        std::string tempDirectory;
        std::string certificateFile;
        std::string privateKeyFile;
        std::vector<std::string> provisioningFiles;
        std::string password;
        std::string entitlementsFile;
        bool adhoc = false;
        bool sha256Only = true;
    };

    class Service {
      public:
        bool Run(const Request& request, Report& report, std::string& error) const;
    };

    [[nodiscard]] std::string ToJson(const Report& report);
    [[nodiscard]] std::string ToText(const Report& report);
    [[nodiscard]] bool HasBlockingIssues(const Report& report, bool strictWarnings);
    [[nodiscard]] const char* SeverityName(Severity severity);

} // namespace orchardseal::audit
