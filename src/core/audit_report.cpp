#include "audit.h"

#include "json.h"

#include <sstream>
#include <utility>

namespace orchardseal::audit {
    namespace {

        jvalue ArchitectureJson(const MachOSliceInfo& architecture) {
            jvalue value(jvalue::E_OBJECT);
            value["architecture"] = architecture.architecture;
            value["file_type"] = architecture.fileType;
            value["size_bytes"] = static_cast<std::int64_t>(architecture.sizeBytes);
            value["is_64_bit"] = architecture.is64Bit;
            value["big_endian"] = architecture.bigEndian;
            value["encrypted"] = architecture.encrypted;
            value["signature_present"] = architecture.signaturePresent;
            value["executable"] = architecture.executable;
            return value;
        }

    } // namespace

    const char* SeverityName(Severity severity) {
        switch (severity) {
        case Severity::Info:
            return "info";
        case Severity::Warning:
            return "warning";
        case Severity::Error:
            return "error";
        }
        return "unknown";
    }

    std::string ToJson(const Report& report) {
        jvalue root(jvalue::E_OBJECT);
        root["schema_version"] = report.schemaVersion;
        root["product"] = report.product;
        root["engine"] = report.engine;
        root["product_version"] = report.productVersion;
        root["generated_at"] = report.generatedAt;
        root["input_path"] = report.inputPath;
        root["input_type"] = report.inputType;
        root["input_size_bytes"] = report.inputSizeBytes;
        root["ready_for_signing"] = report.readyForSigning;

        jvalue summary(jvalue::E_OBJECT);
        summary["bundle_count"] = report.summary.bundleCount;
        summary["binary_count"] = report.summary.binaryCount;
        summary["signed_binary_count"] = report.summary.signedBinaryCount;
        summary["unsigned_binary_count"] = report.summary.unsignedBinaryCount;
        summary["encrypted_binary_count"] = report.summary.encryptedBinaryCount;
        summary["info_count"] = report.summary.infoCount;
        summary["warning_count"] = report.summary.warningCount;
        summary["error_count"] = report.summary.errorCount;
        root["summary"] = std::move(summary);

        jvalue signingAsset(jvalue::E_OBJECT);
        signingAsset["requested"] = report.signingAsset.requested;
        signingAsset["valid"] = report.signingAsset.valid;
        signingAsset["certificate_subject"] = report.signingAsset.certificateSubject;
        signingAsset["team_id"] = report.signingAsset.teamId;
        signingAsset["application_identifier"] = report.signingAsset.applicationIdentifier;
        root["signing_asset"] = std::move(signingAsset);

        root["profiles"] = jvalue(jvalue::E_ARRAY);
        for (const ProvisioningProfileInfo& profile : report.profiles) {
            jvalue value(jvalue::E_OBJECT);
            value["path"] = profile.path;
            value["name"] = profile.name;
            value["uuid"] = profile.uuid;
            value["team_id"] = profile.teamId;
            value["team_name"] = profile.teamName;
            value["application_identifier"] = profile.applicationIdentifier;
            value["expiration"] = profile.expiration;
            value["kind"] = profile.kind;
            value["embedded"] = profile.embedded;
            value["valid"] = profile.valid;
            value["expired"] = profile.expired;
            value["platforms"] = jvalue(jvalue::E_ARRAY);
            for (const std::string& platform : profile.platforms) {
                value["platforms"].push_back(platform);
            }
            root["profiles"].push_back(value);
        }

        root["bundles"] = jvalue(jvalue::E_ARRAY);
        for (const BundleInfo& bundle : report.bundles) {
            jvalue value(jvalue::E_OBJECT);
            value["path"] = bundle.path;
            value["type"] = bundle.type;
            value["bundle_id"] = bundle.bundleId;
            value["display_name"] = bundle.displayName;
            value["version"] = bundle.version;
            value["short_version"] = bundle.shortVersion;
            value["minimum_os_version"] = bundle.minimumOsVersion;
            value["executable"] = bundle.executable;
            value["matched_profile"] = bundle.matchedProfile;
            value["main_bundle"] = bundle.mainBundle;
            value["info_plist_valid"] = bundle.infoPlistValid;
            value["provisioning_profile_present"] = bundle.provisioningProfilePresent;
            root["bundles"].push_back(value);
        }

        root["binaries"] = jvalue(jvalue::E_ARRAY);
        for (const BinaryInfo& binary : report.binaries) {
            jvalue value(jvalue::E_OBJECT);
            value["path"] = binary.path;
            value["owner_bundle_id"] = binary.ownerBundleId;
            value["size_bytes"] = binary.sizeBytes;
            value["main_executable"] = binary.mainExecutable;
            value["signature_present"] = binary.signaturePresent;
            value["encrypted"] = binary.encrypted;
            value["architectures"] = jvalue(jvalue::E_ARRAY);
            for (const MachOSliceInfo& architecture : binary.architectures) {
                value["architectures"].push_back(ArchitectureJson(architecture));
            }
            root["binaries"].push_back(value);
        }

        root["issues"] = jvalue(jvalue::E_ARRAY);
        for (const Issue& issue : report.issues) {
            jvalue value(jvalue::E_OBJECT);
            value["severity"] = SeverityName(issue.severity);
            value["code"] = issue.code;
            value["message"] = issue.message;
            value["path"] = issue.path;
            root["issues"].push_back(value);
        }

        return root.style_write() + "\n";
    }

    std::string ToText(const Report& report) {
        std::ostringstream output;
        output << "OrchardSeal SealCheck preflight audit\n";
        output << "Input:  " << report.inputPath << '\n';
        output << "Type:   " << report.inputType << '\n';
        output << "Status: " << (report.readyForSigning ? "READY" : "BLOCKED") << "\n\n";
        output << "Summary\n";
        output << "  Bundles: " << report.summary.bundleCount << '\n';
        output << "  Mach-O binaries: " << report.summary.binaryCount << '\n';
        output << "  Signature slots present: " << report.summary.signedBinaryCount << '\n';
        output << "  Unsigned/partial: " << report.summary.unsignedBinaryCount << '\n';
        output << "  Encrypted: " << report.summary.encryptedBinaryCount << '\n';
        output << "  Issues: " << report.summary.errorCount << " error(s), " << report.summary.warningCount
               << " warning(s)\n";

        if (!report.bundles.empty()) {
            output << "\nBundles\n";
            for (const BundleInfo& bundle : report.bundles) {
                output << "  " << (bundle.mainBundle ? "* " : "  ") << bundle.path;
                if (!bundle.bundleId.empty()) {
                    output << "  [" << bundle.bundleId << ']';
                }
                output << '\n';
                if (!bundle.executable.empty()) {
                    output << "      executable: " << bundle.executable << '\n';
                }
                if (!bundle.matchedProfile.empty()) {
                    output << "      profile: " << bundle.matchedProfile << '\n';
                }
            }
        }

        if (!report.profiles.empty()) {
            output << "\nProvisioning profiles\n";
            for (const ProvisioningProfileInfo& profile : report.profiles) {
                output << "  " << profile.path;
                if (!profile.name.empty()) {
                    output << "  [" << profile.name << ']';
                }
                output << "\n      app id: " << profile.applicationIdentifier;
                if (!profile.expiration.empty()) {
                    output << "\n      expires: " << profile.expiration;
                }
                output << '\n';
            }
        }

        if (!report.issues.empty()) {
            output << "\nIssues\n";
            for (const Issue& issue : report.issues) {
                output << "  [" << SeverityName(issue.severity) << "] " << issue.code;
                if (!issue.path.empty()) {
                    output << " — " << issue.path;
                }
                output << "\n      " << issue.message << '\n';
            }
        }
        return output.str();
    }

    bool HasBlockingIssues(const Report& report, bool strictWarnings) {
        return report.summary.errorCount > 0 || (strictWarnings && report.summary.warningCount > 0);
    }

} // namespace orchardseal::audit
