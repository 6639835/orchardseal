#include "audit.h"

#include "common.h"
#include "json.h"
#include "macho_file.h"
#include "orchardseal/version.h"
#include "signing_asset.h"
#include "zip_archive.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <system_error>
#include <utility>

namespace orchardseal::audit {
    namespace {

        namespace fs = std::filesystem;

        struct ProfileRecord {
            ProvisioningProfileInfo info;
            fs::path absolutePath;
            std::time_t expirationEpoch = 0;
            std::string parseError;
        };

        struct BundleRecord {
            BundleInfo info;
            fs::path absolutePath;
            fs::path executablePath;
            int embeddedProfileIndex = -1;
        };

        class ScopedDirectory {
          public:
            explicit ScopedDirectory(fs::path path) : path_(std::move(path)) {}

            ~ScopedDirectory() {
                if (!path_.empty()) {
                    FileSystem::RemoveFolder(path_.string().c_str());
                }
            }

            ScopedDirectory(const ScopedDirectory&) = delete;
            ScopedDirectory& operator=(const ScopedDirectory&) = delete;

          private:
            fs::path path_;
        };

        std::string LowerCopy(std::string value) {
            std::transform(value.begin(), value.end(), value.begin(),
                           [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
            return value;
        }

        bool HasExtension(const fs::path& path, const char* extension) {
            return LowerCopy(path.extension().string()) == extension;
        }

        bool IsSignableBundlePath(const fs::path& path) {
            const std::string extension = LowerCopy(path.extension().string());
            return extension == ".app" || extension == ".appex" || extension == ".framework" || extension == ".xctest";
        }

        std::string BundleType(const fs::path& path) {
            const std::string extension = LowerCopy(path.extension().string());
            if (extension == ".app") {
                return "app";
            }
            if (extension == ".appex") {
                return "extension";
            }
            if (extension == ".framework") {
                return "framework";
            }
            if (extension == ".xctest") {
                return "test-bundle";
            }
            return "bundle";
        }

        bool IsProfileRequired(const BundleRecord& bundle, bool adhoc) {
            return !adhoc && (bundle.info.type == "app" || bundle.info.type == "extension");
        }

        std::string FormatUtc(std::time_t value) {
            if (value <= 0) {
                return {};
            }

            std::tm timeParts{};
#ifdef _WIN32
            if (gmtime_s(&timeParts, &value) != 0) {
                return {};
            }
#else
            if (gmtime_r(&value, &timeParts) == nullptr) {
                return {};
            }
#endif

            std::array<char, 32> buffer{};
            if (std::strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%SZ", &timeParts) == 0) {
                return {};
            }
            return buffer.data();
        }

        std::string CurrentUtc() {
            return FormatUtc(std::time(nullptr));
        }

        std::string DisplayPath(const fs::path& root, const fs::path& path) {
            std::error_code error;
            fs::path relative = fs::relative(path, root, error);
            if (!error && !relative.empty() && relative != ".") {
                return relative.generic_string();
            }
            if (path == root && !path.filename().empty()) {
                return path.filename().generic_string();
            }
            return path.generic_string();
        }

        bool IsWithin(const fs::path& child, const fs::path& parent) {
            const fs::path normalizedChild = child.lexically_normal();
            const fs::path normalizedParent = parent.lexically_normal();
            auto childPart = normalizedChild.begin();
            auto parentPart = normalizedParent.begin();
            for (; parentPart != normalizedParent.end(); ++parentPart, ++childPart) {
                if (childPart == normalizedChild.end() || *childPart != *parentPart) {
                    return false;
                }
            }
            return true;
        }

        std::size_t PathDepth(const fs::path& path) {
            return static_cast<std::size_t>(std::distance(path.begin(), path.end()));
        }

        bool IsUnderPayload(const fs::path& path) {
            return std::any_of(path.begin(), path.end(),
                               [](const fs::path& component) { return component == "Payload"; });
        }

        void AddIssue(Report& report, Severity severity, std::string code, std::string message, std::string path = {}) {
            report.issues.push_back(Issue{severity, std::move(code), std::move(message), std::move(path)});
        }

        bool IsMachOMagic(std::uint32_t magic) {
            return magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
                   magic == FAT_MAGIC || magic == FAT_CIGAM;
        }

        bool IsMachOFile(const fs::path& path) {
            std::ifstream input(path, std::ios::binary);
            std::uint32_t magic = 0;
            input.read(reinterpret_cast<char*>(&magic), sizeof(magic));
            return input.gcount() == static_cast<std::streamsize>(sizeof(magic)) && IsMachOMagic(magic);
        }

        std::int64_t CalculateInputSize(const fs::path& input) {
            std::error_code error;
            if (fs::is_regular_file(input, error)) {
                const std::uintmax_t size = fs::file_size(input, error);
                return error ? 0 : static_cast<std::int64_t>(size);
            }
            if (!fs::is_directory(input, error)) {
                return 0;
            }

            std::uintmax_t total = 0;
            fs::recursive_directory_iterator iterator(input, fs::directory_options::skip_permission_denied, error);
            const fs::recursive_directory_iterator end;
            while (!error && iterator != end) {
                if (iterator->is_regular_file(error)) {
                    const std::uintmax_t size = iterator->file_size(error);
                    if (!error) {
                        total += size;
                    }
                }
                iterator.increment(error);
            }
            return static_cast<std::int64_t>(total);
        }

        std::vector<fs::path> FindBundlePaths(const fs::path& root) {
            std::vector<fs::path> bundles;
            if (IsSignableBundlePath(root)) {
                bundles.push_back(root);
            }

            std::error_code error;
            fs::recursive_directory_iterator iterator(root, fs::directory_options::skip_permission_denied, error);
            const fs::recursive_directory_iterator end;
            while (!error && iterator != end) {
                const fs::directory_entry& entry = *iterator;
                if (entry.is_symlink(error)) {
                    if (entry.is_directory(error)) {
                        iterator.disable_recursion_pending();
                    }
                    iterator.increment(error);
                    continue;
                }

                if (entry.is_directory(error)) {
                    const std::string name = entry.path().filename().string();
                    if (name == "__MACOSX" || HasExtension(entry.path(), ".dsym")) {
                        iterator.disable_recursion_pending();
                    } else if (IsSignableBundlePath(entry.path())) {
                        bundles.push_back(entry.path());
                    }
                }
                iterator.increment(error);
            }

            std::sort(bundles.begin(), bundles.end(), [](const fs::path& left, const fs::path& right) {
                const std::size_t leftDepth = PathDepth(left);
                const std::size_t rightDepth = PathDepth(right);
                if (leftDepth != rightDepth) {
                    return leftDepth < rightDepth;
                }
                return left.generic_string() < right.generic_string();
            });
            bundles.erase(std::unique(bundles.begin(), bundles.end()), bundles.end());
            return bundles;
        }

        fs::path FindMainBundle(const std::vector<fs::path>& bundles) {
            fs::path best;
            for (const fs::path& candidate : bundles) {
                if (!HasExtension(candidate, ".app")) {
                    continue;
                }
                if (best.empty()) {
                    best = candidate;
                    continue;
                }
                const bool candidateInPayload = IsUnderPayload(candidate);
                const bool bestInPayload = IsUnderPayload(best);
                if (candidateInPayload != bestInPayload) {
                    if (candidateInPayload) {
                        best = candidate;
                    }
                    continue;
                }
                if (PathDepth(candidate) < PathDepth(best)) {
                    best = candidate;
                }
            }
            return best;
        }

        std::vector<fs::path> FindScanRoots(const fs::path& root, const std::vector<fs::path>& bundles) {
            if (HasExtension(root, ".app") || HasExtension(root, ".appex")) {
                return {root};
            }

            std::vector<fs::path> roots;
            for (const fs::path& candidate : bundles) {
                if (!HasExtension(candidate, ".app")) {
                    continue;
                }
                const bool nestedInOtherApp = std::any_of(bundles.begin(), bundles.end(), [&](const fs::path& other) {
                    return other != candidate && HasExtension(other, ".app") && IsWithin(candidate, other);
                });
                if (!nestedInOtherApp) {
                    roots.push_back(candidate);
                }
            }
            if (roots.empty()) {
                roots.push_back(root);
            }
            return roots;
        }

        void ValidateIpaLayout(const fs::path& root, Report& report) {
            const fs::path payload = root / "Payload";
            std::error_code error;
            if (!fs::is_directory(payload, error)) {
                AddIssue(report, Severity::Error, "IPA_PAYLOAD_MISSING",
                         "The archive does not contain a top-level Payload directory.", "Payload");
                return;
            }

            std::vector<fs::path> mainApps;
            fs::directory_iterator iterator(payload, fs::directory_options::skip_permission_denied, error);
            const fs::directory_iterator end;
            while (!error && iterator != end) {
                const fs::directory_entry& entry = *iterator;
                if (!entry.is_symlink(error) && entry.is_directory(error) && HasExtension(entry.path(), ".app")) {
                    mainApps.push_back(entry.path());
                }
                iterator.increment(error);
            }

            if (error) {
                AddIssue(report, Severity::Error, "IPA_PAYLOAD_UNREADABLE",
                         "The Payload directory could not be enumerated completely.", "Payload");
                return;
            }
            if (mainApps.size() != 1U) {
                AddIssue(report, Severity::Error, "IPA_MAIN_APP_COUNT_INVALID",
                         "An IPA must contain exactly one immediate Payload/*.app bundle; found " +
                             std::to_string(mainApps.size()) + ".",
                         "Payload");
            }
        }

        std::string ProfileKind(const jvalue& profile) {
            if (profile["ProvisionsAllDevices"].as_bool()) {
                return "enterprise";
            }
            if (profile["ProvisionedDevices"].is_array()) {
                return profile["Entitlements"]["get-task-allow"].as_bool() ? "development" : "ad-hoc";
            }
            return "app-store";
        }

        bool ParseProfile(const fs::path& path, bool embedded, ProfileRecord& record, std::string& error) {
            record = ProfileRecord{};
            record.absolutePath = path;
            record.info.path = path.generic_string();
            record.info.embedded = embedded;

            std::string data;
            if (!FileSystem::ReadFile(path.string().c_str(), data)) {
                error = "Unable to read provisioning profile.";
                return false;
            }

            std::string content;
            if (!SigningAsset::GetCMSContent(data, content)) {
                error = "Provisioning profile is not a readable CMS payload.";
                return false;
            }

            jvalue profile;
            if (!profile.read_plist(content)) {
                error = "Provisioning profile payload is not a valid plist.";
                return false;
            }

            record.info.name = profile["Name"].as_cstr();
            record.info.uuid = profile["UUID"].as_cstr();
            record.info.teamName = profile["TeamName"].as_cstr();
            record.info.teamId = profile["TeamIdentifier"][0].as_cstr();
            record.info.applicationIdentifier = profile["Entitlements"]["application-identifier"].as_cstr();
            if (record.info.applicationIdentifier.empty()) {
                record.info.applicationIdentifier =
                    profile["Entitlements"]["com.apple.application-identifier"].as_cstr();
            }
            record.info.kind = ProfileKind(profile);

            if (profile["Platform"].is_array()) {
                for (std::size_t index = 0; index < profile["Platform"].size(); ++index) {
                    record.info.platforms.emplace_back(profile["Platform"][index].as_cstr());
                }
            }

            if (profile["ExpirationDate"].is_date()) {
                record.expirationEpoch = profile["ExpirationDate"].as_date();
                record.info.expiration = FormatUtc(record.expirationEpoch);
                record.info.expired = record.expirationEpoch > 0 && record.expirationEpoch <= std::time(nullptr);
            }

            record.info.valid = !record.info.teamId.empty() && !record.info.applicationIdentifier.empty();
            if (!record.info.valid) {
                error = "Provisioning profile is missing TeamIdentifier or application-identifier.";
            }
            return record.info.valid;
        }

        std::string BundlePattern(const ProvisioningProfileInfo& profile) {
            const std::size_t separator = profile.applicationIdentifier.find('.');
            if (separator == std::string::npos || separator + 1 >= profile.applicationIdentifier.size()) {
                return {};
            }
            return profile.applicationIdentifier.substr(separator + 1);
        }

        int ProfileMatchScore(const ProvisioningProfileInfo& profile, const std::string& bundleId) {
            const std::string pattern = BundlePattern(profile);
            if (pattern.empty() || bundleId.empty()) {
                return -1;
            }
            if (pattern == bundleId) {
                return 100000 + static_cast<int>(pattern.size());
            }
            if (pattern.back() == '*') {
                const std::string prefix = pattern.substr(0, pattern.size() - 1);
                if (bundleId.compare(0, prefix.size(), prefix) == 0) {
                    return static_cast<int>(prefix.size());
                }
            }
            return -1;
        }

        int FindBestProfile(const std::vector<ProfileRecord>& profiles, const std::vector<int>& candidates,
                            const std::string& bundleId) {
            int bestIndex = -1;
            int bestScore = -1;
            for (const int index : candidates) {
                if (index < 0 || static_cast<std::size_t>(index) >= profiles.size()) {
                    continue;
                }
                const ProfileRecord& profile = profiles[static_cast<std::size_t>(index)];
                if (!profile.info.valid || profile.info.expired) {
                    continue;
                }
                const int score = ProfileMatchScore(profile.info, bundleId);
                if (score > bestScore) {
                    bestIndex = index;
                    bestScore = score;
                }
            }
            return bestIndex;
        }

        BundleRecord ParseBundle(const fs::path& root, const fs::path& path, const fs::path& mainBundle,
                                 Report& report) {
            BundleRecord record;
            record.absolutePath = path;
            record.info.path = DisplayPath(root, path);
            record.info.type = BundleType(path);
            record.info.mainBundle = path == mainBundle;

            const fs::path infoPath = path / "Info.plist";
            jvalue info;
            if (!info.read_plist_from_file("%s", infoPath.string().c_str())) {
                AddIssue(report, Severity::Error, "INFO_PLIST_INVALID", "Info.plist is missing or unreadable.",
                         record.info.path);
                return record;
            }

            record.info.infoPlistValid = true;
            record.info.bundleId = info["CFBundleIdentifier"].as_cstr();
            record.info.displayName = info["CFBundleDisplayName"].as_cstr();
            if (record.info.displayName.empty()) {
                record.info.displayName = info["CFBundleName"].as_cstr();
            }
            record.info.version = info["CFBundleVersion"].as_cstr();
            record.info.shortVersion = info["CFBundleShortVersionString"].as_cstr();
            record.info.minimumOsVersion = info["MinimumOSVersion"].as_cstr();
            const std::string executableName = info["CFBundleExecutable"].as_cstr();

            if (record.info.bundleId.empty()) {
                AddIssue(report, Severity::Error, "BUNDLE_ID_MISSING", "CFBundleIdentifier is missing.",
                         record.info.path);
            }
            if (record.info.version.empty()) {
                AddIssue(report, Severity::Warning, "BUNDLE_VERSION_MISSING", "CFBundleVersion is missing.",
                         record.info.path);
            }
            if (executableName.empty()) {
                AddIssue(report, Severity::Error, "BUNDLE_EXECUTABLE_MISSING", "CFBundleExecutable is missing.",
                         record.info.path);
            } else {
                record.executablePath = path / executableName;
                record.info.executable = DisplayPath(root, record.executablePath);
                std::error_code fsError;
                if (!fs::is_regular_file(record.executablePath, fsError)) {
                    AddIssue(report, Severity::Error, "BUNDLE_EXECUTABLE_NOT_FOUND",
                             "The executable declared by CFBundleExecutable does not exist.", record.info.executable);
                } else if (!IsMachOFile(record.executablePath)) {
                    AddIssue(report, Severity::Error, "BUNDLE_EXECUTABLE_NOT_MACHO",
                             "The file declared by CFBundleExecutable is not a Mach-O binary.", record.info.executable);
                }
            }

            const fs::path embeddedProfile = path / "embedded.mobileprovision";
            std::error_code fsError;
            record.info.provisioningProfilePresent = fs::is_regular_file(embeddedProfile, fsError);
            return record;
        }

        void ValidateBundleIdentifiers(const std::vector<BundleRecord>& bundles, Report& report) {
            std::map<std::string, std::string> firstPathByIdentifier;
            for (const BundleRecord& bundle : bundles) {
                if (bundle.info.bundleId.empty()) {
                    continue;
                }
                const auto [iterator, inserted] = firstPathByIdentifier.emplace(bundle.info.bundleId, bundle.info.path);
                if (!inserted) {
                    AddIssue(report, Severity::Error, "BUNDLE_ID_DUPLICATE",
                             "Bundle identifier '" + bundle.info.bundleId + "' is also used by " + iterator->second +
                                 ".",
                             bundle.info.path);
                }
            }
        }

        std::string OwnerBundleId(const fs::path& binary, const std::vector<BundleRecord>& bundles) {
            const BundleRecord* best = nullptr;
            for (const BundleRecord& bundle : bundles) {
                if (!IsWithin(binary, bundle.absolutePath)) {
                    continue;
                }
                if (best == nullptr || PathDepth(bundle.absolutePath) > PathDepth(best->absolutePath)) {
                    best = &bundle;
                }
            }
            return best == nullptr ? std::string() : best->info.bundleId;
        }

        bool IsMainExecutable(const fs::path& binary, const std::vector<BundleRecord>& bundles) {
            return std::any_of(bundles.begin(), bundles.end(), [&](const BundleRecord& bundle) {
                return !bundle.executablePath.empty() &&
                       binary.lexically_normal() == bundle.executablePath.lexically_normal();
            });
        }

        bool AuditBinary(const fs::path& root, const fs::path& path, const std::vector<BundleRecord>& bundles,
                         bool checkArm64, Report& report) {
            const std::string displayPath = DisplayPath(root, path);
            MachOFile macho;
            const int previousLogLevel = Logger::GetLogLevel();
            Logger::SetLogLevel(Logger::E_NONE);
            const bool initialized = macho.InitReadOnly(path.string().c_str());
            Logger::SetLogLevel(previousLogLevel);
            if (!initialized) {
                AddIssue(report, Severity::Error, "MACHO_INVALID", "Mach-O headers could not be parsed.", displayPath);
                return false;
            }

            BinaryInfo binary;
            binary.path = displayPath;
            binary.ownerBundleId = OwnerBundleId(path, bundles);
            binary.mainExecutable = IsMainExecutable(path, bundles);
            binary.sizeBytes = FileSystem::GetFileSize(path.string().c_str());
            binary.architectures = macho.GetArchitectureInfo();
            binary.signaturePresent = !binary.architectures.empty() &&
                                      std::all_of(binary.architectures.begin(), binary.architectures.end(),
                                                  [](const MachOSliceInfo& item) { return item.signaturePresent; });
            const bool anySignature = std::any_of(binary.architectures.begin(), binary.architectures.end(),
                                                  [](const MachOSliceInfo& item) { return item.signaturePresent; });
            binary.encrypted = std::any_of(binary.architectures.begin(), binary.architectures.end(),
                                           [](const MachOSliceInfo& item) { return item.encrypted; });

            if (!binary.signaturePresent) {
                AddIssue(report, Severity::Warning, anySignature ? "BINARY_PARTIALLY_SIGNED" : "BINARY_UNSIGNED",
                         anySignature ? "Only some architectures contain a code-signature slot."
                                      : "No code-signature slot is present; signing will create one.",
                         displayPath);
            }
            if (binary.encrypted) {
                AddIssue(report, Severity::Error, "BINARY_ENCRYPTED",
                         "The binary contains an active encryption command and must be decrypted before re-signing.",
                         displayPath);
            }

            if (binary.mainExecutable) {
                const bool allSlicesExecutable =
                    !binary.architectures.empty() &&
                    std::all_of(binary.architectures.begin(), binary.architectures.end(),
                                [](const MachOSliceInfo& item) { return item.executable; });
                if (!allSlicesExecutable) {
                    AddIssue(
                        report, Severity::Error, "MAIN_BINARY_TYPE_INVALID",
                        "The bundle's main binary must use the MH_EXECUTE Mach-O file type for every architecture.",
                        displayPath);
                }
            }

            if (checkArm64 && binary.mainExecutable) {
                const bool hasArm64 = std::any_of(
                    binary.architectures.begin(), binary.architectures.end(), [](const MachOSliceInfo& item) {
                        return item.architecture == "arm64" || item.architecture == "arm64e" ||
                               item.architecture == "arm64v8";
                    });
                if (!hasArm64) {
                    AddIssue(report, Severity::Warning, "MAIN_BINARY_ARM64_MISSING",
                             "The main executable does not contain an arm64-family architecture.", displayPath);
                }
            }

            report.binaries.push_back(std::move(binary));
            return true;
        }

        void ScanMachOBinaries(const fs::path& root, const std::vector<fs::path>& scanRoots,
                               const std::vector<BundleRecord>& bundles, Report& report) {
            std::set<std::string> visited;
            for (const fs::path& scanRoot : scanRoots) {
                std::error_code error;
                fs::recursive_directory_iterator iterator(scanRoot, fs::directory_options::skip_permission_denied,
                                                          error);
                const fs::recursive_directory_iterator end;
                while (!error && iterator != end) {
                    const fs::directory_entry& entry = *iterator;
                    if (entry.is_symlink(error)) {
                        if (entry.is_directory(error)) {
                            iterator.disable_recursion_pending();
                        }
                        iterator.increment(error);
                        continue;
                    }
                    if (entry.is_directory(error)) {
                        const std::string name = entry.path().filename().string();
                        if (name == "__MACOSX" || HasExtension(entry.path(), ".dsym")) {
                            iterator.disable_recursion_pending();
                        }
                    } else if (entry.is_regular_file(error) && IsMachOFile(entry.path())) {
                        const std::string normalized = entry.path().lexically_normal().generic_string();
                        if (visited.insert(normalized).second) {
                            AuditBinary(root, entry.path(), bundles, true, report);
                        }
                    }
                    iterator.increment(error);
                }
            }
        }

        void AddProfileIssues(const std::vector<ProfileRecord>& profiles, Report& report) {
            for (const ProfileRecord& profile : profiles) {
                if (!profile.info.valid) {
                    AddIssue(report, Severity::Error, "PROFILE_INVALID",
                             profile.parseError.empty()
                                 ? "Provisioning profile is malformed or lacks required identifiers."
                                 : profile.parseError,
                             profile.info.path);
                } else if (profile.info.expired) {
                    AddIssue(report, Severity::Error, "PROFILE_EXPIRED",
                             "Provisioning profile expired at " + profile.info.expiration + ".", profile.info.path);
                }
            }
        }

        void MatchProfiles(const Request& request, std::vector<ProfileRecord>& profiles,
                           const std::vector<int>& externalProfiles, std::vector<BundleRecord>& bundles,
                           Report& report) {
            for (BundleRecord& bundle : bundles) {
                if (!IsProfileRequired(bundle, request.adhoc)) {
                    continue;
                }

                std::vector<int> candidates = externalProfiles;
                if (candidates.empty() && bundle.embeddedProfileIndex >= 0) {
                    candidates.push_back(bundle.embeddedProfileIndex);
                }

                if (candidates.empty()) {
                    AddIssue(report, Severity::Warning, "PROFILE_NOT_PROVIDED",
                             "No provisioning profile is available for compatibility checks.", bundle.info.path);
                    continue;
                }

                const int profileIndex = FindBestProfile(profiles, candidates, bundle.info.bundleId);
                if (profileIndex < 0) {
                    AddIssue(report, Severity::Error, "PROFILE_BUNDLE_ID_MISMATCH",
                             "No valid provisioning profile matches bundle identifier '" + bundle.info.bundleId + "'.",
                             bundle.info.path);
                    continue;
                }

                const ProfileRecord& profile = profiles[static_cast<std::size_t>(profileIndex)];
                bundle.info.matchedProfile = profile.info.uuid.empty() ? profile.info.path : profile.info.uuid;
                if (!profile.info.teamId.empty() && !bundle.info.bundleId.empty()) {
                    const std::string pattern = BundlePattern(profile.info);
                    if (pattern.empty()) {
                        AddIssue(report, Severity::Error, "PROFILE_APPLICATION_ID_INVALID",
                                 "The matched provisioning profile has an invalid application identifier.",
                                 profile.info.path);
                    }
                }
            }
        }

        void ValidateSigningAssets(const Request& request, const std::vector<ProfileRecord>& profiles,
                                   const std::vector<int>& externalProfiles, const std::vector<BundleRecord>& bundles,
                                   Report& report) {
            if (request.privateKeyFile.empty() && request.certificateFile.empty()) {
                return;
            }

            report.signingAsset.requested = true;
            if (request.privateKeyFile.empty()) {
                AddIssue(report, Severity::Error, "PRIVATE_KEY_MISSING",
                         "A certificate was supplied without a private key or PKCS#12 file.", request.certificateFile);
                return;
            }
            if (!FileSystem::IsFileExists(request.privateKeyFile.c_str())) {
                AddIssue(report, Severity::Error, "PRIVATE_KEY_NOT_FOUND", "Private key or PKCS#12 file was not found.",
                         request.privateKeyFile);
                return;
            }
            if (!request.certificateFile.empty() && !FileSystem::IsFileExists(request.certificateFile.c_str())) {
                AddIssue(report, Severity::Error, "CERTIFICATE_NOT_FOUND", "Certificate file was not found.",
                         request.certificateFile);
                return;
            }

            std::vector<std::string> profilePaths;
            for (const int index : externalProfiles) {
                if (index >= 0 && static_cast<std::size_t>(index) < profiles.size()) {
                    profilePaths.push_back(profiles[static_cast<std::size_t>(index)].absolutePath.string());
                }
            }
            if (profilePaths.empty()) {
                for (const BundleRecord& bundle : bundles) {
                    if (bundle.embeddedProfileIndex >= 0) {
                        const ProfileRecord& profile = profiles[static_cast<std::size_t>(bundle.embeddedProfileIndex)];
                        profilePaths.push_back(profile.absolutePath.string());
                    }
                }
            }
            std::sort(profilePaths.begin(), profilePaths.end());
            profilePaths.erase(std::unique(profilePaths.begin(), profilePaths.end()), profilePaths.end());

            if (!request.adhoc && profilePaths.empty()) {
                AddIssue(report, Severity::Error, "SIGNING_PROFILE_REQUIRED",
                         "Signing assets cannot be validated without a provisioning profile.", request.privateKeyFile);
                return;
            }
            if (request.adhoc) {
                profilePaths.emplace_back();
            }

            bool allValid = true;
            for (const std::string& profilePath : profilePaths) {
                SigningAsset signingAsset;
                const int previousLogLevel = Logger::GetLogLevel();
                Logger::SetLogLevel(Logger::E_NONE);
                const bool valid = signingAsset.Init(request.certificateFile, request.privateKeyFile, profilePath,
                                                     request.entitlementsFile, request.password, request.adhoc,
                                                     request.sha256Only, bundles.empty());
                Logger::SetLogLevel(previousLogLevel);
                if (!valid) {
                    allValid = false;
                    AddIssue(report, Severity::Error, "SIGNING_ASSET_INVALID",
                             "The private key, certificate, password, and provisioning profile could not be validated "
                             "as a compatible set.",
                             profilePath.empty() ? request.privateKeyFile : profilePath);
                    continue;
                }

                if (report.signingAsset.certificateSubject.empty()) {
                    report.signingAsset.certificateSubject = signingAsset.SubjectCommonName();
                    report.signingAsset.teamId = signingAsset.TeamId();
                    report.signingAsset.applicationIdentifier = signingAsset.ApplicationIdentifier();
                }
            }
            report.signingAsset.valid = allValid;
        }

        void FinalizeReport(Report& report) {
            std::sort(report.issues.begin(), report.issues.end(), [](const Issue& left, const Issue& right) {
                if (left.severity != right.severity) {
                    return static_cast<int>(left.severity) > static_cast<int>(right.severity);
                }
                if (left.path != right.path) {
                    return left.path < right.path;
                }
                return left.code < right.code;
            });

            report.summary.bundleCount = static_cast<std::int64_t>(report.bundles.size());
            report.summary.binaryCount = static_cast<std::int64_t>(report.binaries.size());
            for (const BinaryInfo& binary : report.binaries) {
                if (binary.signaturePresent) {
                    ++report.summary.signedBinaryCount;
                } else {
                    ++report.summary.unsignedBinaryCount;
                }
                if (binary.encrypted) {
                    ++report.summary.encryptedBinaryCount;
                }
            }
            for (const Issue& issue : report.issues) {
                switch (issue.severity) {
                case Severity::Info:
                    ++report.summary.infoCount;
                    break;
                case Severity::Warning:
                    ++report.summary.warningCount;
                    break;
                case Severity::Error:
                    ++report.summary.errorCount;
                    break;
                }
            }
            report.readyForSigning = report.summary.errorCount == 0;
        }

    } // namespace

    bool Service::Run(const Request& request, Report& report, std::string& error) const {
        report = Report{};
        report.productVersion = ORCHARDSEAL_VERSION_STRING;
        report.generatedAt = CurrentUtc();
        report.inputPath = request.inputPath;

        if (request.inputPath.empty()) {
            error = "Input path is empty.";
            return false;
        }

        const fs::path input = fs::path(request.inputPath).lexically_normal();
        std::error_code fsError;
        if (!fs::exists(input, fsError)) {
            error = "Input path does not exist.";
            return false;
        }
        report.inputSizeBytes = CalculateInputSize(input);

        std::vector<ProfileRecord> profiles;
        std::vector<int> externalProfileIndexes;
        for (const std::string& profilePath : request.provisioningFiles) {
            ProfileRecord profile;
            std::string profileError;
            const bool parsed = ParseProfile(fs::path(profilePath), false, profile, profileError);
            const int index = static_cast<int>(profiles.size());
            if (!parsed) {
                profile.parseError = profileError;
            }
            profiles.push_back(std::move(profile));
            externalProfileIndexes.push_back(index);
        }

        fs::path auditRoot = input;
        fs::path temporaryDirectory;
        if (FileSystem::IsZipFile(input.string().c_str())) {
            report.inputType = "ipa-archive";
            temporaryDirectory =
                fs::path(request.tempDirectory) / ("orchardseal_audit_" + std::to_string(Utility::GetMicroSecond()));
            if (!ZipArchive::Extract(input.string().c_str(), temporaryDirectory.string().c_str())) {
                error = "Archive extraction failed. The archive may be corrupt or contain unsafe paths.";
                return false;
            }
            auditRoot = temporaryDirectory;
        } else if (fs::is_directory(input, fsError)) {
            report.inputType = HasExtension(input, ".app") ? "app-bundle" : "directory";
        } else if (fs::is_regular_file(input, fsError) && IsMachOFile(input)) {
            report.inputType = "mach-o";
        } else {
            error = "Input is not a Mach-O file, app bundle, directory, or IPA archive.";
            return false;
        }

        ScopedDirectory temporaryCleanup(temporaryDirectory);
        std::vector<BundleRecord> bundleRecords;

        if (report.inputType == "mach-o") {
            AuditBinary(input.parent_path(), input, bundleRecords, false, report);
        } else {
            const std::vector<fs::path> bundlePaths = FindBundlePaths(auditRoot);
            if (report.inputType == "ipa-archive") {
                ValidateIpaLayout(auditRoot, report);
            }
            const fs::path mainBundle = FindMainBundle(bundlePaths);
            for (const fs::path& bundlePath : bundlePaths) {
                bundleRecords.push_back(ParseBundle(auditRoot, bundlePath, mainBundle, report));
            }

            ValidateBundleIdentifiers(bundleRecords, report);

            for (BundleRecord& bundle : bundleRecords) {
                const fs::path embeddedPath = bundle.absolutePath / "embedded.mobileprovision";
                if (!bundle.info.provisioningProfilePresent) {
                    continue;
                }
                ProfileRecord profile;
                std::string profileError;
                const bool parsed = ParseProfile(embeddedPath, true, profile, profileError);
                profile.info.path = DisplayPath(auditRoot, embeddedPath);
                profile.absolutePath = embeddedPath;
                if (!parsed) {
                    profile.parseError = profileError;
                }
                bundle.embeddedProfileIndex = static_cast<int>(profiles.size());
                profiles.push_back(std::move(profile));
            }

            if (bundleRecords.empty()) {
                AddIssue(report, Severity::Warning, "APP_BUNDLE_NOT_FOUND",
                         "No .app, .appex, .framework, or .xctest bundle was found; scanning the directory for Mach-O "
                         "files.",
                         DisplayPath(auditRoot, auditRoot));
            }

            const std::vector<fs::path> scanRoots = FindScanRoots(auditRoot, bundlePaths);
            ScanMachOBinaries(auditRoot, scanRoots, bundleRecords, report);
            if (report.binaries.empty()) {
                AddIssue(report, Severity::Error, "NO_SIGNABLE_BINARIES", "No Mach-O binaries were found.",
                         DisplayPath(auditRoot, auditRoot));
            }

            MatchProfiles(request, profiles, externalProfileIndexes, bundleRecords, report);
            for (const BundleRecord& bundle : bundleRecords) {
                report.bundles.push_back(bundle.info);
            }
        }

        AddProfileIssues(profiles, report);
        for (const ProfileRecord& profile : profiles) {
            report.profiles.push_back(profile.info);
        }
        ValidateSigningAssets(request, profiles, externalProfileIndexes, bundleRecords, report);
        FinalizeReport(report);
        return true;
    }

} // namespace orchardseal::audit
