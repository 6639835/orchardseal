#include "application.h"

#include "app_bundle.h"
#include "audit.h"
#include "zip_archive.h"
#include "certificate_check.h"
#include "common.h"
#include "macho_file.h"
#include "metadata.h"
#include "signing_asset.h"
#include "stopwatch.h"

#include <cstdio>
#include <filesystem>
#include <limits>
#include <list>
#include <set>
#include <utility>

namespace orchardseal::cli {
    namespace {

        std::string FirstProvisionFile(const Options& options) {
            return options.provisionFiles.empty() ? std::string() : options.provisionFiles.front();
        }

        std::set<std::string> NormalizeDylibRemovalNames(const std::vector<std::string>& names) {
            std::set<std::string> normalized;
            for (const std::string& name : names) {
                if (name.find('/') != std::string::npos) {
                    normalized.insert(name);
                } else {
                    normalized.insert("@executable_path/" + name);
                }
            }
            return normalized;
        }

    } // namespace

    Application::Application(Options options) : options_(std::move(options)) {}

    int Application::Run() {
        if (!ValidateEnvironment()) {
            return 1;
        }

        if (Logger::IsDebug()) {
            FileSystem::CreateFolder("./.orchardseal_debug");
            for (const std::string& argument : options_.rawArguments) {
                Logger::DebugV(">>> Argument:\t%s\n", argument.c_str());
            }
        }

        if (options_.audit) {
            return RunAudit();
        }

        const int certificateCheckResult = RunCertificateCheckIfRequested();
        if (certificateCheckResult != std::numeric_limits<int>::min()) {
            return certificateCheckResult;
        }

        const bool isZipFile = FileSystem::IsZipFile(options_.targetPath.c_str());
        if (!isZipFile && !FileSystem::IsFolder(options_.targetPath.c_str())) {
            return ProcessSingleMachO();
        }

        return ProcessBundleOrArchive();
    }

    bool Application::ValidateEnvironment() const {
        if (!FileSystem::IsFolder(options_.tempFolder.c_str())) {
            Logger::ErrorV(">>> Invalid temp folder! %s\n", options_.tempFolder.c_str());
            return false;
        }

        if (!FileSystem::IsFileExists(options_.targetPath.c_str())) {
            Logger::ErrorV(">>> Invalid path! %s\n", options_.targetPath.c_str());
            return false;
        }

        if (options_.zipLevel < 0 || options_.zipLevel > 9) {
            Logger::Error(">>> Invalid zip level! Please input 0 - 9.\n");
            return false;
        }

        for (const std::string& dylibFile : options_.dylibFiles) {
            if (CommandLineOptions::IsDylibLoadCommandName(dylibFile)) {
                continue;
            }

            if (!FileSystem::IsFileExists(dylibFile.c_str())) {
                Logger::ErrorV(">>> Dylib file not found! %s\n", dylibFile.c_str());
                return false;
            }

            MachOFile dylibMachO;
            if (!dylibMachO.Init(dylibFile.c_str())) {
                Logger::ErrorV(">>> Invalid dylib file! Not a valid Mach-O format. %s\n", dylibFile.c_str());
                return false;
            }
        }

        if (!options_.iconFile.empty() && !FileSystem::IsFileExists(options_.iconFile.c_str())) {
            Logger::ErrorV(">>> Icon file not found! %s\n", options_.iconFile.c_str());
            return false;
        }

        return true;
    }

    int Application::RunCertificateCheckIfRequested() const {
        if (options_.checkSignature && options_.privateKeyFile.empty() && options_.provisionFiles.empty()) {
            const int result = CheckCertificate(options_.targetPath, options_.password);
            return result == 0 ? 0 : 1;
        }

        return std::numeric_limits<int>::min();
    }

    int Application::RunAudit() const {
        audit::Request request;
        request.inputPath = options_.targetPath;
        request.tempDirectory = options_.tempFolder;
        request.certificateFile = options_.certificateFile;
        request.privateKeyFile = options_.privateKeyFile;
        request.provisioningFiles = options_.provisionFiles;
        request.password = options_.password;
        request.entitlementsFile = options_.entitlementsFile;
        request.adhoc = options_.adhoc;
        request.sha256Only = options_.sha256Only;

        audit::Report report;
        std::string error;
        if (!audit::Service().Run(request, report, error)) {
            Logger::ErrorV(">>> Audit failed: %s\n", error.c_str());
            return 1;
        }

        const std::string jsonReport = audit::ToJson(report);
        if (!options_.auditReportFile.empty()) {
            const std::filesystem::path reportPath = std::filesystem::u8path(options_.auditReportFile);
            const std::filesystem::path parent = reportPath.parent_path();
            if (!parent.empty() && !FileSystem::CreateFolder(parent.u8string().c_str())) {
                Logger::ErrorV(">>> Could not create audit report directory: %s\n", parent.u8string().c_str());
                return 1;
            }
            if (!FileSystem::WriteFile(options_.auditReportFile.c_str(), jsonReport)) {
                Logger::ErrorV(">>> Could not write audit report: %s\n", options_.auditReportFile.c_str());
                return 1;
            }
        }

        const std::string standardOutput =
            options_.auditFormat == AuditFormat::Json ? jsonReport : audit::ToText(report);
        if (!standardOutput.empty()) {
            Logger::Report(standardOutput.c_str());
        }

        return audit::HasBlockingIssues(report, options_.strictAudit) ? 3 : 0;
    }

    bool Application::CreateSignAsset(SigningAsset& asset, bool singleBinary, const std::string& provisionFile) const {
        return asset.Init(options_.certificateFile, options_.privateKeyFile, provisionFile, options_.entitlementsFile,
                          options_.password, options_.adhoc, options_.sha256Only, singleBinary);
    }

    int Application::ProcessSingleMachO() {
        const bool shouldOnlyPrintInfo = !options_.adhoc && options_.dylibFiles.empty() &&
                                         options_.removeDylibNames.empty() &&
                                         (options_.privateKeyFile.empty() || options_.provisionFiles.empty());

        MachOFile macho;
        const bool initialized = shouldOnlyPrintInfo ? macho.InitReadOnly(options_.targetPath.c_str())
                                                     : macho.Init(options_.targetPath.c_str());
        if (!initialized) {
            Logger::ErrorV(">>> Invalid Mach-O file! %s\n", options_.targetPath.c_str());
            return 1;
        }

        if (shouldOnlyPrintInfo) {
            macho.PrintInfo();
            return 0;
        }

        SigningAsset signAsset;
        if (!CreateSignAsset(signAsset, true, FirstProvisionFile(options_))) {
            return 1;
        }

        for (const std::string& dylibFile : options_.dylibFiles) {
            if (!macho.InjectDylib(options_.weakInject, dylibFile.c_str())) {
                return 1;
            }
        }

        if (!options_.removeDylibNames.empty()) {
            if (!macho.RemoveDylibs(NormalizeDylibRemovalNames(options_.removeDylibNames))) {
                return 1;
            }
        }

        Stopwatch timer;
        timer.Reset();
        Logger::PrintV(">>> Signing:\t%s %s\n", options_.targetPath.c_str(), options_.adhoc ? " (Ad-hoc)" : "");

        std::string infoSha1;
        std::string infoSha256;
        std::string codeResourcesData;
        bool signedOk =
            macho.Sign(&signAsset, options_.force, options_.bundleId, infoSha1, infoSha256, codeResourcesData);
        timer.PrintResult(signedOk, ">>> Signed %s!", signedOk ? "OK" : "Failed");
        if (signedOk && options_.checkSignature && CheckCertificate(options_.targetPath, "") != 0) {
            Logger::Error(">>> Post-sign verification failed.\n");
            signedOk = false;
        }
        return signedOk ? 0 : 1;
    }

    int Application::ProcessBundleOrArchive() {
        Stopwatch actionTimer;
        Stopwatch globalTimer;

        const bool inputIsZipFile = FileSystem::IsZipFile(options_.targetPath.c_str());
        bool tempOutputFile = false;
        bool tempFolder = false;
        bool enableCache = true;
        bool force = options_.force;
        std::string outputFile = options_.outputFile;
        std::string workingFolder = options_.targetPath;

        if (outputFile.empty()) {
            if (options_.install) {
                tempOutputFile = true;
                outputFile = FileSystem::GetRealPathV("%s/orchardseal_temp_%llu.ipa", options_.tempFolder.c_str(),
                                                      Utility::GetMicroSecond());
            } else if (inputIsZipFile) {
                Logger::Error(">>> Use -o option to specify the output file.\n");
                return 1;
            }
        }

        SigningAsset signAsset;
        if (!CreateSignAsset(signAsset, false, FirstProvisionFile(options_))) {
            return 1;
        }

        if (inputIsZipFile) {
            force = true;
            tempFolder = true;
            enableCache = false;
            workingFolder = FileSystem::GetRealPathV("%s/orchardseal_folder_%llu", options_.tempFolder.c_str(),
                                                     actionTimer.Reset());
            Logger::PrintV(">>> Unzip:\t%s (%s) -> %s ... \n", options_.targetPath.c_str(),
                           FileSystem::GetFileSizeString(options_.targetPath.c_str()).c_str(), workingFolder.c_str());
            if (!ZipArchive::Extract(options_.targetPath.c_str(), workingFolder.c_str())) {
                Logger::Error(">>> Unzip failed!\n");
                return 1;
            }
            actionTimer.PrintResult(true, ">>> Unzip OK!");
        }

        actionTimer.Reset();
        AppBundle bundle;
        bundle.SetEnableDocuments(options_.enableDocuments);
        bundle.SetMinimumVersion(options_.minimumVersion);
        bundle.SetRemoveExtensions(options_.removeExtensions);
        bundle.SetRemoveWatchApp(options_.removeWatchApp);
        bundle.SetRemoveUiSupportedDevices(options_.removeUISupportedDevices);
        bundle.SetIconFile(options_.iconFile);
        bundle.SetDylibInjectScope(options_.dylibInjectScope);

        bool signedOk = false;
        if (options_.provisionFiles.size() > 1) {
            std::list<SigningAsset> signAssets;
            for (const std::string& provisionFile : options_.provisionFiles) {
                signAssets.emplace_back();
                if (!CreateSignAsset(signAssets.back(), false, provisionFile)) {
                    Logger::ErrorV(">>> Failed to init provision: %s\n", provisionFile.c_str());
                    signAssets.pop_back();
                }
            }
            signedOk = bundle.SignFolder(&signAssets, workingFolder, options_.bundleId, options_.bundleVersion,
                                         options_.displayName, options_.dylibFiles, options_.removeDylibNames, force,
                                         options_.weakInject, enableCache, options_.removeProvision);
        } else {
            signedOk = bundle.SignFolder(&signAsset, workingFolder, options_.bundleId, options_.bundleVersion,
                                         options_.displayName, options_.dylibFiles, options_.removeDylibNames, force,
                                         options_.weakInject, enableCache, options_.removeProvision);
        }
        actionTimer.PrintResult(signedOk, ">>> Signed %s!", signedOk ? "OK" : "Failed");

        if (signedOk && options_.checkSignature && !bundle.AppFolder().empty()) {
            if (CheckSignedBinary(bundle.AppFolder()) != 0) {
                Logger::Error(">>> Post-sign verification failed.\n");
                signedOk = false;
            }
        }

        if (signedOk && !outputFile.empty()) {
            const size_t payloadPosition = bundle.AppFolder().rfind("Payload");
            if (payloadPosition != std::string::npos && payloadPosition > 0) {
                actionTimer.Reset();
                Logger::PrintV(">>> Archiving: \t%s ... \n", outputFile.c_str());
                const std::string baseFolder = bundle.AppFolder().substr(0, payloadPosition - 1);
                if (!ZipArchive::Archive(baseFolder.c_str(), outputFile.c_str(),
                                         static_cast<std::uint32_t>(options_.zipLevel))) {
                    Logger::Error(">>> Archive failed!\n");
                    signedOk = false;
                } else {
                    actionTimer.PrintResult(true, ">>> Archive OK! (%s)",
                                            FileSystem::GetFileSizeString(outputFile.c_str()).c_str());
                    if (!options_.metadataDirectory.empty()) {
                        if (!FileSystem::CreateFolder(options_.metadataDirectory.c_str()) ||
                            !GetMetadata(bundle.AppFolder(), options_.metadataDirectory, outputFile)) {
                            Logger::Error(">>> Metadata extraction failed.\n");
                            signedOk = false;
                        }
                    }
                }
            } else {
                Logger::Error(">>> Can't find payload directory!\n");
                signedOk = false;
            }
        }

        if (signedOk && options_.install) {
            signedOk = Utility::SystemExec({"ideviceinstaller", "install", outputFile});
            if (!signedOk) {
                Logger::Error(
                    ">>> Installation failed. Ensure ideviceinstaller is available and the device is ready.\n");
            }
        }

        if (tempFolder) {
            FileSystem::RemoveFolder(workingFolder.c_str());
        }

        if (tempOutputFile) {
            FileSystem::RemoveFile(outputFile.c_str());
        }

        globalTimer.Print(">>> Done.");
        return signedOk ? 0 : 1;
    }

} // namespace orchardseal::cli
