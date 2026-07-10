#pragma once
#include "common.h"
#include "json.h"
#include "signing_asset.h"
#include <vector>
#include <list>
#include <set>

class MachOFile;

enum DylibInjectionScope
{
	DYLIB_INJECT_ROOT = 1 << 0,
	DYLIB_INJECT_EXTENSIONS = 1 << 1,
	DYLIB_INJECT_FRAMEWORKS = 1 << 2,
	DYLIB_INJECT_FILES = 1 << 3,
	DYLIB_INJECT_ALL = DYLIB_INJECT_ROOT | DYLIB_INJECT_EXTENSIONS | DYLIB_INJECT_FRAMEWORKS | DYLIB_INJECT_FILES
};

class AppBundle {
public:
    AppBundle() = default;

    void SetDylibInjectScope(std::uint32_t scope) noexcept { dylibInjectionScope_ = scope; }
    void SetEnableDocuments(bool enabled) noexcept { enableDocuments_ = enabled; }
    void SetMinimumVersion(const string& version) { minimumVersion_ = version; }
    void SetRemoveExtensions(bool remove) noexcept { removeExtensions_ = remove; }
    void SetRemoveWatchApp(bool remove) noexcept { removeWatchApp_ = remove; }
    void SetRemoveUiSupportedDevices(bool remove) noexcept { removeUiSupportedDevices_ = remove; }
    void SetIconFile(const string& path) { iconFile_ = path; }

    [[nodiscard]] const string& AppFolder() const noexcept { return appFolder_; }

    bool SignFolder(SigningAsset* signingAsset,
                    const string& folder,
                    const string& bundleId,
                    const string& bundleVersion,
                    const string& displayName,
                    const vector<string>& dylibFiles,
                    const vector<string>& dylibsToRemove,
                    bool force,
                    bool weakInject,
                    bool enableCache,
                    bool removeProvision = false);

    bool SignFolder(list<SigningAsset>* signingAssets,
                    const string& folder,
                    const string& bundleId,
                    const string& bundleVersion,
                    const string& displayName,
                    const vector<string>& dylibFiles,
                    const vector<string>& dylibsToRemove,
                    bool force,
                    bool weakInject,
                    bool enableCache,
                    bool removeProvision = false);

private:
    bool SignNode(jvalue& node);
    void GetNodeChangedFiles(jvalue& node);
    void GetChangedFiles(jvalue& node, vector<string>& changedFiles);
    bool ModifyPluginsBundleId(const string& oldBundleId, const string& newBundleId);
    bool ModifyBundleInfo(const string& bundleId, const string& bundleVersion, const string& displayName);
    bool ReplaceBundleIcons(const string& iconFile);
    bool ShouldInjectDylibsIntoNode(jvalue& node);
    bool InjectDylibsIntoTarget(MachOFile& macho,
                                const string& targetFolder,
                                bool useLoaderPath,
                                vector<string>& copiedDylibs);
    bool SignCopiedDylibs(const vector<string>& copiedDylibs);

    bool FindAppFolder(const string& folder, string& appFolder);
    bool GetObjectsToSign(const string& folder, jvalue& info);
    bool GetSignFolderInfo(const string& folder, jvalue& node, bool getName = false);
    bool GenerateCodeResources(const string& folder, jvalue& codeResources);
    void ApplyAppModifications();

    bool forceSign_ = false;
    bool weakInject_ = false;
    bool removeProvision_ = false;
    std::uint32_t dylibInjectionScope_ = DYLIB_INJECT_ROOT;
    SigningAsset* signingAsset_ = nullptr;
    list<SigningAsset>* signingAssets_ = nullptr;
    vector<string> injectionDylibs_;
    set<string> dylibsToRemove_;

    bool enableDocuments_ = false;
    string minimumVersion_;
    bool removeExtensions_ = false;
    bool removeWatchApp_ = false;
    bool removeUiSupportedDevices_ = false;
    string iconFile_;
    string appFolder_;
};
