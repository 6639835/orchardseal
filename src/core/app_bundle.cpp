#include "app_bundle.h"
#include "base64.h"
#include "common.h"
#include "macho_file.h"
#include "sys/stat.h"
#include "sys/types.h"

#include <cstring>

static bool StartsWith(const string& str, const char* prefix) {
    return 0 == str.compare(0, strlen(prefix), prefix);
}

static bool IsDylibLoadCommandName(const string& strDylib) {
    return StartsWith(strDylib, "@executable_path/") || StartsWith(strDylib, "@loader_path/") ||
           StartsWith(strDylib, "@rpath/") || StartsWith(strDylib, "/usr/lib/") ||
           StartsWith(strDylib, "/System/Library/");
}

static string GetBundleType(const string& strFolder) {
    if (FileSystem::IsPathSuffix(strFolder, ".appex")) {
        return "appex";
    }
    if (FileSystem::IsPathSuffix(strFolder, ".framework")) {
        return "framework";
    }
    if (FileSystem::IsPathSuffix(strFolder, ".xctest")) {
        return "xctest";
    }
    if (FileSystem::IsPathSuffix(strFolder, ".app")) {
        return "app";
    }
    return "bundle";
}

static bool ShouldUseLoaderPathForBundleType(const string& strBundleType) {
    return ("framework" == strBundleType || "xctest" == strBundleType);
}

static string GetFolderName(const string& strPath) {
    size_t pos = strPath.find_last_of("/\\");
    if (string::npos == pos) {
        return ".";
    }
    return strPath.substr(0, pos);
}

static string StripPngExtension(string strName) {
    if (FileSystem::IsPathSuffix(strName, ".png")) {
        strName.resize(strName.size() - 4);
    }
    return strName;
}

static bool IsIconFileMatch(const string& strBaseName, const string& strIconName) {
    if (strIconName.empty()) {
        return false;
    }
    if (0 == strBaseName.compare(0, strIconName.size(), strIconName)) {
        return true;
    }
    string strBaseNoExt = StripPngExtension(strBaseName);
    string strIconNoExt = StripPngExtension(strIconName);
    return 0 == strBaseNoExt.compare(0, strIconNoExt.size(), strIconNoExt);
}

static void AddIconName(vector<string>& arrNames, const string& strName) {
    if (!strName.empty() && arrNames.end() == find(arrNames.begin(), arrNames.end(), strName)) {
        arrNames.push_back(strName);
    }
}

static void GetBundleIconNames(jvalue& jvInfo, vector<string>& arrNames) {
    if (jvInfo.has("CFBundleIcons")) {
        jvalue& jvIcons = jvInfo["CFBundleIcons"];
        if (jvIcons.has("CFBundlePrimaryIcon")) {
            jvalue& jvFiles = jvIcons["CFBundlePrimaryIcon"]["CFBundleIconFiles"];
            if (jvFiles.is_array()) {
                for (size_t i = 0; i < jvFiles.size(); i++) {
                    AddIconName(arrNames, jvFiles[i]);
                }
            }
        }
    }

    if (jvInfo.has("CFBundleIconFiles")) {
        jvalue& jvIconFiles = jvInfo["CFBundleIconFiles"];
        if (jvIconFiles.is_array()) {
            for (size_t i = 0; i < jvIconFiles.size(); i++) {
                AddIconName(arrNames, jvIconFiles[i]);
            }
        }
    }

    AddIconName(arrNames, jvInfo["CFBundleIconFile"]);
}

bool AppBundle::FindAppFolder(const string& strFolder, string& strAppFolder) {
    if (FileSystem::IsPathSuffix(strFolder, ".app") || FileSystem::IsPathSuffix(strFolder, ".appex")) {
        strAppFolder = strFolder;
        return true;
    }

    FileSystem::EnumFolder(
        strFolder.c_str(), true,
        [&](bool bFolder, const string& strPath) {
            string strName = Utility::GetBaseName(strPath.c_str());
            if ("__MACOSX" == strName) {
                return true;
            }
            return false;
        },
        [&](bool bFolder, const string& strPath) {
            if (bFolder) {
                if (FileSystem::IsPathSuffix(strPath, ".app") || FileSystem::IsPathSuffix(strPath, ".appex")) {
                    strAppFolder = strPath;
                    return true;
                }
            }
            return false;
        });

    return (!strAppFolder.empty());
}

bool AppBundle::GetSignFolderInfo(const string& strFolder, jvalue& jvNode, bool bGetName) {
    string strInfoPlistData;
    string strInfoPlistPath = strFolder + "/Info.plist";
    FileSystem::ReadFile(strInfoPlistPath.c_str(), strInfoPlistData);

    jvalue jvInfo;
    jvInfo.read_plist(strInfoPlistData);
    string strBundleId = jvInfo["CFBundleIdentifier"];
    string strBundleExe = jvInfo["CFBundleExecutable"];
    string strBundleVersion = jvInfo["CFBundleVersion"];
    if (strBundleId.empty() || strBundleExe.empty()) {
        return false;
    }

    string strInfoSHA1;
    string strInfoSHA256;
    Hash::SHABase64(strInfoPlistData, strInfoSHA1, strInfoSHA256);

    jvNode["bundle_id"] = strBundleId;
    jvNode["bundle_version"] = strBundleVersion;
    jvNode["bundle_executable"] = strBundleExe;
    jvNode["bundle_type"] = GetBundleType(strFolder);
    jvNode["sha1"] = strInfoSHA1;
    jvNode["sha256"] = strInfoSHA256;
    if (!jvNode.has("path")) {
        jvNode["path"] = strFolder.substr(appFolder_.size() + 1);
    }

    if (bGetName) {
        string strBundleName = jvInfo["CFBundleDisplayName"];
        if (strBundleName.empty()) {
            strBundleName = jvInfo["CFBundleName"].as_cstr();
        }
        jvNode["name"] = strBundleName;
    }

    return true;
}

bool AppBundle::GetObjectsToSign(const string& strFolder, jvalue& jvInfo) {
    vector<string> allBundles;

    std::function<bool(const string&)> findAllBundles = [&](const string& currentPath) {
        bool nestedSucceeded = true;
        const bool enumerated =
            FileSystem::EnumFolder(currentPath.c_str(), false, NULL, [&](bool bFolder, const string& strPath) {
                if (bFolder) {
                    if (FileSystem::IsPathSuffix(strPath, ".app") || FileSystem::IsPathSuffix(strPath, ".appex") ||
                        FileSystem::IsPathSuffix(strPath, ".framework") ||
                        FileSystem::IsPathSuffix(strPath, ".xctest")) {
                        allBundles.push_back(strPath);
                        nestedSucceeded = findAllBundles(strPath);
                    } else {
                        nestedSucceeded = findAllBundles(strPath);
                    }
                    if (!nestedSucceeded)
                        return true;
                }
                return false;
            });
        return enumerated && nestedSucceeded;
    };

    if (!findAllBundles(strFolder))
        return false;

    sort(allBundles.begin(), allBundles.end(), [](const string& a, const string& b) {
        size_t depthA = count(a.begin(), a.end(), '/');
        size_t depthB = count(b.begin(), b.end(), '/');
        // deeper paths first
        return depthA > depthB;
    });

    for (const string& bundlePath : allBundles) {
        jvalue jvNode;
        if (!GetSignFolderInfo(bundlePath, jvNode))
            return false;
        jvInfo["folders"].push_back(jvNode);
    }

    bool inspectionFailed = false;
    if (!FileSystem::EnumFolder(
            strFolder.c_str(), true, NULL,
            [&](bool bFolder, const string& strPath) {
                if (bFolder || string::npos != strPath.find(".dSYM") || string::npos != strPath.find("_WatchKitStub")) {
                    return false;
                }
                bool bMachO = false;
                const int64_t fileSize = FileSystem::GetFileSize(strPath.c_str());
                if (fileSize < 0) {
                    inspectionFailed = true;
                    return true;
                }
                if (fileSize >= static_cast<int64_t>(sizeof(uint32_t))) {
                    size_t mappedSize = 0;
                    void* mapped = FileSystem::MapFile(strPath.c_str(), 0, sizeof(uint32_t), &mappedSize, true);
                    if (mapped == nullptr || mappedSize != sizeof(uint32_t)) {
                        inspectionFailed = true;
                        return true;
                    }
                    uint32_t magic = 0;
                    std::memcpy(&magic, mapped, sizeof(magic));
                    if (!FileSystem::UnmapFile(mapped, mappedSize)) {
                        inspectionFailed = true;
                        return true;
                    }
                    bMachO = (magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
                              magic == FAT_MAGIC || magic == FAT_CIGAM);
                }
                if (bMachO) {
                    jvInfo["files"].push_back(strPath.substr(appFolder_.size() + 1));
                }
                return false;
            }) ||
        inspectionFailed)
        return false;

    return true;
}

bool AppBundle::GenerateCodeResources(const string& strFolder, jvalue& jvCodeRes) {
    set<string> setFiles;
    if (!FileSystem::EnumFolder(strFolder.c_str(), true, NULL, [&](bool bFolder, const string& strPath) {
            if (!bFolder) {
                string strNode = strPath.substr(strFolder.size() + 1);
                Utility::StringReplace(strNode, "\\", "/");
                setFiles.insert(strNode);
            }
            return false;
        }))
        return false;

    jvalue jvInfo;
    jvInfo.read_plist_from_file("%s/Info.plist", strFolder.c_str());
    string strBundleExe = jvInfo["CFBundleExecutable"];

    setFiles.erase("_CodeSignature/CodeResources");
    setFiles.erase(strBundleExe);

    jvCodeRes.clear();
    jvCodeRes["files"] = jvalue(jvalue::E_OBJECT);
    jvCodeRes["files2"] = jvalue(jvalue::E_OBJECT);

    for (string strKey : setFiles) {
        if (removeProvision_ && strKey == "embedded.mobileprovision") {
            string strProvFile = strFolder + "/embedded.mobileprovision";
            if (!FileSystem::RemoveFile(strProvFile.c_str()))
                return false;
            Logger::Print(">>> Removed embedded.mobileprovision\n");
            continue;
        }

        string strFile = strFolder + "/" + strKey;
        string strSHA1Base64;
        string strSHA256Base64;
        if (!Hash::SHABase64File(strFile.c_str(), strSHA1Base64, strSHA256Base64))
            return false;

        bool bomit1 = false;
        bool bomit2 = false;

        if (FileSystem::IsPathSuffix(strKey, ".lproj/locversion.plist")) {
            bomit1 = true;
            bomit2 = true;
        }

        if (FileSystem::IsPathSuffix(strKey, ".DS_Store") || "Info.plist" == strKey || "PkgInfo" == strKey) {
            bomit2 = true;
        }

        if (!bomit1) {
            if (string::npos != strKey.rfind(".lproj/")) {
                jvCodeRes["files"][strKey]["hash"] = "data:" + strSHA1Base64;
                jvCodeRes["files"][strKey]["optional"] = true;
            } else {
                jvCodeRes["files"][strKey] = "data:" + strSHA1Base64;
            }
        }

        if (!bomit2) {
            jvCodeRes["files2"][strKey]["hash"] = "data:" + strSHA1Base64;
            jvCodeRes["files2"][strKey]["hash2"] = "data:" + strSHA256Base64;
            if (string::npos != strKey.rfind(".lproj/")) {
                jvCodeRes["files2"][strKey]["optional"] = true;
            }
        }
    }

    jvCodeRes["rules"]["^.*"] = true;
    jvCodeRes["rules"]["^.*\\.lproj/"]["optional"] = true;
    jvCodeRes["rules"]["^.*\\.lproj/"]["weight"] = 1000.0;
    jvCodeRes["rules"]["^.*\\.lproj/locversion.plist$"]["omit"] = true;
    jvCodeRes["rules"]["^.*\\.lproj/locversion.plist$"]["weight"] = 1100.0;
    jvCodeRes["rules"]["^Base\\.lproj/"]["weight"] = 1010.0;
    jvCodeRes["rules"]["^version.plist$"] = true;

    jvCodeRes["rules2"]["^.*"] = true;
    jvCodeRes["rules2"][".*\\.dSYM($|/)"]["weight"] = 11.0;
    jvCodeRes["rules2"]["^(.*/)?\\.DS_Store$"]["omit"] = true;
    jvCodeRes["rules2"]["^(.*/)?\\.DS_Store$"]["weight"] = 2000.0;
    jvCodeRes["rules2"]["^.*\\.lproj/"]["optional"] = true;
    jvCodeRes["rules2"]["^.*\\.lproj/"]["weight"] = 1000.0;
    jvCodeRes["rules2"]["^.*\\.lproj/locversion.plist$"]["omit"] = true;
    jvCodeRes["rules2"]["^.*\\.lproj/locversion.plist$"]["weight"] = 1100.0;
    jvCodeRes["rules2"]["^Base\\.lproj/"]["weight"] = 1010.0;
    jvCodeRes["rules2"]["^Info\\.plist$"]["omit"] = true;
    jvCodeRes["rules2"]["^Info\\.plist$"]["weight"] = 20.0;
    jvCodeRes["rules2"]["^PkgInfo$"]["omit"] = true;
    jvCodeRes["rules2"]["^PkgInfo$"]["weight"] = 20.0;
    jvCodeRes["rules2"]["^embedded\\.provisionprofile$"]["weight"] = 20.0;
    jvCodeRes["rules2"]["^version\\.plist$"]["weight"] = 20.0;

    return true;
}

void AppBundle::GetChangedFiles(jvalue& jvNode, vector<string>& arrChangedFiles) {
    if (jvNode.has("files")) {
        for (size_t i = 0; i < jvNode["files"].size(); i++) {
            arrChangedFiles.push_back(jvNode["files"][i]);
        }
    }

    if (jvNode.has("folders")) {
        for (size_t i = 0; i < jvNode["folders"].size(); i++) {
            jvalue& jvSubNode = jvNode["folders"][i];
            GetChangedFiles(jvSubNode, arrChangedFiles);
            string strPath = jvSubNode["path"];
            arrChangedFiles.push_back(strPath + "/_CodeSignature/CodeResources");
            arrChangedFiles.push_back(strPath + "/" + jvSubNode["bundle_executable"].as_string());
        }
    }
}

void AppBundle::GetNodeChangedFiles(jvalue& jvNode) {
    if (jvNode.has("folders")) {
        for (size_t i = 0; i < jvNode["folders"].size(); i++) {
            GetNodeChangedFiles(jvNode["folders"][i]);
        }
    }

    vector<string> arrChangedFiles;
    GetChangedFiles(jvNode, arrChangedFiles);
    for (size_t i = 0; i < arrChangedFiles.size(); i++) {
        jvNode["changed"].push_back(arrChangedFiles[i]);
    }

    if ("/" == jvNode["path"]) { // root
        jvNode["changed"].push_back("embedded.mobileprovision");
    }
}

bool AppBundle::ShouldInjectDylibsIntoNode(jvalue& jvNode) {
    if (injectionDylibs_.empty() && dylibsToRemove_.empty()) {
        return false;
    }

    string strPath = jvNode["path"];
    string strBundleType = jvNode["bundle_type"];
    if ("/" == strPath) {
        return (0 != (dylibInjectionScope_ & DYLIB_INJECT_ROOT));
    }
    if ("framework" == strBundleType) {
        return (0 != (dylibInjectionScope_ & DYLIB_INJECT_FRAMEWORKS));
    }
    if ("appex" == strBundleType || "xctest" == strBundleType || "app" == strBundleType) {
        return (0 != (dylibInjectionScope_ & DYLIB_INJECT_EXTENSIONS));
    }
    return false;
}

bool AppBundle::InjectDylibsIntoTarget(MachOFile& macho, const string& strTargetFolder, bool bUseLoaderPath,
                                       vector<string>& arrCopiedDylibs) {
    for (const string& strDylib : injectionDylibs_) {
        string strInstallName = strDylib;
        if (!IsDylibLoadCommandName(strDylib)) {
            if (!FileSystem::IsFileExists(strDylib.c_str())) {
                Logger::ErrorV(">>> Dylib file not found! %s\n", strDylib.c_str());
                return false;
            }

            string strFileName = Utility::GetBaseName(strDylib.c_str());
            string strDestFile = strTargetFolder + "/" + strFileName;
            string strFullDestFile = FileSystem::GetFullPath(strDestFile.c_str());
            if (strFullDestFile != strDylib) {
                if (!FileSystem::CopyFile(strDylib.c_str(), strDestFile.c_str())) {
                    Logger::ErrorV(">>> Can't copy dylib: %s -> %s\n", strDylib.c_str(), strDestFile.c_str());
                    return false;
                }
            }
            arrCopiedDylibs.push_back(strDestFile);
            strInstallName = string(bUseLoaderPath ? "@loader_path/" : "@executable_path/") + strFileName;
        }

        if (!macho.InjectDylib(weakInject_, strInstallName.c_str())) {
            return false;
        }
    }
    return true;
}

bool AppBundle::SignCopiedDylibs(const vector<string>& arrCopiedDylibs) {
    set<string> setSigned;
    for (const string& strCopiedDylib : arrCopiedDylibs) {
        if (!setSigned.insert(strCopiedDylib).second) {
            continue;
        }
        Logger::PrintV(">>> SignInjectedDylib: \t%s\n", strCopiedDylib.c_str());
        MachOFile macho;
        if (!macho.Init(strCopiedDylib.c_str())) {
            Logger::ErrorV(">>> Invalid injected dylib file! %s\n", strCopiedDylib.c_str());
            return false;
        }
        if (!macho.Sign(signingAsset_, true, "", "", "", "")) {
            return false;
        }
    }
    return true;
}

bool AppBundle::SignNode(jvalue& jvNode) {
    Base64Codec b64;
    string strInfoSHA1;
    string strInfoSHA256;
    string strFolder = jvNode["path"];
    string strBundleId = jvNode["bundle_id"];
    string strBundleExe = jvNode["bundle_executable"];
    string strBundleType = jvNode["bundle_type"];
    b64.Decode(jvNode["sha1"].as_cstr(), strInfoSHA1);
    b64.Decode(jvNode["sha256"].as_cstr(), strInfoSHA256);
    if (strBundleId.empty() || strBundleExe.empty() || strInfoSHA1.empty() || strInfoSHA256.empty()) {
        Logger::ErrorV(">>> Can't get BundleID or BundleExecute or Info.plist SHASum in Info.plist! %s\n",
                       strFolder.c_str());
        return false;
    }

    string strBaseFolder = appFolder_;
    if ("/" != strFolder) {
        strBaseFolder += "/";
        strBaseFolder += strFolder;
    }

    string strExePath = strBaseFolder + "/" + strBundleExe;
    Logger::PrintV(">>> SignFolder: %s, (%s)\n",
                   ("/" == strFolder) ? Utility::GetBaseName(appFolder_.c_str()) : strFolder.c_str(),
                   strBundleExe.c_str());

    MachOFile macho;
    if (!macho.Init(strExePath.c_str())) {
        Logger::ErrorV(">>> Can't parse BundleExecute file! %s\n", strExePath.c_str());
        return false;
    }

    bool bForceSign = forceSign_;
    if (ShouldInjectDylibsIntoNode(jvNode)) {
        vector<string> arrCopiedDylibs;
        if (!injectionDylibs_.empty()) {
            if (!InjectDylibsIntoTarget(macho, strBaseFolder, ShouldUseLoaderPathForBundleType(strBundleType),
                                        arrCopiedDylibs)) {
                return false;
            }
            if (!SignCopiedDylibs(arrCopiedDylibs)) {
                return false;
            }
            bForceSign = true;
        }

        if (!dylibsToRemove_.empty()) {
            if (!macho.RemoveDylibs(dylibsToRemove_))
                return false;
            for (const string& name : dylibsToRemove_) {
                string baseName = name;
                if (StartsWith(baseName, "@executable_path/")) {
                    baseName = baseName.substr(17);
                } else if (StartsWith(baseName, "@loader_path/")) {
                    baseName = baseName.substr(13);
                }
                if (baseName.find('/') == string::npos) {
                    FileSystem::RemoveFileV("%s/%s", strBaseFolder.c_str(), baseName.c_str());
                }
            }
            bForceSign = true;
        }
    }

    if (jvNode.has("files")) {
        for (size_t i = 0; i < jvNode["files"].size(); i++) {
            string strFile = jvNode["files"][i];
            string strCurrentExecutable = ("/" == strFolder) ? strBundleExe : (strFolder + "/" + strBundleExe);
            if (strFile == strCurrentExecutable) {
                continue;
            }
            string strFullFile = appFolder_ + "/" + strFile;
            Logger::PrintV(">>> SignFile: \t%s\n", strFile.c_str());
            MachOFile fileMachO;
            if (fileMachO.Init(strFullFile.c_str())) {
                bool bFileForceSign = forceSign_;
                if (0 != (dylibInjectionScope_ & DYLIB_INJECT_FILES)) {
                    vector<string> arrCopiedDylibs;
                    if (!InjectDylibsIntoTarget(fileMachO, GetFolderName(strFullFile), true, arrCopiedDylibs)) {
                        return false;
                    }
                    if (!SignCopiedDylibs(arrCopiedDylibs)) {
                        return false;
                    }
                    if (!dylibsToRemove_.empty()) {
                        if (!fileMachO.RemoveDylibs(dylibsToRemove_))
                            return false;
                    }
                    bFileForceSign = true;
                }
                if (!fileMachO.Sign(signingAsset_, bFileForceSign, "", "", "", "")) {
                    return false;
                }
            } else {
                Logger::WarnV(">>> Warning: Skipping non-Mach-O file: \t%s\n", strFile.c_str());
            }
        }
    }

    if (jvNode.has("folders")) {
        for (size_t i = 0; i < jvNode["folders"].size(); i++) {
            if (!SignNode(jvNode["folders"][i])) {
                return false;
            }
        }
    }

    if (signingAssets_ && !removeProvision_ && "framework" != strBundleType) {
        auto endsWith = [](const string& str, const string& suffix) {
            return str.size() >= suffix.size() && 0 == str.compare(str.size() - suffix.size(), suffix.size(), suffix);
        };

        for (auto it = signingAssets_->rbegin(); it != signingAssets_->rend(); ++it) {
            if (endsWith(it->ApplicationIdentifier(), strBundleId)) {
                signingAsset_ = &(*it);
                if (!FileSystem::WriteFileV(signingAsset_->ProvisioningData(), "%s/%s/embedded.mobileprovision",
                                            appFolder_.c_str(), strFolder.c_str())) {
                    Logger::ErrorV(">>> Can't write embedded.mobileprovision!\n");
                    return false;
                }
                bForceSign = true;
                break;
            }
        }
    }

    FileSystem::CreateFolderV("%s/_CodeSignature", strBaseFolder.c_str());
    string strCodeResFile = strBaseFolder + "/_CodeSignature/CodeResources";

    jvalue jvCodeRes;
    if (!bForceSign) {
        jvCodeRes.read_plist_from_file(strCodeResFile.c_str());
    }

    if (bForceSign || jvCodeRes.is_null()) { // create
        if (!GenerateCodeResources(strBaseFolder, jvCodeRes)) {
            Logger::ErrorV(">>> Create CodeResources failed! %s\n", strBaseFolder.c_str());
            return false;
        }
    } else if (jvNode.has("changed")) { // use existed
        for (size_t i = 0; i < jvNode["changed"].size(); i++) {
            string strFile = jvNode["changed"][i].as_cstr();
            string strRealFile = appFolder_ + "/" + strFile;

            string strFileSHA1;
            string strFileSHA256;
            if (!Hash::SHABase64File(strRealFile.c_str(), strFileSHA1, strFileSHA256)) {
                Logger::ErrorV(">>> Can't get changed file SHASum! %s", strFile.c_str());
                return false;
            }

            string strKey = strFile;
            if ("/" != strFolder) {
                strKey = strFile.substr(strFolder.size() + 1);
            }

            jvCodeRes["files"][strKey] = "data:" + strFileSHA1;
            jvCodeRes["files2"][strKey]["hash"] = "data:" + strFileSHA1;
            jvCodeRes["files2"][strKey]["hash2"] = "data:" + strFileSHA256;

            Logger::DebugV("\t\tChanged file: %s, %s\n", strFileSHA1.c_str(), strKey.c_str());
        }
    }

    string strCodeResData;
    jvCodeRes.style_write_plist(strCodeResData);
    if (!FileSystem::WriteFile(strCodeResFile.c_str(), strCodeResData)) {
        Logger::ErrorV("\tWriting CodeResources failed! %s\n", strCodeResFile.c_str());
        return false;
    }

    if (!macho.Sign(signingAsset_, bForceSign, strBundleId, strInfoSHA1, strInfoSHA256, strCodeResData)) {
        return false;
    }

    return true;
}

bool AppBundle::ModifyPluginsBundleId(const string& strOldBundleId, const string& strNewBundleId) {
    vector<string> arrFolders;
    if (!FileSystem::EnumFolder(appFolder_.c_str(), true, NULL, [&](bool bFolder, const string& strPath) {
            if (bFolder) {
                if (FileSystem::IsPathSuffix(strPath, ".app") || FileSystem::IsPathSuffix(strPath, ".appex")) {
                    arrFolders.push_back(strPath);
                }
            }
            return false;
        }))
        return false;

    for (const string& strFolder : arrFolders) {
        jvalue jvInfo;
        if (!jvInfo.read_plist_from_file("%s/Info.plist", strFolder.c_str())) {
            Logger::WarnV(">>> Can't find Plugin's Info.plist! %s\n", strFolder.c_str());
            continue;
        }

        string strOldPIBundleID = jvInfo["CFBundleIdentifier"];
        string strNewPIBundleID = strOldPIBundleID;
        Utility::StringReplace(strNewPIBundleID, strOldBundleId, strNewBundleId);
        jvInfo["CFBundleIdentifier"] = strNewPIBundleID;
        Logger::PrintV(">>> BundleId: \t%s -> %s, Plugin\n", strOldPIBundleID.c_str(), strNewPIBundleID.c_str());

        if (jvInfo.has("WKCompanionAppBundleIdentifier")) {
            string strOldWKCBundleID = jvInfo["WKCompanionAppBundleIdentifier"];
            string strNewWKCBundleID = strOldWKCBundleID;
            Utility::StringReplace(strNewWKCBundleID, strOldBundleId, strNewBundleId);
            jvInfo["WKCompanionAppBundleIdentifier"] = strNewWKCBundleID;
            Logger::PrintV(">>> BundleId: \t%s -> %s, Plugin-WKCompanionAppBundleIdentifier\n",
                           strOldWKCBundleID.c_str(), strNewWKCBundleID.c_str());
        }

        if (jvInfo.has("NSExtension")) {
            if (jvInfo["NSExtension"].has("NSExtensionAttributes")) {
                if (jvInfo["NSExtension"]["NSExtensionAttributes"].has("WKAppBundleIdentifier")) {
                    string strOldWKBundleID = jvInfo["NSExtension"]["NSExtensionAttributes"]["WKAppBundleIdentifier"];
                    string strNewWKBundleID = strOldWKBundleID;
                    Utility::StringReplace(strNewWKBundleID, strOldBundleId, strNewBundleId);
                    jvInfo["NSExtension"]["NSExtensionAttributes"]["WKAppBundleIdentifier"] = strNewWKBundleID;
                    Logger::PrintV(
                        ">>> BundleId: \t%s -> %s, NSExtension-NSExtensionAttributes-WKAppBundleIdentifier\n",
                        strOldWKBundleID.c_str(), strNewWKBundleID.c_str());
                }
            }
        }

        if (!jvInfo.style_write_plist_to_file("%s/Info.plist", strFolder.c_str()))
            return false;
    }

    return true;
}

bool AppBundle::ModifyBundleInfo(const string& strBundleId, const string& strBundleVersion,
                                 const string& strDisplayName) {
    jvalue jvInfo;
    if (!jvInfo.read_plist_from_file("%s/Info.plist", appFolder_.c_str())) {
        Logger::ErrorV(">>> Can't find app's Info.plist! %s\n", appFolder_.c_str());
        return false;
    }

    if (!strBundleId.empty()) {
        string strOldBundleId = jvInfo["CFBundleIdentifier"];
        jvInfo["CFBundleIdentifier"] = strBundleId;
        Logger::PrintV(">>> BundleId: \t%s -> %s\n", strOldBundleId.c_str(), strBundleId.c_str());
        if (!ModifyPluginsBundleId(strOldBundleId, strBundleId))
            return false;
    }

    if (!strDisplayName.empty()) {

        string strNewDisplayName = strDisplayName;

        string strOldDisplayName = jvInfo["CFBundleDisplayName"];
        if (strOldDisplayName.empty()) {
            strOldDisplayName = jvInfo["CFBundleName"].as_cstr();
        }

        jvInfo["CFBundleName"] = strNewDisplayName;
        jvInfo["CFBundleDisplayName"] = strNewDisplayName;

        jvalue jvInfoStrings;
        if (jvInfoStrings.read_plist_from_file("%s/zh_CN.lproj/InfoPlist.strings", appFolder_.c_str())) {
            jvInfoStrings["CFBundleName"] = strNewDisplayName;
            jvInfoStrings["CFBundleDisplayName"] = strNewDisplayName;
            jvInfoStrings.style_write_plist_to_file("%s/zh_CN.lproj/InfoPlist.strings", appFolder_.c_str());
        }

        jvInfoStrings.clear();
        if (jvInfoStrings.read_plist_from_file("%s/zh-Hans.lproj/InfoPlist.strings", appFolder_.c_str())) {
            jvInfoStrings["CFBundleName"] = strNewDisplayName;
            jvInfoStrings["CFBundleDisplayName"] = strNewDisplayName;
            jvInfoStrings.style_write_plist_to_file("%s/zh-Hans.lproj/InfoPlist.strings", appFolder_.c_str());
        }

        Logger::PrintV(">>> BundleName: %s -> %s\n", strOldDisplayName.c_str(), strNewDisplayName.c_str());
    }

    if (!strBundleVersion.empty()) {
        string strOldBundleVersion = jvInfo["CFBundleVersion"];
        jvInfo["CFBundleVersion"] = strBundleVersion;
        jvInfo["CFBundleShortVersionString"] = strBundleVersion;
        Logger::PrintV(">>> BundleVersion: %s -> %s\n", strOldBundleVersion.c_str(), strBundleVersion.c_str());
    }

    return jvInfo.style_write_plist_to_file("%s/Info.plist", appFolder_.c_str());
}

bool AppBundle::ReplaceBundleIcons(const string& strIconFile) {
    if (!FileSystem::IsFileExists(strIconFile.c_str())) {
        Logger::ErrorV(">>> Icon file not found! %s\n", strIconFile.c_str());
        return false;
    }

    vector<string> arrBundleFolders;
    arrBundleFolders.push_back(appFolder_);
    if (!FileSystem::EnumFolder(appFolder_.c_str(), true, NULL, [&](bool bFolder, const string& strPath) {
            if (bFolder && (FileSystem::IsPathSuffix(strPath, ".app") || FileSystem::IsPathSuffix(strPath, ".appex"))) {
                arrBundleFolders.push_back(strPath);
            }
            return false;
        }))
        return false;

    uint32_t uReplaced = 0;
    for (const string& strBundleFolder : arrBundleFolders) {
        jvalue jvInfo;
        if (!jvInfo.read_plist_from_file("%s/Info.plist", strBundleFolder.c_str())) {
            continue;
        }

        vector<string> arrIconNames;
        GetBundleIconNames(jvInfo, arrIconNames);
        if (arrIconNames.empty()) {
            continue;
        }

        bool replacementFailed = false;
        const bool enumerated =
            FileSystem::EnumFolder(strBundleFolder.c_str(), false, NULL, [&](bool bFolder, const string& strPath) {
                if (bFolder) {
                    return false;
                }

                string strBaseName = Utility::GetBaseName(strPath.c_str());
                for (const string& strIconName : arrIconNames) {
                    if (IsIconFileMatch(strBaseName, strIconName)) {
                        if (FileSystem::CopyFile(strIconFile.c_str(), strPath.c_str())) {
                            uReplaced++;
                            Logger::PrintV(">>> Replaced icon: %s\n", strPath.c_str());
                        } else {
                            Logger::ErrorV(">>> Failed to replace icon: %s\n", strPath.c_str());
                            replacementFailed = true;
                            return true;
                        }
                        break;
                    }
                }
                return false;
            });
        if (!enumerated || replacementFailed)
            return false;
    }

    if (0 == uReplaced) {
        Logger::Warn(">>> No declared app icon files found to replace.\n");
        return false;
    }

    Logger::PrintV(">>> Replaced %u icon file(s).\n", uReplaced);
    return true;
}

void AppBundle::ApplyAppModifications() {

    if (!iconFile_.empty()) {
        if (ReplaceBundleIcons(iconFile_)) {
            forceSign_ = true;
        }
    }

    if (enableDocuments_) {
        jvalue jvInfo;
        jvInfo.read_plist_from_file("%s/Info.plist", appFolder_.c_str());
        jvInfo["UISupportsDocumentBrowser"] = true;
        jvInfo["UIFileSharingEnabled"] = true;
        jvInfo.style_write_plist_to_file("%s/Info.plist", appFolder_.c_str());
        forceSign_ = true;
        Logger::Print(">>> Enabled documents support\n");
    }

    if (!minimumVersion_.empty()) {
        jvalue jvInfo;
        jvInfo.read_plist_from_file("%s/Info.plist", appFolder_.c_str());
        string strOldVersion = jvInfo["MinimumOSVersion"];
        jvInfo["MinimumOSVersion"] = minimumVersion_;
        jvInfo.style_write_plist_to_file("%s/Info.plist", appFolder_.c_str());
        forceSign_ = true;
        Logger::PrintV(">>> MinimumOSVersion: %s -> %s\n", strOldVersion.c_str(), minimumVersion_.c_str());
    }

    if (removeExtensions_) {
        const char* extDirs[] = {"PlugIns", "Extensions"};
        for (const char* dir : extDirs) {
            string strPath = appFolder_ + "/" + dir;
            if (FileSystem::IsFolder(strPath.c_str())) {
                FileSystem::RemoveFolder(strPath.c_str());
                Logger::PrintV(">>> Removed %s\n", dir);
                forceSign_ = true;
            }
        }
    }

    if (removeWatchApp_) {
        const char* watchDirs[] = {"Watch", "WatchKit", "com.apple.WatchPlaceholder"};
        for (const char* dir : watchDirs) {
            string strPath = appFolder_ + "/" + dir;
            if (FileSystem::IsFolder(strPath.c_str())) {
                FileSystem::RemoveFolder(strPath.c_str());
                Logger::PrintV(">>> Removed %s\n", dir);
                forceSign_ = true;
            }
        }
    }

    if (removeUiSupportedDevices_) {
        jvalue jvInfo;
        jvInfo.read_plist_from_file("%s/Info.plist", appFolder_.c_str());
        if (jvInfo.has("UISupportedDevices")) {
            jvInfo.erase("UISupportedDevices");
            jvInfo.style_write_plist_to_file("%s/Info.plist", appFolder_.c_str());
            forceSign_ = true;
            Logger::Print(">>> Removed UISupportedDevices\n");
        }
    }
}

bool AppBundle::SignFolder(SigningAsset* pSignAsset, const string& strFolder, const string& strBundleId,
                           const string& strBundleVersion, const string& strDisplayName,
                           const vector<string>& arrInjectDylibs, const vector<string>& arrRemoveDylibNames,
                           bool bForce, bool bWeakInject, bool bEnableCache, bool bRemoveProvision) {
    forceSign_ = bForce;
    signingAsset_ = pSignAsset;
    weakInject_ = bWeakInject;
    removeProvision_ = bRemoveProvision;
    injectionDylibs_.clear();
    dylibsToRemove_.clear();
    for (const string& name : arrRemoveDylibNames) {
        if (name.find('/') != string::npos) {
            dylibsToRemove_.insert(name);
        } else {
            dylibsToRemove_.insert("@executable_path/" + name);
        }
    }
    if (NULL == signingAsset_) {
        return false;
    }

    if (!FindAppFolder(strFolder, appFolder_)) {
        Logger::ErrorV(">>> Can't find app folder! %s\n", strFolder.c_str());
        return false;
    }

    ApplyAppModifications();

    if (!strBundleId.empty() || !strDisplayName.empty() || !strBundleVersion.empty()) {
        forceSign_ = true;
        if (!ModifyBundleInfo(strBundleId, strBundleVersion, strDisplayName)) {
            return false;
        }
    }

    FileSystem::RemoveFileV("%s/embedded.mobileprovision", appFolder_.c_str());
    if (!pSignAsset->ProvisioningData().empty()) {
        if (!FileSystem::WriteFileV(pSignAsset->ProvisioningData(), "%s/embedded.mobileprovision",
                                    appFolder_.c_str())) { // embedded.mobileprovision
            Logger::ErrorV(">>> Can't write embedded.mobileprovision!\n");
            return false;
        }
    }

    if (!arrInjectDylibs.empty()) {
        forceSign_ = true;
        injectionDylibs_ = arrInjectDylibs;
    }
    if (!dylibsToRemove_.empty()) {
        forceSign_ = true;
    }

    string strCacheName;
    Hash::SHA1Text(appFolder_, strCacheName);
    if (!FileSystem::IsFileExistsV("./.orchardseal_cache/%s.json", strCacheName.c_str())) {
        forceSign_ = true;
    }

    jvalue jvRoot;
    if (forceSign_) {
        jvRoot["path"] = "/";
        jvRoot["root"] = appFolder_;
        if (!GetSignFolderInfo(appFolder_, jvRoot, true)) {
            Logger::ErrorV(">>> Can't get BundleID, BundleVersion, or BundleExecute in Info.plist! %s\n",
                           appFolder_.c_str());
            return false;
        }
        if (!GetObjectsToSign(appFolder_, jvRoot)) {
            return false;
        }
        GetNodeChangedFiles(jvRoot);
    } else {
        jvRoot.read_from_file("./.orchardseal_cache/%s.json", strCacheName.c_str());
    }

    string strAppName = jvRoot["name"];

    Logger::PrintV(">>> Signing: \t%s ...\n", appFolder_.c_str());
    Logger::PrintV(">>> AppName: \t%s\n", strAppName.c_str());
    Logger::PrintV(">>> BundleId: \t%s\n", jvRoot["bundle_id"].as_cstr());
    Logger::PrintV(">>> Version: \t%s\n", jvRoot["bundle_version"].as_cstr());
    Logger::PrintV(">>> TeamId: \t%s\n", signingAsset_->TeamId().c_str());
    Logger::PrintV(">>> SubjectCN: \t%s\n", signingAsset_->SubjectCommonName().c_str());
    Logger::PrintV(">>> ReadCache: \t%s\n", forceSign_ ? "NO" : "YES");

    if (SignNode(jvRoot)) {
        if (bEnableCache) {
            FileSystem::CreateFolder("./.orchardseal_cache");
            jvRoot.style_write_to_file("./.orchardseal_cache/%s.json", strCacheName.c_str());
        }
        return true;
    }

    return false;
}

bool AppBundle::SignFolder(list<SigningAsset>* pSignAssets, const string& strFolder, const string& strBundleId,
                           const string& strBundleVersion, const string& strDisplayName,
                           const vector<string>& arrInjectDylibs, const vector<string>& arrRemoveDylibNames,
                           bool bForce, bool bWeakInject, bool bEnableCache, bool bRemoveProvision) {
    signingAssets_ = pSignAssets;
    if (NULL == signingAssets_ || signingAssets_->empty()) {
        Logger::ErrorV(">>> No valid provisioning profiles were loaded.\n");
        return false;
    }
    return SignFolder(&signingAssets_->front(), strFolder, strBundleId, strBundleVersion, strDisplayName,
                      arrInjectDylibs, arrRemoveDylibNames, bForce, bWeakInject, bEnableCache, bRemoveProvision);
}
